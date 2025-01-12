#include "HAL9000.h"
#include "vmm.h"
#include "synch.h"
#include "pmm.h"
#include "bitmap.h"
#include "cpumu.h"
#include "mtrr.h"
#include "io.h"
#include "vm_reservation_space.h"
#include "thread_internal.h"
#include "process_internal.h"
#include "mdl.h"

#define VMM_SIZE_FOR_RESERVATION_METADATA            (5*TB_SIZE)

typedef struct _VMM_DATA
{
    VMM_RESERVATION_SPACE   VmmReservationSpace;


    // Global paging related defines
    // No matter what CR3 we're using the same WB and UC indexes will be used
    BYTE                    WriteBackIndex;
    BYTE                    UncacheableIndex;
} VMM_DATA, *PVMM_DATA;

typedef
BOOLEAN
(__cdecl FUNC_PageWalkCallback)(
    IN      PML4                    Cr3,
    IN      PVOID                   PageTable,
    IN      PVOID                   VirtualAddress,
    IN      BYTE                    PageLevel,
    IN_OPT  PVOID                   Context
    );

typedef FUNC_PageWalkCallback *PFUNC_PageWalkCallback;

static
void
_VmmAddFrameMappings(
    IN          PHYSICAL_ADDRESS    PhysicalAddress,
    IN          PVOID               VirtualAddress,
    IN          DWORD               FrameCount
);

typedef struct _VMM_MAP_UNMAP_PAGE_WALK_CONTEXT
{
    // These fields are valid only when mapping memory in _VmMapPage
    PPAGING_DATA                    PagingData;
    PHYSICAL_ADDRESS                PhysicalAddressBase;
    PVOID                           VirtualAddressBase;

    PAGE_RIGHTS                     PageRights;
    BOOLEAN                         Invalidate;
    BOOLEAN                         Uncacheable;

    // Valid only when unmapping memory in _VmUnmapPage;
    BOOLEAN                         ReleaseMemory;
} VMM_MAP_UNMAP_PAGE_WALK_CONTEXT, *PVMM_MAP_UNMAP_PAGE_WALK_CONTEXT;

// Used when determining the physical address, a/d bits and when resetting them
typedef struct _VMM_RETRIEVE_PHYS_ACCESS_PAGE_WALK_CONTEXT
{
    PHYSICAL_ADDRESS                PhysicalAddress;

    // Returns the values of the A/D bits
    BOOLEAN                         Accessed;
    BOOLEAN                         Dirty;

    // When set clears the A/D bits
    BOOLEAN                         ClearAccessed;
    BOOLEAN                         ClearDirty;
} VMM_RETRIEVE_PHYS_ACCESS_PAGE_WALK_CONTEXT, *PVMM_RETRIEVE_PHYS_ACCESS_PAGE_WALK_CONTEXT;

static VMM_DATA m_vmmData;

static
void
_VmSetupPagingStructure(
    IN      PPAGING_DATA            PagingData,
    IN      PVOID                   PagingStructure
    );

static
BOOL_SUCCESS
BOOLEAN
_VmDeterminePatIndices(
    IN      QWORD                   PatValues,
    OUT     PBYTE                   WbIndex,
    OUT     PBYTE                   UcIndex
    );

static
void
_VmWalkPagingTables(
    IN      PML4                        Cr3,
    IN      PVOID                       BaseAddress,
    IN      QWORD                       Size,
    IN      PFUNC_PageWalkCallback      WalkCallback,
    IN_OPT  PVOID                       Context
    );

static FUNC_PageWalkCallback            _VmMapPage;
static FUNC_PageWalkCallback            _VmUnmapPage;
static FUNC_PageWalkCallback            _VmRetrievePhyAccess;

__forceinline
static
PHYSICAL_ADDRESS
_VmRetrieveNextPhysicalAddressForPagingStructure(
    IN      PPAGING_DATA            PagingData
    )
{
    QWORD nextAddress;
    DWORD currentIndex;

    ASSERT( NULL != PagingData );

    currentIndex = PagingData->CurrentIndex;

    ASSERT( currentIndex < PagingData->NumberOfFrames );

    nextAddress = (QWORD) PagingData->BasePhysicalAddress + currentIndex * PAGE_SIZE;
    PagingData->CurrentIndex++;

    return (PHYSICAL_ADDRESS) nextAddress;
}

__forceinline
static
BOOLEAN
_VmIsKernelAddress(
    IN      PVOID                   Address
    )
{
    return IsBooleanFlagOn((QWORD)Address, (QWORD)1 << VA_HIGHEST_VALID_BIT);
}

__forceinline
static
BOOLEAN
_VmIsKernelRange(
    IN      PVOID                   Address,
    IN      QWORD                   RangeSize
    )
{
    ASSERT(RangeSize != 0);

    // Check both ends, if one of the addresses is a KM address => game over :)
    return _VmIsKernelAddress(Address) || _VmIsKernelAddress(PtrOffset(Address, RangeSize - 1));
}

__forceinline
static
PTR_SUCCESS
PVMM_RESERVATION_SPACE
_VmmRetrieveReservationSpaceForAddress(
    IN      PVOID           VirtualAddress
    )
{
    if (_VmIsKernelAddress(VirtualAddress))
    {
        return &m_vmmData.VmmReservationSpace;
    }
    else
    {
        PTHREAD pThread;

        // by the time we have UM processes it's clear that we'll have a populated THREAD structure
        // with a process to which it belongs

        pThread = GetCurrentThread();

        ASSERT(pThread != NULL);
        ASSERT(pThread->Process != NULL);

        return pThread->Process->VaSpace;
    }
}

_No_competing_thread_
void
VmmPreinit(
    void
    )
{
    memzero(&m_vmmData, sizeof(VMM_DATA));
}

_No_competing_thread_
STATUS
VmmInit(
    IN      PVOID                   BaseAddress
    )
{
    if (BaseAddress == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    VmReservationSpaceInit(BaseAddress,
                           NULL,
                           VMM_SIZE_FOR_RESERVATION_METADATA,
                           &m_vmmData.VmmReservationSpace);

    return STATUS_SUCCESS;
}

PTR_SUCCESS
PVOID
VmmMapMemoryEx(
    IN      PPAGING_DATA            PagingData,
    IN      PHYSICAL_ADDRESS        PhysicalAddress,
    IN      QWORD                   Size,
    IN      PAGE_RIGHTS             PageRights,
    IN      BOOLEAN                 Invalidate,
    IN      BOOLEAN                 Uncacheable
    )
{
    PVOID pVirtualAddress;

    if (PagingData == NULL)
    {
        return NULL;
    }

    if (!IsAddressAligned(PhysicalAddress, PAGE_SIZE))
    {
        return NULL;
    }

    if ((0 == Size) || (!IsAddressAligned(Size, PAGE_SIZE)))
    {
        return NULL;
    }

    pVirtualAddress = VmReservationSpaceDetermineNextFreeVirtualAddress(&m_vmmData.VmmReservationSpace, Size);
    LOG_TRACE_VMM("Virtual address: 0x%X\n", pVirtualAddress);
    ASSERT(IsAddressAligned(pVirtualAddress, PAGE_SIZE));

    VmmMapMemoryInternal(PagingData,
                         PhysicalAddress,
                         Size,
                         pVirtualAddress,
                         PageRights,
                         Invalidate,
                         Uncacheable
                         );

    return pVirtualAddress;
}

void
VmmMapMemoryInternal(
    IN      PPAGING_DATA            PagingData,
    IN      PHYSICAL_ADDRESS        PhysicalAddress,
    IN      QWORD                   Size,
    IN      PVOID                   BaseAddress,
    IN      PAGE_RIGHTS             PageRights,
    IN      BOOLEAN                 Invalidate,
    IN      BOOLEAN                 Uncacheable
    )
{
    VMM_MAP_UNMAP_PAGE_WALK_CONTEXT ctx = { 0 };
    PML4 cr3;

    ASSERT(PagingData != NULL);
    ASSERT(IsAddressAligned(PhysicalAddress, PAGE_SIZE));
    ASSERT(0 != Size && IsAddressAligned(Size, PAGE_SIZE));

    ctx.PagingData = PagingData;
    ctx.PhysicalAddressBase = PhysicalAddress;
    ctx.VirtualAddressBase = BaseAddress;
    ctx.PageRights = PageRights;
    ctx.Invalidate = Invalidate;
    ctx.Uncacheable = Uncacheable;

    cr3.Raw = (QWORD) PagingData->BasePhysicalAddress;

    _VmWalkPagingTables(cr3,
                        BaseAddress,
                        Size,
                        _VmMapPage,
                        &ctx);
}

void
VmmUnmapMemoryEx(
    IN      PML4                    Cr3,
    IN      PVOID                   VirtualAddress,
    IN      QWORD                   Size,
    IN      BOOLEAN                 ReleaseMemory
    )
{
    VMM_MAP_UNMAP_PAGE_WALK_CONTEXT ctx = { 0 };

    if ((NULL == VirtualAddress) || (!IsAddressAligned(VirtualAddress, PAGE_SIZE)))
    {
        return;
    }

    if ((0 == Size) || (!IsAddressAligned(Size, PAGE_SIZE)))
    {
        return;
    }

    ctx.ReleaseMemory = ReleaseMemory;

    _VmWalkPagingTables(Cr3,
                        VirtualAddress,
                        Size,
                        _VmUnmapPage,
                        &ctx);
}

PTR_SUCCESS
PHYSICAL_ADDRESS
VmmGetPhysicalAddressEx(
    IN      PML4                    Cr3,
    IN      PVOID                   VirtualAddress,
    OUT_OPT BOOLEAN*                Accessed,
    OUT_OPT BOOLEAN*                Dirty
    )
{
    VMM_RETRIEVE_PHYS_ACCESS_PAGE_WALK_CONTEXT ctx = { 0 };

    ASSERT(NULL != VirtualAddress);
    ASSERT(IsAddressAligned(VirtualAddress, PAGE_SIZE));

    ctx.ClearAccessed = Accessed != NULL;
    ctx.ClearDirty = Dirty != NULL;

    _VmWalkPagingTables(Cr3,
                        VirtualAddress,
                        PAGE_SIZE,
                        _VmRetrievePhyAccess,
                        &ctx
                        );

    if (Accessed != NULL)
    {
        *Accessed = ctx.Accessed;
    }

    if (Dirty != NULL)
    {
        *Dirty = ctx.Dirty;
    }

    return ctx.PhysicalAddress;
}

_No_competing_thread_
STATUS
VmmPreparePagingData(
    void
    )
{
    QWORD ia32PatValues;
    BOOLEAN bResult;

    ia32PatValues = 0;
    bResult = FALSE;

    ia32PatValues = __readmsr(IA32_PAT);
    bResult = _VmDeterminePatIndices(ia32PatValues,
                                     &m_vmmData.WriteBackIndex,
                                     &m_vmmData.UncacheableIndex
    );
    if (!bResult)
    {
        LOG_ERROR("_VmDeterminePatIndices failed!\n");
        return STATUS_PAT_LAYOUT_NOT_COMPATIBLE;
    }

    LOG("IA32_PAT: 0x%X\n", ia32PatValues);
    LOG("WbIndex: %u\n", m_vmmData.WriteBackIndex);
    LOG("UcIndex: %u\n", m_vmmData.UncacheableIndex);

    return STATUS_SUCCESS;
}

STATUS
VmmSetupPageTables(
    INOUT   PPAGING_DATA            PagingDataWhereToMap,
    OUT     PPAGING_DATA            PagingData,
    IN      PHYSICAL_ADDRESS        BasePhysicalAddress,
    IN      DWORD                   FramesReserved,
    IN      BOOLEAN                 KernelStructures
    )
{
    DWORD sizeReservedForPagingStructures;
    PVOID pBaseVirtualAddress;

    ASSERT(PagingDataWhereToMap != NULL);
    ASSERT(PagingData != NULL);
    ASSERT(BasePhysicalAddress != NULL);
    ASSERT(FramesReserved != 0);

    pBaseVirtualAddress = (PVOID) PA2VA(BasePhysicalAddress);

    ASSERT(FramesReserved <= MAX_DWORD / PAGE_SIZE);
    sizeReservedForPagingStructures = FramesReserved * PAGE_SIZE;

    // Current index should start at 1 because at 0 we have the CR3 (PML4 table address)
    PagingData->CurrentIndex = 1;
    PagingData->NumberOfFrames = FramesReserved;
    PagingData->BasePhysicalAddress = BasePhysicalAddress;
    PagingData->KernelSpace = KernelStructures;

    LOG_TRACE_VMM("Will setup paging tables at physical address: 0x%X\n", PagingData->BasePhysicalAddress);
    LOG_TRACE_VMM("BaseAddress: 0x%X\n", pBaseVirtualAddress);
    LOG_TRACE_VMM("Size of paging tables: 0x%x\n", sizeReservedForPagingStructures);

    // 1. We cannot zero the memory before mapping it (because it's not mapped)
    // 2. We cannot zero it after it was mapped because we already have some entries
    // populated to describe the mapped memory.

    // This is not a problem anyway because when we setup a new paging structure we
    // zero it anyway.

    VmmMapMemoryInternal(PagingDataWhereToMap,
                         PagingData->BasePhysicalAddress,
                         sizeReservedForPagingStructures,
                         pBaseVirtualAddress,
                         PAGE_RIGHTS_READWRITE,
                         TRUE,
                         FALSE
                         );
    LOG_TRACE_VMM("VmmMapMemoryInternal finished\n");

    if (PagingDataWhereToMap != PagingData)
    {
        // Zero the newly mapped PML4 if we didn't map it in it's own
        // paging structures - else it would already be populated
        memzero(pBaseVirtualAddress, PAGE_SIZE);
    }

    return STATUS_SUCCESS;
}

void
VmmChangeCr3(
    IN      PHYSICAL_ADDRESS        Pml4Base,
    IN_RANGE(PCID_FIRST_VALID_VALUE, PCID_TOTAL_NO_OF_VALUES - 1)
            PCID                    Pcid,
    IN      BOOLEAN                 Invalidate
    )
{
    ASSERT(IsAddressAligned(Pml4Base,PAGE_SIZE));
    ASSERT(PCID_IS_VALID(Pcid));

    // Intel System Programming Manual Vol 3C
    // Section 4.10.4.1 Operations that Invalidate TLBs and Paging-Structure Caches

    // If CR4.PCIDE = 1 and bit 63 of the instruction�s source operand is 0, the instruction invalidates all TLB
    // entries associated with the PCID specified in bits 11:0 of the instruction�s source operand except those for
    // global pages.It also invalidates all entries in all paging - structure caches associated with that PCID.It is not
    // required to invalidate entries in the TLBs and paging - structure caches that are associated with other PCIDs.

    // If CR4.PCIDE = 1 and bit 63 of the instruction�s source operand is 1, the instruction is not required to
    // invalidate any TLB entries or entries in paging - structure caches.
    __writecr3((Invalidate ? 0 : MOV_TO_CR3_DO_NOT_INVALIDATE_PCID_MAPPINGS) | (QWORD)Pml4Base | Pcid);

    /// TODO: This should be broadcast on all CPUs to invalidate their mappings for PCID Pcid
}

_No_competing_thread_
void
VmmInitReservationSystem(
    void
    )
{
    VmReservationSpaceFinishInit(&m_vmmData.VmmReservationSpace);
}

static
void
_VmmMapDescribedRegion(
    IN      PVOID                   BaseAddress,
    IN      PMDL                    Mdl,
    IN      PAGE_RIGHTS             Rights,
    IN_OPT  PPAGING_LOCK_DATA       PagingData
    )
{
    QWORD currentOffset = 0;

    ASSERT(BaseAddress != NULL);
    ASSERT(IsAddressAligned(BaseAddress, PAGE_SIZE));
    ASSERT(Mdl != NULL);

    for (DWORD i = 0;
         i < MdlGetNumberOfPairs(Mdl);
         ++i)
    {
        PHYSICAL_ADDRESS alignedPa;
        QWORD alignedPaSize;
        PMDL_TRANSLATION_PAIR pMdlPair;

        pMdlPair = MdlGetTranslationPair(Mdl, i);

        alignedPa = (PHYSICAL_ADDRESS)AlignAddressLower(pMdlPair->Address, PAGE_SIZE);
        alignedPaSize = AlignAddressUpper(pMdlPair->NumberOfBytes + AddressOffset(pMdlPair->Address, PAGE_SIZE), PAGE_SIZE);

        MmuMapMemoryInternal(alignedPa,
                             alignedPaSize,
                             Rights,
                             PtrOffset(BaseAddress, currentOffset),
                             FALSE,
                             FALSE,
                             PagingData);

        // advance to the next VA->PA physical mapping
        currentOffset += alignedPaSize;
    }
}

PTR_SUCCESS
PVOID
VmmAllocRegionEx(
    IN_OPT  PVOID                   BaseAddress,
    IN      QWORD                   Size,
    IN      VMM_ALLOC_TYPE          AllocType,
    IN      PAGE_RIGHTS             Rights,
    IN      BOOLEAN                 Uncacheable,
    IN_OPT  PFILE_OBJECT            FileObject,
    IN_OPT  PVMM_RESERVATION_SPACE  VaSpace,
    IN_OPT  PPAGING_LOCK_DATA       PagingData,
    IN_OPT  PMDL                    Mdl
    )
{
    PVOID pBaseAddress;
    QWORD alignedSize;
    STATUS status;
    PVMM_RESERVATION_SPACE pVaSpace;
    PHYSICAL_ADDRESS pa;

    LOG("sunt in Region Ex");

    ASSERT(Size != 0);

    // We need at least one of these flags set, else we have nothing to do
    ASSERT(IsFlagOn(AllocType, VMM_ALLOC_TYPE_COMMIT | VMM_ALLOC_TYPE_RESERVE));

    // If the MDL is non-NULL we must have the VMM_ALLOC_TYPE_NOT_LAZY set,
    // we don't have an implementation for allocating a VA lazily for memory ranges described by a MDL
    ASSERT(Mdl == NULL || IsBooleanFlagOn(AllocType, VMM_ALLOC_TYPE_NOT_LAZY));

    // We currently do not support mapping zero pages
    ASSERT(!IsBooleanFlagOn(AllocType, VMM_ALLOC_TYPE_ZERO));

    // We cannot have both the Mdl and the FileObject non-NULL, the region either is already backed up by some physical
    // frames or it is backed up by a file, or it is not backed up by anything
    ASSERT((Mdl == NULL) || (FileObject == NULL));

    status = STATUS_SUCCESS;
    pBaseAddress = NULL;
    pa = NULL;
    alignedSize = 0;

    pVaSpace = (VaSpace == NULL) ? &m_vmmData.VmmReservationSpace : VaSpace;
    ASSERT(pVaSpace != NULL);

    __try
    {
        status = VmReservationSpaceAllocRegion(pVaSpace,
                                               BaseAddress,
                                               Size,
                                               AllocType,
                                               Rights,
                                               Uncacheable,
                                               FileObject,
                                               &pBaseAddress,
                                               &alignedSize);
        LOG("Allocating region\n");
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("VmReservationSpaceAllocRegion", status);
            __leave;
        }
		LOG("base address is 0x%X\n", pBaseAddress);
        ASSERT(NULL != pBaseAddress);

        if (IsBooleanFlagOn(AllocType, VMM_ALLOC_TYPE_NOT_LAZY))
        {
            ASSERT(IsBooleanFlagOn(AllocType, VMM_ALLOC_TYPE_COMMIT));
			LOG("Allocating region with MDL\n");
            if (Mdl != NULL)
            {
                // If we received a MDL as a parameter => we already have some initialized physical frames
                // which we want to map to pBaseAddress
                ASSERT(Mdl->ByteCount <= alignedSize);

                _VmmMapDescribedRegion(pBaseAddress, Mdl, Rights, PagingData);
            }
            else
            {
                // This area is not described by an MDL, we need to reserve it now
                // We will ask for a continuous number of frames, we have no way of
                // asking for discontinuous frames - even if we call the function multiple
                // times with 1 frame we probably will receive a continuous mapping because
                // there is noone else requesting physical frames in the meantime

                ASSERT(alignedSize / PAGE_SIZE <= MAX_DWORD);
                DWORD noOfFrames = (DWORD)(alignedSize / PAGE_SIZE);

                pa = PmmReserveMemory(noOfFrames);
                if (NULL == pa)
                {
                    LOG_ERROR("PmmReserverMemory failed!\n");
                    __leave;
                }

                MmuMapMemoryInternal(pa,
                                     alignedSize,
                                     Rights,
                                     pBaseAddress,
                                     TRUE,
                                     Uncacheable,
                                     PagingData
                );

                if (PagingData != NULL && !PagingData->Data.KernelSpace)
                {
                    _VmmAddFrameMappings(pa, pBaseAddress, noOfFrames);
                }

                // Check if the mapping is backed up by a file
                if (FileObject != NULL)
                {
                    QWORD fileOffset;
                    QWORD bytesRead;

                    // make sure we read from the start of the file
                    fileOffset = 0;

                    status = IoReadFile(FileObject,
                                        alignedSize,
                                        &fileOffset,
                                        pBaseAddress,
                                        &bytesRead);
                    if (!SUCCEEDED(status))
                    {
                        LOG_FUNC_ERROR("IoReadFile", status);
                        __leave;
                    }

                    LOG_TRACE_VMM("File size is 0x%X, bytes read are 0x%X\n", alignedSize, bytesRead);

                    // zero the rest of the file
                    ASSERT(alignedSize - bytesRead <= MAX_DWORD);

                    // memzero the rest of the allocation (in case the size of the allocation is greater than the
                    // size of the file)
                    memzero(PtrOffset(pBaseAddress, bytesRead), (DWORD)(alignedSize - bytesRead));
                }
            }
        }

    }
    __finally
    {
        if (!SUCCEEDED(status))
        {
            LOG_ERROR("We failed with status 0x%x\n", status);

            if (pBaseAddress != NULL)
            {
                PVOID pAlignedAddress;

                VmReservationSpaceFreeRegion(pVaSpace,
                                             pBaseAddress,
                                             0,
                                             VMM_FREE_TYPE_RELEASE,
                                             &pAlignedAddress,
                                             &alignedSize
                                             );
                ASSERT(pAlignedAddress == pBaseAddress);
                pBaseAddress = NULL;

                if (pa != NULL)
                {
                    MmuUnmapMemoryEx(pAlignedAddress, (DWORD) alignedSize, TRUE, PagingData);
                    pa = NULL;
                }
            }
            ASSERT(pa == NULL);
        }
        else
        {
            if (IsBooleanFlagOn(Rights, PAGE_RIGHTS_EXECUTE | PAGE_RIGHTS_WRITE))
            {
                LOG_WARNING("Successfully mapped W+X memory at 0x%X of size 0x%X\n",
                            pBaseAddress, alignedSize);
            }
        }
    }

    return pBaseAddress;
}

static
void
_VmmAddFrameMappings(
    IN          PHYSICAL_ADDRESS    PhysicalAddress,
    IN          PVOID               VirtualAddress,
    IN          DWORD               FrameCount
)
{
    PPROCESS pProcess;
    PALLOCATION_MAPPING pMapping;
    INTR_STATE intrState;

    pProcess = GetCurrentProcess();

    if (ProcessIsSystem(pProcess))
    {
        return;
    }

    for (DWORD i = 0; i < FrameCount; ++i)
    {
        pMapping = ExAllocatePoolWithTag(PoolAllocatePanicIfFail, sizeof(PALLOCATION_MAPPING), HEAP_MMU_TAG, 0);

        pMapping->PhysicalAddress = PtrOffset(PhysicalAddress, i * PAGE_SIZE);
        pMapping->VirtualAddress = PtrOffset(VirtualAddress, i * PAGE_SIZE);
        pMapping->Size = 1;

        LockAcquire(&pProcess->AddressMappingsLock, &intrState);
        InsertTailList(&pProcess->AddressMappingsHead, &pMapping->ListEntry);
        LockRelease(&pProcess->AddressMappingsLock, intrState);

        LOG("Allocated entry from 0x%X -> 0x%X\n",
            pMapping->VirtualAddress, pMapping->PhysicalAddress);
    }
}

static
STATUS
(__cdecl SearchInListProcess)(
    IN PLIST_ENTRY pEntry,
    IN PVOID Context
)
{
	ASSERT(pEntry != NULL);
	ASSERT(Context != NULL);

	PALLOCATION_MAPPING pMapping;
	PVOID* pContext = (PVOID*)Context;
	PVOID pVirtualAddress = (PVOID)pContext[0];

	pMapping = CONTAINING_RECORD(pEntry, ALLOCATION_MAPPING, ListEntry);

    if (AlignAddressLower(pMapping->VirtualAddress, PAGE_SIZE) == AlignAddressLower(pVirtualAddress, PAGE_SIZE)) {
		pContext[1] = pMapping;
		return STATUS_ELEMENT_FOUND;
    }

	return STATUS_SUCCESS;
}

void
VmmFreeRegionEx(
    IN      PVOID                   Address,
    _When_(VMM_FREE_TYPE_RELEASE == FreeType, _Reserved_)
    _When_(VMM_FREE_TYPE_RELEASE != FreeType, IN)
            QWORD                   Size,
    IN      VMM_FREE_TYPE           FreeType,
    IN      BOOLEAN                 Release,
    IN_OPT  PVMM_RESERVATION_SPACE  VaSpace,
    IN_OPT  PPAGING_LOCK_DATA       PagingData
    )
{
    PVOID alignedAddress;
    QWORD alignedSize;

    ASSERT(Address != NULL);
    ASSERT(IsBooleanFlagOn( FreeType, VMM_FREE_TYPE_RELEASE ) ^ IsBooleanFlagOn(FreeType, VMM_FREE_TYPE_DECOMMIT ));
    ASSERT((IsBooleanFlagOn(FreeType, VMM_FREE_TYPE_RELEASE) && (Size == 0))
           || (IsBooleanFlagOn(FreeType, VMM_FREE_TYPE_DECOMMIT) && (Size != 0)));

    alignedAddress = NULL;
    alignedSize = 0;

    VmReservationSpaceFreeRegion((VaSpace == NULL) ? &m_vmmData.VmmReservationSpace : VaSpace,
                                 Address,
                                 Size,
                                 FreeType,
                                 &alignedAddress,
                                 &alignedSize);

    if (IsFlagOn(FreeType, VMM_FREE_TYPE_DECOMMIT | VMM_FREE_TYPE_RELEASE ))
    {
        ASSERT( NULL != alignedAddress);
        ASSERT( 0 != alignedSize);

        LOG_TRACE_VMM("Will free %U bytes of memory starting from VA: 0x%X\n", alignedSize, alignedAddress );

        // un-map memory
        // this must be called without the reservation lock taken
        MmuUnmapMemoryEx(alignedAddress,
                         alignedSize,
                         Release,
                         PagingData);
    }

    /* Free these allocated FRAME_MAPPING entries in VmmFreeRegionEx(). NOTE: You will probably want to add some additional information in VMM_RESERVATION_SPACE to determine the process to which the structure belongs to. When freeing the FRAME_MAPPING entries, log a message containing the fields of the FRAME_MAPPING being freed.*/
    if (VaSpace != NULL) {
        PPROCESS pProcess;
        pProcess = VaSpace->Process;
        if (pProcess) {
            INTR_STATE oldState;
            PVOID* Context = ExAllocatePoolWithTag(
                PoolAllocateZeroMemory,
                2 * sizeof(PVOID),
                HEAP_TEMP_TAG,
                0
            );
            Context[0] = alignedAddress;
            Context[1] = NULL;
            LockAcquire(&pProcess->AddressMappingsLock, &oldState);
            ForEachElementExecute(
                &pProcess->AddressMappingsHead, SearchInListProcess, Context, FALSE);
            LockRelease(&pProcess->AddressMappingsLock, oldState);

            if (Context[1]) {
				PALLOCATION_MAPPING pMappingAux = (PALLOCATION_MAPPING)Context[1];
				RemoveEntryList(&pMappingAux->ListEntry);
				ExFreePoolWithTag(pMappingAux, HEAP_TEMP_TAG);
            }
			ExFreePoolWithTag(Context, HEAP_TEMP_TAG);
        }

    }

		//if (ProcessIsSystem(pProcess))
		//{
		//	return;
		//}

		//LockAcquire(&pProcess->AddressMappingsLock, &intrState);

		//LIST_ENTRY* pEntry = pProcess->AddressMappingsHead.Flink;
		//while (pEntry != &pProcess->AddressMappingsHead) {
		//	pMapping = CONTAINING_RECORD(pEntry, ALLOCATION_MAPPING, ListEntry);
		//	pEntry = pEntry->Flink;

		//	if (pMapping->VirtualAddress == Address) {
		//		RemoveEntryList(&pMapping->ListEntry);
		//		ExFreePoolWithTag(pMapping, HEAP_MMU_TAG);
		//	}
		//}

		//LockRelease(&pProcess->AddressMappingsLock, intrState);
}

BOOLEAN
VmmSolvePageFault(
    IN      PVOID                   FaultingAddress,
    IN      PAGE_RIGHTS             RightsRequested,
    IN      PPAGING_LOCK_DATA       PagingData
    )
{
    BOOLEAN bSolvedPageFault;
    BOOLEAN bAccessValid;
    STATUS status;
    PPCPU pCpu;
    PAGE_RIGHTS pageRights;
    BOOLEAN uncacheable;
    PFILE_OBJECT pBackingFile;
    QWORD fileOffset;
    BOOLEAN bKernelAddress;
    QWORD bytesReadFromFile;

    ASSERT(INTR_OFF == CpuIntrGetState());
    ASSERT(PagingData != NULL);

    // Virtual Memory. 1
    LOG_TRACE_VMM("Page fault at faulting address 0x%X\n", FaultingAddress);
    LOG_TRACE_VMM("Access rights requested: 0x%X\n", RightsRequested);

    // we will certainly not use the first virtual page of memory
    if (NULL == (PVOID) AlignAddressLower(FaultingAddress, PAGE_SIZE))
    {
        return FALSE;
    }

    bKernelAddress = _VmIsKernelAddress(FaultingAddress);

    if (bKernelAddress && !PagingData->Data.KernelSpace)
    {
        LOG_TRACE_VMM("User code should not access KM pages!\n");

        // Virtual Memory 1. 
		LOG_TRACE_VMM("Faulting process name is 0x%X\n", GetCurrentProcess()->Id);
        return FALSE;
    }
    else if (!bKernelAddress && PagingData->Data.KernelSpace)
    {
        LOG_ERROR("Kernel code should not access UM pages!\n");
        return FALSE;
    }

    bSolvedPageFault = FALSE;
    bAccessValid = FALSE;
    status = STATUS_SUCCESS;
    pCpu = GetCurrentPcpu();
    pageRights = 0;
    uncacheable = FALSE;
    pBackingFile = NULL;
    fileOffset = 0;
    bytesReadFromFile = 0;

    // See if the VA is already committed and retrieve its description (the page rights with which it was mapped,
    // cacheability and for memory backed by files the FILE_OBJECT and corresponding offset in file)
    bAccessValid = VmReservationCanAddressBeAccessed(_VmmRetrieveReservationSpaceForAddress(FaultingAddress),
                                                     FaultingAddress,
                                                     RightsRequested,
                                                     &pageRights,
                                                     &uncacheable,
                                                     &pBackingFile,
                                                     &fileOffset);

    __try
    {
        if (bAccessValid)
        {
            PHYSICAL_ADDRESS pa;
            PVOID alignedAddress;


            // Virtual Memory. 7
            /*Modify the page fault handler such that when the faulty address is on the first page the following will happen:
            a. if page zero is marked as usable (i.e. SyscallMapZeroPage was called and no SyscallUnmapZeroPage was called in the meantime) the OS will allocate a physical frame, will zero it, will map the virtual page zero on the allocated physical frame, and will resume transparently the faulty instruction (and process);
            b. if page zero is marked as unusable (i.e. SyscallUnmapZeroPage was called and no SyscallMapZeroPage was called in the meantime) the OS will terminate the calling process.*/

            PVMM_RESERVATION_SPACE pVmmReservationSpace = _VmmRetrieveReservationSpaceForAddress(FaultingAddress);

            PVMM_RESERVATION pRegion = pVmmReservationSpace->ReservationList;

            if (pRegion != NULL) {
                if ((FaultingAddress >= pRegion->StartVa) && (FaultingAddress < (PVOID)((QWORD)pRegion->StartVa + PAGE_SIZE))) {
                    //               //if (pRegion->checkReserved) {
                    //               //    goto page_alloc;
                    //               //}
                    //               //else {
                    //               //    ProcessTerminate(GetCurrentProcess());
                    //               //}
                                   //if (!pRegion->checkReserved) {
                                   //	ProcessTerminate(GetCurrentProcess());
                    //                   __leave;
                                   //}
                    //           }
                    LOG("pana aci ii bine");
                }
            }

            // Each time a #PF is solved for a user application unmap one 'random' page without releasing the physical memory. When a #PF will occur for that unmapped page remap it to the same physical frame. (Use the lists created at problem 4 for this
			//PALLOCATION_MAPPING pMapping = VmmFindAllocationMappingForAddress(GetCurrentProcess(), FaultingAddress);
   //         if (pMapping != NULL) {
   //             if (!pMapping->IsMapped) {
			//		MmuMapMemoryInternal(pMapping->PhysicalAddress,
			//			PAGE_SIZE,
			//			pageRights,
			//			pMapping->VirtualAddress,
			//			TRUE,
			//			uncacheable,
			//			PagingData
			//		);
			//		pMapping->IsMapped = TRUE;
   //             }
   //         }

            //// solve #PF
            //page_alloc:
            // 1. Reserve one frame of physical memory
            pa = PmmReserveMemory(1);
            ASSERT(NULL != pa);

            alignedAddress = (PVOID)AlignAddressLower(FaultingAddress, PAGE_SIZE);

            // 2. Map the aligned faulting address to the newly acquired physical frame
            MmuMapMemoryInternal(pa,
                                 PAGE_SIZE,
                                 pageRights,
                                 alignedAddress,
                                 TRUE,
                                 uncacheable,
                                 PagingData
                                 );

            if (!PagingData->Data.KernelSpace)
            {
                _VmmAddFrameMappings(pa, alignedAddress, 1);
            }

            // 3. If the virtual address is backed by a file read its contents
            if (pBackingFile != NULL)
            {
                LOGL("Will read data from file 0x%X and offset 0x%X\n", pBackingFile, fileOffset);

                status = IoReadFile(pBackingFile,
                                    PAGE_SIZE,
                                    &fileOffset,
                                    alignedAddress,
                                    &bytesReadFromFile);
                if (!SUCCEEDED(status))
                {
                    LOG_FUNC_ERROR("IoReadFile", status);
                    __leave;
                }

                LOGL("Bytes read 0x%X\n", bytesReadFromFile);
                ASSERT(bytesReadFromFile <= PAGE_SIZE);
            }

            // 4. Zero the rest of the memory (in case the remaining file size was smaller than a page
            /// TODO: check if this is really necessary (we have a ZERO worker thread already!)
            if (bytesReadFromFile != PAGE_SIZE)
            {
                /// TODO: Check if we really need to remove the WP (I'd rather not do this)
                /// According to the Intel manual the WP flag has nothing to do with accessing UM pages
                /// It is more generic, if WP is set => supervisor accesses can write to any virtual address
                /// even if it is read-only
                __writecr0(__readcr0() & ~CR0_WP);
                memzero(PtrOffset(alignedAddress, bytesReadFromFile), PAGE_SIZE - (DWORD)bytesReadFromFile);
                __writecr0(__readcr0() | CR0_WP);
            }

            if (NULL != pCpu)
            {
                // solved another page fault :)
                pCpu->PageFaults = pCpu->PageFaults + 1;
            }
            bSolvedPageFault = TRUE;

			// Virtual Memory. 8
			//PVOID randomUnmappedAddress = VmmGetRandomUnmappedAddress(GetCurrentProcess()); 
   //         if (randomUnmappedAddress != NULL) {
			//	PALLOCATION_MAPPING pRandomMapping = VmmFindAllocationMappingForAddress(GetCurrentProcess(), randomUnmappedAddress);
   //             if (pRandomMapping != NULL) {
			//		UnmapPageAndMakeItNotMapped(pRandomMapping, PagingData);
   //             }
   //         }
        }
    }
    __finally
    {

    }

    return bSolvedPageFault;
}

PVMM_RESERVATION_SPACE
VmmRetrieveReservationSpaceForSystemProcess(
    void
    )
{
    return &m_vmmData.VmmReservationSpace;
}

STATUS
VmmCreateVirtualAddressSpace(
    OUT_PTR struct _VMM_RESERVATION_SPACE** ReservationSpace,
    IN      QWORD                           ReservationMetadataSize,
    IN      PVOID                           StartOfVirtualAddressSpace
    )
{
    STATUS status;
    PVMM_RESERVATION_SPACE pProcessVaHeader;
    PVOID pReservationMetadataStart;

    if (ReservationSpace == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (ReservationSpace == 0)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    if (StartOfVirtualAddressSpace == NULL)
    {
        return STATUS_INVALID_PARAMETER3;
    }

    status = STATUS_SUCCESS;
    pProcessVaHeader = NULL;
    pReservationMetadataStart = NULL;

    __try
    {
        pProcessVaHeader = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(VMM_RESERVATION_SPACE), HEAP_PROCESS_TAG, 0);
        if (pProcessVaHeader == NULL)
        {
            status = STATUS_INSUFFICIENT_MEMORY;
            LOG_FUNC_ERROR_ALLOC("ExAllocatePoolWithTag", sizeof(VMM_RESERVATION_SPACE));
            __leave;
        }

        pReservationMetadataStart = VmmAllocRegionEx(NULL,
                                                     ReservationMetadataSize,
                                                     VMM_ALLOC_TYPE_RESERVE | VMM_ALLOC_TYPE_COMMIT,
                                                     PAGE_RIGHTS_READWRITE,
                                                     FALSE,
                                                     NULL,
                                                     NULL,
                                                     NULL,
                                                     NULL);
        if (pReservationMetadataStart == NULL)
        {
            status = STATUS_INSUFFICIENT_MEMORY;
            LOG_FUNC_ERROR_ALLOC("VmmAllocRegionEx", ReservationMetadataSize);
            __leave;
        }

        VmReservationSpaceInit(pReservationMetadataStart,
                               StartOfVirtualAddressSpace,
                               ReservationMetadataSize,
                               pProcessVaHeader);
        VmReservationSpaceFinishInit(pProcessVaHeader);
    }
    __finally
    {
        if (!SUCCEEDED(status))
        {
            if (pReservationMetadataStart != NULL)
            {
                VmmFreeRegion(pReservationMetadataStart, 0, VMM_FREE_TYPE_RELEASE);
                pReservationMetadataStart = NULL;
            }

            if (pProcessVaHeader != NULL)
            {
                ExFreePoolWithTag(pProcessVaHeader, HEAP_PROCESS_TAG);
                pProcessVaHeader = NULL;
            }
        }
        else
        {
            *ReservationSpace = pProcessVaHeader;
        }
    }

    return status;
}

void
VmmDestroyVirtualAddressSpace(
    _Pre_valid_ _Post_ptr_invalid_
        struct _VMM_RESERVATION_SPACE*      ReservationSpace
    )
{
    ASSERT(ReservationSpace != NULL);

    if (ReservationSpace->ReservationList != NULL)
    {
        /// TODO: go through each reservation belonging to the process and
        /// release all the physical frames used (else we have physical memory leaks :) - not fun)

        VmmFreeRegion(ReservationSpace->ReservationList, 0, VMM_FREE_TYPE_RELEASE);
        ReservationSpace->ReservationList = NULL;
    }

    ExFreePoolWithTag(ReservationSpace, HEAP_PROCESS_TAG);
}

STATUS
VmmIsBufferValid(
    IN          PVOID                               Buffer,
    IN          QWORD                               BufferSize,
    IN          PAGE_RIGHTS                         RightsRequested,
    IN          PVMM_RESERVATION_SPACE              ReservationSpace,
    IN          BOOLEAN                             KernelAccess
    )
{
    STATUS status;
    PAGE_RIGHTS rightsGranted;

    ASSERT(Buffer != NULL);
    ASSERT(BufferSize != 0);
    ASSERT(ReservationSpace != NULL);

    if (!KernelAccess && _VmIsKernelRange(Buffer, BufferSize))
    {
        // We shouldn't be accessing from UM kernel buffers :)
        LOG_TRACE_VMM("Usermode code should not be accessing kernel memory between 0x%X -> 0x%X\n",
                  BufferSize, PtrOffset(BufferSize, BufferSize - 1));
        return STATUS_MEMORY_PREVENTS_USERMODE_ACCESS;
    }

    status = VmReservationReturnRightsForAddress(ReservationSpace,
                                                 Buffer,
                                                 BufferSize,
                                                 &rightsGranted);
    if (!SUCCEEDED(status))
    {
        LOG_TRACE_VMM("VmReservationReturnRightsForAddress", status);
        return status;
    }

    if (!IsBooleanFlagOn(rightsGranted, RightsRequested))
    {
        LOG_ERROR("The VA space has paging rights of 0x%x, but we requested 0x%x. Will certainly not allow!\n",
                  rightsGranted, RightsRequested);
        return STATUS_MEMORY_INSUFFICIENT_ACCESS_RIGHTS;
    }

    return STATUS_SUCCESS;
}

static
void
_VmSetupPagingStructure(
    IN      PPAGING_DATA            PagingData,
    IN      PVOID                   PagingStructure
    )
{
    PHYSICAL_ADDRESS physicalAddr;
    PTE_MAP_FLAGS flags = { 0 };

    ASSERT(NULL != PagingData);
    ASSERT(NULL != PagingStructure);

    // request 1 frame of physical memory
    physicalAddr = _VmRetrieveNextPhysicalAddressForPagingStructure(PagingData);
    flags.Writable = TRUE;
    flags.Executable = TRUE;
    flags.PagingStructure = TRUE;
    flags.UserAccess = !PagingData->KernelSpace;

    // for paging structure PA2VA can always be used :)
    PteMap(PagingStructure, physicalAddr, flags);

    PageInvalidateTlb((PVOID)PA2VA(physicalAddr));

    // Zero the current paging structure entry => we cannot get stray memory accesses
    memzero((PVOID)PA2VA(physicalAddr), PAGE_SIZE);
}

static
BOOL_SUCCESS
BOOLEAN
_VmDeterminePatIndices(
    IN      QWORD                   PatValues,
    OUT     PBYTE                   WbIndex,
    OUT     PBYTE                   UcIndex
    )
{
    BOOLEAN bFoundWb;
    BOOLEAN bFoundUc;
    PBYTE patArrayValue;

    ASSERT( NULL != WbIndex );
    ASSERT( NULL != UcIndex );

    bFoundWb = bFoundUc = FALSE;
    patArrayValue = (PBYTE) &PatValues;

    for (BYTE i = 0; i < sizeof(QWORD); ++i)
    {
        if (MemoryCachingStrongUncacheable == patArrayValue[i] )
        {
            if (!bFoundUc)
            {
                bFoundUc = TRUE;
                *UcIndex = i;
            }
        }
        else if (MemoryCachingWriteBack == patArrayValue[i])
        {
            if( !bFoundWb)
            {
                bFoundWb = TRUE;
                *WbIndex = i;
            }
        }
    }

    return bFoundWb && bFoundUc;
}

static
void
_VmWalkPagingTables(
    IN      PML4                        Cr3,
    IN      PVOID                       BaseAddress,
    IN      QWORD                       Size,
    IN      PFUNC_PageWalkCallback      WalkCallback,
    IN_OPT  PVOID                       Context
    )
{
    // we may need to map multiple pages => we iterate until we map all the
    // addresses
    for(QWORD offset = 0;
        offset < Size;
        offset = offset + PAGE_SIZE)
    {
        WORD offsets[4];
        BOOLEAN bContinue;
        PVOID currentVa;
        PHYSICAL_ADDRESS curStructPa;

        // address to map
        currentVa = PtrOffset(BaseAddress, offset);

        offsets[0] = MASK_PML4_OFFSET(currentVa);
        offsets[1] = MASK_PDPTE_OFFSET(currentVa);
        offsets[2] = MASK_PDE_OFFSET(currentVa);
        offsets[3] = MASK_PTE_OFFSET(currentVa);

        bContinue = FALSE;

        curStructPa = (PHYSICAL_ADDRESS)(Cr3.Pcide.PhysicalAddress << SHIFT_FOR_PHYSICAL_ADDR);

        for (BYTE i = PAGING_TABLES_FIRST_LEVEL;
             i <= PAGING_TABLES_LAST_LEVEL;
             ++i)
        {
            PT_ENTRY* pCurrentEntry;

            pCurrentEntry = (PT_ENTRY*)PA2VA(curStructPa);

            pCurrentEntry = &(pCurrentEntry[offsets[i-1]]);

            if (!WalkCallback(Cr3,
                              pCurrentEntry,
                              currentVa,
                              i,
                              Context))
            {
                bContinue = TRUE;
                break;
            }

            if (i != PAGING_TABLES_LAST_LEVEL)
            {
                ASSERT(((PD_ENTRY_PT*)pCurrentEntry)->PageSize == 0);
            }

            curStructPa = PteGetPhysicalAddress(pCurrentEntry);
        }

        if (bContinue)
        {
            continue;
        }
    }
}

static
BOOLEAN
(__cdecl _VmMapPage)(
    IN      PML4                    Cr3,
    IN      PVOID                   PageTable,
    IN      PVOID                   VirtualAddress,
    IN      BYTE                    PageLevel,
    IN_OPT  PVOID                   Context
    )
{
    PVMM_MAP_UNMAP_PAGE_WALK_CONTEXT pPageContext;

    UNREFERENCED_PARAMETER(Cr3);

    ASSERT(PageTable != NULL);
    ASSERT(VirtualAddress != NULL);
    ASSERT(PAGING_TABLES_FIRST_LEVEL <= PageLevel && PageLevel <= PAGING_TABLES_LAST_LEVEL);

    pPageContext = (PVMM_MAP_UNMAP_PAGE_WALK_CONTEXT) Context;
    ASSERT(pPageContext != NULL);

    if (PteIsPresent(PageTable) &&
        !((PageLevel == PAGING_TABLES_LAST_LEVEL) && pPageContext->Invalidate))
    {
        return TRUE;
    }

    if (PageLevel == PAGING_TABLES_LAST_LEVEL)
    {
        PHYSICAL_ADDRESS physAddr = (PHYSICAL_ADDRESS)(PtrOffset(pPageContext->PhysicalAddressBase,
                                                       PtrDiff(VirtualAddress, pPageContext->VirtualAddressBase)));
        PTE_MAP_FLAGS flags = { 0 };

        flags.Executable = IsBooleanFlagOn(pPageContext->PageRights, PAGE_RIGHTS_EXECUTE);
        flags.Writable = IsBooleanFlagOn(pPageContext->PageRights, PAGE_RIGHTS_WRITE);
        flags.PatIndex = pPageContext->Uncacheable ? m_vmmData.UncacheableIndex : m_vmmData.WriteBackIndex;
        flags.GlobalPage = pPageContext->PagingData->KernelSpace;
        flags.UserAccess = !pPageContext->PagingData->KernelSpace;

        PteMap(PageTable, physAddr, flags);

        PageInvalidateTlb(VirtualAddress);

        /// TODO: signal other processors to invalidate the mapping
    }
    else
    {
        // paging structure
        _VmSetupPagingStructure(pPageContext->PagingData, PageTable);
    }

    // continue iteration
    return TRUE;
}

static
BOOLEAN
(__cdecl _VmUnmapPage)(
    IN      PML4                    Cr3,
    IN      PVOID                   PageTable,
    IN      PVOID                   VirtualAddress,
    IN      BYTE                    PageLevel,
    IN_OPT  PVOID                   Context
    )
{
    PVMM_MAP_UNMAP_PAGE_WALK_CONTEXT pPageContext;

    UNREFERENCED_PARAMETER(Cr3);

    ASSERT(PageTable != NULL);
    ASSERT(VirtualAddress != NULL);
    ASSERT(PAGING_TABLES_FIRST_LEVEL <= PageLevel && PageLevel <= PAGING_TABLES_LAST_LEVEL);

    pPageContext = (PVMM_MAP_UNMAP_PAGE_WALK_CONTEXT) Context;
    ASSERT(pPageContext != NULL);

    if (!PteIsPresent(PageTable))
    {
        return FALSE;
    }

    if (PageLevel == PAGING_TABLES_LAST_LEVEL)
    {
        PHYSICAL_ADDRESS pa = PteGetPhysicalAddress(PageTable);

        PteUnmap(PageTable);

        PageInvalidateTlb(VirtualAddress);

        if (pPageContext->ReleaseMemory)
        {
            MmuReleaseMemory(pa, 1);
        }

        /// TODO: signal other processors to invalidate the mapping
    }

    // continue iteration
    return TRUE;
}

static
BOOLEAN
(__cdecl _VmRetrievePhyAccess)(
    IN      PML4                    Cr3,
    IN      PVOID                   PageTable,
    IN      PVOID                   VirtualAddress,
    IN      BYTE                    PageLevel,
    IN_OPT  PVOID                   Context
    )
{
    PVMM_RETRIEVE_PHYS_ACCESS_PAGE_WALK_CONTEXT pPageContext;
    BOOLEAN bContinue;

    UNREFERENCED_PARAMETER(Cr3);

    ASSERT(PageTable != NULL);
    ASSERT(VirtualAddress != NULL);
    ASSERT(PAGING_TABLES_FIRST_LEVEL <= PageLevel && PageLevel <= PAGING_TABLES_LAST_LEVEL);

    pPageContext = (PVMM_RETRIEVE_PHYS_ACCESS_PAGE_WALK_CONTEXT) Context;
    ASSERT(pPageContext != NULL);

    bContinue = TRUE;

    if (!PteIsPresent(PageTable))
    {
        pPageContext->PhysicalAddress = NULL;
        return FALSE;
    }

    if (PageLevel < PAGING_TABLES_LAST_LEVEL - 1)
    {
        return TRUE;
    }

    __try
    {
        if (PageLevel == PAGING_TABLES_LAST_LEVEL - 1)
        {
            PD_ENTRY_2MB* pPdEntry = (PD_ENTRY_2MB*) PageTable;

            if (pPdEntry->PageSize == 1)
            {
                pPageContext->PhysicalAddress = PtrOffset(PteLargePageGetPhysicalAddress(PageTable),
                                                          AddressOffset(VirtualAddress, PAGE_2MB_OFFSET + 1));

                bContinue = FALSE;
                __leave;
            }
        }
        else
        {
            ASSERT(PageLevel == PAGING_TABLES_LAST_LEVEL);

            pPageContext->PhysicalAddress = PteGetPhysicalAddress(PageTable);
            bContinue = FALSE;
            __leave;
        }
    }
    __finally
    {
        if (!bContinue)
        {
            BOOLEAN bInvalidatePage = FALSE;
            PT_ENTRY* pPtEntry = (PT_ENTRY*)PageTable;

            pPageContext->Accessed = (BOOLEAN) pPtEntry->Accessed;
            pPageContext->Dirty = (BOOLEAN) pPtEntry->Dirty;

            if (pPageContext->ClearAccessed)
            {
                pPtEntry->Accessed = FALSE;
                bInvalidatePage = TRUE;
            }

            if (pPageContext->ClearDirty)
            {
                pPtEntry->Dirty = FALSE;
                bInvalidatePage = TRUE;
            }

            if (bInvalidatePage)
            {
                // 4.10.4.2 Recommended Invalidation
                // If software modifies a paging - structure entry that maps a page(rather than referencing
                // another paging structure), it should execute INVLPG for any linear address with a page
                // number whose translation uses that paging - structure entry.

                // 4.10.4.3 Optional Invalidation
                // If a paging - structure entry is modified to change the accessed flag from 1 to 0, failure
                // to perform an invalidation may result in the processor not setting that bit in response to
                // a subsequent access to a linear address whose translation uses the entry.Software cannot
                // interpret the bit being clear as an indication that such an access has not occurred.

                // If software modifies a paging - structure entry that identifies the final physical address
                // for a linear address (either a PTE or a paging - structure entry in which the PS flag is 1)
                // to change the dirty flag from 1 to 0, failure to perform an invalidation may result in the
                // processor not setting that bit in response to a subsequent write to a linear address whose
                // translation uses the entry.Software cannot interpret the bit being clear as an indication
                // that such a write has not occurred.
                PageInvalidateTlb(VirtualAddress);

                /// TODO: signal other processors to invalidate the mapping
            }
        }
    }

    return bContinue;
}

// Virtual Memory. 5
static     PHYSICAL_ADDRESS physicalAddressSwap;
STATUS
VmmSwapOut(
    IN PPAGING_LOCK_DATA PagingData,
    IN PVOID VirtualAddress
)
{
    PVOID swapSlotAddress;

	ASSERT(PagingData != NULL);

	// 1. Allocate a swap slot
	swapSlotAddress = VmmAllocRegionEx(NULL,
		PAGE_SIZE,
		VMM_ALLOC_TYPE_COMMIT | VMM_ALLOC_TYPE_RESERVE,
		PAGE_RIGHTS_READWRITE,
		FALSE,
		NULL,
		NULL,
		PagingData,
		NULL
	);
	if (swapSlotAddress == NULL)
	{
		LOG_ERROR("VmmAllocRegionEx failed!\n");
		return STATUS_UNSUCCESSFUL;
	}

	// 2. Map the swap slot to the virtual address
    physicalAddressSwap = PmmReserveMemory(1);
	if (physicalAddressSwap == NULL)
	{
		LOG_ERROR("PmmReserveMemory failed!\n");
		VmmFreeRegion(swapSlotAddress, 0, VMM_FREE_TYPE_RELEASE);
		return STATUS_UNSUCCESSFUL;
	}

	MmuMapMemoryInternal(physicalAddressSwap,
		PAGE_SIZE,
		PAGE_RIGHTS_READWRITE,
		VirtualAddress,
		TRUE,
		FALSE,
		PagingData
	);

	// 3. Copy the contents of the virtual address to the swap slot
	memcpy(swapSlotAddress, VirtualAddress, PAGE_SIZE);

	// 4. Unmap the virtual address
	MmuUnmapMemoryEx(VirtualAddress, PAGE_SIZE, TRUE, PagingData);

	// 5. Map the swap slot to the virtual address
	MmuMapMemoryInternal(physicalAddressSwap,
		PAGE_SIZE,
		PAGE_RIGHTS_READWRITE,
		VirtualAddress,
		TRUE,
		FALSE,
		PagingData
	);

	// 6. Release the physical memory
	MmuReleaseMemory(physicalAddressSwap, 1);

	return STATUS_SUCCESS;
}

// Virtual Memory. 6
// On each scheduler tick, goes through the list of physical to virtual mappings (created at problem 4) for the current process and displays a message for each dirty or accessed page. [
void
VmmDisplayDirtyAccessedPages(
    void
)
{
	PPROCESS pProcess = GetCurrentProcess();
	INTR_STATE oldState;

	LockAcquire(&pProcess->AddressMappingsLock, &oldState);

	PLIST_ENTRY pCurrentEntry = pProcess->AddressMappingsHead.Flink;
    while (pCurrentEntry != &pProcess->AddressMappingsHead)
    {
		PALLOCATION_MAPPING pAddressMapping = CONTAINING_RECORD(pCurrentEntry, ALLOCATION_MAPPING, ListEntry);
        PML4 cr3;
		BOOLEAN accessedFlag;
		BOOLEAN dirtyFlag;
        cr3.Raw = (QWORD)pProcess->PagingData->Data.BasePhysicalAddress;
        PHYSICAL_ADDRESS physicalAdd = VmmGetPhysicalAddressEx(
            cr3,
            pAddressMapping->VirtualAddress,
            &accessedFlag,
            &dirtyFlag
        );
		if (accessedFlag || dirtyFlag)
		{
			LOG_TRACE_VMM("Accessed page at 0x%X: accessed %s, dirty %s\n", pAddressMapping->VirtualAddress, accessedFlag, dirtyFlag);
		}

        if (!physicalAdd)
		{
			LOG_ERROR("VmmGetPhysicalAddressEx failed!\n");
			return;
		}

        if (accessedFlag || dirtyFlag)
            pAddressMapping->Size++;

        pCurrentEntry = pCurrentEntry->Flink;
    }

	LockRelease(&pProcess->AddressMappingsLock, oldState);
}

// Virtual Memory. 7
void
VmmMakePageUsable(
	PVMM_RESERVATION_SPACE ReservationSpace
)
{
	PVMM_RESERVATION pRegion = ReservationSpace->ReservationList;

	if (pRegion != NULL) {
		if (pRegion->checkReserved) {
			pRegion->checkReserved = FALSE;
		}
	}
}


// Virtual Memory. 7
void 
VmmMakePageUnusable(
	PVMM_RESERVATION_SPACE ReservationSpace
	)
{
	PVMM_RESERVATION pRegion = ReservationSpace->ReservationList;

	if (pRegion != NULL) {
		if (!pRegion->checkReserved) {
			pRegion->checkReserved = TRUE;
		}
	}
}

// Virtual Memory. 8
static
PALLOCATION_MAPPING
VmmFindAllocationMappingForAddress(
	PPROCESS pProcess,
	PVOID virtualAdd
)
{
	INTR_STATE oldState;

	LockAcquire(&pProcess->AddressMappingsLock, &oldState);

    PALLOCATION_MAPPING pMapping = NULL;

	PLIST_ENTRY pCurrentEntry = pProcess->AddressMappingsHead.Flink;
	while (pCurrentEntry != &pProcess->AddressMappingsHead)
	{
		PALLOCATION_MAPPING pAddressMapping = CONTAINING_RECORD(pCurrentEntry, ALLOCATION_MAPPING, ListEntry);
        if (pAddressMapping->VirtualAddress == virtualAdd) {
            pMapping = pAddressMapping;
            break;
        }
		pCurrentEntry = pCurrentEntry->Flink;
	}

	LockRelease(&pProcess->AddressMappingsLock, oldState);

	return pMapping;
}

// Virtual Memory. 8
PVOID
VmmGetRandomUnmappedAddress(
    PPROCESS pProcess
)
{
    INTR_STATE oldState;

    LockAcquire(&pProcess->AddressMappingsLock, &oldState);

    PVOID randomUnmappedAddress = NULL;

    PLIST_ENTRY pCurrentEntry = pProcess->AddressMappingsHead.Flink;
    while (pCurrentEntry != &pProcess->AddressMappingsHead)
    {
        PALLOCATION_MAPPING pAddressMapping = CONTAINING_RECORD(pCurrentEntry, ALLOCATION_MAPPING, ListEntry);
        if (pAddressMapping->IsMapped) {
            randomUnmappedAddress = pAddressMapping->VirtualAddress;
            break;
        }
        pCurrentEntry = pCurrentEntry->Flink;
    }

    LockRelease(&pProcess->AddressMappingsLock, oldState);

    return randomUnmappedAddress;
}

// Virtual Memory. 8
void
UnmapPageAndMakeItNotMapped(
	PALLOCATION_MAPPING pMapping,
	PPAGING_LOCK_DATA PagingData
)
{
	if (pMapping->IsMapped) {
		MmuUnmapMemoryEx(pMapping->VirtualAddress, PAGE_SIZE, TRUE, PagingData);
		pMapping->IsMapped = FALSE;
	}
}