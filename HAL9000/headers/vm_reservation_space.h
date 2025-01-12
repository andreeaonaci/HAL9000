#pragma once

#include "mem_structures.h"
#include "vmm.h"
#include "bitmap.h"

typedef struct _FILE_OBJECT *PFILE_OBJECT;


typedef enum _VMM_RESERVATION_STATE
{
    VmmReservationStateFree = 0x0,
    VmmReservationStateUsed = 0x1,
    VmmReservationStateLast = 0x2,
} VMM_RESERVATION_STATE;

// A reservation is allocated each time a process reserves an area of
// virtual memory. The commit bitmap is used to distinguish between the
// reserved memory and the committed memory.
typedef struct _VMM_RESERVATION
{
    // Starting addresses of the virtual memory allocation
    PVOID                   StartVa;

    // Size of the allocation
    QWORD                   Size;

    // The rights with which the memory was allocated
    PAGE_RIGHTS             PageRights;

    // The state of the this structure, this is used for finding the
    // next free slot
    VMM_RESERVATION_STATE   State;

    // If TRUE memory will be set as strong uncacheable (UC)
    // If FALSE the memory will be set as write back (WB)
    BOOLEAN                 Uncacheable;

    // Used for memory backed up by files
    // Indicates the file which holds the data
    PFILE_OBJECT            BackingFile;

    // Describes which pages of the virtual memory reserved are actually
    // committed, i.e. which are valid when a #PF occurs
    BITMAP                  CommitBitmap;

    // Virtual Memory. 7
    BOOLEAN 			 checkReserved;
} VMM_RESERVATION, * PVMM_RESERVATION;

typedef struct _VMM_RESERVATION_SPACE
{
    // Because we have an effectively infinite virtual address space
    // we will never decrement this pointer and the virtual addresses
    // allocated will be strictly monotonically increasing
    volatile PVOID      FreeVirtualAddressPointer;

    // Space from which we can allocate virtual addresses
    PVOID               StartOfVirtualAddressSpace;

    PVOID               BitmapAddressStart;
    QWORD               ReservedAreaSize;

    QWORD               TotalMetadataSize;

    RW_SPINLOCK         ReservationLock;

    PPROCESS Process;

    _Guarded_by_(ReservationLock)
    PBYTE               FreeBitmapAddress;

	_Requires_lock_held_(ReservationLock)
    struct _VMM_RESERVATION*    ReservationList;
} VMM_RESERVATION_SPACE, *PVMM_RESERVATION_SPACE;

//******************************************************************************
// Function:     VmReservationSpaceInit
// Description:  
// Returns:      void
// Parameter:    IN PVOID ReservationMetadataBaseAddress - represents the virtual
//               address where the metadata describing the virtual reservations
//               will be placed
// Parameter:    IN_OPT PVOID ReservationBaseAddress - the address from which the
//               allocations should start, if NULL they start at the end of the
//               metadata.
// Parameter:    IN QWORD ReservationMetadataSize - size of VA space to reserve
//               for the metadata.
//******************************************************************************
_No_competing_thread_
void
VmReservationSpaceInit(
    IN                      PVOID                   ReservationMetadataBaseAddress,
    IN_OPT                  PVOID                   ReservationBaseAddress,
    IN                      QWORD                   ReservationMetadataSize,
    OUT                     PVMM_RESERVATION_SPACE  ReservationSpace
    );

_No_competing_thread_
void
VmReservationSpaceFinishInit(
    INOUT                   PVMM_RESERVATION_SPACE  ReservationSpace
    );

__forceinline
RET_NOT_NULL
PVOID
VmReservationSpaceDetermineNextFreeVirtualAddress(
    INOUT                   PVMM_RESERVATION_SPACE  ReservationSpace,
    IN                      QWORD                   Size
    )
{
    ASSERT(ReservationSpace != NULL);

    return (PVOID) _InterlockedExchangeAdd64(&ReservationSpace->FreeVirtualAddressPointer, Size);
}

//******************************************************************************
// Function:     VmReservationCanAddressBeAccessed
// Description:  Checks if an Address belonging to a VA reservation space is
//               valid for access with the RightsRequested.
// Returns:      BOOLEAN - TRUE the address can be accessed with the requested
//               rights.
//                       - FALSE the address is either not committed or the
//               rights requested exceed those of the commitment.
// Parameter:    INOUT PVMM_RESERVATION_SPACE ReservationSpace
// Parameter:    IN PVOID FaultingAddress
// Parameter:    IN PAGE_RIGHTS RightsRequested
// Parameter:    OUT PAGE_RIGHTS * MemoryRights
// Parameter:    OUT BOOLEAN * Uncacheable
// Parameter:    OUT_PTR_MAYBE_NULL PFILE_OBJECT * BackingFile
// Parameter:    OUT QWORD * FileOffset
//******************************************************************************
BOOLEAN
VmReservationCanAddressBeAccessed(
    INOUT                   PVMM_RESERVATION_SPACE  ReservationSpace,
    IN                      PVOID                   FaultingAddress,
    IN                      PAGE_RIGHTS             RightsRequested,
    OUT                     PAGE_RIGHTS*            MemoryRights,
    OUT                     BOOLEAN*                Uncacheable,
    OUT_PTR_MAYBE_NULL      PFILE_OBJECT*           BackingFile,
    OUT                     QWORD*                  FileOffset
    );

STATUS
VmReservationSpaceAllocRegion(
    IN                      PVMM_RESERVATION_SPACE  ReservationSpace,
    IN_OPT                  PVOID                   BaseAddress,
    IN                      QWORD                   Size,
    IN                      VMM_ALLOC_TYPE          AllocType,
    IN                      PAGE_RIGHTS             Rights,
    IN                      BOOLEAN                 Uncacheable,
    IN_OPT                  PFILE_OBJECT            FileObject,
    OUT                     PVOID*                  MappedAddress,
    OUT                     QWORD*                  MappedSize
    );

void
VmReservationSpaceFreeRegion(
    INOUT                   PVMM_RESERVATION_SPACE  ReservationSpace,
    IN                      PVOID                   Address,
    _When_(VMM_FREE_TYPE_RELEASE == FreeType, IN_OPT)
    _When_(VMM_FREE_TYPE_RELEASE != FreeType, IN)
                            QWORD                   Size,
    IN                      VMM_FREE_TYPE           FreeType,
    OUT                     PVOID*                  AlignedAddress,
    OUT                     QWORD*                  AlignedSize
    );

STATUS
VmReservationReturnRightsForAddress(
    IN                      PVMM_RESERVATION_SPACE  ReservationSpace,
    IN                      PVOID                   Address,
    IN                      QWORD                   Size,
    OUT                     PAGE_RIGHTS*            Rights
    );
