#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "io.h"
#include "vmm.h"
#include "iomu.h"
#include "thread_internal.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

// Userprog. 6
static BOOLEAN SyscallDisabled = FALSE;

// Userprog. 7
typedef struct GLOBAL_VARIABLE
{
	char VariableName[MAX_PATH];
	QWORD Value;
	LIST_ENTRY ListOfGlobalVariables;
} GLOBAL_VARIABLE, * PGLOBAL_VARIABLE;

#define MAX_GLOBAL_VARIABLES 100

// Userprog. 7
LIST_ENTRY ListGlobalVariablesHead;
LOCK GlobalVariablesLock;

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Userprog. 6
        if (!SyscallDisabled) {
            // Dispatch syscalls
            switch (sysCallId)
            {
            case SyscallIdIdentifyVersion:
                status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
                break;
                // STUDENT TODO: implement the rest of the syscalls
            case SyscallIdProcessExit:
                status = SyscallProcessExit((STATUS)*pSyscallParameters);
                break;
            case SyscallIdThreadExit:
                status = SyscallThreadExit((STATUS)*pSyscallParameters);
                break;
            case SyscallIdFileWrite:
                status = SyscallFileWrite(
                    (UM_HANDLE)pSyscallParameters[0],
                    (PVOID)pSyscallParameters[1],
                    (QWORD)pSyscallParameters[2],
                    (QWORD*)pSyscallParameters[3]
                );
                break;
            case SyscallIdMemset:
                status = SyscallMemset(
                    (PBYTE)pSyscallParameters[0],
                    (DWORD)pSyscallParameters[1],
                    (BYTE)pSyscallParameters[2]
                );
                break;
            case SyscallIdProcessCreate:
                status = SyscallProcessCreate(
                    (char*)pSyscallParameters[0],
                    (QWORD)pSyscallParameters[1],
                    (char*)pSyscallParameters[2],
                    (QWORD)pSyscallParameters[3],
                    (UM_HANDLE*)pSyscallParameters[4]
                );
                break;
			case SyscallIdDisableSyscalls:
				status = SyscallDisableSyscalls((BOOLEAN)*pSyscallParameters);
				break;
            case SyscallIdSetGlobalVariable:
				status = SyscallSetGlobalVariable(
					(char*)pSyscallParameters[0],
					(DWORD)pSyscallParameters[1],
					(QWORD)pSyscallParameters[2]
				);
				break;
			case SyscallIdVirtualAlloc:
				status = SyscallVirtualAlloc(
					(PVOID*)pSyscallParameters[0],
					(QWORD)pSyscallParameters[1],
					(DWORD)pSyscallParameters[2],
					(PAGE_RIGHTS)pSyscallParameters[3],
					(UM_HANDLE)pSyscallParameters[4],
					(QWORD)pSyscallParameters[5],
					(PVOID*)pSyscallParameters[6]
				);
				break;
			case SyscallIdGetGlobalVariable:
				status = SyscallGetGlobalVariable(
					(char*)pSyscallParameters[0],
                    (DWORD)pSyscallParameters[1],
                    (PQWORD)pSyscallParameters[2]
				);
				break;
            // Userprog. 8
            case SyscallIdMutexInit:
				status = SyscallMutexInit((UM_HANDLE*)pSyscallParameters[0]);
				break;
			case SyscallIdMutexAcquire:
				status = SyscallMutexAcquire((UM_HANDLE)pSyscallParameters[0]);
				break;
			case SyscallIdMutexRelease:
				status = SyscallMutexRelease((UM_HANDLE)pSyscallParameters[0]);
				break;
			case SyscallIdMutexDestroy:
				status = SyscallMutexDestroy((UM_HANDLE)pSyscallParameters[0]);
				break;
            default:
                LOG_ERROR("Unimplemented syscall called from User-space!\n");
                status = STATUS_UNSUPPORTED;
                break;
            }
        }
        else
        {
            switch (sysCallId)
            {
            case SyscallIdDisableSyscalls:
                status = SyscallDisableSyscalls((BOOLEAN)*pSyscallParameters);
                break;
            default:
                LOG_ERROR("Unimplemented syscall called from User-space!\n");
                status = STATUS_UNSUPPORTED;
                break;
            }
        }
    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{
	LockInit(&GlobalVariablesLock);
	InitializeListHead(&ListGlobalVariablesHead);
}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
// Userprog. 1
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls

// Userprog. 1
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
	LOG("[%s]: Process will exit with status 0x%x\n", ProcessGetName(NULL), ExitStatus);
	PPROCESS pProcess = GetCurrentProcess();
	if (pProcess != NULL) {
		ProcessTerminate(pProcess);
	}
    else
		return STATUS_UNSUCCESSFUL;
	return STATUS_SUCCESS;
}

// Userprog. 1
STATUS
SyscallThreadExit(
IN  STATUS                      ExitStatus
)
{
    ThreadExit(ExitStatus);
	//LOG("[%s]: Thread will exit with status 0x%x\n", ProcessGetName(NULL), ExitStatus);
    return STATUS_SUCCESS;
}

// Userprog. 2
STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    if (BytesWritten == NULL) {
        return STATUS_UNSUCCESSFUL;

    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {

        *BytesWritten = BytesToWrite;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
        return STATUS_SUCCESS;


    }

    *BytesWritten = BytesToWrite;
    return STATUS_SUCCESS;
}

// Userprog. 4
STATUS
SyscallMemset (
    OUT_WRITES(BytesToWrite)    PBYTE   Address,
    IN                          DWORD   BytesToWrite,
    IN                          BYTE    ValueToWrite
)
{
	if (Address == NULL) {
		return STATUS_INVALID_PARAMETER1;
	}

	STATUS status = MmuIsBufferValid(Address, BytesToWrite, PAGE_RIGHTS_WRITE, GetCurrentProcess());
	if (!SUCCEEDED(status)) {
		return STATUS_INVALID_PARAMETER1;
	}

	memset(Address, ValueToWrite, BytesToWrite);
	return STATUS_SUCCESS;
}

// Userprog. 5
//Maintain the list of children for each process. If the parent of a process dies, you should move the dying process children to have as the parent the system process.
//NOTE: You will need to implement SyscallIdProcessCreate for this to work, you can directly return the PID as the UM_HANDLE.
STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{
    INTR_STATE oldState;

	if (ProcessPath == NULL || ProcessHandle == NULL) {
		return STATUS_INVALID_PARAMETER1;
	}

	if (PathLength == 0) {
		return STATUS_INVALID_PARAMETER2;
	}

	if (ArgLength == 0) {
		return STATUS_INVALID_PARAMETER4;
	}

    char ProcessActualPath[MAX_PATH];

    if (ProcessPath == strrchr(ProcessPath, '\\'))
    {
        sprintf(ProcessActualPath, "C:\\Applications\\%s", ProcessPath);
    }
    else
    {
        strcpy(ProcessActualPath, ProcessPath);
    }

	STATUS status = STATUS_SUCCESS;
	PPROCESS pProcess;
	status = ProcessCreate(ProcessActualPath, Arguments, &pProcess);

	if (!SUCCEEDED(status)) {
		return status;
	}


    *ProcessHandle = GetCurrentProcess()->Id;

	LockAcquire(&pProcess->ChildrenListLock, &oldState);
	InsertTailList(&GetCurrentProcess()->ChildrenListHead, &pProcess->ChildrenList);
	LockRelease(&pProcess->ChildrenListLock, oldState);

	return STATUS_SUCCESS;
}

// Userprog. 6
// Implement a new system call SyscallIdDisableSyscalls which depending on the parameter either disables all other system calls effectively causing them to fail or enables them.
/*    // When Disable == TRUE => all system calls except SyscallDisableSyscalls will fail
    // When Disable == FALSE => all system calls work normally
    STATUS
    SyscallDisableSyscalls(
        IN      BOOLEAN     Disable
        );*/
STATUS
SyscallDisableSyscalls(
	IN      BOOLEAN     Disable
)
{
	SyscallDisabled = Disable;
	return STATUS_SUCCESS;
}

/*Implement two system calls SyscallIdSetGlobalVariable and SyscallIdGetGlobalVariable for processes to be able to share information.

    STATUS
    SyscallSetGlobalVariable(
        IN_READS_Z(VarLength)           char*   VariableName,
        IN                              DWORD   VarLength,
        IN                              QWORD   Value
        );
        
    STATUS
    SyscallGetGlobalVariable(
        IN_READS_Z(VarLength)           char*   VariableName,
        IN                              DWORD   VarLength,
        OUT                             PQWORD  Value
        );
        
    Usage example:
    Process 0:
    
    SyscallSetGlobalVariable("cool", sizeof("cool"), 0x300);
    
    Process 1:
    QWORD value;
    
    // this should fail because "Cool" doesn't exist
    SyscallGetGlobalVariable("Cool", sizeof("Cool", &value);
    
    // this should succeed and set value <- 0x300
    SyscallGetGlobalVariable("cool", sizeof("cool", &value);*/

STATUS
SyscallSetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    IN                              QWORD   Value
)
{
    if (VariableName == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    if (VarLength == 0 || VarLength >= MAX_PATH) {
        return STATUS_INVALID_PARAMETER2;
    }

    INTR_STATE oldState;
    LockAcquire(&GlobalVariablesLock, &oldState);

    PLIST_ENTRY pEntry;
    PGLOBAL_VARIABLE pGlobalVar;
    BOOLEAN found = FALSE;

    // Check if the variable already exists
    for (pEntry = ListGlobalVariablesHead.Flink; pEntry != &ListGlobalVariablesHead; pEntry = pEntry->Flink) {
        pGlobalVar = CONTAINING_RECORD(pEntry, GLOBAL_VARIABLE, ListOfGlobalVariables);
        if (strcmp(pGlobalVar->VariableName, VariableName) == 0) {
            pGlobalVar->Value = Value;
            found = TRUE;
            break;
        }
    }

    if (!found) {
        pGlobalVar = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(GLOBAL_VARIABLE), 'glbl', 0);
        if (pGlobalVar == NULL) {
            LockRelease(&GlobalVariablesLock, oldState);
            return STATUS_NO_MORE_OBJECTS;
        }

        strcpy(pGlobalVar->VariableName, VariableName);
        pGlobalVar->Value = Value;
        InsertTailList(&ListGlobalVariablesHead, &pGlobalVar->ListOfGlobalVariables);
    }

    LockRelease(&GlobalVariablesLock, oldState);
    return STATUS_SUCCESS;
}

STATUS
SyscallGetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    OUT                             PQWORD  Value
)
{
    if (VarLength == 0 || VarLength >= MAX_PATH) {
        return STATUS_INVALID_PARAMETER2;
    }

    INTR_STATE oldState;
    LockAcquire(&GlobalVariablesLock, &oldState);

    PLIST_ENTRY pEntry;
    PGLOBAL_VARIABLE pGlobalVar;
    BOOLEAN found = FALSE;

    // Search for the variable
    for (pEntry = ListGlobalVariablesHead.Flink; pEntry != &ListGlobalVariablesHead; pEntry = pEntry->Flink) {
        pGlobalVar = CONTAINING_RECORD(pEntry, GLOBAL_VARIABLE, ListOfGlobalVariables);
        if (strcmp(pGlobalVar->VariableName, VariableName) == 0) {
            *Value = pGlobalVar->Value;
            found = TRUE;
            break;
        }
    }

    LockRelease(&GlobalVariablesLock, oldState);

    if (!found) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

// Virtual Memory. 3
//Implement the basic SyscallIdVirtualAlloc system call ignoring the Key parameter.
STATUS
SyscallVirtualAlloc(
	IN_OPT PVOID* Address,
	IN      QWORD   Size,
	IN      DWORD   AllocType,
	IN      PAGE_RIGHTS Protect,
	IN_OPT  UM_HANDLE FileHandle,
	IN_OPT  QWORD   Key,
	OUT     PVOID* FinalAddress
)
{
	UNREFERENCED_PARAMETER(FileHandle);
	UNREFERENCED_PARAMETER(Key);

	if (Address == NULL) {
		return STATUS_INVALID_PARAMETER1;
	}

	if (Size == 0) {
		return STATUS_INVALID_PARAMETER2;
	}

	PPROCESS pProcess = GetCurrentProcess();

	if (pProcess == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	*FinalAddress = VmmAllocRegionEx(
        *Address,
		Size,
		AllocType,
		Protect,
        FALSE,
        NULL,
		pProcess->VaSpace,
        pProcess->PagingData,
        NULL
    );

	return STATUS_SUCCESS;
}

// Virtual Memory. 5

STATUS
SyscallSwapOut(
	IN      PVOID       VirtualAddress
)
{
	if (VirtualAddress == NULL) {
		return STATUS_INVALID_PARAMETER1;
	}

	PPROCESS pProcess = GetCurrentProcess();

	if (pProcess == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	STATUS status = VmmSwapOut(pProcess->PagingData, VirtualAddress);

	if (!SUCCEEDED(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}

// Virtual Memory. 7
STATUS
SyscallMapZeroPage(
    void
)
{
    PPROCESS pProcess = GetCurrentProcess();

    if (pProcess == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    VmmMakePageUsable(
        pProcess->VaSpace
    );

    return STATUS_SUCCESS;
}

// Virtual Memory. 7
STATUS
SyscallUnmapZeroPage(
	void
)
{
	PPROCESS pProcess = GetCurrentProcess();

	if (pProcess == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	VmmMakePageUnusable(
		pProcess->VaSpace
	);

	return STATUS_SUCCESS;
}

// Userprog. 8
STATUS
SyscallMutexInit(
    OUT     UM_HANDLE* MutexHandle
)
{
    INTR_STATE oldState;
    if (MutexHandle == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    PMUTEX mutex = NULL;
	MutexInit(mutex, FALSE);

	*MutexHandle = (UM_HANDLE)mutex;

	LockAcquire(&mutexLock, &oldState);
	InsertTailList(&mutexHead, &mutex->mutexList);
	LockRelease(&mutexLock, oldState);

    return STATUS_SUCCESS;
}

// Userprog. 8
STATUS
SyscallMutexAcquire(
	IN      UM_HANDLE   MutexHandle
)
{
	if (MutexHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}

	PMUTEX mutex = (PMUTEX)MutexHandle;

	MutexAcquire(mutex);

	return STATUS_SUCCESS;
}

// Userprog. 8
STATUS
SyscallMutexRelease(
	IN      UM_HANDLE   MutexHandle
)
{
	if (MutexHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}

	PMUTEX mutex = (PMUTEX)MutexHandle;

	MutexRelease(mutex);

	return STATUS_SUCCESS;
}

// Userprog. 8
STATUS
SyscallMutexDestroy(
	IN      UM_HANDLE   MutexHandle
)
{
	if (MutexHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}

    INTR_STATE oldState;
	LockAcquire(&mutexLock, &oldState);

    PMUTEX pMutex = (PMUTEX)MutexHandle;

	PLIST_ENTRY pEntry = mutexHead.Flink;
	while (pEntry != &mutexHead) {
		if (pEntry == &pMutex->mutexList) {
			RemoveEntryList(pEntry);
			break;
		}
		pEntry = pEntry->Flink;
	}   

	LockAcquire(&mutexLock, &oldState);

	return STATUS_SUCCESS;
}
