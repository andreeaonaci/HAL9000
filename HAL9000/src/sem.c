#include "sem.h"
#include "thread.h"
#include "thread_internal.h"
#include "synch.h"

_No_competing_thread_
void
SemaphoreInit(
    OUT     PSEMAPHORE      Semaphore,
    IN      DWORD           InitialValue
)
{
    ASSERT(NULL != Semaphore);

    memzero(Semaphore, sizeof(SEMAPHORE));

    LockInit(&Semaphore->SemLock);

    Semaphore->Value = InitialValue;
    Semaphore->InitValue = InitialValue;

    InitializeListHead(&Semaphore->WaitingList);
    InitializeListHead(&Semaphore->RunningList);
}

void
SemaphoreDown(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
) 
{
    ASSERT(NULL != Semaphore);
    ASSERT(Value > 0);

    INTR_STATE oldState;
    INTR_STATE cpuState;

    cpuState = CpuIntrDisable();
    PTHREAD pCurrentThread = GetCurrentThread();
    ASSERT(NULL != pCurrentThread);

    LockAcquire(&Semaphore->SemLock, &oldState);

    // Verify if the current thread is not already in the running list
    ASSERT(!IsListEntryInList(&Semaphore->RunningList, &pCurrentThread->SemaphoreList));

    // Wait until there is sufficient value in the semaphore
    while (Semaphore->Value < Value)
    {
        // Add to waiting list if there are not enough resources
        InsertTailList(&Semaphore->WaitingList, &pCurrentThread->SemaphoreList);
        ThreadTakeBlockLock();
        LockRelease(&Semaphore->SemLock, oldState);
        ThreadBlock();
        LockAcquire(&Semaphore->SemLock, &oldState);
    }

    // Remove from waiting list and add to running list
    RemoveEntryList(&pCurrentThread->SemaphoreList);
    InsertTailList(&Semaphore->RunningList, &pCurrentThread->SemaphoreList);
    Semaphore->Value -= Value;

    LockRelease(&Semaphore->SemLock, oldState);
    CpuIntrSetState(cpuState);
}
