#include "HAL9000.h"
#include "thread_internal.h"
#include "mutex.h"

#define MUTEX_MAX_RECURSIVITY_DEPTH         MAX_BYTE

_No_competing_thread_
void
MutexInit(
    OUT         PMUTEX      Mutex,
    IN          BOOLEAN     Recursive
    )
{
    //ASSERT( NULL != Mutex );

    memzero(Mutex, sizeof(MUTEX));

    LockInit(&Mutex->MutexLock);

    InitializeListHead(&Mutex->WaitingList);

	// Threads. 5
	INTR_STATE oldState;
	InitializeListHead(&mutexHead);
	LockAcquire(&mutexLock, &oldState);
	if (&Mutex->mutexList == NULL)
	{
		LockRelease(&mutexLock, oldState);
		return;
	}
	InsertTailList(&mutexHead, &Mutex->mutexList);
	LockRelease(&mutexLock, oldState);

    Mutex->MaxRecursivityDepth = Recursive ? MUTEX_MAX_RECURSIVITY_DEPTH : 1;
}

ACQUIRES_EXCL_AND_REENTRANT_LOCK(*Mutex)
REQUIRES_NOT_HELD_LOCK(*Mutex)
void
MutexAcquire(
    INOUT       PMUTEX      Mutex
    )
{
    INTR_STATE dummyState;
    INTR_STATE oldState;
    PTHREAD pCurrentThread = GetCurrentThread();

    ASSERT( NULL != Mutex);
    ASSERT( NULL != pCurrentThread );

    if (pCurrentThread == Mutex->Holder)
    {
        ASSERT( Mutex->CurrentRecursivityDepth < Mutex->MaxRecursivityDepth );

        Mutex->CurrentRecursivityDepth++;
        return;
    }

    oldState = CpuIntrDisable();

    LockAcquire(&Mutex->MutexLock, &dummyState );
    if (NULL == Mutex->Holder)
    {
        Mutex->Holder = pCurrentThread;
        Mutex->CurrentRecursivityDepth = 1;
    }

    while (Mutex->Holder != pCurrentThread)
    {
        InsertTailList(&Mutex->WaitingList, &pCurrentThread->ReadyList);
        ThreadTakeBlockLock();
        LockRelease(&Mutex->MutexLock, dummyState);
        ThreadBlock();
        LockAcquire(&Mutex->MutexLock, &dummyState );
    }

    _Analysis_assume_lock_acquired_(*Mutex);

    LockRelease(&Mutex->MutexLock, dummyState);

    CpuIntrSetState(oldState);
}

RELEASES_EXCL_AND_REENTRANT_LOCK(*Mutex)
REQUIRES_EXCL_LOCK(*Mutex)
void
MutexRelease(
    INOUT       PMUTEX      Mutex
    )
{
    INTR_STATE oldState;
    PLIST_ENTRY pEntry;

    ASSERT(NULL != Mutex);
    ASSERT(GetCurrentThread() == Mutex->Holder);

    if (Mutex->CurrentRecursivityDepth > 1)
    {
        Mutex->CurrentRecursivityDepth--;
        return;
    }

    pEntry = NULL;

    LockAcquire(&Mutex->MutexLock, &oldState);

    pEntry = RemoveHeadList(&Mutex->WaitingList);
    if (pEntry != &Mutex->WaitingList)
    {
        PTHREAD pThread = CONTAINING_RECORD(pEntry, THREAD, ReadyList);

        // wakeup first thread
        Mutex->Holder = pThread;
        Mutex->CurrentRecursivityDepth = 1;
        ThreadUnblock(pThread);
    }
    else
    {
        Mutex->Holder = NULL;
    }

    _Analysis_assume_lock_released_(*Mutex);

    LockRelease(&Mutex->MutexLock, oldState);
}

// Threads. 5
void
MutexSystemPreinit(
    void
)
{
    LOG("Initializing mutex system\n");
    InitializeListHead(&mutexHead);
    LockInit(&mutexLock);
}

void
MutexDestroy(
    INOUT	PMUTEX		Mutex
)
{
    ASSERT(NULL != Mutex);

    INTR_STATE oldState;
    LockAcquire(&mutexLock, &oldState);
    RemoveEntryList(&Mutex->mutexList);
    LockRelease(&mutexLock, oldState);
}

STATUS
DisplayMutexForEach(
    IN      PFUNC_ListFunction  Function,
    IN_OPT  PVOID               Context
)
{
    INTR_STATE oldState;
    STATUS status;

	LOG("am intrat aici\n");

	if (NULL == Function)
	{
		return STATUS_INVALID_PARAMETER1;
	}

    status = STATUS_SUCCESS;

	LOG("sunt inainte de lock\n");

    LockAcquire(&mutexLock, &oldState);
    status = ForEachElementExecute(&mutexHead, Function, Context, FALSE);
    LockRelease(&mutexLock, oldState);

	LOG("sunt dupa lock\n");

    return STATUS_SUCCESS;
}