#include "HAL9000.h"
#include "ex_event.h"
#include "thread_internal.h"
#include "conditional_variables.h"
#include "mutex.h"

void
CondVariableInit(
	OUT     PCONDITIONAL_VARIABLE   CondVariable
)
{
	//ASSERT(CondVariable != NULL);

	InitializeListHead(&CondVariable->WaiterList);
	LOG("CondVariable initialized\n");
}

void
CondVariableWait(
	INOUT   PCONDITIONAL_VARIABLE   CondVariable,
	INOUT   PMUTEX                  Lock
)
{
	//ASSERT(CondVariable != NULL);
	//ASSERT(Lock != NULL);

	INTR_STATE oldState;

	LockAcquire(&Lock->MutexLock, &oldState);

	// Add the current thread to the waiting list
	InitializeListHead(&GetCurrentThread()->ReadyList);
	InsertTailList(&CondVariable->WaiterList, &GetCurrentThread()->ReadyList);

	LockRelease(&Lock->MutexLock, oldState);

	// Block the current thread
	ThreadBlock();

	// Re-acquire the lock
	//LockAcquire(&Lock->MutexLock, &oldState);
}

void
CondVariableSignal(
	INOUT   PCONDITIONAL_VARIABLE   CondVariable,
	INOUT   PMUTEX                  Lock
)
{
	//ASSERT(CondVariable != NULL);
	//ASSERT(Lock != NULL);

	INTR_STATE oldState;

	PTHREAD pThreadToWakeUp;

	if (IsListEmpty(&CondVariable->WaiterList))
	{
		return;
	}

	LockAcquire(&Lock->MutexLock, &oldState);

	// 1. Get the first thread from the waiting list
	pThreadToWakeUp = CONTAINING_RECORD(RemoveHeadList(&CondVariable->WaiterList), THREAD, ReadyList);

	// 2. Unblock the thread
	ThreadUnblock(pThreadToWakeUp);

	// 3. Release the lock
	LockRelease(&Lock->MutexLock, oldState);
}

void
CondVariableBroadcast(
	INOUT   PCONDITIONAL_VARIABLE   CondVariable,
	INOUT   PMUTEX                  Lock
)
{
	//ASSERT(CondVariable != NULL);
	//ASSERT(Lock != NULL);

	INTR_STATE oldState;

	PTHREAD pThreadToWakeUp;

	LockAcquire(&Lock->MutexLock, &oldState);

	while (!IsListEmpty(&CondVariable->WaiterList))
	{
		// 1. Get the first thread from the waiting list
		pThreadToWakeUp = CONTAINING_RECORD(RemoveHeadList(&CondVariable->WaiterList), THREAD, ReadyList);

		// 2. Unblock the thread
		ThreadUnblock(pThreadToWakeUp);
	}

	// 3. Release the lock
	LockRelease(&Lock->MutexLock, oldState);
}

