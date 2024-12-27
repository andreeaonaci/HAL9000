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
	ASSERT(CondVariable != NULL);

	InitializeListHead(&CondVariable->WaiterList);
}

void
CondVariableWait(
	INOUT   PCONDITIONAL_VARIABLE   CondVariable,
	INOUT   PMUTEX                  Lock
)
{
	ASSERT(CondVariable != NULL);
	ASSERT(Lock != NULL);

	// 1. Release the lock
	MutexRelease(Lock);

	// 2. Add the current thread to the waiting list
	InsertTailList(&CondVariable->WaiterList, &GetCurrentThread()->ReadyList);

	// 3. Block the current thread
	ThreadBlock();

	// 4. Re-acquire the lock
	MutexAcquire(Lock);
}

void
CondVariableSignal(
	INOUT   PCONDITIONAL_VARIABLE   CondVariable,
	INOUT   PMUTEX                  Lock
)
{
	ASSERT(CondVariable != NULL);
	ASSERT(Lock != NULL);

	PTHREAD pThreadToWakeUp;

	if (IsListEmpty(&CondVariable->WaiterList))
	{
		return;
	}

	// 1. Get the first thread from the waiting list
	pThreadToWakeUp = CONTAINING_RECORD(RemoveHeadList(&CondVariable->WaiterList), THREAD, ReadyList);

	// 2. Unblock the thread
	ThreadUnblock(pThreadToWakeUp);
}

void
CondVariableBroadcast(
	INOUT   PCONDITIONAL_VARIABLE   CondVariable,
	INOUT   PMUTEX                  Lock
)
{
	ASSERT(CondVariable != NULL);
	ASSERT(Lock != NULL);

	PTHREAD pThreadToWakeUp;

	while (!IsListEmpty(&CondVariable->WaiterList))
	{
		// 1. Get the first thread from the waiting list
		pThreadToWakeUp = CONTAINING_RECORD(RemoveHeadList(&CondVariable->WaiterList), THREAD, ReadyList);

		// 2. Unblock the thread
		ThreadUnblock(pThreadToWakeUp);
	}
}

