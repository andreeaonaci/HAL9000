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

	InitializeListHead(&Semaphore->WaitingList);
	InitializeListHead(&Semaphore->RunningList);

	Semaphore->InitValue = InitialValue;
}


void
SemaphoreDown(
	INOUT   PSEMAPHORE      Semaphore,
	IN      DWORD           Value
) 
{
	UNREFERENCED_PARAMETER(Value);
	UNREFERENCED_PARAMETER(Semaphore);

	PTHREAD pCurrentThread = GetCurrentThread();

	ASSERT(NULL != Semaphore);
	ASSERT(NULL != pCurrentThread);

	INTR_STATE oldState;
	INTR_STATE CpuState;

	CpuState = CpuIntrDisable();

	LockAcquire(&Semaphore->SemLock, &oldState);
	
	//verify if the current thread is already in the running list
	//ASSERT(pCurrentThread->SemaphoreList is NOT in Sem->RunningList)

	while (Semaphore->Value  >= Value)
	{
		InsertTailList(&Semaphore->WaitingList, &pCurrentThread->SemaphoreList);
		ThreadTakeBlockLock();
		LockRelease(&Semaphore->SemLock, oldState);
		ThreadBlock();
		//after thread is unblocked
		LockAcquire(&Semaphore->SemLock, &oldState);
	}

	RemoveEntryList(&pCurrentThread->SemaphoreList);
	InsertTailList(&Semaphore->RunningList, &pCurrentThread->SemaphoreList);
	Semaphore->Value-=Value;


	LockRelease(&Semaphore->SemLock, oldState);
	CpuIntrSetState(CpuState);

}
void
SemaphoreUp(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
)
{
	UNREFERENCED_PARAMETER(Value);
	UNREFERENCED_PARAMETER(Semaphore);

	//verify if the current thread is already in the running 
	//ASSERT(pCurrentThread->SemaphoreList is NOT in Sem)
	// if sem->value + Value > sem->InitValue then sem->value = sem->InitValue
}