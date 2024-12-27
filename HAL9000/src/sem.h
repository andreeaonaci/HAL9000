#pragma once
#include "HAL9000.h"
#include "list.h"
#include "synch.h"

typedef struct _SEMAPHORE
{
	LOCK 		    SemLock;
    
    _Guarded_by_(SemLock)
    DWORD           Value;

	DWORD 	        InitValue;
    
    _Guarded_by_(SemLock)
	LIST_ENTRY      WaitingList;

    _Guarded_by_(SemLock)
	LIST_ENTRY      RunningList;

} SEMAPHORE, * PSEMAPHORE;

void
SemaphoreInit(
    OUT     PSEMAPHORE      Semaphore,
    IN      DWORD           InitialValue
);

void
SemaphoreDown(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
);

void
SemaphoreUp(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
);