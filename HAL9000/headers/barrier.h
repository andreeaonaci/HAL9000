#include "HAL9000.h"
#include "mutex.h"
#include "thread_internal.h"
#include "smp.h"

// Threads. 6

typedef struct _BARRIER
{
    DWORD NoOfParticipants; // Total number of participants (CPUs)
    volatile DWORD Counter; // Counter to track the number of CPUs that reached the barrier
    volatile DWORD Generation; // Used to distinguish between successive uses of the barrier
} BARRIER, * PBARRIER;

void
BarrierInit(
    OUT     PBARRIER        Barrier,
    IN      DWORD           NoOfParticipants
);

void
BarrierWait(
    INOUT   PBARRIER        Barrier
);