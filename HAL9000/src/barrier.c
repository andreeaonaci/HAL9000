#include "barrier.h"

void
BarrierInit(
    OUT     PBARRIER        Barrier,
    IN      DWORD           NoOfParticipants
)
{
    ASSERT(Barrier != NULL);
    ASSERT(NoOfParticipants > 0);

    Barrier->NoOfParticipants = NoOfParticipants;
    Barrier->Counter = 0;
    Barrier->Generation = 0;
}

void
BarrierWait(
    INOUT PBARRIER Barrier
)
{
    DWORD localGeneration;

    ASSERT(Barrier != NULL);

    localGeneration = Barrier->Generation;

    // Atomically increment the counter
    DWORD position = _InterlockedIncrement(&Barrier->Counter);

    LOG("BarrierWait: CPU %x reached barrier, position %u/%u\n",
        CpuGetApicId(), position, Barrier->NoOfParticipants);

    if (position == Barrier->NoOfParticipants)
    {
        // Last CPU to reach the barrier resets the counter and increments the generation
        LOG("BarrierWait: CPU %x is the last participant, resetting barrier.\n", CpuGetApicId());
        Barrier->Counter = 0; // Reset for future use
        _InterlockedIncrement(&Barrier->Generation); // Increment to unblock all CPUs
    }
    else
    {
        // Busy-wait until the generation changes
        while (Barrier->Generation == localGeneration)
        {
            _mm_pause(); // Prevent excessive CPU spinning
        }
    }

    LOG("BarrierWait: CPU %x passed barrier.\n", CpuGetApicId());
}


