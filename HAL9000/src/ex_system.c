#include "HAL9000.h"
#include "ex_system.h"
#include "thread_internal.h"
#include "vmm.h"

void
ExSystemTimerTick(
    void
    )
{

    ThreadTick();
    // Virtual Memory. 6
    //VmmDisplayDirtyAccessedPages();
}