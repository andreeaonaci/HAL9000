#pragma once

void
SystemPreinit(
    void
    );

STATUS
SystemInit(
    IN  ASM_PARAMETERS*     Parameters
    );

void
SystemUninit(
    void
    );

static
STATUS
MakeInfiniteLoop(
    IN_OPT		PVOID		Context
);

void
MakeCPUNonPreeemptible(
    void
);