#include "list.h"

typedef struct _CONDITIONAL_VARIABLE
{
    LIST_ENTRY              WaiterList;
} CONDITIONAL_VARIABLE, * PCONDITIONAL_VARIABLE;

void
CondVariableInit(
    OUT     PCONDITIONAL_VARIABLE   CondVariable
);

void
CondVariableWait(
    INOUT   PCONDITIONAL_VARIABLE   CondVariable,
    INOUT   PMUTEX                  Lock
);

void
CondVariableSignal(
    INOUT   PCONDITIONAL_VARIABLE   CondVariable,
    INOUT   PMUTEX                  Lock
);

void
CondVariableBroadcast(
    INOUT   PCONDITIONAL_VARIABLE   CondVariable,
    INOUT   PMUTEX                  Lock
);