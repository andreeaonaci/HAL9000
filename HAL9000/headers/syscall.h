#pragma once

void
SyscallPreinitSystem(
    void
    );

STATUS
SyscallInitSystem(
    void
    );

STATUS
SyscallUninitSystem(
    void
    );

void
SyscallCpuInit(
    void
    );

STATUS
SyscallMemset(
    OUT_WRITES(BytesToWrite)    PBYTE   Address,
    IN                          DWORD   BytesToWrite,
    IN                          BYTE    ValueToWrite
);

//STATUS
//SyscallProcessCreate(
//    IN_READS_Z(PathLength)
//    char* ProcessPath,
//    IN          QWORD               PathLength,
//    IN_READS_OPT_Z(ArgLength)
//    char* Arguments,
//    IN          QWORD               ArgLength,
//    OUT         UM_HANDLE*       ProcessHandle
//);

// Userprog. 6
STATUS
SyscallDisableSyscalls(
    IN      BOOLEAN     Disable
);

// Userprog. 7
STATUS
SyscallSetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    IN                              QWORD   Value
);

STATUS
SyscallGetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    OUT                             PQWORD  Value
);

STATUS
SyscallSwapOut(
    IN      PVOID       VirtualAddress
);

