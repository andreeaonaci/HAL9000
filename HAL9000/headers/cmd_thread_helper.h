#pragma once

#include "cmd_common.h"

FUNC_GenericCommand CmdListCpus;
FUNC_GenericCommand CmdListThreads;
FUNC_GenericCommand CmdYield;
FUNC_GenericCommand CmdRunTest;
FUNC_GenericCommand CmdSendIpi;
FUNC_GenericCommand CmdListCpuInterrupts;
FUNC_GenericCommand CmdTestTimer;
FUNC_GenericCommand CmdCpuid;
FUNC_GenericCommand CmdRdmsr;
FUNC_GenericCommand CmdWrmsr;
FUNC_GenericCommand CmdCheckAd;
FUNC_GenericCommand CmdSpawnThreads;
// Threads. 4
FUNC_GenericCommand CmdDisplayThreadInfo;
// Threads. 5
FUNC_GenericCommand CmdDisplayMutexInfo;
// Threads. 7
FUNC_GenericCommand CmdDisplayCondVariableInfo;
// Threads. 9
FUNC_GenericCommand CmdCalculateSum;
FUNC_GenericCommand CmdSwapOut;

