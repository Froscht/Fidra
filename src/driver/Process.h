#pragma once

#include <ntddk.h>
#include "Communication.h"

NTSTATUS FidraEnumerateProcesses(
    PPROCESS_ENTRY Buffer,
    ULONG MaxCount,
    PULONG ActualCount
);

NTSTATUS FidraGetProcessModules(
    ULONG ProcessId,
    PMODULE_ENTRY Buffer,
    ULONG MaxCount,
    PULONG ActualCount
);

NTSTATUS FidraProtectProcess(
    ULONG ProcessId
);

NTSTATUS FidraGetProcessThreads(
    ULONG ProcessId,
    PULONG ThreadIds,
    ULONG MaxCount,
    PULONG ActualCount
);
