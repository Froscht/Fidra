#pragma once

#include <ntddk.h>

NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTSTATUS FidraReadProcessMemory(
    ULONG ProcessId,
    ULONG64 Address,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead
);

NTSTATUS FidraWriteProcessMemory(
    ULONG ProcessId,
    ULONG64 Address,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten
);

NTSTATUS FidraGetProcessBaseAddress(
    ULONG ProcessId,
    PULONG64 BaseAddress
);

NTSTATUS FidraGetProcessByPid(
    ULONG ProcessId,
    PEPROCESS *Process
);

NTSTATUS FidraReadPhysicalMemory(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead
);

NTSTATUS FidraWritePhysicalMemory(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten
);

NTSTATUS FidraGetDirectoryTableBase(
    ULONG ProcessId,
    PULONG64 DirectoryTableBase
);
