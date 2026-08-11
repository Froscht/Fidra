#include "Memory.h"

#define DIRECTORY_TABLE_BASE_OFFSET 0x028

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AidaReadProcessMemory)
#pragma alloc_text(PAGE, AidaWriteProcessMemory)
#pragma alloc_text(PAGE, AidaGetProcessBaseAddress)
#pragma alloc_text(PAGE, AidaGetProcessByPid)
#pragma alloc_text(PAGE, AidaGetDirectoryTableBase)
#endif

NTSTATUS AidaGetProcessByPid(
    ULONG ProcessId,
    PEPROCESS *Process)
{
    PAGED_CODE();

    if (Process == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, Process);
}

NTSTATUS AidaReadProcessMemory(
    ULONG ProcessId,
    ULONG64 Address,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;
    SIZE_T ReturnSize = 0;

    if (Buffer == NULL || BytesRead == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesRead = 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MmCopyVirtualMemory(
        TargetProcess,
        (PVOID)Address,
        PsGetCurrentProcess(),
        Buffer,
        (SIZE_T)Size,
        KernelMode,
        &ReturnSize
    );

    if (NT_SUCCESS(Status)) {
        *BytesRead = (ULONG)ReturnSize;
    }

    ObDereferenceObject(TargetProcess);
    return Status;
}

NTSTATUS AidaWriteProcessMemory(
    ULONG ProcessId,
    ULONG64 Address,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;
    SIZE_T ReturnSize = 0;

    if (Buffer == NULL || BytesWritten == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesWritten = 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        Buffer,
        TargetProcess,
        (PVOID)Address,
        (SIZE_T)Size,
        KernelMode,
        &ReturnSize
    );

    if (NT_SUCCESS(Status)) {
        *BytesWritten = (ULONG)ReturnSize;
    }

    ObDereferenceObject(TargetProcess);
    return Status;
}

NTSTATUS AidaGetProcessBaseAddress(
    ULONG ProcessId,
    PULONG64 BaseAddress)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;
    PVOID ImageBase;

    if (BaseAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *BaseAddress = 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    ImageBase = PsGetProcessSectionBaseAddress(TargetProcess);
    if (ImageBase == NULL) {
        ObDereferenceObject(TargetProcess);
        return STATUS_NOT_FOUND;
    }

    *BaseAddress = (ULONG64)ImageBase;
    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}

NTSTATUS AidaReadPhysicalMemory(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesRead)
{
    PHYSICAL_ADDRESS PhysAddr;
    PVOID MappedAddress;

    if (Buffer == NULL || BytesRead == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesRead = 0;

    PhysAddr.QuadPart = (LONGLONG)PhysicalAddress;

    MappedAddress = MmMapIoSpace(PhysAddr, (SIZE_T)Size, MmNonCached);
    if (MappedAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        RtlCopyMemory(Buffer, MappedAddress, Size);
        *BytesRead = Size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(MappedAddress, (SIZE_T)Size);
        return GetExceptionCode();
    }

    MmUnmapIoSpace(MappedAddress, (SIZE_T)Size);
    return STATUS_SUCCESS;
}

NTSTATUS AidaWritePhysicalMemory(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG BytesWritten)
{
    PHYSICAL_ADDRESS PhysAddr;
    PVOID MappedAddress;

    if (Buffer == NULL || BytesWritten == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesWritten = 0;

    PhysAddr.QuadPart = (LONGLONG)PhysicalAddress;

    MappedAddress = MmMapIoSpace(PhysAddr, (SIZE_T)Size, MmNonCached);
    if (MappedAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        RtlCopyMemory(MappedAddress, Buffer, Size);
        *BytesWritten = Size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(MappedAddress, (SIZE_T)Size);
        return GetExceptionCode();
    }

    MmUnmapIoSpace(MappedAddress, (SIZE_T)Size);
    return STATUS_SUCCESS;
}

NTSTATUS AidaGetDirectoryTableBase(
    ULONG ProcessId,
    PULONG64 DirectoryTableBase)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;

    if (DirectoryTableBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DirectoryTableBase = 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    *DirectoryTableBase = *(PULONG64)((PUCHAR)TargetProcess + DIRECTORY_TABLE_BASE_OFFSET);

    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}
