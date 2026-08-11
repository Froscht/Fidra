#include <ntddk.h>
#include "Ioctl.h"
#include "Communication.h"
#include "Memory.h"
#include "Process.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AidaDriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH AidaDispatchCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH AidaDispatchClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH AidaDispatchDeviceControl;

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\AiDA");
UNICODE_STRING SymbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\AiDA");
PDEVICE_OBJECT GlobalDeviceObject = NULL;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AidaDriverUnload)
#pragma alloc_text(PAGE, AidaDispatchCreate)
#pragma alloc_text(PAGE, AidaDispatchClose)
#pragma alloc_text(PAGE, AidaDispatchDeviceControl)
#endif

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &GlobalDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(GlobalDeviceObject);
        GlobalDeviceObject = NULL;
        return Status;
    }

    DriverObject->DriverUnload = AidaDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AidaDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AidaDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AidaDispatchDeviceControl;

    GlobalDeviceObject->Flags |= DO_BUFFERED_IO;
    GlobalDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

VOID AidaDriverUnload(
    PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    IoDeleteSymbolicLink(&SymbolicLinkName);

    if (GlobalDeviceObject != NULL) {
        IoDeleteDevice(GlobalDeviceObject);
        GlobalDeviceObject = NULL;
    }
}

NTSTATUS AidaDispatchCreate(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS AidaDispatchClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleReadMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (InputLength < sizeof(READ_MEMORY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PREAD_MEMORY_REQUEST Request = (PREAD_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (Request->Size == 0 || Request->Size > MAX_MEMORY_BUFFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG RequiredOutput = FIELD_OFFSET(READ_MEMORY_RESPONSE, Data) + Request->Size;
    if (OutputLength < RequiredOutput) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PREAD_MEMORY_RESPONSE Response = (PREAD_MEMORY_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    ULONG BytesRead = 0;

    Response->Status = AidaReadProcessMemory(
        Request->ProcessId,
        Request->Address,
        Response->Data,
        Request->Size,
        &BytesRead
    );

    Response->BytesRead = BytesRead;
    Irp->IoStatus.Information = FIELD_OFFSET(READ_MEMORY_RESPONSE, Data) + BytesRead;
    return STATUS_SUCCESS;
}

static NTSTATUS HandleWriteMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputLength < FIELD_OFFSET(WRITE_MEMORY_REQUEST, Data) + 1) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PWRITE_MEMORY_REQUEST Request = (PWRITE_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (Request->Size == 0 || Request->Size > MAX_MEMORY_BUFFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputLength < FIELD_OFFSET(WRITE_MEMORY_REQUEST, Data) + Request->Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (OutputLength < sizeof(WRITE_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG BytesWritten = 0;
    NTSTATUS OpStatus = AidaWriteProcessMemory(
        Request->ProcessId,
        Request->Address,
        Request->Data,
        Request->Size,
        &BytesWritten
    );

    PWRITE_MEMORY_RESPONSE Response = (PWRITE_MEMORY_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    Response->Status = OpStatus;
    Response->BytesWritten = BytesWritten;
    Irp->IoStatus.Information = sizeof(WRITE_MEMORY_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetBase(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (InputLength < sizeof(GET_BASE_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputLength < sizeof(GET_BASE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PGET_BASE_REQUEST Request = (PGET_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    PGET_BASE_RESPONSE Response = (PGET_BASE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ULONG64 BaseAddress = 0;
    Response->Status = AidaGetProcessBaseAddress(Request->ProcessId, &BaseAddress);
    Response->BaseAddress = BaseAddress;

    Irp->IoStatus.Information = sizeof(GET_BASE_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetProcessList(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (OutputLength < sizeof(GET_PROCESS_LIST_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG AvailableSpace = OutputLength - FIELD_OFFSET(GET_PROCESS_LIST_RESPONSE, Entries);
    ULONG MaxEntries = AvailableSpace / sizeof(PROCESS_ENTRY);

    if (MaxEntries == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (MaxEntries > MAX_PROCESS_COUNT) {
        MaxEntries = MAX_PROCESS_COUNT;
    }

    PGET_PROCESS_LIST_RESPONSE Response = (PGET_PROCESS_LIST_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    ULONG ActualCount = 0;

    Response->Status = AidaEnumerateProcesses(Response->Entries, MaxEntries, &ActualCount);
    Response->Count = ActualCount;

    Irp->IoStatus.Information = FIELD_OFFSET(GET_PROCESS_LIST_RESPONSE, Entries) +
                                (ActualCount * sizeof(PROCESS_ENTRY));
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetModules(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (InputLength < sizeof(GET_MODULES_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputLength < sizeof(GET_MODULES_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PGET_MODULES_REQUEST Request = (PGET_MODULES_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    ULONG Pid = Request->ProcessId;

    ULONG AvailableSpace = OutputLength - FIELD_OFFSET(GET_MODULES_RESPONSE, Entries);
    ULONG MaxEntries = AvailableSpace / sizeof(MODULE_ENTRY);

    if (MaxEntries == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (MaxEntries > MAX_MODULE_COUNT) {
        MaxEntries = MAX_MODULE_COUNT;
    }

    PGET_MODULES_RESPONSE Response = (PGET_MODULES_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    ULONG ActualCount = 0;

    Response->Status = AidaGetProcessModules(Pid, Response->Entries, MaxEntries, &ActualCount);
    Response->Count = ActualCount;

    Irp->IoStatus.Information = FIELD_OFFSET(GET_MODULES_RESPONSE, Entries) +
                                (ActualCount * sizeof(MODULE_ENTRY));
    return STATUS_SUCCESS;
}

static NTSTATUS HandleReadPhysical(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (InputLength < sizeof(READ_PHYSICAL_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PREAD_PHYSICAL_REQUEST Request = (PREAD_PHYSICAL_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (Request->Size == 0 || Request->Size > MAX_MEMORY_BUFFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG RequiredOutput = FIELD_OFFSET(READ_PHYSICAL_RESPONSE, Data) + Request->Size;
    if (OutputLength < RequiredOutput) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PREAD_PHYSICAL_RESPONSE Response = (PREAD_PHYSICAL_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    ULONG BytesRead = 0;

    Response->Status = AidaReadPhysicalMemory(
        Request->PhysicalAddress,
        Response->Data,
        Request->Size,
        &BytesRead
    );

    Response->BytesRead = BytesRead;
    Irp->IoStatus.Information = FIELD_OFFSET(READ_PHYSICAL_RESPONSE, Data) + BytesRead;
    return STATUS_SUCCESS;
}

static NTSTATUS HandleWritePhysical(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputLength < FIELD_OFFSET(WRITE_PHYSICAL_REQUEST, Data) + 1) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PWRITE_PHYSICAL_REQUEST Request = (PWRITE_PHYSICAL_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (Request->Size == 0 || Request->Size > MAX_MEMORY_BUFFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputLength < FIELD_OFFSET(WRITE_PHYSICAL_REQUEST, Data) + Request->Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (OutputLength < sizeof(WRITE_PHYSICAL_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ULONG BytesWritten = 0;
    NTSTATUS OpStatus = AidaWritePhysicalMemory(
        Request->PhysicalAddress,
        Request->Data,
        Request->Size,
        &BytesWritten
    );

    PWRITE_PHYSICAL_RESPONSE Response = (PWRITE_PHYSICAL_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    Response->Status = OpStatus;
    Response->BytesWritten = BytesWritten;
    Irp->IoStatus.Information = sizeof(WRITE_PHYSICAL_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetCr3(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (InputLength < sizeof(GET_CR3_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputLength < sizeof(GET_CR3_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PGET_CR3_REQUEST Request = (PGET_CR3_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    PGET_CR3_RESPONSE Response = (PGET_CR3_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ULONG64 Dtb = 0;
    Response->Status = AidaGetDirectoryTableBase(Request->ProcessId, &Dtb);
    Response->DirectoryTableBase = Dtb;

    Irp->IoStatus.Information = sizeof(GET_CR3_RESPONSE);
    return STATUS_SUCCESS;
}

NTSTATUS AidaDispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    Irp->IoStatus.Information = 0;

    switch (IoStack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_READ_MEMORY:
        Status = HandleReadMemory(Irp, IoStack);
        break;

    case IOCTL_WRITE_MEMORY:
        Status = HandleWriteMemory(Irp, IoStack);
        break;

    case IOCTL_GET_BASE:
        Status = HandleGetBase(Irp, IoStack);
        break;

    case IOCTL_GET_PROCESS_LIST:
        Status = HandleGetProcessList(Irp, IoStack);
        break;

    case IOCTL_GET_MODULES:
        Status = HandleGetModules(Irp, IoStack);
        break;

    case IOCTL_READ_PHYSICAL:
        Status = HandleReadPhysical(Irp, IoStack);
        break;

    case IOCTL_WRITE_PHYSICAL:
        Status = HandleWritePhysical(Irp, IoStack);
        break;

    case IOCTL_GET_CR3:
        Status = HandleGetCr3(Irp, IoStack);
        break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
