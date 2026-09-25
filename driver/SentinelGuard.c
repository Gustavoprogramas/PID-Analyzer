#include <fltKernel.h>
#include "shared/sentinel_protocol.h"

#define SG_TAG 'dGtS'
typedef struct _SG_POLICY {
    SG_REQUEST Request;
    PEPROCESS Processes[SG_MAX_ALLOW];
} SG_POLICY;

static PFLT_FILTER Filter;
static PFLT_PORT ServerPort, ClientPort;
static EX_PUSH_LOCK PolicyLock;
static SG_POLICY* Policy;
static BOOLEAN Connected;
static volatile LONG64 WouldDeny, Denied, NameFailures, Bypassed;

static VOID FreePolicy(SG_POLICY* p) {
    ULONG i;
    if (!p) return;
    for (i = 0; i < SG_MAX_ALLOW; ++i) if (p->Processes[i]) ObDereferenceObject(p->Processes[i]);
    ExFreePoolWithTag(p, SG_TAG);
}
static VOID ClearPolicy(VOID) {
    SG_POLICY* old;
    KeEnterCriticalRegion(); ExAcquirePushLockExclusive(&PolicyLock);
    Connected = FALSE; old = Policy; Policy = NULL;
    ExReleasePushLockExclusive(&PolicyLock); KeLeaveCriticalRegion();
    FreePolicy(old);
}
static BOOLEAN Matches(const SG_PATH* path, PCUNICODE_STRING name) {
    UNICODE_STRING prefix;
    const USHORT bytes = (USHORT)(path->Length * sizeof(WCHAR));
    prefix.Buffer = (PWCH)path->Name; prefix.Length = prefix.MaximumLength = bytes;
    if (!RtlPrefixUnicodeString(&prefix, name, TRUE)) return FALSE;
    if (name->Length == bytes) return TRUE;
    if (name->Length < bytes + sizeof(WCHAR)) return FALSE;
    // Inclui alternate data streams do arquivo e respeita a fronteira da pasta.
    return name->Buffer[path->Length] == L':' ||
        (path->Kind == SG_DIRECTORY && name->Buffer[path->Length] == L'\\');
}
static FLT_PREOP_CALLBACK_STATUS PreOperation(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* context) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PEPROCESS requestor;
    NTSTATUS status;
    ULONG i, mask = 0, granted = 0, mode = SG_OFF;
    BOOLEAN active;
    UNREFERENCED_PARAMETER(objects); UNREFERENCED_PARAMETER(context);
    if (KeGetCurrentIrql() > APC_LEVEL || data->RequestorMode != UserMode ||
        FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        InterlockedIncrement64(&Bypassed); return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    KeEnterCriticalRegion(); ExAcquirePushLockShared(&PolicyLock);
    active = Policy && Policy->Request.Mode != SG_OFF;
    ExReleasePushLockShared(&PolicyLock); KeLeaveCriticalRegion();
    if (!active) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ACCESS_MASK access = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        if (!(access & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED)))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (FlagOn(data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
            InterlockedIncrement64(&Bypassed); return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }
    requestor = FltGetRequestorProcess(data);
    if (!requestor) { InterlockedIncrement64(&Bypassed); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) { InterlockedIncrement64(&NameFailures); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    KeEnterCriticalRegion(); ExAcquirePushLockShared(&PolicyLock);
    if (Policy) {
        mode = Policy->Request.Mode;
        for (i = 0; i < Policy->Request.PathCount; ++i)
            if (Matches(&Policy->Request.Paths[i], &name->Name)) mask |= 1u << i;
        for (i = 0; i < Policy->Request.AllowCount; ++i)
            if (Policy->Processes[i] == requestor) granted |= Policy->Request.Allowed[i].PathMask;
    }
    ExReleasePushLockShared(&PolicyLock); KeLeaveCriticalRegion();
    FltReleaseFileNameInformation(name);
    if (mode != SG_OFF && (mask & ~granted)) {
        InterlockedIncrement64(&WouldDeny);
        if (mode == SG_ENFORCE) {
            InterlockedIncrement64(&Denied);
            data->IoStatus.Status = STATUS_ACCESS_DENIED;
            data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
static NTSTATUS Message(PVOID cookie, PVOID input, ULONG inputSize, PVOID output, ULONG outputSize, PULONG returned) {
    SG_POLICY *next = NULL, *old = NULL;
    SG_REPLY reply = {0};
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    UNREFERENCED_PARAMETER(cookie);
    *returned = 0;
    if (!input || inputSize != sizeof(SG_REQUEST) || !output || outputSize < sizeof(SG_REPLY)) return STATUS_INVALID_PARAMETER;
    next = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SG_POLICY), SG_TAG);
    if (!next) return STATUS_INSUFFICIENT_RESOURCES;
    __try { RtlCopyMemory(&next->Request, input, sizeof(SG_REQUEST)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { FreePolicy(next); return GetExceptionCode(); }
    if (!SgValidRequest(&next->Request)) { FreePolicy(next); return STATUS_INVALID_PARAMETER; }
    if (next->Request.Command == SG_SET_POLICY) {
        for (i = 0; i < next->Request.PathCount; ++i) {
            UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume");
            UNICODE_STRING path;
            ULONG offset;
            path.Buffer = next->Request.Paths[i].Name;
            path.Length = path.MaximumLength = (USHORT)(next->Request.Paths[i].Length * sizeof(WCHAR));
            if (!RtlPrefixUnicodeString(&prefix, &path, TRUE)) { status = STATUS_INVALID_PARAMETER; break; }
            offset = prefix.Length / sizeof(WCHAR);
            while (offset < next->Request.Paths[i].Length && path.Buffer[offset] >= L'0' && path.Buffer[offset] <= L'9') ++offset;
            // Nao aceita um volume inteiro como raiz de protecao.
            if (offset == prefix.Length / sizeof(WCHAR) || offset + 1 >= next->Request.Paths[i].Length || path.Buffer[offset] != L'\\') {
                status = STATUS_INVALID_PARAMETER; break;
            }
        }
        for (i = 0; NT_SUCCESS(status) && i < next->Request.AllowCount; ++i) {
            status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)next->Request.Allowed[i].Pid, &next->Processes[i]);
            if (NT_SUCCESS(status) && (ULONGLONG)PsGetProcessCreateTimeQuadPart(next->Processes[i]) != next->Request.Allowed[i].Created)
                status = STATUS_INVALID_CID;
        }
        if (NT_SUCCESS(status)) {
            KeEnterCriticalRegion(); ExAcquirePushLockExclusive(&PolicyLock);
            if (!Connected) status = STATUS_PORT_DISCONNECTED;
            else { old = Policy; Policy = next; next = NULL; }
            ExReleasePushLockExclusive(&PolicyLock); KeLeaveCriticalRegion();
            FreePolicy(old);
        }
    }
    FreePolicy(next);
    if (!NT_SUCCESS(status)) return status;
    reply.Version = SG_VERSION; reply.Size = sizeof(reply);
    KeEnterCriticalRegion(); ExAcquirePushLockShared(&PolicyLock);
    if (Policy) { reply.Mode = Policy->Request.Mode; reply.PathCount = Policy->Request.PathCount; }
    ExReleasePushLockShared(&PolicyLock); KeLeaveCriticalRegion();
    reply.WouldDeny = InterlockedCompareExchange64(&WouldDeny, 0, 0);
    reply.Denied = InterlockedCompareExchange64(&Denied, 0, 0);
    reply.NameFailures = InterlockedCompareExchange64(&NameFailures, 0, 0);
    reply.Bypassed = InterlockedCompareExchange64(&Bypassed, 0, 0);
    __try { RtlCopyMemory(output, &reply, sizeof(reply)); *returned = sizeof(reply); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    return STATUS_SUCCESS;
}
static NTSTATUS Connect(PFLT_PORT port, PVOID serverCookie, PVOID context, ULONG size, PVOID* cookie) {
    UNREFERENCED_PARAMETER(serverCookie); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(size);
    *cookie = NULL; ClientPort = port;
    KeEnterCriticalRegion(); ExAcquirePushLockExclusive(&PolicyLock); Connected = TRUE;
    ExReleasePushLockExclusive(&PolicyLock); KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}
static VOID Disconnect(PVOID cookie) {
    UNREFERENCED_PARAMETER(cookie);
    ClearPolicy(); FltCloseClientPort(Filter, &ClientPort);
}
static NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_SETUP_FLAGS flags, DEVICE_TYPE device, FLT_FILESYSTEM_TYPE fs) {
    UNREFERENCED_PARAMETER(objects); UNREFERENCED_PARAMETER(flags);
    return device == FILE_DEVICE_DISK_FILE_SYSTEM && fs == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}
static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    FltCloseCommunicationPort(ServerPort);
    FltCloseClientPort(Filter, &ClientPort);
    FltUnregisterFilter(Filter);
    ClearPolicy();
    return STATUS_SUCCESS;
}
static const FLT_OPERATION_REGISTRATION Operations[] = {
    { IRP_MJ_CREATE, 0, PreOperation, NULL },
    { IRP_MJ_READ, 0, PreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};
static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0,
    NULL, Operations, Unload, InstanceSetup,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    NTSTATUS status;
    PSECURITY_DESCRIPTOR security = NULL;
    UNICODE_STRING name = RTL_CONSTANT_STRING(SG_PORT_NAME);
    OBJECT_ATTRIBUTES attributes;
    UNREFERENCED_PARAMETER(registry);
    ExInitializePushLock(&PolicyLock);
    status = FltRegisterFilter(driver, &Registration, &Filter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, security);
        status = FltCreateCommunicationPort(Filter, &ServerPort, &attributes, NULL, Connect, Disconnect, Message, 1);
        FltFreeSecurityDescriptor(security);
    }
    if (NT_SUCCESS(status)) status = FltStartFiltering(Filter);
    if (!NT_SUCCESS(status)) {
        if (ServerPort) FltCloseCommunicationPort(ServerPort);
        FltUnregisterFilter(Filter);
    }
    return status;
}
