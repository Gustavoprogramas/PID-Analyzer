#pragma once

#define SG_VERSION 1u
#define SG_MAX_PATHS 8u
#define SG_MAX_ALLOW 64u
#define SG_PATH_CHARS 512u
#define SG_PORT_NAME L"\\SentinelGuardPort"
#define SG_QUERY 1u
#define SG_SET_POLICY 2u
#define SG_OFF 0u
#define SG_AUDIT 1u
#define SG_ENFORCE 2u
#define SG_FILE 1u
#define SG_DIRECTORY 2u

// Tipos Win32/WDK de largura fixa; o protocolo e exclusivo de x64.
typedef struct _SG_PATH {
    ULONG Kind;
    ULONG Length;
    WCHAR Name[SG_PATH_CHARS];
} SG_PATH;
typedef struct _SG_ALLOW {
    ULONGLONG Pid;
    ULONGLONG Created;
    ULONG PathMask;
    ULONG Reserved;
} SG_ALLOW;
typedef struct _SG_REQUEST {
    ULONG Version;
    ULONG Size;
    ULONG Command;
    ULONG Mode;
    ULONG PathCount;
    ULONG AllowCount;
    ULONG Reserved[2];
    SG_PATH Paths[SG_MAX_PATHS];
    SG_ALLOW Allowed[SG_MAX_ALLOW];
} SG_REQUEST;
typedef struct _SG_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG Mode;
    ULONG PathCount;
    ULONGLONG WouldDeny;
    ULONGLONG Denied;
    ULONGLONG NameFailures;
    ULONGLONG Bypassed;
} SG_REPLY;

static __inline int SgValidRequest(const SG_REQUEST* r) {
    ULONG i, j;
    if (r->Version != SG_VERSION || r->Size != sizeof(SG_REQUEST) ||
        r->Reserved[0] || r->Reserved[1]) return 0;
    if (r->Command == SG_QUERY) return 1;
    if (r->Command != SG_SET_POLICY || r->Mode > SG_ENFORCE ||
        r->PathCount > SG_MAX_PATHS || r->AllowCount > SG_MAX_ALLOW ||
        (r->Mode != SG_OFF && !r->PathCount)) return 0;
    for (i = 0; i < r->PathCount; ++i) {
        const SG_PATH* p = &r->Paths[i];
        if ((p->Kind != SG_FILE && p->Kind != SG_DIRECTORY) || p->Length < 10 ||
            p->Length >= SG_PATH_CHARS || p->Name[p->Length] || p->Name[0] != L'\\' ||
            p->Name[p->Length - 1] == L'\\') return 0;
        for (j = 0; j < p->Length; ++j)
            if (!p->Name[j] || p->Name[j] == L'/' || p->Name[j] == L'*' || p->Name[j] == L'?') return 0;
    }
    for (i = 0; i < r->AllowCount; ++i)
        if (r->Allowed[i].Pid <= 4 || r->Allowed[i].Pid > 0xffffffffULL || !r->Allowed[i].Created ||
            r->Allowed[i].Reserved || !r->Allowed[i].PathMask ||
            (r->Allowed[i].PathMask & ~((1u << r->PathCount) - 1u))) return 0;
    return 1;
}
