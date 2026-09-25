#define UNICODE
#define _UNICODE
#include <Windows.h>
#include <fltUser.h>
#include <conio.h>
#include <iostream>
#include <string>
#include <memory>
#include "../shared/sentinel_protocol.h"
#pragma comment(lib, "FltLib.lib")

struct Resource {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Resource() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
static_assert(sizeof(SG_PATH) == 1032 && sizeof(SG_ALLOW) == 24 && sizeof(SG_REPLY) == 48 && sizeof(SG_REQUEST) == 9824, "protocol layout");

bool addPath(SG_REQUEST& request, const wchar_t* file, ULONG kind) {
    if (request.PathCount >= SG_MAX_PATHS || !file || wcslen(file) < 3 || file[1] != L':' || file[2] != L'\\') return false;
    Resource handle;
    handle.value = CreateFileW(file, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle.value == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle.value, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (!!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != (kind == SG_DIRECTORY))) return false;
    SG_PATH& path = request.Paths[request.PathCount];
    DWORD size = GetFinalPathNameByHandleW(handle.value, path.Name, SG_PATH_CHARS, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
    if (!size || size >= SG_PATH_CHARS) return false;
    if (path.Name[size - 1] == L'\\') path.Name[--size] = 0;
    path.Length = size; path.Kind = kind; ++request.PathCount;
    return true;
}
bool addAllowed(SG_REQUEST& request, const wchar_t* text) {
    if (request.AllowCount >= SG_MAX_ALLOW) return false;
    wchar_t* end = nullptr; const auto id = _wcstoui64(text, &end, 10);
    if (end == text || *end || id <= 4 || id > MAXDWORD) return false;
    Resource process; process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(id));
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!process.value || !GetProcessTimes(process.value, &created, &exited, &kernel, &user)) return false;
    auto& entry = request.Allowed[request.AllowCount++];
    entry.Pid = id; entry.Created = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return true;
}
HRESULT send(HANDLE port, SG_REQUEST& request, SG_REPLY& reply) {
    DWORD returned = 0;
    HRESULT hr = FilterSendMessage(port, &request, sizeof(request), &reply, sizeof(reply), &returned);
    if (SUCCEEDED(hr) && (returned != sizeof(reply) || reply.Version != SG_VERSION || reply.Size != sizeof(reply))) return E_UNEXPECTED;
    return hr;
}
int wmain(int argc, wchar_t** argv) {
    auto request = std::make_unique<SG_REQUEST>();
    request->Version = SG_VERSION; request->Size = sizeof(*request); request->Command = SG_SET_POLICY; request->Mode = SG_AUDIT;
    bool valid = argc > 1;
    for (int i = 1; valid && i < argc; ++i) {
        const std::wstring arg = argv[i];
        if ((arg == L"--directory" || arg == L"--file") && i + 1 < argc) valid = addPath(*request, argv[++i], arg == L"--file" ? SG_FILE : SG_DIRECTORY);
        else if (arg == L"--allow-pid" && i + 1 < argc) valid = addAllowed(*request, argv[++i]);
        else if (arg == L"--enforce") request->Mode = SG_ENFORCE;
        else valid = false;
    }
    for (ULONG i = 0; i < request->AllowCount; ++i) request->Allowed[i].PathMask = (1u << request->PathCount) - 1u;
    if (!valid || !request->PathCount || !SgValidRequest(request.get())) {
        std::wcerr << L"Uso (somente VM): guardctl --directory C:\\SentinelLab [--file C:\\SentinelLab\\fixture.txt] [--allow-pid PID] [--enforce]\n"
            L"Padrao: AUDIT. Caminhos devem existir. --allow-pid permite a instancia atual em todos os caminhos informados.\n";
        return 2;
    }
    for (ULONG i = 0; i < request->PathCount; ++i) std::wcout << L"Proteger: " << request->Paths[i].Name << L'\n';
    if (request->Mode == SG_ENFORCE) {
        std::wcout << L"ENFORCE nega novos opens/reads de processos fora da lista. Somente em VM de teste. Digite ENFORCE: ";
        std::wstring confirm; std::getline(std::wcin, confirm); if (confirm != L"ENFORCE") return 2;
    }
    Resource port;
    HRESULT hr = FilterConnectCommunicationPort(SG_PORT_NAME, 0, nullptr, 0, nullptr, &port.value);
    if (FAILED(hr)) { std::wcerr << L"Driver indisponivel/sem permissao: 0x" << std::hex << hr << L'\n'; return 1; }
    SG_REPLY reply{}; hr = send(port.value, *request, reply);
    if (FAILED(hr)) { std::wcerr << L"Politica recusada: 0x" << std::hex << hr << L'\n'; return 1; }
    std::wcout << L"Politica ativa. Q encerra e remove a politica. Desconectar tambem volta a OFF.\n";
    request->Command = SG_QUERY;
    while (!_kbhit() || (towlower(_getwch()) != L'q')) {
        hr = send(port.value, *request, reply);
        if (FAILED(hr)) { std::wcerr << L"Falha no canal: 0x" << std::hex << hr << L'\n'; return 1; }
        std::wcout << L"mode=" << reply.Mode << L" would-deny=" << reply.WouldDeny << L" denied=" << reply.Denied
            << L" name-failures=" << reply.NameFailures << L" bypassed=" << reply.Bypassed << L"    \r";
        Sleep(1000);
    }
    return 0;
}
