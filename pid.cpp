#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <winternl.h>
#include <taskschd.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <io.h>
#include <fcntl.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <cwctype>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "uuid.lib")

struct Handle {
    HANDLE h = nullptr;
    explicit Handle(HANDLE value = nullptr) : h(value) {}
    ~Handle() { if (*this) CloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};
template<class T> struct Com {
    T* p = nullptr;
    ~Com() { if (p) p->Release(); }
    Com() = default;
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;
    T* operator->() const { return p; }
    T** out() { return &p; }
    explicit operator bool() const { return p != nullptr; }
};
struct Bstr {
    BSTR p = nullptr;
    explicit Bstr(const wchar_t* s = nullptr) { if (s) p = SysAllocString(s); }
    ~Bstr() { SysFreeString(p); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    std::wstring str() const { return p ? std::wstring(p, SysStringLen(p)) : L""; }
};

std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return std::towlower(c); });
    return s;
}
bool has(const std::wstring& s, const std::wstring& sub) { return lower(s).find(lower(sub)) != std::wstring::npos; }
std::wstring trim(const std::wstring& s) {
    const auto a = s.find_first_not_of(L" \t\r\n");
    return a == std::wstring::npos ? L"" : s.substr(a, s.find_last_not_of(L" \t\r\n") - a + 1);
}
std::wstring errorCode(HRESULT value) {
    std::wostringstream out;
    out << L" (0x" << std::hex << static_cast<ULONG>(value) << L")";
    return out.str();
}
std::wstring expand(const std::wstring& s) {
    DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (!n || n > 32768) return s;
    std::vector<wchar_t> b(n);
    const DWORD used = ExpandEnvironmentStringsW(s.c_str(), b.data(), n);
    return used && used <= n ? std::wstring(b.data()) : s;
}
std::wstring windowsDir() {
    wchar_t b[MAX_PATH]{};
    return GetWindowsDirectoryW(b, MAX_PATH) ? std::wstring(b) : L"";
}
std::wstring normalize(std::wstring s) {
    s = trim(expand(s));
    if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"') s = s.substr(1, s.size() - 2);
    std::replace(s.begin(), s.end(), L'/', L'\\');
    if (lower(s).find(L"\\systemroot\\") == 0) s = windowsDir() + s.substr(11);
    if (s.find(L"\\\\?\\") == 0 || s.find(L"\\??\\") == 0) s.erase(0, 4);
    if (s.size() > 2 && s[1] == L':') {
        std::vector<wchar_t> b(32768);
        DWORD n = GetFullPathNameW(s.c_str(), static_cast<DWORD>(b.size()), b.data(), nullptr);
        if (n && n < b.size()) s.assign(b.data(), n);
        n = GetLongPathNameW(s.c_str(), b.data(), static_cast<DWORD>(b.size()));
        if (n && n < b.size()) s.assign(b.data(), n);
    }
    return lower(s);
}
bool inside(const std::wstring& path, std::wstring dir) {
    if (dir.empty()) return false;
    dir = normalize(dir);
    if (dir.back() != L'\\') dir += L'\\';
    return normalize(path).find(dir) == 0;
}
std::wstring basename(const std::wstring& path) {
    const auto n = path.find_last_of(L"\\/");
    return lower(n == std::wstring::npos ? path : path.substr(n + 1));
}
std::vector<std::wstring> arguments(const std::wstring& command) {
    int count = 0;
    LPWSTR* values = CommandLineToArgvW(command.c_str(), &count);
    std::vector<std::wstring> result;
    if (values) {
        for (int i = 0; i < count; ++i) result.emplace_back(values[i]);
        LocalFree(values);
    }
    return result;
}
bool interpreter(const std::wstring& name) {
    static const std::set<std::wstring> names = { L"python.exe", L"pythonw.exe", L"py.exe", L"powershell.exe", L"pwsh.exe",
        L"wscript.exe", L"cscript.exe", L"mshta.exe", L"cmd.exe", L"node.exe", L"rundll32.exe", L"regsvr32.exe" };
    return names.count(lower(name)) != 0;
}
bool browser(const std::wstring& name) {
    static const std::set<std::wstring> names = { L"chrome.exe", L"msedge.exe", L"firefox.exe", L"brave.exe", L"opera.exe", L"vivaldi.exe" };
    return names.count(lower(name)) != 0;
}
bool office(const std::wstring& name) {
    static const std::set<std::wstring> names = { L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe", L"onenote.exe" };
    return names.count(lower(name)) != 0;
}
int locationScore(const std::wstring& path) {
    if (path.empty()) return 0;
    if (has(path, L"\\temp\\") || has(path, L"\\tmp\\") || inside(path, expand(L"%TEMP%"))) return 4;
    if (has(path, L"\\appdata\\")) return 2;
    if (has(path, L"\\downloads\\")) return 1;
    return 0;
}
bool systemName(const std::wstring& name) {
    static const std::set<std::wstring> names = { L"svchost.exe", L"lsass.exe", L"csrss.exe", L"services.exe",
        L"winlogon.exe", L"explorer.exe", L"smss.exe", L"wininit.exe", L"spoolsv.exe", L"dwm.exe" };
    return names.count(lower(name)) != 0;
}
bool legitimateSystemPath(const std::wstring& name, const std::wstring& path) {
    const auto n = lower(name), root = normalize(windowsDir());
    if (root.empty()) return false;
    const auto p = normalize(path);
    if (n == L"explorer.exe") return p == root + L"\\explorer.exe";
    return p == root + L"\\system32\\" + n || (n == L"svchost.exe" && p == root + L"\\syswow64\\" + n);
}

struct WarningLog {
    std::map<std::wstring, size_t> counts;
    void add(const std::wstring& text) { ++counts[text]; }
};
enum class SigKind { Microsoft, Other, Unsigned, Invalid, Unavailable };
struct Signature {
    SigKind kind = SigKind::Unavailable;
    std::wstring publisher;
    LONG status = ERROR_ACCESS_DENIED;
    bool catalog = false;
};
bool trusted(const Signature& s) { return s.kind == SigKind::Microsoft || s.kind == SigKind::Other; }
bool suspectSignature(const Signature& s) { return s.kind == SigKind::Unsigned || s.kind == SigKind::Invalid; }
std::wstring signatureLabel(const Signature& s) {
    switch (s.kind) {
    case SigKind::Microsoft: return L"Microsoft: valida";
    case SigKind::Other: return L"Outro fornecedor: valida";
    case SigKind::Unsigned: return L"Sem assinatura";
    case SigKind::Invalid: return L"Assinatura invalida/nao confiavel";
    default: return L"Verificacao indisponivel/inconclusiva";
    }
}
Signature verifyTrust(WINTRUST_DATA& data) {
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    Signature s;
    s.status = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    if (s.status == ERROR_SUCCESS) {
        s.kind = SigKind::Other;
        auto provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        auto signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain && signer->pasCertChain[0].pCert) {
            auto cert = signer->pasCertChain[0].pCert;
            wchar_t name[512]{};
            CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512);
            s.publisher = name;
            wchar_t org[512]{};
            CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(szOID_ORGANIZATION_NAME), org, 512);
            if (lower(org) == L"microsoft corporation") s.kind = SigKind::Microsoft;
        }
    } else if (s.status == TRUST_E_NOSIGNATURE) s.kind = SigKind::Unsigned;
    else if (s.status == TRUST_E_BAD_DIGEST || s.status == TRUST_E_EXPLICIT_DISTRUST ||
             s.status == CERT_E_REVOKED || s.status == CERT_E_EXPIRED || s.status == CERT_E_UNTRUSTEDROOT ||
             s.status == CERT_E_CHAINING || s.status == TRUST_E_SUBJECT_NOT_TRUSTED || s.status == CERT_E_WRONG_USAGE)
        s.kind = SigKind::Invalid;
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    return s;
}
Signature signature(const std::wstring& path) {
    static thread_local std::map<std::wstring, Signature> cache;
    static thread_local ULONGLONG cacheTime = 0;
    if (GetTickCount64() - cacheTime > 60000 || cache.size() > 4096) { cache.clear(); cacheTime = GetTickCount64(); }
    auto key = normalize(path);
    if (key.empty()) return {};
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) return cache[key] = Signature{};
    WINTRUST_FILE_INFO info{};
    info.cbStruct = sizeof(info); info.pcwszFilePath = path.c_str(); info.hFile = file.h;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE; data.pFile = &info;
    Signature s = verifyTrust(data);
    if (s.kind != SigKind::Unsigned) return cache[key] = s;
    bool catalogLookupComplete = true;
    for (const wchar_t* algorithm : { L"SHA256", L"SHA1" }) {
        HCATADMIN admin = nullptr;
        if (!CryptCATAdminAcquireContext2(&admin, nullptr, algorithm, nullptr, 0)) { catalogLookupComplete = false; continue; }
        DWORD size = 0;
        SetFilePointer(file.h, 0, nullptr, FILE_BEGIN);
        BOOL ok = CryptCATAdminCalcHashFromFileHandle2(admin, file.h, &size, nullptr, 0);
        if (!ok || !size || size > 4096) {
            catalogLookupComplete = false; CryptCATAdminReleaseContext(admin, 0); continue;
        }
        std::vector<BYTE> hash(size);
        SetFilePointer(file.h, 0, nullptr, FILE_BEGIN);
        if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.h, &size, hash.data(), 0)) {
            catalogLookupComplete = false; CryptCATAdminReleaseContext(admin, 0); continue;
        }
        HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), size, 0, nullptr);
        while (catalog) {
            CATALOG_INFO ci{}; ci.cbStruct = sizeof(ci);
            if (CryptCATCatalogInfoFromContext(catalog, &ci, 0)) {
                const wchar_t digits[] = L"0123456789ABCDEF";
                std::wstring tag;
                for (DWORD i = 0; i < size; ++i) { tag += digits[hash[i] >> 4]; tag += digits[hash[i] & 15]; }
                WINTRUST_CATALOG_INFO wi{};
                wi.cbStruct = sizeof(wi); wi.pcwszCatalogFilePath = ci.wszCatalogFile;
                wi.pcwszMemberTag = tag.c_str(); wi.pcwszMemberFilePath = path.c_str();
                wi.hMemberFile = file.h; wi.pbCalculatedFileHash = hash.data(); wi.cbCalculatedFileHash = size; wi.hCatAdmin = admin;
                WINTRUST_DATA cd{}; cd.dwUnionChoice = WTD_CHOICE_CATALOG; cd.pCatalog = &wi;
                Signature candidate = verifyTrust(cd); candidate.catalog = true;
                s = candidate;
                if (trusted(s)) { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); catalog = nullptr; break; }
            } else catalogLookupComplete = false;
            catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), size, 0, &catalog);
        }
        CryptCATAdminReleaseContext(admin, 0);
        if (trusted(s)) break;
    }
    if (s.kind == SigKind::Unsigned && !catalogLookupComplete) s.kind = SigKind::Unavailable;
    return cache[key] = s;
}

using NtQueryProcess = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
NtQueryProcess ntQuery() {
    static auto fn = reinterpret_cast<NtQueryProcess>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    return fn;
}
std::wstring commandLine(HANDLE process) {
    auto fn = ntQuery();
    if (!fn) return L"";
    ULONG size = 0;
    fn(process, 60 /* ProcessCommandLineInformation */, nullptr, 0, &size);
    if (size < sizeof(UNICODE_STRING) || size > 1024 * 1024) return L"";
    std::vector<BYTE> b(size);
    if (fn(process, 60, b.data(), size, &size) < 0) return L"";
    auto u = reinterpret_cast<const UNICODE_STRING*>(b.data());
    const auto begin = reinterpret_cast<ULONG_PTR>(b.data()), ptr = reinterpret_cast<ULONG_PTR>(u->Buffer);
    if (u->Length % sizeof(wchar_t) || ptr < begin || ptr > begin + b.size() || u->Length > begin + b.size() - ptr) return L"";
    return std::wstring(u->Buffer, u->Length / sizeof(wchar_t));
}
ULONGLONG creationTime(HANDLE process) {
    FILETIME c{}, e{}, k{}, u{};
    return GetProcessTimes(process, &c, &e, &k, &u) ? (static_cast<ULONGLONG>(c.dwHighDateTime) << 32) | c.dwLowDateTime : 0;
}
struct Connection {
    std::wstring protocol, local, remote, state;
    bool external = false, listening = false, exposed = false;
};
using Network = std::map<DWORD, std::vector<Connection>>;
bool publicV4(DWORD address) {
    const DWORD n = ntohl(address);
    const DWORD a = n >> 24, b = (n >> 16) & 255;
    return !(a == 0 || a == 10 || a == 127 || a >= 224 || (a == 169 && b == 254) ||
        (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127));
}
bool loopV6(const UCHAR* a) {
    for (int i = 0; i < 15; ++i) if (a[i]) return false;
    return a[15] == 1;
}
bool publicV6(const UCHAR* a) {
    bool mapped = true;
    for (int i = 0; i < 10; ++i) if (a[i]) mapped = false;
    if (mapped && a[10] == 255 && a[11] == 255) { DWORD v4; memcpy(&v4, a + 12, 4); return publicV4(v4); }
    return (a[0] & 0xe0) == 0x20 && !(a[0] == 0x20 && a[1] == 1 && a[2] == 0x0d && a[3] == 0xb8);
}
std::wstring endpoint(int family, const void* address, DWORD port, DWORD scope = 0) {
    wchar_t b[INET6_ADDRSTRLEN]{};
    if (!InetNtopW(family, const_cast<void*>(address), b, INET6_ADDRSTRLEN)) return L"?";
    std::wstring s = b;
    if (family == AF_INET6) { if (scope) s += L"%" + std::to_wstring(scope); s = L"[" + s + L"]"; }
    return s + L":" + std::to_wstring(ntohs(static_cast<u_short>(port)));
}
std::wstring tcpState(DWORD state) {
    static const wchar_t* names[] = { L"UNKNOWN", L"CLOSED", L"LISTENING", L"SYN_SENT", L"SYN_RCVD",
        L"ESTABLISHED", L"FIN_WAIT1", L"FIN_WAIT2", L"CLOSE_WAIT", L"CLOSING", L"LAST_ACK", L"TIME_WAIT", L"DELETE_TCB" };
    return state < _countof(names) ? names[state] : L"UNKNOWN";
}
Network network(WarningLog& warnings) {
    Network result;
    for (ULONG family : { ULONG(AF_INET), ULONG(AF_INET6) }) {
        for (bool udp : { false, true }) {
            std::vector<BYTE> b;
            DWORD size = 0, error = ERROR_INSUFFICIENT_BUFFER;
            for (int attempt = 0; attempt < 5; ++attempt) {
                error = udp ? GetExtendedUdpTable(b.empty() ? nullptr : b.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0)
                            : GetExtendedTcpTable(b.empty() ? nullptr : b.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (error != ERROR_INSUFFICIENT_BUFFER) break;
                if (!size || size > 128 * 1024 * 1024) break;
                b.resize(size);
            }
            if (error != NO_ERROR || b.empty()) { warnings.add(std::wstring(udp ? L"UDP" : L"TCP") + (family == AF_INET ? L" IPv4 indisponivel" : L" IPv6 indisponivel")); continue; }
            if (!udp && family == AF_INET) {
                auto table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(b.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& r = table->table[i];
                    const bool listen = r.dwState == MIB_TCP_STATE_LISTEN;
                    const bool active = r.dwState == MIB_TCP_STATE_ESTAB || r.dwState == MIB_TCP_STATE_SYN_SENT;
                    result[r.dwOwningPid].push_back({ L"TCP4", endpoint(AF_INET, &r.dwLocalAddr, r.dwLocalPort),
                        listen ? L"-" : endpoint(AF_INET, &r.dwRemoteAddr, r.dwRemotePort), tcpState(r.dwState),
                        active && publicV4(r.dwRemoteAddr), listen, listen && (ntohl(r.dwLocalAddr) >> 24) != 127 });
                }
            } else if (!udp) {
                auto table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(b.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& r = table->table[i];
                    const bool listen = r.dwState == MIB_TCP_STATE_LISTEN;
                    const bool active = r.dwState == MIB_TCP_STATE_ESTAB || r.dwState == MIB_TCP_STATE_SYN_SENT;
                    result[r.dwOwningPid].push_back({ L"TCP6", endpoint(AF_INET6, r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                        listen ? L"-" : endpoint(AF_INET6, r.ucRemoteAddr, r.dwRemotePort, r.dwRemoteScopeId), tcpState(r.dwState),
                        active && publicV6(r.ucRemoteAddr), listen, listen && !loopV6(r.ucLocalAddr) });
                }
            } else if (family == AF_INET) {
                auto table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(b.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& r = table->table[i];
                    result[r.dwOwningPid].push_back({ L"UDP4", endpoint(AF_INET, &r.dwLocalAddr, r.dwLocalPort), L"nao fornecido pela API", L"BOUND" });
                }
            } else {
                auto table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(b.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& r = table->table[i];
                    result[r.dwOwningPid].push_back({ L"UDP6", endpoint(AF_INET6, r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId), L"nao fornecido pela API", L"BOUND" });
                }
            }
        }
    }
    return result;
}

struct Process {
    DWORD pid = 0, parent = 0;
    ULONGLONG created = 0;
    std::wstring name, path, command, parentDescription, dllStatus = L"nao consultado", browserStatus = L"desativado";
    Signature sig;
    int score = 0;
    std::vector<std::pair<int, std::wstring>> reasons;
    std::vector<std::wstring> persistence, dlls, browserFiles;
    std::wstring scriptStatus, scriptPath;
    void add(int points, const std::wstring& reason) { score += points; reasons.emplace_back(points, reason); }
};
std::map<DWORD, Process> processes(WarningLog& warnings) {
    std::map<DWORD, Process> result;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) { warnings.add(L"Lista de processos indisponivel"); return result; }
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.h, &entry)) { warnings.add(L"Lista de processos vazia/indisponivel"); return result; }
    do {
        if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4 || entry.th32ProcessID == GetCurrentProcessId()) continue;
        Process p; p.pid = entry.th32ProcessID; p.parent = entry.th32ParentProcessID; p.name = entry.szExeFile;
        Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
        if (h) {
            std::vector<wchar_t> path(32768); DWORD size = static_cast<DWORD>(path.size());
            if (QueryFullProcessImageNameW(h.h, 0, path.data(), &size)) p.path.assign(path.data(), size);
            p.created = creationTime(h.h);
            p.command = commandLine(h.h);
        }
        if (p.path.empty()) warnings.add(L"Processos sem caminho acessivel (protegidos, acesso negado ou encerrados)");
        if (p.command.empty()) warnings.add(L"Processos sem linha de comando acessivel");
        result.emplace(p.pid, std::move(p));
    } while (Process32NextW(snapshot.h, &entry));
    return result;
}

enum class PersistKind { Run, Startup, Task, Service };
struct Persistence {
    PersistKind kind;
    std::wstring source, executable, args;
    DWORD pid = 0;
    bool enabled = true;
};
std::pair<std::wstring, std::wstring> splitCommand(const std::wstring& command) {
    auto s = trim(expand(command));
    if (s.empty()) return {};
    if (s.front() == L'"') {
        auto end = s.find(L'"', 1);
        if (end == std::wstring::npos) return {};
        return { s.substr(1, end - 1), trim(s.substr(end + 1)) };
    }
    const auto l = lower(s);
    auto exe = l.find(L".exe");
    while (exe != std::wstring::npos) {
        if (exe + 4 == s.size() || iswspace(s[exe + 4])) return { s.substr(0, exe + 4), trim(s.substr(exe + 4)) };
        exe = l.find(L".exe", exe + 4);
    }
    const auto end = s.find_first_of(L" \t");
    return { s.substr(0, end), end == std::wstring::npos ? L"" : trim(s.substr(end + 1)) };
}
void registryPersistence(std::vector<Persistence>& out, WarningLog& warnings) {
    for (HKEY hive : { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE }) {
        for (REGSAM view : { REGSAM(KEY_WOW64_64KEY), REGSAM(KEY_WOW64_32KEY) }) {
            for (const wchar_t* leaf : { L"Run", L"RunOnce" }) {
                const std::wstring key = std::wstring(L"Software\\Microsoft\\Windows\\CurrentVersion\\") + leaf;
                HKEY h = nullptr;
                LONG error = RegOpenKeyExW(hive, key.c_str(), 0, KEY_QUERY_VALUE | view, &h);
                if (error == ERROR_FILE_NOT_FOUND) continue;
                if (error != ERROR_SUCCESS) { warnings.add(L"Chaves Run/RunOnce inacessiveis"); continue; }
                DWORD maxName = 0, maxData = 0;
                if (RegQueryInfoKeyW(h, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &maxName, &maxData, nullptr, nullptr) != ERROR_SUCCESS) {
                    warnings.add(L"Metadados Run/RunOnce indisponiveis"); RegCloseKey(h); continue;
                }
                std::vector<wchar_t> name(maxName + 2), data(maxData / sizeof(wchar_t) + 2);
                for (DWORD i = 0;; ++i) {
                    DWORD n = static_cast<DWORD>(name.size()), bytes = static_cast<DWORD>((data.size() - 1) * sizeof(wchar_t)), type = 0;
                    std::fill(data.begin(), data.end(), L'\0');
                    error = RegEnumValueW(h, i, name.data(), &n, nullptr, &type, reinterpret_cast<BYTE*>(data.data()), &bytes);
                    if (error == ERROR_NO_MORE_ITEMS) break;
                    if (error != ERROR_SUCCESS) { warnings.add(L"Valores Run/RunOnce nao lidos"); continue; }
                    if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                    auto parts = splitCommand(data.data());
                    std::wstring source = hive == HKEY_CURRENT_USER ? L"HKCU\\" : L"HKLM\\";
                    source += key + L" [" + (view == KEY_WOW64_64KEY ? std::wstring(L"64") : std::wstring(L"32")) + L" bits] / " + std::wstring(name.data(), n);
                    out.push_back({ PersistKind::Run, source, parts.first, parts.second });
                }
                RegCloseKey(h);
            }
        }
    }
}
void startupPersistence(std::vector<Persistence>& out, WarningLog& warnings, bool comReady) {
    for (const KNOWNFOLDERID* id : { &FOLDERID_Startup, &FOLDERID_CommonStartup }) {
        PWSTR folder = nullptr;
        if (FAILED(SHGetKnownFolderPath(*id, KF_FLAG_DONT_VERIFY, nullptr, &folder))) { warnings.add(L"Pasta Startup indisponivel"); continue; }
        std::wstring directory(folder); CoTaskMemFree(folder);
        WIN32_FIND_DATAW item{};
        HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &item);
        if (find == INVALID_HANDLE_VALUE) { if (GetLastError() != ERROR_FILE_NOT_FOUND) warnings.add(L"Pasta Startup nao enumerada"); continue; }
        do {
            if (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            const std::wstring path = directory + L"\\" + item.cFileName;
            std::wstring exe = path, args;
            if (has(basename(path), L".lnk") && basename(path).size() >= 4 && basename(path).substr(basename(path).size() - 4) == L".lnk") {
                Com<IShellLinkW> link; Com<IPersistFile> file;
                if (!comReady || FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(link.out()))) ||
                    FAILED(link->QueryInterface(IID_PPV_ARGS(file.out()))) || FAILED(file->Load(path.c_str(), STGM_READ))) {
                    warnings.add(L"Atalhos Startup nao resolvidos"); continue;
                }
                std::vector<wchar_t> target(32768), argumentsBuffer(32768);
                if (FAILED(link->GetPath(target.data(), static_cast<int>(target.size()), nullptr, SLGP_RAWPATH))) { warnings.add(L"Destino Startup indisponivel"); continue; }
                exe = target.data();
                if (SUCCEEDED(link->GetArguments(argumentsBuffer.data(), static_cast<int>(argumentsBuffer.size())))) args = argumentsBuffer.data();
            }
            out.push_back({ PersistKind::Startup, L"Startup: " + path, exe, args });
        } while (FindNextFileW(find, &item));
        FindClose(find);
    }
}
void taskFolder(ITaskFolder* folder, std::vector<Persistence>& out, WarningLog& warnings, int depth = 0) {
    if (depth > 32) { warnings.add(L"Limite de profundidade de tarefas atingido"); return; }
    Com<IRegisteredTaskCollection> tasks;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, tasks.out()))) {
        LONG count = 0; tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            VARIANT index{}; index.vt = VT_I4; index.lVal = i;
            Com<IRegisteredTask> task; Com<ITaskDefinition> definition; Com<IActionCollection> actions;
            if (FAILED(tasks->get_Item(index, task.out())) || FAILED(task->get_Definition(definition.out())) || FAILED(definition->get_Actions(actions.out()))) {
                warnings.add(L"Definicoes de tarefas inacessiveis"); continue;
            }
            Bstr name; task->get_Path(&name.p);
            VARIANT_BOOL enabled = VARIANT_FALSE; task->get_Enabled(&enabled);
            LONG total = 0; actions->get_Count(&total);
            for (LONG j = 1; j <= total; ++j) {
                Com<IAction> action; Com<IExecAction> exec;
                if (FAILED(actions->get_Item(j, action.out()))) { warnings.add(L"Acoes de tarefas inacessiveis"); continue; }
                if (FAILED(action->QueryInterface(IID_PPV_ARGS(exec.out())))) { warnings.add(L"Acoes de tarefas nao executaveis (ex.: COM) nao correlacionadas"); continue; }
                Bstr path, args; exec->get_Path(&path.p); exec->get_Arguments(&args.p);
                out.push_back({ PersistKind::Task, L"Tarefa: " + name.str(), path.str(), args.str(), 0, enabled == VARIANT_TRUE });
            }
        }
    } else warnings.add(L"Pastas de tarefas inacessiveis");
    Com<ITaskFolderCollection> folders;
    if (FAILED(folder->GetFolders(0, folders.out()))) { warnings.add(L"Subpastas de tarefas inacessiveis"); return; }
    LONG count = 0; folders->get_Count(&count);
    for (LONG i = 1; i <= count; ++i) {
        VARIANT index{}; index.vt = VT_I4; index.lVal = i;
        Com<ITaskFolder> child;
        if (SUCCEEDED(folders->get_Item(index, child.out()))) taskFolder(child.p, out, warnings, depth + 1);
        else warnings.add(L"Subpastas de tarefas inacessiveis");
    }
}
void taskPersistence(std::vector<Persistence>& out, WarningLog& warnings, bool comReady) {
    Com<ITaskService> service;
    if (!comReady || FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(service.out())))) {
        warnings.add(L"Agendador de tarefas indisponivel"); return;
    }
    VARIANT empty{}; empty.vt = VT_EMPTY;
    if (FAILED(service->Connect(empty, empty, empty, empty))) { warnings.add(L"Conexao com Agendador indisponivel"); return; }
    Bstr root(L"\\"); Com<ITaskFolder> folder;
    const HRESULT result = service->GetFolder(root.p, folder.out());
    if (SUCCEEDED(result)) taskFolder(folder.p, out, warnings);
    else warnings.add(L"Pasta raiz do Agendador indisponivel" + errorCode(result));
}
void servicePersistence(std::vector<Persistence>& out, WarningLog& warnings) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { warnings.add(L"Lista de servicos indisponivel"); return; }
    DWORD resume = 0;
    std::vector<BYTE> b(256 * 1024);
    for (;;) {
        DWORD needed = 0, count = 0;
        BOOL ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, b.data(),
            static_cast<DWORD>(b.size()), &needed, &count, &resume, nullptr);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && error != ERROR_MORE_DATA) { warnings.add(L"Enumeracao de servicos incompleta"); break; }
        auto entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(b.data());
        for (DWORD i = 0; i < count; ++i) {
            SC_HANDLE service = OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (!service) { warnings.add(L"Configuracoes de servicos inacessiveis"); continue; }
            DWORD size = 0; QueryServiceConfigW(service, nullptr, 0, &size);
            std::vector<BYTE> config(size);
            if (size && QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()), size, &size)) {
                auto c = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
                auto parts = splitCommand(c->lpBinaryPathName ? c->lpBinaryPathName : L"");
                out.push_back({ PersistKind::Service, std::wstring(L"Servico: ") + entries[i].lpServiceName +
                    (c->dwStartType == SERVICE_AUTO_START ? L" (automatico)" : L" (sob demanda/desativado)"),
                    parts.first, parts.second, entries[i].ServiceStatusProcess.dwProcessId, c->dwStartType != SERVICE_DISABLED });
            } else warnings.add(L"Configuracoes de servicos nao lidas");
            CloseServiceHandle(service);
        }
        if (ok) break;
        if (!count) { warnings.add(L"Limite de enumeracao de servicos atingido"); break; }
    }
    CloseServiceHandle(scm);
}

bool matches(const Persistence& entry, const Process& process) {
    if (process.path.empty() || entry.executable.empty()) return false;
    auto target = normalize(entry.executable), actual = normalize(process.path);
    if (target.size() < 3 || target[1] != L':' || target != actual) return false;
    if (entry.kind == PersistKind::Service && entry.pid && entry.pid != process.pid) return false;
    if (interpreter(process.name) || basename(process.name) == L"svchost.exe") {
        auto configured = arguments(L"host.exe " + expand(entry.args));
        auto running = arguments(process.command);
        if (configured.size() <= 1 || running.size() < configured.size()) return false;
        for (size_t i = 1; i < configured.size(); ++i) {
            const auto c = expand(configured[i]), r = running[i];
            const bool pathArgument = c.size() > 2 && c[1] == L':' && r.size() > 2 && r[1] == L':';
            if (pathArgument ? normalize(c) != normalize(r) : c != r) return false;
        }
    }
    return true;
}
void commandSignals(Process& p) {
    if (!interpreter(p.name) || p.command.empty()) return;
    auto args = arguments(p.command);
    bool encoded = false, hidden = false, scriptTemp = false, scriptAppData = false;
    const bool powershell = lower(p.name) == L"powershell.exe" || lower(p.name) == L"pwsh.exe";
    for (size_t i = 1; i < args.size(); ++i) {
        auto a = lower(args[i]);
        if (powershell && (a == L"-ec" || (a.size() >= 2 && std::wstring(L"-encodedcommand").find(a) == 0))) encoded = true;
        if (powershell && (a == L"-windowstyle" || a == L"-w" || a == L"-window") && i + 1 < args.size() &&
            (lower(args[i + 1]) == L"hidden" || args[i + 1] == L"1")) hidden = true;
        const auto n = normalize(args[i]);
        if (n.size() > 2 && n[1] == L':') {
            const int loc = locationScore(n);
            if (loc == 4) scriptTemp = true;
            else if (loc == 2) scriptAppData = true;
        }
    }
    if (encoded) p.add(2, L"PowerShell com comando codificado (-EncodedCommand ou abreviacao)");
    if (hidden) p.add(1, L"PowerShell solicita janela oculta na linha de comando");
    if (scriptTemp) p.add(4, L"Interpretador referencia arquivo/argumento em Temp");
    else if (scriptAppData) p.add(2, L"Interpretador referencia arquivo/argumento em AppData");
    if (lower(p.name) == L"pythonw.exe") p.add(1, L"pythonw executa sem console (tambem comum em aplicativos legitimos)");
}
void parentSignals(Process& p, const std::map<DWORD, Process>& all) {
    const auto it = all.find(p.parent);
    if (it == all.end() || !p.created || !it->second.created || it->second.created > p.created) {
        p.parentDescription = L"indisponivel/encerrado ou PID reutilizado"; return;
    }
    const auto& parent = it->second;
    p.parentDescription = parent.name + L" | " + parent.path;
    if (!interpreter(p.name)) return;
    if (browser(parent.name) || office(parent.name)) p.add(2, L"Interpretador iniciado por navegador/aplicativo Office");
    else if (interpreter(parent.name)) {
        const auto grand = all.find(parent.parent);
        if (grand != all.end() && grand->second.created && grand->second.created <= parent.created &&
            (browser(grand->second.name) || office(grand->second.name)))
            p.add(2, L"Cadeia incomum: " + grand->second.name + L" -> " + parent.name + L" -> " + p.name);
    }
}
void loadedModules(Process& p, WarningLog& warnings) {
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
    if (!process || !p.created || creationTime(process.h) != p.created) { p.dllStatus = L"processo inacessivel/encerrado"; warnings.add(L"DLLs nao verificadas em alguns processos"); return; }
    HANDLE raw = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 3; ++i) {
        raw = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p.pid);
        if (raw != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
    }
    Handle snapshot(raw);
    if (!snapshot) { p.dllStatus = L"acesso negado/protegido ou encerrado"; warnings.add(L"DLLs nao verificadas em alguns processos"); return; }
    MODULEENTRY32W m{}; m.dwSize = sizeof(m);
    if (!Module32FirstW(snapshot.h, &m)) { p.dllStatus = L"lista indisponivel"; warnings.add(L"DLLs nao verificadas em alguns processos"); return; }
    std::set<std::wstring> seen;
    bool temp = false, unsignedUser = false;
    do {
        const std::wstring path = m.szExePath;
        const auto key = normalize(path);
        if (key == normalize(p.path) || !seen.insert(key).second) continue;
        const int loc = locationScore(path);
        if (loc < 2) continue;
        const auto sig = signature(path);
        p.dlls.push_back(path + L" [" + signatureLabel(sig) + L"]");
        if (loc == 4) temp = true;
        else if (suspectSignature(sig)) unsignedUser = true;
    } while (Module32NextW(snapshot.h, &m));
    p.dllStatus = L"consultado (modulos enumeraveis pelo Windows)";
    if (temp) p.add(4, L"Modulo carregado de Temp");
    else if (unsignedUser) p.add(4, L"Modulo sem assinatura valida carregado de AppData");
}

struct NativeHandleEntry {
    HANDLE value;
    ULONG_PTR handleCount, pointerCount;
    ULONG grantedAccess, objectTypeIndex, attributes, reserved;
};
struct NativeHandleSnapshot { ULONG_PTR count, reserved; NativeHandleEntry entries[1]; };
struct BrowserResult {
    DWORD completed, count, skipped;
    wchar_t paths[16][1024];
};
bool browserStorage(const std::wstring& path) {
    const auto p = lower(path), name = basename(p);
    const bool discord = has(p, L"\\discord\\local storage\\leveldb\\") ||
        has(p, L"\\discordcanary\\local storage\\leveldb\\") || has(p, L"\\discordptb\\local storage\\leveldb\\");
    if (discord) return true;
    bool profile = has(p, L"\\google\\chrome\\user data\\") || has(p, L"\\microsoft\\edge\\user data\\") ||
        has(p, L"\\bravesoftware\\brave-browser\\user data\\") || has(p, L"\\vivaldi\\user data\\") ||
        has(p, L"\\opera software\\") || has(p, L"\\mozilla\\firefox\\profiles\\");
    return profile && (name == L"login data" || name == L"cookies" || name == L"web data" || name == L"local state" ||
        name == L"logins.json" || name == L"key4.db" || name == L"cookies.sqlite" || has(p, L"\\local storage\\") ||
        has(p, L"\\session storage\\") || has(p, L"\\sessions\\"));
}
int browserWorker(DWORD pid, ULONGLONG created, HANDLE mapping) {
    auto result = static_cast<BrowserResult*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(BrowserResult)));
    if (!result) return 2;
    Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid));
    auto fn = ntQuery();
    if (!process || !fn || !created || creationTime(process.h) != created) { UnmapViewOfFile(result); return 3; }
    ULONG size = 65536;
    std::vector<BYTE> b;
    LONG status = -1;
    for (int attempt = 0; attempt < 10; ++attempt) {
        b.resize(size);
        ULONG needed = 0;
        status = fn(process.h, 51 /* ProcessHandleInformation */, b.data(), size, &needed);
        if (status >= 0) break;
        if (status != static_cast<LONG>(0xC0000004L) && status != static_cast<LONG>(0xC0000023L)) break;
        size = std::max(size * 2, needed);
        if (size > 32 * 1024 * 1024) break;
    }
    if (status < 0) { UnmapViewOfFile(result); return 4; }
    auto snapshot = reinterpret_cast<const NativeHandleSnapshot*>(b.data());
    const size_t capacity = (b.size() - offsetof(NativeHandleSnapshot, entries)) / sizeof(NativeHandleEntry);
    if (snapshot->count > capacity) { UnmapViewOfFile(result); return 5; }
    std::set<std::wstring> seen;
    const size_t limit = std::min<size_t>(snapshot->count, 8192);
    if (snapshot->count > limit) result->skipped = 1;
    for (size_t i = 0; i < limit; ++i) {
        HANDLE copy = nullptr;
        if (!DuplicateHandle(process.h, snapshot->entries[i].value, GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            ++result->skipped; continue;
        }
        Handle h(copy);
        if (GetFileType(h.h) != FILE_TYPE_DISK) continue;
        wchar_t name[32768]{};
        DWORD n = GetFinalPathNameByHandleW(h.h, name, _countof(name), FILE_NAME_OPENED | VOLUME_NAME_DOS);
        if (!n || n >= _countof(name)) { ++result->skipped; continue; }
        if (browserStorage(name) && seen.insert(normalize(name)).second) {
            if (result->count >= _countof(result->paths)) { ++result->skipped; break; }
            wcsncpy_s(result->paths[result->count], name, _TRUNCATE);
            ++result->count;
        }
    }
    result->completed = 1;
    UnmapViewOfFile(result);
    return 0;
}
void browserHandles(Process& p, DWORD timeout) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(BrowserResult), nullptr));
    if (!mapping) { p.browserStatus = L"memoria compartilhada indisponivel"; return; }
    auto result = static_cast<BrowserResult*>(MapViewOfFile(mapping.h, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(BrowserResult)));
    if (!result) { p.browserStatus = L"memoria compartilhada indisponivel"; return; }
    ZeroMemory(result, sizeof(*result));
    std::vector<wchar_t> exe(32768);
    DWORD n = GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size()));
    if (!n || n >= exe.size()) { UnmapViewOfFile(result); p.browserStatus = L"caminho do scanner indisponivel"; return; }
    std::wstring command = L"\"" + std::wstring(exe.data()) + L"\" --browser-worker " + std::to_wstring(p.pid) + L" " +
        std::to_wstring(p.created) + L" " + std::to_wstring(reinterpret_cast<ULONG_PTR>(mapping.h));
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<BYTE> attrs(size);
    STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrs.data());
    bool initialized = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size) != FALSE;
    PROCESS_INFORMATION pi{};
    bool started = initialized && UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        &mapping.h, sizeof(mapping.h), nullptr, nullptr) && CreateProcessW(exe.data(), &command[0], nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi);
    if (initialized) DeleteProcThreadAttributeList(si.lpAttributeList);
    if (started) {
        Handle child(pi.hProcess), thread(pi.hThread);
        const DWORD wait = WaitForSingleObject(child.h, timeout);
        if (wait != WAIT_OBJECT_0) {
            TerminateProcess(child.h, 124); WaitForSingleObject(child.h, 1000);
            p.browserStatus = L"tempo limite; consulta incompleta";
        } else if (result->completed) {
            p.browserStatus = result->skipped ? L"consulta parcial; alguns handles nao resolvidos" : L"handles abertos consultados";
            for (DWORD i = 0; i < std::min<DWORD>(result->count, 16); ++i) p.browserFiles.emplace_back(result->paths[i]);
        } else p.browserStatus = L"acesso negado, processo encerrado ou API indisponivel";
    } else p.browserStatus = L"nao foi possivel iniciar consulta isolada";
    UnmapViewOfFile(result);
    if (!p.browserFiles.empty()) p.add(5, L"Handle aberto para armazenamento de navegador; nao prova leitura/exfiltracao");
}

const wchar_t* classification(int score) {
    if (score >= 13) return L"ALTO RISCO";
    if (score >= 8) return L"SUSPEITO";
    if (score >= 4) return L"ATENCAO";
    return L"BAIXO";
}
#include "pid_script.h"
void scoreProcess(Process& p, const std::map<DWORD, Process>& all, const std::vector<Persistence>& persistence, const std::vector<Connection>& connections) {
    const int loc = locationScore(p.path);
    if (loc) p.add(loc, loc == 4 ? L"Executavel em Temp" : loc == 2 ? L"Executavel em AppData" : L"Executavel em Downloads");
    p.sig = signature(p.path);
    if (p.sig.kind == SigKind::Unsigned) p.add(2, L"Executavel sem assinatura (embutida/catalogo)");
    if (p.sig.kind == SigKind::Invalid) p.add(3, L"Assinatura invalida ou nao confiavel neste computador");
    if (!p.path.empty() && systemName(p.name)) {
        if (!legitimateSystemPath(p.name, p.path)) p.add(5, L"Nome de processo do Windows fora do caminho esperado");
        else if (p.sig.kind != SigKind::Microsoft && p.sig.kind != SigKind::Unavailable) p.add(5, L"Nome de processo do Windows sem assinatura Microsoft validada");
    }
    size_t external = 0;
    bool listener = false;
    for (const auto& c : connections) { if (c.external) ++external; if (c.exposed) listener = true; }
    if (external) p.add(1, L"Conexao TCP ativa/tentativa para endereco externo");
    if (external >= 10) p.add(2, L"Dez ou mais conexoes TCP externas simultaneas");
    if (external && interpreter(p.name)) p.add(2, L"Interpretador com conexao externa");
    if (listener) p.add(2, L"Porta TCP LISTENING em interface nao loopback");
    commandSignals(p);
    scriptSignals(p);
    parentSignals(p, all);
    std::set<PersistKind> scored;
    for (const auto& entry : persistence) {
        if (!matches(entry, p)) continue;
        std::wstring description = entry.source + (entry.enabled ? L"" : L" [desativada]") + L" -> " + entry.executable;
        if (!entry.args.empty()) description += L" " + entry.args;
        p.persistence.push_back(description);
        const bool suspicious = loc > 0 || suspectSignature(p.sig) || interpreter(p.name) || p.score >= 4;
        if (!entry.enabled || scored.count(entry.kind)) continue;
        if ((entry.kind == PersistKind::Task || entry.kind == PersistKind::Service) && !suspicious) continue;
        scored.insert(entry.kind);
        switch (entry.kind) {
        case PersistKind::Run: p.add(4, L"Persistencia correlacionada em Run/RunOnce"); break;
        case PersistKind::Startup: p.add(4, L"Persistencia correlacionada na pasta Startup"); break;
        case PersistKind::Task: p.add(4, L"Tarefa agendada correlacionada com outros sinais"); break;
        case PersistKind::Service: p.add(4, L"Servico correlacionado com outros sinais (idade nao determinada)"); break;
        }
    }
}
std::wstring printable(std::wstring s) {
    for (auto& c : s) if (c < 32 || c == 127) c = L' ';
    return s;
}
void printProcess(const Process& p, const std::vector<Connection>& connections) {
    std::wcout << L"\n========================================\nPID: " << p.pid << L"\nProcesso: " << printable(p.name)
        << L"\nCaminho: " << (p.path.empty() ? L"indisponivel" : printable(p.path))
        << L"\nLinha de comando: " << (p.command.empty() ? L"indisponivel" : printable(p.command))
        << L"\nPai PID: " << p.parent << L" | " << printable(p.parentDescription)
        << L"\nAssinatura: " << signatureLabel(p.sig);
    if (!p.sig.publisher.empty()) std::wcout << L" | " << printable(p.sig.publisher);
    if (p.sig.catalog) std::wcout << L" (catalogo)";
    std::wcout << L" | status 0x" << std::hex << static_cast<ULONG>(p.sig.status) << std::dec
        << L"\nRISCO: " << p.score << L" | " << classification(p.score) << L"\nEvidencias:\n";
    if (p.reasons.empty()) std::wcout << L"  Nenhum sinal pontuado nesta coleta.\n";
    for (const auto& reason : p.reasons) std::wcout << L"  [+" << reason.first << L"] " << printable(reason.second) << L"\n";
    if (!connections.empty()) {
        std::wcout << L"Rede (" << connections.size() << L" entradas; UDP mostra apenas endpoint local):\n";
        for (const auto& c : connections) std::wcout << L"  " << c.protocol << L" " << c.local << L" -> " << c.remote << L" " << c.state << (c.external ? L" [EXTERNA]" : L"") << L"\n";
    }
    if (!p.persistence.empty()) {
        std::wcout << L"Persistencia correlacionada:\n";
        for (const auto& value : p.persistence) std::wcout << L"  " << printable(value) << L"\n";
    }
    std::wcout << L"DLLs: " << p.dllStatus << L"\n";
    if (!p.scriptStatus.empty()) std::wcout << L"Script: " << p.scriptStatus << L" | " << printable(p.scriptPath) << L"\n";
    for (const auto& value : p.dlls) std::wcout << L"  " << printable(value) << L"\n";
    std::wcout << L"Armazenamento de navegador: " << p.browserStatus << L"\n";
    for (const auto& value : p.browserFiles) std::wcout << L"  " << printable(value) << L"\n";
    if (p.score >= 13) std::wcout << L"Combinacao de sinais compativel com malware/stealer/RAT; exige investigacao.\n";
}
void help() {
    std::wcout << L"Sem argumentos: interface Sentinel com monitoramento continuo.\n"
        L"  --gui              Abre a interface grafica.\n"
        L"  --scan             Executa o scanner pontual no terminal.\n"
        L"Uso do scanner: pid.exe [--scan] [--all] [--min-score N] [--pid N] [--browser-handles] [--pause]\n"
        L"  --all              Mostra tambem processos com risco baixo.\n"
        L"  --min-score N      Limiar de exibicao (padrao: 4).\n"
        L"  --pid N            Examina somente este PID (mostra qualquer score).\n"
        L"  --browser-handles  Consulta arquivos de navegador abertos em processos\n"
        L"                     com score >= 4, ou no PID explicitamente selecionado.\n"
        L"                     Limite de 3 s/processo e 30 s no total.\n"
        L"  --pause            Opcional; a pausa no final agora e automatica.\n"
        L"  --help             Mostra esta ajuda.\n"
        L"Windows 10/11 x64. Consulta somente leitura; nao remove nem encerra alvos.\n";
}
bool number(const wchar_t* text, ULONGLONG& value) {
    if (!text || !*text) return false;
    value = 0;
    for (const wchar_t* p = text; *p; ++p) {
        if (*p < L'0' || *p > L'9' || value > (ULLONG_MAX - (*p - L'0')) / 10) return false;
        value = value * 10 + (*p - L'0');
    }
    return true;
}
#ifndef PID_CORE_ONLY
#include "pid_monitor_ui.h"
#endif
int wmain(int argc, wchar_t** argv) {
    if (argc == 5 && std::wstring(argv[1]) == L"--browser-worker") {
        ULONGLONG pid = 0, created = 0, mapping = 0;
        if (!number(argv[2], pid) || pid > MAXDWORD || !number(argv[3], created) || !number(argv[4], mapping)) return 2;
        return browserWorker(static_cast<DWORD>(pid), created, reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(mapping)));
    }
#ifndef PID_CORE_ONLY
    if (argc == 1 || std::wstring(argv[1]) == L"--gui" || std::wstring(argv[1]) == L"--ui-test") return monitorApp(argc, argv);
#endif
    if (argc > 1 && std::wstring(argv[1]) == L"--scan") { --argc; ++argv; }
    _setmode(_fileno(stdout), _isatty(_fileno(stdout)) ? _O_U16TEXT : _O_U8TEXT);
    _setmode(_fileno(stderr), _isatty(_fileno(stderr)) ? _O_U16TEXT : _O_U8TEXT);
    int minScore = 4; DWORD onlyPid = 0; bool deep = false;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"/?") { help(); return 0; }
        if (arg == L"--all") minScore = 0;
        else if (arg == L"--browser-handles") deep = true;
        else if (arg == L"--pause") { /* Mantido por compatibilidade. */ }
        else if ((arg == L"--min-score" || arg == L"--pid") && i + 1 < argc) {
            ULONGLONG value = 0;
            if (!number(argv[++i], value) || (arg == L"--pid" ? value == 0 || value > MAXDWORD : value > 100000)) {
                std::wcerr << L"Valor numerico invalido.\n"; return 2;
            }
            if (arg == L"--pid") onlyPid = static_cast<DWORD>(value); else minScore = static_cast<int>(value);
        } else { std::wcerr << L"Opcao desconhecida/incompleta: " << arg << L"\n"; help(); return 2; }
    }
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { std::wcerr << L"Falha ao iniciar Winsock.\n"; return 1; }
    const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool comReady = SUCCEEDED(co);
    WarningLog warnings;
    if (comReady) {
        const HRESULT security = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
        if (FAILED(security) && security != RPC_E_TOO_LATE) warnings.add(L"Seguranca COM indisponivel" + errorCode(security));
    }
    std::wcerr << L"Coletando processos, rede e persistencia...\n";
    auto all = processes(warnings);
    if (all.empty() || (onlyPid && !all.count(onlyPid))) {
        std::wcerr << L"Nenhum processo acessivel/selecionado encontrado. PID 0, 4 e o scanner sao excluidos.\n";
        if (comReady) CoUninitialize(); WSACleanup(); return 1;
    }
    auto net = network(warnings);
    std::vector<Persistence> persistence;
    registryPersistence(persistence, warnings);
    startupPersistence(persistence, warnings, comReady);
    taskPersistence(persistence, warnings, comReady);
    servicePersistence(persistence, warnings);
    std::vector<Process*> ranked;
    size_t done = 0;
    for (auto& item : all) {
        auto& p = item.second;
        if (onlyPid && p.pid != onlyPid) continue;
        scoreProcess(p, all, persistence, net[p.pid]);
        loadedModules(p, warnings);
        ranked.push_back(&p);
        if (++done % 25 == 0) std::wcerr << L"Verificados " << done << L" processos...\n";
    }
    auto sortRisk = [](const Process* a, const Process* b) { return a->score != b->score ? a->score > b->score : a->pid < b->pid; };
    std::sort(ranked.begin(), ranked.end(), sortRisk);
    if (deep) {
        std::wcerr << L"Consultando handles de arquivos em processos selecionados...\n";
        const ULONGLONG start = GetTickCount64();
        for (auto p : ranked) {
            if (!onlyPid && p->score < 4) { p->browserStatus = L"nao selecionado (score < 4)"; continue; }
            if (!onlyPid && browser(p->name) && trusted(p->sig)) { p->browserStatus = L"navegador assinado; acesso esperado, consulta omitida"; continue; }
            ULONGLONG elapsed = GetTickCount64() - start;
            if (elapsed >= 30000) { p->browserStatus = L"nao consultado: limite global de 30 s"; warnings.add(L"Consulta de handles limitada pelo tempo global"); continue; }
            browserHandles(*p, static_cast<DWORD>(std::min<ULONGLONG>(3000, 30000 - elapsed)));
        }
        std::sort(ranked.begin(), ranked.end(), sortRisk);
    }
    std::wcout << L"========== TRIAGEM DE PROCESSOS ==========\n"
        L"Foto do momento; pontuacao heuristica, nao diagnostico de infeccao.\n"
        L"BAIXO 0-3 | ATENCAO 4-7 | SUSPEITO 8-12 | ALTO RISCO 13+\n"
        L"Assinaturas verificadas com confianca local, sem consulta online de revogacao.\n"
        L"UDP nao revela destino remoto nesta API; nao recebe pontos por conexao externa.\n"
        L"Linhas de comando podem conter informacoes privadas; revise antes de compartilhar.\n";
    size_t shown = 0;
    for (const auto p : ranked) if (onlyPid || p->score >= minScore) { printProcess(*p, net[p->pid]); ++shown; }
    std::wcout << L"\n========================================\nAnalisados: " << ranked.size() << L" | Exibidos: " << shown
        << L" | Entradas de persistencia coletadas: " << persistence.size() << L"\n";
    if (!shown) std::wcout << L"Nenhum processo atingiu o limiar. Isso nao garante ausencia de malware.\n";
    std::wcout << L"Cobertura: HKCU atual, HKLM 32/64 bits, Startup atual/comum, tarefas e servicos acessiveis.\n"
        L"Sem historico de acesso a arquivos, de criacao de servicos ou de conexoes.\n"
        L"Handles abertos nao comprovam leitura; arquivos ja fechados nao sao observados.\n"
        L"Permissoes elevadas ampliam a cobertura, mas processos protegidos podem permanecer inacessiveis.\n";
    if (!warnings.counts.empty()) {
        std::wcout << L"Consultas incompletas/limitacoes observadas:\n";
        for (const auto& item : warnings.counts) std::wcout << L"  " << item.first << L": " << item.second << L"\n";
    }
    if (comReady) CoUninitialize();
    WSACleanup();
    std::wcout << std::flush;
    std::system("pause");
    return 0;
}
