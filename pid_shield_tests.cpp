#define PID_CORE_ONLY
#define wmain scanner_entry
#include "pid.cpp"
#undef wmain
#include "pid_shield.h"
#include "driver/shared/sentinel_protocol.h"

static int failures = 0;
void check(bool value, const char* label) { std::cout << (value ? "PASS " : "FAIL ") << label << '\n'; if (!value) ++failures; }
template<class F> bool until(F predicate) {
    const auto started = GetTickCount64();
    while (GetTickCount64() - started < 8000) { if (predicate()) return true; Sleep(10); }
    return false;
}
struct FakeFirewall : ShieldBackend {
    std::atomic<int> blocks{0}, removes{0}, lists{0};
    std::atomic<HRESULT> readiness{S_OK}, blockResult{S_OK}, removeResult{S_OK};
    std::vector<ShieldRule> rules;
    HRESULT available() override { return readiness.load(); }
    HRESULT list(std::vector<ShieldRule>& out) override { out = rules; ++lists; return S_OK; }
    HRESULT block(const Process& p, ShieldRule& rule) override {
        ++blocks;
        HRESULT hr = blockResult.load();
        if (SUCCEEDED(hr)) { rule = {L"fixture", normalize(p.path)}; rules.push_back(rule); }
        return hr;
    }
    HRESULT remove(const ShieldRule& rule) override {
        ++removes;
        HRESULT hr = removeResult.load();
        if (SUCCEEDED(hr)) rules.erase(std::remove_if(rules.begin(), rules.end(), [&](const ShieldRule& r) { return r.name == rule.name; }), rules.end());
        return hr;
    }
};
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--fixture") { Sleep(60000); return 0; }
    const std::wstring storage = L"C:\\Users\\Fixture\\AppData\\Roaming\\Discord\\Local Storage\\leveldb\\000001.ldb";
    Process python; python.pid = 987654; python.created = 123; python.name = L"python.exe"; python.path = L"C:\\Fixture\\python.exe";
    check(!shieldCandidate(python, L"C:\\project\\main.py", false), "ordinary Python never isolated without sensitive storage");
    check(shieldCandidate(python, storage, false), "interpreter with sensitive storage eligible before full scan");
    auto unknown = python; unknown.created = 0;
    check(!shieldCandidate(unknown, storage, true), "unknown process identity rejected");
    unknown = python; unknown.pid = GetCurrentProcessId();
    check(!shieldCandidate(unknown, storage, true), "self process rejected");
    unknown = python; unknown.name = L"tool.exe"; unknown.path = L"C:\\Fixture\\tool.exe"; unknown.score = 8;
    check(!shieldCandidate(unknown, storage, false) && shieldCandidate(unknown, storage, true), "other executables require completed analysis and score");
    unknown.score = 7;
    check(!shieldCandidate(unknown, storage, true), "low score below threshold");
    Process discord = unknown; discord.name = L"Discord.exe"; discord.path = L"C:\\Fixture\\Discord.exe";
    discord.sig.kind = SigKind::Other; discord.sig.publisher = L"Discord Inc."; discord.score = 20;
    check(expectedStorageAccess(discord, storage) && !shieldCandidate(discord, storage, true), "signed Discord accessing own LevelDB allowed");
    discord.sig.publisher = L"Unrelated Publisher";
    check(!expectedStorageAccess(discord, storage), "any valid publisher is not enough");
    discord.sig.publisher = L"Discord Inc."; discord.name = L"evil-discord.exe";
    check(!expectedStorageAccess(discord, storage), "substring impersonation not allowed");
    auto chrome = discord; chrome.name = L"chrome.exe"; chrome.path = L"C:\\Fixture\\chrome.exe"; chrome.sig.publisher = L"Google LLC";
    check(!expectedStorageAccess(chrome, storage), "signed browser does not allow access to Discord");
    check(expectedStorageAccess(chrome, L"C:\\Fixture\\Google\\Chrome\\User Data\\Default\\Login Data"), "signed Chrome accessing own storage allowed");
    chrome.sig.kind = SigKind::Invalid;
    check(!expectedStorageAccess(chrome, L"C:\\Fixture\\Google\\Chrome\\User Data\\Local State"), "invalid signature cannot bypass Shield");

    wchar_t own[32768]{}; GetModuleFileNameW(nullptr, own, _countof(own));
    std::wstring command = L"\"" + std::wstring(own) + L"\" --fixture";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION child{};
    const bool spawned = CreateProcessW(own, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child) != FALSE;
    check(spawned, "create harmless identity fixture");
    if (spawned) {
        Handle process(child.hProcess), thread(child.hThread);
        Process live; live.pid = child.dwProcessId; live.created = creationTime(process.h); live.path = own;
        { Handle verified; std::wstring path; check(SUCCEEDED(shieldLiveIdentity(live, verified, path)), "live PID creation and path validated without firewall changes"); }
        --live.created;
        { Handle verified; std::wstring path; check(FAILED(shieldLiveIdentity(live, verified, path)), "reused PID creation mismatch rejected before mutation"); }
        ++live.created; live.path += L".wrong";
        { Handle verified; std::wstring path; check(FAILED(shieldLiveIdentity(live, verified, path)), "changed executable path rejected before mutation"); }
        live.path = own; TerminateProcess(process.h, 0); WaitForSingleObject(process.h, 5000);
        { Handle verified; std::wstring path; check(FAILED(shieldLiveIdentity(live, verified, path)), "exited process rejected before mutation"); }
    }

    auto backend = std::make_unique<FakeFirewall>(); auto* fake = backend.get();
    fake->rules.push_back({L"previous-session", L"c:\\fixture\\old.exe"});
    std::mutex logMutex; std::vector<std::wstring> messages;
    ShieldController shield([&](int, const std::wstring& message) { std::lock_guard<std::mutex> guard(logMutex); messages.push_back(message); }, std::move(backend));
    shield.start();
    check(until([&] { return shield.snapshot().rules.size() == 1; }), "persistent rules recovered at startup");
    shield.consider(python, storage, false); Sleep(100);
    check(!shield.snapshot().enabled && fake->blocks == 0, "detect-only default has no firewall mutation");
    shield.enable(true);
    check(until([&] { return !shield.snapshot().busy && shield.snapshot().status.find(L"indisponivel") != std::wstring::npos; }), "cannot arm without file ETW");
    shield.coverage(true); fake->readiness = E_ACCESSDENIED; shield.enable(true);
    check(until([&] { return !shield.snapshot().busy && shield.snapshot().status.find(L"indisponivel") != std::wstring::npos; }), "admin failure never reports armed");
    fake->readiness = S_OK; shield.enable(true);
    check(until([&] { return shield.snapshot().enabled; }), "explicit enable with available backend");
    for (int i = 0; i < 20; ++i) shield.consider(python, storage, false);
    check(until([&] { return shield.snapshot().rules.size() == 2; }) && fake->blocks == 1, "repeated reads create one rule per executable");
    shield.enable(false);
    check(shield.snapshot().rules.size() == 2 && fake->removes == 0, "detect-only retains persistent blocks");
    fake->removeResult = E_ACCESSDENIED; shield.restore();
    check(until([&] { return fake->removes == 2 && !shield.snapshot().busy; }) && shield.snapshot().rules.size() == 2, "failed removal retains visible rules");
    fake->removeResult = S_OK; shield.restore();
    check(until([&] { return shield.snapshot().rules.empty(); }) && !shield.snapshot().enabled, "restore removes recovered and new rules and disables auto isolation");
    shield.enable(true); until([&] { return shield.snapshot().enabled; });
    fake->blockResult = E_FAIL; shield.consider(python, storage, false);
    check(until([&] { return fake->blocks == 2 && !shield.snapshot().busy; }) && shield.snapshot().rules.empty(), "failed block never reports success");
    shield.consider(python, storage, false); Sleep(100);
    check(fake->blocks == 2, "failed block retries are rate limited");
    fake->readiness = E_ACCESSDENIED;
    check(until([&] { return !shield.snapshot().enabled; }), "firewall availability loss disarms automatically");
    fake->readiness = S_OK; shield.enable(true); until([&] { return shield.snapshot().enabled; });
    shield.coverage(false);
    check(!shield.snapshot().enabled, "ETW loss disarms automatic action");
    shield.shutdown();

    auto request = std::make_unique<SG_REQUEST>();
    request->Version = SG_VERSION; request->Size = sizeof(*request); request->Command = SG_SET_POLICY; request->Mode = SG_ENFORCE;
    check(!SgValidRequest(request.get()), "driver refuses enforce without protected paths");
    request->PathCount = 1; request->Paths[0].Kind = SG_DIRECTORY;
    wcscpy_s(request->Paths[0].Name, L"\\Device\\HarddiskVolume3\\SentinelLab");
    request->Paths[0].Length = static_cast<ULONG>(wcslen(request->Paths[0].Name));
    check(SgValidRequest(request.get()), "bounded driver policy accepted");
    request->Version = 999; check(!SgValidRequest(request.get()), "driver version mismatch rejected"); request->Version = SG_VERSION;
    request->AllowCount = 1; request->Allowed[0] = {1234, 0, 1, 0};
    check(!SgValidRequest(request.get()), "driver allow entry requires creation time");
    request->Allowed[0].Created = 123;
    check(SgValidRequest(request.get()), "driver PID plus creation identity accepted");
    request->Allowed[0].PathMask = 2;
    check(!SgValidRequest(request.get()), "driver allow mask cannot reference nonexistent path");
    request->Allowed[0].PathMask = 1; request->Paths[0].Length = SG_PATH_CHARS;
    check(!SgValidRequest(request.get()), "driver oversized path rejected before indexing");
    std::cout << "Failures: " << failures << '\n'; return failures ? 1 : 0;
}
