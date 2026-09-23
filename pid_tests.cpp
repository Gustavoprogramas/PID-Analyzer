// Testes locais: cl /std:c++17 /EHsc /O2 /MT /W4 pid_tests.cpp /Fe:pid_tests.exe
#define wmain scanner_entry
#define PID_CORE_ONLY
#include "pid.cpp"
#undef wmain

static int failures = 0;
void check(bool condition, const char* name) {
    std::cout << (condition ? "PASS " : "FAIL ") << name << '\n';
    if (!condition) ++failures;
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--fixture") {
        Handle file(CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file) return 2;
        Sleep(60000);
        return 0;
    }
    check(classification(3) == std::wstring(L"BAIXO") && classification(4) == std::wstring(L"ATENCAO") &&
        classification(8) == std::wstring(L"SUSPEITO") && classification(13) == std::wstring(L"ALTO RISCO"), "score boundaries");
    check(locationScore(L"C:\\Users\\Test\\AppData\\Local\\Temp\\test.exe") == 4, "Temp does not also score AppData");
    check(locationScore(L"C:\\Users\\Test\\AppData\\Roaming\\test.exe") == 2, "AppData score");
    check(locationScore(L"C:\\Users\\Test\\Downloads\\test.exe") == 1, "Downloads score");
    check(locationScore(windowsDir() + L"\\System32\\cmd.exe") == 0, "System32 location neutral");
    check(!inside(L"C:\\TempFake\\a.exe", L"C:\\Temp"), "directory boundary");
    check(legitimateSystemPath(L"explorer.exe", windowsDir() + L"\\explorer.exe"), "Explorer real path");
    check(!legitimateSystemPath(L"svchost.exe", L"C:\\Users\\Test\\AppData\\svchost.exe"), "system impersonation");
    check(splitCommand(L"\"C:\\Program Files\\App\\app.exe\" --start").first == L"C:\\Program Files\\App\\app.exe", "quoted executable");
    check(splitCommand(L"C:\\Program Files\\App\\app.exe --start").second == L"--start", "unquoted service path with spaces");
    Process p; p.path = L"C:\\Apps\\python.exe"; p.name = L"python.exe";
    p.command = L"\"C:\\Apps\\python.exe\" \"C:\\Scripts\\safe.py\"";
    Persistence startup{ PersistKind::Run, L"fixture", p.path, L"\"C:\\Scripts\\different.py\"" };
    check(!matches(startup, p), "same interpreter different script does not match");
    startup.args = L"\"C:\\Scripts\\safe.py\"";
    check(matches(startup, p), "same interpreter and script match");
    startup.executable = L"python.exe";
    check(!matches(startup, p), "basename only does not match");
    Process shell; shell.name = L"powershell.exe";
    shell.command = L"powershell.exe -EncodedCommand AAA -WindowStyle Hidden -File C:\\Users\\Test\\AppData\\Local\\Temp\\sample.ps1";
    commandSignals(shell);
    check(shell.score == 7, "encoded hidden temp script scoring");
    Process normal; normal.name = L"powershell.exe"; normal.command = L"powershell.exe -File C:\\Scripts\\sample.ps1";
    commandSignals(normal);
    check(normal.score == 0, "plain interpreter has no automatic penalty");
    std::map<DWORD, Process> all;
    Process parent; parent.pid = 10; parent.name = L"winword.exe"; parent.created = 100;
    all[10] = parent;
    Process child; child.name = L"cmd.exe"; child.parent = 10; child.created = 200;
    parentSignals(child, all);
    check(child.score == 2, "Office spawning interpreter");
    child.score = 0; child.created = 50;
    parentSignals(child, all);
    check(child.score == 0, "reused parent PID rejected");
    IN_ADDR v4{};
    InetPtonW(AF_INET, L"127.0.0.1", &v4); check(!publicV4(v4.S_un.S_addr), "loopback not external");
    InetPtonW(AF_INET, L"100.64.1.2", &v4); check(!publicV4(v4.S_un.S_addr), "CGNAT not external");
    InetPtonW(AF_INET, L"8.8.8.8", &v4); check(publicV4(v4.S_un.S_addr), "public IPv4");
    IN6_ADDR v6{};
    InetPtonW(AF_INET6, L"::1", &v6); check(!publicV6(v6.u.Byte), "IPv6 loopback not external");
    InetPtonW(AF_INET6, L"fe80::1", &v6); check(!publicV6(v6.u.Byte), "IPv6 link local not external");
    InetPtonW(AF_INET6, L"::ffff:192.168.1.2", &v6); check(!publicV6(v6.u.Byte), "IPv4 mapped private address");
    InetPtonW(AF_INET6, L"2606:4700:4700::1111", &v6); check(publicV6(v6.u.Byte), "public IPv6");
    check(browserStorage(L"C:\\Fixture\\Google\\Chrome\\User Data\\Default\\Login Data"), "synthetic profile path recognized");
    check(!browserStorage(L"C:\\Other\\Login Data"), "unrelated file not classified as browser storage");
    check(browserStorage(L"C:\\Users\\Test\\AppData\\Roaming\\Discord\\Local Storage\\leveldb\\000005.ldb"), "Discord LevelDB path");
    check(browserStorage(L"C:\\Users\\Test\\AppData\\Roaming\\discordcanary\\Local Storage\\leveldb\\CURRENT"), "Discord Canary path");
    check(browserStorage(L"C:\\Users\\Test\\AppData\\Roaming\\discordptb\\Local Storage\\leveldb\\0001.log"), "Discord PTB path");
    check(!browserStorage(L"C:\\Users\\Test\\Discord\\Cache\\icon.png"), "unrelated Discord cache ignored");
    check(inspectScriptText("APPDATA Authorization discord").score == 0, "isolated script keywords do not score");
    check(inspectScriptText("discord leveldb token re.findall").score == 0, "storage and token without HTTP do not score");
    check(inspectScriptText("discord leveldb Authorization urllib").score == 6, "static combination without webhook");
    check(inspectScriptText("Discord Local Storage TOKEN re.findall requests.post api/webhooks").score == 8, "combined static indicators case-insensitive");
    auto selfCommand = commandLine(GetCurrentProcess());
    check(has(selfCommand, L"pid_tests"), "native command line query");
    const auto microsoft = signature(windowsDir() + L"\\System32\\cmd.exe");
    check(microsoft.kind == SigKind::Microsoft, "Microsoft catalog/embedded verification on cmd.exe");
    check(signature(L"C:\\not-existing-pid-test-6733.exe").kind == SigKind::Unavailable, "missing file is unknown, not unsigned");
    wchar_t self[MAX_PATH]{}; GetModuleFileNameW(nullptr, self, MAX_PATH);
    check(signature(self).kind == SigKind::Unsigned, "unsigned test executable");
    ULONGLONG value = 0;
    check(!number(L"-1", value) && !number(L"18446744073709551616", value) && number(L"42", value) && value == 42, "strict numeric parsing");
    WSADATA ws{}; WSAStartup(MAKEWORD(2, 2), &ws);
    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), udp = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    check(tcp != INVALID_SOCKET && bind(tcp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 && listen(tcp, 1) == 0, "create harmless loopback TCP listener");
    sockaddr_in6 addr6{}; addr6.sin6_family = AF_INET6; addr6.sin6_addr = in6addr_loopback;
    check(udp != INVALID_SOCKET && bind(udp, reinterpret_cast<sockaddr*>(&addr6), sizeof(addr6)) == 0, "create harmless UDP6 endpoint");
    WarningLog warnings; auto net = network(warnings);
    bool tcpSeen = false, udpSeen = false;
    for (const auto& c : net[GetCurrentProcessId()]) {
        if (c.protocol == L"TCP4" && c.listening && !c.exposed && !c.external) tcpSeen = true;
        if (c.protocol == L"UDP6" && !c.external) udpSeen = true;
    }
    check(tcpSeen, "observe listener with no external-listener score");
    check(udpSeen, "observe UDP6 without inventing remote address");
    closesocket(tcp); closesocket(udp); WSACleanup();
    std::cout << "Failures: " << failures << '\n';
    return failures ? 1 : 0;
}
