#define PID_CORE_ONLY
#define wmain scanner_entry
#include "pid.cpp"
#undef wmain
#include "pid_monitor.h"

int failures = 0;
void require(bool yes, const char* name) { std::cout << (yes ? "PASS " : "FAIL ") << name << '\n'; if (!yes) ++failures; }
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--fixture") {
        WSADATA ws{}; WSAStartup(MAKEWORD(2, 2), &ws);
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
        if (s == INVALID_SOCKET || bind(s, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(s, 1)) return 2;
        Sleep(90000); closesocket(s); WSACleanup(); return 0;
    }
    wchar_t working[32768]{}, self[32768]{};
    GetCurrentDirectoryW(_countof(working), working); GetModuleFileNameW(nullptr, self, _countof(self));
    std::wstring directory = std::wstring(working) + L"\\output\\monitor-test";
    CreateDirectoryW(directory.c_str(), nullptr); directory += L"\\Temp"; CreateDirectoryW(directory.c_str(), nullptr);
    const auto fixturePath = directory + L"\\monitor-fixture.exe";
    if (!CopyFileW(self, fixturePath.c_str(), FALSE)) { std::cerr << "Fixture copy failed\n"; return 1; }
    std::wstring command = L"\"" + fixturePath + L"\" --fixture";
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(fixturePath.c_str(), &command[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return 1;
    Handle child(pi.hProcess), thread(pi.hThread);
    MonitorEngine engine; engine.intervalMs = 500;
    require(engine.start(), "start live monitor");
    require(!engine.start(), "duplicate start is rejected");
    auto find = [&]() -> MonitorRow {
        auto state = engine.snapshot();
        for (auto& row : state.rows) if (row.process.pid == pi.dwProcessId) return row;
        return {};
    };
    MonitorRow row;
    const ULONGLONG start = GetTickCount64();
    do { Sleep(250); row = find(); } while ((!row.ready || row.process.score < 8) && GetTickCount64() - start < 45000);
    require(row.ready, "new process analyzed asynchronously");
    require(row.process.score == 8, "Temp + unsigned + listener baseline");
    const int baseline = row.process.score;
    Sleep(1600);
    require(find().process.score == baseline, "repeated polling does not accumulate score");
    const auto fakePath = L"C:\\SyntheticFixture\\Discord\\Local Storage\\leveldb\\empty.ldb";
    engine.enqueue({ LiveEvent::StorageRead, pi.dwProcessId, row.process.created ? row.process.created - 1 : 0, fakePath });
    Sleep(1100);
    require(find().process.score == baseline, "old process generation does not receive storage points");
    engine.enqueue({ LiveEvent::StorageRead, pi.dwProcessId, fileTimeNow(), fakePath });
    Sleep(1100);
    require(find().process.score == baseline + 5, "file telemetry correlates with the current process");
    engine.enqueue({ LiveEvent::StorageRead, pi.dwProcessId, fileTimeNow(), fakePath });
    Sleep(1100);
    require(find().process.score == baseline + 5, "repeated file event does not duplicate points");
    const auto before = engine.snapshot();
    require(!before.telemetry.empty() && before.cycles >= 3, "coverage and sampling progress exposed");
    require(monitorReport(before).find(L"SyntheticFixture") != std::wstring::npos, "export contains observed evidence");
    engine.requestStop();
    const auto stopTime = GetTickCount64();
    while (!engine.finished && GetTickCount64() - stopTime < 15000) Sleep(100);
    require(engine.finished, "stop completes and releases sensors");
    engine.join();
    const auto stoppedCount = engine.snapshot().eventCount;
    require(engine.start(), "restart after stop");
    Sleep(1600); engine.requestStop(); engine.join();
    require(engine.snapshot().eventCount > stoppedCount, "restart retains session history");
    // Encerra somente o processo de teste criado acima.
    TerminateProcess(child.h, 0); WaitForSingleObject(child.h, 3000);
    DeleteFileW(fixturePath.c_str());
    std::cout << "Failures: " << failures << '\n';
    return failures ? 1 : 0;
}
