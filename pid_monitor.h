#pragma once
#include "pid_etw.h"
#include <condition_variable>
#include <memory>
#include "pid_shield.h"

using ProcessKey = std::pair<DWORD, ULONGLONG>;
ProcessKey processKey(const Process& p) { return { p.pid, p.created }; }
std::wstring clockText(ULONGLONG time = 0) {
    SYSTEMTIME s{};
    if (time) {
        FILETIME utc{ static_cast<DWORD>(time), static_cast<DWORD>(time >> 32) }, local{};
        FileTimeToLocalFileTime(&utc, &local); FileTimeToSystemTime(&local, &s);
    } else GetLocalTime(&s);
    wchar_t text[32]{}; swprintf_s(text, L"%02u:%02u:%02u", s.wHour, s.wMinute, s.wSecond);
    return text;
}
struct MonitorRow {
    Process process;
    std::vector<Connection> connections;
    ULONGLONG externalAt = 0, storageAt = 0, nextAnalysis = 0, lastProbe = 0;
    int peak = 0;
    bool ready = false, queued = false;
    std::wstring storagePath, storageAction;
};
struct ConsoleEvent { ULONGLONG serial = 0; int level = 0; std::wstring time, category, message; };
struct MonitorSnapshot {
    std::vector<MonitorRow> rows;
    std::deque<ConsoleEvent> events;
    std::wstring telemetry = L"Aguardando inicio", phase = L"Pronto para monitorar", updated = L"--:--:--";
    ULONGLONG cycles = 0, eventCount = 0;
    size_t pending = 0, protectedCount = 0;
    ShieldState shield;
};
class MonitorEngine {
    struct Job { Process process; std::map<DWORD, Process> family; bool probe = false; };
    std::mutex dataMutex, jobMutex, inputMutex;
    std::condition_variable jobWake;
    MonitorSnapshot data;
    std::deque<Job> jobs;
    std::map<ProcessKey, Process> results;
    std::deque<LiveEvent> input;
    std::atomic<unsigned> dropped{0};
    std::thread controller;
    std::map<ProcessKey, MonitorRow> rows;
    std::map<ProcessKey, Process> analyzed;
    std::set<std::wstring> warned;
    std::set<std::wstring> previousConnections;
    std::map<std::wstring, ULONGLONG> lastStorageEvent;
    void emit(int level, const std::wstring& category, const std::wstring& message, ULONGLONG timestamp = 0) {
        std::lock_guard<std::mutex> guard(dataMutex);
        data.events.push_back({ ++data.eventCount, level, clockText(timestamp), category, printable(message) });
        while (data.events.size() > 1500) data.events.pop_front();
    }
    void warnings(const WarningLog& log) {
        for (const auto& w : log.counts) if (warned.insert(w.first).second) emit(1, L"COBERTURA", w.first + L" (" + std::to_wstring(w.second) + L")");
    }
    void analyzeLoop() {
        const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        std::vector<Persistence> persistent;
        ULONGLONG refreshed = 0;
        while (!stopRequested) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(jobMutex);
                jobWake.wait_for(lock, std::chrono::milliseconds(250), [&] { return stopRequested || !jobs.empty(); });
                if (stopRequested) break;
                if (jobs.empty()) continue;
                job = std::move(jobs.front()); jobs.pop_front();
            }
            if (!refreshed || GetTickCount64() - refreshed >= 60000) {
                WarningLog log; std::vector<Persistence> fresh;
                registryPersistence(fresh, log); startupPersistence(fresh, log, SUCCEEDED(com));
                taskPersistence(fresh, log, SUCCEEDED(com)); servicePersistence(fresh, log);
                persistent = std::move(fresh); refreshed = GetTickCount64();
                for (const auto& w : log.counts) enqueue({ LiveEvent::Notice, 0, fileTimeNow(), w.first });
            }
            auto p = std::move(job.process);
            Handle live(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
            if (p.created && (!live || creationTime(live.h) != p.created)) continue;
            scoreProcess(p, job.family, persistent, {});
            if (p.score >= 4 || interpreter(p.name)) loadedModules(p, scratchWarnings);
            else p.dllStatus = L"nao selecionado nesta rodada (sem sinais iniciais)";
            scratchWarnings.counts.clear();
            if (job.probe && !stopRequested) browserHandles(p, 1000);
            {
                std::lock_guard<std::mutex> lock(jobMutex);
                if (results.size() < 1024) results[processKey(p)] = std::move(p);
            }
        }
        if (SUCCEEDED(com)) CoUninitialize();
    }
    WarningLog scratchWarnings;
    void consumeEvents() {
        std::deque<LiveEvent> events;
        { std::lock_guard<std::mutex> lock(inputMutex); events.swap(input); }
        for (const auto& e : events) {
            if (e.kind == LiveEvent::Notice) { if (warned.insert(e.text).second) emit(1, L"COBERTURA", e.text); continue; }
            if (e.kind == LiveEvent::Start || e.kind == LiveEvent::Exit) {
                emit(0, L"ETW / PROCESSO", std::wstring(e.kind == LiveEvent::Start ? L"Criado: " : L"Encerrado: ") + e.text + L" | PID " + std::to_wstring(e.pid), e.time);
                continue;
            }
            const std::wstring dedup = std::to_wstring(e.pid) + L"|" + e.text + L"|" + std::to_wstring(e.kind);
            const auto now = GetTickCount64();
            auto previous = lastStorageEvent.find(dedup);
            bool log = previous == lastStorageEvent.end() || now - previous->second > 10000;
            lastStorageEvent[dedup] = now;
            if (lastStorageEvent.size() > 4096) lastStorageEvent.clear();
            bool expected = false, attributed = false;
            for (auto& item : rows) {
                auto& row = item.second;
                if (row.process.pid != e.pid || !row.process.created || e.time < row.process.created) continue;
                expected = expectedStorageAccess(row.process, e.text);
                attributed = true;
                if (!expected && browserStorage(e.text)) {
                    row.storageAt = now; row.storagePath = e.text;
                    row.storageAction = e.kind == LiveEvent::StorageRead ? L"ETW Read" : L"ETW Create/open solicitado";
                    row.nextAnalysis = 0;
                    shield.consider(row.process, e.text, row.ready);
                }
                break;
            }
            if (log && !expected) emit(1, L"ETW / STORAGE", std::to_wstring(e.pid) + L" | " +
                (e.kind == LiveEvent::StorageRead ? L"operacao Read: " : L"abertura solicitada: ") + e.text +
                (attributed ? L"" : L" [processo fora da amostra; sem score atribuido]"), e.time);
        }
        unsigned lost = dropped.exchange(0);
        if (lost) emit(2, L"COBERTURA", L"Fila ETW excedida: " + std::to_wstring(lost) + L" eventos descartados.");
    }
    void run() {
        WSADATA ws{};
        if (WSAStartup(MAKEWORD(2, 2), &ws)) { emit(2, L"ERRO", L"Nao foi possivel iniciar Winsock."); finished = true; return; }
        EtwMonitor etw;
        etw.start([this](LiveEvent e) { enqueue(std::move(e)); });
        shield.coverage(etw.fileEnabled);
        { std::lock_guard<std::mutex> lock(dataMutex); data.telemetry = etw.status; }
        std::thread analyzer([this] {
            try { analyzeLoop(); }
            catch (...) { enqueue({ LiveEvent::Notice, 0, fileTimeNow(), L"Analise detalhada interrompida por erro interno; reinicie o monitor." }); stopRequested = true; }
        });
        struct JoinAnalyzer {
            MonitorEngine* self; std::thread& thread;
            ~JoinAnalyzer() { self->stopRequested = true; self->jobWake.notify_all(); if (thread.joinable()) thread.join(); }
        } joinAnalyzer{ this, analyzer };
        bool baseline = true;
        std::vector<wchar_t> ownPath(32768);
        GetModuleFileNameW(nullptr, ownPath.data(), static_cast<DWORD>(ownPath.size()));
        const auto ownImage = normalize(ownPath.data());
        ULONGLONG lastLossCheck = 0;
        while (!stopRequested) {
            const ULONGLONG cycleStart = GetTickCount64();
            shield.coverage(etw.fileEnabled && etw.consumerRunning);
            if (etw.fileEnabled && !etw.consumerRunning) {
                std::lock_guard<std::mutex> lock(dataMutex); data.telemetry = L"Consumidor ETW inativo | Shield desarmado";
            }
            WarningLog log;
            auto all = processes(log); auto net = network(log);
            warnings(log);
            std::set<ProcessKey> present;
            for (auto& entry : all) {
                auto& p = entry.second;
                if (has(p.command, L"--browser-worker") && normalize(p.path) == ownImage) continue;
                const auto key = processKey(p); present.insert(key);
                auto found = rows.find(key);
                if (found == rows.end()) {
                    MonitorRow row; row.process = p; row.process.browserStatus = L"consulta de handles opcional";
                    rows.emplace(key, std::move(row));
                    if (!baseline) emit(0, L"PROCESSO", L"Novo: " + p.name + L" | PID " + std::to_wstring(p.pid));
                }
            }
            for (auto it = rows.begin(); it != rows.end();) {
                if (!present.count(it->first)) {
                    if (!baseline) emit(0, L"PROCESSO", L"Saiu da amostra: " + it->second.process.name + L" | PID " + std::to_wstring(it->first.first));
                    analyzed.erase(it->first); it = rows.erase(it);
                } else ++it;
            }
            { std::lock_guard<std::mutex> lock(jobMutex);
                for (auto& result : results) {
                    auto row = rows.find(result.first);
                    if (row != rows.end()) { analyzed[result.first] = std::move(result.second); row->second.ready = true; row->second.queued = false;
                        row->second.nextAnalysis = cycleStart + (interpreter(row->second.process.name) ? 15000 : 60000); }
                }
                results.clear();
            }
            // Recalcula os sinais temporais sem acumular pontos de ciclos anteriores.
            for (auto& entry : rows) {
                auto found = analyzed.find(entry.first);
                if (found != analyzed.end()) entry.second.process = found->second;
                else { auto fresh = all.find(entry.first.first); if (fresh != all.end()) entry.second.process = fresh->second; }
            }
            consumeEvents();
            std::set<std::wstring> connectionSet;
            std::vector<ProcessKey> pending;
            for (auto& entry : rows) {
                auto& row = entry.second; auto& p = row.process;
                row.connections = net[p.pid];
                size_t external = 0; bool listener = false;
                for (const auto& c : row.connections) {
                    if (c.external) {
                        ++external;
                        auto key = std::to_wstring(p.pid) + L"/" + std::to_wstring(p.created) + L" " + c.protocol + L" " + c.local + L" -> " + c.remote;
                        connectionSet.insert(key);
                        if (!baseline && !previousConnections.count(key)) emit(0, L"REDE", p.name + L" | " + key);
                    }
                    if (c.exposed) listener = true;
                }
                if (external) row.externalAt = cycleStart;
                if (row.externalAt && cycleStart - row.externalAt < 60000) {
                    p.add(1, external ? L"Conexao externa observada nesta amostra" : L"Conexao externa observada nos ultimos 60 s");
                    if (interpreter(p.name)) p.add(2, L"Interpretador com conexao externa recente");
                }
                if (external >= 10) p.add(2, L"Dez ou mais conexoes externas na amostra");
                if (listener) p.add(2, L"Porta TCP LISTENING fora do loopback");
                const bool expectedStorage = expectedStorageAccess(p, row.storagePath);
                if (!expectedStorage && row.storageAt && cycleStart - row.storageAt < 60000) {
                    p.add(5, row.storageAction + L" em storage sensivel nos ultimos 60 s: " + row.storagePath);
                    shield.consider(p, row.storagePath, row.ready);
                }
                if (row.ready && p.score >= 8 && p.score > row.peak) emit(p.score >= 13 ? 2 : 1, L"ALERTA", p.name + L" | PID " + std::to_wstring(p.pid) +
                    L" | score " + std::to_wstring(p.score) + L" | " + classification(p.score));
                row.peak = std::max(row.peak, p.score);
                if (!row.queued && cycleStart >= row.nextAnalysis) pending.push_back(entry.first);
            }
            previousConnections = std::move(connectionSet);
            std::stable_sort(pending.begin(), pending.end(), [&](const ProcessKey& a, const ProcessKey& b) {
                auto priority = [&](const ProcessKey& k) { const auto& p = rows[k].process; return (interpreter(p.name) ? 100 : 0) + locationScore(p.path) * 10 + p.score; };
                return priority(a) > priority(b);
            });
            { std::lock_guard<std::mutex> lock(jobMutex);
                for (const auto& key : pending) {
                    if (jobs.size() >= 512) break;
                    auto& row = rows[key]; auto current = all.find(key.first);
                    if (current == all.end()) continue;
                    Job job; job.process = current->second;
                    auto parent = all.find(job.process.parent);
                    if (parent != all.end()) { job.family.emplace(parent->first, parent->second);
                        auto grand = all.find(parent->second.parent); if (grand != all.end()) job.family.emplace(grand->first, grand->second); }
                    job.probe = probeHandles && (interpreter(job.process.name) || row.process.score >= 4);
                    if (!baseline && interpreter(job.process.name)) jobs.push_front(std::move(job)); else jobs.push_back(std::move(job));
                    row.queued = true;
                }
                jobWake.notify_one();
            }
            if (baseline) { emit(0, L"MONITOR", L"Base inicial: " + std::to_wstring(rows.size()) + L" processos. Analise detalhada em segundo plano."); baseline = false; }
            if (cycleStart - lastLossCheck > 10000) { etw.checkLoss(); lastLossCheck = cycleStart; }
            { std::lock_guard<std::mutex> lock(dataMutex);
                data.rows.clear(); data.pending = 0; data.protectedCount = 0;
                for (const auto& item : rows) { data.rows.push_back(item.second); if (!item.second.ready) ++data.pending; if (item.second.process.path.empty()) ++data.protectedCount; }
                std::sort(data.rows.begin(), data.rows.end(), [](const MonitorRow& a, const MonitorRow& b) {
                    if (a.process.score != b.process.score) return a.process.score > b.process.score;
                    return a.process.pid < b.process.pid;
                });
                ++data.cycles; data.updated = clockText();
                data.phase = L"Monitorando | " + std::to_wstring(intervalMs.load()) + L" ms entre amostras";
            }
            while (!stopRequested && GetTickCount64() - cycleStart < intervalMs) Sleep(50);
        }
        shield.coverage(false);
        etw.stop(); jobWake.notify_all();
        if (analyzer.joinable()) analyzer.join();
        consumeEvents();
        WSACleanup();
        emit(0, L"MONITOR", L"Monitor parado. Historico mantido nesta sessao.");
        { std::lock_guard<std::mutex> lock(dataMutex); data.phase = L"Parado | historico preservado"; data.telemetry = L"ETW desligado"; }
        finished = true;
    }
public:
    ShieldController shield{[this](int level, const std::wstring& message) { emit(level, L"SHIELD", message); }};
    std::atomic<bool> stopRequested{false}, finished{true}, probeHandles{false};
    std::atomic<DWORD> intervalMs{1000};
    MonitorEngine() { shield.start(); }
    ~MonitorEngine() { requestStop(); join(); shield.shutdown(); }
    void enqueue(LiveEvent event) {
        std::lock_guard<std::mutex> lock(inputMutex);
        if (input.size() < 4096) input.push_back(std::move(event)); else ++dropped;
    }
    bool start() {
        if (!finished) return false;
        join(); rows.clear(); analyzed.clear(); warned.clear(); previousConnections.clear(); lastStorageEvent.clear();
        { std::lock_guard<std::mutex> lock(jobMutex); jobs.clear(); results.clear(); }
        stopRequested = false; finished = false;
        emit(0, L"MONITOR", L"Iniciando sensores. Shield inicia em detectar somente; habilite isolamento nas configuracoes.");
        controller = std::thread([this] { try { run(); } catch (...) { shield.coverage(false); emit(2, L"ERRO", L"Falha interna no monitor. Reinicie a coleta."); finished = true; } });
        return true;
    }
    void requestStop() { stopRequested = true; shield.coverage(false); jobWake.notify_all(); }
    void join() { if (controller.joinable()) controller.join(); }
    MonitorSnapshot snapshot() {
        MonitorSnapshot copy;
        { std::lock_guard<std::mutex> lock(dataMutex); copy = data; }
        copy.shield = shield.snapshot(); return copy;
    }
};
std::wstring rowDetails(const MonitorRow& row) {
    const auto& p = row.process;
    std::wostringstream o;
    o << p.name << L"  /  PID " << p.pid << L"\r\n" << classification(p.score) << L"  |  SCORE " << p.score
      << (row.ready ? L"" : L"  |  ANALISE PENDENTE") << L"\r\n\r\n";
    o << L"CAMINHO\r\n" << (p.path.empty() ? L"Inacessivel ou protegido" : p.path) << L"\r\n\r\nLINHA DE COMANDO\r\n" << p.command
      << L"\r\n\r\nPAI\r\n" << p.parent << L" | " << p.parentDescription << L"\r\n\r\nASSINATURA\r\n" << signatureLabel(p.sig) << L" | " << p.sig.publisher;
    o << L"\r\n\r\nEVIDENCIAS\r\n";
    for (const auto& r : p.reasons) o << L"[+" << r.first << L"] " << r.second << L"\r\n";
    if (p.reasons.empty()) o << (row.ready ? L"Nenhum sinal pontuado nesta coleta.\r\n" : L"Aguardando verificacao em segundo plano.\r\n");
    if (!p.scriptStatus.empty()) o << L"\r\nSCRIPT\r\n" << p.scriptPath << L"\r\n" << p.scriptStatus << L"\r\n";
    o << L"\r\nREDE (amostra atual)\r\n";
    for (const auto& c : row.connections) o << c.protocol << L" " << c.local << L" -> " << c.remote << L" " << c.state << L"\r\n";
    o << L"\r\nPERSISTENCIA\r\n";
    for (const auto& s : p.persistence) o << s << L"\r\n";
    o << L"\r\nDLLs: " << p.dllStatus << L"\r\n";
    for (const auto& s : p.dlls) o << s << L"\r\n";
    o << L"\r\nHANDLES: " << p.browserStatus << L"\r\n";
    for (const auto& s : p.browserFiles) o << s << L"\r\n";
    o << L"\r\nPontuacao heuristica. Nao confirma infeccao. ETW Open registra solicitacao; Read nao prova exfiltracao.\r\n";
    return o.str();
}
bool writeUtf8(const std::wstring& path, const std::wstring& text) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return false;
    std::string bytes(size, '\0'); WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), bytes.data(), size, nullptr, nullptr);
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    DWORD written = 0;
    return file && WriteFile(file.h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
}
std::wstring monitorReport(const MonitorSnapshot& s) {
    std::wostringstream o;
    o << L"PID SENTINEL / Relatorio da sessao\r\n" << s.phase << L"\r\n" << s.telemetry << L"\r\nAtualizado: " << s.updated
      << L" | ciclos " << s.cycles << L" | pendentes " << s.pending << L"\r\n"
      << L"Rede por amostragem; conexoes entre amostras podem nao ser vistas. UDP sem destino remoto.\r\n"
      << L"Eventos ETW dependem de permissao, schemas e buffers. Historico limitado aos ultimos 1500 eventos.\r\n"
      << L"Correlacao de storage/rede: 60 segundos. Fontes Python: caminho absoluto, local, ate 1 MiB.\r\n"
      << L"Nenhum conteudo de cookies, tokens ou senhas e coletado. Revise linhas de comando antes de compartilhar.\r\n\r\n";
    o << L"SHIELD\r\n" << s.shield.status << L"\r\n"
      << L"ETW e reativo. Uma regra de saida nao desfaz leituras nem garante impedir exfiltracao.\r\n";
    for (const auto& rule : s.shield.rules) o << L"Regra persistente: " << rule.name << L" | " << rule.path << L"\r\n";
    o << L"\r\n";
    for (const auto& r : s.rows) o << L"========================================\r\n" << rowDetails(r) << L"\r\n";
    o << L"\r\nCONSOLE / HISTORICO\r\n";
    for (const auto& e : s.events) o << L"[" << e.time << L"] [" << e.category << L"] " << e.message << L"\r\n";
    return o.str();
}
