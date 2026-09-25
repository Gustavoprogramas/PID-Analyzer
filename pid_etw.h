#pragma once
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <deque>
#include <functional>
#pragma comment(lib, "tdh.lib")

struct LiveEvent {
    enum Kind { Start, Exit, StorageOpen, StorageRead, Notice } kind = Notice;
    DWORD pid = 0;
    ULONGLONG time = 0;
    std::wstring text;
};
ULONGLONG fileTimeNow() {
    FILETIME t{}; GetSystemTimeAsFileTime(&t);
    return (static_cast<ULONGLONG>(t.dwHighDateTime) << 32) | t.dwLowDateTime;
}
class EtwMonitor {
    inline static const GUID processProvider = { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16 } };
    inline static const GUID fileProvider = { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9,0x70,0xc2,0x56,0x0f,0xb5,0xc2,0x89 } };
    static constexpr const wchar_t* sessionName = L"PID.Sentinel.Live";
    TRACEHANDLE session = 0, trace = INVALID_PROCESSTRACE_HANDLE;
    std::vector<BYTE> properties;
    std::thread consumer;
    std::function<void(LiveEvent)> receive;
    std::map<ULONGLONG, std::wstring> objects, keys;
    ULONG lastLost = 0;
    EVENT_TRACE_PROPERTIES* props() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.data()); }
    static std::vector<BYTE> property(PEVENT_RECORD e, const wchar_t* name) {
        PROPERTY_DATA_DESCRIPTOR d{}; d.PropertyName = reinterpret_cast<ULONGLONG>(name); d.ArrayIndex = ULONG_MAX;
        ULONG bytes = 0;
        if (TdhGetPropertySize(e, 0, nullptr, 1, &d, &bytes) != ERROR_SUCCESS || bytes > 65536 || !bytes) return {};
        std::vector<BYTE> data(bytes);
        if (TdhGetProperty(e, 0, nullptr, 1, &d, bytes, data.data()) != ERROR_SUCCESS) return {};
        return data;
    }
    static ULONGLONG integer(PEVENT_RECORD e, const wchar_t* name) {
        auto data = property(e, name); ULONGLONG n = 0;
        if (data.size() == 4 || data.size() == 8) memcpy(&n, data.data(), data.size());
        return n;
    }
    static std::wstring string(PEVENT_RECORD e, const wchar_t* name) {
        auto data = property(e, name);
        if (data.empty() || data.size() % 2) return L"";
        const auto s = reinterpret_cast<const wchar_t*>(data.data());
        size_t n = data.size() / 2; while (n && !s[n - 1]) --n;
        return std::wstring(s, n);
    }
    void notice(const std::wstring& text) { receive({ LiveEvent::Notice, 0, fileTimeNow(), text }); }
    static void WINAPI callback(PEVENT_RECORD e) {
        auto self = static_cast<EtwMonitor*>(e->UserContext);
        if (!self) return;
        try { self->event(e); } catch (...) { /* Excecoes nao devem atravessar o callback do Windows. */ }
    }
    void event(PEVENT_RECORD e) {
        const auto id = e->EventHeader.EventDescriptor.Id;
        const ULONGLONG timestamp = static_cast<ULONGLONG>(e->EventHeader.TimeStamp.QuadPart);
        if (e->EventHeader.ProviderId == processProvider) {
            if (id != 1 && id != 2) return;
            const DWORD pid = static_cast<DWORD>(integer(e, L"ProcessID"));
            if (!pid || pid == GetCurrentProcessId()) return;
            receive({ id == 1 ? LiveEvent::Start : LiveEvent::Exit, pid, timestamp, string(e, L"ImageName") });
            return;
        }
        if (e->EventHeader.ProviderId != fileProvider) return;
        if (id != 10 && id != 11 && id != 12 && id != 14 && id != 15) return;
        if (id == 10 || id == 11) {
            const auto key = integer(e, L"FileKey");
            if (id == 11) keys.erase(key);
            else {
                auto path = string(e, L"FileName");
                if (key && browserStorage(path)) keys[key] = path;
            }
            if (keys.size() > 8192) { keys.clear(); notice(L"ETW: cache de nomes atingiu o limite; cobertura parcial."); }
            return;
        }
        const auto object = integer(e, L"FileObject");
        if (id == 14) { objects.erase(object); return; }
        std::wstring path;
        if (id == 12) {
            path = string(e, L"FileName");
            if (path.empty()) path = string(e, L"OpenPath");
            objects.erase(object);
            if (!browserStorage(path)) return;
            if (object) objects[object] = path;
        } else {
            auto found = objects.find(object);
            if (found != objects.end()) path = found->second;
            else { auto key = keys.find(integer(e, L"FileKey")); if (key != keys.end()) path = key->second; }
            if (path.empty()) return;
        }
        if (objects.size() > 8192) { objects.clear(); notice(L"ETW: cache de arquivos atingiu o limite; cobertura parcial."); }
        DWORD pid = e->EventHeader.ProcessId;
        // Usa a thread solicitante quando o evento e emitido pelo sistema.
        DWORD tid = static_cast<DWORD>(integer(e, L"IssuingThreadId"));
        if (!tid) tid = static_cast<DWORD>(integer(e, L"ThreadId"));
        if (!tid) tid = static_cast<DWORD>(integer(e, L"TTID"));
        if (tid) { Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid)); if (thread) pid = GetProcessIdOfThread(thread.h); }
        if (!pid || pid == 4 || pid == GetCurrentProcessId()) return;
        receive({ id == 15 ? LiveEvent::StorageRead : LiveEvent::StorageOpen, pid, timestamp, path });
    }
    ULONG enable(const GUID& provider, ULONGLONG keyword, std::initializer_list<USHORT> ids) {
        std::vector<BYTE> b(sizeof(EVENT_FILTER_EVENT_ID) + ids.size() * sizeof(USHORT));
        auto filter = reinterpret_cast<EVENT_FILTER_EVENT_ID*>(b.data());
        filter->FilterIn = TRUE; filter->Count = static_cast<USHORT>(ids.size());
        std::copy(ids.begin(), ids.end(), filter->Events);
        EVENT_FILTER_DESCRIPTOR desc{}; desc.Type = EVENT_FILTER_TYPE_EVENT_ID; desc.Ptr = reinterpret_cast<ULONGLONG>(filter);
        desc.Size = static_cast<ULONG>(offsetof(EVENT_FILTER_EVENT_ID, Events) + ids.size() * sizeof(USHORT));
        ENABLE_TRACE_PARAMETERS params{}; params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        params.EnableFilterDesc = &desc; params.FilterDescCount = 1;
        return EnableTraceEx2(session, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, keyword, 0, 0, &params);
    }
public:
    std::atomic<bool> consumerRunning{false};
    std::wstring status = L"ETW desligado";
    bool fileEnabled = false, processEnabled = false;
    ~EtwMonitor() { stop(); }
    void start(std::function<void(LiveEvent)> callbackFn) {
        receive = std::move(callbackFn);
        properties.resize(sizeof(EVENT_TRACE_PROPERTIES) + 1024);
        auto p = props(); ZeroMemory(p, properties.size());
        p->Wnode.BufferSize = static_cast<ULONG>(properties.size()); p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->Wnode.ClientContext = 1; p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); p->BufferSize = 64; p->MinimumBuffers = 8; p->MaximumBuffers = 32; p->FlushTimer = 1;
        const ULONG error = StartTraceW(&session, sessionName, p);
        if (error) {
            session = 0;
            status = L"ETW indisponivel (erro " + std::to_wstring(error) + L"); consultas periodicas";
            notice(status + (error == ERROR_ACCESS_DENIED ? L". Execute como administrador para ampliar cobertura." : L"."));
            return;
        }
        const auto procError = enable(processProvider, 0x10, { 1, 2 });
        const auto fileError = enable(fileProvider, 0x1b0, { 10, 11, 12, 14, 15 });
        processEnabled = procError == ERROR_SUCCESS; fileEnabled = fileError == ERROR_SUCCESS;
        EVENT_TRACE_LOGFILEW log{};
        log.LoggerName = const_cast<LPWSTR>(sessionName);
        log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = callback; log.Context = this;
        trace = OpenTraceW(&log);
        if (trace == INVALID_PROCESSTRACE_HANDLE || (!fileEnabled && !processEnabled)) {
            status = L"ETW sem consumidor/provedores; consultas periodicas"; stop(); notice(status); return;
        }
        status = std::wstring(L"ETW processos: ") + (processEnabled ? L"ativo" : L"indisponivel") + L" | arquivos: " + (fileEnabled ? L"ativo" : L"indisponivel");
        notice(status);
        if (procError) notice(L"ETW processo: erro " + std::to_wstring(procError));
        if (fileError) notice(L"ETW arquivo: erro " + std::to_wstring(fileError));
        const TRACEHANDLE openedTrace = trace;
        consumerRunning = true;
        consumer = std::thread([this, openedTrace] {
            TRACEHANDLE h = openedTrace;
            const ULONG result = ProcessTrace(&h, 1, nullptr, nullptr);
            consumerRunning = false;
            if (result != ERROR_SUCCESS && result != ERROR_CANCELLED) notice(L"Consumidor ETW terminou: erro " + std::to_wstring(result));
        });
    }
    void checkLoss() {
        if (session && ControlTraceW(session, sessionName, props(), EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
            const ULONG lost = props()->EventsLost + props()->RealTimeBuffersLost;
            if (lost != lastLost) { lastLost = lost; notice(L"ETW: eventos/buffers perdidos = " + std::to_wstring(lost) + L". Historico incompleto."); }
        }
    }
    void stop() {
        if (session) { ControlTraceW(session, sessionName, props(), EVENT_TRACE_CONTROL_STOP); session = 0; }
        if (trace != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(trace); trace = INVALID_PROCESSTRACE_HANDLE; }
        if (consumer.joinable()) consumer.join();
        fileEnabled = processEnabled = false;
    }
};
