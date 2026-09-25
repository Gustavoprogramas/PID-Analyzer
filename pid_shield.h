#pragma once
#include <netfw.h>
#include <condition_variable>
#include <functional>
#include <memory>
#include <deque>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

bool expectedStorageAccess(const Process& p, const std::wstring& storage) {
    if (!trusted(p.sig)) return false;
    const auto name = lower(p.name), publisher = lower(trim(p.sig.publisher)), path = lower(storage);
    if (name != basename(p.path)) return false;
    if ((name == L"discord.exe" || name == L"discordcanary.exe" || name == L"discordptb.exe") &&
        (publisher == L"discord inc." || publisher == L"discord inc"))
        return has(path, L"\\" + name.substr(0, name.size() - 4) + L"\\local storage\\leveldb\\");
    if (name == L"chrome.exe" && publisher == L"google llc") return has(path, L"\\google\\chrome\\user data\\");
    if (name == L"msedge.exe" && publisher == L"microsoft corporation") return has(path, L"\\microsoft\\edge\\user data\\");
    if (name == L"brave.exe" && publisher == L"brave software, inc.") return has(path, L"\\bravesoftware\\brave-browser\\user data\\");
    if (name == L"firefox.exe" && publisher == L"mozilla corporation") return has(path, L"\\mozilla\\firefox\\profiles\\");
    if (name == L"vivaldi.exe" && publisher == L"vivaldi technologies as") return has(path, L"\\vivaldi\\user data\\");
    if (name == L"opera.exe" && publisher == L"opera norway as") return has(path, L"\\opera software\\opera ");
    return false;
}
bool shieldCandidate(const Process& p, const std::wstring& storage, bool analyzed) {
    return p.pid > 4 && p.pid != GetCurrentProcessId() && p.created && !p.path.empty() &&
        basename(p.path) == lower(p.name) &&
        browserStorage(storage) && !expectedStorageAccess(p, storage) &&
        (interpreter(p.name) || (analyzed && p.score >= 8));
}
struct ShieldRule { std::wstring name, path; };
struct ShieldState {
    bool enabled = false, coverage = false, busy = false;
    std::wstring status = L"Detectar somente";
    std::vector<ShieldRule> rules;
};
struct ShieldBackend {
    virtual ~ShieldBackend() = default;
    virtual HRESULT available() = 0;
    virtual HRESULT list(std::vector<ShieldRule>& rules) = 0;
    virtual HRESULT block(const Process& process, ShieldRule& rule) = 0;
    virtual HRESULT remove(const ShieldRule& rule) = 0;
};
HRESULT shieldLiveIdentity(const Process& process, Handle& live, std::wstring& path) {
    if (process.pid <= 4 || process.pid == GetCurrentProcessId() || !process.created) return E_INVALIDARG;
    live.h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, process.pid);
    if (!live) return HRESULT_FROM_WIN32(GetLastError());
    if (creationTime(live.h) != process.created || WaitForSingleObject(live.h, 0) != WAIT_TIMEOUT)
        return HRESULT_FROM_WIN32(ERROR_PROCESS_ABORTED);
    BOOL critical = TRUE;
    if (!IsProcessCritical(live.h, &critical) || critical) return E_ACCESSDENIED;
    wchar_t image[32768]{}; DWORD size = _countof(image);
    if (!QueryFullProcessImageNameW(live.h, 0, image, &size)) return HRESULT_FROM_WIN32(GetLastError());
    path = normalize(image);
    if (path != normalize(process.path) || path.size() < 4 || path[1] != L':' || path[2] != L'\\' ||
        GetDriveTypeW(path.substr(0, 3).c_str()) != DRIVE_FIXED) return E_INVALIDARG;
    if (inside(path, windowsDir()) && !interpreter(basename(path))) return E_ACCESSDENIED;
    return S_OK;
}
class WindowsFirewall final : public ShieldBackend {
    static constexpr const wchar_t* group = L"PID Sentinel Shield";
    static constexpr const wchar_t* prefix = L"PID Sentinel Shield v1 ";
    static constexpr const wchar_t* description = L"PID Sentinel: isolamento de saida por executavel. Gerenciado pelo Shield v1.";
    HRESULT policy(Com<INetFwPolicy2>& p) {
        return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), reinterpret_cast<void**>(p.out()));
    }
    bool owned(INetFwRule* r, ShieldRule& result) {
        Bstr n, g, d, path; NET_FW_RULE_DIRECTION direction{}; NET_FW_ACTION action{};
        if (FAILED(r->get_Name(&n.p)) || FAILED(r->get_Grouping(&g.p)) || FAILED(r->get_Description(&d.p)) ||
            FAILED(r->get_ApplicationName(&path.p)) || FAILED(r->get_Direction(&direction)) || FAILED(r->get_Action(&action))) return false;
        if (g.str() != group || d.str() != description || n.str().find(prefix) != 0 ||
            direction != NET_FW_RULE_DIR_OUT || action != NET_FW_ACTION_BLOCK || path.str().empty()) return false;
        result = {n.str(), normalize(path.str())}; return true;
    }
public:
    HRESULT available() override {
        Handle token; TOKEN_ELEVATION elevated{}; DWORD size = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h)) return HRESULT_FROM_WIN32(GetLastError());
        if (!GetTokenInformation(token.h, TokenElevation, &elevated, sizeof(elevated), &size) || !elevated.TokenIsElevated) return E_ACCESSDENIED;
        Com<INetFwPolicy2> p; HRESULT hr = policy(p); if (FAILED(hr)) return hr;
        NET_FW_MODIFY_STATE state{}; hr = p->get_LocalPolicyModifyState(&state);
        if (FAILED(hr)) return hr;
        if (state != NET_FW_MODIFY_STATE_OK) return HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY);
        for (const auto profile : {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC}) {
            VARIANT_BOOL enabled = VARIANT_FALSE; hr = p->get_FirewallEnabled(profile, &enabled);
            if (FAILED(hr)) return hr;
            if (enabled != VARIANT_TRUE) return HRESULT_FROM_WIN32(ERROR_SERVICE_DISABLED);
        }
        return S_OK;
    }
    HRESULT list(std::vector<ShieldRule>& out) override {
        Com<INetFwPolicy2> p; HRESULT hr = policy(p); if (FAILED(hr)) return hr;
        Com<INetFwRules> rules; hr = p->get_Rules(rules.out()); if (FAILED(hr)) return hr;
        Com<IUnknown> unknown; hr = rules->get__NewEnum(unknown.out()); if (FAILED(hr)) return hr;
        Com<IEnumVARIANT> items; hr = unknown->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(items.out())); if (FAILED(hr)) return hr;
        std::vector<ShieldRule> found;
        VARIANT value; VariantInit(&value);
        while ((hr = items->Next(1, &value, nullptr)) == S_OK) {
            if (value.vt == VT_DISPATCH && value.pdispVal) {
                Com<INetFwRule> rule;
                if (SUCCEEDED(value.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(rule.out())))) {
                    ShieldRule entry; if (owned(rule.p, entry)) found.push_back(std::move(entry));
                }
            }
            VariantClear(&value);
        }
        VariantClear(&value);
        if (FAILED(hr)) return hr;
        out = std::move(found); return S_OK;
    }
    HRESULT block(const Process& process, ShieldRule& result) override {
        HRESULT hr = available(); if (FAILED(hr)) return hr;
        Handle live; std::wstring path;
        hr = shieldLiveIdentity(process, live, path); if (FAILED(hr)) return hr;
        GUID id{}; hr = CoCreateGuid(&id); if (FAILED(hr)) return hr;
        wchar_t guid[40]{}; if (!StringFromGUID2(id, guid, _countof(guid))) return E_FAIL;
        Bstr name((std::wstring(prefix) + guid).c_str()), app(path.c_str()), grouping(group), desc(description);
        Com<INetFwRule> rule;
        hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), reinterpret_cast<void**>(rule.out()));
        if (FAILED(hr)) return hr;
        if (FAILED(hr = rule->put_Name(name.p)) || FAILED(hr = rule->put_Description(desc.p)) ||
            FAILED(hr = rule->put_Grouping(grouping.p)) || FAILED(hr = rule->put_Protocol(NET_FW_IP_PROTOCOL_ANY)) ||
            FAILED(hr = rule->put_ApplicationName(app.p)) || FAILED(hr = rule->put_Direction(NET_FW_RULE_DIR_OUT)) ||
            FAILED(hr = rule->put_Profiles(NET_FW_PROFILE2_ALL)) || FAILED(hr = rule->put_Action(NET_FW_ACTION_BLOCK)) ||
            FAILED(hr = rule->put_Enabled(VARIANT_TRUE))) return hr;
        Com<INetFwPolicy2> p; hr = policy(p); if (FAILED(hr)) return hr;
        Com<INetFwRules> rules; hr = p->get_Rules(rules.out()); if (FAILED(hr)) return hr;
        Com<INetFwRule> collision;
        if (SUCCEEDED(rules->Item(name.p, collision.out()))) return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        if (WaitForSingleObject(live.h, 0) != WAIT_TIMEOUT) return HRESULT_FROM_WIN32(ERROR_PROCESS_ABORTED);
        hr = rules->Add(rule.p);
        if (SUCCEEDED(hr)) result = {name.str(), path};
        return hr;
    }
    HRESULT remove(const ShieldRule& target) override {
        Com<INetFwPolicy2> p; HRESULT hr = policy(p); if (FAILED(hr)) return hr;
        Com<INetFwRules> rules; hr = p->get_Rules(rules.out()); if (FAILED(hr)) return hr;
        Bstr name(target.name.c_str()); Com<INetFwRule> rule;
        hr = rules->Item(name.p, rule.out()); if (FAILED(hr)) return hr;
        ShieldRule current;
        if (!owned(rule.p, current) || current.path != target.path) return E_ACCESSDENIED;
        return rules->Remove(name.p);
    }
};

class ShieldController {
    struct Task { enum Kind { Enable, Block, Restore } kind; Process process; std::wstring storage; unsigned generation = 0; };
    std::unique_ptr<ShieldBackend> backend;
    std::function<void(int, const std::wstring&)> log;
    std::mutex mutex;
    std::condition_variable wake;
    std::thread worker;
    bool stopping = false;
    unsigned generation = 0;
    ShieldState state;
    std::deque<Task> tasks;
    std::map<std::wstring, ULONGLONG> attempted;
    void refreshRules() {
        std::vector<ShieldRule> rules; HRESULT hr = backend->list(rules);
        if (SUCCEEDED(hr)) { std::lock_guard<std::mutex> guard(mutex); state.rules = std::move(rules); }
        else log(1, L"Nao foi possivel consultar regras persistentes do Shield" + errorCode(hr));
    }
    void loop() {
        const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(com)) {
            { std::lock_guard<std::mutex> guard(mutex); stopping = true; state.status = L"Firewall indisponivel: falha ao iniciar COM"; }
            log(2, L"Firewall indisponivel: COM" + errorCode(com)); return;
        }
        refreshRules();
        for (;;) {
            Task task;
            {
                std::unique_lock<std::mutex> guard(mutex);
                if (!wake.wait_for(guard, std::chrono::seconds(state.enabled ? 5 : 30), [&] { return stopping || !tasks.empty(); })) {
                    const bool checkAvailability = state.enabled;
                    const unsigned observedGeneration = generation;
                    guard.unlock();
                    refreshRules();
                    if (checkAvailability) {
                        const HRESULT hr = backend->available();
                        if (FAILED(hr)) {
                            bool changed = false;
                            { std::lock_guard<std::mutex> update(mutex);
                                if (state.enabled && generation == observedGeneration) {
                                    state.enabled = false; ++generation; changed = true;
                                    state.status = L"Shield desarmado: Firewall indisponivel";
                                }
                            }
                            if (changed) log(2, L"Shield desarmado: disponibilidade do Firewall mudou" + errorCode(hr));
                        }
                    }
                    continue;
                }
                if (stopping) break;
                task = std::move(tasks.front()); tasks.pop_front();
                if (task.generation != generation) continue;
                if (task.kind == Task::Block && (!state.enabled || !state.coverage)) continue;
                state.busy = true;
            }
            if (task.kind == Task::Enable) {
                HRESULT hr = backend->available();
                bool enabled;
                { std::lock_guard<std::mutex> guard(mutex);
                    enabled = SUCCEEDED(hr) && state.coverage && task.generation == generation && !stopping;
                    state.enabled = enabled;
                    state.status = enabled ? L"Shield: isolamento de saida habilitado" : L"Shield indisponivel: administrador, ETW de arquivos e Firewall ativo sao necessarios";
                }
                log(enabled ? 1 : 2, enabled ? L"Shield habilitado. Isolamento por executavel; regras persistem ate restauracao explicita." :
                    L"Shield nao habilitado. Verifique administrador, ETW, perfis do Firewall e politica local" + errorCode(hr));
            } else if (task.kind == Task::Restore) {
                refreshRules();
                const auto current = snapshot();
                for (const auto& rule : current.rules) {
                    HRESULT hr = backend->remove(rule);
                    log(FAILED(hr) ? 2 : 0, (FAILED(hr) ? L"Falha ao remover regra: " : L"Regra removida: ") + rule.path + (FAILED(hr) ? errorCode(hr) : L""));
                }
                refreshRules();
            } else {
                ShieldRule rule; HRESULT hr = backend->block(task.process, rule);
                if (SUCCEEDED(hr)) {
                    { std::lock_guard<std::mutex> guard(mutex); state.rules.push_back(rule); }
                    log(2, L"REGRA DE BLOQUEIO CRIADA | PID " + std::to_wstring(task.process.pid) + L" | " + rule.path +
                        L" | todas as instancias deste executavel, todos os perfis | " + task.storage);
                } else log(2, L"Falha ao isolar PID " + std::to_wstring(task.process.pid) + L" | " + task.process.path + errorCode(hr));
            }
            { std::lock_guard<std::mutex> guard(mutex); state.busy = false; }
        }
        CoUninitialize();
    }
public:
    explicit ShieldController(std::function<void(int, const std::wstring&)> logger,
        std::unique_ptr<ShieldBackend> implementation = std::make_unique<WindowsFirewall>()) : backend(std::move(implementation)), log(std::move(logger)) {}
    ~ShieldController() { shutdown(); }
    void start() { worker = std::thread([this] { try { loop(); } catch (...) {
        { std::lock_guard<std::mutex> guard(mutex); state.enabled = false; state.busy = false; state.status = L"Falha interna no Shield; reinicie o app"; stopping = true; }
        log(2, L"Shield interrompido por erro interno. Regras existentes permanecem no Firewall.");
    } }); }
    void shutdown() {
        { std::lock_guard<std::mutex> guard(mutex); stopping = true; state.enabled = false; ++generation; tasks.clear(); }
        wake.notify_all(); if (worker.joinable()) worker.join();
    }
    ShieldState snapshot() { std::lock_guard<std::mutex> guard(mutex); return state; }
    void coverage(bool ready) {
        bool disabled = false;
        { std::lock_guard<std::mutex> guard(mutex); state.coverage = ready;
            if (!ready && state.enabled) { state.enabled = false; ++generation; disabled = true; state.status = L"Shield desarmado: ETW de arquivos inativo"; }
        }
        if (disabled) log(1, L"Shield desarmado: ETW de arquivos inativo. Regras existentes permanecem ate restauracao explicita.");
    }
    void enable(bool value) {
        { std::lock_guard<std::mutex> guard(mutex);
            if (stopping) return;
            ++generation; state.enabled = false; tasks.clear(); attempted.clear();
            state.status = value ? L"Verificando disponibilidade do Shield..." : L"Detectar somente (regras existentes preservadas)";
            if (value && !stopping) tasks.push_back({Task::Enable, {}, {}, generation});
        }
        wake.notify_one();
        if (!value) log(0, L"Modo detectar somente. Regras de bloqueio existentes permanecem ate restauracao explicita.");
    }
    void restore() {
        { std::lock_guard<std::mutex> guard(mutex);
            if (stopping) return;
            ++generation; state.enabled = false; tasks.clear(); attempted.clear();
            state.status = L"Detectar somente; restauracao das regras solicitada";
            tasks.push_back({Task::Restore, {}, {}, generation});
        }
        wake.notify_one();
    }
    void consider(const Process& p, const std::wstring& storage, bool analyzed) {
        if (!shieldCandidate(p, storage, analyzed)) return;
        const auto path = normalize(p.path);
        std::lock_guard<std::mutex> guard(mutex);
        if (!state.enabled || !state.coverage || stopping || tasks.size() >= 128) return;
        for (const auto& rule : state.rules) if (rule.path == path) return;
        auto last = attempted.find(path); const auto now = GetTickCount64();
        if (last != attempted.end() && now - last->second < 30000) return;
        if (attempted.size() >= 4096) return;
        attempted[path] = now; tasks.push_back({Task::Block, p, storage, generation}); wake.notify_one();
    }
};
