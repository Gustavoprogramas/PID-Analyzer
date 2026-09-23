#pragma once
struct ScriptIndicators {
    int score = 0;
    bool storage = false, credentials = false, network = false, webhook = false;
};
ScriptIndicators inspectScriptText(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c); });
    auto contains = [&](const char* term) { return text.find(term) != std::string::npos; };
    ScriptIndicators s;
    s.storage = (contains("leveldb") || contains("login data") || contains("local storage")) &&
        (contains("discord") || contains("chrome") || contains("brave") || contains("user data") || contains("opera"));
    s.credentials = contains("authorization") || (contains("token") && (contains("findall") || contains("regex") || contains("re.search"))) || contains("decryptdata");
    s.network = contains("requests.") || contains("urllib") || contains("httpx") || contains("aiohttp") || contains("urlopen");
    s.webhook = contains("api/webhooks") || contains("discordwebhook") || (contains("webhook") && contains("discord.com"));
    // A pontuacao exige uma combinacao de indicadores.
    if (s.storage && s.credentials && s.network) s.score = s.webhook ? 8 : 6;
    return s;
}
void scriptSignals(Process& p) {
    const auto name = lower(p.name);
    if (name != L"python.exe" && name != L"pythonw.exe" && name != L"py.exe") return;
    p.scriptStatus = L"sem arquivo .py absoluto identificavel";
    const auto args = arguments(p.command);
    for (size_t i = 1; i < args.size(); ++i) {
        const auto a = lower(args[i]);
        if (a == L"-c" || a == L"-m") { p.scriptStatus = L"codigo inline/modulo: nao analisado"; return; }
        if (a == L"-w" || a == L"-x") { ++i; continue; }
        if (a.empty() || a[0] == L'-') continue;
        if (!(a.size() >= 3 && a.substr(a.size() - 3) == L".py") && !(a.size() >= 4 && a.substr(a.size() - 4) == L".pyw")) return;
        p.scriptPath = args[i];
        if (a.size() < 3 || a[1] != L':' || (a[2] != L'\\' && a[2] != L'/')) { p.scriptStatus = L"caminho relativo: nao resolvido com seguranca"; return; }
        const std::wstring root = a.substr(0, 3);
        if (GetDriveTypeW(root.c_str()) != DRIVE_FIXED) { p.scriptStatus = L"unidade nao local: consulta omitida"; return; }
        Handle file(CreateFileW(args[i].c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!file) { p.scriptStatus = L"arquivo inacessivel"; return; }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file.h, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
            info.nFileSizeHigh || info.nFileSizeLow > 1024 * 1024) { p.scriptStatus = L"arquivo ignorado: limite 1 MiB ou link/reparse"; return; }
        std::string source(info.nFileSizeLow, '\0'); DWORD read = 0;
        if (!ReadFile(file.h, source.data(), static_cast<DWORD>(source.size()), &read, nullptr)) { p.scriptStatus = L"erro de leitura"; return; }
        source.resize(read);
        if (source.find('\0') != std::string::npos) { p.scriptStatus = L"codificacao nao suportada"; return; }
        const auto indicators = inspectScriptText(source);
        p.scriptStatus = indicators.score ? L"combinacao de indicadores estaticos; revisar o fonte" : L"analisado: sem a combinacao de indicadores conhecida";
        if (indicators.score) p.add(indicators.score, indicators.webhook ?
            L"Script combina storage sensivel, credenciais, biblioteca HTTP e webhook" :
            L"Script combina storage sensivel, credenciais e biblioteca HTTP");
        return;
    }
}
