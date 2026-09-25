#pragma once
#include "pid_monitor.h"
#include "ui-assets/embedded_assets.h"
#include <commctrl.h>
#include <commdlg.h>
#include <gdiplus.h>
#include <dwmapi.h>
#include <uxtheme.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace MonitorUI {
using namespace Gdiplus;
constexpr COLORREF background = RGB(10, 8, 16), panelColor = RGB(19, 15, 29), textColor = RGB(239, 232, 250), mutedColor = RGB(158, 145, 180);
constexpr int StartButton = 101, StopButton = 102, SettingsButton = 103, ExportButton = 104;
struct Png {
    IStream* stream = nullptr;
    std::unique_ptr<Bitmap> bitmap;
    ~Png() { bitmap.reset(); if (stream) stream->Release(); }
    void load(const unsigned char* bytes, size_t size) {
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, size);
        if (!memory) return;
        void* target = GlobalLock(memory);
        if (!target) { GlobalFree(memory); return; }
        memcpy(target, bytes, size); GlobalUnlock(memory);
        if (FAILED(CreateStreamOnHGlobal(memory, TRUE, &stream))) { GlobalFree(memory); return; }
        bitmap.reset(Bitmap::FromStream(stream));
        if (bitmap && bitmap->GetLastStatus() != Ok) bitmap.reset();
    }
};
struct App {
    HWND window = nullptr, list = nullptr, details = nullptr, console = nullptr, search = nullptr;
    HWND buttons[4]{};
    MonitorEngine engine;
    MonitorSnapshot snapshot;
    std::vector<ProcessKey> visible;
    ProcessKey selected{};
    HFONT body = nullptr, mono = nullptr;
    HBRUSH panelBrush = CreateSolidBrush(panelColor);
    Png artwork[4][3];
    Png cardSurface, consoleSurface;
    int width = 1280, height = 850, nav = 0;
    int hovered = 0;
    bool closing = false, updating = false, uiTest = false, screenshotDone = false;
    std::wstring lastDetail, exportStatus, testPath;
    ULONGLONG lastConsole = 0, started = 0;
    std::deque<size_t> networkTrend;
    ULONGLONG lastCycle = 0;
    int testStage = 0, testFailures = 0;
    ULONGLONG testCycle = 0;
    std::wstring checks;
    ~App() { if (body) DeleteObject(body); if (mono) DeleteObject(mono); DeleteObject(panelBrush); }
};
App* app(HWND hwnd) { return reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA)); }
void fill(Graphics& g, int x, int y, int w, int h, Color c) { SolidBrush b(c); g.FillRectangle(&b, x, y, w, h); }
void roundPanel(Graphics& g, int x, int y, int w, int h, Color fillColor, Color edge, int radius = 14) {
    if (w <= 0 || h <= 0) return;
    const int d = radius * 2;
    GraphicsPath path;
    path.AddArc(x, y, d, d, 180, 90); path.AddArc(x + w - d, y, d, d, 270, 90);
    path.AddArc(x + w - d, y + h - d, d, d, 0, 90); path.AddArc(x, y + h - d, d, d, 90, 90); path.CloseFigure();
    SolidBrush b(fillColor); Pen p(edge, 1); g.FillPath(&b, &path); g.DrawPath(&p, &path);
}
void text(Graphics& g, const std::wstring& value, int x, int y, int w, int h, float size = 13, Color color = Color(238, 230, 250), bool bold = false, const wchar_t* face = L"Segoe UI") {
    Font font(face, size, bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color); StringFormat format;
    format.SetTrimming(StringTrimmingEllipsisCharacter); format.SetFormatFlags(StringFormatFlagsNoWrap);
    g.DrawString(value.c_str(), -1, &font, RectF(static_cast<REAL>(x), static_cast<REAL>(y), static_cast<REAL>(w), static_cast<REAL>(h)), &format, &brush);
}
int contentX() { return 204; }
int contentWidth(const App& a) { return a.width - contentX() - 28; }
int tableWidth(const App& a) { return (contentWidth(a) - 18) * 55 / 100; }
int consoleTop(const App& a) { return a.height - 221; }
void paint(App& a, HDC dc) {
    Graphics g(dc); g.SetSmoothingMode(SmoothingModeAntiAlias); g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
    fill(g, 0, 0, a.width, a.height, Color(10, 8, 16));
    fill(g, 0, 0, 178, a.height, Color(16, 11, 26));
    Pen divider(Color(43, 31, 60)); g.DrawLine(&divider, 178, 0, 178, a.height);
    roundPanel(g, 21, 26, 40, 40, Color(64, 30, 108), Color(131, 83, 190), 11);
    text(g, L"S", 32, 30, 28, 34, 25, Color(232, 214, 255), true);
    text(g, L"SENTINEL", 71, 30, 99, 24, 15, Color(241, 230, 255), true);
    text(g, L"PID MONITOR", 72, 51, 100, 18, 9, Color(145, 120, 173), true);
    text(g, L"WORKSPACE LOCAL", 23, 102, 149, 20, 9, Color(136, 113, 162), true);
    const wchar_t* navLabels[] = { L"Visao geral", L"Alertas", L"Processos", L"Console" };
    const wchar_t* navIcons[] = { L"01", L"02", L"03", L"04" };
    for (int i = 0; i < 4; ++i) {
        const int y = 137 + i * 51;
        if (a.nav == i) roundPanel(g, 15, y - 7, 148, 43, Color(47, 27, 73), Color(88, 51, 126), 9);
        text(g, navIcons[i], 27, y + 3, 28, 22, 11, Color(155, 104, 210), true, L"Consolas");
        text(g, navLabels[i], 62, y, 99, 26, 13, a.nav == i ? Color(244, 231, 255) : Color(165, 148, 184), a.nav == i);
    }
    roundPanel(g, 16, a.height - 147, 146, 105, Color(22, 15, 34), Color(49, 32, 69), 10);
    text(g, a.snapshot.shield.enabled ? L"SHIELD HABILITADO" : L"DETECTAR SOMENTE", 25, a.height - 132, 136, 21, 10, Color(190, 149, 231), true);
    text(g, L"Regras de rede: " + std::to_wstring(a.snapshot.shield.rules.size()), 25, a.height - 103, 136, 20, 11, Color(152, 135, 170));
    text(g, L"Gerenciar: Configuracoes", 25, a.height - 84, 136, 20, 10, Color(152, 135, 170));
    const int x = contentX(), cw = contentWidth(a);
    text(g, L"SEGURANCA  /  ATIVIDADE DO SISTEMA", x, 22, cw - 220, 20, 10, Color(158, 121, 197), true);
    text(g, L"Monitor de atividade", x, 48, cw - 250, 43, 29, Color(247, 240, 255), true);
    text(g, L"Processos, conexoes e sinais de acesso a dados sensiveis.", x, 92, cw - 180, 23, 13, Color(154, 139, 175));
    const bool running = !a.engine.finished && !a.engine.stopRequested;
    const std::wstring mode = a.closing ? L"ENCERRANDO" : running ? L"MONITOR ATIVO" : a.engine.finished ? L"MONITOR PARADO" : L"PARANDO";
    roundPanel(g, a.width - 215, 33, 187, 36, Color(30, 21, 44), Color(68, 45, 91), 18);
    SolidBrush dot(running ? Color(121, 210, 178) : Color(160, 111, 211)); g.FillEllipse(&dot, a.width - 200, 47, 7, 7);
    text(g, mode, a.width - 184, 42, 152, 22, 10, Color(219, 199, 241), true);
    text(g, L"Ultima amostra  " + a.snapshot.updated, a.width - 219, 82, 191, 22, 11, Color(144, 127, 163));
    const int cardW = (cw - 32) / 3;
    size_t alerts = 0; for (const auto& r : a.snapshot.rows) if (r.ready && r.process.score >= 8) ++alerts;
    const std::wstring values[] = { std::to_wstring(a.snapshot.rows.size()), std::to_wstring(alerts), std::to_wstring(a.snapshot.eventCount) };
    const wchar_t* labels[] = { L"PROCESSOS NA AMOSTRA", L"SUSPEITOS / ALTO RISCO", L"EVENTOS DA SESSAO" };
    const std::wstring subtitles[] = { std::to_wstring(a.snapshot.pending) + L" aguardando analise detalhada", L"Score >= 8  |  revisar evidencias", L"Historico local com horario e origem" };
    for (int i = 0; i < 3; ++i) {
        const int cx = x + i * (cardW + 16);
        roundPanel(g, cx, 132, cardW, 115, Color(21, 15, 33), Color(51, 34, 70), 13);
        if (a.cardSurface.bitmap) g.DrawImage(a.cardSurface.bitmap.get(), cx, 132, cardW, 115);
        text(g, labels[i], cx + 18, 148, cardW - 36, 21, 10, Color(157, 136, 183), true);
        text(g, values[i], cx + 17, 173, cardW - 36, 43, 29, i == 1 && alerts ? Color(215, 153, 252) : Color(244, 234, 255), true);
        text(g, subtitles[i], cx + 18, 218, cardW - 36, 22, 10, Color(143, 126, 161));
    }
    const int top = 320, leftW = tableWidth(a), consoleY = consoleTop(a);
    roundPanel(g, x, top, leftW, consoleY - top - 15, Color(19, 15, 29), Color(46, 33, 63), 12);
    roundPanel(g, x + leftW + 18, top, cw - leftW - 18, consoleY - top - 15, Color(19, 15, 29), Color(46, 33, 63), 12);
    text(g, a.nav == 1 ? L"ALERTAS DA AMOSTRA" : L"PROCESSOS OBSERVADOS", x + 16, top + 14, leftW - 170, 22, 11, Color(214, 197, 234), true);
    text(g, L"EVIDENCIAS DO PROCESSO", x + leftW + 34, top + 14, cw - leftW - 50, 22, 11, Color(214, 197, 234), true);
    fill(g, x + 10, 365, leftW - 20, 25, Color(28, 21, 40));
    text(g, L"PID", x + 17, 371, 60, 18, 9, Color(160, 139, 183), true);
    text(g, L"PROCESSO", x + 82, 371, leftW - 250, 18, 9, Color(160, 139, 183), true);
    text(g, L"SCORE", x + leftW - 168, 371, 52, 18, 9, Color(160, 139, 183), true);
    text(g, L"RISCO", x + leftW - 111, 371, 94, 18, 9, Color(160, 139, 183), true);
    roundPanel(g, x, consoleY, cw, 151, Color(14, 11, 22), Color(47, 32, 65), 12);
    if (a.consoleSurface.bitmap) g.DrawImage(a.consoleSurface.bitmap.get(), x, consoleY, cw, 151);
    text(g, L"CONSOLE  /  EVENTOS AO VIVO", x + 16, consoleY + 11, 330, 22, 10, Color(197, 167, 224), true, L"Consolas");
    text(g, L"ULTIMOS 1500 EVENTOS", a.width - 203, consoleY + 11, 178, 22, 9, Color(116, 96, 138), false, L"Consolas");
    text(g, a.snapshot.telemetry, x, a.height - 57, cw, 22, 10, Color(172, 138, 200));
    text(g, a.exportStatus.empty() ? L"Rede por amostragem  |  Pontuacao heuristica, nao confirma infeccao  |  " + std::to_wstring(a.snapshot.protectedCount) + L" processos inacessiveis" : a.exportStatus,
        x, a.height - 34, cw, 22, 10, Color(124, 111, 140));
}
void layout(App& a) {
    RECT r{}; GetClientRect(a.window, &r); a.width = r.right; a.height = r.bottom;
    const int x = contentX(), cw = contentWidth(a), lw = tableWidth(a), cy = consoleTop(a);
    const int bw = (cw - 30) / 4;
    for (int i = 0; i < 4; ++i) MoveWindow(a.buttons[i], x + i * (bw + 10), 264, bw, 44, TRUE);
    MoveWindow(a.search, x + lw - 181, 331, 163, 23, TRUE);
    MoveWindow(a.list, x + 9, 393, lw - 18, cy - 424, TRUE);
    MoveWindow(a.details, x + lw + 34, 364, cw - lw - 48, cy - 394, TRUE);
    MoveWindow(a.console, x + 16, cy + 39, cw - 32, 100, TRUE);
    ListView_SetColumnWidth(a.list, 0, 65); ListView_SetColumnWidth(a.list, 1, std::max(115, lw - 259));
    ListView_SetColumnWidth(a.list, 2, 54); ListView_SetColumnWidth(a.list, 3, 101);
    InvalidateRect(a.window, nullptr, FALSE);
}
void setDetail(App& a) {
    const int selected = ListView_GetNextItem(a.list, -1, LVNI_SELECTED);
    if (selected >= 0 && static_cast<size_t>(selected) < a.visible.size()) a.selected = a.visible[selected];
    std::wstring value = L"Selecione um processo para inspecionar\r\nas evidencias, a linha de comando e a rede.\r\n\r\nA coleta detalhada ocorre em segundo plano.\r\n\r\nNenhum dado de cookies ou tokens e lido.";
    for (const auto& row : a.snapshot.rows) if (processKey(row.process) == a.selected) {
        value = rowDetails(row);
        for (const auto& rule : a.snapshot.shield.rules) if (rule.path == normalize(row.process.path)) {
            value = L"SHIELD: REGRA DE SAIDA POR EXECUTAVEL\r\nTodas as instancias deste caminho. Restaurar em Configuracoes.\r\n\r\n" + value; break;
        }
        break;
    }
    if (value != a.lastDetail) {
        const LRESULT scroll = SendMessageW(a.details, EM_GETFIRSTVISIBLELINE, 0, 0);
        SetWindowTextW(a.details, value.c_str()); SendMessageW(a.details, EM_LINESCROLL, 0, scroll);
        a.lastDetail = std::move(value);
    }
}
void refresh(App& a) {
    a.snapshot = a.engine.snapshot();
    wchar_t filter[256]{}; GetWindowTextW(a.search, filter, _countof(filter));
    const auto query = lower(filter);
    const int topIndex = ListView_GetTopIndex(a.list);
    a.updating = true; SendMessageW(a.list, WM_SETREDRAW, FALSE, 0); ListView_DeleteAllItems(a.list); a.visible.clear();
    int index = 0, selection = -1;
    for (const auto& row : a.snapshot.rows) {
        const auto& p = row.process;
        if (a.nav == 1 && (!row.ready || p.score < 8)) continue;
        if (!query.empty() && !has(p.name + L" " + std::to_wstring(p.pid) + L" " + p.path, query)) continue;
        std::wstring pid = std::to_wstring(p.pid), name = p.name, score = row.ready ? std::to_wstring(p.score) : L"...", state = row.ready ? classification(p.score) : L"ANALISANDO";
        LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = index; item.pszText = &pid[0];
        ListView_InsertItem(a.list, &item);
        ListView_SetItemText(a.list, index, 1, &name[0]); ListView_SetItemText(a.list, index, 2, &score[0]); ListView_SetItemText(a.list, index, 3, &state[0]);
        a.visible.push_back(processKey(p)); if (a.visible.back() == a.selected) selection = index;
        ++index;
    }
    if (selection < 0 && index) { selection = 0; a.selected = a.visible[0]; }
    if (selection >= 0) ListView_SetItemState(a.list, selection, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    if (topIndex > 0 && index) ListView_EnsureVisible(a.list, std::min(topIndex, index - 1), FALSE);
    SendMessageW(a.list, WM_SETREDRAW, TRUE, 0); InvalidateRect(a.list, nullptr, FALSE); a.updating = false; setDetail(a);
    if (a.lastConsole != a.snapshot.eventCount) {
        std::wstring value;
        for (const auto& e : a.snapshot.events) value += L"[" + e.time + L"] " + (e.level == 2 ? L"! " : e.level == 1 ? L"~ " : L"  ") + L"[" + e.category + L"] " + e.message + L"\r\n";
        DWORD start = 0, end = 0; SendMessageW(a.console, EM_GETSEL, reinterpret_cast<WPARAM>(&start), reinterpret_cast<LPARAM>(&end));
        if (start == end) {
            SetWindowTextW(a.console, value.c_str()); SendMessageW(a.console, EM_SETSEL, value.size(), value.size()); SendMessageW(a.console, EM_SCROLLCARET, 0, 0);
        }
        a.lastConsole = a.snapshot.eventCount;
    }
    EnableWindow(a.buttons[0], a.engine.finished && !a.closing);
    EnableWindow(a.buttons[1], !a.engine.finished && !a.engine.stopRequested);
    RECT top{178, 0, a.width, 258}, bottom{178, a.height - 64, a.width, a.height};
    InvalidateRect(a.window, &top, FALSE); InvalidateRect(a.window, &bottom, FALSE);
    RECT shieldPanel{16, a.height - 147, 164, a.height - 41}; InvalidateRect(a.window, &shieldPanel, FALSE);
}
void settings(App& a) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING | (a.engine.intervalMs == 500 ? MF_CHECKED : 0), 301, L"Amostragem: 0,5 segundo");
    AppendMenuW(menu, MF_STRING | (a.engine.intervalMs == 1000 ? MF_CHECKED : 0), 302, L"Amostragem: 1 segundo");
    AppendMenuW(menu, MF_STRING | (a.engine.intervalMs == 2000 ? MF_CHECKED : 0), 303, L"Amostragem: 2 segundos");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (a.engine.probeHandles ? MF_CHECKED : 0), 304, L"Consultar handles em candidatos (mais lento)");
    AppendMenuW(menu, MF_STRING, 305, L"Sobre cobertura e privacidade");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (!a.snapshot.shield.enabled ? MF_CHECKED : 0), 306, L"Shield: detectar somente");
    AppendMenuW(menu, MF_STRING | (a.snapshot.shield.enabled ? MF_CHECKED : 0), 307, L"Shield: isolar executavel da rede...");
    AppendMenuW(menu, MF_STRING, 308, L"Shield: bloquear leitura com driver (em desenvolvimento)...");
    AppendMenuW(menu, MF_STRING, 309, L"Shield: consultar regras e disponibilidade...");
    AppendMenuW(menu, MF_STRING, 310, L"Shield: restaurar todas as regras gerenciadas...");
    RECT r{}; GetWindowRect(a.buttons[2], &r);
    int action = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_LEFTALIGN, r.left, r.bottom + 4, 0, a.window, nullptr);
    DestroyMenu(menu);
    if (action >= 301 && action <= 303) a.engine.intervalMs = action == 301 ? 500 : action == 302 ? 1000 : 2000;
    if (action == 304) a.engine.probeHandles = !a.engine.probeHandles;
    if (action == 305) MessageBoxW(a.window,
        L"ETW tenta observar criacao/saida de processos e operacoes em arquivos sensiveis. Pode exigir administrador.\n\n"
        L"Rede: amostragem de 0,5 a 2 segundos; conexoes mais rapidas podem escapar. Nao identifica URLs HTTPS.\n\n"
        L"Scripts: leitura apenas do .py local associado, com caminho absoluto e ate 1 MiB. Comentarios e exemplos tambem podem corresponder aos indicadores.\n\n"
        L"Discord/navegadores: observa nomes de arquivos, nunca o conteudo de tokens, cookies ou senhas.\n\n"
        L"Historico: ultimos 1500 eventos na memoria. Persistencia e assinaturas sao reavaliadas periodicamente.\n\n"
        L"Shield e opcional: cria regras de saida por executavel. ETW detecta depois da operacao; pode haver leitura e envio antes do bloqueio.\n\n"
        L"A ausencia de alertas nao garante ausencia de malware.", L"Sentinel / Cobertura", MB_OK | MB_ICONINFORMATION);
    if (action == 306) a.engine.shield.enable(false);
    if (action == 307 && !a.uiTest) {
        if (!a.snapshot.shield.coverage) MessageBoxW(a.window,
            L"Inicie o monitor como administrador e verifique se o ETW de arquivos esta ativo. O Shield nao pode ser habilitado sem esse sensor.",
            L"Shield indisponivel", MB_OK | MB_ICONWARNING);
        else if (MessageBoxW(a.window,
            L"Habilitar isolamento automatico para interpretadores ou processos com score >= 8 acessando storage sensivel?\n\n"
            L"A regra bloqueia saidas de rede de TODAS as instancias do mesmo executavel, inclusive rede local. Isolar Python afeta outros scripts que usam esse Python.\n\n"
            L"Regras permanecem ao parar/fechar o app ou reiniciar o PC. Use Configuracoes > Restaurar todas as regras gerenciadas para remove-las.\n\n"
            L"ETW e reativo: leitura e envio podem ocorrer antes do bloqueio. Nenhum processo sera suspenso. Requer administrador e Firewall ativo.",
            L"Habilitar Shield Mode", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) == IDYES) a.engine.shield.enable(true);
    }
    if (action == 308) MessageBoxW(a.window,
        L"SentinelGuard e uma base experimental em driver\\. Nao existe driver compilado, assinado ou validado neste pacote.\n\n"
        L"O bloqueio preventivo ainda nao pode ser ativado pela interface. Consulte driver\\README.md para compilar com WDK e testar a politica em uma VM.",
        L"SentinelGuard / Em desenvolvimento", MB_OK | MB_ICONINFORMATION);
    if (action == 309) {
        const auto shield = a.engine.shield.snapshot();
        std::wstring message = shield.status + L"\n\nRegras persistentes gerenciadas: " + std::to_wstring(shield.rules.size()) + L"\n";
        for (size_t i = 0; i < shield.rules.size() && i < 20; ++i) message += L"\n" + shield.rules[i].path;
        if (shield.rules.size() > 20) message += L"\n... Exportar relatorio para a lista completa.";
        message += L"\n\nA lista identifica regras gerenciadas; politicas externas podem alterar a efetividade do Firewall.";
        MessageBoxW(a.window, message.c_str(), L"Shield / Regras de rede", MB_OK | MB_ICONINFORMATION);
    }
    if (action == 310 && !a.uiTest && MessageBoxW(a.window,
        L"Remover todas as regras de rede criadas pelo Shield, inclusive de sessoes anteriores?\n\n"
        L"A operacao exige administrador e tambem desativa novos isolamentos. Outras regras do Firewall permanecem intactas. Falhas serao registradas no console.",
        L"Restaurar rede dos executaveis", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) == IDYES) a.engine.shield.restore();
    refresh(a);
}
void exportReport(App& a) {
    wchar_t filename[32768] = L"sentinel-relatorio.txt";
    OPENFILENAMEW dialog{}; dialog.lStructSize = sizeof(dialog); dialog.hwndOwner = a.window;
    dialog.lpstrFilter = L"Relatorio de texto UTF-8\0*.txt\0\0"; dialog.lpstrFile = filename; dialog.nMaxFile = _countof(filename);
    dialog.lpstrDefExt = L"txt"; dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&dialog)) return;
    a.exportStatus = writeUtf8(filename, monitorReport(a.snapshot)) ? L"Relatorio exportado: " + std::wstring(filename) : L"Falha ao salvar o relatorio.";
    InvalidateRect(a.window, nullptr, FALSE);
}
void drawButton(App& a, const DRAWITEMSTRUCT& item) {
    const int index = static_cast<int>(item.CtlID) - StartButton;
    if (index < 0 || index >= 4) return;
    Graphics g(item.hDC); g.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    fill(g, 0, 0, item.rcItem.right, item.rcItem.bottom, Color(10, 8, 16));
    const int state = (item.itemState & ODS_SELECTED) ? 2 : a.hovered == static_cast<int>(item.CtlID) ? 1 : 0;
    auto image = a.artwork[index][state].bitmap.get();
    if (image) {
        ImageAttributes attributes;
        ColorMatrix matrix = { 1,0,0,0,0, 0,1,0,0,0, 0,0,1,0,0, 0,0,0,(item.itemState & ODS_DISABLED) ? .32f : 1.f,0, 0,0,0,0,1 };
        attributes.SetColorMatrix(&matrix);
        g.DrawImage(image, Rect(0, 0, item.rcItem.right, item.rcItem.bottom), 0, 0, image->GetWidth(), image->GetHeight(), UnitPixel, &attributes);
    }
    if (item.itemState & ODS_FOCUS) { Pen p(Color(195, 147, 246)); g.DrawRectangle(&p, 3, 3, item.rcItem.right - 7, item.rcItem.bottom - 7); }
}
void uiCheck(App& a, bool condition, const wchar_t* description) {
    a.checks += std::wstring(condition ? L"PASS " : L"FAIL ") + description + L"\r\n";
    if (!condition) ++a.testFailures;
}
LRESULT CALLBACK buttonProc(HWND hwnd, UINT message, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR ref) {
    auto& a = *reinterpret_cast<App*>(ref);
    if (message == WM_MOUSEMOVE) {
        a.hovered = GetDlgCtrlID(hwnd); InvalidateRect(hwnd, nullptr, FALSE);
        TRACKMOUSEEVENT track{ sizeof(track), TME_LEAVE, hwnd, 0 }; TrackMouseEvent(&track);
    } else if (message == WM_MOUSELEAVE) { a.hovered = 0; InvalidateRect(hwnd, nullptr, FALSE); }
    return DefSubclassProc(hwnd, message, w, l);
}
bool screenshot(App& a, const std::wstring& path) {
    HDC source = GetDC(a.window), memory = CreateCompatibleDC(source);
    HBITMAP bitmap = CreateCompatibleBitmap(source, a.width, a.height);
    HGDIOBJ old = SelectObject(memory, bitmap);
    paint(a, memory);
    for (HWND child = GetWindow(a.window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        RECT bounds{}; GetWindowRect(child, &bounds);
        MapWindowPoints(nullptr, a.window, reinterpret_cast<POINT*>(&bounds), 2);
        const int state = SaveDC(memory);
        SetViewportOrgEx(memory, bounds.left, bounds.top, nullptr);
        IntersectClipRect(memory, 0, 0, bounds.right - bounds.left, bounds.bottom - bounds.top);
        SendMessageW(child, WM_PRINT, reinterpret_cast<WPARAM>(memory), PRF_CLIENT | PRF_NONCLIENT | PRF_CHILDREN | PRF_ERASEBKGND);
        RestoreDC(memory, state);
    }
    const bool rendered = GetPixel(memory, 5, 5) == RGB(16, 11, 26) && GetPixel(memory, 190, 5) == background;
    bool saved = false;
    {
        Bitmap image(bitmap, nullptr);
        UINT count = 0, size = 0; GetImageEncodersSize(&count, &size); std::vector<BYTE> bytes(size);
        if (rendered && size && GetImageEncoders(count, size, reinterpret_cast<ImageCodecInfo*>(bytes.data())) == Ok) {
            auto codecs = reinterpret_cast<ImageCodecInfo*>(bytes.data());
            for (UINT i = 0; i < count; ++i) if (wcscmp(codecs[i].MimeType, L"image/png") == 0) { saved = image.Save(path.c_str(), &codecs[i].Clsid) == Ok; break; }
        }
    }
    SelectObject(memory, old); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(a.window, source);
    return saved;
}
LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM w, LPARAM l) {
    if (message == WM_NCCREATE) { SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams)); }
    App* value = app(hwnd);
    if (!value) return DefWindowProcW(hwnd, message, w, l);
    auto& a = *value;
    switch (message) {
    case WM_GETMINMAXINFO: { auto info = reinterpret_cast<MINMAXINFO*>(l); info->ptMinTrackSize = { 1120, 820 }; return 0; }
    case WM_SIZE: if (a.list) layout(a); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd, &ps);
        HDC buffer = CreateCompatibleDC(dc); HBITMAP bitmap = CreateCompatibleBitmap(dc, a.width, a.height);
        HGDIOBJ old = SelectObject(buffer, bitmap); paint(a, buffer); BitBlt(dc, 0, 0, a.width, a.height, buffer, 0, 0, SRCCOPY);
        SelectObject(buffer, old); DeleteObject(bitmap); DeleteDC(buffer); EndPaint(hwnd, &ps); return 0;
    }
    case WM_PRINTCLIENT: paint(a, reinterpret_cast<HDC>(w)); return 0;
    case WM_DRAWITEM: drawButton(a, *reinterpret_cast<DRAWITEMSTRUCT*>(l)); return TRUE;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: SetTextColor(reinterpret_cast<HDC>(w), reinterpret_cast<HWND>(l) == a.console ? RGB(178, 158, 204) : textColor);
        SetBkColor(reinterpret_cast<HDC>(w), panelColor); return reinterpret_cast<LRESULT>(a.panelBrush);
    case WM_LBUTTONUP: {
        const int x = static_cast<short>(LOWORD(l)), y = static_cast<short>(HIWORD(l));
        if (x < 178 && y >= 130 && y < 334) { a.nav = std::min(3, (y - 130) / 51); refresh(a); InvalidateRect(hwnd, nullptr, FALSE); if (a.nav == 3) SetFocus(a.console); }
        return 0;
    }
    case WM_COMMAND:
        if (HIWORD(w) == EN_CHANGE && reinterpret_cast<HWND>(l) == a.search) { refresh(a); return 0; }
        switch (LOWORD(w)) {
        case StartButton: a.engine.start(); a.exportStatus.clear(); refresh(a); return 0;
        case StopButton: a.engine.requestStop(); refresh(a); return 0;
        case SettingsButton: settings(a); return 0;
        case ExportButton: exportReport(a); return 0;
        }
        break;
    case WM_NOTIFY: {
        const auto header = reinterpret_cast<NMHDR*>(l);
        if (header->hwndFrom == a.list && header->code == LVN_ITEMCHANGED && !a.updating) setDetail(a);
        if (header->hwndFrom == a.list && header->code == NM_CUSTOMDRAW) {
            auto draw = reinterpret_cast<NMLVCUSTOMDRAW*>(l);
            if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                draw->clrTextBk = panelColor; draw->clrText = textColor;
                const size_t i = static_cast<size_t>(draw->nmcd.dwItemSpec);
                if (i < a.visible.size()) for (const auto& row : a.snapshot.rows) if (processKey(row.process) == a.visible[i]) {
                    if (!row.ready) draw->clrText = mutedColor;
                    else if (row.process.score >= 13) draw->clrText = RGB(238, 143, 179);
                    else if (row.process.score >= 8) draw->clrText = RGB(205, 157, 246);
                    break;
                }
                return CDRF_DODEFAULT;
            }
        }
        break;
    }
    case WM_TIMER:
        refresh(a);
        if (a.uiTest && GetTickCount64() - a.started > 10000 && !a.screenshotDone) {
            a.screenshotDone = true;
            uiCheck(a, !a.engine.finished && a.snapshot.cycles >= 2, L"start button runs live collection");
            uiCheck(a, !a.snapshot.shield.enabled, L"Shield starts in detect-only mode");
            uiCheck(a, !IsWindowEnabled(a.buttons[0]) && IsWindowEnabled(a.buttons[1]), L"running button states");
            bool assets = true; for (auto& button : a.artwork) for (auto& variant : button) if (!variant.bitmap) assets = false;
            uiCheck(a, assets && a.cardSurface.bitmap && a.consoleSurface.bitmap, L"exported buttons and interface surfaces embedded and decoded");
            SetWindowTextW(a.search, L"__no_such_process_fixture__");
            uiCheck(a, ListView_GetItemCount(a.list) == 0, L"search filters real process table");
            SetWindowTextW(a.search, L"");
            uiCheck(a, ListView_GetItemCount(a.list) == a.snapshot.rows.size(), L"clearing search restores process table");
            a.nav = 1; refresh(a);
            bool onlyAlerts = true;
            for (const auto& key : a.visible) for (const auto& row : a.snapshot.rows)
                if (processKey(row.process) == key && (!row.ready || row.process.score < 8)) onlyAlerts = false;
            uiCheck(a, onlyAlerts, L"alerts tab filters by analyzed risk");
            a.nav = 0; refresh(a); InvalidateRect(hwnd, nullptr, FALSE); UpdateWindow(hwnd);
            uiCheck(a, screenshot(a, a.testPath), L"render native window to PNG");
            uiCheck(a, writeUtf8(a.testPath + L".txt", monitorReport(a.snapshot)), L"export session as UTF-8");
            SendMessageW(hwnd, WM_COMMAND, StopButton, 0);
            a.testStage = 1;
        }
        if (a.uiTest && a.testStage == 1 && a.engine.finished) {
            uiCheck(a, IsWindowEnabled(a.buttons[0]) && !IsWindowEnabled(a.buttons[1]), L"stop button completes and updates controls");
            a.testCycle = a.snapshot.cycles;
            SendMessageW(hwnd, WM_COMMAND, StartButton, 0);
            uiCheck(a, !a.engine.finished, L"start button restarts monitor");
            a.testStage = 2;
        } else if (a.uiTest && a.testStage == 2 && a.snapshot.cycles > a.testCycle) {
            SendMessageW(hwnd, WM_COMMAND, StopButton, 0); a.testStage = 3;
        } else if (a.uiTest && a.testStage == 3 && a.engine.finished) {
            a.checks += L"Failures: " + std::to_wstring(a.testFailures) + L"\r\n";
            writeUtf8(a.testPath + L".checks.txt", a.checks); a.closing = true;
        }
        if (a.closing && a.engine.finished) DestroyWindow(hwnd);
        return 0;
    case WM_CLOSE: a.closing = true; a.engine.requestStop(); if (a.engine.finished) DestroyWindow(hwnd); else InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_DESTROY: KillTimer(hwnd, 1); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
}
void loadArtwork(App& a) {
    a.cardSurface.load(UiAssets::surface_card, sizeof(UiAssets::surface_card));
    a.consoleSurface.load(UiAssets::surface_console, sizeof(UiAssets::surface_console));
#define LOAD(i, name) a.artwork[i][0].load(UiAssets::name##_normal, sizeof(UiAssets::name##_normal)); a.artwork[i][1].load(UiAssets::name##_hover, sizeof(UiAssets::name##_hover)); a.artwork[i][2].load(UiAssets::name##_pressed, sizeof(UiAssets::name##_pressed));
    LOAD(0, btn_start) LOAD(1, btn_stop) LOAD(2, btn_settings) LOAD(3, btn_export)
#undef LOAD
}
}
int monitorApp(int argc, wchar_t** argv) {
    using namespace MonitorUI;
    const bool test = argc >= 2 && std::wstring(argv[1]) == L"--ui-test";
    if (test && argc != 3) return 2;
    // Fecha apenas o console temporario criado pelo Explorer.
    DWORD consolePids[2]{};
    if (!test && GetConsoleProcessList(consolePids, 2) == 1) FreeConsole();
    SetProcessDPIAware();
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    GdiplusStartupInput input; ULONG_PTR token = 0;
    if (GdiplusStartup(&token, &input, nullptr) != Ok) return 1;
    int result = 0;
    {
        App a; a.uiTest = test; if (test) a.testPath = argv[2];
        a.started = GetTickCount64();
        loadArtwork(a);
        INITCOMMONCONTROLSEX controls{ sizeof(controls), ICC_LISTVIEW_CLASSES }; InitCommonControlsEx(&controls);
        WNDCLASSW wc{}; wc.lpfnWndProc = windowProc; wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW); wc.lpszClassName = L"PIDSentinelMonitor"; wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
        RegisterClassW(&wc);
        a.window = CreateWindowExW(0, wc.lpszClassName, L"Sentinel | Monitor de processos", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 1300, 920, nullptr, nullptr, wc.hInstance, &a);
        if (!a.window) result = 1;
        else {
            BOOL dark = TRUE; DwmSetWindowAttribute(a.window, 20, &dark, sizeof(dark));
            a.body = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            a.mono = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
            const wchar_t* names[] = { L"Iniciar monitor", L"Parar monitor", L"Configuracoes", L"Exportar relatorio" };
            for (int i = 0; i < 4; ++i) {
                a.buttons[i] = CreateWindowExW(0, L"BUTTON", names[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0, a.window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(StartButton + i)), wc.hInstance, nullptr);
                SetWindowSubclass(a.buttons[i], buttonProc, 1, reinterpret_cast<DWORD_PTR>(&a));
            }
            a.search = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, a.window, reinterpret_cast<HMENU>(201), wc.hInstance, nullptr);
            SendMessageW(a.search, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Buscar nome ou PID"));
            a.list = CreateWindowExW(0, WC_LISTVIEWW, L"Processos observados", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER | LVS_NOCOLUMNHEADER,
                0, 0, 0, 0, a.window, reinterpret_cast<HMENU>(202), wc.hInstance, nullptr);
            ListView_SetExtendedListViewStyle(a.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            ListView_SetBkColor(a.list, panelColor); ListView_SetTextBkColor(a.list, panelColor); ListView_SetTextColor(a.list, textColor);
            SetWindowTheme(a.list, L"DarkMode_Explorer", nullptr); SetWindowTheme(ListView_GetHeader(a.list), L"DarkMode_ItemsView", nullptr);
            const wchar_t* headings[] = { L"PID", L"PROCESSO", L"SCORE", L"RISCO" };
            for (int i = 0; i < 4; ++i) { LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH; column.cx = 100; column.pszText = const_cast<wchar_t*>(headings[i]); ListView_InsertColumn(a.list, i, &column); }
            a.details = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, a.window, reinterpret_cast<HMENU>(203), wc.hInstance, nullptr);
            a.console = CreateWindowExW(0, L"EDIT", L"Aguardando eventos...", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL, 0, 0, 0, 0, a.window, reinterpret_cast<HMENU>(204), wc.hInstance, nullptr);
            SendMessageW(a.details, EM_SETLIMITTEXT, 2 * 1024 * 1024, 0); SendMessageW(a.console, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
            for (HWND h : { a.search, a.list, a.details, a.console }) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(h == a.console ? a.mono : a.body), TRUE);
            layout(a); SetTimer(a.window, 1, 500, nullptr);
            ShowWindow(a.window, SW_SHOW); UpdateWindow(a.window);
            SendMessageW(a.window, WM_COMMAND, StartButton, 0);
            MSG message{};
            while (GetMessageW(&message, nullptr, 0, 0) > 0) {
                if (!IsDialogMessageW(a.window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
            }
            a.engine.requestStop(); a.engine.join();
            if (test && a.testFailures) result = 1;
        }
    }
    GdiplusShutdown(token); if (SUCCEEDED(com)) CoUninitialize();
    return result;
}
