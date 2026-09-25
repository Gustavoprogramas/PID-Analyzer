# Validação desta versão

Ambiente de compilação: Visual Studio 2026 Developer Command Prompt v18.5.2, MSVC 19.50.35730, x64, Windows SDK 10.0.26100.0.

- `pid.exe`: compilado com o comando documentado, C++17, `/EHsc /O2 /MT`. Dependências importadas são DLLs do Windows; não há dependência dinâmica do runtime C++ do Visual Studio.
- Scanner: 43 verificações passaram, incluindo pontuação, assinaturas, rede local e indicadores estáticos.
- Monitor: 13 verificações passaram, incluindo início/parada/reinício, correlação temporal, PID antigo e não acumulação de score.
- Shield/protocolo: 37 verificações passaram, incluindo identidade real de um processo de teste inofensivo, detecção sem ações por padrão, condições de habilitação, deduplicação, falha de bloqueio/remoção, recuperação de regras, restauração e perda de disponibilidade. As operações do Firewall foram simuladas por um backend de teste.
- Interface: 11 verificações passaram, incluindo controles, busca, filtro de alertas, relatório, reinício e Shield desabilitado por padrão. O autoteste renderiza os próprios controles para PNG e rejeita uma captura vazia.
- `guardctl.exe`: compilado com C++17 `/W4 /MT` e layout do protocolo verificado por `static_assert`. A execução sem argumentos mostra uso e sai sem conectar ao driver.
- Projeto WDK: XML verificado. O Windows SDK deste ambiente não inclui `km/fltKernel.h`; o driver não foi compilado, assinado, instalado nem executado.

A coleta ETW elevada, a efetividade das regras reais de Firewall e o driver precisam dos testes em VM descritos na documentação. Os testes executados não demonstram prevenção de exfiltração. O exemplo de stealer não foi executado nem incluído no repositório. Capturas e relatórios locais ficam em `output/`, ignorado pelo Git.
