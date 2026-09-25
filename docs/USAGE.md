# PID Analyzer — monitor de processos

Aplicativo Windows com interface preta/roxa, console de eventos, processos pesquisáveis, painel de evidências e monitoramento contínuo. É uma ferramenta de triagem, não um antivírus. Não remove arquivos, não altera inicialização e não encerra os processos examinados.

Abra `pid.exe` para iniciar a interface e a coleta. **Parar monitor** interrompe os sensores e preserva o histórico; **Iniciar monitor** retoma a coleta. Fechar a janela encerra os sensores. **Configurações** permite selecionar o intervalo de 0,5, 1 ou 2 segundos e habilitar consultas de handles em candidatos. **Exportar relatório** salva processos, evidências, cobertura e histórico em texto UTF-8.

A interface mostra dados reais, inclusive análises pendentes. Assinaturas, scripts, persistência e módulos são analisados em segundo plano; a lista e o console continuam respondendo durante esse trabalho. As abas Alertas e Processos filtram a amostra atual; eventos anteriores permanecem no console.

## Sensores contínuos e limites

- **ETW de processos e arquivos:** tenta receber eventos de criação/saída de processos e abertura/leitura em locais sensíveis de Discord e navegadores. Usa uma sessão própria, filtros de IDs de eventos e metadados TDH. Não instala driver nem muda configurações de segurança. A sessão é desligada ao parar/fechar o monitor. Apenas uma sessão `PID.Sentinel.Live` pode existir; uma sessão já existente não é encerrada automaticamente.
- **Permissões:** ETW pode exigir execução como administrador. Se a inicialização ou um provedor falhar, o erro aparece no console e no rodapé, e as consultas periódicas continuam. Evento Open significa solicitação de abertura; Read identifica uma operação de leitura, sem revelar conteúdo nem comprovar exfiltração. Nem todo evento pode ser associado a um PID, especialmente depois que a thread/processo termina.
- **Rede TCP/UDP:** amostragem de 0,5–2 segundos. Conexões que começam e terminam entre amostras podem escapar. Não há captura de pacotes, inspeção de HTTPS nem identificação de URL/webhook pelo tráfego.
- **Correlação:** conexões externas e operações ETW em storage sensível podem contribuir por 60 segundos. Observações repetidas não acumulam os mesmos pontos. A identidade do processo usa PID e data de criação, evitando atribuir eventos antigos a um PID reutilizado. Acesso esperado exige nome exato, assinatura válida do fornecedor e correspondência entre aplicativo e família de storage.
- **Análise estática de Python:** consulta somente um `.py`/`.pyw` de caminho absoluto e local associado à linha de comando, limitado a 1 MiB. Exige combinação de referências a storage, credenciais e biblioteca HTTP; webhook adiciona peso à combinação. Não executa o script nem extrai tokens. Comentários/exemplos podem gerar indicadores, e código ofuscado, `-c`, `-m`, caminhos relativos e scripts já removidos podem escapar.
- **Revisões:** interpretadores são agendados para nova análise em cerca de 15 segundos; outros processos, persistência e cache de assinaturas, em cerca de 60 segundos, conforme a fila de trabalho. DLLs são consultadas em interpretadores ou processos com sinais iniciais. Handles opcionais têm limite de 1 segundo por candidato no monitor.
- **Histórico:** até 1500 eventos em memória, limitado à sessão do aplicativo. O console agrega repetições frequentes do mesmo evento de storage. Limites de filas, caches e perdas informadas pelo ETW são registrados. O relatório exportado inclui também processos atuais com risco baixo ou análise pendente.

Nenhum conteúdo de LevelDB, senhas, cookies ou tokens é lido. O scanner lê metadados desses arquivos via ETW/handles e, separadamente, o código-fonte do script Python associado. Não há proteção preventiva nem garantia de detectar todo stealer.

## Shield Mode de rede

O monitor inicia em **Detectar somente**. Nas Configurações é possível habilitar isolamento automático, consultar disponibilidade/regras e restaurar todas as regras gerenciadas. A confirmação de habilitação explica o alcance por executável. Sem ETW de arquivos, privilégios administrativos ou Firewall disponível, o console registra a falha e o modo permanece desabilitado.

A decisão exige um evento de abertura/leitura em storage reconhecido, associado a um PID com data de criação compatível. Interpretadores são candidatos imediatamente; outros executáveis exigem análise concluída e score ≥ 8, incluindo os sinais temporais. Uma conexão externa aumenta o score, mas não é pré-requisito: esperar observar a conexão poderia perder o primeiro envio. A correlação permanece válida por 60 segundos. Processos que já terminaram, acessos sem atribuição e leituras ocorridas antes de iniciar o sensor podem escapar.

O trabalho do Firewall ocorre numa thread separada. Antes de adicionar a regra, são conferidos novamente o processo vivo, PID/data de criação, caminho completo e condição de processo crítico. Caminhos remotos, o próprio Sentinel e componentes do Windows que não sejam interpretadores são recusados. Falhas são visíveis no console; não são apresentadas como isolamento bem-sucedido.

A regra usa `INetFwPolicy2`/`INetFwRule`, saída, qualquer protocolo e todos os perfis. Seu nome inclui um GUID, e grupo/descrição identificam sua propriedade. **É uma regra por caminho, não por PID**: outros processos e execuções futuras daquele executável também serão afetados. O app não altera a política global nem ativa serviços/perfis desabilitados. Políticas corporativas podem impedir regras locais.

As regras persistem após fechar o app ou reiniciar o Windows. Parar o monitor ou mudar para Detectar somente impede novos isolamentos, mantendo as regras anteriores. Ao reiniciar a coleta, habilite o Shield novamente. **Restaurar todas as regras gerenciadas** enumera regras persistentes, verifica nome, grupo, descrição, ação, direção e caminho antes de remover; falhas não apagam o registro da regra. A restauração desativa novos bloqueios, evitando isolamento imediato novamente. O app não remove regras de terceiros. Para recuperação manual, as regras aparecem no Firewall Avançado no grupo **PID Sentinel Shield**.

Limites: há latência do ETW, intervalo do monitor (0,5–2 s), filas, análise e propagação do Firewall. A regra não desfaz dados lidos/enviados, não garante encerrar toda conexão já existente e não impede que outro executável envie dados em nome do alvo. Não há suspensão, proteção contra injeção em processos permitidos ou resistência a um atacante administrador. Os testes automatizados usam Firewall simulado; a cadeia ETW elevado → regra real → tráfego deve ser validada em VM.

A etapa preventiva experimental é descrita em [SentinelGuard](../driver/README.md). Ela não é ativada pela interface desta versão.

## Compilação e distribuição

No **Visual Studio 2026 Developer Command Prompt x64**:

```bat
cd PID-Analyzer
cl /std:c++17 /EHsc /O2 /MT pid.cpp /link iphlpapi.lib ws2_32.lib wintrust.lib crypt32.lib /OUT:pid.exe
```

As bibliotecas adicionais do Windows estão declaradas no fonte com `#pragma comment(lib, ...)`. Mantenha `pid_script.h`, `pid_etw.h`, `pid_monitor.h`, `pid_shield.h`, `pid_monitor_ui.h` e `ui-assets/embedded_assets.h` junto ao projeto para recompilar. O `.exe` continua usando `/MT`; o driver possui compilação, assinatura e distribuição separadas.

O `ui-assets/export.js` exporta as artes dos botões e painéis a partir do HTML/CSS com Playwright. O exportador também grava `embedded_assets.h`, incorporado ao executável. Para alterar as artes:

```bat
cd ui-assets
npm ci
npx playwright install chromium
node export.js
cd ..
```

Depois, recompile o C++. **Node, Playwright e a pasta de PNGs não são necessários para executar o aplicativo em outro PC.** Os cards de exemplo do HTML não são usados como dados reais na interface.

Distribua apenas `pid.exe`. O alvo é **Windows 10/11 x64**; não há caminhos do computador de desenvolvimento embutidos no funcionamento do scanner. `/MT` vincula o runtime C/C++ estaticamente, dispensando o Visual C++ Redistributable separado. O executável continua dependendo das DLLs e dos serviços do próprio Windows. Não é uma versão para Windows 32 bits, Linux ou macOS, nem foi validado em todas as versões de Windows.

## Modo de scanner pelo terminal

```bat
pid.exe --scan
pid.exe --all
pid.exe --pid 1234
pid.exe --min-score 8
pid.exe --browser-handles
pid.exe --pid 1234 --browser-handles
pid.exe --browser-handles > relatorio.txt
pid.exe --pause
```

Sem argumentos, `pid.exe` abre a interface. `--gui` também abre a interface. No scanner pontual, o padrão mostra score a partir de 4, em ordem decrescente. `--pid` mostra o PID escolhido independentemente do score. `--all` inclui risco baixo. Ao concluir a análise pelo terminal, o programa executa `system("pause")` e aguarda uma tecla antes de fechar. `--pause` continua aceito por compatibilidade. A interface permanece aberta até você fechá-la e não usa uma pausa de terminal. `--help` lista as opções do scanner.

Executar em um terminal como administrador pode ampliar a cobertura. Acesso negado, processo encerrado e consulta indisponível são reportados; não são interpretados como ausência de risco ou ausência de assinatura. O scanner não tenta obter privilégios adicionais automaticamente.

## Evidências e pesos

| Sinal | Pontos |
|---|---:|
| Executável em Temp / AppData / Downloads | 4 / 2 / 1, sem acumular os três |
| Sem assinatura / assinatura inválida ou não confiável | 2 / 3 |
| Nome de processo Windows fora do local esperado, ou sem assinatura Microsoft no local esperado | 5 |
| TCP externo ativo ou SYN_SENT | 1 |
| Dez ou mais conexões TCP externas simultâneas | 2 adicionais |
| Interpretador com TCP externo | 2 adicionais |
| TCP LISTENING em interface que não é loopback | 2 |
| PowerShell com comando codificado / janela oculta | 2 / 1 |
| Interpretador com argumento de caminho em Temp / AppData | 4 / 2 |
| pythonw, execução sem console | 1 |
| Navegador/Office iniciando interpretador, diretamente ou por outro interpretador | 2 |
| Run/RunOnce / Startup correlacionado | 4 por categoria |
| Tarefa habilitada / serviço habilitado correlacionado com outros sinais | 4 por categoria |
| Módulo em Temp ou módulo sem assinatura válida em AppData | 4 no máximo |
| Handle aberto para armazenamento de navegador na consulta opcional | 5 |
| Operação ETW em storage sensível nos últimos 60 s (monitor) | 5 |
| Script combinando storage + credenciais + HTTP | 6 |
| Mesma combinação de script com indicador de webhook | 8, substitui os 6 |

Classificação: **BAIXO 0–3**, **ATENÇÃO 4–7**, **SUSPEITO 8–12**, **ALTO RISCO 13+**. São pesos heurísticos, não probabilidades calibradas. Aplicativos legítimos também podem atingir scores altos. Assinatura válida também não garante que o comportamento seja seguro.

Assinaturas são verificadas tanto no executável quanto em catálogos do Windows, separando Microsoft, outro fornecedor, sem assinatura, inválida/não confiável e inconclusiva. A classificação Microsoft usa a organização exata do certificado de um signatário validado. A validação usa confiança local e cache, sem consulta online de revogação.

TCP IPv4/IPv6 mostra PID, endpoints, portas e estado. UDP IPv4/IPv6 mostra somente endpoints locais: `GetExtendedUdpTable` não fornece destinos remotos, portanto UDP não gera pontos de conexão externa. LISTENING não prova exposição pela internet; regras de firewall não são examinadas.

## Persistência e limites de correlação

São consultados Run e RunOnce em HKCU/HKLM, visões 32/64 bits, Startup do usuário atual e comum (incluindo destinos de atalhos), tarefas agendadas acessíveis em subpastas e serviços Win32. Entradas são relacionadas aos processos pelo caminho completo normalizado, nunca só pelo nome do arquivo. Interpretadores e svchost exigem também compatibilidade entre os argumentos configurados e os argumentos em execução. Um mesmo tipo de persistência pontua uma vez por processo.

Tarefas desativadas aparecem como evidência, mas não pontuam. Tarefas e serviços precisam de outros sinais para pontuar. Não se afirma que um serviço foi criado recentemente: não há coleta de histórico/eventos. A existência de Run/Startup não comprova que a entrada está efetivamente autorizada pelas configurações de inicialização do Windows.

Não há enumeração dos perfis de todos os usuários. Comandos relativos, scripts associados diretamente a extensões, variáveis específicas de outro usuário, argumentos expandidos dinamicamente, wrappers e tarefas baseadas em COM podem não ser correlacionados. A comparação conservadora evita atribuir a um script a persistência de outro script que usa o mesmo interpretador. A enumeração de DLLs não cobre módulos ocultos, removidos das listas ou carregados manualmente.

## Consulta opcional de armazenamento de navegador

`--browser-handles` examina **nomes de arquivos já abertos**, sem ler seus conteúdos. Reconhece locais conhecidos de Chrome, Edge, Firefox, Brave, Opera e Vivaldi, incluindo Login Data, Cookies, Web Data, Local State, logins.json, key4.db e armazenamento local/de sessão. Também reconhece `Discord`, `discordcanary` e `discordptb` em `Local Storage/leveldb`. Não coleta senhas, cookies ou tokens.

Na varredura geral, seleciona processos com score inicial >= 4 e omite navegadores com assinatura válida. Use `--pid N --browser-handles` para examinar explicitamente qualquer processo acessível. Cada consulta usa um processo auxiliar sem janela, limitado a 3 segundos, com orçamento total de 30 segundos. Só o auxiliar do scanner pode ser encerrado por timeout. São examinados até 8192 handles por processo e exibidos até 16 caminhos; limites e falhas são sinalizados.

**Um handle aberto não comprova leitura nem roubo.** Arquivos já fechados não são observados. A enumeração usa APIs nativas carregadas dinamicamente e pode ficar indisponível conforme permissões e versão do Windows. O resultado não substitui telemetria contínua ou análise forense.

Linhas de comando podem conter parâmetros privados. Revise o relatório antes de enviá-lo a outras pessoas.

## Validação local

```bat
cl /std:c++17 /EHsc /O2 /MT /W4 pid_tests.cpp /Fe:pid_tests.exe
pid_tests.exe
cl /std:c++17 /EHsc /O2 /MT /W4 pid_monitor_tests.cpp /Fe:output\pid_monitor_tests.exe /Fo:output\pid_monitor_tests.obj
output\pid_monitor_tests.exe
pid.exe --ui-test "%CD%\output\sentinel-preview.png"
```

Os testes exercitam pontuação, normalização, correlação conservadora, processo pai, IPv4/IPv6, assinatura Microsoft, arquivo não assinado/inexistente e observação real de endpoints TCP/UDP locais. Não criam tarefas, serviços nem entradas de inicialização.

Os testes cobrem o scanner, o monitor e os controles da interface. O teste do monitor cria um processo sintético com listener de porta aleatória; os eventos de storage usados para testar correlação são sintéticos. O teste de interface verifica busca, abas, iniciar/parar e exportação, além de salvar uma imagem da janela.

Os testes de correlação com eventos sintéticos não validam a captura ETW elevada de ponta a ponta. Essa captura e a compatibilidade entre versões do Windows exigem validação adicional. Falhas de permissão do ETW ou de acesso ao Agendador são reportadas como cobertura parcial.

## Referências das APIs

- [Runtime estático /MT — Microsoft](https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library)
- [GetExtendedUdpTable — Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- [WinVerifyTrust — Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [Definições das APIs nativas de processo — phnt](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h)
- [StartTrace e permissões das sessões — Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
- [EnableTraceEx2 e filtros — Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
- [Metadados TDH — Microsoft](https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhgetproperty-to-consume-event-data)
