# PID Analyzer

Monitor de processos para Windows, com interface Sentinel em preto e roxo, console de eventos e análise de sinais suspeitos.

[Baixar pid.exe](https://github.com/Gustavoprogramas/PID-Analyzer/raw/refs/heads/main/pid.exe) · [Documentação técnica](docs/USAGE.md)

## Recursos

- Monitoramento contínuo com iniciar/parar, busca por nome ou PID e painel de evidências.
- Processos, linha de comando, processo pai, assinatura digital e DLLs carregadas.
- Conexões TCP/UDP IPv4 e IPv6 e portas TCP em escuta.
- Correlação de persistência em Run/RunOnce, Startup, tarefas e serviços.
- Eventos ETW de processos e acesso a armazenamento sensível de Discord e navegadores, quando disponíveis.
- Shield Mode opcional: isolamento de saída por executável no Firewall, com histórico e restauração das regras.
- Análise estática de indicadores combinados em scripts Python associados a processos.
- Histórico em memória e exportação de relatórios em UTF-8.

## Executar

Requer **Windows 10/11 de 64 bits**. Abra `pid.exe`: a interface inicia a coleta automaticamente. O botão **Parar monitor** interrompe a coleta e mantém o histórico da sessão. Fechar a janela encerra os sensores.

O executável inclui o runtime C++ e as artes da interface. Não é necessário instalar Node, Playwright ou Visual Studio para usá-lo.

Executar como administrador pode ampliar a cobertura de processos e ETW. Sem acesso ao ETW, o aplicativo registra a limitação e continua com consultas periódicas. Nenhum privilégio é solicitado automaticamente.

## Shield Mode

O padrão é **Detectar somente**. Para habilitar, execute como administrador, inicie o monitor e selecione **Configurações → Shield: isolar executável da rede**. Exige ETW de arquivos disponível, Firewall ativo em todos os perfis e permissão para regras locais.

O Shield reage a acessos inesperados a storage sensível por interpretadores ou por processos analisados com score ≥ 8. Um Python executando um projeto comum, sem esse acesso, não é isolado. Exceções de acesso esperado exigem nome exato, assinatura válida do fornecedor e storage correspondente ao aplicativo.

**O bloqueio afeta todas as instâncias do mesmo caminho de executável**, incluindo outros scripts usando aquele Python e conexões com a rede local. As regras permanecem após parar/fechar o app e reiniciar o Windows. **Configurações → Shield: restaurar todas as regras gerenciadas** desativa novos isolamentos e remove somente as regras do Shield. Regras anteriores são recuperadas ao abrir o app; o relatório inclui seus nomes e caminhos.

ETW observa a operação depois que ela ocorreu. Há latência de coleta, análise e aplicação da regra; leitura ou envio podem acontecer antes do isolamento. A criação de uma regra não comprova que uma exfiltração foi impedida. Esta versão não suspende processos.

### SentinelGuard — etapa kernel experimental

O diretório [`driver/`](driver/README.md) contém callbacks de `IRP_MJ_CREATE`/`IRP_MJ_READ`, política por caminhos e identidades de processos, canal administrativo, cliente de laboratório, projeto WDK e modelo INF. A política é enviada **antes** das operações; no modo enforce, uma operação coberta e não permitida recebe `STATUS_ACCESS_DENIED`.

**Não há `.sys` compilado, assinado ou validado neste pacote.** A opção de driver na interface apenas informa esse estado. O protótipo exige testes em VM e ainda não é proteção completa para credenciais; veja os limites e a matriz de testes em [driver/README.md](driver/README.md).

Para uma análise pontual no terminal:

```bat
pid.exe --scan
pid.exe --pid 1234 --browser-handles
pid.exe --all
pid.exe --help
```

O modo de terminal aguarda uma tecla ao terminar. A interface permanece aberta até ser fechada.

## Compilar

Abra o **Developer Command Prompt x64 do Visual Studio**, com as ferramentas C++ e o Windows SDK instalados:

```bat
git clone https://github.com/Gustavoprogramas/PID-Analyzer.git
cd PID-Analyzer
build.bat
```

Ou use o compilador diretamente:

```bat
cl /std:c++17 /EHsc /O2 /MT pid.cpp /link iphlpapi.lib ws2_32.lib wintrust.lib crypt32.lib /OUT:pid.exe
```

As bibliotecas adicionais estão declaradas no fonte com `#pragma comment(lib, ...)`. A interface está incorporada em `ui-assets/embedded_assets.h`, portanto não é necessário exportar as artes para compilar uma cópia do repositório.

## Editar a interface

Os arquivos HTML/CSS em `ui-assets` definem as artes dos botões e painéis. Para atualizá-las, com Node instalado:

```bat
cd ui-assets
npm ci
npx playwright install chromium
npm run export
cd ..
build.bat
```

O exportador grava os PNGs em `ui-assets/output` e atualiza o header incorporado ao programa. Os exemplos de dados no HTML são apenas uma demonstração visual.

## Testes

No Developer Command Prompt x64:

```bat
test.bat
```

O script compila e executa os testes do scanner, monitor, Shield e validação do protocolo do driver. Os testes usam processos/eventos sintéticos e um backend de Firewall simulado; não alteram o Firewall real nem leem credenciais. Para verificar a interface:

```bat
build.bat
if not exist output mkdir output
pid.exe --ui-test "%CD%\output\sentinel-preview.png"
```

Os arquivos de teste ficam em `output`, fora do versionamento. A captura ETW elevada não foi validada de ponta a ponta; os testes sintéticos verificam a correlação e o tratamento de cobertura parcial.

## Limitações e privacidade

O score é heurístico e **não confirma uma infecção**. O isolamento pode interromper aplicativos legítimos; revise as evidências e restaure as regras quando necessário. O aplicativo não substitui um antivírus.

A rede é consultada em intervalos de 0,5 a 2 segundos, podendo perder conexões mais rápidas. Não há inspeção de HTTPS. ETW depende de permissões, provedores e buffers disponíveis. Código ofuscado, scripts encerrados rapidamente e processos protegidos podem não ser analisados por completo.

O monitor observa nomes e metadados de arquivos sensíveis; não lê tokens, cookies ou senhas. A análise de Python lê somente o arquivo-fonte local associado, sujeito aos limites descritos na [documentação](docs/USAGE.md). Relatórios podem conter caminhos e linhas de comando: revise-os antes de compartilhar.
