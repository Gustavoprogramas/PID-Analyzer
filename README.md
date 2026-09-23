# PID Analyzer

Monitor de processos para Windows, com interface Sentinel em preto e roxo, console de eventos e análise de sinais suspeitos.

[Baixar pid.exe](https://github.com/Gustavoprogramas/PID-Analyzer/raw/refs/heads/main/pid.exe) · [Documentação técnica](docs/USAGE.md)

## Recursos

- Monitoramento contínuo com iniciar/parar, busca por nome ou PID e painel de evidências.
- Processos, linha de comando, processo pai, assinatura digital e DLLs carregadas.
- Conexões TCP/UDP IPv4 e IPv6 e portas TCP em escuta.
- Correlação de persistência em Run/RunOnce, Startup, tarefas e serviços.
- Eventos ETW de processos e acesso a armazenamento sensível de Discord e navegadores, quando disponíveis.
- Análise estática de indicadores combinados em scripts Python associados a processos.
- Histórico em memória e exportação de relatórios em UTF-8.

## Executar

Requer **Windows 10/11 de 64 bits**. Abra `pid.exe`: a interface inicia a coleta automaticamente. O botão **Parar monitor** interrompe a coleta e mantém o histórico da sessão. Fechar a janela encerra os sensores.

O executável inclui o runtime C++ e as artes da interface. Não é necessário instalar Node, Playwright ou Visual Studio para usá-lo.

Executar como administrador pode ampliar a cobertura de processos e ETW. Sem acesso ao ETW, o aplicativo registra a limitação e continua com consultas periódicas. Nenhum privilégio é solicitado automaticamente.

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

O script compila e executa os testes do scanner e do monitor. Os testes usam processos e eventos sintéticos; não criam persistência nem leem credenciais. Para verificar a interface:

```bat
build.bat
if not exist output mkdir output
pid.exe --ui-test "%CD%\output\sentinel-preview.png"
```

Os arquivos de teste ficam em `output`, fora do versionamento. A captura ETW elevada não foi validada de ponta a ponta; os testes sintéticos verificam a correlação e o tratamento de cobertura parcial.

## Limitações e privacidade

O score é heurístico e **não confirma uma infecção**. O aplicativo não bloqueia processos nem substitui um antivírus.

A rede é consultada em intervalos de 0,5 a 2 segundos, podendo perder conexões mais rápidas. Não há inspeção de HTTPS. ETW depende de permissões, provedores e buffers disponíveis. Código ofuscado, scripts encerrados rapidamente e processos protegidos podem não ser analisados por completo.

O monitor observa nomes e metadados de arquivos sensíveis; não lê tokens, cookies ou senhas. A análise de Python lê somente o arquivo-fonte local associado, sujeito aos limites descritos na [documentação](docs/USAGE.md). Relatórios podem conter caminhos e linhas de comando: revise-os antes de compartilhar.
