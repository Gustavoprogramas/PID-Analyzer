# SentinelGuard — base experimental do minifiltro

Esta é a segunda etapa do Shield: código de um minifiltro x64, **ainda sem compilação WDK, assinatura ou validação em kernel**. Não acompanha um `.sys` nem é carregado pelo `pid.exe`. A primeira etapa, o isolamento de rede, funciona independentemente deste diretório.

## Arquitetura e escopo

```text
pid.exe                         guardctl.exe (laboratório; futuro serviço de política)
  ETW + correlação                canal administrativo \SentinelGuardPort
  Shield de rede                             |
  Windows Firewall                      SentinelGuard.sys
                                        IRP_MJ_CREATE / IRP_MJ_READ
                                           |
                                  caminho protegido + processo não permitido
                                           |
                                  AUDIT: contabiliza, permite
                                  ENFORCE: STATUS_ACCESS_DENIED
```

`SentinelGuard.c` registra callbacks de pré-operação. O driver só conecta a volumes NTFS locais. A política contém até oito arquivos/diretórios normalizados e 64 identidades permitidas, cada uma com máscara dos caminhos autorizados. Diretórios têm limite de componente; arquivos incluem seus streams alternativos. A identidade usa PID + criação na entrada da política e uma referência ao objeto de processo no kernel, evitando herdar permissão quando um PID é reutilizado.

O canal é restrito por `FltBuildDefaultSecurityDescriptor` a administradores/SYSTEM e aceita um cliente. Cada mensagem tem tamanho fixo, versão, limites e validação antes de uso. A política é preparada fora do lock e substituída como uma unidade. As callbacks consultam somente a política local: não esperam uma resposta do app durante o I/O. Nenhum conteúdo de arquivo ou credencial é coletado.

A política precisa estar ativa **antes** da tentativa de acesso. Enviar uma decisão após um evento ETW não protege retroativamente a primeira leitura. O protótipo não permite processos por nome: o cliente de laboratório autoriza instâncias explícitas. A identificação automática de navegador/Discord, validação de assinatura e atualização da política para novas instâncias ainda precisam de um serviço confiável. O cliente não verifica publicadores; `--allow-pid` é uma decisão manual de laboratório, não uma validação de confiança.

O driver inicia sem política (OFF). O cliente usa AUDIT por padrão; `--enforce` exige confirmação no terminal. Ao desconectar, a política é removida e o driver volta a OFF. Esse comportamento facilita recuperação de falhas no laboratório e **não oferece proteção persistente contra encerramento do cliente**. Contadores distinguem operações que seriam negadas, negadas, falhas de resolução de nome e caminhos ignorados.

## Compilação

O `pid.exe` continua compilando com o comando C++17 `/MT` do projeto. O kernel usa outro projeto: `SentinelGuard.vcxproj`, toolset `WindowsKernelModeDriver10.0`, `FltMgr.lib`, Windows 10 2004 ou posterior (usa `ExAllocatePool2`). O template INF usa o layout de instâncias do Windows 11 24H2; versões anteriores precisam de um INF correspondente, além de validação própria.

Instale um par SDK/WDK compatível com seu Visual Studio conforme a [documentação oficial do WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk). O Developer Command Prompt comum com apenas o Windows SDK compila `guardctl`, mas não o minifiltro.

No Developer Command Prompt x64 com WDK:

```bat
cd driver
build.bat
```

Saídas previstas: `output/guardctl.exe` e `output/driver/Release/SentinelGuard.sys`, na raiz do projeto. O projeto desabilita assinatura automática e geração de catálogo; compilar não instala nem carrega nada. `SentinelGuard.inf.in` é um modelo deliberadamente incompleto: substitua `@ASSIGNED_ALTITUDE@` pela altitude atribuída, confirme classe/grupo adequados e valide o INF com as ferramentas do WDK. Não distribua usando uma altitude copiada de outro produto. Consulte [solicitação de altitude](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request) e [INF de minifiltros](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver).

Antes de instalar em uma VM descartável: compile com análise de código do WDK, valide o INF, gere o catálogo e use o processo de assinatura de teste documentado pela Microsoft para o ambiente de laboratório. Distribuição pública exige o processo de assinatura/compatibilidade aplicável a drivers Windows. Consulte [assinatura de drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing). Não altere Secure Boot, integridade de memória ou políticas de assinatura no PC de uso diário para carregar este protótipo.

## Exercício controlado em VM

Depois da compilação, revisão, assinatura e instalação de laboratório, crie `C:\SentinelLab\fixture.txt` com texto fictício. Não use perfis reais de Discord/navegadores no primeiro teste.

```bat
output\guardctl.exe --directory C:\SentinelLab
```

Com AUDIT, abrir o arquivo num processo separado deve funcionar e incrementar `would-deny`. Encerre com Q. Em seguida:

```bat
output\guardctl.exe --directory C:\SentinelLab --enforce
```

Confirme no terminal e tente abrir novamente: uma operação coberta deve falhar com acesso negado. Q remove a política. `--file` protege um arquivo exato. `--allow-pid 1234` autoriza a instância atual daquele PID para todos os caminhos informados no comando; novas instâncias exigem nova política. O protocolo suporta máscaras diferentes por caminho para o futuro serviço.

## Validação necessária e limites conhecidos

| Caso na VM | Resultado a verificar |
| --- | --- |
| OFF / AUDIT | Leitura funciona; AUDIT conta acessos não permitidos |
| ENFORCE antes de abrir | `CreateFile`/`ReadFile` cobertos retornam acesso negado, zero bytes |
| Processo explicitamente permitido | Lê somente os caminhos da máscara |
| Nome parecido (`SentinelLabFake`) | Não corresponde à pasta protegida |
| Novo processo reutilizando PID | Não herda permissão da instância encerrada |
| Mensagem truncada/versão/tamanho inválido | Rejeitada, política anterior preservada |
| Cliente sem elevação / segundo cliente | Canal recusado |
| Desconexão/unload concorrente com I/O | Política removida, sem travamento/leak |
| Estresse e pouca memória | Sem corrupção; revisar contadores e Driver Verifier |
| Firewall user-mode | Em VM separada, alvo inofensivo, validar TCP/UDP IPv4/IPv6 e restauração |

O código ainda deixa passar e contabiliza I/O de kernel, paging, IRQL alto, requestor desconhecido, aberturas por ID e falhas de normalização do nome. **Não é uma fronteira de segurança completa**. Mapas de memória/handles já abertos, handles duplicados, aliases/hard links, reparse points, renomeação, acesso a volumes brutos, injeção em um processo permitido e administradores precisam de projeto e testes adicionais. A referência do processo protege a identidade, não a integridade de seu código.

Antes de produção faltam: compilação e revisão com WDK; testes reais com Driver Verifier/Filter Verifier; política de handles/streams e falhas de nome; mapeamento/aliases; serviço confiável para identidade e assinatura por aplicação; provisionamento e recuperação; política persistente de falhas; telemetria para a GUI; assinatura e compatibilidade/HVCI. Até lá, a GUI mantém a opção kernel informativa.

## Referências de implementação

- [Completar I/O na callback de pré-operação](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/completing-an-i-o-operation-in-a-preoperation-callback-routine).
- [Comunicação user-mode/kernel-mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode).
- [ACL padrão do canal](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltbuilddefaultsecuritydescriptor).
- [Restrições de consultas de nomes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation).
