# LabGuard - Manual atual de instalação e uso

TI 2.4.6 · Cliente Automático 2.5.1 · Central 1.2.1 · Desinstalador 1.0.1

Revisão: 17 de novembro de 2026.

## Escolha o arquivo certo

Este manual reúne o filtro de rede da TI, o Cliente Automático e a Central opcional. Cada programa tem uma função. Comece por uma estação e confirme o resultado na conta padrão do aluno antes de distribuir.

| Arquivo | Onde executar | Função |
|---|---|---|
| LabGuard-TI-Setup.exe | PC da TI | Filtro DNS completo, bancos, mapas, relatórios e acesso à Central. |
| LabGuard-Jogos.exe | Cada PC dos alunos | Proteção local automática: jogos reconhecidos e políticas dos navegadores. |
| LabGuardTecnico.exe | PC administrador | Central opcional: vínculos, avisos, políticas e Sites rápidos. Não é o filtro DNS. |
| LabGuard-TI-Portable.zip | PC da TI | Filtro em pasta: extraia tudo e abra LabGuard.exe. |
| LabGuard-Desinstalador.exe | PC a retirar do sistema | Remove componentes identificados e informa pendências. Não serve para atualizar. |

Downloads oficiais: https://perabru.github.io/LabGuard/downloads/ . O ZIP das estações contém Cliente + Central + guia; não inclui o filtro TI completo. Código-fonte não é instalador.

> Requisitos do cliente: Windows 10/11 x64, .NET Framework 4.8 e Windows PowerShell 5.1. A instalação solicita administrador; o aluno deve usar uma conta padrão. Linux e servidores têm pacotes próprios da edição de rede.

O filtro e a Central podem funcionar no mesmo PC. Não é necessário instalar uma nova Central apenas para ativar o cliente local. Publicar ou baixar um arquivo não atualiza remotamente as estações.

## Instale ou atualize o filtro da TI

1. Entre na mesma conta Windows usada para configurar a edição anterior. Copie %USERPROFILE%\.labguard para um local seguro. Não use o desinstalador para atualizar.
2. Feche o filtro durante uma janela de manutenção e execute LabGuard-TI-Setup.exe. Fechar o filtro interrompe o DNS que ele fornece até a reabertura.
3. Abra o atalho LabGuard. Confira o banco e as preferências anteriores. A opção salva de iniciar o filtro ao abrir o aplicativo continua sendo respeitada.
4. Na primeira instalação, use Configurar e escolha a conexão real do laboratório. Reserve o IP deste PC, autorize UDP/TCP 53 para a rede atendida e configure as estações ou o DHCP para usar esse DNS.
5. Confira Filtro ligado neste PC. No aluno, teste um domínio bloqueado e um site permitido. Um teste local na TI não confirma a configuração do DNS de todos os alunos.

A aba Clientes e avisos acrescenta Abrir Central existente, Instalar / reparar Central, Conferir conexão e Bloquear lista rápida no DNS. A lista rápida é acrescentada sem apagar regras anteriores; os bancos DNS e Central continuam separados.

> Mantenha o PC da TI e o filtro ligados enquanto forem o DNS das estações. Restaure o DNS anterior nos alunos ou no DHCP antes de parar definitivamente. Falha na Central não deve desligar o filtro.

Vivo + switch Mercusys simples: o DNS pode funcionar sem MikroTik e sem trocar cabos, desde que as estações usem o filtro. Um switch não gerenciável não oferece bloqueio por IP/MAC. DNS local não inspeciona conteúdo HTTPS nem garante bloquear VPN, proxy, DoH ou DNS alternativo.

## Ative o Cliente Automático em cada aluno

1. Salve LabGuard-Jogos.exe em Downloads. Se baixou o ZIP, extraia antes de executar.
2. Abra o EXE, autorize o UAC e confirme a ativação. A proteção local começa sem IP, arquivo de vínculo ou Python instalado.
3. Aguarde Proteção local confirmada. Se aparecerem pendências, leia os detalhes e os registros antes de sair. Não trate confirmação parcial como sucesso completo.
4. Feche a janela. As tarefas permanecem configuradas para o início do Windows; o painel não precisa ficar aberto. Um ícone identificado permanece na bandeja.
5. Reabra Chrome, Edge ou Firefox na conta padrão do aluno. Teste bloqueio e navegação permitida e confira o monitor em Opções avançadas.

| Rotina | O que faz |
|---|---|
| Monitor | Fecha processos de jogos reconhecidos; intervalo nominal de 2 segundos. |
| Limpeza | Primeira solicitação na ativação e repetição a cada 5 minutos, sem sobrepor operações. |
| Catálogo | 839 domínios de jogos, apostas, adultos e IA; Sites rápidos e YouTube são controlados separadamente. |
| Reconhecimento | Launchers e instalações conhecidas de Steam, Roblox, Minecraft, Epic, emuladores e jogos Windows/Xbox; não há reconhecimento universal. |

> A remoção é permanente e pode apagar jogos, saves e mundos das pastas abrangidas. Faça backup. Roblox Studio, Minecraft Education e ferramentas educacionais reconhecidas são preservados. ISO e arquivo desconhecido não são apagados somente por extensão ou aparência.

Registros em %ProgramData%\LabGuardJogos2: install-status.json, guard-status.json, guard.log, remocoes.log e fullcatalog-status.json. O relatório do catálogo informa a confirmação por navegador. Capturas ficam desligadas; executáveis suspeitos são encaminhados ao Defender.

## Conecte à Central para avisos e controle

1. No PC administrador, abra a Central pelo LabGuard TI ou execute LabGuardTecnico.exe. Se já existir, abra a instalação atual; use Instalar / reparar para atualizar.
2. Na primeira configuração, informe IP real/reservado, rede autorizada e senha. Abra o painel local http://127.0.0.1:8787/ e entre. Não exponha essa interface na internet.
3. Em Computadores → Vincular computador, gere um JSON individual. O vínculo vale por uma hora e para uma estação.
4. No cliente já instalado, abra a administração pelo ícone LabGuard e escolha Conectar ao painel (opcional). Importe o JSON. Não é necessário reinstalar a proteção.
5. Confira último contato e revisões em Computadores. Em Avisos e proteção, acompanhe jogos encerrados, falhas e perda de contato. Para notificações do navegador, mantenha a sessão autenticada aberta e autorize as notificações.

O canal das estações usa HTTPS/TCP 8788, certificado da Central e credencial individual. Autorize somente a rede do laboratório. O cliente consulta em torno de 15 segundos; sem contato, mantém a última política local e não recebe novas regras.

> Local HTTP 127.0.0.1:8787 é o painel do administrador. HTTPS 8788 é o canal dos clientes. São destinos diferentes. Confira IP, rede autorizada, firewall e relógios quando houver falha de vínculo ou comunicação.

A Central recebe estados e eventos de proteção. Este canal não transmite capturas de tela, arquivos ou histórico de navegação. Vincular estações não concede automaticamente controle a equipamentos sem o cliente correspondente.

## Bloqueie, libere e confira os sites

| Site rápido | Domínio |
|---|---|
| Termo | term.ooo |
| Friv | friv.com e friv.com.br |
| Poki (Poke) | poki.com |
| Chess.com | chess.com |
| YouTube | youtube.com e domínios auxiliares do catálogo |
| Joguester | Endereço pendente: use Editar endereço com o domínio real. |

1. Na Central, abra Sites rápidos, escolha Bloquear ou Liberar e confira a revisão aplicada pela estação. Bloquear tudo aplica a lista rápida cadastrada e o YouTube; não corta toda a internet nem ativa novas remoções.
2. No filtro TI, use Sites para Bloquear ou Liberar. Liberar mantém o domínio cadastrado. Um domínio pai, perfil de IA ou filtro de saída ainda pode restringir o endereço.
3. Se usa cliente e DNS simultaneamente, libere nas duas camadas. Se a estação está sem contato com a Central, aguarde a sincronização e confira a revisão.
4. Reabra o navegador após alterar as regras e teste a conta do aluno. O LabGuard não fecha o navegador inteiro; uma aba já carregada pode continuar mostrando conteúdo.

> O catálogo completo também bloqueia serviços de IA usados em aula. Os controles de Sites rápidos não são um editor de todos os 839 domínios. Para exceções fora da lista rápida, revise a política institucional do navegador ou o pacote. Regras externas são preservadas.

Teste mínimo: um site da lista deve bloquear; um site da aula deve abrir; a Central deve mostrar a revisão confirmada quando vinculada. A gravação no Registro e a confirmação de DNS não comprovam bloqueio em todo aplicativo, proxy ou navegador não abrangido.

## Resolva as falhas mais comuns

| Sintoma | Conferência e próximo passo |
|---|---|
| Só abriu a Central | Abra o atalho LabGuard do Setup TI. LabGuardTecnico.exe sozinho não é o filtro. |
| Sumiu a configuração antiga | Confira a conta Windows e o backup de .labguard. Não apague nem recrie o banco por tentativa. |
| Bloqueado mesmo após Liberar | Confira DNS + Sites rápidos + catálogo local + regras externas. Aguarde sincronização e reabra o navegador. |
| TI testa DNS; aluno não bloqueia | Confira DNS efetivo do adaptador, IPv6/DoH, porta53 e acesso ao IP do filtro. Teste direto e DNS padrão na estação. |
| Cliente sem contato | Confira HTTPS8788, IP/rede autorizada, firewall e relógios; a proteção local continua. |
| Limpeza com pendências | Leia remocoes.log, feche o jogo pelo fluxo normal e confira privilégios e instalação reconhecida. Não apague pastas desconhecidas. |
| Instalador sem confirmação | Leia install-status.json e detalhes da janela. Não desative antivírus/UAC. Repare a instalação e confira o monitor. |

A GUI do filtro oferece Não identificou? Ver passo a passo, diagnóstico de rede e teste de estações. Administrar remotamente um Windows sem cliente exige WinRM HTTPS ou o canal institucional já autorizado; estar na mesma rede não prepara esse acesso.

> Teste com arquivos de jogo fictícios, nunca com documentos pessoais. Monitor sem Central, bloqueio no navegador e início após login são verificações separadas. Testes automatizados e Windows descartável não substituem uma estação real da escola.

Para suporte, informe versão, componente, mensagem, horário e etapa que falhou. Não envie senhas, JSON de vínculo válido, tokens ou dados de alunos.

## Atualize, desinstale e consulte os guias

Cliente: execute o novo EXE em Downloads e confirme. Ele pausa novas limpezas e aguarda a operação anterior; vínculos e política da Central são preservados. Se a proteção estava pausada pelo administrador, retome no painel. Se não concluir no prazo, leia a pendência; não force o encerramento do Windows Installer.

TI: use a mesma conta, mantenha o backup de .labguard e instale sobre a edição existente. A edição TI é atualizada manualmente com o Setup do canal TI; Verificar atualizações abre suas versões próprias. A atualização automática da edição de rede comum fica desabilitada nesta edição para preservar a extensão TI. Central: use Instalar / reparar. Linux, portátil e servidores usam os pacotes correspondentes.

1. Antes de remover o PC que serve DNS, restaure o DNS dos alunos ou do DHCP. Encerrar o servidor não altera automaticamente as outras máquinas.
2. Salve LabGuard-Desinstalador.exe fora das pastas instaladas, abra e autorize o administrador. Use Conferir instalações e depois Desinstalar tudo do LabGuard.
3. Confira o relatório e as pendências, reabra navegadores e reinicie se solicitado. Execute em cada PC que deve deixar de usar o produto.
4. O desinstalador remove componentes e regras próprias identificadas; preserva alterações externas e o estado necessário para corrigir restaurações pendentes. Não recupera jogos ou saves já apagados.

Relatório de remoção: %LocalAppData%\LabGuard-Desinstalador-Relatorios. DNS e IPv6 só são restaurados quando há registro válido e estado compatível. Instalações personalizadas ou mudanças externas podem exigir revisão da TI.

> Guias oficiais: downloads e instruções atuais em https://perabru.github.io/LabGuard/downloads/ ; filtro DNS detalhado em https://perabru.github.io/LabGuard/tecnico/ ; manual de rede em https://perabru.github.io/LabGuard/manual2/ . Código e relatórios de validação em https://github.com/perabru/LabGuard .

Revisão do manual: 17 de novembro de 2026. Consulte a página de versões para o resultado de cada compilação e os arquivos SHA256SUMS. Um hash confere integridade; os executáveis não têm certificado comercial de assinatura.
