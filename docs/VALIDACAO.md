# Validação da versão 2.4.3

Em **Administrar estações → Verificar porta**, o PC da TI testa a porta TCP 5986 do endereço selecionado. Os ensaios da interface cobriram porta acessível e recusada, troca de estação, limpeza da senha e manutenção das três indicações de DNS sem confirmação após falha no login. Em loopback, o cliente WinRM fez conexões HTTPS reais para conferir recusa TCP, cadeia de confiança, nome do certificado e respostas HTTP 401 e 403. O destino utilizado foi um servidor de teste local. O acesso à estação da escola depende da configuração dela e precisa ser verificado a partir do laboratório.

Os 510 testes de regressão passaram no ambiente local. Windows e Linux concluíram seus ensaios de compilação e instalação. No Windows, o instalador abriu o painel após a instalação e o ensaio de atualização passou da versão 2.4.2 para a 2.4.3. [Execução dos testes e compilação](https://github.com/perabru/LabGuard/actions/runs/42678014908)

O instalador verificado tem 25.567.859 bytes. SHA-256 `9f93c66edb8ddc917ebb54cfdb98fde2c60039f47a8037bc4effa39d6ff217c2`. [Versão 2.4.3 e downloads](https://github.com/perabru/LabGuard/releases/tag/v2.4.3)

## Evidência anterior da versão 2.4.2

Na [versão 2.4.2](https://github.com/perabru/LabGuard/releases/tag/v2.4.2), **Proteger laboratório** aplica oito domínios de jogos e conteúdo adulto e confere as regras pela leitura do filtro ativo. O ensaio isolado usou DNS real em loopback para conferir respostas NXDOMAIN em A e AAAA, incluiu subdomínios, preservou regras existentes e verificou comportamento em falhas parciais. A escolha do DNS de saída familiar foi testada na configuração e na persistência. A classificação externa dos sites depende do provedor escolhido.

A [compilação](https://github.com/perabru/LabGuard/actions/runs/42658173373) passou no commit `7350d1df195322125b6c65c87493a2b441ae9c5b`, com **491 testes no Linux** e **443 aprovados no Windows**, com quatro verificações específicas de POSIX/Linux ignoradas nessa plataforma, instaladores e serviços. A atualização Windows de 2.4.1 para 2.4.2 foi verificada por instalação e encerramento normais dos binários, recibo de atualização, versão PE/HKCU e autoteste.

[Windows PowerShell 5.1](https://github.com/perabru/LabGuard/actions/runs/42658173373/job/129302371378) executou consultas TXT e A pelo resolvedor nativo, em loopback. O ensaio comparou resposta direta com NXDOMAIN pelo caminho padrão, conferiu o bloqueio de um domínio e isolou o adaptador, as alterações de DNS e o backup em uma simulação. Verificou aplicação, restauração, falha parcial e mudança concorrente. O preparo WinRM foi validado por sintaxe e simulação do certificado e das configurações no Windows. WinRM em rede, DCOM/Kerberos em domínio, GPO/MDM e equipamentos físicos da escola não foram homologados.

O painel web utiliza o navegador da TI em loopback. A autorização por token, origem da requisição, expiração de prévia e troca de fonte passaram por testes HTTP. O [site e o manual](https://github.com/perabru/LabGuard/actions/runs/42655380066) foram publicados. O manual contém 20 páginas em 16 capítulos.

O instalador Windows foi conferido por integridade do artefato, SHA-256 interno, CRC do ZIP, formato PE e autotestes. Tamanho de 25,563,391 bytes. SHA-256 `031286979313e1677d3113d94013fd89b4c94e09317d8512e26f246aa862a24c`.

## Evidência anterior da versão 2.4.1

Publicada em 9 de novembro de 2026. O [fluxo completo](https://github.com/perabru/LabGuard/actions/runs/42645163153) passou no commit `71d1653a8a53a075c1b19f1a7f59a740db462cc1`. A revisão preserva o início com três ações e corrige a abertura do assistente durante uma leitura em segundo plano: controles e interfaces acompanham o resultado sem exigir reabrir a janela. Campos preenchidos pelo usuário são preservados.

Passaram **442 testes no Linux** e **398 no Windows**. O fluxo Tk exercitou a transição ocupado/pronto, sugestão de interface real após a leitura, preservação de edição manual, abertura em janelas menores, diagnóstico UDP/TCP, aplicação de Roblox no loopback, confirmação antes de parar e recuperação da política no início opcional. Nenhuma alteração de LAN ou sistema foi necessária nesses testes.

Os pacotes nativos passaram por instalação, abertura gráfica, DNS real UDP/TCP, serviços SCM/systemd e atualização Windows isolada **2.4 → 2.4.1**, com espera pelo processo, versão PE/HKCU, autoteste e limpeza da instalação de teste. O [site e o manual](https://github.com/perabru/LabGuard/actions/runs/42645163072) também foram publicados. O manual mantém 18 páginas e 16 capítulos; a imagem do painel usa um endereço versionado para evitar a imagem anterior em cache.

O [release 2.4.1](https://github.com/perabru/LabGuard/releases/tag/v2.4.1) contém seis pacotes, manifesto, somas e relatórios. O EXE passou por hash do artefato, CRC, SHA-256 interno, estrutura PE e autotestes. Tamanho: **25.441.360 bytes**. SHA-256: `46def7cd1d133bfad66cbbb2a953dbbb13bc78234ee164282d179c1d1cf419fe`.

Nenhum equipamento da escola foi acessado ou homologado. O filtro depende do DNS configurado nos clientes e do PC acessível, ligado e autorizado em UDP/TCP 53. O teste local não confirma as estações; teste cada uma e também um domínio permitido. VPN, DoH, DNS IPv6 alternativo e cache exigem controles complementares. Os limites das integrações e do filtro local continuam os descritos abaixo.

## Evidência anterior: 2.4.0

Publicada em 9 de novembro de 2026. O [fluxo Windows/Linux](https://github.com/perabru/LabGuard/actions/runs/42643188350) passou no commit `49c39b3d5eacacb5b4864ff319e94fcd3761a705`. A [versão 2.4.0](https://github.com/perabru/LabGuard/releases/tag/v2.4.0) contém os seis pacotes desktop/servidor, manifesto de atualização, somas e relatórios dos executáveis.

Passaram **441 testes no Linux** e **397 testes compatíveis com Windows**. O novo diagnóstico do assistente foi exercitado com consultas reais UDP/TCP somente ao listener local do próprio transporte, incluindo recusa de código incorreto, timeout, conexão encerrada e fontes sem DNS. O resultado nunca confirma cobertura das estações. A origem do teste não é um parâmetro arbitrário exposto pela API.

A GUI Tk foi conferida em 1240×820/1000×700, com três cards e opções avançadas recolhidas. O assistente passou em 880×700/820×650, incluindo campos manuais quando não há uma interface real sugerida, autorização desmarcada, cópia do IP em uso e teste local. Janelas encerradas ou trocas de fonte ignoram resultados atrasados. O fluxo ativou DNS em loopback/porta alta, aplicou `roblox.com`, recebeu NXDOMAIN real, preservou o serviço ao recusar o encerramento e recuperou regras e início opcional ao reabrir. Não alterou LAN, DHCP, DNS do sistema ou firewall.

Instalação, janela nativa, DNS UDP/TCP dos executáveis e serviços SCM/systemd passaram nas plataformas correspondentes. A atualização Windows isolada **2.3 → 2.4** usou os instaladores reais e o helper real, com substituição apenas do transporte de release por respostas locais de teste. Foram conferidos hash fixo do pacote anterior, espera explícita pelo processo, versão PE/HKCU, autoteste após atualização e remoção da instalação isolada. Preferências privadas e cofre temporário também passaram.

O [Pages](https://github.com/perabru/LabGuard/actions/runs/42643188445) publicou site e manual. O manual mantém **18 páginas e 16 capítulos**, com os caminhos simplificados e o teste local explicados; as páginas alteradas foram renderizadas e revisadas. A apresentação foi conferida no navegador, com a imagem real da interface em Demonstração.

O instalador foi conferido por hash do artefato, CRC do ZIP, SHA-256 interno, estrutura PE e relatórios 2.4.0. Tamanho: **25.436.867 bytes**. SHA-256: `502cde192861f9d659180c7bd3390800ec3e6223d2a8a9c8fda44bc4063ed289`.

Nenhum equipamento da escola foi acessado ou homologado. Vivo e switch simples exigem que as estações usem o DNS do LabGuard, com IP estável, conectividade e UDP/TCP 53 permitido. O filtro local não oferece corte de internet por IP/MAC, controle do switch simples ou remoção de programas. VPN, DoH, DNS IPv6 alternativo e cache exigem controles complementares; consultas não comprovam visitas. Antes de parar o filtro, restaure o DNS anterior nos clientes.

## Evidência anterior: 2.3.0

Publicada em 9 de novembro de 2026. O [fluxo completo](https://github.com/perabru/LabGuard/actions/runs/42639341179) passou para o commit `7f9492f6527518e82a13cf09b79f9c23a318fe1e`. A [versão 2.3.0](https://github.com/perabru/LabGuard/releases/tag/v2.3.0) contém seis pacotes, manifesto, autotestes DNS e atualização verificada.

Passaram **433 testes** localmente e no Linux CI e **389 testes compatíveis com Windows**. O filtro foi testado com DNS real no loopback UDP/TCP, recusa de clientes fora do segmento, subdomínios, AAAA/HTTPS/TXT, aliases CNAME, respostas inválidas de saída, truncamento UDP com repetição TCP, limites de histórico/taxa e conflito de porta. O teste TXT confirma a identidade do resolvedor de teste, sem alegar cobertura de todas as máquinas.

O executável instalado em cada plataforma abriu listeners somente em loopback e confirmou bloqueios UDP/TCP, código de diagnóstico e encerramento. Os arquivos `windows-dns-self-test.json` e `linux-dns-self-test.json` acompanham a versão. O backend opcional de servidor foi testado em fonte; a abertura gráfica, os instaladores e serviços SCM/systemd também passaram nos sistemas nativos. O CI de serviços usa demonstração, não implanta o DNS na rede escolar.

O Windows validou DACL privada, cofre temporário com limpeza, PowerShell 5.1 e uma atualização real isolada **2.2 → 2.3**. Os instaladores e helper foram reais, com transporte de release substituído apenas por respostas locais de teste; foram confirmados espera explícita pelo encerramento, versão PE/HKCU, autoteste e remoção da instalação de teste. Não houve elevação, encerramento forçado de outros programas ou mudança de rede para liberar o teste.

O assistente Tk foi conferido em 930×770/820×650 e o início em 1240×820/1000×700, com opções desligadas por padrão e sem preencher IPs de demonstração. O smoke de interface ativou DNS somente em loopback/porta alta de teste, aplicou um domínio, recebeu NXDOMAIN real, respeitou a recusa de parar o serviço e retomou a política por opção salva. O começo automático é exclusivo do perfil DNS explicitamente salvo; não restaura autorização de alteração do RouterOS.

O [Pages](https://github.com/perabru/LabGuard/actions/runs/42639341070) publicou site e manual 2.3. O manual tem **18 páginas e 16 capítulos**; as páginas do cenário Vivo/Mercusys foram renderizadas e revisadas. Links, âncoras, ausência de imagens quebradas e apresentação foram conferidos no navegador.

O instalador foi verificado pelo hash do artefato, CRC do ZIP, SHA-256 interno, estrutura PE e autotestes. SHA-256 do EXE: `cba4c69eb2cb0dbe1d76c790bdfd2303b542b73404fd98f350226bea09169165`.

Nenhum equipamento do colégio foi acessado ou homologado. O filtro precisa de clientes configurados para usar o DNS do LabGuard, IP estável, permissão para UDP/TCP 53 e conectividade ao DNS de saída. Não muda o Vivo, o switch, o DNS das estações ou o firewall sozinho. Não corta internet por IP/MAC nem garante eliminar VPN, DoH, DNS alternativo, IPv6 ou cache. Consultas recebidas não são visitas nem identificação de pessoas. Antes de parar, restaure o DNS anterior nos clientes; o aplicativo avisa, mas não consegue manter o DNS ativo com o computador desligado.

## Evidência anterior: 2.2.0

Publicada em 7 de novembro de 2026. O [fluxo completo Windows/Linux](https://github.com/perabru/LabGuard/actions/runs/42387750673) passou para o commit `fe6ed9a221ea475ac00c6699e8a50060f369907b`. A [versão 2.2.0](https://github.com/perabru/LabGuard/releases/tag/v2.2.0) inclui seis pacotes desktop/servidor, manifesto de atualização, relatório de atualização real, autotestes e somas SHA-256.

Passaram **411 testes** localmente e no Linux CI e **367 testes compatíveis com Windows**. O CI Windows validou permissões privadas de diretório/arquivo e uma gravação, recuperação e exclusão real no cofre, usando somente credencial temporária isolada. Coletores e helper passaram no parser PowerShell 5.1; a coleta alternativa CIM/ARP real permaneceu somente para consulta.

A atualização nativa isolada **2.1 → 2.2** passou: instalador anterior com hash fixo, pacotes reais, leitura HTTPS substituída por respostas locais de teste, preparo e verificação reais, recibo explícito de espera, fechamento por `WM_CLOSE`, helper PowerShell real e instalação no mesmo diretório com espaços. Foram confirmadas versão PE numérica, registro HKCU e autoteste do aplicativo atualizado. A instalação de teste foi removida ao final. O teste não alterou o scheduler de produção, que exige o próprio PID e a imagem instalada; não prova uma transferência HTTPS real em cada rede escolar.

Instalação, abertura da janela e serviços SCM/systemd passaram nas plataformas nativas. A primeira migração exige instalar a 2.2 uma vez. A aplicação automática fica restrita ao Windows instalado por usuário e ao encerramento voluntário, sem elevar privilégios, fechar outras instâncias ou reiniciar. Linux, portátil e servidores mantêm a atualização sob administração da TI.

O [Pages](https://github.com/perabru/LabGuard/actions/runs/42386745085) publicou site e manual 2.2. O manual tem **16 páginas e 15 capítulos**, com renderização/revisão visual, links e âncoras conferidos. A GUI foi verificada em 1240×820 e 1000×700; o início em observação e a restauração opcional em consulta passaram no smoke Tk sem mutações de rede.

O instalador anexado foi conferido por hash do artefato, CRC do ZIP, SHA-256 interno, estrutura PE e autotestes. SHA-256 do EXE: `c24b30741f6c4baf379e3ca640985fd05f86009e03971977deeb417ba3d6f8ec`. O mesmo hash foi publicado no asset da versão. HTTPS e SHA-256 do repositório fixo verificam procedência/transporte e integridade, sem equivaler a uma assinatura digital independente do autor. Nenhum equipamento do colégio foi acessado ou homologado.

A automação do aplicativo não cria compatibilidade universal com hardware, não altera permissões do roteador e não autoriza escrita ao restaurar acesso salvo. Os cenários de atualização administrativa serão identificados explicitamente.

## Evidência anterior: 2.1.0

Publicada em 7 de novembro de 2026. O [fluxo completo Windows/Linux](https://github.com/perabru/LabGuard/actions/runs/42384743010) passou para o commit `8f6141d5c0388dfe13fbdcd40447d7ce49824843`. A [versão 2.1.0](https://github.com/perabru/LabGuard/releases/tag/v2.1.0) contém seis pacotes desktop/servidor, autotestes e somas SHA-256.

Passaram **344 testes** localmente e no Linux CI e **300 testes compatíveis com Windows**. O Windows PowerShell 5.1 validou os coletores no parser e executou CIM/ARP locais reais com falha do método primário forçada; nenhuma capacidade de alteração foi exposta. Instalação, abertura gráfica e serviços SCM/systemd passaram nos sistemas nativos.

O [Pages](https://github.com/perabru/LabGuard/actions/runs/42384743008) publicou site/manual 2.1.0. O manual mantém 15 páginas e 14 capítulos, com renderização e revisão visual. A interface foi conferida em 1240×820 e 1000×700, incluindo conflitos, registros duplicados e falha mantendo dados antigos.

O instalador Windows foi verificado por hash do artefato, CRC do ZIP, SHA-256 interno, estrutura PE e autotestes. SHA-256 do EXE: `fed1e22bbaec63dec05a6a5ce052c41f29b4975ffcc51d73fb4ee395879358aa`. Nenhum equipamento do colégio foi acessado; os testes não comprovam descoberta universal ou homologação no hardware escolar.

O inventário continua parcial: contagens de endereços não são uma medida de todas as máquinas físicas nem de pessoas. Leituras recentes confirmam a coleta, não a presença atual de cada cliente. A nova interface deve identificar fontes, dados antigos, lacunas e conflitos, mantendo os controles dependentes de permissões e capacidades reais.

## Evidência anterior: 2.0.1

Publicada em 6 de novembro de 2026. O [fluxo completo Windows/Linux](https://github.com/perabru/LabGuard/actions/runs/42296126982) passou no commit `8735368630f207dd2ecb16e112eafb3e20a38318`. A [versão 2.0.1](https://github.com/perabru/LabGuard/releases/tag/v2.0.1) inclui os seis pacotes desktop/servidor, autotestes e somas SHA-256.

Foram aprovados **294 testes** localmente e no Linux CI e **250 testes compatíveis com Windows**. Instalação, abertura da janela e serviços SCM/systemd também passaram nas plataformas nativas. O autoteste do desktop congelado confirmou o módulo de ajuda com seis passos no cenário sem gateway, sem abrir Tk ou consultar a rede.

O manual de **15 páginas e 14 capítulos** foi renderizado e revisado. O [Pages](https://github.com/perabru/LabGuard/actions/runs/42296126823) publicou o site e a seção de identificação; o link, a âncora e a apresentação foram conferidos em navegador. A prévia local do navegador apontou para outro projeto e não foi usada como evidência.

O instalador Windows anexado foi conferido pelo hash do artefato, CRC do arquivo ZIP, SHA-256 interno, estrutura PE e autotestes 2.0.1. SHA-256 do EXE: `917a2a57ff6cb64da4b8fd7ab34057786de54e08a08510b2b6f0b129bae140de`.

## Alteração anterior: 2.0.1

O desktop inclui **Não identificou? Ver passo a passo**, com orientação por sintoma e sistema. A consulta de diagnóstico não altera regras, rede, arquivos de configuração ou capacidades. O assistente não usa demonstração para substituir uma leitura falhada e não exibe segredos a partir das mensagens de erro. O painel de servidor oferece um guia equivalente. O pacote Debian passa a declarar a dependência `iproute2`; a versão portátil continua dependendo das ferramentas locais.

O manual inclui verificações de IP/gateway, inventário parcial, MAC ausente, modelo desconhecido e acesso HTTPS/API. Uma informação ausente nem sempre representa erro: o cache local é limitado, o MAC do próprio PC pode ficar vazio e a descoberta cobre IPv4 privada.

## Evidência anterior: 2.0.0

Publicada em 6 de novembro de 2026. O [fluxo completo no GitHub Actions](https://github.com/perabru/LabGuard/actions/runs/42291112160) passou para o commit `0aed0142ccaafe7ee903ef30f93e6e1becb4c013`. A [versão 2.0.0](https://github.com/perabru/LabGuard/releases/tag/v2.0.0) contém os seis pacotes desktop/servidor, quatro autotestes JSON e somas SHA-256.

A suíte completa de **277 testes** passou localmente e no Linux CI; os **233 testes compatíveis com Windows** também passaram. As etapas nativas validaram instalação, abertura da interface e serviços nas plataformas correspondentes. O site e o manual 2.0 passaram no [fluxo de publicação do Pages](https://github.com/perabru/LabGuard/actions/runs/42291112037).

## Escopo verificado

A versão 2.0 inicia em Observação local e usa quatro telas: Início, Dispositivos, Sites e Atividade. A observação consulta somente tabelas e configuração do próprio sistema; não faz varredura ativa nem aplica regras. A ausência de vizinhos ou de ferramentas locais produz um diagnóstico parcial, sem dispositivos inventados.

Os testes do controlador verificam isolamento da demonstração, capacidades, saúde, encerramento e autorização de escrita. O banco local preserva a intenção ao conectar o primeiro RouterOS, mantém bancos separados por destino e exige aplicação explícita. Relatórios identificam modo, fonte, horário e limites do inventário.

O adaptador RouterOS é testado com respostas REST simuladas, incluindo TLS obrigatório, ausência de redirecionamentos e proxy, limites de resposta, regras próprias, pares de bloqueio IP, proteção administrativa, alterações concorrentes, falhas parciais e confirmação posterior. Regras externas são preservadas. Essas verificações não equivalem a homologação em um roteador físico.

O servidor conserva autenticação, perfis de consulta/administração, validação de Host/Origin e arquivos privados. Seu controlador padrão também é Observação. O segredo do RouterOS fica separado da configuração pública. Os testes HTTP locais não utilizam equipamentos do colégio.

## Pacotes nativos

| Pacote | Verificação executada no fluxo 2.0.0 |
|---|---|
| Windows instalador e portátil | Compilação x64, instalação silenciosa, autoteste e abertura da janela em demonstração |
| Linux Debian e portátil | Compilação x86_64, instalação Debian, autoteste e janela real no Xvfb |
| Servidor Windows | Autoteste, serviço SCM, PowerShell 5.1, caminhos com espaços e permissões privadas |
| Servidor Linux | Autoteste, serviço systemd e resposta de saúde em demonstração isolada |

Os pacotes foram compilados no Windows x64 e Ubuntu 22.04 x86_64. A janela foi aberta em demonstração explícita; o modo de início padrão é Observação, confirmado também pelo autoteste do executável. O manual de 13 páginas foi renderizado e revisado; a versão HTML e o site foram conferidos em navegador.

Uma resposta HTTP 200 em `/healthz` confirma apenas o processo ativo. Demonstração e compilação não confirmam regras de rede, WinRM, SSH ou certificados do colégio. A [versão 1.4.0](https://github.com/perabru/LabGuard/releases/tag/v1.4.0) permanece disponível para o fluxo legado; seus pacotes não devem ser confundidos com 2.0.

## Homologação no colégio

Nenhum equipamento ou computador do colégio foi acessado ou alterado. Para bloquear na rede existente, o equipamento já responsável pelo tráfego precisa oferecer uma integração compatível. Estar na mesma LAN ou Wi-Fi, por si só, não concede controle sobre os outros dispositivos. O modelo e a API do modem Vivo ainda precisam ser identificados.

No RouterOS, confirme HTTPS e permissões, gateway DHCP, rede do laboratório, lista WAN, DNS entregue aos clientes, IPv6, FastTrack e offload. O programa não muda essas configurações gerais para liberar ações. O filtro DNS exige RouterOS 7.18 ou superior e DNS compatível; IP/MAC são escopos independentes. Não há histórico DNS por cliente nem inventário de processos por esse adaptador.

Comece por uma estação de teste. Confirme fisicamente IP/MAC e proteção administrativa. Aplique e remova um domínio controlado, teste corte e restauração por IP e confira as regras diretamente no equipamento. Cache, VPN, DoH, IPv6 e caminhos alternativos exigem avaliação no ambiente. MAC privado ou oculto por NAT reduz a identificação; o mapa é lógico, não comprova cabos ou associação Wi-Fi.

A administração de programas exige WinRM HTTPS ou SSH previamente preparado. Remoções e avisos continuam limitados ao catálogo e às permissões da estação. Nenhum jogo real foi removido durante os testes. Consulte o [manual 2.2](MANUAL_DO_USUARIO_V2.html), o [roteador direto](ROTEADOR_DIRETO.md), [servidores](SERVIDORES.md) e [administração remota](ADMINISTRACAO_REMOTA.md).
