# Administração dos computadores sem instalar cliente

O LabGuard administra um computador selecionado por vez usando **WinRM HTTPS do Windows** ou **OpenSSH do Linux**, previamente habilitados pela equipe de TI. Não instala agente nas estações, não habilita serviços remotamente e não descobre credenciais. A conexão direta ao roteador continua responsável pelas regras da rede; desinstalar programas e consultar processos exige acesso administrativo ao próprio computador.

## Preparação do laboratório

| Computador | Pré-requisitos existentes na estação | Conexão do painel |
|---|---|---|
| Windows compatível com administração WinRM | WinRM HTTPS autorizado, certificado de servidor válido para o nome/IP utilizado, conta com permissões administrativas necessárias | TCP 5986; usuário e senha informados na sessão; CA institucional opcional |
| Linux | OpenSSH, `/usr/bin/python3`, autenticação por chave e programas de gerenciamento correspondentes | Porta SSH autorizada; identidade do host previamente conferida em `known_hosts` |

Restrinja as portas de administração à máquina/sub-rede de gestão. A implantação do WinRM, certificados e permissões pertence à equipe de TI e pode depender da edição do Windows e das políticas do domínio. Não desative validação TLS, não use HTTP 5985 e não abra essas portas para toda a Internet. Linux exige permissões `sudo -n` previamente concedidas **somente aos comandos de remoção autorizados**, com argumentos exatos; não é necessário liberar um shell root ou uma regra `NOPASSWD: ALL`.

Na instalação Python do painel, o suporte Windows utiliza `pywinrm>=0.5,<0.6`. Essa biblioteca fica no computador do administrador. No Linux remoto, os scripts transitórios usam apenas a biblioteca padrão do Python já disponível e não criam serviço ou arquivo de agente. O executável Windows do painel inclui a biblioteca WinRM quando gerado com as dependências de build do projeto.

## DNS da estação pelo PC da TI

Em **Configurar → Administrar estações**, selecione o IPv4 de uma estação autorizada. **Testar estação** consulta o filtro pelo IP e depois pelo DNS padrão do alvo. O teste Windows utiliza WinRM HTTPS. No Linux, requer SSH com chave, Python 3 e `dig`. Para Windows, **Preparar alteração**, **Aplicar DNS** e **Restaurar DNS** permitem ajustar o adaptador da estação com prévia e confirmação.

O navegador local da TI também oferece **Estações → Testar DNS** para Windows. Para preparar WinRM HTTPS pelo domínio ou MDM, consulte **Preparar acesso remoto** e o [capítulo 11 do manual](MANUAL_DO_USUARIO_V2.md). O script é distribuído pelo canal institucional de gestão do computador.

## O que o inventário mostra

A consulta retorna horário UTC, alvo, processos reconhecidos e instalações do catálogo. Roblox, Minecraft, Fortnite, Valorant, League of Legends, Counter-Strike 2 e Genshin Impact possuem nomes reconhecidos; Steam, Epic e outros launchers são identificados como **launchers**. Um launcher aberto não comprova que uma partida esteja em andamento. Nomes podem ser alterados e não equivalem à verificação da integridade do executável.

O programa não coleta `CommandLine`, histórico de navegador, tokens de jogos, senhas, conteúdo de páginas nem arquivos pessoais. Um processo `java`/`javaw` não é classificado como Minecraft. O executável genérico `Windows10Universal.exe` só é atribuído ao Roblox antigo se o caminho observado no próprio Windows corresponder à instalação Store Roblox com identidade permitida; o caminho não é retornado ao painel. Alguns programas por usuário podem não aparecer sob outra conta administrativa.

Esta é uma consulta pontual, sujeita às permissões da conta. Processos que fecham entre atualizações deixam de representar o estado atual. Para remoção, o inventário e a confirmação têm validade de **60 segundos**.

## Remoção explícita por catálogo

Não existe remoção automática ao detectar jogo, domínio ou processo. Primeiro selecione a instalação, confira computador, método e aviso sobre dados e confirme a prévia. Cada confirmação usa um token aleatório de uso único, vinculado ao alvo e à identidade do pacote. Antes da alteração, uma nova consulta precisa encontrar a mesma instalação. O comando no próprio destino também reconfere a identidade/versão permitida. Alterações concorrentes são recusadas quando detectadas; não existe transação distribuída com o gerenciador de pacotes.

| Instalação | Remoção implementada | Limites |
|---|---|---|
| Roblox antigo e Roblox Windows atual da Microsoft Store | `Remove-AppxPackage` do pacote exato, para todas as contas | Nome, família, publicador e assinatura Store precisam corresponder ao catálogo; exige administrador |
| Roblox instalado por EXE e demais instaladores desktop | Consulta e orientação manual | Não executa `UninstallString`, EXE em perfil de usuário nem desinstalador desconhecido como administrador |
| Minecraft da Microsoft Store | Consulta e orientação manual | Faça backup dos mundos antes de desinstalar pelo Windows |
| Debian `minecraft-launcher`, `steam` e `steam-installer` | `dpkg --remove` do pacote exato | Não usa `--purge`; dependências podem impedir a operação; jogos baixados na pasta pessoal permanecem |
| Flatpak de sistema `com.valvesoftware.Steam` e `com.mojang.Minecraft` | `flatpak uninstall --system` da referência exata | Confere arquitetura, branch e commit; não usa `--delete-data` nem remove instalações de outros usuários |
| Outros pacotes ou lojas | Sem remoção remota | Exigem adaptador revisado e nova versão do catálogo |

**Dados locais do Roblox Store:** o Windows pode redefinir os dados locais do app na desinstalação. A opção Microsoft `PreserveApplicationData` destina-se a apps de desenvolvimento e não oferece preservação geral para `-AllUsers`. A prévia informa esse efeito. O LabGuard não executa comandos para apagar pastas pessoais ou Roblox Studio. Minecraft Store permanece manual para proteger mundos locais. Os Flatpaks citados são empacotamentos da comunidade, sem suporte oficial de Valve/Mojang.

Identidades Roblox permitidas:

| Campo | Antigo | Atual |
|---|---|---|
| Nome Appx | `ROBLOXCORPORATION.ROBLOX` | `ROBLOXCorporation.RobloxGDK` |
| Família | `ROBLOXCorporation.ROBLOX_55nm5eh3cm0pr` | `ROBLOXCorporation.RobloxGDK_55nm5eh3cm0pr` |
| Publicador | `CN=6FEF9772-62F8-4C8B-8DE0-70F628846515` | Mesmo publicador |
| Assinatura exigida | `Store` | `Store` |

Identidade diferente não é aceita apenas por conter “Roblox” no nome. O catálogo não inclui GUIDs MSI nem recebe scripts/desinstaladores baixados de perfis personalizados.

Uma falha de rede ou limite de tempo durante a remoção pode deixar o resultado incerto. Atualize o inventário e confira a estação antes de tentar novamente; nunca interprete timeout como garantia de que nada aconteceu. O painel não faz rollback de instalações.

## Avisos aos alunos

Há modelos fixos para **jogos** e **conteúdo adulto**, com domínio opcional validado, sem campo para comandos arbitrários. O intervalo mínimo é de cinco minutos por tipo de aviso e alvo, durante a sessão.

- **Windows:** envia por `msg.exe` às sessões de usuário, quando disponíveis e autorizadas. Isso pode exibir uma janela do sistema. Nenhuma sessão ou permissão de mensagens gera resultado de não entrega.
- **Linux:** usa `wall` em terminais conectados. É uma mensagem de terminal; esta versão não garante popup no ambiente gráfico e depende das permissões de mensagens da sessão.

“Enviado” significa que o serviço do sistema aceitou a mensagem. Não confirma que o aluno leu ou viu o aviso. Consultas DNS podem ocorrer em segundo plano, por anúncios ou pré-carregamento: **uma consulta de domínio não prova visita a uma página**. Dados da rede, sozinhos, não identificam qual jogo está aberto; isso vem da consulta autenticada de processos. A interface deve manter qualquer automação de avisos opcional e visível.

## Proteções implementadas

Credenciais permanecem em memória durante a sessão e são liberadas ao desconectar; não são gravadas em arquivos, snapshots, mensagens de erro ou argumentos do SSH. Python não garante apagamento físico de cópias de memória. HTTPS exige certificado válido; proxies herdados do ambiente ficam desativados para WinRM. SSH mantém verificação estrita do host e ignora configurações locais que poderiam executar comandos ou abrir encaminhamentos.

As operações usam scripts fixos e catálogo fechado, limites de registros e saída, timeouts e mensagens de erro sem detalhes de autenticação. O cliente WinRM recebe a saída em blocos com limite total de 512 KiB e prazo de recepção; o SSH usa o executor limitado do projeto. A limpeza de sessões WinRM também está sujeita aos timeouts HTTP. Fechar a janela invalida confirmações e referências de credenciais. Isso não substitui as permissões, atualizações e proteção do sistema operacional.

O recurso foi validado com testes automatizados e respostas simuladas. A comunicação com cada modelo/edição do laboratório precisa ser homologada pela TI antes do uso real. Os testes não fazem alterações em computadores da escola.

## API Python

```python
from labguard.remote import create_session, RemoteError

session = create_session("windows", host, user, password, ca_file=ca_file)
try:
    snapshot = session.inspect()
    # A interface exibe a prévia e solicita confirmação explícita do operador.
    preview = session.preview_uninstall(install_id)
    # Somente após confirmar a prévia:
    result = session.uninstall(preview["token"])
    notice = session.notify("games")
finally:
    session.close()
```

`inspect()` retorna `host`, `platform`, `observed_at`, `processes`, `games`, `capabilities` e `warnings`. Cada instalação contém `id`, `name`, `install_id`, `method`, `can_uninstall`, `reason` e `identity`. `notify()` retorna `sent`, `confirmed=False`, `channel` e `message`. Não há API pública de execução livre de comandos.

## Referências primárias

- [Microsoft: implantação WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [pywinrm: biblioteca e configuração HTTPS](https://github.com/diyan/pywinrm)
- [Microsoft: Remove-AppxPackage e limites de preservação de dados](https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage)
- [Microsoft: msg e permissões de mensagens](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msg)
- [Microsoft DisplayCatalog: Roblox antigo](https://displaycatalog.mp.microsoft.com/v7.0/products/9NBLGGGZM6WM?market=US&languages=en-US)
- [Microsoft DisplayCatalog: Roblox atual](https://displaycatalog.mp.microsoft.com/v7.0/products/9PMF91N3LZ3M?market=US&languages=en-US)
- [Roblox: migração para o novo app Store](https://en.help.roblox.com/hc/en-us/articles/40842585714196-Get-the-New-and-Improved-Roblox-App-in-the-Microsoft-Store)
- [Minecraft: downloads oficiais](https://www.minecraft.net/en-us/download)
- [Debian: steam-installer](https://packages.debian.org/stable/steam-installer)
- [Flatpak: referência de comandos](https://docs.flatpak.org/en/latest/flatpak-command-reference.html)
- [Flathub: Steam](https://flathub.org/en/apps/com.valvesoftware.Steam) e [Minecraft Launcher](https://flathub.org/en/apps/com.mojang.Minecraft)
