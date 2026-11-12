# LabGuard — Desinstalador Windows 1.0.0

Executável independente para remover as instalações Windows conhecidas do LabGuard neste computador. Não precisa de Python instalado. Requer Windows 10/11 x64 e a autorização normal de administrador do Windows (UAC).

## Como usar

1. Salve **LabGuard-Desinstalador.exe** em Downloads ou na Área de Trabalho, fora das pastas de instalação do LabGuard.
2. Abra o executável e autorize o UAC. **Conferir instalações** apenas lista o que foi identificado.
3. Clique em **Desinstalar tudo do LabGuard** e confirme uma vez. A janela mostra cada etapa e informa pendências, sem esconder erros.
4. Reabra os navegadores depois da remoção. Reinicie o Windows quando houver componente em uso ou quando o relatório solicitar. Uma segunda execução pode concluir itens que estavam bloqueados.

Execute em cada computador que deve deixar de usar o LabGuard. No computador que fornece o DNS ao laboratório, restaure primeiro o DNS das estações que dependem dele. Apagar o programa do servidor não altera automaticamente os outros PCs.

## O que é removido

- LabGuard Jogos 1.x (BATCH) e 2.x: limpeza, monitor rápido, inicialização e arquivos reconhecidos.
- LabGuard Cliente 1.x, Central/Técnico, painel Windows e LabGuard Server nas pastas identificadas.
- Tarefas agendadas, serviço LabGuardServer, processos identificados, inicialização automática, cadastros de desinstalação e atalhos do produto.
- Pastas de instalação reconhecidas e dados do LabGuard nos perfis locais: configurações, banco de sites, logs e capturas.
- Regras locais de firewall identificadas como LabGuard. O firewall não é desativado nem redefinido.
- Credenciais RouterOS do LabGuard no cofre da conta administrativa que executa a remoção. O Windows não permite apagar silenciosamente os cofres privados de outras contas sem entrar nelas.

## Restauração de sites e rede

As regras do YouTube e do Cliente são retiradas somente quando o registro de propriedade corresponde à regra atual. Entradas criadas ou modificadas por outros administradores são preservadas. No Firefox, a primeira posição necessária à leitura de regras externas é preservada. O hosts mantém as entradas externas; o bloco do Cliente usa sua assinatura de integridade original.

DNS e IPv6 são restaurados pelos registros `NetworkDNS` e `StationDNS` do LabGuard, quando válidos e compatíveis com o estado atual. **Não se escolhe um DNS público nem se força DHCP/IPv6 em todos os adaptadores.** Mudanças manuais, adaptadores ausentes e conflitos com outras políticas aparecem como pendências.

## O que fica de propósito

O relatório de remoção é salvo em `%LocalAppData%\LabGuard-Desinstalador-Relatorios`. Não contém senhas ou capturas. Quando a restauração de uma política falha, o estado necessário para corrigir a pendência é preservado e identificado no relatório. Não se anuncia remoção total enquanto houver essas pendências.

Downloads, cópias do código-fonte, pastas não reconhecidas, credenciais de outras contas e registros mantidos pelo próprio Windows não são apagados indiscriminadamente. Instalações personalizadas em pastas compartilhadas são recusadas em vez de apagar documentos. Links/junctions não são percorridos.

Este executável não reinstala jogos, não recupera saves ou arquivos anteriormente apagados e não altera roteadores, switches, serviços WinRM/SSH compartilhados, certificados institucionais ou computadores remotos. Regras externas à estação precisam ser tratadas na origem.

## Verificação

A compilação executa testes de remoção em arquivos e componentes sintéticos, preservação de regras externas e abertura da interface em Windows. Isso não substitui a validação nas máquinas reais do laboratório. O pacote inclui `VERIFICACAO.txt` e `SHA256SUMS.txt`.

Binário sem certificado comercial de assinatura. Confira a origem e o SHA-256; não desative o antivírus ou o UAC para executá-lo.

## Código e compilação

`prepare.py` monta o código executado com restrições explícitas de caminhos e inclui os restauradores já usados pelo projeto. O cliente existente é importado somente como código-fonte empacotado: não se executa um programa instalado nem uma linha arbitrária de desinstalação do Registro. `operations.ps1` contém operações locais fixas. `build.ps1` gera e verifica o executável com PyInstaller.
