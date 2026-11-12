# LabGuard Jogos 2.1.0 — cliente Windows

Windows 10/11 x64, Windows PowerShell 5.1 e .NET Framework 4.8. Não exige Python. Instale somente nas estações administradas pela escola; é necessária uma conta administrativa no UAC. Depois da instalação não há confirmação do aluno a cada ação.

## Novidades

- Monitor SYSTEM independente do painel: verifica processos em intervalo nominal de 2 segundos e encerra jogos/launchers reconhecidos. Tenta fechar a janela quando está na mesma sessão; se necessário, encerra o processo. Isso pode perder progresso não salvo do jogo.
- Limpeza de arquivos e desinstalação continuam a cada 5 minutos, no início do Windows e no login. Operações demoradas não são sobrepostas.
- Xbox (Gaming App e aplicativo antigo), Game Bar e jogos Microsoft Store do catálogo: Paciência, Mahjong, Campo Minado, Sudoku, Jigsaw e Bingo. Pacotes compatíveis são desinstalados para todos os usuários e retirados do provisionamento para novos perfis. Nem todos esses jogos existem em toda versão do Windows.
- Preserva Microsoft Store, calculadora, bloco de notas, Paint, frameworks, Gaming Services, identidade compartilhada do Xbox e componentes não removíveis. Não apaga a pasta WindowsApps nem executa remoção genérica de aplicativos Microsoft.
- YouTube bloqueado por padrão na instalação/atualização, com **Bloquear YouTube** e **Liberar YouTube** no painel. Usa entradas delimitadas no hosts e políticas de URL do Chrome, Edge e Firefox. Não encerra o navegador nem suas outras abas. Reabra o navegador depois de alterar a política. Exceções corporativas, outros navegadores, proxies e configurações externas podem interferir; não é interceptação universal de tráfego.
- O X do painel mantém o monitor na bandeja. A tarefa SYSTEM continua mesmo se o painel for encerrado. O estado do monitor e a quantidade de processos encerrados aparecem no painel; ausência de heartbeat é sinalizada, não mostrada como proteção ativa.

## Instalar ou atualizar

1. Abra `LabGuard-Jogos.exe`, confira **Simular sem apagar** e clique em **Instalar e ativar**.
2. Autorize a conta administrativa e confirme a política. Faça backup: a remoção é permanente e pode atingir saves/mundos nas pastas de jogos.
3. Confira os estados e os registros. A instalação inicia a limpeza e o monitor. O painel também começa no login de cada usuário.

Na atualização, abra o novo EXE de uma pasta diferente da instalação, por exemplo Downloads. A rotina fecha somente os processos da versão antiga instalados em `%ProgramFiles%\LabGuardJogos2` para substituir o arquivo, sem encerrar o LabGuard de rede. Se a limpeza anterior estiver em execução, a atualização é recusada com instrução para pausar e concluir essa operação primeiro. A atualização não é instalada remotamente nos computadores por publicar o download.

## Alvos, exclusões e limites

Inclui Steam, Roblox Player, Epic Games Launcher, Minecraft de jogos, emuladores catalogados e Xbox/Windows descritos acima. Não identifica todos os jogos existentes. Renomeados, portáteis e títulos desconhecidos podem exigir **Aprovar pasta de jogo** uma vez; escolha somente uma pasta exclusiva do jogo. O monitor encerra executáveis dessa pasta, preservando executáveis compartilhados, navegadores e ferramentas de desenvolvimento protegidas.

Jogos instalados por ISO são reconhecidos pela instalação ou por nome e executável do catálogo, não pela extensão da ISO. Pastas XboxGames são tratadas individualmente quando o título é reconhecido e há manifesto MicrosoftGame.config. Desconhecidos são registrados como pendências.

Roblox Studio, Minecraft Education, Unreal Engine e ferramentas educacionais reconhecidas são preservados. Não fecha aplicativos por palavras no título da janela. Java só é classificado como Minecraft quando há sinais específicos da classe principal e do diretório .minecraft; a linha de comando não é gravada nos logs.

A conta do aluno deve ser padrão. Um administrador local consegue modificar/desativar a política. Privilégios administrativos não garantem encerrar todo processo protegido pelo sistema; falhas de remoção aparecem nos registros. Pacotes protegidos não são forçados. A desinstalação pode deixar componentes compartilhados e registros antigos.

## Painel e registros

**Ativar fechamento/Pausar fechamento** controlam o monitor rápido. **Pausar limpeza** também suspende o fechamento rápido; **Retomar limpeza** reativa o agendamento e o monitor. O YouTube tem política independente, alterada pelos seus dois botões. Liberar YouTube remove somente as regras que o LabGuard criou e ainda possui; outras regras do administrador não são apagadas. Não restaura aplicativos já removidos.

- Tarefa de limpeza: `LabGuard-Jogos2-Limpeza` (5 minutos).
- Monitor: `LabGuard-Jogos2-Monitor` (processo contínuo, verificação nominal de 2 segundos, inicialização no boot/login e tentativa de recuperação a cada minuto).
- Binário/configuração: `%ProgramFiles%\LabGuardJogos2`.
- Limpezas: `%ProgramData%\LabGuardJogos2\remocoes.log`.
- Fechamentos: `%ProgramData%\LabGuardJogos2\guard.log`.
- Status: `status.json`, `guard-status.json`, `youtube-status.json` no mesmo diretório.

## Capturas e arquivos suspeitos

Capturas continuam desligadas por padrão e exigem autorização institucional separada, com aviso visível. São locais, sem envio a servidor, com limite de 24 imagens e retenção de até 24 horas. O usuário pode pausar as imagens da sessão. Não existe classificação visual por IA e nenhum arquivo é removido por interpretação do print. O monitor rápido não depende de capturas.

O Microsoft Defender analisa uma seleção limitada de arquivos novos/alterados de Downloads, quando disponível. Quarentena/remediação seguem a política do antivírus. Isso não garante um computador livre de ameaças.

## Testes e origem

A compilação executa parsing no PowerShell 5.1, testes de catálogo e exclusões, reversibilidade de hosts, preservação de políticas em um ramo de Registro isolado, agendamento SYSTEM, teste da interface e fechamento de uma janela de jogo fictícia. Não é uma validação de todos os jogos no laboratório real. Não desative proteções do Windows; confira a origem e o SHA-256. O binário não possui certificado comercial de assinatura de código.

Código original e extensões são montados por `assemble.ps1`, com verificação de âncoras para recusar montagens incompletas. O motor e os controles são embutidos no EXE; não são carregados de um script gravável pelo aluno.
