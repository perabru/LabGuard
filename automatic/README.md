# LabGuard Automático 2.5 — cliente Windows + Central 1.2 opcional

## Começar no PC do aluno

Abra **LabGuard-Jogos.exe**, autorize a conta administrativa no UAC e confirme **Sim** no aviso de ativação. A partir dessa confirmação, instalação, atualização, ativação dos bloqueios e conferência do monitor acontecem automaticamente. Não é necessário informar IP, selecionar vínculo ou instalar Python para a proteção local.

O instalador mostra **Proteção local confirmada** somente após verificar o monitor, o agendamento e as regras. Se aparecer **pendências**, consulte os detalhes. Feche a janela ao terminar: as rotinas seguem no início do Windows, sem abrir o painel na sessão do aluno. Um ícone identificado permanece na bandeja. Não há ocultação dos componentes do Windows.

## O que fica automático sem Central

- Monitor de jogos reconhecidos: intervalo nominal de dois segundos.
- Limpeza de instalações reconhecidas e pastas previamente aprovadas: primeira solicitação na instalação e repetição de cinco minutos. Operações não se sobrepõem.
- **Catálogo completo do LabGuard**: 839 domínios distintos de jogos, launchers online, Minecraft, Roblox, apostas, sites adultos e inteligência artificial nas políticas locais do Chrome, Edge e Firefox. A lista vem das fontes versionadas do Cliente e do filtro TI; não é gerada por adivinhação.
- **Sites rápidos separados**: YouTube, Termo (term.ooo), Friv (friv.com e friv.com.br), Poki (poki.com) e Chess.com. Mantêm os botões individuais Bloquear/Liberar do painel. As regras completas não impedem essas exceções específicas.
- As regras são salvas com registro de propriedade por navegador. O relatório `fullcatalog-status.json` mostra se todos os domínios foram confirmados; não anuncia sucesso parcial como completo.
- Inicialização das tarefas com o Windows; instalação exige administrador apenas para configurar essas tarefas.
- Capturas de tela desligadas. Arquivos executáveis considerados suspeitos são encaminhados ao Microsoft Defender; **nenhum arquivo pessoal ou desconhecido é apagado somente por parecer suspeito**.

A rotina também identifica launchers conhecidos (como Steam, Epic, Battle.net, EA app, Ubisoft Connect, GOG Galaxy e Riot Client), emuladores e pacotes de jogos do Windows/Xbox. Instalações não reconhecidas ficam pendentes de classificação; não existe desinstalação universal segura de todo programa. A exclusão de jogos é permanente e pode incluir saves e mundos das pastas abrangidas. Faça backup antes. Roblox Studio, Minecraft Education e ferramentas educacionais reconhecidas continuam preservados. Não há reconhecimento universal de todo jogo: títulos desconhecidos e portáteis podem exigir aprovação administrativa de sua pasta exclusiva. ISO não é apagada somente pela extensão.

**Joguester continua com endereço pendente**: informe seu domínio real em Sites rápidos no painel. Poke foi interpretado como Poki. **Bloquear tudo** aplica-se à lista cadastrada de Sites rápidos e ao YouTube, não corta toda a internet nem ativa novas remoções.

## Painel opcional no administrador

Para receber avisos e alterar regras remotamente, use **LabGuardTecnico.exe (Central 1.2)** no PC administrador. Quem já tem a Central 1.2 não precisa reinstalá-la só para usar o Cliente 2.5.

1. Primeira Central: abra o EXE, informe IP real/reservado, rede autorizada e senha. Central anterior: use **Instalar / reparar**. O painel é local em `http://127.0.0.1:8787/`.
2. Gere um JSON individual em **Computadores → Vincular computador**. Cada vínculo serve para uma estação e expira em uma hora.
3. No cliente já instalado, abra a administração pelo ícone LabGuard e clique **Conectar ao painel (opcional)**. Selecione o JSON. Não é preciso instalar a proteção outra vez.
4. Confira o primeiro contato e as confirmações em Computadores. Depois use **Sites rápidos → Bloquear tudo** e **Avisos e proteção**.

O canal usa HTTPS/TCP 8788, certificado da Central e credencial por estação. O instalador do administrador libera apenas a rede informada; não exponha a porta na internet. O cliente consulta em torno de 15 segundos. Sem conexão, mantém a última política local. As notificações do navegador exigem permissão e painel aberto/autenticado. Nenhuma tela, arquivo ou histórico de navegação é enviado nesse canal.

## Atualizar versões 2.1, 2.2 ou 2.3

Execute o novo **LabGuard-Jogos.exe** a partir de Downloads e confirme. Ele pausa novas limpezas, aguarda a operação anterior e substitui sua própria instalação. Não use o desinstalador para atualizar. Os vínculos existentes e as regras da Central são preservados. Se a Central tiver pausado a proteção, a atualização não contradiz essa decisão: retome no painel.

Se a operação antiga não terminar dentro do limite, a atualização informa a pendência e tenta restaurar o estado anterior; não força a interrupção do Windows Installer. Confira o resultado antes de sair da estação.

## O impacto de bloquear o catálogo inteiro

Esta opção também bloqueia domínios de IA, apostas e sites adultos. Serviços de IA usados em aulas, como ChatGPT, Copilot ou Gemini, podem ficar inacessíveis nos computadores dos alunos. **Verifique a política pedagógica da escola antes de instalar.** O botão "Bloquear tudo" da Central ainda se refere à lista rápida; ele não remove softwares. Para liberar domínios do catálogo completo por exceção institucional, utilize as políticas administrativas específicas do navegador ou revise a versão do pacote — configurações externas não são substituídas pelo LabGuard.

## Confirmar que funcionou

Reabra o navegador na conta padrão do aluno e teste um site bloqueado e um site de aula. Confira o estado do monitor em **Opções avançadas** e os registros em `%ProgramData%\LabGuardJogos2`. A instalação gera `install-status.json`, `fullcatalog-status.json` e três registros `fullcatalog-owned-*.json` de propriedade das regras; a atividade do monitor fica em `guard-status.json` e `guard.log`.

A gravação das regras não garante o bloqueio em todo navegador, aplicativo, proxy ou aba já carregada. Chrome, Edge e Firefox são os navegadores abrangidos. Exceções institucionais e outro filtro podem prevalecer. O programa não encerra o navegador inteiro.

## Arquivo certo

**LabGuard-Jogos.exe** instala/atualiza a proteção local em cada estação. **LabGuardTecnico.exe** é o painel opcional do administrador. O **ZIP** reúne os dois executáveis e o guia: extraia antes de abrir. **LabGuard-Setup.exe (rede/DNS)** é outra edição e não recebe os avisos do cliente sozinho. **LabGuard-Desinstalador.exe** remove o produto; não serve para atualizar.

Compatível com Windows 10/11 x64, .NET Framework 4.8 e Windows PowerShell 5.1. Binários sem certificado comercial: confira a origem e o SHA-256, sem desativar antivírus ou UAC. Alunos devem usar contas padrão, não administradores locais.

## Verificação

Além dos testes anteriores, esta versão exige verificar os três navegadores com amostras do catálogo completo e instalação real do executável em um Windows descartável, início do monitor, agendamento SYSTEM, bloqueios locais sem vínculo, fechamento de uma janela de jogo fictício, exclusão de arquivos de jogo fictício, preservação de um documento e reparo da instalação. Consulte TESTE_INSTALACAO.txt. Isso não significa que já foi instalada ou testada nos PCs do laboratório.
