# LabGuard Jogos 2.0.0

Agente administrativo local, independente do filtro DNS. Windows 10/11 x64 com Windows PowerShell 5.1 e .NET Framework 4.8. O EXE abre um painel visivel e solicita UAC apenas para administrar. Nao exige Python e nao desliga o antivirus, o UAC ou politicas de seguranca.

## Instalar
1. Abra `LabGuard-Jogos.exe` e clique em **Instalar e ativar**.
2. Autorize o UAC com uma conta administrativa da escola e confirme o aviso de remocao permanente. Saves e mundos nos caminhos removidos podem ser perdidos: faca backup antes.
3. Confira **Status** e **Ver registros**. A tarefa `LabGuard-Jogos2-Limpeza` usa SYSTEM no boot, login e a cada 5 minutos. Operacoes demoradas nao se sobrepoem; o ciclo seguinte pode aguardar o anterior.
4. O painel inicia no login de cada usuario. O status diferencia rotina instalada, em execucao, pausada, falha e resultado antigo. Se a instalacao for feita dentro da conta do tecnico, encerre a sessao e entre na conta do aluno para iniciar o painel nessa sessao.

## Alvos e limites
Steam, Roblox Player, Epic Games Launcher, Minecraft de jogos, launchers alternativos e emuladores do catalogo. Instalacoes MSI e Microsoft Store reconhecidas usam os mecanismos de desinstalacao do Windows; outras instalacoes reconhecidas sao removidas por caminhos delimitados. Podem permanecer entradas antigas de desinstalacao e componentes compartilhados. Nao se executam comandos arbitrarios encontrados no Registro como SYSTEM.

Jogos de ISO sao identificados pelo cadastro instalado ou por nome + executavel em pastas de jogos. Nao ha um indicador universal de que um aplicativo foi instalado de ISO. ISOs desconhecidas sao sinalizadas, nao excluidas. Jogos fora do catalogo, portateis ou renomeados exigem **Aprovar pasta de jogo**; selecione apenas a pasta exclusiva do jogo. Steam/Epic podem conter ferramentas educacionais: conteudo fora do catalogo fica pendente para aprovacao, nao e presumido jogo.

Preserva por padrao Roblox Studio, Minecraft Education, Unreal Engine, Android Studio, ferramentas de desenvolvimento, documentos e pastas genericas. Nao remove `.iso`/`.exe` por extensao, nem todas as pastas de Downloads. Nao ha garantia de identificar todos os jogos. A conta do aluno deve ser padrao, nao administradora; um administrador local pode desativar a ferramenta.

## Tela e arquivos suspeitos
As capturas ficam **desligadas por padrao**. O tecnico pode autoriza-las explicitamente no painel, conforme a politica da escola e o aviso aos usuarios. O painel mostra aviso permanente; a captura ocorre na sessao interativa, no maximo a cada 5 minutos, sem envio a servidor. O usuario pode suspender as capturas da sessao. Retencao local de 24 horas, limite de 24 imagens por usuario. A imagem e acompanhada de indicios de processos conhecidos, nao de uma classificacao visual por IA. Nenhum arquivo e apagado por conclusao extraida de uma imagem.

Arquivos suspeitos sao encaminhados a analise do Microsoft Defender: ate dois arquivos novos/alterados por ciclo entre os oito mais recentes de Downloads de cada perfil, com limite de espera. A remediacao/quarentena segue a politica do antivirus. Erros ou antivirus inativo aparecem como pendencias; isso nao equivale a uma garantia de computador limpo.

## Controle e registros
- Administracao: Instalar, Simular, Verificar agora, Pausar, Retomar, Aprovar pasta, Autorizar/desligar capturas e Desativar instalacao.
- Binario/configuracao: `%ProgramFiles%\LabGuardJogos2` (alteracoes so por administradores/SYSTEM).
- Status/logs: `%ProgramData%\LabGuardJogos2`.
- Evidencias da sessao: `%LocalAppData%\LabGuardJogos2\Capturas`.
- Desativar remove a tarefa, o inicio automatico e o cadastro do produto. Mantem o binario e os registros para auditoria; nao restaura dados de jogos removidos.

## Compilacao e testes
`powershell -NoProfile -ExecutionPolicy Bypass -File games\build.ps1` compila com o compilador C# do .NET Framework presente no Windows. O workflow executa verificacoes do catalogo e caminhos, compila o EXE e faz smoke test da interface sem instalar a rotina ou remover jogos. A validacao do laboratorio real ainda e necessaria. Binario sem certificado comercial de assinatura de codigo: confira SHA-256 e origem. Nao desative protecoes do Windows para executar.
