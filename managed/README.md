# LabGuard gerenciado — Cliente Jogos 2.2 / Central 1.1

Instalação administrativa simplificada, execução automática em segundo plano e avisos no PC do administrador. Windows 10/11 x64; o cliente usa .NET Framework 4.8 e PowerShell 5.1. Os executáveis não precisam de Python instalado.

## Dois arquivos, dois locais

**LabGuardTecnico.exe**: computador administrador. Instale/atualize a Central com este arquivo. Mantém os cadastros da Central 1.0; o filtro DNS antigo (LabGuard 2.4.x) é outro componente e, sozinho, não recebe estes avisos.

**LabGuard-Jogos.exe**: cada computador de aluno. A primeira abertura pede a conta administrativa e mostra apenas o vínculo, o nome da estação e **Instalar e conectar**. A atualização substitui Jogos 2.x; não substitui automaticamente o antigo Cliente 1.x.

## Guia rápido

1. No PC administrador, abra **LabGuardTecnico.exe** e autorize o UAC. Na primeira instalação, informe o IPv4 real do PC, a sub-rede autorizada e uma senha de pelo menos 12 caracteres. Use um IP reservado. Em uma Central já configurada, clique em **Instalar / reparar**, não apenas em Abrir painel, para instalar a nova versão.
2. Abra o painel em **http://127.0.0.1:8787/**, no próprio PC administrador, e entre com a senha. Em **Computadores → Vincular computador**, gere o arquivo JSON. Ele vale por uma hora e somente para uma estação.
3. Leve o arquivo ao PC do aluno. Abra **LabGuard-Jogos.exe**, selecione o vínculo, informe um nome como LAB-01 e clique em **Instalar e conectar**. Confirme a política; a remoção de jogos/saves é permanente. Na atualização, execute o novo arquivo em Downloads, não dentro da pasta instalada. Se houver limpeza anterior em andamento, pause e deixe a operação concluir antes de atualizar.
4. No administrador, confira **Computadores** e **Avisos e proteção**. O cliente se comunica nominalmente a cada 15 segundos; o painel consulta aproximadamente a cada 5 segundos. Vínculo salvo não equivale a contato confirmado: confira a revisão de proteção e a última comunicação.
5. Feche a tela de instalação no PC do aluno. No próximo login, aparece apenas o ícone **LabGuard — computador gerenciado**, sem painel ou avisos interrompendo a aula. O monitor SYSTEM e a limpeza não dependem da janela. A administração continua exigindo uma conta administrativa.

## Avisos no painel

Mostra computador, recebimento, nome do processo e ocorrência: jogo encerrado, cliente iniciado, proteção pausada, falha de monitor, falha de limpeza, comunicação estabelecida e ausência de contato por mais de 90 segundos. Marcar como conferido não interrompe a proteção. Avisos repetidos de reenvio são deduplicados.

**Ativar notificações neste navegador** pede a permissão normal do navegador. Mantenha o painel aberto e autenticado; o histórico permanece na Central mesmo com o navegador fechado. Ausência de contato pode ser desligamento do PC, perda de rede ou falha; não prova evasão pelo aluno.

## Controles centrais e alcance

Em **Avisos e proteção**, três opções aplicam-se a todos os clientes Jogos 2.2 vinculados: proteção/limpeza, fechamento de jogos e bloqueio do YouTube. A limpeza ocorre a cada 5 minutos; o fechamento verifica jogos conhecidos em intervalo nominal de 2 segundos. Desligar a proteção/limpeza também suspende o fechamento. O bloqueio do YouTube é independente.

A lista **Sites e regras** permanece compatível com o Cliente 1.x e não é uma lista de sites arbitrários aplicada pelo novo agente de jogos. O cliente Jogos 2.2 recebe somente essas três opções de proteção. O filtro DNS existente pode continuar controlando os outros domínios. Políticas independentes podem continuar bloqueando um domínio mesmo quando uma regra do LabGuard é liberada.

Steam, Roblox Player, Epic, Minecraft, Xbox/jogos Windows e emuladores conhecidos mantêm o alcance da versão 2.1. Jogos desconhecidos, portáteis ou renomeados podem exigir configuração administrativa local em **Opções avançadas**. Não há garantia de reconhecer todos os jogos. Reabra o navegador após alterar o YouTube.

## Rede, privacidade e segurança

A Central recebe os clientes em **HTTPS/TCP 8788**, liberada pelo instalador apenas para a rede informada. O painel é local em **127.0.0.1:8787**. Não é necessário expor portas na internet, instalar WinRM nem alterar DNS para este canal. O arquivo de vínculo contém o certificado específico da Central; certificados diferentes, vínculos usados, expirados ou revogados são recusados.

O programa não é clandestino: permanece identificado no Windows, na bandeja e nas tarefas agendadas. A conexão envia somente identificação da estação, versão, estados da proteção e eventos com nome do processo. **Não envia telas, arquivos, linhas de comando, nomes de alunos, senhas ou histórico de navegação.** Use nomes técnicos como LAB-01 em vez de nomes de alunos. Capturas ficam desligadas na instalação gerenciada.

Sem rede, a proteção local continua com a última configuração. O cliente guarda até 500 eventos por até 7 dias para reenvio; ao exceder o limite, descarta os mais antigos. A Central mantém até 10 mil eventos por até 7 dias e mostra os últimos 200. As credenciais do cliente são protegidas pelo Windows e por uma pasta restrita à administração/SYSTEM. Um administrador local ainda pode desativar o programa; os alunos devem usar contas padrão.

## Diagnóstico rápido

- **Sem contato:** confirme o PC administrador ligado, IP reservado, mesma rede autorizada, porta 8788, firewall e relógio do Windows.
- **Vínculo recusado:** atualize primeiro a Central 1.1 e gere outro vínculo. Cada arquivo é individual e expira.
- **Política pendente/falha:** veja a estação e os registros locais. Conexão confirmada não garante que todas as regras foram aplicadas; a revisão precisa ser confirmada.
- **Avisos fora do navegador:** clique em Ativar notificações, aceite a permissão e mantenha a sessão aberta. O banner e a lista não precisam dessa permissão.
- **Retirar a proteção:** use o desinstalador independente do LabGuard, como administrador, em cada PC. Ele também remove os arquivos de vínculo dentro da instalação.

Logs locais: `%ProgramData%\LabGuardJogos2\guard.log`, `remocoes.log` e `central-status.json`. A Central guarda seu banco na pasta administrativa `%ProgramFiles%\LabGuardCentral`.

## Validação

O pacote é publicado após testes da base de jogos, regressão da Central, autenticação/CSRF, revogação, retenção, deduplicação, interface e integração real de um cliente C# com uma Central HTTPS descartável. Não significa que já foi instalado ou testado nos PCs do laboratório. Confira `VERIFICACAO.txt` e `SHA256SUMS.txt`; não desative antivírus/UAC para executar um binário sem certificado comercial.
