# LabGuard Cliente para Windows 10 e 11 (x64)

Esta edição roda no computador da escola. Funciona sem o painel da TI, sem WinRM e sem alterar o DNS do roteador. Use conta de aluno padrão e reserve as credenciais de administrador para a TI. A tarefa **LabGuardCliente** é identificada no Agendador de Tarefas. O cliente não abre painel, console ou ícone de bandeja no login do aluno. Avisos de bloqueio do navegador e eventuais telas do desinstalador do fabricante podem aparecer.

## Novo na versão 1.2.0: controle pelo técnico

O cliente também pode receber os sites da **LabGuard Central 1.0.0**. Instale a [Central no computador do técnico](../central/README.md), gere um arquivo de vínculo para cada estação e, no cliente instalado, abra **Técnico → Importar vínculo**. A TI poderá adicionar, excluir, liberar e bloquear os domínios em um único painel. O cliente informa a revisão aplicada e mantém a última política válida quando a central estiver offline.

Para atualizar uma instalação 1.1.0, abra o novo EXE como administrador e importe o vínculo; o programa atualiza a cópia instalada pelo ciclo de instalação existente. Os sites definidos na Central substituem a lista e o catálogo locais enquanto houver vínculo. As opções locais de jogos são preservadas. **Técnico → Desvincular** retoma a política local original. Consulte o [guia da Central](https://perabru.github.io/LabGuard/tecnico/) para instalar, vincular e interpretar as confirmações.

## Começar em uma máquina piloto

1. Baixe **LabGuardCliente.exe** na [versão do cliente](https://github.com/perabru/LabGuard/releases/tag/cliente-v1.2.0). Guarde a cópia baixada para administração e remoção. Abra e confirme a solicitação de administrador do Windows. O EXE contém Python. Para utilizar o arquivo fonte, veja abaixo.
2. Em **Sites**, escolha **Bloquear os listados** para aplicar o catálogo de jogos, conteúdo adulto e serviços de IA. Para uma aula com navegação restrita, escolha **Permitir só os listados** e escreva os domínios necessários, um por linha. Inclua os domínios de login, arquivos, vídeos e demais recursos que sua atividade usa. Confira em um perfil de aluno antes de replicar a política.
3. Em **Jogos**, marque os títulos desejados. **Desinstalar o Roblox identificado** está ativo na política inicial. Desinstalações podem apagar dados locais do aplicativo. Minecraft da Store só pode ser desinstalado se a TI habilitar essa opção expressamente; faça backup dos mundos primeiro.
4. Clique em **Instalar e proteger agora** e confirme a instalação. O Windows executa a tarefa imediatamente no PC já ligado e novamente a cada inicialização. Na aba **Estação**, use **Atualizar estado** e **Detalhes técnicos** até aparecer uma verificação recente. Feche a janela da TI. O Windows inicia a tarefa no boot e a edição clássica do Roblox é tratada no login padrão seguinte.
5. Na conta de teste, reabra o navegador. No modo de bloqueados, abra um domínio da lista e um site didático permitido. No modo de permitidos, confira também o login e os materiais do site permitido. Para diagnosticar as políticas efetivas, abra `edge://policy`, `chrome://policy` ou `about:policies` no navegador correspondente.
6. Para mudar a lista, abra novamente a cópia baixada como administrador, edite e salve a política. O agente reaplica as regras localmente. Para retirar a proteção, abra **Estação → Desinstalar cliente** pela cópia baixada. A operação desregistra a tarefa, remove a inicialização no login e restaura os registros gerenciados e o trecho do arquivo hosts. Reinstale separadamente um jogo que a TI tenha desinstalado se ele voltar a ser necessário.

## Banco de sites

O instalador cria **banco.sqlite3** na estação, com **831 domínios** e procedência por registro. Jogos têm 209 entradas, Roblox tem 40, Minecraft tem 23, conteúdo adulto tem 220, apostas têm 300 e IA tem 39. O catálogo vem dentro do arquivo Python e do executável. A instalação funciona sem baixar listas. A cópia **LabGuard-Catalogo.sqlite3** nos downloads permite consultar as mesmas entradas fora da estação.

Abra **Banco de sites** para pesquisar, editar uma entrada, pausar uma categoria ou revisar um CSV antes de importar. O agente verifica a revisão do banco e reaplica as mudanças enquanto o computador continua ligado. **Ativar agora** solicita novamente a execução da tarefa quando a proteção instalada precisar ser retomada. O banco aceita até **10.000 registros**; o conjunto ativo tem limite de **975 nomes distintos**, somados os domínios adicionais da TI. Se o número exceder o limite, a alteração é recusada e a lista anterior permanece válida. O limite guarda espaço para regras preexistentes nos navegadores; confira o diagnóstico se as políticas da instituição já usarem muitas entradas.

Em **Bloquear os listados**, os domínios e os subdomínios do catálogo ficam bloqueados nos navegadores gerenciados. Em **Permitir só os listados**, somente os domínios autorizados pela TI e as exceções institucionais efetivas podem passar. O filtro do sistema preserva os endereços explicitamente liberados nesse modo. O conjunto do Minecraft concentra-se em downloads, mods e servidores de jogo para reduzir impactos sobre serviços escolares compartilhados. Bloquear a rede do Roblox também pode afetar Roblox Studio. A desinstalação do cliente remove o banco local; use a exportação para guardar os cadastros e anote as categorias pausadas.

## O que é protegido

| Recurso | Alcance nesta versão |
|---|---|
| Navegadores gerenciados | Políticas locais de URL em Edge, Chrome e Firefox compatíveis. As regras por domínio cobrem subdomínios. No modo de permitidos, sites fora da lista recebem bloqueio nos navegadores que aplicam a política. Confira conflitos com GPO, políticas de nuvem ou exceções de terceiros. |
| Outros aplicativos | O arquivo hosts do Windows recebe entradas para nomes exatos do catálogo, incluindo nomes conhecidos do Roblox, em IPv4 e IPv6. Navegadores alternativos, acesso por IP, resolvedores próprios, VPN e execução offline exigem controles adicionais. O cliente não inspeciona conteúdo HTTPS nem altera os adaptadores da máquina. |
| Jogos em execução | Identifica periodicamente executáveis conhecidos, confere o caminho ou a identidade do pacote e encerra jogadores reconhecidos. Um jogo pode abrir até a próxima verificação. Inclui Roblox, Minecraft para Windows (Bedrock), Fortnite, VALORANT, League of Legends, Counter-Strike 2 e Genshin Impact. Roblox Studio, Java genérico e launchers compartilhados são preservados. |
| Roblox da Microsoft Store | A tarefa verifica os pacotes reconhecidos das contas da máquina, confere identidade e assinatura, solicita a desinstalação e lê novamente o inventário. A verificação de pacotes se repete periodicamente e após mudanças na política. |
| Roblox clássico no perfil de aluno | No login, o cliente usa a conta do próprio usuário para executar somente o desinstalador registrado, compatível e assinado pela Roblox. Ausência de registro confiável, edição fora do catálogo, edição instalada para a máquina ou instalador que exige interação podem exigir remoção pela TI em Aplicativos instalados. |
| Demais jogos | Os títulos reconhecidos têm controle de execução. Remoção automática adicional disponível para Minecraft da Store, com autorização explícita. |
| Administração | Configuração local por estação ou gerenciamento opcional dos sites pela LabGuard Central. A aba Técnico permite importar vínculo, sincronizar e desvincular. A Central recebe nome da estação, versão e confirmação das regras de sites; não coleta histórico de navegação. O status não confirma uma tentativa de navegação em cada perfil. |

O endereço de um serviço adulto novo ou de um jogo novo precisa estar no catálogo para ser bloqueado no modo de lista de bloqueio. Para uma aula restrita aos recursos selecionados, use **Permitir só os listados**. Políticas existentes da escola podem ter precedência; na configuração do Edge, perfis conectados com conta Microsoft pessoal podem ter tratamento diferente. Teste com o perfil usado em sala.

## Usar o arquivo Python

Salve **labguard_cliente.py**. O cliente usa somente a biblioteca padrão. Para a instalação em código-fonte, use Python 64 bits **3.10 ou superior**, instalado **para todos os usuários em Arquivos de Programas**, com Tcl/Tk para a janela da TI. Isso evita que uma tarefa de sistema execute um interpretador modificável pelo aluno. No PowerShell da TI, use o caminho real do interpretador. Exemplo com uma instalação em `Python312`:

```powershell
& "$env:ProgramFiles\Python312\python.exe" -I -S -B .\labguard_cliente.py
```

O mesmo cliente aceita comandos para implantação pela TI por GPO/MDM ou outra gestão já autorizada. Execute os comandos administrativos com elevação. O segundo comando abaixo exibe o status; `verificar` retorna código 2 se a proteção ainda estiver pendente. O fonte e o executável usam as mesmas operações. O EXE gráfico aceita `--saida` para gravar o retorno em **um arquivo novo**.

```powershell
& "$env:ProgramFiles\Python312\python.exe" -I -S -B .\labguard_cliente.py instalar --politica .\politica-lab.json --sim
& "$env:ProgramFiles\Python312\python.exe" -I -S -B .\labguard_cliente.py status --json
& "$env:ProgramFiles\Python312\python.exe" -I -S -B .\labguard_cliente.py politica --politica .\politica-lab.json --sim
& "$env:ProgramFiles\Python312\python.exe" -I -S -B .\labguard_cliente.py remover --sim
```

Exemplo mínimo do arquivo `politica-lab.json`. Substitua os domínios pelos serviços autorizados pela escola. No modo de permitidos, uma entrada não pode estar em conflito com a lista de bloqueio; os nomes aqui são apenas exemplos.

```json
{
  "mode": "bloqueados",
  "catalog_enabled": true,
  "domains": ["roblox.com", "rbxcdn.com", "poki.com"],
  "allowed_domains": [],
  "games": ["roblox"],
  "remove_roblox": true,
  "remove_games": []
}
```

O programa mantém sua configuração e o estado de restauração em `%ProgramFiles%\LabGuardCliente`. Use a interface para administrá-los. Se o arquivo hosts contiver uma edição conflitante ou se uma política corporativa impedir a alteração, confira o diagnóstico antes de tentar novamente. Os dados locais de um jogo removido não são recuperados pela desinstalação do cliente.

[Políticas de URL do Edge](https://learn.microsoft.com/deployedge/microsoft-edge-policies/urlblocklist) · [Políticas do Chrome](https://support.google.com/chrome/a/answer/9942583) · [Políticas do Firefox](https://firefox-admin-docs.mozilla.org/reference/policies/websitefilter/) · [Desinstalação do Roblox](https://en.help.roblox.com/hc/pt-br/articles/203312980-Como-Desinstalar-a-Roblox)

## Origem dos registros

A revisão de 9 de novembro de 2026 usa identificadores de serviços e listas publicadas por v2fly/domain-list-community e Sinfonietta/hostfiles, além de 183 domínios do levantamento de apostas da Secretaria de Prêmios e Apostas publicado em setembro de 2026. A classificação serve à política da escola. As origens e licenças acompanham o arquivo Python e o banco distribuído.
