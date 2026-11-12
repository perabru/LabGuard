# LabGuard gerenciado — Cliente Jogos 2.3 / Central 1.2

## Qual arquivo baixar

| Arquivo | Onde usar | Função |
|---|---|---|
| LabGuardTecnico.exe — Central 1.2 | Somente no PC administrador | Recebe os clientes, mostra avisos e envia as políticas. Não é o cliente do aluno. |
| LabGuard-Jogos.exe — Cliente 2.3 | Em cada PC dos alunos | Aplica bloqueios, fecha jogos reconhecidos e executa a limpeza autorizada. Precisa da Central para receber alterações e enviar avisos. |
| LabGuard-Gerenciado-Windows.zip | PC da TI ou pendrive de instalação | Contém os dois EXEs prontos, instruções e verificações. Extraia antes de executar. Não é um terceiro programa. |
| LabGuard-Setup.exe — rede 2.4.x | PC responsável pelo DNS | Filtro de domínios e painel de rede independente. Não recebe estes avisos sozinho e não substitui a Central/Cliente. |
| LabGuard-Desinstalador.exe | Cada PC do qual retirar o LabGuard | Remove instalações identificadas e restaura regras próprias quando possível. Não instala proteção. |
| Source code / código-fonte | Desenvolvimento e auditoria | Arquivos para estudar ou compilar. Não é o pacote pronto para uso. |

Windows 10/11 x64. O cliente usa .NET Framework 4.8 e Windows PowerShell 5.1. Os EXEs não precisam de Python instalado. Não desative antivírus ou UAC.

## Atualizar sem perder os vínculos

1. No PC administrador, abra o NOVO LabGuardTecnico.exe e use **Instalar / reparar**. Apenas Abrir painel não atualiza a cópia instalada. A migração mantém os cadastros e os vínculos existentes.
2. Em cada estação, abra o NOVO LabGuard-Jogos.exe a partir de Downloads, como administrador. Se já houver vínculo, use **Atualizar e manter vínculo** sem selecionar outro arquivo.
3. Se a limpeza antiga estiver em andamento, pause-a, deixe a operação concluir e execute novamente a atualização. Não use o desinstalador para uma atualização normal.
4. Atualize a página do administrador e confira a versão do cliente e a confirmação de Sites em **Computadores**. Publicar o download não instala a atualização remotamente.

## Primeira instalação

No administrador: informe o IPv4 real/reservado, a sub-rede autorizada e uma senha com pelo menos 12 caracteres. Abra o painel local em `http://127.0.0.1:8787/`. Em **Computadores → Vincular computador**, gere um JSON individual (uma estação; validade de uma hora).

Na estação: abra LabGuard-Jogos.exe, selecione o JSON, informe um nome técnico como LAB-01 e clique **Instalar e conectar**. Confirme a política. A limpeza pode excluir definitivamente jogos, saves e mundos: faça backup antes. Mantenha o aluno em uma conta padrão, não administrativa.

## Novidade: Sites rápidos → Bloquear tudo

O catálogo inclui Termo (`term.ooo`), Friv (`friv.com` e `friv.com.br`), Poki (`poki.com`, interpretação de Poke), Chess.com (`chess.com`) e YouTube. Joguester fica identificado como **Endereço pendente**, pois o domínio não foi confirmado; use **Editar endereço** para informar o link correto. Nenhum domínio é inventado.

**Bloquear tudo** solicita o bloqueio de todos os sites com endereço cadastrado nesta lista e do YouTube em todos os clientes 2.3 vinculados. NÃO corta toda a internet, NÃO muda as demais categorias do catálogo legado e NÃO ativa a remoção de jogos. Itens sem endereço continuam pendentes.

Há também **Bloquear**, **Liberar** e **Editar endereço** por site. Ao informar Joguester, salve com bloqueio marcado ou use Bloquear tudo depois. Até seis domínios por item, trinta no total; URLs HTTP/HTTPS são convertidas no domínio. Sem curinga global ou execução remota de comandos.

As regras cobrem domínios/subdomínios nos navegadores Chrome, Edge e Firefox. A confirmação significa que a configuração foi escrita, não que a navegação real de todos os perfis já foi testada. Reabra os navegadores e teste na conta do aluno. Sites já carregados, aplicações offline, outros navegadores, proxies e políticas externas podem interferir. O LabGuard não encerra o navegador nem apaga trabalhos das outras abas.

**Liberar** remove apenas regras ainda pertencentes a esta lista. Regras e exceções de outros administradores são preservadas. A lista antiga **Sites — Cliente 1.x** continua destinada ao cliente legado, não ao novo agente de jogos.

## Avisos e funcionamento

O cliente inicia com o Windows, sem abrir o painel administrativo na sessão do aluno. Permanece identificado na bandeja e no Windows. A limpeza ocorre a cada cinco minutos, o monitor verifica jogos conhecidos nominalmente a cada dois segundos e a comunicação com a Central acontece em torno de quinze segundos. Não se promete reconhecer todo jogo existente.

A Central mostra eventos de jogo encerrado, falhas, pausa e ausência de contato por mais de noventa segundos. Mantenha o painel aberto e autenticado para os avisos do navegador e autorize suas notificações. Ausência de contato também pode ser desligamento normal ou falha de rede.

A conexão usa HTTPS na porta TCP 8788 e certificado específico da Central. O painel administrativo é local na porta 8787. Não é necessário alterar DNS nem expor portas na internet para esse canal. A conexão não envia capturas, arquivos, senhas ou histórico de navegação.

Sem rede, permanece a última política local. O cliente mantém até 500 eventos por até 7 dias; a Central, até 10 mil eventos por até 7 dias. Credenciais ficam protegidas por Windows e permissões administrativas. Um administrador local pode alterar/desativar o programa.

## Conferir e solucionar

**Sites sem confirmação:** atualize ambos os EXEs; confira a linha Sites em Computadores. Cliente 2.2 ou legado 1.x não confirma a nova lista.

**Sem contato:** confira IP do administrador, rede autorizada, porta 8788, firewall e relógios. Não desative proteções globalmente.

**Joguester pendente:** informe o endereço real em Editar endereço. Não é um erro de conexão.

**Bloqueio não aparece no navegador:** reabra-o e confira `chrome://policy`, `edge://policy` ou `about:policies`, conforme o navegador. Exceções externas podem ter precedência.

**Remover o LabGuard:** use o desinstalador independente em cada PC, não no lugar do instalador. Ele reconhece o registro de propriedade das novas regras de navegador.

## Testes

A compilação exige testes de autenticação/CSRF, migração, preservação de vínculos, listas, bloqueio em lote, liberação individual, integração HTTPS C# e operações em Registro sintético. Inclui teste de interface em Edge. Nenhum computador real do laboratório é alterado pela compilação. Consulte VERIFICACAO.txt e SHA256SUMS.txt.
