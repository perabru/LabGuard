# LabGuard Central 1.0.0 — técnico do laboratório

Controle os sites de todas as estações vinculadas a partir de um painel com senha. A Central funciona no PC do técnico; o **LabGuard Cliente 1.2.0** aplica as regras no Windows dos alunos e informa a revisão aplicada.

## Downloads

- [LabGuardTecnico.exe — PC do técnico](https://github.com/perabru/LabGuard/releases/download/central-v1.0.0/LabGuardTecnico.exe)
- [LabGuardCliente.exe 1.2.0 — PCs dos alunos](https://github.com/perabru/LabGuard/releases/download/cliente-v1.2.0/LabGuardCliente.exe)
- [Código-fonte completo da Central e do Cliente](https://github.com/perabru/LabGuard/releases/download/central-v1.0.0/LabGuardCentral-Fonte.zip)
- [Guia ilustrado de início](https://perabru.github.io/LabGuard/tecnico/)

Os dois executáveis incluem Python. Use Windows 10/11 x64 e uma conta administrativa da TI para instalar. Reserve um IPv4 fixo para o computador do técnico no DHCP do roteador.

Para gerar os executáveis a partir do pacote fonte, instale Python 3.12 x64 com Tcl/Tk e abra `GERAR_EXECUTAVEIS_WINDOWS.bat` na pasta principal. O script instala as dependências em um ambiente local, executa os testes e gera `Executaveis/LabGuardTecnico.exe` e `Executaveis/LabGuardCliente.exe`.

## 1. Preparar o computador do técnico

1. Abra **LabGuardTecnico.exe** e confirme o pedido de administrador do Windows.
2. Informe o IPv4 real deste computador e a rede autorizada dos alunos em CIDR. Exemplo: IP `192.168.15.10`, rede `192.168.15.0/24`, **somente se forem os endereços reais do seu laboratório**. Consulte `ipconfig` ou a configuração de rede do Windows; não copie um IP de exemplo sem conferir.
3. Crie e confirme uma senha de pelo menos 12 caracteres.
4. Clique em **Instalar e abrir painel**. A tarefa identificada **LabGuardCentral** inicia imediatamente e no boot do Windows. A instalação autoriza apenas a conexão TCP da rede informada à porta 8788 deste aplicativo.
5. O navegador abre `http://127.0.0.1:8787/`. Entre com a senha que acabou de criar.

O painel abre no próprio PC do técnico. Os clientes se comunicam pela rede local com `https://IP-DO-TECNICO:8788`, usando o certificado específico da Central. Não é necessário configurar WinRM, encaminhar portas na internet ou mudar o DNS do roteador. O PC da TI precisa estar ligado para distribuir novas alterações.

## 2. Vincular cada computador de aluno

1. No painel do técnico, abra **Computadores** e gere um **arquivo de vínculo**. Cada arquivo serve para **uma estação**, por **uma hora**.
2. Leve o arquivo para o computador que receberá o cliente, por exemplo em um pendrive administrado pela TI.
3. Abra o **LabGuardCliente.exe 1.2.0** como administrador. Em **Jogos**, revise as opções de bloqueio e desinstalação; a política inicial local inclui a remoção do Roblox identificado. Configure essas opções conforme a escola e clique em **Instalar e proteger agora**. Se já houver uma instalação 1.1.0, abra o novo EXE: a importação do vínculo atualiza a cópia instalada antes de conectar à Central.
4. Na aba **Técnico**, importe o arquivo de vínculo e confirme. Apague a cópia de transporte depois que o vínculo for concluído.
5. Aguarde o computador aparecer na Central e confirmar a revisão atual. A consulta é periódica, em torno de 15 segundos; a confirmação de aplicação pode chegar no ciclo seguinte.
6. Faça um teste no navegador da conta de aluno: um domínio bloqueado e outro liberado. Reabra o navegador para que a política seja atualizada, se necessário.

Gere outro arquivo para a próxima estação. O aluno deve usar uma conta padrão; mantenha a conta administrativa sob controle da TI.

## 3. Adicionar, bloquear, liberar e excluir

| Ação | Resultado |
|---|---|
| Adicionar | Cadastra um domínio, uma categoria e a ação desejada. Digite, por exemplo, `poki.com`, sem caminho de página. |
| Bloquear | Envia o bloqueio do domínio e dos subdomínios aos navegadores gerenciados. |
| Liberar | Cria uma exceção para o domínio e seus subdomínios. Ela pode liberar um subdomínio de um domínio bloqueado. |
| Excluir | Retira aquele cadastro. Uma regra de domínio pai pode continuar valendo; use **Liberar** quando quiser uma exceção explícita. |
| Pausar categoria | Suspende os registros daquela categoria até que ela seja ativada novamente. |

Liberar um domínio pai suspende, na política efetiva, os bloqueios de seus filhos. Os cadastros dos filhos permanecem no banco e voltam a valer se a liberação for removida. Para bloquear um filho de um domínio liberado, remova ou bloqueie primeiro a liberação do pai; essa regra mantém a mesma interpretação entre os navegadores.

A Central começa com os 831 domínios do catálogo do cliente e permite até 975 regras ativas para manter margem nos limites das políticas dos navegadores. Liberar um site não desativa o controle de execução de um jogo instalado. Um serviço pode usar vários domínios de autenticação, arquivos e vídeo; libere também os recursos necessários à aula.

## 4. Acompanhar os computadores

O painel diferencia revisão **confirmada**, atualização **pendente**, estação **offline**, aplicação com **erro** e vínculo **revogado**. O status confirmado informa que o agente aplicou suas regras de navegador e hosts; não é uma comprovação de navegação real em todos os perfis. O histórico mostra alterações administrativas, sem registrar páginas visitadas pelos alunos.

Se a Central ou a rede ficar indisponível, a estação mantém a última política válida. Quando a conexão voltar, receberá as alterações pendentes. Revogar uma estação impede novas sincronizações e preserva a última regra local; para voltar à configuração independente, use **Desvincular** na aba Técnico do cliente, como administrador. Para retirar a proteção, use a desinstalação do próprio cliente.

Enquanto vinculada, a estação recebe da Central a lista de sites completa. O catálogo local e as listas locais de sites voltam a valer após a desvinculação. As opções locais de jogos continuam sendo administradas na própria estação.

## Operação e recuperação

- Para abrir o painel novamente, abra **LabGuardTecnico.exe → Abrir painel**.
- **Parar central** interrompe a distribuição até que seja iniciada novamente. A tarefa continua registrada para o próximo boot.
- **Remover inicialização automática** para a Central e remove a sua regra de entrada no firewall. Mantém os cadastros para reinstalação.
- Os arquivos da Central ficam em `%ProgramFiles%\LabGuardCentral`, acessíveis apenas à administração e ao sistema. Faça backup dessa pasta com a tarefa parada; ela contém banco, certificado e credenciais. Restaure somente na máquina administrativa de confiança, mantendo o IP configurado.
- Uma mudança do IP do técnico exige atualizar a configuração/certificado e refazer os vínculos. Reserve o IP antes da implantação. Esta versão não inclui recuperação automática de senha; mantenha a senha administrativa no cofre da TI.
- Confira rede, IP, isolamento entre computadores, relógio do Windows e a porta TCP 8788 se o vínculo falhar. O arquivo `central-erro.log` é criado se a inicialização do serviço falhar.

## Executar a Central pelo Python

O fonte usa Python 3.10+ e a dependência indicada em `central/requirements.txt`. O executável é o caminho recomendado para instalação com início automático no Windows. A estrutura `central/` e `client/` deve permanecer junta.

```powershell
python -m pip install -r central/requirements.txt
python central/labguard_tecnico.py init --directory ./dados-central --host 192.168.15.10 --network 192.168.15.0/24
python central/labguard_tecnico.py run --directory ./dados-central
```

O comando `init` pede a senha de forma interativa. No Windows, execute em console administrativo e use uma pasta protegida contra escrita de alunos. No Linux, proteja a pasta de dados e libere a porta TCP 8788 somente para a rede autorizada. A versão inicial oferece instalação automática apenas no Windows.

Implantação do cliente pelo console administrativo, com um vínculo exclusivo por estação:

```powershell
.\LabGuardCliente.exe parear --vinculo .\vinculo.json --sim --saida .\resultado-vinculo.json
.\LabGuardCliente.exe sincronizar --saida .\resultado-sincronizacao.json
.\LabGuardCliente.exe desvincular --sim --saida .\resultado-desvinculacao.json
```

Os arquivos de saída precisam ser novos. Para Python, use o interpretador confiável instalado para todos os usuários e substitua o EXE pelo caminho do fonte, conforme o [guia do cliente](../client/README.md).

## Alcance e validação

O cliente aplica políticas locais de Edge, Chrome e Firefox e entradas exatas no arquivo hosts. Não inspeciona HTTPS e não transforma o PC do técnico em um roteador de tráfego. Políticas corporativas preexistentes, perfis pessoais do Edge, aplicativos com resolvedor próprio, VPN, conexões por IP e jogos offline podem exigir controles complementares da instituição. A Central administra sites; não executa comandos arbitrários nas estações.

O fluxo de compilação verifica autenticação, CSRF, TLS, cadastro/remoção/liberação/bloqueio, expiração e revogação de vínculos, persistência, limite de regras e comportamento offline. O teste Windows instala os EXEs em uma VM descartável, confere as regras reais do registro e o retorno do cliente antes de publicar o download.

Referências oficiais: [Microsoft Edge: URLAllowlist](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/urlallowlist), [URLBlocklist](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/urlblocklist), [Firefox: WebsiteFilter](https://firefox-admin-docs.mozilla.org/reference/policies/websitefilter/).
