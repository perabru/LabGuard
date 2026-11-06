# LabGuard Server para Windows e Linux

O modo servidor executa sem ambiente gráfico e oferece uma central web **somente no próprio servidor**, em `http://127.0.0.1:8765/`. Ele usa o gateway LabGuard existente para consultar a rede e aplicar as operações autorizadas. No Windows Server, ele é um serviço de administração; **não instala um firewall DNS nativo do Windows**. No Linux, o gateway de tráfego continua tendo instalação separada.

Esta interface HTTP local não foi projetada para publicação direta na internet ou em uma interface da LAN. O endereço de escuta é fixo em loopback. Para acesso remoto, use uma sessão administrativa no servidor ou um túnel SSH autenticado do sistema, com a mesma porta local. Não abra a porta 8765 no firewall ou no roteador.

## Pacotes

| Pacote | Conteúdo |
|---|---|
| Windows Server | `LabGuardServer.exe`, seus arquivos internos e `server/install-server.ps1` |
| Linux Server | Binário `LabGuardServer`, seus arquivos internos, unidade systemd e `server/install-server.sh` |

Extraia o pacote inteiro. O executável depende da pasta `_internal` ao lado dele. Mantenha as pastas `server` e `docs` do pacote.

## Configuração e credenciais

O comando de inicialização cria um modelo de configuração, dois hashes de credenciais em `secrets.json` e um arquivo privado `access-tokens.txt` para o administrador. Ele não mostra os tokens no terminal e não substitui uma configuração existente.

```bash
LabGuardServer init --directory /CAMINHO/PRIVADO
```

Edite `config.json` com os valores do gateway:

```json
{
  "version": 1,
  "port": 8765,
  "gateway": {
    "host": "192.168.50.1",
    "port": 22,
    "user": "labguard",
    "key_path": "/CAMINHO/PRIVADO/chave-do-servico",
    "known_hosts": "/CAMINHO/PRIVADO/known_hosts"
  }
}
```

Use os caminhos Windows correspondentes quando necessário, por exemplo `C:\\ProgramData\\LabGuardServer\\chave-do-servico`. A chave SSH deve ser exclusiva do serviço e já estar autorizada no comando restrito do gateway. Confira a impressão digital por um canal administrativo confiável antes de preencher `known_hosts`; não desabilite a verificação do host. O serviço não solicita senha da chave nem depende de uma sessão interativa de `ssh-agent`.

O modelo começa sem host/chave. O modo real recusa iniciar enquanto esses campos não forem configurados. É possível testar explicitamente sem rede:

```bash
LabGuardServer run --directory /CAMINHO/PRIVADO --demo
```

O painel identifica a demonstração. As regras de rede simuladas ficam na memória; os cadastros do banco de sites são persistentes no diretório privado, inclusive em demonstração. Use um diretório de configuração separado para testes, pois a primeira aplicação vincula o banco ao gateway correspondente.

## Windows Server

Use Windows Server com suporte à execução de aplicações x64 e Cliente OpenSSH disponível. Em um PowerShell elevado, dentro do pacote extraído:

```powershell
.\server\install-server.ps1
```

O instalador copia o pacote para `C:\Program Files\LabGuardServer`, cria os dados em `C:\ProgramData\LabGuardServer` e registra o serviço nativo **LabGuardServer** com a conta restrita **LocalService**. Ele não inicia o serviço sem `-Start`. Configure primeiro os campos SSH e permita que LocalService leia a chave e `known_hosts`; proteja esses arquivos contra leitura de outros usuários.

Depois de configurar:

```powershell
Start-Service LabGuardServer
Get-Service LabGuardServer
```

O arquivo `access-tokens.txt` fica restrito a Administradores e SYSTEM. O serviço lê apenas hashes de tokens para autenticar as solicitações. Os diretórios `logs` e `data` permitem escrita a LocalService; a aplicação não executa como administrador.

Para um teste isolado com dados fictícios, o instalador aceita `-Demo -Start`. A opção é explícita e não deve ser usada como configuração de produção.

Para remover o serviço sem apagar suas configurações:

```powershell
Stop-Service LabGuardServer
sc.exe delete LabGuardServer
```

Depois de confirmar que nenhum serviço usa os arquivos, as pastas de instalação e dados podem ser tratadas conforme a política do colégio. Guarde ou revogue as credenciais antes de transferir um servidor para outro responsável.

## Linux Server

Use uma distribuição compatível com o binário e systemd, com o cliente OpenSSH instalado. Dentro do pacote extraído:

```bash
sudo bash server/install-server.sh
```

O instalador cria o usuário de sistema `labguard-server`, instala em `/opt/labguard-server`, configura os dados privados em `/etc/labguard-server` e habilita `labguard-server.service`. Ele não inicia o serviço sem `--start`. Ajuste `config.json` e mantenha chave SSH e `known_hosts` em `/etc/labguard-server`, com proprietário `labguard-server` e modo `600`. A unidade protege o diretório de instalação e não acessa diretórios pessoais.

```bash
sudo systemctl start labguard-server
sudo systemctl status labguard-server
sudo journalctl -u labguard-server -n 30
```

O arquivo `access-tokens.txt` fica acessível somente a root. Configuração e hashes pertencem ao usuário do serviço e são privados. Os logs ficam em `/etc/labguard-server/logs` e o banco em `/etc/labguard-server/data/banlist.sqlite3`. A unidade systemd permite escrita somente nesses dois subdiretórios; o diretório `data` usa modo `700` e o banco usa `600`.

Para um teste isolado: `sudo bash server/install-server.sh --demo --start`. Para remover a inicialização automática sem apagar dados: `sudo systemctl disable --now labguard-server`.

## Uso do painel e permissões

Abra o painel no navegador do servidor e informe uma credencial de `access-tokens.txt`:

- **viewer:** consulta a saúde, máquinas, domínios, auditoria, eventos e banco de sites; pode exportar o cadastro.
- **admin:** também pode alterar os domínios, o perfil de IA, o corte de internet de uma máquina e os cadastros do banco, além de aplicar explicitamente a lista.

O token permanece somente na memória da aba. Sair, fechar a página ou ficar dez minutos sem interação limpa a credencial da interface. Isso não revoga o token de acesso emitido para a API. Para revogação, pare o serviço e substitua as credenciais com procedimento administrativo; não compartilhe uma credencial entre pessoas sem avaliar a auditoria necessária.

As alterações na rede exigem estado recente do gateway. Se a atualização falhar, o painel bloqueia novas ações de rede até uma leitura válida. O banco local continua disponível para consulta e edição autorizada. O servidor valida novamente permissões, formato e saúde do serviço necessário. O gateway continua sendo responsável por conferir IPs protegidos, domínios e limites da sub-rede.

## Banco de sites

A seção **Banco de sites** mantém domínios nas categorias Jogos, IA, Adultos e Outros, com ativação individual, observações e controle de revisão para evitar sobrescrever uma edição simultânea. Pesquise pelo domínio e filtre por categoria ou ativação. A consulta exibe até mil resultados; refine os filtros para bases maiores. O arquivo CSV exporta todos os cadastros ativos e inativos que não foram excluídos. A importação recebe até cem domínios por lote, dentro do limite de 8 KiB; não altera registros já existentes.

Salvar, importar, desativar ou excluir um cadastro **não altera a rede**. O botão **Aplicar lista** pede confirmação e inicia um lote em segundo plano, com até vinte alterações por padrão. A interface acompanha o resultado, apresenta erros e pendências e não reaplica automaticamente os itens restantes. Aguarde o lote terminar antes de editar o cadastro; sair do painel não cancela um lote já autorizado. Ao encerrar o serviço, o lote termina a operação em andamento e interrompe a sequência entre domínios.

A sincronização remove somente regras que o próprio banco criou e cuja identidade continua confirmada. Regras manuais preexistentes e regras do perfil de IA são preservadas. Um resultado de rede incerto fica registrado para revisão; não existe reversão global das alterações já confirmadas. O primeiro lote vincula o banco à identidade do gateway e à sub-rede. Use outro banco para outro gateway, inclusive ao trocar demonstração por ambiente real.

Faça backup com o serviço parado, incluindo o diretório `data` completo, configuração e chaves sob a política de acesso do colégio. Não copie apenas o arquivo SQLite enquanto estiver em uso: arquivos auxiliares de transação podem fazer parte do estado. Nenhum programa precisa ser instalado nas máquinas dos alunos; o gateway deve estar no caminho do tráfego e configurado conforme o guia de instalação.

Rotas autenticadas: `GET /api/banlist` (filtros `q`, `category` e `enabled=true|false`), `GET /api/banlist/export` e `GET /api/banlist/sync-status` aceitam consulta. `POST /api/banlist/upsert`, `/delete`, `/import` e `/sync` exigem administração. O último inicia um lote e retorna HTTP 202; acompanhe o estado a cada três segundos. Todos os corpos JSON respeitam o limite de 8 KiB, e os tokens vão exclusivamente no cabeçalho `Authorization: Bearer ...`.

## Mapa, relatórios e controle por endereço

Em **Mapa e relatórios**, use **Carregar mapa** e os downloads **Mapa SVG**, **HTML**, **CSV** ou **PDF**. O desenho representa relações lógicas inferidas do inventário. Não descobre cabos, portas de switch, SSID ou AP; informações Wi-Fi só aparecem quando a fonte as fornece. Consulte [REGRAS_IP_MAC.md](REGRAS_IP_MAC.md) para topologia em ponte, limites de NAT/MAC privado e independência dos escopos.

As exportações usam exclusivamente a última amostra já recebida, sem iniciar SSH ou alterar a rede. Atualize o gateway antes da primeira exportação. Leituras antigas continuam disponíveis com identificação de fonte desatualizada. O cabeçalho `X-LabGuard-Snapshot-State` informa `fresh` ou `stale`. São permitidos até 500 registros de inventário, 1.000 eventos DNS, 1.000 regras diretas e 4 MiB por resposta; SVG mostra até 200 registros e o mapa do PDF até 12. Os relatórios desktop têm limites próprios maiores. A geração é serializada e os arquivos temporários são privados, removidos ao final.

`GET /api/network-map` retorna SVG e `GET /api/report?format=html|csv|pdf` retorna o relatório; ambos permitem viewer/admin e downloads autenticados. Formato desconhecido, parâmetros adicionais e tokens na URL são recusados. A dependência ReportLab acompanha os pacotes; a execução por código-fonte precisa das dependências em `requirements.txt` para gerar PDF.

Em **Máquinas e endereços**, admin pode criar ou retirar regras diretas de IP/MAC. A API existente recebe `set_address_block` com `kind`, `address` e `blocked`. IPv4, MAC unicast e booleanos são validados, assim como leitura recente, saúde de firewall/encaminhamento e proteção administrativa. Novos bloqueios exigem alvo observado; uma regra persistida pode ser retirada sem observação atual da estação. Liberar IP não libera MAC ou suspensão por máquina automaticamente. O gateway reconfere os parâmetros e a sub-rede antes da alteração. Os controles cortam encaminhamento de internet e não desassociam clientes de um rádio Wi-Fi.

## Proteções e limites

- Escuta apenas em loopback, com verificação de Host e Origin, sem CORS.
- Tokens de alta entropia; hashes SHA-256 no arquivo lido pelo serviço; comparações em tempo constante.
- Permissões de consulta/administração separadas, lista de operações permitidas e confirmação visual de alterações.
- Limites de requisições, tentativas inválidas, corpo de 8 KiB, respostas de 4 MiB, tempo de leitura e conexões simultâneas; uma exportação acima desse limite retorna erro.
- Política de conteúdo, bloqueio de enquadramento, proibição de cache e ausência de código de terceiros na interface.
- Logs locais com rotação e sem tokens, senhas ou cabeçalhos de autorização.

Essas proteções não equivalem a certificação, teste de invasão ou publicação segura de uma API em rede não confiável. Um usuário com privilégio de administrador/root pode ler ou alterar arquivos do servidor. O histórico DNS continua sendo uma amostra de solicitações, sem comprovar visita do aluno ou revelar conteúdo HTTPS.

## Verificações

`LabGuardServer --self-test --output resultado.json` verifica recursos do pacote sem iniciar rede ou Tk. `GET /healthz` apenas confirma que o processo HTTP está ativo; não comprova comunicação com o gateway nem que as regras do laboratório foram aplicadas.

Os testes automatizados verificam autenticação, permissões, bloqueio de origem indevida, estado desatualizado, limites e leitura de arquivos. A validação de uma rede real precisa ser feita conforme o guia de instalação do gateway.

Referências: [HTTP server do Python](https://docs.python.org/3/library/http.server.html), [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager), [StartServiceCtrlDispatcherW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw).
