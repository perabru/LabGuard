# LabGuard Server para Windows e Linux

O modo servidor executa sem ambiente gráfico e oferece uma central web **somente no próprio servidor**, em `http://127.0.0.1:8765/`. O computador continua usando sua conexão de rede existente: não precisa ficar entre o roteador e os alunos nem receber um segundo cabo. A inicialização padrão usa **observação local, sem alterações na rede**.

Para controlar a rede, o servidor administra diretamente um **RouterOS compatível por REST HTTPS**, com credenciais autorizadas e requisitos confirmados. Outros equipamentos não recebem automaticamente essas capacidades por pertencerem a uma marca conhecida. A instalação antiga de gateway Linux por SSH permanece como opção avançada de compatibilidade, sem ser requisito da observação ou do controle direto.

Esta interface HTTP local não foi projetada para publicação direta na internet ou em uma interface da LAN. O endereço de escuta é fixo em loopback. Para acesso remoto, use uma sessão administrativa no servidor ou um túnel SSH autenticado do sistema, com a mesma porta local. Não abra a porta 8765 no firewall ou no roteador.

## Pacotes

| Pacote | Conteúdo |
|---|---|
| Windows Server | `LabGuardServer.exe`, seus arquivos internos e `server/install-server.ps1` |
| Linux Server | Binário `LabGuardServer`, seus arquivos internos, unidade systemd e `server/install-server.sh` |

Extraia o pacote inteiro. O executável depende da pasta `_internal` ao lado dele. Mantenha as pastas `server` e `docs` do pacote.

## Configuração e credenciais

O comando de inicialização cria um modelo de observação, dois hashes de credenciais em `secrets.json` e um arquivo privado `access-tokens.txt` para o administrador. Ele não mostra os tokens no terminal e não substitui uma configuração existente.

```bash
LabGuardServer init --directory /CAMINHO/PRIVADO
```

O `config.json` inicial permite começar sem configurar um equipamento:

```json
{
  "version": 1,
  "port": 8765,
  "controller": {"kind": "observation"}
}
```

Inicie o processo e abra o navegador local:

```bash
LabGuardServer run --directory /CAMINHO/PRIVADO
```

A observação usa somente as evidências disponíveis ao computador. Não representa inventário completo do roteador, histórico DNS de todos os alunos ou presença física confirmada. Controles de rede ficam desabilitados; o cadastro local de sites e os relatórios da amostra continuam disponíveis conforme o papel de acesso.

Para treinar com dados fictícios, selecione explicitamente demonstração em outro diretório:

```bash
LabGuardServer run --directory /CAMINHO/PRIVADO --demo
```

O painel identifica a demonstração. As regras de rede simuladas ficam na memória; os cadastros do banco de sites são persistentes no diretório privado, inclusive em demonstração. Use um diretório de configuração separado para testes, pois a primeira aplicação vincula o banco à fonte correspondente.

## Estações no painel web local

Com o filtro DNS ativo e o acesso administrativo do LabGuard, abra **Estações** no navegador da TI. Para Windows, informe o IPv4 privado do alvo no segmento autorizado e a conta que tem acesso WinRM HTTPS ao computador. O certificado da estação precisa ser confiável e apresentar o IPv4 usado no SAN. Se necessário, disponibilize a CA institucional em `station-ca.pem` na pasta privada de configuração do servidor.

1. Em **Testar DNS**, confira os resultados direto e padrão da estação para o código TXT atual.
2. Se o direto passar e o padrão divergir, use **Preparar alteração**. Confira o alvo, o adaptador, os DNS IPv4 e IPv6 e o efeito nos nomes internos.
3. Confirme **Aplicar DNS**. A configuração anterior fica na estação Windows. A verificação usa o caminho DNS padrão da estação após a alteração. Para reverter a mudança correspondente, confirme **Restaurar DNS** no mesmo alvo.

Em um PC de TI com Windows, **Preparar nesta estação** usa um canal WMI/DCOM já autorizado com Kerberos e privacidade de pacotes para preparar WinRM HTTPS no alvo. Informe IPv4, FQDN canônico e conta de domínio, confirme o equipamento e confira o resultado do teste HTTPS. O processo exige um computador membro do domínio com o certificado de máquina descrito abaixo.

**Preparar acesso remoto** fornece um script PowerShell personalizado com o IP de gestão. A TI o distribui a uma estação Windows piloto pela GPO ou MDM em contexto de computador. Antes da implantação, prepare no repositório pessoal de certificados da máquina um certificado confiável com chave privada, autenticação de servidor, nome do host e SAN que inclua o IPv4 do alvo. A interface precisa ter perfil Domínio ou Privado. O script prepara o serviço WinRM HTTPS e a permissão de firewall TCP 5986 para o IP da TI. Consulte o [capítulo 11 do manual](MANUAL_DO_USUARIO_V2.md) para a sequência completa.

## Equipamento RouterOS por HTTPS

Prepare previamente REST HTTPS no RouterOS compatível, uma conta autorizada e um certificado válido para o nome/IP usado. Use a rede de gestão da escola e restrinja o acesso. Não desative a validação TLS nem exponha a administração à internet. O programa não habilita o serviço remoto, não descobre credenciais e não troca o firmware.

Edite somente `config.json` com os parâmetros públicos. Exemplo inicialmente em consulta:

```json
{
  "version": 1,
  "port": 8765,
  "controller": {
    "kind": "routeros",
    "host": "192.168.1.1",
    "port": 443,
    "user": "labguard-read",
    "ca_file": "/CAMINHO/PRIVADO/ca-do-colegio.pem",
    "protected_ips": ["192.168.1.10"],
    "protected_macs": [],
    "lab_cidr": "192.168.1.0/24",
    "wan_interface_list": "WAN",
    "manage_rules": false
  }
}
```

No Windows, use caminhos JSON com barras invertidas escapadas, por exemplo `C:\\ProgramData\\LabGuardServer\\ca-do-colegio.pem`. A CA pode ficar vazia quando a cadeia já é confiável pelo sistema. Confirme a identidade do equipamento com a TI; um arquivo CA incorreto não deve ser contornado ignorando certificados.

A senha pertence **somente a `controller_password` em `secrets.json`**, que já possui esse campo vazio. Preserve os hashes em `tokens` e a versão do arquivo; altere apenas o campo necessário com um editor local autorizado. Não coloque `password` em `config.json`, nas observações do banco, na URL ou em comandos do terminal. A configuração recusa senha no objeto público do controlador. O arquivo privado não é criptografado; mantenha as permissões do instalador e proteja seus backups.

`manage_rules: false` mantém a conexão somente leitura mesmo que uma resposta indevida declare capacidades de alteração. Para autorizar controle, a TI deve revisar a conta, a rede, IPs/MACs protegidos, lista WAN, DNS, IPv6 e FastTrack. Marcar `manage_rules: true` **não garante** que o equipamento está pronto: as capacidades retornadas e a saúde confirmada continuam sendo obrigatórias. Um requisito não atendido mantém o recurso desabilitado. Comece com uma estação de teste e confira cada alteração antes de liberar o laboratório.

## Compatibilidade com o gateway SSH antigo

Configurações antigas com o objeto `gateway`, sem `controller`, continuam aceitas como modo `legacy`. Elas ainda precisam de host, porta, usuário, chave privada e `known_hosts` válidos. O servidor não migra automaticamente uma instalação antiga para observação, nem desativa suas regras.

Use esse modo apenas se já administra um gateway LabGuard dedicado e deseja mantê-lo. A chave deve ser exclusiva do serviço, autorizada no comando restrito, e a impressão digital conferida por um canal confiável. OpenSSH e os arquivos de chave/`known_hosts` só são necessários para essa opção. O serviço não pede senha de chave nem depende do agente SSH interativo do professor. Consulte o guia antigo de gateway para instalação e recuperação; ele não é requisito da arquitetura direta.

## Windows Server

Use Windows Server com suporte à execução de aplicações x64. Cliente OpenSSH é necessário somente para o gateway SSH opcional. Em um PowerShell elevado, dentro do pacote extraído:

```powershell
.\server\install-server.ps1
```

O instalador copia o pacote para `C:\Program Files\LabGuardServer`, cria os dados em `C:\ProgramData\LabGuardServer` e registra o serviço nativo **LabGuardServer** com a conta restrita **LocalService**. Ele não inicia o serviço sem `-Start`. A observação padrão pode iniciar imediatamente. Para RouterOS, configure o controlador e o segredo privado; permita que LocalService leia a CA, quando necessária. Para o modo SSH opcional, permita leitura da chave e de `known_hosts`, mantendo esses arquivos protegidos.

Para iniciar ou consultar:

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

Use uma distribuição compatível com o binário e systemd. O cliente OpenSSH é necessário somente para o gateway antigo opcional. Dentro do pacote extraído:

```bash
sudo bash server/install-server.sh
```

O instalador cria o usuário de sistema `labguard-server`, instala em `/opt/labguard-server`, configura os dados privados em `/etc/labguard-server` e habilita `labguard-server.service`. Ele não inicia o serviço sem `--start`. A observação padrão está pronta para iniciar. Para equipamento direto, ajuste `config.json` e o segredo privado. Mantenha a CA necessária em local legível pelo serviço; se usar o gateway SSH opcional, mantenha chave e `known_hosts` em `/etc/labguard-server`, com proprietário `labguard-server` e modo `600`. A unidade protege o diretório de instalação e não acessa diretórios pessoais.

```bash
sudo systemctl start labguard-server
sudo systemctl status labguard-server
sudo journalctl -u labguard-server -n 30
```

O arquivo `access-tokens.txt` fica acessível somente a root. Configuração e hashes pertencem ao usuário do serviço e são privados. Os logs ficam em `/etc/labguard-server/logs` e o banco em `/etc/labguard-server/data/banlist.sqlite3`. A unidade systemd permite escrita somente nesses dois subdiretórios; o diretório `data` usa modo `700` e o banco usa `600`.

Para um teste isolado: `sudo bash server/install-server.sh --demo --start`. Para remover a inicialização automática sem apagar dados: `sudo systemctl disable --now labguard-server`.

## Uso do painel e permissões

Abra o painel no navegador do servidor e informe uma credencial de `access-tokens.txt`:

- **viewer:** consulta as informações que a fonte disponibiliza e o banco local; pode exportar o cadastro e os relatórios.
- **admin:** também pode editar o banco local e executar somente as alterações de rede explicitamente suportadas pelo equipamento, com requisitos confirmados.

O token permanece somente na memória da aba. Sair, fechar a página ou ficar dez minutos sem interação limpa a credencial da interface. Isso não revoga o token de acesso emitido para a API. Para revogação, pare o serviço e substitua as credenciais com procedimento administrativo; não compartilhe uma credencial entre pessoas sem avaliar a auditoria necessária.

O painel diferencia `observation` (evidências locais sem controles), `equipment` (equipamento direto), `gateway` (instalação SSH antiga) e `demo` (dados fictícios). Botões dependem de capacidades booleanas explícitas, papel de administrador, leitura recente de até vinte segundos e saúde dos serviços necessários. Capacidade ausente ou com tipo inválido é tratada como indisponível. Observação e `manage_rules: false` nunca autorizam alterações de rede.

As capacidades são `inventory`, `domain_filtering`, `device_internet_cut`, `address_blocking`, `ai_block`, `dns_history` e `port_control`. DNS precisa estar confirmado para domínios/IA; firewall e encaminhamento para cortes de internet. Se a atualização falhar, novas alterações são bloqueadas até uma leitura válida. O banco local continua disponível para consulta e edição autorizada. O adaptador confere novamente os requisitos e o alvo antes de alterar o equipamento. Um inventário disponível não implica histórico DNS ou capacidade de bloqueio.

## Banco de sites

A seção **Banco de sites** mantém domínios nas categorias Jogos, IA, Adultos e Outros, com ativação individual, observações e controle de revisão para evitar sobrescrever uma edição simultânea. Pesquise pelo domínio e filtre por categoria ou ativação. A consulta exibe até mil resultados; refine os filtros para bases maiores. O arquivo CSV exporta todos os cadastros ativos e inativos que não foram excluídos. A importação recebe até cem domínios por lote, dentro do limite de 8 KiB; não altera registros já existentes.

Salvar, importar, desativar ou excluir um cadastro **não altera a rede**. **Aplicar lista no equipamento** exige suporte confirmado a filtro de domínios e DNS saudável. Em observação ou consulta somente leitura, esse botão fica desabilitado. Quando disponível, ele pede confirmação e inicia um lote em segundo plano, com até vinte alterações por padrão. A interface acompanha o resultado, apresenta erros e pendências e não reaplica automaticamente os itens restantes. Aguarde o lote terminar antes de editar o cadastro; sair do painel não cancela um lote já autorizado. Ao encerrar o serviço, o lote termina a operação em andamento e interrompe a sequência entre domínios.

A sincronização remove somente regras que o próprio banco criou e cuja identidade continua confirmada. Regras manuais preexistentes e regras do perfil de IA são preservadas. Um resultado de rede incerto fica registrado para revisão; não existe reversão global das alterações já confirmadas. O primeiro lote vincula o banco à identidade da fonte e à rede. Use outro banco para outro equipamento, inclusive ao trocar demonstração por ambiente real.

Faça backup com o serviço parado, incluindo o diretório `data` completo e arquivos privados sob a política de acesso do colégio. Não copie apenas o arquivo SQLite enquanto estiver em uso: arquivos auxiliares de transação podem fazer parte do estado. O PC de gestão não encaminha o tráfego; os controles diretos dependem de o equipamento compatível controlar a saída dos clientes.

Rotas autenticadas: `GET /api/banlist` (filtros `q`, `category` e `enabled=true|false`), `GET /api/banlist/export` e `GET /api/banlist/sync-status` aceitam consulta. `POST /api/banlist/upsert`, `/delete`, `/import` e `/sync` exigem administração. O último inicia um lote e retorna HTTP 202; acompanhe o estado a cada três segundos. Todos os corpos JSON respeitam o limite de 8 KiB, e os tokens vão exclusivamente no cabeçalho `Authorization: Bearer ...`.

## Mapa, relatórios e controle por endereço

Em **Mapa e relatórios**, use **Carregar mapa** e os downloads **Mapa SVG**, **HTML**, **CSV** ou **PDF**. O desenho representa relações lógicas inferidas do inventário. Não descobre cabos, portas de switch, SSID ou AP; informações Wi-Fi só aparecem quando a fonte as fornece. Consulte [REGRAS_IP_MAC.md](REGRAS_IP_MAC.md) para topologia em ponte, limites de NAT/MAC privado e independência dos escopos.

As exportações usam exclusivamente a última amostra já recebida, sem consultar novamente o equipamento nem alterar a rede. Atualize a fonte antes da primeira exportação. Leituras antigas continuam disponíveis com identificação de fonte desatualizada. O cabeçalho `X-LabGuard-Snapshot-State` informa `fresh` ou `stale`. São permitidos até 500 registros de inventário, 1.000 eventos DNS, 1.000 regras diretas e 4 MiB por resposta; SVG mostra até 200 registros e o mapa do PDF até 12. Os relatórios desktop têm limites próprios maiores. A geração é serializada e os arquivos temporários são privados, removidos ao final. Em observação, a exportação não transforma evidências locais em inventário completo ou histórico DNS de todos os computadores.

`GET /api/network-map` retorna SVG e `GET /api/report?format=html|csv|pdf` retorna o relatório; ambos permitem viewer/admin e downloads autenticados. Formato desconhecido, parâmetros adicionais e tokens na URL são recusados. A dependência ReportLab acompanha os pacotes; a execução por código-fonte precisa das dependências em `requirements.txt` para gerar PDF.

Em **Máquinas e endereços**, admin pode criar ou retirar regras diretas de IP/MAC somente quando `address_blocking` está confirmado. A API recebe `set_address_block` com `kind`, `address` e `blocked`. IPv4, MAC unicast e booleanos são validados, assim como leitura recente, saúde de firewall/encaminhamento e proteção administrativa. Novos bloqueios exigem alvo observado; uma regra persistida pode ser retirada sem observação atual da estação. Liberar IP não libera MAC ou suspensão por máquina automaticamente. O adaptador reconfere os parâmetros e a rede antes da alteração. Os controles não desassociam clientes de um rádio Wi-Fi.

## Proteções e limites

- Escuta apenas em loopback, com verificação de Host e Origin, sem CORS.
- Tokens de alta entropia; hashes SHA-256 no arquivo lido pelo serviço; comparações em tempo constante.
- Permissões de consulta/administração separadas, lista de operações permitidas e confirmação visual de alterações.
- Limites de requisições, tentativas inválidas, corpo de 8 KiB, respostas de 4 MiB, tempo de leitura e conexões simultâneas; uma exportação acima desse limite retorna erro.
- Política de conteúdo, bloqueio de enquadramento, proibição de cache e ausência de código de terceiros na interface.
- Logs locais com rotação e sem tokens, senhas ou cabeçalhos de autorização.

Essas proteções não equivalem a certificação, teste de invasão ou publicação segura de uma API em rede não confiável. Um usuário com privilégio de administrador/root pode ler ou alterar arquivos do servidor. O histórico DNS continua sendo uma amostra de solicitações, sem comprovar visita do aluno ou revelar conteúdo HTTPS.

## Verificações

`LabGuardServer --self-test --output resultado.json` verifica recursos do pacote sem iniciar rede ou Tk. `GET /healthz` apenas confirma que o processo HTTP está ativo; não comprova comunicação com um equipamento nem que as regras do laboratório foram aplicadas.

Os testes automatizados verificam autenticação, permissões, capacidades ausentes ou somente leitura, bloqueio de origem indevida, estado desatualizado, limites e leitura de arquivos. Eles usam respostas simuladas. A operação real precisa ser homologada no equipamento/modelo/firmware da escola, começando por uma estação de teste.

Referências: [HTTP server do Python](https://docs.python.org/3/library/http.server.html), [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager), [StartServiceCtrlDispatcherW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw).
