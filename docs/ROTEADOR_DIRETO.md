# Controle direto de RouterOS 7

O painel pode funcionar em um computador conectado à rede, sem ficar no caminho dos alunos. Neste modo ele envia comandos à API do **roteador que realmente encaminha o tráfego**. Estar na mesma rede não permite interceptar outro computador. O adaptador implementado é para MikroTik RouterOS 7 com REST HTTPS; não representa suporte universal a modems Vivo, switches ou outros fabricantes.

## Preparação pelo responsável da rede

O roteador deve oferecer REST pelo serviço HTTPS `www-ssl`, com certificado confiável e usuário autorizado a consultar os menus necessários. Para alterar regras, esse usuário também precisa da política de escrita correspondente. Use uma conta dedicada e restrinja o serviço à rede de administração. O aplicativo não ativa HTTPS, não muda usuários, certificados, DNS, DHCP, IPv6, aceleração ou regras gerais do equipamento.

Informe o **IP literal** e a porta HTTPS do roteador, usuário, senha e, quando necessário, o arquivo da autoridade certificadora. O certificado precisa validar esse IP. Não há opção de ignorar a verificação TLS. Nomes DNS não são aceitos neste adaptador para evitar uma resolução sem prazo controlável. Proxies de ambiente e redirecionamentos HTTP não são usados.

A conexão começa com `manage_rules=False`, em modo de consulta. Ativar a autorização de gerenciar regras permite somente as funções cujas condições também foram confirmadas no próprio roteador. Permissão de escrita sozinha não torna uma configuração incompatível em segura.

## O que aparece no painel

O inventário combina concessões DHCP e registros ARP. Cada cliente informa a evidência observada; isso não comprova que esteja usando internet naquele instante. IP e MAC podem mudar ou ser alterados pelo dispositivo. Conflitos de identidade impedem novos bloqueios.

O adaptador não consulta histórico DNS por cliente, conexões individuais, portas físicas nem registros de rádio/CAPsMAN. Os campos `events` e `connections` ficam vazios, acompanhados de aviso de indisponibilidade. SSID, AP e identificação Wi-Fi ficam desconhecidos; não são inferidos de nomes ou endereços MAC. Essas lacunas não significam ausência de navegação.

O PC de administração é identificado pelo endereço local da conexão HTTPS. Esse IP, seu MAC observado, os IPs/MACs do próprio roteador e a lista adicional de protegidos não podem receber novos cortes. Se o IP administrativo não puder ser confirmado, os cortes ficam indisponíveis.

## Pré-condições dos cortes

O laboratório precisa corresponder a uma única sub-rede IPv4 privada. Ela pode ser informada em `lab_cidr`; quando o campo está vazio, só é adotada automaticamente se houver uma única rede DHCP identificável. Redes ambíguas permanecem em consulta. O DHCP deve anunciar como gateway um IP LAN deste RouterOS.

A lista configurada em `wan_interface_list`, por padrão `WAN`, precisa existir e conter interfaces com endereçamento externo à LAN do laboratório, sem incluir interfaces LAN/DHCP. Listas com inclusões/exclusões não verificadas são recusadas. O administrador deve confirmar que essa lista representa todas as saídas de internet utilizadas pelos alunos; rotas especiais, túneis e outro gateway podem criar caminhos fora do escopo dessas regras.

O encaminhamento IPv4 precisa estar ativo. IPv6 encaminhado ou não verificável impede os cortes, assim como FastTrack ativo/não verificável e offload de roteamento L3 ativo/não verificável. O programa não desativa esses recursos automaticamente. Dependendo do modelo e das permissões, a falta de informação sobre aceleração resulta corretamente em inventário sem controles.

Regras de corte são `drop` na cadeia `forward`, restritas à lista WAN e colocadas antes das regras existentes dessa cadeia. O escopo IP exige um par coerente: saída pelo IP de origem e retorno pelo IP de destino. O escopo MAC usa o MAC de origem para impedir saída à WAN. MAC não desassocia o Wi-Fi e não garante interromper imediatamente um fluxo UDP somente de entrada já iniciado. Não se afirma controle de camada 2 quando um roteador/NAT intermediário oculta o MAC real.

IP e MAC são escopos independentes. Retirar um deles preserva o outro. Regras persistidas próprias podem ser removidas quando o cliente está offline. O adaptador não habilita ou remove FastTrack, não fecha portas de switch e não modifica regras de outros administradores.

## Filtro de domínios

Este adaptador adota RouterOS **7.18 ou superior** como versão mínima de suporte ao filtro DNS. O DNS remoto do roteador já precisa estar ativo e o DHCP da rede selecionada precisa anunciar somente endereços DNS do próprio equipamento. O programa cria uma entrada estática de tipo `NXDOMAIN`, com `match-subdomain=true`, incluindo os subdomínios.

O filtro vale para clientes que consultam esse DNS e pode afetar outras redes que também o utilizem. DNS externo, DoH, VPNs, IPs diretos e caches dos clientes podem contorná-lo. O programa não altera silenciosamente DNS/DHCP, não força tráfego DNS e não limpa caches globais. Uma regra DNS externa sobreposta ou uma expressão regular existente impede a inclusão, preservando a configuração anterior.

## Propriedade, confirmação e limites

Somente regras com comentários estruturados `LabGuard2:v1:...`, metadados válidos e formato exato reconhecido são gerenciadas. Os comentários preservam domínio/categoria/data de criação ou endereço/escopo/direção. Eles identificam a política da aplicação; não são uma assinatura contra um administrador do roteador.

Pares incompletos, duplicatas e regras alteradas exigem revisão manual. Antes de cada remoção, o registro é lido novamente por ID e comparado ao observado. Um comentário parecido não autoriza apagar uma regra diferente. A confirmação final exige uma nova leitura bem-sucedida dos registros correspondentes; uma consulta falhada não é interpretada como lista vazia nem como remoção confirmada.

Cada ação altera no máximo duas regras de corte ou uma entrada DNS. Uma falha na criação pode tentar remover somente os IDs que a mesma operação acabou de criar, após nova verificação. Resposta perdida, prazo expirado ou erro de leitura geram resultado não confirmado; revise o roteador antes de repetir. Não há transação distribuída que desfaça alterações de outro administrador.

Leituras têm limite de 2 MiB e 5.000 registros por resposta, orçamento de consulta de 25 segundos e timeout de socket de até 3 segundos, reduzido ao prazo restante. Esse orçamento é verificado entre as operações e leituras; não representa uma garantia de tempo real diante do escalonamento do sistema operacional. Não há espera por resolução DNS porque o destino precisa ser um IP, com certificado que o inclua no SAN. Um resolvedor DNS do sistema não oferece o mesmo controle de prazo. O fechamento da conexão invalida novas solicitações e limpa as referências usuais a usuário/senha sem esperar a thread HTTP; isso não promete apagar cópias de strings da memória do Python. Credenciais não são escritas em logs ou arquivos pelo adaptador.

## Contrato Python

`DirectRouterOSTransport(host, port=443, user='', password='', ca_file='', protected_ips=None, protected_macs=None, lab_cidr='', manage_rules=False, wan_interface_list='WAN')` fornece `request(action, **params)` e `close()`.

As ações aceitas são `snapshot`, `set_address_block(kind, address, blocked)`, `add_domain(domain, category='Outros')` e `remove_domain(domain)`. Parâmetros extras são recusados. `set_device_block`, ativação global de IA e execução arbitrária de comandos não são implementados pelo adaptador. Um controlador superior pode aplicar seu catálogo de IA como domínios explicitamente gerenciados.

A amostra usa `mode='equipment'`, `gateway.hostname`, `gateway.lab_cidr`, `devices`, `domains`, `address_blocks`, `health`, `warnings` e os campos habituais do painel. Cada dispositivo inclui `protected`, `blocked_ip`, `blocked_mac`, `blocked_by` e `blocked`. As capacidades booleanas são `inventory`, `domain_filtering`, `device_internet_cut`, `address_blocking`, `ai_block`, `dns_history` e `port_control`. `device_internet_cut`, `ai_block`, `dns_history` e `port_control` permanecem falsas neste adaptador; os botões de IP/MAC usam `address_blocking` e a ação `set_address_block`, sem chamar a operação legada de máquina.

Referências oficiais: [REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API), [DNS](https://manual.mikrotik.com/docs/network-management/dns/), [IP/IPv6 settings](https://help.mikrotik.com/docs/spaces/ROS/pages/103841817/IP+Settings), [FastTrack](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking/).
