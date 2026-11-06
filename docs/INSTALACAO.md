# Instalação no laboratório

> **LabGuard 2.0:** este guia descreve o gateway Linux opcional. Para começar em observação local ou administrar um roteador compatível sem reposicionar o PC, use [Comece aqui](COMECE_AQUI.md) e o [manual 2.0](MANUAL_DO_USUARIO_V2.html).

## 1. Topologia necessária

Conecte a saída LAN do roteador à interface WAN do gateway Linux. Conecte a interface LAN do gateway a um switch exclusivo do laboratório. As máquinas do laboratório devem usar esse switch, sem um segundo cabo ou Wi-Fi que alcance diretamente o roteador.

O painel pode rodar no computador do professor. No exemplo abaixo ele recebe o IP fixo protegido `192.168.50.10`, fora da faixa DHCP.

| Elemento | Exemplo |
|---|---|
| Roteador atual | `192.168.0.1` |
| Gateway — WAN | `enp1s0`, IP recebido do roteador |
| Gateway — LAN | `enp2s0`, `192.168.50.1/24` |
| Laboratório | `192.168.50.0/24` |
| DHCP do laboratório | `192.168.50.100` a `192.168.50.220` |
| Professor/administração | `192.168.50.10/24`, gateway e DNS `192.168.50.1` |
| DNS de saída | DNS aprovado pelo colégio; `192.168.0.1` é apenas um exemplo |

Use sub-redes distintas na WAN e na LAN. O DHCP do roteador não pode alcançar o switch do laboratório. Configure a LAN fixa e a rota WAN pelo gerenciador de rede da distribuição, usando o console local. O instalador verifica esses valores e não muda as interfaces.

Esta primeira versão administra IPv4. O encaminhamento IPv6 da LAN é bloqueado para não criar um caminho alternativo ao filtro. Ela não é uma implementação de gateway IPv6 completo.

## 2. Preparar o Linux

Use Debian ou Ubuntu com systemd em um gateway dedicado. Instale os componentes:

```bash
sudo apt update
sudo apt install python3 iproute2 nftables dnsmasq-base conntrack sudo openssh-server logrotate
```

Confira os nomes das interfaces e a rota padrão:

```bash
ip -br address
ip route
```

Antes de prosseguir, confirme acesso à internet na WAN e o IP fixo da LAN. Resolva qualquer serviço DNS/DHCP já ocupando a LAN, incluindo uma instância padrão de `dnsmasq.service` ou o compartilhamento de conexão do NetworkManager. O LabGuard usa uma unidade própria, sem arquivo PID compartilhado, e não desativa serviços de outras aplicações. Também não remove firewalls existentes; regras de UFW, Docker ou outro administrador podem interferir e precisam de análise local.

Não use flowtables ou offload de encaminhamento nesse gateway: esses caminhos podem contornar o filtro. O instalador recusa flowtables já presentes; não habilite offload depois.

## 3. Criar a chave no computador do professor

No PowerShell do Windows ou no terminal Linux:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/labguard
```

Use uma senha para proteger a chave e carregue-a no agente SSH da sua sessão. O painel usa conexão não interativa e não solicita senhas de chave. Sem agente, uma chave protegida não conseguirá conectar. Mantenha a chave privada no computador autorizado; copie somente o arquivo `labguard.pub` para o gateway.

Com o serviço/agente SSH da sessão já iniciado, carregue a chave:

```bash
ssh-add ~/.ssh/labguard
```

No Windows, o caminho normalmente é `C:\Users\SEU_USUARIO\.ssh\labguard`. No Linux é `~/.ssh/labguard`.

## 4. Adaptar e instalar

Copie toda a pasta `LabGuard` para o gateway. Dentro dela:

```bash
cp gateway/config.example.json gateway/config.local.json
nano gateway/config.local.json
```

Preencha interfaces, rede, IP do gateway, faixa DHCP, IPs protegidos e DNS de saída. Nunca inclua o professor na faixa DHCP: reserve um IP fixo ou configure uma reserva DHCP fora deste programa. O campo `protected_ips` deve conter todos os computadores que não podem ser cortados pelo painel.

Os caminhos `state_dir`, `log_dir` e `dnsmasq_config` devem manter os valores do exemplo para usar o instalador fornecido.

Valide e instale usando o caminho da chave **pública**:

```bash
sudo python3 gateway/agent.py --config gateway/config.local.json --validate-config
sudo bash gateway/install.sh gateway/config.local.json /CAMINHO/labguard.pub
```

O instalador cria um usuário restrito `labguard`, instala o agente e as unidades systemd, habilita encaminhamento IPv4 e inicia o DNS/DHCP do laboratório. Um temporizador reconcilia os bloqueios com os endereços DHCP/vizinhos a cada cinco segundos, mesmo se o painel estiver fechado. A chave SSH só permite executar o agente com um conjunto limitado de ações JSON. Não há console remoto, encaminhamento de portas ou senha de roteador salva pelo painel.

Veja o resultado:

```bash
sudo systemctl status labguard-firewall.service labguard-dnsmasq.service
sudo systemctl status labguard-reconcile.timer
sudo nft list table inet labguard
sudo journalctl -u labguard-dnsmasq.service -n 30
```

O temporizador deve aparecer ativo, aguardando a próxima execução. O serviço `labguard-reconcile.service` é uma tarefa curta: aparecer inativo entre execuções é normal. Confira falhas em `journalctl -u labguard-reconcile.service`.

O instalador copia o catálogo `gateway/ai_services.json` para `/opt/labguard/ai_services.json`, com leitura permitida e escrita restrita ao administrador. Mantenha esse arquivo ao lado de `agent.py` também ao validar o pacote antes da instalação.

Se a inicialização falhar, pare o teste e use [diagnóstico e recuperação](RECUPERACAO.md). O instalador não faz remoção automática das alterações parciais: serviços, arquivos e encaminhamento já habilitados devem ser conferidos pelo procedimento de recuperação. Não conecte o laboratório inteiro até resolver a causa.

## 5. Verificar a identidade SSH

No console local do gateway, anote a impressão digital:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

No computador do professor, conecte uma vez e compare a impressão exibida com a anotada. Aceite somente se coincidir:

```bash
ssh -i ~/.ssh/labguard -o HostKeyAlgorithms=ssh-ed25519 labguard@192.168.50.1
```

A conta não abre um terminal. Depois da autenticação, envie a linha abaixo e finalize a entrada: Ctrl+D no Linux; no Windows, Ctrl+Z e Enter quando suportado pelo terminal. A resposta deve ser JSON.

```json
{"version":1,"action":"snapshot","params":{}}
```

Se preferir, envie pela entrada padrão:

```bash
echo '{"version":1,"action":"snapshot","params":{}}' | ssh -i ~/.ssh/labguard labguard@192.168.50.1
```

No PowerShell, as aspas simples preservam o JSON. A identidade fica em `known_hosts`. O painel exige host já conhecido, e recusa automaticamente uma identidade alterada.

## 6. Conectar o painel

Abra `main.py`, entre na área de conexão e preencha:

| Campo | Exemplo |
|---|---|
| Host | `192.168.50.1` |
| Porta | `22` |
| Usuário | `labguard` |
| Chave privada | Arquivo `labguard`, sem `.pub` |
| known_hosts | Deixe o padrão, ou selecione o arquivo no qual verificou o host |

Só uma resposta válida do gateway ativa o modo real. Uma falha de conexão não substitui dados reais por dados fictícios.

O catálogo de IA começa desativado no gateway. Ative o controle de bloqueio de IA no painel para aplicá-lo a toda a rede do laboratório. Confirme o resultado primeiro na máquina de teste. Desativar esse controle preserva os domínios que foram cadastrados manualmente. Para integração direta com um equipamento, siga também [INTEGRACOES.md](INTEGRACOES.md); o procedimento depende do adaptador e das capacidades do modelo.

## 7. Teste antes de liberar

1. Conecte uma máquina de teste ao switch isolado. Renove a concessão DHCP e confira IP, gateway e DNS da faixa correta.
2. Acesse um site permitido. Confira a máquina no inventário e as consultas na aba DNS.
3. Cadastre um domínio escolhido para o teste, por exemplo `example.com`. Execute `nslookup example.com 192.168.50.1`; a resposta deve indicar domínio inexistente. Confira o registro de bloqueio DNS.
4. Remova o domínio e repita o teste após limpar o cache DNS. No Windows: `ipconfig /flushdns`.
5. Abra um download ou conexão de teste. Corte a internet dessa máquina e confirme a interrupção; restaure e teste novamente.
6. Tente selecionar o IP protegido do professor: o agente deve recusar o corte.
7. Reinicie o gateway e confirme que as regras persistiram. Confira a política IPv6 e teste também navegadores com as políticas do colégio aplicadas.
8. Feche o painel e confira se `labguard-reconcile.timer` continua ativo. Em um teste administrado de mudança de IP da máquina bloqueada, confirme que a associação de endereços é atualizada sem abrir a interface.
9. Desconecte o gateway para confirmar que as máquinas não conseguem alcançar a internet por outro Wi-Fi ou cabo.
10. Ative o bloqueio de IA, consulte um domínio do catálogo pelo DNS do gateway e confirme a resposta de bloqueio. Desative a política e confira a liberação. Um domínio do mesmo catálogo adicionado manualmente deve continuar bloqueado após desativar a política.

Depois de concluir esses testes, conecte gradualmente as demais máquinas.
