# Diagnóstico e recuperação

> **LabGuard 2.0:** este guia descreve o gateway Linux opcional. Para começar em observação local ou administrar um roteador compatível sem reposicionar o PC, use [Comece aqui](COMECE_AQUI.md) e o [manual 2.0](MANUAL_DO_USUARIO_V2.html).

Faça alterações pelo console local do gateway durante a implantação. Mantenha uma forma de administrar a rede caso o DNS ou a rota estejam incorretos.

## Verificações rápidas

| Sintoma | Verificação |
|---|---|
| Painel não abre | Python com Tcl/Tk; no Linux instale `python3-tk` |
| SSH não conecta | Cliente `ssh`, porta, IP, chave privada, agente SSH e impressão do host verificada |
| Chave protegida não autentica | Carregue a chave no agente SSH da sessão com `ssh-add`; o painel não pede senha |
| DNS não inicia | IP da LAN, conflito na porta 53/67, caminho de logs e `journalctl` |
| Máquinas não recebem IP | Interface LAN e switch isolado; cabo deve entrar na LAN do gateway |
| Internet não funciona | Rota padrão WAN, DNS de saída e regras existentes de outros firewalls |
| Bloqueio não funciona | Caminho alternativo de rede, VPN, DoH, cache ou flowtable/offload |
| Máquina não aparece | Ela precisa gerar tráfego ou obter DHCP; não há varredura física completa |

Comandos no gateway:

```bash
sudo systemctl status labguard-firewall labguard-dnsmasq
sudo systemctl status labguard-reconcile.timer labguard-reconcile.service
sudo journalctl -u labguard-firewall -u labguard-dnsmasq -n 80
sudo dnsmasq --test --conf-file=/etc/labguard/dnsmasq.conf
sudo nft list table inet labguard
ip -4 route
ip -j neigh show
```

Uma resposta SSH `ok: false` deve ser analisada antes de repetir uma alteração. O agente tenta restaurar a configuração anterior se a aplicação falhar; a restauração também pode falhar por um problema externo. Nesse caso, use o console e confira o estado real dos serviços.

## Restaurar uma configuração anterior

Em uma reinstalação, o instalador salva configuração e estado anteriores em uma pasta datada sob `/var/backups/labguard-*`. Escolha a pasta correta e restaure apenas os arquivos desejados. Pare o DNS e o temporizador antes de substituir arquivos e mantenha os donos/permissões originais.

```bash
sudo systemctl stop labguard-dnsmasq.service
sudo systemctl stop labguard-reconcile.timer labguard-reconcile.service
sudo cp /var/backups/labguard-DATA/config.json /etc/labguard/config.json
sudo cp /var/backups/labguard-DATA/state.json /var/lib/labguard/state.json
sudo chmod 600 /etc/labguard/config.json /var/lib/labguard/state.json
sudo python3 -I /opt/labguard/agent.py --config /etc/labguard/config.json --validate-config
sudo systemctl restart labguard-firewall.service
sudo systemctl start labguard-dnsmasq.service
sudo systemctl start labguard-reconcile.timer
```

Substitua `labguard-DATA` pela pasta existente. Nem todo backup inclui um estado anterior; confira antes de copiar.

## Remover o LabGuard

Ao remover o gateway, o laboratório ficará sem o DHCP/DNS fornecido por ele. Antes da remoção, planeje a nova ligação, faixa de rede e serviço DHCP. Não ligue simultaneamente dois servidores DHCP ao mesmo switch.

No console local, pare as unidades e remova somente a tabela própria do programa:

```bash
sudo systemctl disable --now labguard-reconcile.timer labguard-dnsmasq.service labguard-firewall.service
sudo systemctl stop labguard-reconcile.service
sudo nft delete table inet labguard
sudo rm -f /etc/systemd/system/labguard-dnsmasq.service /etc/systemd/system/labguard-firewall.service
sudo rm -f /etc/systemd/system/labguard-reconcile.timer /etc/systemd/system/labguard-reconcile.service
sudo rm -f /etc/logrotate.d/labguard /etc/sudoers.d/labguard /usr/local/sbin/labguard-agent
sudo rm -f /etc/sysctl.d/90-labguard.conf
sudo systemctl daemon-reload
```

Se a tabela já não existir, o comando `nft delete` apenas informará isso. **Não use `nft flush ruleset`**: ele apagaria regras de outras aplicações.

Antes de restaurar `ip_forward`, confira se outro serviço passou a depender de encaminhamento. O valor anterior à primeira instalação está em `/var/lib/labguard/install-ip-forward.before`. Se o gateway for dedicado e não houver outra dependência, restaure esse valor conscientemente com `sudo sysctl -w net.ipv4.ip_forward=VALOR`.

Preserve `/etc/labguard`, `/var/lib/labguard` e `/var/log/labguard` pelo tempo necessário para backup. Depois, remova somente esses diretórios e `/opt/labguard` se não quiser manter regras ou registros. A conta `labguard` e seu diretório `/var/lib/labguard-operator` também podem ser removidos após revogar a chave. Os pacotes do sistema e configurações de outros serviços permanecem sob administração do colégio.
