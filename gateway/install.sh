#!/usr/bin/env bash
# Debian/Ubuntu, dedicated gateway. Does not reconfigure addresses or other firewalls.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || fail 'Execute com sudo no gateway dedicado.'
[[ "$#" -eq 2 ]] || fail 'Uso: sudo bash gateway/install.sh CONFIG.json CHAVE_PUBLICA.pub'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
config_input="$(realpath -- "$1")"
public_key_input="$(realpath -- "$2")"
[[ -f "$config_input" && -f "$public_key_input" ]] || fail 'Configuração ou chave pública ausente.'
for dependency in python3 ip nft dnsmasq conntrack sudo ssh-keygen sshd systemctl visudo; do
    command -v "$dependency" >/dev/null || fail "Falta $dependency. Instale os pré-requisitos descritos no guia."
done
[[ -f "$script_dir/agent.py" ]] || fail 'Mantenha todos os arquivos do pacote na mesma pasta.'
[[ -f "$script_dir/ai_services.json" ]] || fail 'Falta gateway/ai_services.json. Mantenha o catálogo de IA ao lado do agente.'
/usr/bin/python3 -I "$script_dir/agent.py" --config "$config_input" --validate-config

# Fixed installation paths keep the privileged SSH command independent of caller input.
/usr/bin/python3 - "$config_input" "$public_key_input" <<'PY'
import ipaddress, json, pathlib, re, subprocess, sys
cfg = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = {'state_dir': '/var/lib/labguard', 'log_dir': '/var/log/labguard',
            'dnsmasq_config': '/etc/labguard/dnsmasq.conf'}
for key, value in expected.items():
    if cfg.get(key, value) != value:
        raise SystemExit(f'Este instalador exige {key}={value}.')
key = pathlib.Path(sys.argv[2]).read_text().strip()
if '\n' in key or not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]*)?', key):
    raise SystemExit('Forneça uma única chave pública OpenSSH, sem opções de authorized_keys.')
subprocess.run(['ssh-keygen', '-l', '-f', sys.argv[2]], check=True)
net = ipaddress.ip_network(cfg['lab_cidr'])
lan, wan = cfg['lan_interface'], cfg['wan_interface']
addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address', 'show', 'dev', lan]))
if not any(a.get('local') == cfg['gateway_ip'] and a.get('prefixlen') == net.prefixlen
           for interface in addresses for a in interface.get('addr_info', [])):
    raise SystemExit('Configure primeiro o IP/máscara da interface LAN conforme o guia; nada foi instalado.')
routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'default']))
if not any(route.get('dev') == wan for route in routes):
    raise SystemExit('A interface WAN precisa ter uma rota padrão funcionando.')
rules = json.loads(subprocess.check_output(['nft', '-j', 'list', 'ruleset']))
if any('flowtable' in item for item in rules.get('nftables', [])):
    raise SystemExit('Há flowtable/offload no gateway. Remova esse recurso antes de instalar o LabGuard.')
if not cfg.get('protected_ips'):
    raise SystemExit('Reserve e proteja pelo menos o IP do computador de administração.')
for resolver in cfg['upstream_dns']:
    if ipaddress.ip_address(resolver) in net:
        raise SystemExit('O DNS de saída precisa estar fora da rede do laboratório.')
print('Pré-validação concluída. A LAN deve estar isolada do DHCP do roteador.')
PY

if getent passwd labguard >/dev/null; then
    [[ "$(getent passwd labguard | cut -d: -f6)" == /var/lib/labguard-operator ]] || fail 'Usuário labguard existente pertence a outra instalação.'
else
    useradd --system --user-group --home-dir /var/lib/labguard-operator --shell /bin/sh labguard
fi
if ! getent passwd dnsmasq >/dev/null; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin dnsmasq
fi
passwd -l labguard >/dev/null
install -d -m 0755 -o root -g root /opt/labguard /etc/labguard /var/lib/labguard
install -d -m 0750 -o dnsmasq -g dnsmasq /var/lib/labguard/dnsmasq
install -d -m 0755 -o root -g root /var/log/labguard
if [[ ! -e /var/log/labguard/dnsmasq.log ]]; then
    install -m 0640 -o dnsmasq -g dnsmasq /dev/null /var/log/labguard/dnsmasq.log
fi
install -d -m 0755 -o root -g root /var/lib/labguard-operator
install -d -m 0700 -o labguard -g labguard /var/lib/labguard-operator/.ssh
if [[ -f /etc/labguard/config.json ]]; then
    backup_dir="/var/backups/labguard-$(date +%Y%m%dT%H%M%S)"
    install -d -m 0700 "$backup_dir"
    cp -a /etc/labguard/config.json "$backup_dir/config.json"
    [[ ! -f /var/lib/labguard/state.json ]] || cp -a /var/lib/labguard/state.json "$backup_dir/state.json"
    printf 'Backup da configuração anterior: %s\n' "$backup_dir"
fi
if [[ ! -f /var/lib/labguard/install-ip-forward.before ]]; then
    cat /proc/sys/net/ipv4/ip_forward > /var/lib/labguard/install-ip-forward.before
fi
install -m 0644 -o root -g root "$script_dir/agent.py" /opt/labguard/agent.py
install -m 0644 -o root -g root "$script_dir/ai_services.json" /opt/labguard/ai_services.json
install -m 0600 -o root -g root "$config_input" /etc/labguard/config.json
install -m 0755 -o root -g root "$script_dir/labguard-agent" /usr/local/sbin/labguard-agent
install -m 0644 -o root -g root "$script_dir/labguard-firewall.service" /etc/systemd/system/labguard-firewall.service
install -m 0644 -o root -g root "$script_dir/labguard-dnsmasq.service" /etc/systemd/system/labguard-dnsmasq.service
install -m 0644 -o root -g root "$script_dir/labguard-reconcile.service" /etc/systemd/system/labguard-reconcile.service
install -m 0644 -o root -g root "$script_dir/labguard-reconcile.timer" /etc/systemd/system/labguard-reconcile.timer
install -m 0644 -o root -g root "$script_dir/labguard.logrotate" /etc/logrotate.d/labguard

/usr/bin/python3 - "$public_key_input" <<'PY'
import pathlib, sys
key = pathlib.Path(sys.argv[1]).read_text().strip()
path = pathlib.Path('/var/lib/labguard-operator/.ssh/authorized_keys')
path.write_text('restrict,command="/usr/bin/sudo -n /usr/local/sbin/labguard-agent" ' + key + '\n')
path.chmod(0o600)
PY
# Root ownership prevents the restricted operator from replacing its forced command key.
chown root:root /var/lib/labguard-operator/.ssh /var/lib/labguard-operator/.ssh/authorized_keys
chmod 0755 /var/lib/labguard-operator/.ssh
chmod 0644 /var/lib/labguard-operator/.ssh/authorized_keys
printf '%s\n' 'labguard ALL=(root) NOPASSWD: /usr/local/sbin/labguard-agent ""' > /etc/sudoers.d/labguard
chmod 0440 /etc/sudoers.d/labguard
visudo -c -f /etc/sudoers.d/labguard

printf '%s\n' 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-labguard.conf
systemctl daemon-reload
systemctl enable labguard-firewall.service labguard-dnsmasq.service labguard-reconcile.timer
systemctl restart labguard-firewall.service
sysctl -w net.ipv4.ip_forward=1 >/dev/null
systemctl restart labguard-dnsmasq.service
systemctl restart labguard-reconcile.timer
systemctl is-active --quiet labguard-dnsmasq.service || fail 'O DNS não iniciou. Consulte journalctl -u labguard-dnsmasq.'
printf '\n%s\n' 'LabGuard instalado. Cadastre a chave de host SSH antes de conectar a interface.'
printf '%s\n' 'Confira os serviços e execute o teste de uma única máquina descrito no guia.'
