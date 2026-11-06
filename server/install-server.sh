#!/usr/bin/env bash
# Pacote binário Linux. O gateway de tráfego é instalado separadamente.
set -euo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo 'Execute com sudo.' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
server_executable="$script_dir/../LabGuardServer"
demo=false
start=false
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --executable) [[ "$#" -ge 2 ]] || exit 2; server_executable="$2"; shift 2 ;;
        --demo) demo=true; shift ;;
        --start) start=true; shift ;;
        *) echo 'Uso: install-server.sh [--executable CAMINHO] [--demo] [--start]' >&2; exit 2 ;;
    esac
done
for dependency in systemctl runuser getent useradd realpath; do
    command -v "$dependency" >/dev/null || { echo "Falta $dependency." >&2; exit 1; }
done
server_executable="$(realpath -- "$server_executable")"
[[ -f "$server_executable" && -x "$server_executable" && "$(basename -- "$server_executable")" == LabGuardServer ]] || { echo 'Use o executável LabGuardServer do pacote de servidor.' >&2; exit 1; }
source_dir="$(dirname -- "$server_executable")"
if ! getent passwd labguard-server >/dev/null; then
    useradd --system --user-group --create-home --home-dir /var/lib/labguard-server --shell /usr/sbin/nologin labguard-server
fi
install -d -m 0755 -o root -g root /opt/labguard-server
if [[ "$source_dir" != /opt/labguard-server ]]; then
    cp -a -- "$source_dir/." /opt/labguard-server/
fi
chown -R root:root /opt/labguard-server
chmod -R go-w /opt/labguard-server
install -d -m 0700 -o labguard-server -g labguard-server /etc/labguard-server
if [[ ! -f /etc/labguard-server/config.json ]]; then
    runuser -u labguard-server -- /opt/labguard-server/LabGuardServer init --directory /etc/labguard-server
fi
chown labguard-server:labguard-server /etc/labguard-server/config.json /etc/labguard-server/secrets.json
chmod 0600 /etc/labguard-server/config.json /etc/labguard-server/secrets.json
install -d -m 0700 -o labguard-server -g labguard-server /etc/labguard-server/logs
install -d -m 0700 -o labguard-server -g labguard-server /etc/labguard-server/data
if [[ -f /etc/labguard-server/access-tokens.txt ]]; then
    chown root:root /etc/labguard-server/access-tokens.txt
    chmod 0600 /etc/labguard-server/access-tokens.txt
fi
[[ -f "$script_dir/labguard-server.service" ]] || { echo 'Arquivo systemd ausente.' >&2; exit 1; }
install -m 0644 -o root -g root "$script_dir/labguard-server.service" /etc/systemd/system/labguard-server.service
if "$demo"; then
    sed -i 's@--directory /etc/labguard-server$@--directory /etc/labguard-server --demo@' /etc/systemd/system/labguard-server.service
fi
systemctl daemon-reload
systemctl enable labguard-server.service
if "$start"; then
    systemctl restart labguard-server.service
    echo 'Serviço iniciado. Acesse http://127.0.0.1:8765/ no servidor.'
else
    echo 'Serviço instalado, sem iniciar. Configure o gateway e use sudo systemctl start labguard-server.'
fi
echo 'Credenciais locais: /etc/labguard-server/access-tokens.txt (somente root).'
if "$demo"; then echo 'DEMONSTRAÇÃO EXPLÍCITA: dados fictícios, sem controle real da rede.'; fi
