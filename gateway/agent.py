#!/usr/bin/env python3
"""LabGuard: API JSON restrita do gateway Linux. Não executa texto de shell.

Leia docs/INSTALACAO.md antes de instalar. Testes usam diretórios
temporários e comandos simulados; nenhuma regra de rede é aplicada nos testes.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import copy
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import subprocess
import sys
import tempfile
import time

VERSION = "1.4.0"
DEFAULT_CONFIG = "/etc/labguard/config.json"
TABLE = "labguard"
SERVICE = "labguard-dnsmasq"
MAX_DOMAINS = 10000
MAX_LOG_BYTES = 2_000_000
MAX_EVENTS = 500
MAX_REQUEST_BYTES = 8192
REQUEST_TIMEOUT = 10
LOCK_TIMEOUT = 8
MAX_CONFIG_BYTES = 65536
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_LEASE_BYTES = 2 * 1024 * 1024
AI_CATALOG = Path(__file__).with_name("ai_services.json")
MAX_AI_CATALOG_BYTES = 256_000
IFACE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}\Z")
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


class AgentError(Exception):
    pass


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def read_request(stream, timeout=REQUEST_TIMEOUT):
    """One bounded JSON line/EOF. SSH clients cannot hold a root reader forever."""
    descriptor = stream.fileno()
    deadline = time.monotonic() + timeout
    chunks, size = [], 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise AgentError("Tempo esgotado para receber a solicitação. Reconecte o painel.")
        chunk = os.read(descriptor, min(4096, MAX_REQUEST_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_REQUEST_BYTES:
            raise AgentError("Requisição excede 8 KiB.")
        if b"\n" in chunk:
            # json.loads rejects a second JSON object already in this chunk.
            break
    raw = b"".join(chunks)
    if not raw.strip():
        raise AgentError("A solicitação está vazia.")
    return raw


@contextlib.contextmanager
def open_regular_file(path):
    """Data written by dnsmasq must not turn a privileged read into a FIFO/link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AgentError("A leitura requer um arquivo regular, sem links nem dispositivos.")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def read_binary_file(path, maximum, label):
    with open_regular_file(path) as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise AgentError(f"{label} excede o tamanho permitido.")
    return raw


def read_json_file(path, maximum, label):
    raw = read_binary_file(path, maximum, label)
    return json.loads(raw.decode("utf-8"))


def verify_root_path(path, *, directory=False, private=False):
    """Reject replaceable privileged inputs and any symlink in their ancestors."""
    path = Path(path).absolute()
    for current in [path, *path.parents]:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AgentError(f"Permissões inseguras em {current}. Reinstale o gateway com o administrador.")
        if current == path:
            wanted = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
            if not wanted:
                raise AgentError(f"Caminho de instalação inválido: {current}.")
            if private and info.st_mode & 0o077:
                raise AgentError(f"Arquivo administrativo exposto: {current}. Ajuste para permissão 0600.")


def verify_privileged_installation(config, config_path):
    for path in (Path(__file__).absolute(), AI_CATALOG):
        verify_root_path(path)
    verify_root_path(config_path, private=True)
    for path in (config.state_dir, config.log_dir, config.dnsmasq_config.parent):
        verify_root_path(path, directory=True)
    for path in (config.state_file, config.dnsmasq_config):
        if path.exists() or path.is_symlink():
            verify_root_path(path, private=path == config.state_file)


def audit_context(request):
    """Only known operation names and validated targets; never log raw parameters."""
    actions = {"add_domain": "Bloquear domínio", "remove_domain": "Remover domínio",
               "set_device_block": "Alterar internet", "set_ai_block": "Alterar bloqueio de IA"}
    if not isinstance(request, dict):
        return "Solicitação recusada", "Protocolo"
    request_action = request.get("action")
    action = actions.get(request_action, "Solicitação recusada") if isinstance(request_action, str) else "Solicitação recusada"
    params = request.get("params", {})
    if not isinstance(params, dict):
        return action, "Parâmetros rejeitados"
    try:
        if request.get("action") in ("add_domain", "remove_domain"):
            return action, domain_name(params.get("domain"))
        if request.get("action") == "set_device_block":
            return action, str(ipv4(params.get("ip"), "IP"))
        if request.get("action") == "set_ai_block":
            return action, "Perfil de inteligência artificial"
    except AgentError:
        pass
    return action, "Entrada rejeitada"


def domain_name(value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise AgentError("Informe um domínio válido, como exemplo.com.")
    value = value.strip().lower().rstrip(".")
    if "://" in value or any(c in value for c in "/\\:*?@#\n\r\t"):
        raise AgentError("Use somente o domínio, sem URL, caminho, porta ou curinga.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AgentError("Domínio inválido.") from exc
    labels = value.split(".")
    if len(labels) < 2 or len(value) > 253 or labels[-1].isdigit():
        raise AgentError("O domínio precisa incluir a extensão, como exemplo.com.")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise AgentError("Domínio inválido.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise AgentError("Informe um domínio, não um endereço IP.")


def ipv4(value, label):
    try:
        result = ipaddress.IPv4Address(value)
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise AgentError(f"{label}: endereço IPv4 inválido.") from exc
    return result


class Config:
    def __init__(self, data):
        if not isinstance(data, dict):
            raise AgentError("A configuração precisa ser um objeto JSON.")
        self.raw = dict(data)
        for key in ("lan_interface", "wan_interface"):
            value = data.get(key)
            if not isinstance(value, str) or not IFACE_RE.fullmatch(value):
                raise AgentError(f"{key}: nome de interface inválido.")
            setattr(self, key, value)
        if self.lan_interface == self.wan_interface:
            raise AgentError("LAN e WAN precisam ser interfaces diferentes.")
        try:
            self.network = ipaddress.IPv4Network(data.get("lab_cidr"), strict=True)
        except (ValueError, TypeError) as exc:
            raise AgentError("lab_cidr: informe uma sub-rede IPv4, por exemplo 192.168.50.0/24.") from exc
        private_ranges = [ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        if not any(self.network.subnet_of(value) for value in private_ranges) or self.network.prefixlen < 16 or self.network.prefixlen > 29:
            raise AgentError("Use uma sub-rede IPv4 privada entre /16 e /29 para o laboratório.")
        self.gateway_ip = self.host(data.get("gateway_ip"), "gateway_ip")
        self.dhcp_start = self.host(data.get("dhcp_start"), "dhcp_start")
        self.dhcp_end = self.host(data.get("dhcp_end"), "dhcp_end")
        if self.dhcp_start > self.dhcp_end or self.dhcp_start <= self.gateway_ip <= self.dhcp_end:
            raise AgentError("A faixa DHCP está invertida ou inclui o gateway.")
        protected = data.get("protected_ips", [])
        if not isinstance(protected, list) or len(protected) > 256:
            raise AgentError("protected_ips precisa ser uma lista com até 256 IPv4.")
        self.protected_ips = {str(self.host(x, "protected_ips")) for x in protected}
        self.protected_ips.add(str(self.gateway_ip))
        if any(self.dhcp_start <= ipv4(x, "IP protegido") <= self.dhcp_end for x in self.protected_ips):
            raise AgentError("IPs protegidos devem ficar fora da faixa DHCP dinâmica.")
        upstream = data.get("upstream_dns", [])
        if not isinstance(upstream, list) or not 1 <= len(upstream) <= 4:
            raise AgentError("Configure de 1 a 4 servidores upstream_dns IPv4.")
        self.upstream_dns = []
        for value in upstream:
            address = ipv4(value, "upstream_dns")
            if address in self.network or address.is_unspecified or address.is_multicast or address.is_loopback:
                raise AgentError("O DNS upstream precisa estar fora do laboratório e ser alcançável pela WAN.")
            self.upstream_dns.append(str(address))
        for key, default in (("state_dir", "/var/lib/labguard"), ("log_dir", "/var/log/labguard"), ("dnsmasq_config", "/etc/labguard/dnsmasq.conf")):
            value = data.get(key, default)
            if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in Path(value).parts:
                raise AgentError(f"{key}: use um caminho absoluto simples.")
            setattr(self, key, Path(value))
        self.state_file = self.state_dir / "state.json"
        self.lease_file = self.state_dir / "dnsmasq" / "dnsmasq.leases"
        self.log_file = self.log_dir / "dnsmasq.log"

    def host(self, value, label="IP"):
        address = ipv4(value, label)
        if address not in self.network or address in (self.network.network_address, self.network.broadcast_address):
            raise AgentError(f"{label}: o endereço precisa ser um host da sub-rede do laboratório.")
        return address


def default_state():
    return {"version": 1, "domains": [], "blocked": {}, "audit": [], "ai_block_enabled": False}


def load_ai_catalog(path=None):
    """Only local, root-owned installation data; never a remote blocklist."""
    path = Path(path) if path is not None else AI_CATALOG
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(MAX_AI_CATALOG_BYTES + 1)
        if len(raw) > MAX_AI_CATALOG_BYTES:
            raise AgentError("O catálogo de IA excede o tamanho permitido.")
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentError("Não foi possível ler o catálogo de IA. Reinstale o arquivo ai_services.json do pacote.") from exc
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise AgentError("Formato do catálogo de IA incompatível.")
    if not isinstance(data.get("updated_at"), str):
        raise AgentError("Data do catálogo de IA inválida.")
    try:
        dt.date.fromisoformat(data["updated_at"])
    except ValueError as exc:
        raise AgentError("Data do catálogo de IA inválida.") from exc
    rows = data.get("services")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise AgentError("O catálogo de IA precisa ter entre 1 e 100 serviços.")
    services, domains = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise AgentError("Serviço inválido no catálogo de IA.")
        name, source = row.get("name"), row.get("source_url")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or any(ord(c) < 32 for c in name):
            raise AgentError("Nome inválido no catálogo de IA.")
        if not isinstance(source, str) or not source.startswith("https://") or len(source) > 2000 or any(ord(c) < 32 for c in source):
            raise AgentError("Referência inválida no catálogo de IA.")
        values = row.get("domains")
        if not isinstance(values, list) or not 1 <= len(values) <= 100:
            raise AgentError("Lista de domínios inválida no catálogo de IA.")
        normalized = sorted({domain_name(value) for value in values})
        domains.update(normalized)
        services.append({"name": name.strip(), "domains": normalized, "source_url": source})
    return {"version": 1, "updated_at": data["updated_at"], "services": services, "domains": sorted(domains)}


def effective_domains(state, catalog=None):
    """Combine rules without changing ownership of manually added domains."""
    rows = {row["domain"]: dict(row, source="manual") for row in state["domains"]}
    if state.get("ai_block_enabled", False):
        catalog = catalog if catalog is not None else load_ai_catalog()
        for domain in catalog["domains"]:
            rows.setdefault(domain, {"domain": domain, "category": "Inteligência artificial",
                                     "source": "ai_profile", "created_at": ""})
    return sorted(rows.values(), key=lambda row: row["domain"])


def blocked_address(key):
    # Usually an IPv4 key. A composite key retains a previous MAC identity when
    # its old DHCP address is re-used by another machine that is also blocked.
    if not isinstance(key, str):
        raise AgentError("Identificador de bloqueio inválido.")
    parts = key.split("|")
    if len(parts) > 2 or (len(parts) == 2 and not MAC_RE.fullmatch(parts[1])):
        raise AgentError("Identificador de bloqueio inválido.")
    return parts[0]


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".labguard-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def render_dnsmasq(config, state):
    lines = [
        "# Gerado pelo LabGuard. Edite domínios pelo painel.",
        "port=53", "domain-needed", "bogus-priv", "no-resolv", "no-hosts",
        "user=dnsmasq", "group=dnsmasq", "bind-dynamic",
        f"interface={config.lan_interface}", f"listen-address={config.gateway_ip}",
        "except-interface=lo", "cache-size=1000", "log-queries=extra", "log-dhcp",
        "log-async=50", f"log-facility={config.log_file}",
        f"dhcp-range={config.dhcp_start},{config.dhcp_end},{config.network.netmask},8h",
        f"dhcp-option=option:router,{config.gateway_ip}",
        f"dhcp-option=option:dns-server,{config.gateway_ip}",
        f"dhcp-leasefile={config.lease_file}", "dhcp-authoritative",
    ]
    lines += [f"server={address}" for address in config.upstream_dns]
    # server=/domain/ means no upstream for that subtree: NXDOMAIN for all types.
    lines += [f"server=/{domain_name(item['domain'])}/" for item in effective_domains(state)]
    return "\n".join(lines) + "\n"


def render_nft(config, state, table_exists=False, extra_ips=None):
    ips = {blocked_address(key) for key in state["blocked"]} if extra_ips is None else set(extra_ips)
    for address in ips:
        config.host(address)
    macs = set()
    for entry in state["blocked"].values():
        mac = entry.get("mac", "").lower()
        if mac:
            if not MAC_RE.fullmatch(mac):
                raise AgentError("Estado contém um MAC inválido.")
            macs.add(mac)
    ips -= config.protected_ips
    lan, wan = config.lan_interface, config.wan_interface
    lines = [f"delete table inet {TABLE}"] if table_exists else []
    lines += [f"table inet {TABLE} {{", "  set blocked_v4 {", "    type ipv4_addr;"]
    if ips:
        lines += ["    elements = { " + ", ".join(sorted(ips, key=ipaddress.IPv4Address)) + " };"]
    lines += ["  }", "  set blocked_mac {", "    type ether_addr;"]
    if macs:
        lines += ["    elements = { " + ", ".join(sorted(macs)) + " };"]
    lines += [
        "  }", "  chain forward {", "    type filter hook forward priority -10; policy accept;",
        f'    iifname "{lan}" meta nfproto ipv6 counter drop',
        f'    oifname "{lan}" meta nfproto ipv6 counter drop',
        f'    iifname "{lan}" ip saddr != {config.network} counter drop',
        f'    iifname "{lan}" oifname "{wan}" tcp dport 853 counter reject',
        f'    iifname "{lan}" oifname "{wan}" udp dport 853 counter reject',
        # Fixed administrator addresses are exempt even if an old saved MAC
        # later appears at a protected address. They stay outside DHCP range.
        f'    iifname "{lan}" oifname "{wan}" ip saddr {{ ' + ", ".join(sorted(config.protected_ips)) + " } accept",
        f'    iifname "{wan}" oifname "{lan}" ip daddr {{ ' + ", ".join(sorted(config.protected_ips)) + " } ct state established,related accept",
        # Drops precede established/related so a cut also affects existing sessions.
        f'    iifname "{lan}" oifname "{wan}" ether saddr @blocked_mac counter drop',
        f'    iifname "{lan}" oifname "{wan}" ip saddr @blocked_v4 counter drop',
        f'    iifname "{wan}" oifname "{lan}" ip daddr @blocked_v4 counter drop',
        "    ct state established,related accept",
        f'    iifname "{lan}" oifname "{wan}" ip saddr {config.network} accept',
        # Lab isolation: forwarding through any other interface is not allowed.
        f'    iifname "{lan}" counter drop',
        f'    oifname "{lan}" counter drop',
        "  }", "  chain dns_redirect {",
        "    type nat hook prerouting priority -101; policy accept;",
        f'    iifname "{lan}" meta nfproto ipv4 udp dport 53 redirect to :53',
        f'    iifname "{lan}" meta nfproto ipv4 tcp dport 53 redirect to :53',
        "  }", "  chain masquerade {", "    type nat hook postrouting priority 100; policy accept;",
        f'    oifname "{wan}" ip saddr {config.network} masquerade', "  }", "}",
    ]
    return "\n".join(lines)


def read_tail(path, limit=MAX_LOG_BYTES):
    try:
        with open_regular_file(path) as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - limit))
            data = stream.read(limit)
            if size > limit:
                data = data.split(b"\n", 1)[-1]
            return data.decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


def parse_events(text, network):
    events = []
    serials = {}
    # log-queries=extra: timestamp dnsmasq[pid]: serial client[:port] query[A] domain from client
    query = re.compile(r"(?:^|\s)(\d+)\s+(\S+)\s+query\[([^\]]+)\]\s+(\S+)\s+from\s+(\S+)")
    config_reply = re.compile(r"(?:^|\s)(\d+)\s+\S+\s+config\s+(\S+)\s+is\s+NXDOMAIN")
    for line in text.splitlines():
        found = query.search(line)
        if found:
            serial, _, qtype, domain, source = found.groups()
            source = source.split("#")[0]
            try:
                address = ipaddress.IPv4Address(source)
            except ValueError:
                continue
            if address not in network:
                continue
            event = {"time": line.split("dnsmasq", 1)[0].strip(), "client_ip": source,
                     "domain": domain.rstrip("."), "query_type": qtype,
                     "status": "Consulta"}
            events.append(event)
            serials[serial] = event
        else:
            found = config_reply.search(line)
            if found:
                serial, domain = found.groups()
                event = serials.get(serial)
                if event and event["domain"] == domain.rstrip("."):
                    event["status"] = "Bloqueio DNS confirmado"
    return list(reversed(events[-MAX_EVENTS:]))


def parse_leases(text, config, timestamp=None):
    timestamp = timestamp if timestamp is not None else dt.datetime.now().timestamp()
    devices = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        expires, mac, ip, name = fields[:4]
        try:
            config.host(ip)
            expiry = int(expires)
        except (AgentError, ValueError):
            continue
        mac = mac.lower()
        if not MAC_RE.fullmatch(mac):
            continue
        devices[ip] = {"ip": ip, "mac": mac, "name": "" if name == "*" else name[:100],
                       "state": "Concessão ativa" if expiry == 0 or expiry > timestamp else "Concessão expirada",
                       "last_seen": "", "blocked": False, "protected": ip in config.protected_ips, "dns_queries": 0}
    return devices


def merge_neighbors(devices, data, config):
    for item in data:
        ip = item.get("dst")
        try:
            config.host(ip)
        except AgentError:
            continue
        mac = str(item.get("lladdr", "")).lower()
        if not MAC_RE.fullmatch(mac):
            continue
        entry = devices.setdefault(ip, {"ip": ip, "name": "", "last_seen": "", "dns_queries": 0,
                                      "blocked": False, "protected": ip in config.protected_ips})
        entry["mac"] = mac
        states = item.get("state", [])
        if isinstance(states, str):
            states = [states]
        if "REACHABLE" in states:
            entry["state"] = "Vizinho alcançável"
            entry["last_seen"] = now()
        elif entry.get("state") != "Concessão ativa":
            entry["state"] = "Vizinho observado (" + "/".join(states) + ")"
    return devices


def parse_connections(text, config):
    rows = []
    for line in text.splitlines():
        first = re.search(r"\bsrc=(\S+)\s+dst=(\S+)(?:\s+sport=(\d+)\s+dport=(\d+))?", line)
        if not first:
            continue
        source, destination, _, port = first.groups()
        try:
            config.host(source)
            ipaddress.IPv4Address(destination)
        except (AgentError, ValueError):
            continue
        # Only original-direction external connections, not gateway DNS/local services.
        if ipaddress.IPv4Address(destination) in config.network:
            continue
        protocol_match = re.search(r"\b(tcp|udp|icmp)\b", line)
        state_match = re.search(r"\b(ESTABLISHED|SYN_SENT|SYN_RECV|TIME_WAIT|CLOSE_WAIT|FIN_WAIT|CLOSE|LAST_ACK|UNREPLIED)\b", line)
        rows.append({"source_ip": source, "destination_ip": destination,
                     "protocol": protocol_match.group(1) if protocol_match else "outro",
                     "port": int(port) if port else 0,
                     "state": state_match.group(1) if state_match else "Observada"})
        if len(rows) >= 500:
            break
    return rows


class Agent:
    def __init__(self, config, runner=None):
        self.config = config
        self.runner = runner or subprocess.run

    def command(self, args, input=None, check=True, timeout=15):
        try:
            result = self.runner(args, input=input, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AgentError(f"Não foi possível executar {args[0]}: {exc}") from exc
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "sem detalhe")[:1200].strip()
            raise AgentError(f"Falha em {args[0]}: {detail}")
        return result

    @contextlib.contextmanager
    def lock(self, timeout=LOCK_TIMEOUT):
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.config.state_dir / "agent.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as stream:
            os.fchmod(stream.fileno(), 0o600)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise AgentError("O gateway está ocupado. Aguarde a operação atual e atualize o painel.")
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def load_state(self):
        try:
            value = read_json_file(self.config.state_file, MAX_STATE_BYTES, "O estado salvo")
        except FileNotFoundError:
            return default_state()
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AgentError("O estado salvo não pôde ser lido. Restaure um backup; nenhuma regra foi alterada.") from exc
        if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1:
            raise AgentError("Formato de estado incompatível.")
        value.setdefault("ai_block_enabled", False)
        if type(value["ai_block_enabled"]) is not bool:
            raise AgentError("Estado de bloqueio de IA inválido.")
        if not isinstance(value.get("domains"), list) or len(value["domains"]) > MAX_DOMAINS or not isinstance(value.get("blocked"), dict) or not isinstance(value.get("audit"), list) or len(value["audit"]) > 1000 or len(value["blocked"]) > MAX_DOMAINS:
            raise AgentError("Estado salvo inválido.")
        for row in value["domains"]:
            if not isinstance(row, dict) or not isinstance(row.get("category"), str) or not 1 <= len(row["category"]) <= 60 or any(ord(c) < 32 for c in row["category"]):
                raise AgentError("Domínio salvo possui formato ou categoria inválida.")
            if row.get("domain") != domain_name(row.get("domain")):
                raise AgentError("Domínio salvo não está no formato normalizado.")
            if not isinstance(row.get("created_at", ""), str):
                raise AgentError("Data do domínio salvo inválida.")
        for key, entry in value["blocked"].items():
            self.config.host(blocked_address(key))
            if not isinstance(entry, dict) or not isinstance(entry.get("mac", ""), str) or (entry.get("mac") and not MAC_RE.fullmatch(entry["mac"])) or not isinstance(entry.get("name", ""), str):
                raise AgentError("Bloqueio salvo inválido.")
        for row in value["audit"]:
            if not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in ("time", "action", "target", "outcome")):
                raise AgentError("Histórico salvo inválido.")
        return value

    def save_state(self, state):
        atomic_write(self.config.state_file, json.dumps(state, indent=2, ensure_ascii=False) + "\n")

    def table_exists(self):
        return self.command(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0

    def nft_apply(self, state, extra_ips=None):
        script = render_nft(self.config, state, self.table_exists(), extra_ips)
        self.command(["nft", "--check", "-f", "-"], input=script)
        self.command(["nft", "-f", "-"], input=script)

    def dns_apply(self, state, restart=True):
        text = render_dnsmasq(self.config, state)
        self.config.dnsmasq_config.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="dnsmasq-check-", dir=self.config.dnsmasq_config.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
            self.command(["dnsmasq", "--test", f"--conf-file={temporary}"])
            atomic_write(self.config.dnsmasq_config, text, 0o644)
            if restart:
                self.command(["systemctl", "restart", SERVICE], timeout=25)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def devices(self, state):
        warnings = []
        try:
            text = read_binary_file(self.config.lease_file, MAX_LEASE_BYTES, "O arquivo de concessões DHCP").decode("utf-8")
            devices = parse_leases(text, self.config)
        except FileNotFoundError:
            devices = {}
            warnings.append("Ainda não há concessões DHCP do LabGuard.")
        result = self.command(["ip", "-j", "neigh", "show", "dev", self.config.lan_interface], check=False)
        try:
            if result.returncode:
                raise ValueError()
            neighbors = json.loads(result.stdout)
            if not isinstance(neighbors, list):
                raise ValueError()
            merge_neighbors(devices, neighbors, self.config)
        except (ValueError, TypeError):
            warnings.append("Não foi possível consultar os vizinhos da interface LAN.")
        blocked_macs = {row.get("mac") for row in state["blocked"].values() if row.get("mac")}
        for key, entry in state["blocked"].items():
            ip = blocked_address(key)
            devices.setdefault(ip, {"ip": ip, "mac": entry.get("mac", ""), "name": entry.get("name", ""),
                                    "state": "Bloqueio salvo; presença não confirmada", "last_seen": "", "dns_queries": 0,
                                    "protected": ip in self.config.protected_ips})
        for ip, entry in devices.items():
            saved = state["blocked"].get(ip)
            same_identity = bool(saved and (not saved.get("mac") or not entry.get("mac") or saved["mac"] == entry["mac"]))
            entry["blocked"] = same_identity or entry.get("mac") in blocked_macs
            if ip in self.config.protected_ips:
                entry["blocked"] = False
            if entry["blocked"] and not entry.get("mac"):
                warnings.append(f"{ip}: bloqueio somente por IP; não foi observado MAC.")
        return sorted(devices.values(), key=lambda row: ipaddress.IPv4Address(row["ip"])), warnings

    def current_block_ips(self, state):
        devices, _ = self.devices(state)
        return [row["ip"] for row in devices if row["blocked"] and not row["protected"]]

    def reconcile_firewall(self, state, devices=None):
        """Follow existing MAC policies after DHCP changes; never touch other tables."""
        if not self.table_exists():
            raise AgentError("A tabela LabGuard está ausente; aplique a configuração pelo serviço de inicialização.")
        if devices is None:
            devices, _ = self.devices(state)
        desired = {row["ip"] for row in devices if row["blocked"] and not row["protected"]}
        listed = self.command(["nft", "-j", "list", "set", "inet", TABLE, "blocked_v4"])
        try:
            document = json.loads(listed.stdout)
            current_set = next(row["set"] for row in document["nftables"]
                               if "set" in row and row["set"].get("name") == "blocked_v4")
            current = {str(ipaddress.IPv4Address(value)) for value in current_set.get("elem", [])}
        except (ValueError, KeyError, StopIteration, TypeError) as exc:
            raise AgentError("Não foi possível verificar o conjunto IPv4 aplicado no firewall.") from exc
        if current != desired:
            self.nft_apply(state, desired)
        return current != desired

    def reconcile(self):
        with self.lock():
            return self.reconcile_firewall(self.load_state())

    def snapshot(self, state):
        catalog = load_ai_catalog()
        devices, warnings = self.devices(state)
        firewall_present = self.table_exists()
        firewall = firewall_present
        if firewall:
            try:
                self.reconcile_firewall(state, devices)
            except AgentError as exc:
                warnings.append("Falha ao sincronizar IP/MAC: " + str(exc))
                firewall = False
        events = parse_events(read_tail(self.config.log_file), self.config.network)
        counts = collections.Counter(row["client_ip"] for row in events)
        for row in devices:
            row["dns_queries"] = counts[row["ip"]]
        conn = self.command(["conntrack", "-L", "-f", "ipv4", "-o", "extended"], check=False)
        connections = parse_connections(conn.stdout, self.config) if conn.returncode == 0 else []
        if conn.returncode:
            warnings.append("Conexões indisponíveis: verifique o pacote conntrack e os privilégios do agente.")
        dns = self.command(["systemctl", "is-active", "--quiet", SERVICE], check=False).returncode == 0
        try:
            forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
        except OSError:
            forwarding = False
        if not firewall_present:
            warnings.append("A tabela de firewall LabGuard não está carregada.")
        if not dns:
            warnings.append("O serviço DNS/DHCP LabGuard não está ativo.")
        if not forwarding:
            warnings.append("O encaminhamento IPv4 do gateway está desativado.")
        nft_rules = self.command(["nft", "list", "ruleset"], check=False)
        if nft_rules.returncode == 0 and re.search(r"\bflowtable\b|\bflow\s+(?:add|offload)\b", nft_rules.stdout):
            warnings.append("Há flowtable/offload no gateway: desative antes de usar o corte de máquinas.")
        return {"mode": "gateway", "version": VERSION, "timestamp": now(),
                "gateway": {"hostname": socket.gethostname(), "lab_cidr": str(self.config.network),
                            "lan_interface": self.config.lan_interface, "wan_interface": self.config.wan_interface,
                            "ipv6_policy": "Bloqueado no encaminhamento do laboratório"},
                "health": {"firewall": firewall, "dns": dns, "forwarding": forwarding},
                "devices": devices, "domains": effective_domains(state, catalog), "events": events,
                "policies": {"ai_block": {"enabled": state.get("ai_block_enabled", False),
                                          "services": catalog["services"], "domains": catalog["domains"],
                                          "domain_count": len(catalog["domains"]),
                                          "updated_at": catalog["updated_at"]}},
                "connections": connections, "audit": list(reversed(state["audit"][-250:])),
                "metrics": {"queries_window": len(events), "blocked_events_window": sum(row["status"] == "Bloqueio DNS confirmado" for row in events),
                            "observed_devices": len(devices), "blocked_devices": sum(row["blocked"] for row in devices)},
                "warnings": warnings}

    def apply_startup(self):
        with self.lock():
            load_ai_catalog()
            state = self.load_state()
            self.nft_apply(state, self.current_block_ips(state))
            self.dns_apply(state, restart=False)
            self.save_state(state)

    def handle(self, request):
        try:
            return self._handle_request(request)
        except AgentError as error:
            # A read-only refresh does not add noise. Denials/failures of
            # administrative operations remain visible without logging input.
            if not isinstance(request, dict) or request.get("action") != "snapshot":
                try:
                    with self.lock():
                        state = self.load_state()
                        action, target = audit_context(request)
                        state["audit"].append({"time": now(), "action": action, "target": target,
                                               "outcome": "Não concluído: " + " ".join(str(error).split())[:240]})
                        state["audit"] = state["audit"][-1000:]
                        self.save_state(state)
                except (AgentError, OSError, ValueError):
                    # Do not replace a corrupt state just to record an event.
                    pass
            raise

    def _handle_request(self, request):
        if not isinstance(request, dict) or type(request.get("version")) is not int or request.get("version") != 1:
            raise AgentError("Protocolo incompatível: use version=1.")
        action, params = request.get("action"), request.get("params", {})
        if action not in ("snapshot", "add_domain", "remove_domain", "set_device_block", "set_ai_block") or not isinstance(params, dict):
            raise AgentError("Ação não permitida.")
        allowed = {"snapshot": set(), "add_domain": {"domain", "category"}, "remove_domain": {"domain"}, "set_device_block": {"ip", "blocked"}, "set_ai_block": {"enabled"}}[action]
        if set(params) - allowed:
            raise AgentError("Parâmetro não permitido.")
        with self.lock():
            state = self.load_state()
            if action == "snapshot":
                return self.snapshot(state)
            catalog = load_ai_catalog()
            previous = copy.deepcopy(state)
            target = ""
            if action in ("add_domain", "remove_domain"):
                target = domain_name(params.get("domain"))
                exists = any(row["domain"] == target for row in state["domains"])
                if action == "add_domain":
                    if exists:
                        raise AgentError("Esse domínio já está na lista.")
                    category = params.get("category", "Jogos")
                    if not isinstance(category, str) or not 1 <= len(category.strip()) <= 60 or any(ord(c) < 32 for c in category):
                        raise AgentError("Categoria inválida; use até 60 caracteres sem quebras de linha.")
                    if len(state["domains"]) >= MAX_DOMAINS:
                        raise AgentError("Limite de 10.000 domínios atingido.")
                    state["domains"].append({"domain": target, "category": category.strip(), "created_at": now()})
                else:
                    if not exists:
                        if state.get("ai_block_enabled") and target in catalog["domains"]:
                            raise AgentError("Este domínio pertence ao perfil IA. Desative o perfil IA para retirar esse bloqueio.")
                        raise AgentError("Domínio não encontrado.")
                    state["domains"] = [row for row in state["domains"] if row["domain"] != target]
            elif action == "set_ai_block":
                enabled = params.get("enabled")
                if type(enabled) is not bool:
                    raise AgentError("enabled precisa ser true ou false.")
                state["ai_block_enabled"] = enabled
                target = "Perfil de inteligência artificial"
            else:
                target = str(self.config.host(params.get("ip")))
                blocked = params.get("blocked")
                if not isinstance(blocked, bool):
                    raise AgentError("blocked precisa ser true ou false.")
                if target in self.config.protected_ips:
                    raise AgentError("Esta máquina está protegida na configuração do gateway.")
                devices, _ = self.devices(state)
                selected = next((row for row in devices if row["ip"] == target), None)
                if not selected:
                    raise AgentError("A máquina ainda não foi observada pelo gateway.")
                if blocked:
                    if selected.get("mac") and any(row.get("mac") == selected["mac"] and row["protected"] for row in devices):
                        raise AgentError("Esse MAC está associado a uma máquina protegida.")
                    occupied = state["blocked"].get(target)
                    if occupied and occupied.get("mac") and selected.get("mac") and occupied["mac"] != selected["mac"]:
                        state["blocked"][target + "|" + occupied["mac"]] = state["blocked"].pop(target)
                    state["blocked"][target] = {"mac": selected.get("mac", ""), "name": selected.get("name", ""), "created_at": now()}
                else:
                    mac = selected.get("mac")
                    for key, row in list(state["blocked"].items()):
                        if (mac and row.get("mac") == mac) or (not row.get("mac") and blocked_address(key) == target):
                            del state["blocked"][key]
            state["audit"].append({"time": now(), "action": {"add_domain": "Bloquear domínio", "remove_domain": "Remover domínio", "set_device_block": "Cortar internet" if params.get("blocked") else "Liberar internet", "set_ai_block": "Ativar bloqueio de IA" if params.get("enabled") else "Desativar bloqueio de IA"}[action],
                                   "target": target, "outcome": "Aplicado"})
            state["audit"] = state["audit"][-1000:]
            old_dns = self.config.dnsmasq_config.read_text() if self.config.dnsmasq_config.exists() else None
            had_table = self.table_exists()
            try:
                if action == "set_device_block":
                    # Never report success when acceleration can bypass these hooks.
                    rules = self.command(["nft", "list", "ruleset"])
                    if re.search(r"\bflowtable\b|\bflow\s+(?:add|offload)\b", rules.stdout):
                        raise AgentError("Desative flowtable/offload no gateway antes de cortar máquinas.")
                    self.nft_apply(state, self.current_block_ips(state))
                else:
                    self.dns_apply(state)
                self.save_state(state)
            except Exception as exc:
                rollback_errors = []
                try:
                    if action == "set_device_block":
                        if had_table:
                            self.nft_apply(previous, self.current_block_ips(previous))
                        elif self.table_exists():
                            self.command(["nft", "delete", "table", "inet", TABLE])
                    elif old_dns is not None:
                        atomic_write(self.config.dnsmasq_config, old_dns, 0o644)
                        self.command(["systemctl", "restart", SERVICE], timeout=25)
                    else:
                        self.config.dnsmasq_config.unlink(missing_ok=True)
                        self.command(["systemctl", "stop", SERVICE])
                    self.save_state(previous)
                except Exception as rollback:
                    rollback_errors.append(str(rollback))
                detail = str(exc)
                if rollback_errors:
                    detail += "; A restauração também falhou: " + "; ".join(rollback_errors)
                else:
                    detail += "; a configuração anterior foi restaurada."
                raise AgentError(detail) from exc
            try:
                return self.snapshot(state)
            except (AgentError, OSError) as error:
                # Configuration already committed. Do not imply that retrying
                # is required, nor roll back only because diagnostics failed.
                return self.degraded_snapshot(state, catalog, error)

    def degraded_snapshot(self, state, catalog, error):
        return {"mode": "gateway", "version": VERSION, "timestamp": now(),
                "gateway": {"hostname": socket.gethostname(), "lab_cidr": str(self.config.network),
                            "lan_interface": self.config.lan_interface, "wan_interface": self.config.wan_interface,
                            "ipv6_policy": "Política configurada; verificação indisponível"},
                "health": {"firewall": False, "dns": False, "forwarding": False},
                "devices": [], "domains": effective_domains(state, catalog), "events": [], "connections": [],
                "audit": list(reversed(state["audit"][-250:])),
                "policies": {"ai_block": {"enabled": state.get("ai_block_enabled", False), "services": catalog["services"],
                                          "domains": catalog["domains"], "domain_count": len(catalog["domains"]),
                                          "updated_at": catalog["updated_at"]}},
                "metrics": {"queries_window": 0, "blocked_events_window": 0, "observed_devices": 0, "blocked_devices": 0},
                "warnings": ["A alteração foi aplicada e salva, mas a verificação do gateway falhou. Atualize o painel antes de outra ação.",
                             "Diagnóstico indisponível: " + " ".join(str(error).split())[:240]]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Agente JSON restrito do LabGuard")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate-config", action="store_true")
    mode.add_argument("--apply", action="store_true", help="Aplicar configuração no boot; exclusivo do administrador local")
    mode.add_argument("--reconcile", action="store_true", help="Sincronizar os IPs bloqueados com os MACs observados; uso do timer root")
    args = parser.parse_args(argv)
    try:
        config = Config(read_json_file(args.config, MAX_CONFIG_BYTES, "A configuração"))
        if args.validate_config:
            load_ai_catalog()
            print(json.dumps({"ok": True, "lab_cidr": str(config.network)}, ensure_ascii=False))
            return 0
        if os.geteuid() != 0:
            raise AgentError("Execute o agente pelo comando sudo restrito instalado no gateway.")
        verify_privileged_installation(config, args.config)
        agent = Agent(config)
        if args.apply:
            agent.apply_startup()
            print(json.dumps({"ok": True, "message": "Configuração aplicada"}, ensure_ascii=False))
            return 0
        if args.reconcile:
            changed = agent.reconcile()
            print(json.dumps({"ok": True, "changed": changed}, ensure_ascii=False))
            return 0
        raw = read_request(sys.stdin.buffer)
        request = json.loads(raw.decode("utf-8"))
        data = agent.handle(request)
        print(json.dumps({"ok": True, "data": data}, ensure_ascii=False))
        return 0
    except (AgentError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
