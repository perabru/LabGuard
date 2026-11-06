"""Observação das tabelas locais do sistema, sem sondar ou alterar a rede."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import platform
import shutil
import subprocess
import threading

from .demo import normalize_mac
from .transport import OutputLimitExceeded, TransportError, run_bounded

MAX_OUTPUT = 512 * 1024
MAX_ROWS = 4096
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
BASE_WARNINGS = [
    "Observação parcial: a tabela de vizinhos contém somente endereços conhecidos por este computador; não é uma lista completa das máquinas conectadas.",
    "Uma entrada em cache, inclusive STALE, não confirma que a máquina esteja conectada agora. Não são consultados sites, processos ou conteúdo acessado.",
    "O roteador ou controlador já em uso é responsável pelos bloqueios. Conecte um equipamento compatível para administrar regras; a observação local não modifica a rede.",
    "Marca e modelo do roteador não são inferidos pelo MAC. Confira a etiqueta ou o painel administrativo do equipamento.",
]


def _stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value, maximum=120):
    return value if isinstance(value, str) and len(value) <= maximum and not any(ord(c) < 32 for c in value) else ""


def _private_ipv4(value):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return None
    if not any(address in network for network in PRIVATE_NETWORKS):
        return None
    return address


def _json_command(command, warnings, label):
    try:
        completed = run_bounded(command, timeout=8, max_output_bytes=MAX_OUTPUT)
        if completed.returncode:
            raise ValueError()
        output = completed.stdout.lstrip("\ufeff")
        if len(output.encode("utf-8")) > MAX_OUTPUT:
            raise ValueError()
        result = json.loads(output)
        if not isinstance(result, (list, dict)):
            raise ValueError()
        return result
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired, OutputLimitExceeded):
        warnings.append(f"Não foi possível consultar {label}; o diagnóstico pode estar incompleto.")
        return None


def _rows(value):
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    return [row for row in value[:MAX_ROWS] if isinstance(row, dict)]


def _linux(warnings):
    executable = shutil.which("ip")
    if not executable:
        warnings.append("O comando ip do iproute2 não está disponível. Nenhum programa será instalado automaticamente.")
        return {"interfaces": [], "routes": [], "neighbors": [], "dns": _resolv_dns(warnings)}
    addresses = _json_command([executable, "-j", "-4", "address", "show", "up"], warnings, "os endereços das interfaces")
    routes = _json_command([executable, "-j", "-4", "route", "show", "default"], warnings, "a rota padrão")
    neighbors = _json_command([executable, "-j", "-4", "neigh", "show"], warnings, "a tabela local de vizinhos")
    interfaces = []
    for adapter in _rows(addresses):
        for address in _rows(adapter.get("addr_info")):
            if address.get("family") == "inet":
                interfaces.append({"name": adapter.get("ifname"), "ipv4": address.get("local"),
                                   "prefixlen": address.get("prefixlen"), "ifindex": adapter.get("ifindex")})
    route_rows = [{"gateway": route.get("gateway"), "name": route.get("dev"),
                   "metric": route.get("metric", 0)} for route in _rows(routes)]
    neighbor_rows = [{"ip": row.get("dst"), "mac": row.get("lladdr"), "name": row.get("dev"),
                      "state": ", ".join(str(s) for s in row["state"][:5]) if isinstance(row.get("state"), list) else row.get("state", "")}
                     for row in _rows(neighbors)]
    return {"interfaces": interfaces, "routes": route_rows, "neighbors": neighbor_rows, "dns": _resolv_dns(warnings)}


def _resolv_dns(warnings):
    try:
        with Path("/etc/resolv.conf").open("r", encoding="utf-8", errors="replace") as stream:
            content = stream.read(32768)
    except OSError:
        warnings.append("A configuração DNS local não pôde ser lida.")
        return []
    return [line.split()[1] for line in content.splitlines()
            if len(line.split()) >= 2 and line.split()[0] == "nameserver"][:32]


WINDOWS_SCRIPT = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$interfaces=@();$routes=@();$dns=@();$neighbors=@();$partial=$false
foreach($config in @(Get-NetIPConfiguration -ErrorAction Stop)) {
 foreach($address in @($config.IPv4Address)) {
  if($address.IPAddress){$interfaces+=@{name=[string]$config.InterfaceAlias;ipv4=[string]$address.IPAddress;prefixlen=[int]$address.PrefixLength;ifindex=[int]$config.InterfaceIndex}}
 }
 foreach($route in @($config.IPv4DefaultGateway)) {
  if($route.NextHop){$routes+=@{gateway=[string]$route.NextHop;ifindex=[int]$config.InterfaceIndex;metric=[int]$route.RouteMetric+[int]$config.NetIPv4Interface.InterfaceMetric}}
 }
 foreach($server in @($config.DNSServer.ServerAddresses)) {if($server){$dns+=[string]$server}}
}
try {
 $neighbors=@(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 4096 | ForEach-Object {@{ip=[string]$_.IPAddress;mac=[string]$_.LinkLayerAddress;state=[string]$_.State;ifindex=[int]$_.InterfaceIndex}})
} catch {$partial=$true}
@{interfaces=@($interfaces | Select-Object -First 128);routes=@($routes | Select-Object -First 128);neighbors=$neighbors;dns=@($dns | Select-Object -First 32);partial=$partial} | ConvertTo-Json -Depth 5 -Compress
"""


def _windows(warnings):
    executable = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not executable:
        warnings.append("PowerShell não está disponível para consultar a configuração local. Nenhuma ferramenta será baixada.")
        return {}
    raw = _json_command([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SCRIPT], warnings, "a configuração de rede do Windows")
    if not isinstance(raw, dict):
        return {}
    if raw.get("partial") is True:
        warnings.append("A configuração do Windows foi lida, mas a tabela de vizinhos está indisponível para esta conta.")
    return raw


def _normalize(raw, warnings):
    interfaces, networks, seen = [], [], set()
    for row in _rows(raw.get("interfaces"))[:128]:
        name = _text(row.get("name"))
        address = _private_ipv4(row.get("ipv4"))
        prefix = row.get("prefixlen")
        if not name or address is None or type(prefix) is not int or not 0 <= prefix <= 32:
            continue
        network = ipaddress.IPv4Network((address, prefix), strict=False)
        if prefix <= 30 and address in (network.network_address, network.broadcast_address):
            continue
        key = (name, str(address), prefix)
        if key in seen:
            continue
        seen.add(key)
        clean = {"name": name, "ipv4": str(address), "prefixlen": prefix}
        interfaces.append(clean)
        networks.append((network, name, row.get("ifindex")))

    def on_interface(address, row):
        candidates = []
        for network, name, index in networks:
            if address not in network or network.prefixlen <= 30 and address in (network.network_address, network.broadcast_address):
                continue
            if row.get("ifindex") is not None and index is not None and row["ifindex"] != index:
                continue
            if row.get("name") and row["name"] != name:
                continue
            candidates.append((network, name))
        return candidates

    gateways = []
    for row in _rows(raw.get("routes"))[:128]:
        address = _private_ipv4(row.get("gateway"))
        if address is None or not on_interface(address, row):
            continue
        metric = row.get("metric", 0)
        gateways.append((metric if type(metric) is int and metric >= 0 else 2**31, str(address)))
    gateways.sort()
    gateway = gateways[0][1] if gateways else ""
    if len({value for _, value in gateways}) > 1:
        warnings.append("Há mais de uma rota padrão local. O gateway mostrado tem a menor métrica informada; confirme a interface do laboratório antes de conectar um equipamento.")
    neighbors, observed = [], set()
    own_ips = {row["ipv4"] for row in interfaces}
    for row in _rows(raw.get("neighbors")):
        address = _private_ipv4(row.get("ip"))
        if address is None or str(address) in own_ips or not on_interface(address, row):
            continue
        try:
            mac = normalize_mac(str(row.get("mac", "")).replace("-", ":"))
        except ValueError:
            continue
        state = _text(row.get("state", ""), 80) or "Estado não informado"
        if state.upper() in {"INCOMPLETE", "FAILED", "UNREACHABLE"}:
            continue
        key = (str(address), mac)
        if key in observed:
            continue
        observed.add(key)
        neighbors.append({"ip": str(address), "mac": mac, "state": state})
    dns = []
    for value in raw.get("dns", [])[:32] if isinstance(raw.get("dns"), list) else []:
        try:
            address = ipaddress.ip_address(value)
        except (ValueError, TypeError):
            continue
        if address.is_unspecified or address.is_multicast or str(address) in dns:
            continue
        dns.append(str(address))
    if not interfaces:
        warnings.append("Nenhuma interface IPv4 privada válida foi identificada. Confira a conexão do computador ao laboratório.")
    if not gateway:
        warnings.append("Gateway IPv4 privado não identificado nas rotas locais. Informe o equipamento manualmente após conferir sua configuração.")
    return {"interfaces": interfaces, "gateway": gateway, "neighbors": sorted(neighbors, key=lambda r: int(ipaddress.IPv4Address(r["ip"]))),
            "dns": dns, "warnings": warnings, "source": "local", "timestamp": _stamp()}


def discover_local_network():
    """Leia somente configuração e caches locais; não faz scan nem consultas DNS."""
    warnings = list(BASE_WARNINGS)
    system = platform.system()
    if system == "Linux":
        raw = _linux(warnings)
    elif system == "Windows":
        raw = _windows(warnings)
    else:
        raw = {}
        warnings.append("Diagnóstico automático disponível somente no Windows e Linux. Configure o equipamento manualmente neste sistema.")
    return _normalize(raw, warnings)


class LocalObservationTransport:
    mode = "observation"
    host = ""
    port = ""

    def __init__(self):
        self._closed = False
        self._lock = threading.Lock()

    def request(self, action, **params):
        with self._lock:
            if self._closed:
                raise TransportError("A observação local foi encerrada. Conecte novamente.")
            if action != "snapshot" or params:
                raise TransportError("Observação local permite somente consulta. Conecte o roteador/controlador compatível para alterar a rede.")
            local = discover_local_network()
            devices = [{"ip": row["ip"], "mac": row["mac"], "name": "Gateway local" if row["ip"] == local["gateway"] else "Nome não identificado",
                        "state": "Cache local: " + row["state"], "observed": True,
                        "protected": row["ip"] == local["gateway"], "blocked": False,
                        "blocked_ip": False, "blocked_mac": False, "blocked_by": [],
                        "last_seen": "", "sampled_at": local["timestamp"], "dns_queries": 0}
                       for row in local["neighbors"]]
            for row in local["interfaces"]:
                devices.append({"ip": row["ipv4"], "mac": "", "name": "Este computador — " + row["name"],
                                "state": "Endereço local", "observed": True, "protected": True,
                                "blocked": False, "blocked_ip": False, "blocked_mac": False,
                                "blocked_by": [], "last_seen": local["timestamp"], "dns_queries": 0})
            gateway_address = _private_ipv4(local["gateway"])
            primary = next((row for row in local["interfaces"] if gateway_address is not None and gateway_address in ipaddress.IPv4Network((row["ipv4"], row["prefixlen"]), strict=False)), None)
            return {"mode": "observation", "source": "local", "timestamp": local["timestamp"],
                    "gateway": {"hostname": local["gateway"] or "Não identificado", "ip": local["gateway"],
                                "vendor": "Desconhecido", "model": "Desconhecido",
                                "lab_cidr": str(ipaddress.IPv4Network((primary["ipv4"], primary["prefixlen"]), strict=False)) if primary else "",
                                "lan_interface": primary["name"] if primary else "", "wan_interface": "Não identificado",
                                "ipv6_policy": "Não verificada na observação local"},
                    "interfaces": local["interfaces"], "dns": local["dns"],
                    "capabilities": {"inventory": True, "domain_filtering": False, "device_internet_cut": False,
                                     "address_blocking": False, "ai_block": False, "dns_history": False, "port_control": False},
                    "health": {"firewall": False, "dns": False, "forwarding": False},
                    "devices": devices, "domains": [], "events": [], "connections": [], "audit": [], "address_blocks": [],
                    "metrics": {"observed_devices": len(devices), "blocked_devices": 0, "queries_window": 0, "blocked_events_window": 0},
                    "policies": {}, "warnings": local["warnings"]}

    def close(self):
        self._closed = True
