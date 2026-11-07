"""Observação das tabelas locais do sistema, sem sondar ou alterar a rede."""
from __future__ import annotations

from datetime import datetime, timezone
import errno
import ipaddress
import json
from pathlib import Path
import platform
import re
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


def _mac(value):
    try:
        return normalize_mac(value.replace("-", ":")) if isinstance(value, str) else ""
    except ValueError:
        return ""


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


def _read_local_text(path, warnings, label, maximum=MAX_OUTPUT):
    """Read a bounded kernel/cache file. Paths are fixed by the callers."""
    try:
        with Path(path).open("r", encoding="ascii", errors="strict") as stream:
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise ValueError()
        return content
    except (OSError, UnicodeError, ValueError):
        warnings.append(f"Não foi possível ler {label}; essa fonte local permanece indisponível.")
        return None


def _table(value, warnings, label):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        if value is not None:
            warnings.append(f"Formato inesperado em {label}; outra fonte local será tentada.")
        return None
    if len(value) > MAX_ROWS:
        warnings.append(f"Limite de registros atingido em {label}; a amostra foi reduzida.")
    return value[:MAX_ROWS]


def _sys_interface_mac(name):
    if not isinstance(name, str) or name in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
        return ""
    try:
        with (Path("/sys/class/net") / name / "address").open("r", encoding="ascii", errors="strict") as stream:
            return _mac(stream.read(65).strip())
    except (OSError, UnicodeError):
        return ""


def _linux_interfaces_ioctl(warnings):
    """AF_INET GET ioctls only; no socket is connected and no packet is sent."""
    content = _read_local_text("/proc/net/dev", warnings, "a lista local de interfaces", 65536)
    if content is None:
        return None
    lines = content.splitlines()
    if len(lines) < 2 or "Inter-" not in lines[0] or "face" not in lines[1]:
        warnings.append("A lista de interfaces do kernel tem formato inesperado.")
        return None
    names = []
    for line in lines[2:130]:
        name, separator, _ = line.partition(":")
        name = name.strip()
        if separator and name not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            if name not in names:
                names.append(name)
    if len(lines) > 130:
        warnings.append("Limite de interfaces locais atingido; a leitura alternativa é parcial.")
    try:
        import fcntl
        import socket
        import struct
        interfaces, failures, readable = [], False, False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as descriptor:
            for name in names:
                request = struct.pack("16s24x", name.encode("ascii"))
                try:
                    flags = struct.unpack_from("H", fcntl.ioctl(descriptor.fileno(), 0x8913, request), 16)[0]
                    if not flags & 1:
                        readable = True
                        continue
                    address = fcntl.ioctl(descriptor.fileno(), 0x8915, request)
                    mask = fcntl.ioctl(descriptor.fileno(), 0x891B, request)
                    if struct.unpack_from("H", address, 16)[0] != socket.AF_INET or struct.unpack_from("H", mask, 16)[0] != socket.AF_INET:
                        raise ValueError()
                    ipv4 = socket.inet_ntoa(address[20:24])
                    prefix = ipaddress.IPv4Network("0.0.0.0/" + socket.inet_ntoa(mask[20:24])).prefixlen
                    row = {"name": name, "ipv4": ipv4, "prefixlen": prefix}
                    mac = _sys_interface_mac(name)
                    if mac:
                        row["mac"] = mac
                    interfaces.append(row)
                    readable = True
                except OSError as error:
                    if error.errno == errno.EADDRNOTAVAIL:
                        readable = True
                    else:
                        failures = True
                except (ValueError, struct.error):
                    failures = True
        if failures:
            warnings.append("Algumas interfaces não forneceram IPv4 pela leitura alternativa; a amostra pode estar incompleta.")
        if names and not readable:
            warnings.append("Nenhuma interface pôde ser consultada pela API local alternativa.")
            return None
        warnings.append("A leitura alternativa de interfaces pode não incluir todos os endereços secundários; iproute2 continua sendo a fonte preferencial.")
        return interfaces
    except (ImportError, OSError, ValueError):
        warnings.append("A API local alternativa de interfaces está indisponível neste ambiente.")
        return None


def _proc_lines(path, warnings, label, header):
    content = _read_local_text(path, warnings, label)
    if content is None:
        return None
    lines = content.splitlines()
    if not lines or not lines[0].startswith(header):
        warnings.append(f"Formato inesperado em {label}; essa tabela não foi utilizada.")
        return None
    if len(lines) > MAX_ROWS + 1:
        warnings.append(f"Limite de registros atingido em {label}; a amostra foi reduzida.")
    return lines[1:MAX_ROWS + 1]


def _linux_proc_routes(warnings):
    lines = _proc_lines("/proc/net/route", warnings, "as rotas locais do kernel", "Iface")
    if lines is None:
        return None
    routes = []
    for line in lines:
        parts = line.split()
        try:
            if len(parts) < 11 or parts[1] != "00000000" or parts[7] != "00000000":
                continue
            flags = int(parts[3], 16)
            if flags & 3 != 3 or flags & 0x200 or not re.fullmatch(r"[0-9A-Fa-f]{8}", parts[2]):
                continue
            gateway = str(ipaddress.IPv4Address(int(parts[2], 16).to_bytes(4, "little")))
            metric = int(parts[6])
            if gateway == "0.0.0.0" or not 0 <= metric <= 2**31 - 1:
                continue
            routes.append({"name": parts[0], "gateway": gateway, "metric": metric})
        except (ValueError, OverflowError):
            continue
    return routes


def _linux_proc_neighbors(warnings):
    lines = _proc_lines("/proc/net/arp", warnings, "o cache ARP local do kernel", "IP address")
    if lines is None:
        return None
    neighbors = []
    for line in lines:
        parts = line.split()
        try:
            if len(parts) < 6 or int(parts[1], 16) != 1 or not int(parts[2], 16) & 2:
                continue
            neighbors.append({"ip": parts[0], "mac": parts[3], "name": parts[5],
                              "state": "Cache ARP (presença não verificada)"})
        except ValueError:
            continue
    return neighbors


def _linux(warnings):
    executable = shutil.which("ip")
    sources = []
    if not executable:
        warnings.append("O comando ip do iproute2 não está disponível. Serão tentadas fontes locais alternativas; nenhum programa será instalado.")
        addresses = routes = neighbors = None
    else:
        addresses = _table(_json_command([executable, "-j", "-4", "address", "show", "up"], warnings, "os endereços das interfaces"), warnings, "endereços")
        routes = _table(_json_command([executable, "-j", "-4", "route", "show", "default"], warnings, "a rota padrão"), warnings, "rotas")
        neighbors = _table(_json_command([executable, "-j", "-4", "neigh", "show"], warnings, "a tabela local de vizinhos"), warnings, "vizinhos")
        if any(value is not None for value in (addresses, routes, neighbors)):
            sources.append("linux-iproute2")
    interfaces = None
    if addresses is not None:
        interfaces = []
        for adapter in addresses:
            for address in _rows(adapter.get("addr_info")):
                if address.get("family") == "inet":
                    interfaces.append({"name": adapter.get("ifname"), "ipv4": address.get("local"),
                                       "prefixlen": address.get("prefixlen"), "ifindex": adapter.get("ifindex"), "mac": adapter.get("address")})
    else:
        interfaces = _linux_interfaces_ioctl(warnings)
        if interfaces is not None:
            sources.append("linux-ioctl")
            if any(row.get("mac") for row in interfaces):
                sources.append("linux-sysfs-mac")
    if routes is None:
        route_rows = _linux_proc_routes(warnings)
        if route_rows is not None:
            sources.append("linux-proc-route")
    else:
        route_rows = [{"gateway": route.get("gateway"), "name": route.get("dev"), "metric": route.get("metric", 0)} for route in routes]
    if neighbors is None:
        neighbor_rows = _linux_proc_neighbors(warnings)
        if neighbor_rows is not None:
            sources.append("linux-proc-arp")
    else:
        neighbor_rows = [{"ip": row.get("dst"), "mac": row.get("lladdr"), "name": row.get("dev"),
                          "state": ", ".join(str(s) for s in row["state"][:5]) if isinstance(row.get("state"), list) else row.get("state", "")}
                         for row in neighbors]
    return {"interfaces": interfaces or [], "routes": route_rows or [], "neighbors": neighbor_rows or [],
            "dns": _resolv_dns(warnings), "discovery": _discovery(interfaces is not None, route_rows is not None, neighbor_rows is not None, sources)}


def _discovery(interfaces, routes, neighbors, sources):
    return {"source": "local", "read_success": bool(interfaces or routes or neighbors),
            "interfaces_read": bool(interfaces), "routes_read": bool(routes), "neighbors_read": bool(neighbors),
            "sources": list(dict.fromkeys(sources))}


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
  if($address.IPAddress){$interfaces+=@{name=[string]$config.InterfaceAlias;ipv4=[string]$address.IPAddress;prefixlen=[int]$address.PrefixLength;ifindex=[int]$config.InterfaceIndex;mac=[string]$config.NetAdapter.MacAddress}}
 }
 foreach($route in @($config.IPv4DefaultGateway)) {
  if($route.NextHop){$routes+=@{gateway=[string]$route.NextHop;ifindex=[int]$config.InterfaceIndex;metric=[int]$route.RouteMetric+[int]$config.NetIPv4Interface.InterfaceMetric}}
 }
 foreach($server in @($config.DNSServer.ServerAddresses)) {if($server){$dns+=[string]$server}}
}
try {
 $neighbors=@(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 4097 | ForEach-Object {@{ip=[string]$_.IPAddress;mac=[string]$_.LinkLayerAddress;state=[string]$_.State;ifindex=[int]$_.InterfaceIndex}})
} catch {$partial=$true}
@{interfaces=@($interfaces | Select-Object -First 129);routes=@($routes | Select-Object -First 129);neighbors=$neighbors;dns=@($dns | Select-Object -First 33);partial=$partial} | ConvertTo-Json -Depth 5 -Compress
"""


CIM_SCRIPT = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$interfaces=@();$routes=@();$dns=@();$active=@{};$routesRead=$false;$truncated=$false
$adapterRows=@(Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'NetConnectionStatus=2' -ErrorAction Stop | Select-Object -First 129)
if($adapterRows.Count -gt 128){$truncated=$true}
foreach($adapter in @($adapterRows | Select-Object -First 128)) {
 $active[[int]$adapter.InterfaceIndex]=$adapter
}
$configRows=@(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | Select-Object -First 129)
if($configRows.Count -gt 128){$truncated=$true}
foreach($config in @($configRows | Select-Object -First 128)) {
 $index=[int]$config.InterfaceIndex
 if(-not $active.ContainsKey($index)){continue}
 $adapter=$active[$index];$name=[string]$adapter.NetConnectionID
 if(-not $name){$name=[string]$adapter.Name}
 $addresses=@($config.IPAddress);$masks=@($config.IPSubnet)
 if($addresses.Count -gt 32){$truncated=$true}
 for($n=0;$n -lt [Math]::Min($addresses.Count,33);$n++) {
  if($n -lt $masks.Count){$interfaces+=@{name=$name;ipv4=[string]$addresses[$n];netmask=[string]$masks[$n];ifindex=$index;mac=[string]$config.MACAddress}}
 }
 foreach($server in @($config.DNSServerSearchOrder | Select-Object -First 33)){if($server){$dns+=[string]$server}}
}
try {
 $routeRows=@(Get-CimInstance -ClassName Win32_IP4RouteTable -Filter "Destination='0.0.0.0' AND Mask='0.0.0.0'" -ErrorAction Stop | Select-Object -First 129)
 if($routeRows.Count -gt 128){$truncated=$true}
 foreach($route in $routeRows) {
  if($active.ContainsKey([int]$route.InterfaceIndex) -and [int]$route.Type -eq 4 -and [int64]$route.Metric1 -ge 0){$routes+=@{gateway=[string]$route.NextHop;ifindex=[int]$route.InterfaceIndex;metric=[int64]$route.Metric1}}
 }
 $routesRead=$true
} catch {}
@{interfaces=@($interfaces | Select-Object -First 129);routes=@($routes | Select-Object -First 129);dns=@($dns | Select-Object -First 33);routes_read=$routesRead;truncated=$truncated} | ConvertTo-Json -Depth 5 -Compress
"""


def _windows_arp(executable, interfaces, warnings):
    """Parse only cache sections tied to a confirmed local IP and ifindex."""
    try:
        result = run_bounded([executable, "-a"], timeout=8, max_output_bytes=MAX_OUTPUT)
        if result.returncode or len(result.stdout.encode("utf-8")) > MAX_OUTPUT:
            raise ValueError()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired, OutputLimitExceeded):
        warnings.append("O cache ARP alternativo do Windows está indisponível.")
        return None
    allowed = {(str(address), row["ifindex"]) for row in interfaces
               if (address := _private_ipv4(row.get("ipv4"))) is not None and type(row.get("ifindex")) is int and row["ifindex"] > 0}
    neighbors, current, recognized, count = [], None, False, 0
    for line in result.stdout.splitlines():
        header = re.fullmatch(r"\s*[^:]{1,80}:\s*([0-9.]{7,15})\s+---\s+0x([0-9a-fA-F]{1,8})\s*", line)
        if header:
            key = (header.group(1), int(header.group(2), 16))
            current = key if key in allowed else None
            recognized = recognized or current is not None
            continue
        if "---" in line or ":" in line:
            current = None
            continue
        if not current:
            continue
        parts = line.split()
        if len(parts) < 2 or _private_ipv4(parts[0]) is None or not re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", parts[1]):
            continue
        count += 1
        if count > MAX_ROWS:
            warnings.append("Limite do cache ARP alternativo atingido; a amostra foi reduzida.")
            break
        neighbors.append({"ip": parts[0], "mac": parts[1], "ifindex": current[1],
                          "state": "Cache ARP (presença não verificada)"})
    if not recognized:
        warnings.append("O cache ARP não apresentou uma seção correspondente às interfaces locais confirmadas; seu formato não foi presumido.")
        return None
    return neighbors


def _windows(warnings):
    executable = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not executable:
        warnings.append("PowerShell não está disponível para consultar a configuração local. Nenhuma ferramenta será baixada.")
        return {"discovery": _discovery(False, False, False, [])}
    raw = _json_command([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SCRIPT], warnings, "a configuração de rede do Windows")
    raw = raw if isinstance(raw, dict) else {}
    interfaces = _table(raw.get("interfaces"), warnings, "interfaces do Windows")
    routes = _table(raw.get("routes"), warnings, "rotas do Windows")
    neighbors = _table(raw.get("neighbors"), warnings, "vizinhos do Windows")
    dns = raw.get("dns") if isinstance(raw.get("dns"), list) else None
    sources = ["windows-nettcpip"] if any(value is not None for value in (interfaces, routes, neighbors)) else []
    if raw.get("partial") is True:
        warnings.append("A configuração do Windows foi lida, mas a tabela de vizinhos está indisponível para esta conta.")
        if not neighbors:
            neighbors = None
    if interfaces is None or routes is None or dns is None:
        alternative = _json_command([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", CIM_SCRIPT], warnings, "a configuração CIM local alternativa")
        if isinstance(alternative, dict):
            used = False
            if alternative.get("truncated") is True:
                warnings.append("A leitura CIM atingiu um limite local; somente parte da configuração foi consultada.")
            if interfaces is None:
                rows = _table(alternative.get("interfaces"), warnings, "interfaces CIM")
                if rows is not None:
                    interfaces = []
                    for row in rows:
                        try:
                            prefix = ipaddress.IPv4Network("0.0.0.0/" + str(row.get("netmask"))).prefixlen
                        except ValueError:
                            continue
                        interfaces.append(dict(row, prefixlen=prefix))
                    used = True
            if routes is None and alternative.get("routes_read") is True:
                routes = _table(alternative.get("routes"), warnings, "rotas CIM")
                used = used or routes is not None
            if dns is None and isinstance(alternative.get("dns"), list):
                dns = alternative["dns"]
                used = True
            if used:
                sources.append("windows-cim")
                warnings.append("A leitura CIM alternativa pode ter alcance diferente dos cmdlets NetTCPIP; confirme a interface e as métricas com a TI.")
    if neighbors is None:
        arp = shutil.which("arp.exe")
        if arp and interfaces is not None:
            neighbors = _windows_arp(arp, interfaces, warnings)
            if neighbors is not None:
                sources.append("windows-arp")
    return {"interfaces": interfaces or [], "routes": routes or [], "neighbors": neighbors or [], "dns": dns or [],
            "discovery": _discovery(interfaces is not None, routes is not None, neighbors is not None, sources)}


def _normalize(raw, warnings):
    raw = raw if isinstance(raw, dict) else {}
    for key, limit, label in (("interfaces", 128, "interfaces"), ("routes", 128, "rotas"),
                              ("neighbors", MAX_ROWS, "vizinhos"), ("dns", 32, "servidores DNS")):
        if isinstance(raw.get(key), list) and len(raw[key]) > limit:
            warnings.append(f"Limite de {label} atingido; somente parte dos registros locais é apresentada.")
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
        mac = _mac(row.get("mac"))
        if mac:
            clean["mac"] = mac
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
    discovery = raw.get("discovery")
    discovery = discovery if isinstance(discovery, dict) else _discovery(False, False, False, [])
    return {"interfaces": interfaces, "gateway": gateway, "neighbors": sorted(neighbors, key=lambda r: int(ipaddress.IPv4Address(r["ip"]))),
            "dns": dns, "warnings": warnings, "source": "local", "timestamp": _stamp(), "discovery": discovery}


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
                        "evidence": ["ARP local"],
                        "protected": row["ip"] == local["gateway"], "blocked": False,
                        "blocked_ip": False, "blocked_mac": False, "blocked_by": [],
                        "last_seen": "", "sampled_at": local["timestamp"], "dns_queries": 0}
                       for row in local["neighbors"]]
            for row in local["interfaces"]:
                devices.append({"ip": row["ipv4"], "mac": row.get("mac", ""), "name": "Este computador — " + row["name"],
                                "state": "Endereço local", "observed": True, "protected": True,
                                "evidence": ["Interface local"],
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
                    "interfaces": local["interfaces"], "dns": local["dns"], "discovery": local.get("discovery", _discovery(False, False, False, [])),
                    "capabilities": {"inventory": True, "domain_filtering": False, "device_internet_cut": False,
                                     "address_blocking": False, "ai_block": False, "dns_history": False, "port_control": False},
                    "health": {"firewall": False, "dns": False, "forwarding": False},
                    "devices": devices, "domains": [], "events": [], "connections": [], "audit": [], "address_blocks": [],
                    "metrics": {"observed_devices": len(devices), "blocked_devices": 0, "queries_window": 0, "blocked_events_window": 0},
                    "policies": {}, "warnings": local["warnings"]}

    def close(self):
        self._closed = True
