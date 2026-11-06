"""Restricted RouterOS 7 REST transport. No router services are enabled here."""
from __future__ import annotations

import base64
from collections import Counter
import copy
from datetime import datetime, timezone
import ipaddress
import json
import re
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .demo import normalize_domain, normalize_mac
from .transport import TransportError, validate_host

MAX_RESPONSE = 2 * 1024 * 1024
MAX_ROWS = 5000
DEADLINE_SECONDS = 25
SOCKET_TIMEOUT = 3
PREFIX = "LabGuard2:v1:"
ID_RE = re.compile(r"\*[0-9A-Fa-f]{1,16}\Z")
CAPABILITIES = ("inventory", "domain_filtering", "device_internet_cut", "address_blocking", "ai_block", "dns_history", "port_control")


class DirectRouterOSError(TransportError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _yes(value):
    return value is True or value in ("true", "yes")


def _no(value):
    return value is False or value in ("false", "no")


def _active(row):
    return not _yes(row.get("disabled")) and not _yes(row.get("invalid"))


def _network(value):
    try:
        result = ipaddress.IPv4Network(value, strict=True)
        private = (ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        if not any(result.subnet_of(part) for part in private) or not 16 <= result.prefixlen <= 30:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise ValueError("Use uma sub-rede IPv4 privada entre /16 e /30 para o laboratório.") from None


def _ip(value):
    if not isinstance(value, str):
        raise ValueError("Informe um endereço IPv4 válido.")
    return str(ipaddress.IPv4Address(value))


def _metadata(kind, address, category="Outros", created=None, direction="out"):
    data = {"k": kind, "a": address, "c": category, "t": created or _now(), "d": direction}
    return PREFIX + base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode()).decode().rstrip("=")


def _parse_metadata(row):
    comment = row.get("comment", "")
    if not isinstance(comment, str) or not comment.startswith(PREFIX) or len(comment) > 1024:
        return None
    try:
        raw = comment[len(PREFIX):]
        data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True))
        if set(data) != {"k", "a", "c", "t", "d"} or data["k"] not in ("ip", "mac", "domain") or data["d"] not in ("out", "in"):
            return None
        normalized = normalize_domain(data["a"]) if data["k"] == "domain" else normalize_mac(data["a"]) if data["k"] == "mac" else _ip(data["a"])
        if normalized != data["a"] or not isinstance(data["c"], str) or not 1 <= len(data["c"]) <= 60 or any(ord(c) < 32 for c in data["c"]):
            return None
        if not isinstance(data["t"], str) or datetime.fromisoformat(data["t"]).tzinfo is None:
            return None
        return data
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None


class DirectRouterOSTransport:
    mode = "equipment"

    def __init__(self, host, port=443, user="", password="", ca_file="", protected_ips=None,
                 protected_macs=None, lab_cidr="", manage_rules=False, wan_interface_list="WAN"):
        self.host = validate_host(host)
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            raise ValueError("Informe o IP literal do roteador; nomes DNS não têm prazo de resolução controlável por este adaptador.") from None
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Porta HTTPS inválida.")
        if not isinstance(user, str) or not user or len(user) > 128 or ":" in user or any(ord(c) < 32 for c in user):
            raise ValueError("Informe o usuário REST do roteador.")
        if not isinstance(password, str) or not password or len(password) > 1024 or any(ord(c) < 32 for c in password):
            raise ValueError("Informe a senha do usuário REST do roteador.")
        if type(manage_rules) is not bool:
            raise ValueError("manage_rules precisa ser booleano.")
        if not isinstance(wan_interface_list, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", wan_interface_list):
            raise ValueError("Nome da lista WAN inválido.")
        if not isinstance(lab_cidr, str):
            raise ValueError("Sub-rede inválida.")
        self.port, self.user, self.password = port, user, password
        self.lab_cidr = str(_network(lab_cidr)) if lab_cidr else ""
        self.protected_ips = {_ip(value) for value in self._values(protected_ips)}
        self.protected_macs = {normalize_mac(value) for value in self._values(protected_macs)}
        self.manage_rules, self.wan_interface_list = manage_rules, wan_interface_list
        if ca_file is not None and not isinstance(ca_file, str):
            raise ValueError("Arquivo CA inválido.")
        self.ca_file = ca_file or ""
        context = ssl.create_default_context(cafile=self.ca_file or None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
        authority = "[" + self.host + "]" if ":" in self.host else self.host
        self._base = f"https://{authority}:{port}/rest/"
        self._lock = threading.Lock()
        self._closed = False
        self._management_ip = ""
        self._audit = []

    @staticmethod
    def _values(value):
        if value is None:
            return []
        if not isinstance(value, (list, tuple)) or len(value) > 256:
            raise ValueError("Use uma lista de até 256 endereços protegidos.")
        return value

    def close(self):
        # Never wait for an HTTP worker from the GUI thread. Python strings
        # cannot promise secure memory erasure; invalidate future requests.
        self._closed = True
        self.user = self.password = ""
        self._opener = None

    def _check_open(self):
        if self._closed:
            raise DirectRouterOSError("A conexão com o roteador foi encerrada.")

    def _http(self, method, path, deadline, payload=None):
        self._check_open()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DirectRouterOSError("Tempo total de consulta ao roteador esgotado.")
        opener, user, password = self._opener, self.user, self.password
        headers = {"Accept": "application/json", "Authorization": "Basic " + base64.b64encode((user + ":" + password).encode()).decode()}
        body = None if payload is None else json.dumps(payload, ensure_ascii=True).encode()
        if body is not None:
            headers["Content-Type"] = "application/json"
        self._check_open()
        try:
            request = Request(self._base + path, data=body, headers=headers, method=method)
            with opener.open(request, timeout=min(SOCKET_TIMEOUT, remaining)) as response:
                # Capture the actual socket's local endpoint, rather than
                # guessing which PC address a multi-interface machine uses.
                try:
                    response_socket = response.fp.raw._sock
                    self._management_ip = _ip(response_socket.getsockname()[0])
                except (AttributeError, OSError, ValueError):
                    response_socket = None
                if getattr(response, "status", 200) not in (200, 201, 204):
                    raise DirectRouterOSError("Resposta HTTP inesperada do roteador.")
                content_length = response.headers.get("Content-Length")
                if content_length and (not content_length.isdigit() or int(content_length) > MAX_RESPONSE):
                    raise DirectRouterOSError("Resposta do roteador excede o limite permitido.")
                chunks, total = [], 0
                reader = getattr(response, "read1", None)
                if not callable(reader):
                    raise DirectRouterOSError("A resposta HTTPS não permite leitura com prazo limitado.")
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DirectRouterOSError("Tempo total de consulta ao roteador esgotado.")
                    if response_socket is not None:
                        response_socket.settimeout(min(SOCKET_TIMEOUT, remaining))
                    chunk = reader(min(65536, MAX_RESPONSE + 1 - total))
                    if time.monotonic() >= deadline:
                        raise DirectRouterOSError("Tempo total de consulta ao roteador esgotado.")
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > MAX_RESPONSE:
                        raise DirectRouterOSError("Resposta do roteador excede o limite permitido.")
                raw = b"".join(chunks)
                if not raw:
                    return []
                result = json.loads(raw.decode("utf-8"))
                if not isinstance(result, (dict, list)) or isinstance(result, list) and (len(result) > MAX_ROWS or any(not isinstance(row, dict) for row in result)):
                    raise DirectRouterOSError("Formato de resposta REST inválido.")
                records = result if isinstance(result, list) else [result]
                if any(not isinstance(key, str) or not isinstance(value, (str, bool, int, float, type(None))) for row in records for key, value in row.items()):
                    raise DirectRouterOSError("A resposta REST contém campos inesperados.")
                return result
        except HTTPError as error:
            code = error.code
            error.close()
            raise DirectRouterOSError("Acesso REST recusado (HTTP %s). Verifique permissões e HTTPS; redirecionamentos não são seguidos." % code) from None
        except (URLError, OSError, ValueError, TimeoutError, RecursionError) as error:
            raise DirectRouterOSError("Não foi possível confirmar a resposta REST HTTPS. Verifique endereço, certificado e conexão.") from None

    def _collect(self, deadline):
        resource = self._http("GET", "system/resource", deadline)
        resource = resource[0] if isinstance(resource, list) and resource else resource
        if not isinstance(resource, dict) or not re.match(r"^7(?:\.|$)", str(resource.get("version", ""))):
            raise DirectRouterOSError("Este adaptador exige RouterOS 7 com REST HTTPS.")
        endpoints = ("system/identity", "ip/address", "ip/dhcp-server/network", "ip/dhcp-server/lease", "ip/arp",
                     "ip/firewall/filter", "interface/list", "interface/list/member", "interface", "ip/dhcp-server",
                     "ip/dns", "ip/dns/static", "ipv6/settings", "ip/settings", "interface/ethernet/switch")
        data, warnings = {"system/resource": resource}, []
        for path in endpoints:
            try:
                value = self._http("GET", path, deadline)
                data[path] = [value] if isinstance(value, dict) else value
            except DirectRouterOSError:
                data[path] = None
                warnings.append("Consulta indisponível: /" + path + "; funções dependentes permanecem desativadas.")
        self._check_open()
        return data, warnings

    def _view(self, data, warnings):
        def rows(path):
            return data.get(path) or []
        addresses = []
        for row in rows("ip/address"):
            try:
                address = ipaddress.IPv4Interface(row["address"])
                if _active(row):
                    addresses.append((address, row.get("interface", "")))
            except (ValueError, KeyError, TypeError):
                continue
        router_ips = {str(address.ip) for address, _ in addresses}
        dhcp = []
        for row in rows("ip/dhcp-server/network"):
            try:
                dhcp.append((_network(row["address"]), row))
            except (ValueError, KeyError, TypeError):
                continue
        candidates = {str(network) for network, _ in dhcp if any(address.ip in network for address, _ in addresses)}
        resolved = self.lab_cidr or (next(iter(candidates)) if len(candidates) == 1 else "")
        network = _network(resolved) if resolved else None
        if not network:
            warnings.append("Escolha uma única sub-rede do laboratório; não foi possível determiná-la sem ambiguidade.")
        devices = {}
        for path, evidence in (("ip/dhcp-server/lease", "DHCP"), ("ip/arp", "ARP")):
            for row in rows(path):
                try:
                    address = _ip(row.get("active-address") or row.get("address"))
                    mac = normalize_mac(row.get("active-mac-address") or row.get("mac-address"))
                except (ValueError, TypeError):
                    continue
                if network and ipaddress.IPv4Address(address) not in network or not ipaddress.IPv4Address(address).is_private:
                    continue
                device = devices.setdefault(address, {"ip": address, "mac": mac, "name": "", "state": "Observado no roteador",
                    "last_seen": "", "observed": True, "dns_queries": 0, "evidence": [], "interface": row.get("interface", ""),
                    "wifi": None, "ssid": None, "ap": None})
                if device["mac"] != mac:
                    device["identity_conflict"] = True
                device["mac"] = mac
                device["name"] = str(row.get("host-name", device["name"]))[:100]
                device["evidence"].append(evidence)
                device["state"] = str(row.get("status", "")) or ("ARP " + str(row.get("complete", "observado")))
        protected_ips = self.protected_ips | router_ips | ({self._management_ip} if self._management_ip else set())
        protected_macs = set(self.protected_macs)
        for row in rows("interface"):
            try:
                protected_macs.add(normalize_mac(row.get("mac-address")))
            except ValueError:
                pass
        protected_macs.update(row["mac"] for row in devices.values() if row["ip"] in protected_ips)
        wan_members = {row.get("interface") for row in rows("interface/list/member") if row.get("list") == self.wan_interface_list and _active(row)}
        wan_lists = [row for row in rows("interface/list") if row.get("name") == self.wan_interface_list]
        lab_interfaces = {interface for address, interface in addresses if network and address.ip in network}
        served = {row.get("interface") for row in rows("ip/dhcp-server") if _active(row)}
        wan_ok = bool(network and wan_lists and wan_members and not wan_members & (lab_interfaces | served))
        wan_ok = wan_ok and not any(row.get("include") or row.get("exclude") for row in wan_lists)
        wan_ok = wan_ok and all(any(interface == member and address.ip not in network for address, interface in addresses) for member in wan_members)
        wan_ok = wan_ok and all(data.get(path) is not None for path in ("ip/address", "interface/list", "interface/list/member", "ip/dhcp-server"))
        filters = rows("ip/firewall/filter")
        ip_settings = rows("ip/settings")
        ip_settings = ip_settings[0] if ip_settings else {}
        v6 = rows("ipv6/settings")
        v6 = v6[0] if v6 else {}
        ipv6_safe = _yes(v6.get("disable-ipv6")) or _no(v6.get("forward"))
        fasttrack_safe = data.get("ip/firewall/filter") is not None and _no(ip_settings.get("ipv4-fasttrack-active")) and not any(_active(row) and row.get("action") == "fasttrack-connection" for row in filters)
        switches = data.get("interface/ethernet/switch")
        hw_safe = switches is not None and all(not any(_yes(row.get(key)) for key in ("l3-hw-offloading", "l3-hw-offload"))
            and any(_no(row.get(key)) for key in ("l3-hw-offloading", "l3-hw-offload")) for row in switches)
        forwarding = _yes(ip_settings.get("ip-forward"))
        relevant_dhcp = [row for subnet, row in dhcp if network and subnet == network]
        lab_router_ips = {str(address.ip) for address, _ in addresses if network and address.ip in network}
        gateways = [set(str(row.get("gateway", "")).split(",")) for row in relevant_dhcp]
        routed_here = bool(gateways and all(len(values) == 1 and values <= lab_router_ips for values in gateways))
        cuts_ok = bool(network and routed_here and wan_ok and ipv6_safe and fasttrack_safe and hw_safe and forwarding and self._management_ip and data.get("interface") is not None)
        dns_rows = rows("ip/dns")
        dns = dns_rows[0] if dns_rows else {}
        advertised = [set(str(row.get("dns-server", "")).split(",")) for row in relevant_dhcp]
        dns_use = bool(advertised and all(values and "" not in values and values <= router_ips for values in advertised))
        version = str(data["system/resource"].get("version", ""))
        release = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:\s|$)", version)
        modern_dns = bool(release and tuple(int(release.group(i) or 0) for i in (1, 2, 3)) >= (7, 18, 0))
        dns_ok = bool(network and modern_dns and _yes(dns.get("allow-remote-requests")) and dns_use and data.get("ip/dns/static") is not None)
        reasons = []
        if not self.manage_rules:
            reasons.append("Conexão somente para consulta; habilite a autorização de gerenciar regras para alterar o roteador.")
        if not ipv6_safe:
            reasons.append("IPv6 encaminhado ou não verificável: corte de internet desativado para evitar liberação parcial.")
        if not fasttrack_safe:
            reasons.append("FastTrack ativo ou não verificável: corte desativado; o programa não altera a aceleração do roteador.")
        if not wan_ok:
            reasons.append("Lista WAN não confirmada como saída separada da LAN/DHCP; corte desativado.")
        if not hw_safe:
            reasons.append("Offload de roteamento não verificável ou ativo; corte desativado.")
        if not self._management_ip:
            reasons.append("IP desta conexão administrativa não confirmado; corte desativado.")
        if not dns_ok:
            reasons.append("Filtro DNS exige RouterOS 7.18+, DNS remoto já ativo e DHCP anunciando somente DNS do próprio roteador.")
        if not forwarding:
            reasons.append("Encaminhamento IPv4 não confirmado; corte desativado.")
        if not routed_here:
            reasons.append("O DHCP da LAN não confirma este RouterOS como gateway dos alunos; corte desativado.")
        own_filters, address_blocks, groups = [], {}, {}
        for row in filters:
            meta = _parse_metadata(row)
            if meta and meta["k"] in ("ip", "mac"):
                groups.setdefault((meta["k"], meta["a"]), []).append((row, meta))
        ambiguous_filters = set()
        for key, group in groups.items():
            expected = {"out", "in"} if key[0] == "ip" else {"out"}
            coherent = len(group) == len(expected) and {meta["d"] for _, meta in group} == expected
            coherent = coherent and len({(meta["t"], meta["c"]) for _, meta in group}) == 1
            coherent = coherent and len({_active(row) for row, _ in group}) == 1 and all(self._matches_filter(row, meta) and not _yes(row.get("invalid")) for row, meta in group)
            if not coherent:
                ambiguous_filters.add(key)
                continue
            own_filters.extend(group)
            if all(_active(row) for row, _ in group):
                meta = group[0][1]
                address_blocks[key] = {"kind": key[0], "address": key[1], "created_at": meta["t"], "name": "", "source": "LabGuard2"}
        if ambiguous_filters:
            cuts_ok = False
            reasons.append("Há regras LabGuard2 incompletas, duplicadas ou alteradas; revise-as no roteador antes de outro corte.")
        domains, own_domains = [], []
        for row in rows("ip/dns/static"):
            if not _active(row) or row.get("type") != "NXDOMAIN":
                continue
            try:
                name = normalize_domain(row.get("name"))
            except ValueError:
                continue
            meta = _parse_metadata(row)
            owned = bool(meta and meta["k"] == "domain" and meta["a"] == name and _yes(row.get("match-subdomain")) and not row.get("regexp"))
            if owned:
                own_domains.append((row, meta))
            domains.append({"domain": name, "category": meta["c"] if owned else "Regra externa", "created_at": meta["t"] if owned else "", "source": "manual" if owned else "external"})
        domain_counts = Counter(meta["a"] for _, meta in own_domains)
        duplicate_domains = {domain for domain, count in domain_counts.items() if count != 1}
        if duplicate_domains:
            own_domains = [(row, meta) for row, meta in own_domains if meta["a"] not in duplicate_domains]
            dns_ok = False
            reasons.append("Há regras DNS LabGuard2 duplicadas; revise-as no roteador antes de alterar domínios.")
        for device in devices.values():
            device["protected"] = device["ip"] in protected_ips or device["mac"] in protected_macs
            scopes = (["ip"] if ("ip", device["ip"]) in address_blocks else []) + (["mac"] if ("mac", device["mac"]) in address_blocks else [])
            if device["protected"]:
                scopes = []
            device["blocked_by"] = scopes
            device["blocked_ip"], device["blocked_mac"] = "ip" in scopes, "mac" in scopes
            device["blocked"] = bool(scopes)
        caps = {key: False for key in CAPABILITIES}
        caps.update(inventory=True, domain_filtering=self.manage_rules and dns_ok, address_blocking=self.manage_rules and cuts_ok)
        identity = rows("system/identity")
        hostname = str(identity[0].get("name", self.host)) if identity else self.host
        snapshot = {"mode": "equipment", "timestamp": _now(), "version": version,
            "gateway": {"hostname": hostname, "lab_cidr": resolved, "model": str(data["system/resource"].get("board-name", "RouterOS")),
                        "vendor": "MikroTik", "management_host": self.host, "lan_interface": ", ".join(sorted(lab_interfaces)), "wan_interface": self.wan_interface_list,
                        "ipv6_policy": "Sem encaminhamento IPv6 confirmado" if ipv6_safe else "IPv6 ativo ou não verificável"},
            "health": {"dns": dns_ok, "firewall": cuts_ok, "forwarding": forwarding}, "capabilities": caps,
            "devices": sorted(devices.values(), key=lambda row: ipaddress.IPv4Address(row["ip"])), "domains": domains,
            "address_blocks": list(address_blocks.values()), "events": [], "connections": [], "audit": copy.deepcopy(self._audit[-250:][::-1]),
            "metrics": {"observed_devices": len(devices), "blocked_devices": sum(row["blocked"] for row in devices.values()), "queries_window": 0, "blocked_events_window": 0},
            "warnings": warnings + reasons + ["Histórico DNS por cliente e conexões não são fornecidos por este adaptador; campos vazios não significam ausência de acesso.",
                "Wi-Fi/SSID/AP não são inferidos de DHCP/ARP. MAC exige visibilidade de camada 2; roteadores/NAT podem ocultar clientes.",
                "Filtro de domínio atua nas respostas DNS deste roteador; VPN, DNS externo/DoH e cache dos clientes podem contorná-lo."]}
        return snapshot, {"filters": own_filters, "ambiguous_filters": ambiguous_filters, "domains": own_domains, "protected_ips": protected_ips, "protected_macs": protected_macs, "network": network}

    def _matches_filter(self, row, meta):
        if row.get("chain") != "forward" or row.get("action") != "drop" or not ID_RE.fullmatch(str(row.get(".id", ""))):
            return False
        key = "src-mac-address" if meta["k"] == "mac" else "src-address" if meta["d"] == "out" else "dst-address"
        list_key = "out-interface-list" if meta["d"] == "out" else "in-interface-list"
        allowed = {".id", "chain", "action", key, list_key, "comment", "disabled", "invalid", "dynamic", "log", "log-prefix", "bytes", "packets"}
        return not set(row) - allowed and not _yes(row.get("dynamic")) and row.get(key) == meta["a"] and row.get(list_key) == self.wan_interface_list and (meta["k"] != "mac" or meta["d"] == "out")

    def _delete(self, path, row, deadline):
        identifier = row.get(".id", "")
        if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
            raise DirectRouterOSError("Identificador REST inválido; regra preservada.")
        endpoint = path + "/" + quote(identifier, safe="")
        current = self._http("GET", endpoint, deadline)
        if isinstance(current, list) and len(current) == 1:
            current = current[0]
        volatile = {"packets", "bytes"}
        if not isinstance(current, dict) or {key: value for key, value in current.items() if key not in volatile} != {key: value for key, value in row.items() if key not in volatile}:
            raise DirectRouterOSError("A regra foi alterada desde a consulta; nenhuma remoção foi enviada.")
        meta = _parse_metadata(current)
        valid = bool(meta and (path == "ip/firewall/filter" and self._matches_filter(current, meta) or path == "ip/dns/static" and meta["k"] == "domain" and current.get("name") == meta["a"] and current.get("type") == "NXDOMAIN" and _yes(current.get("match-subdomain")) and not current.get("regexp")))
        if not valid:
            raise DirectRouterOSError("A propriedade da regra não pôde ser confirmada; remoção recusada.")
        self._http("DELETE", endpoint, deadline)

    def request(self, action, **params):
        allowed = {"snapshot": set(), "set_address_block": {"kind", "address", "blocked"}, "add_domain": {"domain", "category"}, "remove_domain": {"domain"}}
        if not isinstance(action, str) or action not in allowed or set(params) - allowed[action]:
            raise ValueError("Ação ou parâmetro indisponível neste adaptador.")
        self._check_open()
        if action != "snapshot" and not self.manage_rules:
            raise DirectRouterOSError("Conexão somente para consulta; nenhuma alteração foi autorizada.")
        if not self._lock.acquire(blocking=False):
            raise DirectRouterOSError("Já existe uma consulta ou alteração do roteador em andamento.")
        try:
            deadline = time.monotonic() + DEADLINE_SECONDS
            data, warnings = self._collect(deadline)
            snapshot, context = self._view(data, warnings)
            if action == "snapshot":
                return snapshot
            self._check_open()
            created, target = [], ""
            try:
                if action == "set_address_block":
                    kind, blocked = params.get("kind"), params.get("blocked")
                    if kind not in ("ip", "mac") or type(blocked) is not bool:
                        raise ValueError("Use kind=ip ou mac e blocked=true ou false.")
                    address = _ip(params.get("address")) if kind == "ip" else normalize_mac(params.get("address"))
                    target = kind.upper() + " " + address
                    if (kind, address) in context["ambiguous_filters"]:
                        raise DirectRouterOSError("Regras incompletas, duplicadas ou alteradas desse endereço precisam de revisão manual.")
                    existing = [(row, meta) for row, meta in context["filters"] if meta["k"] == kind and meta["a"] == address]
                    if not blocked:
                        if not existing:
                            raise DirectRouterOSError("Não há regra própria desse endereço para remover.")
                        for row, _ in existing:
                            self._delete("ip/firewall/filter", row, deadline)
                    else:
                        if not snapshot["capabilities"]["address_blocking"]:
                            raise DirectRouterOSError("Pré-condições de corte não confirmadas. " + " ".join(snapshot["warnings"][:8]))
                        network = context["network"]
                        if kind == "ip" and (ipaddress.IPv4Address(address) not in network or ipaddress.IPv4Address(address) in (network.network_address, network.broadcast_address)):
                            raise ValueError("IP fora da sub-rede de clientes.")
                        matches = [row for row in snapshot["devices"] if row["ip" if kind == "ip" else "mac"] == address]
                        if not matches or any(row.get("identity_conflict") for row in matches):
                            raise DirectRouterOSError("Endereço ainda não observado ou com identidade conflitante.")
                        if any(row["protected"] for row in matches) or kind == "ip" and address in context["protected_ips"] or kind == "mac" and address in context["protected_macs"]:
                            raise DirectRouterOSError("Este endereço pertence ao roteador ou à administração protegida.")
                        if not existing:
                            forwards = [row for row in data["ip/firewall/filter"] if row.get("chain") == "forward"]
                            before = forwards[0].get(".id") if forwards else None
                            if before is not None and not ID_RE.fullmatch(str(before)):
                                raise DirectRouterOSError("Não foi possível confirmar a posição segura da regra.")
                            stamp = _now()
                            directions = ("out", "in") if kind == "ip" else ("out",)
                            for direction in directions:
                                key = "src-mac-address" if kind == "mac" else "src-address" if direction == "out" else "dst-address"
                                body = {"chain": "forward", "action": "drop", key: address,
                                    "out-interface-list" if direction == "out" else "in-interface-list": self.wan_interface_list,
                                    "comment": _metadata(kind, address, created=stamp, direction=direction), "disabled": "false"}
                                if before:
                                    body["place-before"] = before
                                made = self._http("PUT", "ip/firewall/filter", deadline, body)
                                if not isinstance(made, dict) or not ID_RE.fullmatch(str(made.get(".id", ""))):
                                    raise DirectRouterOSError("Criação não confirmada; revise as regras LabGuard2 no roteador.")
                                created.append(("ip/firewall/filter", made))
                else:
                    domain = normalize_domain(params.get("domain"))
                    target = domain
                    existing = [(row, meta) for row, meta in context["domains"] if meta["a"] == domain]
                    if action == "remove_domain":
                        if not existing:
                            raise DirectRouterOSError("O domínio não possui uma regra própria LabGuard2; regras externas são preservadas.")
                        for row, _ in existing:
                            self._delete("ip/dns/static", row, deadline)
                    else:
                        if not snapshot["capabilities"]["domain_filtering"]:
                            raise DirectRouterOSError("Filtro DNS indisponível: confirme RouterOS 7.18+, DNS remoto e DHCP usando o roteador.")
                        if existing:
                            raise DirectRouterOSError("Este domínio já possui uma regra LabGuard2.")
                        category = params.get("category", "Outros")
                        if not isinstance(category, str) or not 1 <= len(category.strip()) <= 60 or any(ord(c) < 32 for c in category):
                            raise ValueError("Categoria inválida; use até 60 caracteres.")
                        for row in data["ip/dns/static"]:
                            name = str(row.get("name", "")).lower().rstrip(".")
                            if _active(row) and (row.get("regexp") or name == domain or name.endswith("." + domain) or domain.endswith("." + name) and _yes(row.get("match-subdomain"))):
                                raise DirectRouterOSError("Há uma regra DNS existente que se sobrepõe ao domínio; ela será preservada.")
                        body = {"name": domain, "type": "NXDOMAIN", "match-subdomain": "true", "disabled": "false", "comment": _metadata("domain", domain, category.strip())}
                        made = self._http("PUT", "ip/dns/static", deadline, body)
                        if not isinstance(made, dict) or not ID_RE.fullmatch(str(made.get(".id", ""))):
                            raise DirectRouterOSError("Inclusão DNS não confirmada; revise o roteador antes de repetir.")
                        created.append(("ip/dns/static", made))
                self._check_open()
                # Fresh reads confirm the real resulting state, not an assumed
                # success based only on a PUT/DELETE status code.
                updated_data, updated_warnings = self._collect(deadline)
                updated, updated_context = self._view(updated_data, updated_warnings)
                required = "ip/firewall/filter" if action == "set_address_block" else "ip/dns/static"
                if updated_data.get(required) is None:
                    raise DirectRouterOSError("A consulta final das regras falhou; o resultado da alteração não foi confirmado.")
                if action == "add_domain" and not any(meta["a"] == target for _, meta in updated_context["domains"]):
                    raise DirectRouterOSError("O roteador não confirmou a regra DNS.")
                if action == "add_domain" and not updated["capabilities"]["domain_filtering"]:
                    raise DirectRouterOSError("As condições DNS mudaram durante a operação; bloqueio não confirmado.")
                if action == "set_address_block":
                    present = any(row["kind"] == params["kind"] and row["address"] == address for row in updated["address_blocks"])
                    if present != params["blocked"]:
                        raise DirectRouterOSError("O roteador não confirmou o escopo solicitado.")
                    if params["blocked"] and not updated["capabilities"]["address_blocking"]:
                        raise DirectRouterOSError("As condições do firewall mudaram; corte completo não confirmado.")
                if action == "remove_domain" and any(meta["a"] == target for _, meta in updated_context["domains"]):
                    raise DirectRouterOSError("A remoção DNS não foi confirmada.")
                self._audit.append({"time": _now(), "action": action, "target": target, "outcome": "Confirmado no roteador"})
                self._audit = self._audit[-250:]
                updated["audit"] = copy.deepcopy(self._audit[::-1])
                return updated
            except Exception:
                # Only rollback records whose IDs this operation just created.
                # A lost response is uncertain; never search-and-delete broadly.
                for path, row in reversed(created):
                    try:
                        self._delete(path, row, deadline)
                    except (DirectRouterOSError, ValueError):
                        pass
                self._audit.append({"time": _now(), "action": action, "target": target, "outcome": "Não confirmado; atualize e revise o roteador"})
                self._audit = self._audit[-250:]
                raise
        finally:
            self._lock.release()
