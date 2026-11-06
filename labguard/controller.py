"""Uma interface de administração, com capacidades confirmadas por cada fonte."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import threading


class ControllerError(RuntimeError):
    pass


CAPABILITY_NAMES = ("inventory", "domain_filtering", "device_internet_cut", "address_blocking",
                    "ai_block", "dns_history", "port_control")
ACTION_CAPABILITY = {"add_domain": "domain_filtering", "remove_domain": "domain_filtering",
                     "set_device_block": "device_internet_cut", "set_address_block": "address_blocking",
                     "set_ai_block": "ai_block"}


def snapshot_capabilities(snapshot):
    """Fontes de observação nunca ganham poder de alteração por um campo recebido."""
    result = dict.fromkeys(CAPABILITY_NAMES, False)
    if not isinstance(snapshot, dict):
        return result
    mode = snapshot.get("mode")
    if mode in {"demo", "gateway"}:
        result.update(inventory=True, domain_filtering=True, device_internet_cut=True,
                      address_blocking=True, ai_block=True, dns_history=True)
    elif mode == "equipment":
        source = snapshot.get("capabilities", {})
        if isinstance(source, dict):
            result.update({key: source.get(key) is True for key in CAPABILITY_NAMES})
    elif mode == "observation":
        result["inventory"] = True
    return result


def normalize_snapshot(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("mode") not in {"observation", "equipment", "gateway", "demo"}:
        raise ControllerError("A fonte não retornou um inventário compatível.")
    result = copy.deepcopy(snapshot)
    result["capabilities"] = snapshot_capabilities(result)
    for key in ("devices", "domains", "events", "connections", "audit", "address_blocks", "warnings"):
        if key not in result:
            result[key] = []
        if not isinstance(result[key], list):
            raise ControllerError("A fonte retornou um inventário inválido.")
    result.setdefault("health", {})
    result.setdefault("metrics", {})
    result.setdefault("policies", {})
    result.setdefault("gateway", {})
    if any(not isinstance(result[key], dict) for key in ("health", "metrics", "policies", "gateway")):
        raise ControllerError("A fonte retornou metadados de rede inválidos.")
    return result


class ControllerTransport:
    """Serializa ações e confere novamente a capacidade antes de alterar a rede."""
    def __init__(self, kind, transport):
        self.kind, self.transport = kind, transport
        self.host = str(getattr(transport, "host", ""))
        self.port = getattr(transport, "port", "")
        self._closed = False
        self._lock = threading.RLock()

    def _checked_snapshot(self, result):
        result = normalize_snapshot(result)
        expected = {"observation": "observation", "demo": "demo", "routeros": "equipment", "legacy": "gateway"}
        if self.kind in expected and result["mode"] != expected[self.kind]:
            raise ControllerError("A conexão retornou um modo diferente do equipamento selecionado.")
        return result

    def request(self, action, **params):
        with self._lock:
            if self._closed:
                raise ControllerError("A conexão foi encerrada. Conecte novamente.")
            if action != "snapshot":
                capability = ACTION_CAPABILITY.get(action)
                if capability is None:
                    raise ControllerError("Ação de administração não permitida.")
                current = self._checked_snapshot(self.transport.request("snapshot"))
                if not current["capabilities"][capability]:
                    raise ControllerError("Esta conexão permite apenas as ações informadas pelo equipamento. O controle solicitado não está disponível.")
                health = ("firewall", "forwarding") if action in {"set_device_block", "set_address_block"} else ("dns",)
                if current["mode"] != "demo" and any(current.get("health", {}).get(key) is not True for key in health):
                    raise ControllerError("O equipamento não confirmou os requisitos para essa alteração. Atualize o diagnóstico.")
            if self._closed:
                raise ControllerError("A conexão foi encerrada. Conecte novamente.")
            return self._checked_snapshot(self.transport.request(action, **params))

    def close(self):
        if self._closed:
            return
        self._closed = True
        close = getattr(self.transport, "close", None)
        if callable(close):
            close()


def create_transport(kind="observation", *, host="", port=None, user="", password="", ca_file="",
                     key_path="", known_hosts="", protected_ips=None, protected_macs=None,
                     lab_cidr="", manage_rules=False, wan_interface_list="WAN"):
    if kind == "observation":
        from .discovery import LocalObservationTransport
        transport = LocalObservationTransport()
    elif kind == "demo":
        from .demo import DemoTransport
        transport = DemoTransport()
    elif kind == "routeros":
        from .direct_routeros import DirectRouterOSTransport
        transport = DirectRouterOSTransport(host=host, port=443 if port is None else port,
            user=user, password=password, ca_file=ca_file, protected_ips=protected_ips or [],
            protected_macs=protected_macs or [], lab_cidr=lab_cidr, manage_rules=manage_rules,
            wan_interface_list=wan_interface_list)
    elif kind == "legacy":
        from .transport import SSHTransport
        transport = SSHTransport(host=host, port=22 if port is None else port, user=user or "labguard",
                                 key_path=key_path, known_hosts=known_hosts or None)
    else:
        raise ControllerError("Selecione observação local, RouterOS compatível ou o gateway avançado existente.")
    return ControllerTransport(kind, transport)


def seed_ai_catalog(database):
    """Prepara a política local. O operador ainda precisa aplicá-la ao equipamento."""
    from .demo import normalize_domain
    catalog_path = Path(__file__).resolve().parents[1] / "gateway" / "ai_services.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    domains = sorted({normalize_domain(domain) for service in catalog["services"] for domain in service["domains"]})
    return database.import_domains(domains, category="Inteligência artificial")
