"""Dados fictícios: este módulo não abre sockets nem modifica a rede."""
from __future__ import annotations

import copy
import ipaddress
import json
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Informe um domínio válido.")
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        raise ValueError("Use somente o domínio, sem curinga. Os subdomínios são incluídos automaticamente.")
    if "://" in value or "/" in value or ":" in value or "@" in value:
        raise ValueError("Use somente o domínio, por exemplo poki.com, sem https:// nem caminhos.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Informe um domínio, não um endereço IP.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Domínio inválido.") from None
    if len(value) > 253 or "." not in value or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")
    ):
        raise ValueError("Domínio inválido. Exemplo: crazygames.com.")
    if value.split(".")[-1].isdigit():
        raise ValueError("Domínio inválido.")
    return value


class DemoTransport:
    mode = "demo"

    def __init__(self):
        self._lock = threading.Lock()
        catalog_path = Path(__file__).resolve().parents[1] / "gateway" / "ai_services.json"
        self._ai_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        self._ai_domains = sorted({normalize_domain(d) for s in self._ai_catalog["services"] for d in s["domains"]})
        now = datetime.now(timezone.utc)
        iso = now.isoformat(timespec="seconds")
        domains = ["poki.com", "roblox.com", "crazygames.com", "friv.com"]
        self.state = {
            "ai_block_enabled": False,
            "mode": "demo", "timestamp": iso,
            "gateway": {"hostname": "gateway-demonstracao", "lab_cidr": "192.168.50.0/24",
                        "lan_interface": "enp2s0", "wan_interface": "enp1s0",
                        "ipv6_policy": "Bloqueado no encaminhamento do laboratório"},
            "health": {"firewall": True, "dns": True, "forwarding": True},
            "devices": [],
            "domains": [{"domain": d, "category": "Jogos", "created_at": iso} for d in domains],
            "events": [], "connections": [], "audit": [], "metrics": {},
            "warnings": ["DEMONSTRAÇÃO: todas as máquinas, consultas e conexões são fictícias. Nenhuma regra é aplicada à rede."]
        }
        for n in range(1, 13):
            teacher = n == 12
            ip = f"192.168.50.{10 if teacher else 100+n}"
            self.state["devices"].append({"ip": ip, "mac": f"02:00:00:00:00:{n:02x}",
                "name": "PROFESSOR" if teacher else f"LAB-{n:02d}", "state": "Concessão ativa",
                "blocked": n == 4, "protected": teacher, "last_seen": iso, "dns_queries": 0})
        sample_domains = ["www.poki.com", "mec.gov.br", "pt.wikipedia.org", "roblox.com", "github.com", "crazygames.com"]
        for n in range(48):
            device = self.state["devices"][n % 12]
            domain = sample_domains[n % len(sample_domains)]
            blocked = any(domain == d or domain.endswith("." + d) for d in domains)
            self.state["events"].append({"time": (now - timedelta(seconds=11*n)).isoformat(timespec="seconds"),
                "client_ip": device["ip"], "domain": domain, "query_type": "A" if n % 3 else "HTTPS",
                "status": "Bloqueio DNS confirmado" if blocked else "Consulta"})
            device["dns_queries"] += 1
        for n, device in enumerate(self.state["devices"]):
            if not device["blocked"]:
                self.state["connections"].append({"source_ip": device["ip"],
                    "destination_ip": f"203.0.113.{n+1}", "protocol": "tcp", "port": 443, "state": "ESTABLISHED"})
        self.state["audit"].append({"time": iso, "action": "Demonstração iniciada", "target": "Painel local", "outcome": "Nenhuma alteração na rede"})

    def request(self, action: str, **params) -> dict:
        with self._lock:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            target = ""
            if action == "add_domain":
                domain = normalize_domain(params.get("domain", ""))
                if any(d["domain"] == domain for d in self.state["domains"]):
                    raise ValueError("Este domínio já está na lista de bloqueio.")
                category = str(params.get("category", "Jogos")).strip()
                if not category or len(category) > 60 or any(ord(c) < 32 for c in category):
                    raise ValueError("Categoria inválida; use até 60 caracteres.")
                self.state["domains"].append({"domain": domain, "category": category, "created_at": now})
                target = domain
            elif action == "remove_domain":
                domain = normalize_domain(params.get("domain", ""))
                if not any(d["domain"] == domain for d in self.state["domains"]):
                    if self.state["ai_block_enabled"] and domain in self._ai_domains:
                        raise ValueError("Este domínio pertence ao perfil de IA. Desative o perfil para removê-lo.")
                    raise ValueError("Domínio não encontrado.")
                self.state["domains"] = [d for d in self.state["domains"] if d["domain"] != domain]
                target = domain
            elif action == "set_ai_block":
                enabled = params.get("enabled")
                if type(enabled) is not bool:
                    raise ValueError("O estado do perfil IA precisa ser verdadeiro ou falso.")
                self.state["ai_block_enabled"] = enabled
                target = "Perfil de inteligência artificial: " + ("ativado" if enabled else "desativado")
                if enabled:
                    for service in self._ai_catalog["services"]:
                        self.state["events"].insert(0, {"time": now, "client_ip": "192.168.50.101",
                            "domain": service["domains"][0], "query_type": "A", "status": "Bloqueio DNS confirmado"})
                    self.state["events"] = self.state["events"][:500]
            elif action == "set_device_block":
                ip = params.get("ip", "")
                blocked = params.get("blocked")
                if type(blocked) is not bool:
                    raise ValueError("O estado de bloqueio precisa ser verdadeiro ou falso.")
                device = next((d for d in self.state["devices"] if d["ip"] == ip), None)
                if not device:
                    raise ValueError("Selecione uma máquina observada no laboratório.")
                if device["protected"]:
                    raise ValueError("A máquina do professor está protegida contra bloqueio.")
                device["blocked"] = blocked
                target = ip
                if blocked:
                    self.state["connections"] = [c for c in self.state["connections"] if c["source_ip"] != ip]
            elif action != "snapshot":
                raise ValueError("Operação desconhecida.")
            if action != "snapshot":
                labels = {"add_domain": "Domínio adicionado", "remove_domain": "Domínio removido", "set_device_block": "Controle de internet alterado", "set_ai_block": "Política de IA alterada"}
                self.state["audit"].insert(0, {"time": now, "action": labels[action], "target": target,
                                              "outcome": "Simulado; nenhuma alteração na rede"})
            self.state["timestamp"] = now
            self.state["metrics"] = {"queries_window": len(self.state["events"]),
                "blocked_events_window": sum(e["status"] == "Bloqueio DNS confirmado" for e in self.state["events"]),
                "observed_devices": len(self.state["devices"]),
                "blocked_devices": sum(d["blocked"] for d in self.state["devices"])}
            data = copy.deepcopy(self.state)
            rows = {d["domain"]: dict(d, source="manual") for d in data["domains"]}
            if data["ai_block_enabled"]:
                for domain in self._ai_domains:
                    rows.setdefault(domain, {"domain": domain, "category": "Inteligência artificial", "created_at": "", "source": "ai_profile"})
            data["domains"] = sorted(rows.values(), key=lambda d: d["domain"])
            data["policies"] = {"ai_block": {"enabled": data["ai_block_enabled"],
                "services": copy.deepcopy(self._ai_catalog["services"]), "domains": list(self._ai_domains),
                "domain_count": len(self._ai_domains), "updated_at": self._ai_catalog["updated_at"]}}
            return data
