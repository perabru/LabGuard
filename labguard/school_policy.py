"""Starter domain rules for a school's active local DNS filter."""
from __future__ import annotations

import re

from .controller import ControllerError
from .demo import normalize_domain
from .inventory import collection_recency

# Games from the project's sample list, plus the Roblox-specific CDN documented
# at https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks
# Adult services listed by the European Commission:
# https://digital-strategy.ec.europa.eu/en/policies/list-designated-vlops-and-vloses
SCHOOL_POLICY = (
    ("roblox.com", "Jogos"),
    ("rbxcdn.com", "Jogos"),
    ("poki.com", "Jogos"),
    ("crazygames.com", "Jogos"),
    ("friv.com", "Jogos"),
    ("pornhub.com", "Adultos"),
    ("xvideos.com", "Adultos"),
    ("xnxx.com", "Adultos"),
)


def _current_domains(snapshot):
    domains = set()
    for row in snapshot.get("domains", ()):
        if not isinstance(row, dict) or row.get("enabled") is False or row.get("deleted"):
            continue
        try:
            domain = normalize_domain(row.get("domain", ""))
        except ValueError:
            continue
        domains.add(domain)
    return domains


def sample_blocked_domain(snapshot):
    """Pick only an applied rule for an A lookup without opening the site."""
    applied = _current_domains(snapshot)
    for domain, _ in SCHOOL_POLICY:
        if domain in applied:
            return domain
    for domain in sorted(applied):
        if not domain.endswith((".invalid", ".localhost", ".local", ".arpa")):
            return domain
    return None


def _read(transport, expected_token):
    snapshot = transport.request("snapshot")
    service = snapshot.get("dns_service", {})
    if (snapshot.get("mode") != "equipment" or snapshot.get("source_type") != "local_dns"
            or service.get("check_token") != expected_token or service.get("service_running") is not True
            or snapshot.get("capabilities", {}).get("domain_filtering") is not True
            or snapshot.get("health", {}).get("dns") is not True
            or not collection_recency(snapshot)["fresh"]):
        raise ControllerError("Atualize o painel e confirme a sessão atual do filtro DNS local.")
    return _current_domains(snapshot)


def apply_school_policy(transport, *, authorized, expected_token):
    if (authorized is not True or getattr(transport, "kind", None) != "local_dns"
            or not isinstance(expected_token, str) or not re.fullmatch(r"LabGuard-[0-9a-f]{16}", expected_token)):
        raise ControllerError("Autorize o filtro DNS local antes de aplicar a proteção do laboratório.")

    initial = _read(transport, expected_token)
    domains = [domain for domain, _ in SCHOOL_POLICY]
    written = set()
    if any(domain not in initial for domain in domains):
        try:
            receipt = transport.request("apply_school_policy", authorized=True, expected_token=expected_token)
            written = set(receipt.get("school_policy_added", ()))
        except Exception:
            # A timeout after a commit is ambiguous. Read the same session once
            # and report observed rules. Never repeat or revert a disputed write.
            pass
    try:
        confirmed = _read(transport, expected_token)
    except Exception:
        return {"ok": False, "completed": False, "added": [], "already_present": [],
                "missing": [], "unconfirmed": domains,
                "message": "A leitura final do filtro ficou indisponível. Confira as regras em Sites."}

    added = [domain for domain in domains if domain in written and domain in confirmed]
    already = [domain for domain in domains if domain in confirmed and domain not in written]
    missing = [domain for domain in domains if domain not in confirmed]
    message = (f"{len(added) + len(already)} de {len(domains)} domínios confirmados no filtro. "
               f"{len(added)} adicionados nesta operação.")
    if missing:
        message += " Pendentes: " + ", ".join(missing) + ". Confira exclusões manuais e o limite do filtro."
    return {"ok": not missing, "completed": not missing, "added": added, "already_present": already,
            "missing": missing, "unconfirmed": [], "message": message}
