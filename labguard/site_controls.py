"""Visible site catalog and explicit single-site changes for the technician."""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import secrets
import time

from .banlist import BanlistError, CATEGORIES, LEASE_SECONDS, MAX_SITES, _fingerprint
from .demo import normalize_domain


@lru_cache(maxsize=1)
def builtin_sites():
    """List packaged names without importing or applying any blocking policy."""
    from .school_policy import SCHOOL_POLICY
    sites = {domain: {"domain": domain, "category": category, "origin": "Catálogo escolar"}
             for domain, category in SCHOOL_POLICY}
    path = Path(__file__).resolve().parents[1] / "gateway" / "ai_services.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    for service in catalog["services"]:
        for value in service["domains"]:
            domain = normalize_domain(value)
            sites.setdefault(domain, {"domain": domain, "category": "Inteligência artificial", "origin": "Catálogo de IA"})
    return tuple(sites[domain] for domain in sorted(sites))


def _domain_rows(rows):
    for row in rows if isinstance(rows, (list, tuple)) else ():
        if not isinstance(row, dict):
            continue
        try:
            domain = normalize_domain(row.get("domain", ""))
        except (ValueError, TypeError):
            continue
        yield domain, row


def _suffixes(domain):
    parts = domain.split(".")
    return [".".join(parts[index:]) for index in range(len(parts) - 1)]


def _subdomain_scope(row):
    declared = row.get("match_subdomains")
    if type(declared) is bool:
        return declared
    if row.get("source", "manual") in {"manual", "ai_profile"}:
        return True
    return None


def site_rows(snapshot, records=(), *, fresh=True, catalog=None):
    """An absent rule means only no block in this source, never an allowlist."""
    names = {}
    for domain, row in _domain_rows(builtin_sites() if catalog is None else catalog):
        names[domain] = {"domain": domain, "category": row.get("category", "Outros"),
                         "origins": [row.get("origin", "Catálogo escolar")]}
    for rows, origin in ((records, "Banco de sites"), (snapshot.get("site_entries", ()), "Cadastro do filtro")):
        for domain, row in _domain_rows(rows):
            if row.get("deleted"):
                continue
            item = names.setdefault(domain, {"domain": domain, "origins": []})
            item["category"] = row.get("category", "Outros")
            if origin not in item["origins"]:
                item["origins"].append(origin)
    active = {}
    for domain, row in _domain_rows(snapshot.get("domains", ())):
        if row.get("enabled") is False or row.get("deleted"):
            continue
        active.setdefault(domain, []).append(row)
        item = names.setdefault(domain, {"domain": domain, "origins": []})
        item["category"] = row.get("category", item.get("category", "Outros"))
    policy = snapshot.get("policies", {}).get("ai_block", {})
    ai_domains = set()
    if isinstance(policy, dict) and policy.get("enabled") is True:
        for value in policy.get("domains", ()):
            try:ai_domains.add(normalize_domain(value))
            except (ValueError, TypeError):pass
    ai_domains.update(domain for domain, rows in active.items()
                      if any(row.get("source") == "ai_profile" for row in rows))
    available = bool(fresh and snapshot.get("mode") != "observation"
                     and snapshot.get("health", {}).get("dns") is True
                     and (snapshot.get("mode") in {"demo", "gateway"}
                          or snapshot.get("capabilities", {}).get("domain_filtering") is True))
    result = []
    for domain, item in sorted(names.items()):
        direct = active.get(domain, [])
        suffixes = _suffixes(domain)
        possible_parents = [rule for rule in suffixes[1:] if rule in active]
        parents = [rule for rule in possible_parents if any(_subdomain_scope(row) is True for row in active[rule])]
        unknown_parents = [rule for rule in possible_parents if rule not in parents
                           and any(_subdomain_scope(row) is None for row in active[rule])]
        profile = any(rule in ai_domains for rule in suffixes)
        conflicting = len(direct) > 1
        source = direct[0].get("source", "manual") if direct else "catalog"
        blocked = bool(direct or parents or profile)
        detail = "A liberação vale para as regras deste filtro. O DNS de saída, cache e outros controles podem interferir."
        if not available:
            state, detail = "Sem confirmação", "Ligue o filtro e atualize a leitura para conferir o estado e usar os controles."
        elif conflicting:
            state, detail = "Regras sobrepostas", "A fonte retornou mais de uma regra para este domínio. Revise a integração antes de alterar."
        elif profile:
            state, detail = "Bloqueado pelo perfil de IA", "Desative o perfil global de IA antes de liberar este domínio. Não há exceção individual sobre esse perfil."
        elif parents:
            state, detail = "Bloqueado por domínio pai", "A regra de " + parents[0] + " também abrange este domínio. Selecione a regra principal para revisá-la."
        elif unknown_parents:
            state, detail = "Sem confirmação", "O escopo da regra externa de " + unknown_parents[0] + " não foi informado. Confira se ela cobre subdomínios no equipamento antes de alterar este site."
        elif direct:
            state = "Bloqueado neste filtro"
            if source == "external":detail = "Regra externa: revise no equipamento pelo fluxo que a criou."
        else:
            state = "Sem bloqueio neste filtro"
        origins = list(item["origins"])
        if direct:
            origins.append({"ai_profile": "Perfil de IA", "external": "Regra externa"}.get(source, "Regra aplicada"))
        result.append({**item, "origin": " + ".join(origins), "source": source, "state": state,
                       "blocked": blocked if available and state != "Sem confirmação" else None, "detail": detail,
                       "can_block": available and not blocked and not (conflicting or unknown_parents),
                       "can_release": available and bool(direct) and source == "manual" and not (profile or parents or conflicting or unknown_parents)})
    return result


def filter_sites(rows, *, query="", category="Todas", state="Todos"):
    term = query.strip().casefold()
    return [row for row in rows
            if (not term or term in (row["domain"] + " " + row["origin"]).casefold())
            and (category == "Todas" or row["category"] == category)
            and (state == "Todos" or state == "Bloqueados" and row["blocked"] is True
                 or state == "Sem bloqueio" and row["blocked"] is False
                 or state == "Sem confirmação" and row["blocked"] is None)]


def _exact_record(database, domain):
    return next((row for row in database.list_sites(query=domain, include_deleted=True, limit=MAX_SITES)
                 if row["domain"] == domain), None)


def apply_site_change(transport, database, *, domain, category, blocked):
    """Persist explicit intent and apply one rule; never erase the visible record.

    The same lease used by batch synchronization keeps another synchronizer from
    reapplying stale intent during this operation. A disputed network result is
    recorded as uncertain and never repeated automatically.
    """
    domain = normalize_domain(domain)
    if type(blocked) is not bool:
        raise BanlistError("Escolha Bloquear ou Liberar.")
    if not database._sync_lock.acquire(blocking=False):
        raise BanlistError("Aguarde a aplicação atual do banco antes de alterar este site.")
    token, leased = secrets.token_hex(16), False
    try:
        with database._connection(write=True) as db:
            lease = db.execute("SELECT expires FROM sync_lease WHERE id=1").fetchone()
            if lease and lease["expires"] > time.time():
                raise BanlistError("Já existe uma aplicação do banco em andamento.")
            db.execute("INSERT OR REPLACE INTO sync_lease(id,owner,expires) VALUES(1,?,?)", (token, time.time() + LEASE_SECONDS))
            leased = True
        before = transport.request("snapshot")
        rules = database._snapshot_rules(before)
        target = database._target(transport, before)
        row = next((item for item in site_rows(before, catalog=({"domain": domain, "category": category},))
                    if item["domain"] == domain), None)
        if row and row["blocked"] is None:
            raise BanlistError(row["detail"])
        if row and row["state"] == "Regras sobrepostas":
            raise BanlistError(row["detail"])
        if not blocked and row and row["blocked"] and not row["can_release"]:
            raise BanlistError(row["detail"])
        if blocked and domain in rules and rules[domain].get("source", "manual") != "manual":
            raise BanlistError("Esta regra pertence a outra política. Revise sua origem antes de alterá-la.")
        with database._connection(write=True) as db:
            old_target = db.execute("SELECT value FROM meta WHERE key='sync_target'").fetchone()
            serialized = json.dumps(target, sort_keys=True)
            if old_target and old_target[0] != serialized:
                raise BanlistError("O banco pertence a outra conexão. Atualize o painel antes de alterar.")
            db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('sync_target',?)", (serialized,))
            tracking = db.execute("SELECT * FROM sync_state WHERE domain=?", (domain,)).fetchone()
            tracking = dict(tracking) if tracking else {}
        previous = _exact_record(database, domain)
        # Some compatible gateways expose their own category vocabulary. Keep
        # their rule unchanged on release while mapping the local bank category.
        bank_category = "Inteligência artificial" if category == "IA" else category
        if bank_category not in CATEGORIES:
            bank_category = "Outros"
        record = database.upsert(domain, bank_category, enabled=blocked, notes=previous["notes"] if previous else "",
                                 expected_revision=previous["revision"] if previous else 0)
        current = rules.get(domain)
        fingerprint = _fingerprint(current)
        owned = bool(tracking.get("owned") and fingerprint and tracking.get("fingerprint") == fingerprint)
        action = "add_domain" if blocked else "remove_domain"
        database._set_tracking(domain, owned, "adding" if blocked else "removing", fingerprint, record["revision"],
                               outcome="Alteração individual solicitada; aguardando confirmação", lease_token=token)
        try:
            if blocked and current is None:
                after = transport.request(action, domain=domain, category=category)
            elif not blocked and current is not None:
                after = transport.request(action, domain=domain)
            else:
                after = before
            updated = database._snapshot_rules(after)
            if database._target(transport, after) != target:
                raise BanlistError("A conexão mudou durante a alteração.")
            if blocked and domain not in updated or not blocked and domain in updated:
                raise BanlistError("O filtro não confirmou o resultado esperado para este domínio.")
            latest = _exact_record(database, domain)
            warning = ""
            if latest is None or latest["revision"] != record["revision"]:
                warning = "O cadastro foi editado durante a operação. A regra foi conferida; revise a intenção atual do banco antes de aplicar outra lista."
            else:
                new_fingerprint = _fingerprint(updated.get(domain))
                own_after = bool(blocked and new_fingerprint and (owned or current is None))
                status = "owned" if own_after else "external" if blocked else "absent"
                database._set_tracking(domain, own_after, status, new_fingerprint if own_after else "", record["revision"],
                                       action="Bloquear site" if blocked else "Liberar site", outcome="Estado confirmado; cadastro preservado", lease_token=token)
            return {"snapshot": after, "domain": domain, "blocked": blocked, "warning": warning}
        except Exception:
            try:
                database._set_tracking(domain, False if blocked else owned, "uncertain_add" if blocked else "uncertain_remove",
                                       fingerprint, record["revision"], outcome="Resultado não confirmado; confira o filtro antes de repetir", lease_token=token)
            except BanlistError:
                pass
            raise
    finally:
        try:
            if leased:
                with database._connection(write=True) as db:
                    db.execute("DELETE FROM sync_lease WHERE id=1 AND owner=?", (token,))
        finally:
            database._sync_lock.release()
