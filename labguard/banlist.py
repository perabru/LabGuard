"""Local SQLite policy database. Editing intent never changes a network by itself."""
from __future__ import annotations

import contextlib
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time

from .demo import normalize_domain

CATEGORIES = ("Jogos", "Inteligência artificial", "Adultos", "Outros")
MAX_SITES = 50000
MAX_IMPORT = 1000
MAX_SYNC = 100
LEASE_SECONDS = 180
LEASE_REFRESH_SECONDS = 30


class BanlistError(RuntimeError):
    pass


class _LeaseLost(BanlistError):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _journal_mode(version):
    # SQLite's 2026 WAL-reset fix is absent in older Python runtimes.
    # Rollback journaling retains transactions without that concurrent race.
    return "WAL" if version >= (3, 51, 3) or version[:2] == (3, 50) and version >= (3, 50, 7) or version[:2] == (3, 44) and version >= (3, 44, 6) else "DELETE"


def _domain(value):
    try:
        return normalize_domain(value)
    except (ValueError, TypeError) as error:
        raise BanlistError("Informe apenas um domínio válido, sem URL, porta ou caminho.") from error


def _category(value):
    if value == "IA":
        value = "Inteligência artificial"
    if value not in CATEGORIES:
        raise BanlistError("Categoria inválida. Use Jogos, IA, Adultos ou Outros.")
    return value


def _csv_safe(value):
    value = str(value if value is not None else "")
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def _record(row):
    if row is None:
        return None
    result = dict(row)
    result["enabled"], result["deleted"] = bool(result["enabled"]), bool(result["deleted"])
    return result


def _fingerprint(row):
    # The gateway does not expose a database owner tag. Require its stable
    # creation metadata and refuse to remove rules whose metadata changed.
    if not row or row.get("source", "manual") != "manual" or not row.get("created_at"):
        return ""
    payload = {key: row.get(key, "") for key in ("domain", "category", "created_at")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


class BanlistDatabase:
    def __init__(self, path=None):
        if path is None:
            base = Path(os.getenv("APPDATA", Path.home())) / "LabGuard" if os.name == "nt" else Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "labguard"
            path = base / "banlist.sqlite3"
        self.path = Path(os.path.abspath(Path(path).expanduser()))
        self.journal_mode = _journal_mode(sqlite3.sqlite_version_info)
        self._lock = threading.RLock()
        self._sync_lock = threading.Lock()
        try:
            self._prepare_path()
        except OSError as error:
            raise BanlistError("Não foi possível preparar o arquivo privado do banco de sites.") from error
        with self._connection(write=True) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sites (
                    id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    notes TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)));
                CREATE TABLE IF NOT EXISTS sync_state (
                    domain TEXT PRIMARY KEY, owned INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'pending', fingerprint TEXT NOT NULL DEFAULT '',
                    record_revision INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, time TEXT NOT NULL, action TEXT NOT NULL,
                    domain TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sync_lease (
                    id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, expires REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS sites_filter ON sites(deleted, enabled, category);
            """)

    def _prepare_path(self):
        for current in [self.path, *self.path.parents]:
            if current.is_symlink():
                raise BanlistError("O banco não pode usar links simbólicos.")
        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o700)
        if os.name != "nt":
            info = parent.stat()
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise BanlistError("Use um diretório privado do administrador, com permissão 0700, para o banco.")
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise BanlistError("O caminho do banco precisa ser um arquivo regular.")
        if os.name != "nt" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise BanlistError("O banco precisa pertencer ao administrador e usar permissão 0600.")

    @contextlib.contextmanager
    def _connection(self, write=False):
        with self._lock:
            if self.path.is_symlink():
                raise BanlistError("Link simbólico recusado para o banco.")
            try:
                db = sqlite3.connect(self.path, timeout=5)
            except sqlite3.Error as error:
                raise BanlistError("Não foi possível abrir o banco de sites.") from error
            db.row_factory = sqlite3.Row
            try:
                db.execute("PRAGMA busy_timeout=5000")
                db.execute("PRAGMA journal_mode=" + self.journal_mode)
                db.execute("PRAGMA synchronous=FULL")
                db.execute("PRAGMA trusted_schema=OFF")
                if write:
                    db.execute("BEGIN IMMEDIATE")
                yield db
                if write:
                    db.commit()
            except sqlite3.Error as error:
                db.rollback()
                raise BanlistError("Não foi possível concluir a operação no banco de sites.") from error
            finally:
                db.close()

    @staticmethod
    def _audit(db, action, domain, outcome):
        db.execute("INSERT INTO audit(time,action,domain,outcome) VALUES(?,?,?,?)", (_now(), action, domain, outcome))
        db.execute("DELETE FROM audit WHERE id <= (SELECT max(id)-10000 FROM audit)")

    def list_sites(self, query="", category="", enabled=None, include_deleted=False, limit=1000, offset=0):
        if not isinstance(query, str) or len(query) > 253 or type(limit) is not int or not 1 <= limit <= MAX_SITES or type(offset) is not int or offset < 0:
            raise BanlistError("Filtros ou limites de consulta inválidos.")
        if enabled is not None and type(enabled) is not bool:
            raise BanlistError("O filtro de ativação precisa ser booleano.")
        if type(include_deleted) is not bool:
            raise BanlistError("Filtro de exclusão inválido.")
        conditions, values = [], []
        if not include_deleted:
            conditions.append("deleted=0")
        if category:
            conditions.append("category=?")
            values.append(_category(category))
        if enabled is not None:
            conditions.append("enabled=?")
            values.append(int(enabled))
        if query:
            conditions.append("instr(lower(domain),lower(?))>0")
            values.append(query.strip())
        sql = "SELECT * FROM sites" + (" WHERE " + " AND ".join(conditions) if conditions else "") + " ORDER BY domain LIMIT ? OFFSET ?"
        with self._connection() as db:
            return [_record(row) for row in db.execute(sql, values + [limit, offset])]

    def upsert(self, domain, category="Outros", enabled=True, notes="", expected_revision=None):
        domain, category = _domain(domain), _category(category)
        if type(enabled) is not bool or not isinstance(notes, str) or len(notes) > 500 or any(ord(c) < 32 and c not in "\n\t" for c in notes):
            raise BanlistError("Ativação ou observação inválida; use até 500 caracteres.")
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 0):
            raise BanlistError("Revisão inválida.")
        with self._connection(write=True) as db:
            old = db.execute("SELECT * FROM sites WHERE domain=?", (domain,)).fetchone()
            if expected_revision is not None and expected_revision != (old["revision"] if old else 0):
                raise BanlistError("Este registro foi alterado. Atualize a lista antes de salvar.")
            timestamp = _now()
            if old:
                db.execute("UPDATE sites SET category=?,enabled=?,notes=?,revision=revision+1,updated_at=?,deleted=0 WHERE domain=?", (category, int(enabled), notes, timestamp, domain))
            else:
                if db.execute("SELECT count(*) FROM sites").fetchone()[0] >= MAX_SITES:
                    raise BanlistError("O banco atingiu o limite de 50000 domínios.")
                db.execute("INSERT INTO sites(domain,category,enabled,notes,created_at,updated_at) VALUES(?,?,?,?,?,?)", (domain, category, int(enabled), notes, timestamp, timestamp))
            self._audit(db, "Atualizar cadastro" if old else "Cadastrar domínio", domain, "Salvo no banco; aplicação na rede é separada")
            return _record(db.execute("SELECT * FROM sites WHERE domain=?", (domain,)).fetchone())

    def delete(self, domain, expected_revision=None):
        domain = _domain(domain)
        with self._connection(write=True) as db:
            old = db.execute("SELECT * FROM sites WHERE domain=?", (domain,)).fetchone()
            if not old:
                raise BanlistError("Domínio não encontrado no banco.")
            if expected_revision is not None and (type(expected_revision) is not int or old["revision"] != expected_revision):
                raise BanlistError("Este registro foi alterado. Atualize a lista antes de excluir.")
            db.execute("UPDATE sites SET enabled=0,deleted=1,revision=revision+1,updated_at=? WHERE domain=?", (_now(), domain))
            self._audit(db, "Excluir cadastro", domain, "Exclusão lógica; remoção na rede depende de sincronização e propriedade")
            return _record(db.execute("SELECT * FROM sites WHERE domain=?", (domain,)).fetchone())

    def import_domains(self, domains, category="Outros"):
        category = _category(category)
        if not isinstance(domains, (list, tuple)) or not 1 <= len(domains) <= MAX_IMPORT:
            raise BanlistError("Importe de 1 a 1000 domínios por vez.")
        valid, errors = [], []
        for index, value in enumerate(domains, 1):
            try:
                domain = _domain(value)
                if domain not in valid:
                    valid.append(domain)
            except BanlistError:
                errors.append({"index": index, "message": "Domínio inválido"})
        added, existing = [], []
        with self._connection(write=True) as db:
            count = db.execute("SELECT count(*) FROM sites").fetchone()[0]
            for domain in valid:
                if db.execute("SELECT 1 FROM sites WHERE domain=?", (domain,)).fetchone():
                    existing.append(domain)
                    continue
                if count >= MAX_SITES:
                    raise BanlistError("A importação excederia o limite do banco; nenhum item desta importação foi salvo.")
                timestamp = _now()
                db.execute("INSERT INTO sites(domain,category,enabled,notes,created_at,updated_at) VALUES(?,?,1,'',?,?)", (domain, category, timestamp, timestamp))
                added.append(domain)
                count += 1
            self._audit(db, "Importar domínios", "Lote", f"{len(added)} novos; {len(existing)} existentes; {len(errors)} inválidos")
        return {"added": added, "existing": existing, "errors": errors}

    def export_csv(self):
        result = io.StringIO(newline="")
        writer = csv.writer(result, delimiter=";")
        writer.writerow(["dominio", "categoria", "ativo", "observacoes", "revisao", "criado_em", "atualizado_em"])
        for row in self.list_sites(limit=MAX_SITES):
            writer.writerow([_csv_safe(row[k]) for k in ("domain", "category", "enabled", "notes", "revision", "created_at", "updated_at")])
        return result.getvalue()

    def audit(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise BanlistError("Limite de auditoria inválido.")
        with self._connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    def _pending(self, db):
        return db.execute("""SELECT count(*) FROM sites s LEFT JOIN sync_state t ON t.domain=s.domain
            WHERE (s.enabled=1 AND s.deleted=0 AND (t.domain IS NULL OR t.record_revision!=s.revision))
               OR ((s.enabled=0 OR s.deleted=1) AND t.owned=1)
               OR t.status IN ('adding','removing','uncertain_add','uncertain_remove')""").fetchone()[0]

    def summary(self):
        with self._connection() as db:
            counts = db.execute("SELECT count(*),sum(deleted=0),sum(enabled=1 AND deleted=0),sum(enabled=0 AND deleted=0),sum(deleted=1) FROM sites").fetchone()
            return {"total": counts[1] or 0, "enabled": counts[2] or 0, "disabled": counts[3] or 0, "deleted": counts[4] or 0,
                    "owned_rules": db.execute("SELECT count(*) FROM sync_state WHERE owned=1").fetchone()[0], "pending": self._pending(db),
                    "uncertain": db.execute("SELECT count(*) FROM sync_state WHERE status IN ('adding','removing','uncertain_add','uncertain_remove')").fetchone()[0]}

    @staticmethod
    def _snapshot_rules(snapshot):
        if not isinstance(snapshot, dict) or snapshot.get("mode") not in ("demo", "gateway", "equipment") or not isinstance(snapshot.get("health"), dict) or snapshot["health"].get("dns") is not True:
            raise BanlistError("O gateway precisa responder com DNS saudável antes de aplicar o banco.")
        if snapshot.get("mode") == "equipment" and (not isinstance(snapshot.get("capabilities"), dict) or snapshot["capabilities"].get("domain_filtering") is not True):
            raise BanlistError("O equipamento não confirmou suporte para aplicar bloqueios de domínios.")
        try:
            if not isinstance(snapshot.get("timestamp"), str):
                raise ValueError()
            stamp = datetime.fromisoformat(snapshot["timestamp"].replace("Z", "+00:00"))
            if stamp.tzinfo is None or not -30 <= (datetime.now(timezone.utc) - stamp).total_seconds() <= 45:
                raise ValueError()
            rows = snapshot["domains"]
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError()
            return {_domain(row["domain"]): dict(row) for row in rows}
        except (KeyError, TypeError, ValueError) as error:
            raise BanlistError("O gateway retornou uma amostra inválida ou desatualizada.") from error

    @staticmethod
    def _target(transport, snapshot):
        gateway = snapshot.get("gateway", {})
        if not isinstance(gateway, dict):
            raise BanlistError("Identificação inválida do gateway.")
        hostname, cidr = gateway.get("hostname"), gateway.get("lab_cidr")
        if not isinstance(hostname, str) or not hostname or not isinstance(cidr, str) or not cidr:
            raise BanlistError("Não foi possível identificar o gateway para vincular este banco.")
        return {"mode": snapshot["mode"], "host": str(getattr(transport, "host", "")), "port": str(getattr(transport, "port", "")), "hostname": hostname, "lab_cidr": cidr}

    @staticmethod
    def _renew_lease(db, token):
        now = time.time()
        updated = db.execute("UPDATE sync_lease SET expires=? WHERE id=1 AND owner=? AND expires>?", (now + LEASE_SECONDS, token, now))
        if updated.rowcount != 1:
            raise _LeaseLost("A sincronização perdeu sua concessão. Atualize os dados antes de iniciar outro lote.")

    def _set_tracking(self, domain, owned, status, fingerprint, revision, action="Sincronizar domínio", outcome="Estado atualizado", lease_token=None):
        with self._connection(write=True) as db:
            if lease_token is not None:
                self._renew_lease(db, lease_token)
            previous = db.execute("SELECT owned,status,fingerprint,record_revision FROM sync_state WHERE domain=?", (domain,)).fetchone()
            if previous and tuple(previous) == (int(owned), status, fingerprint, revision):
                return
            db.execute("""INSERT INTO sync_state(domain,owned,status,fingerprint,record_revision,updated_at) VALUES(?,?,?,?,?,?)
                ON CONFLICT(domain) DO UPDATE SET owned=excluded.owned,status=excluded.status,fingerprint=excluded.fingerprint,
                record_revision=excluded.record_revision,updated_at=excluded.updated_at""", (domain, int(owned), status, fingerprint, revision, _now()))
            self._audit(db, action, domain, outcome)

    def sync(self, transport, limit=100, cancel_event=None):
        if type(limit) is not int or not 1 <= limit <= MAX_SYNC:
            raise BanlistError("Aplique de 1 a 100 operações por lote.")
        if not self._sync_lock.acquire(blocking=False):
            raise BanlistError("Já existe uma sincronização em andamento.")
        token = secrets.token_hex(16)
        report = {"applied": [], "operations": [], "errors": [], "pending": 0, "snapshot": None, "target": None, "cancelled": False, "preserved": 0}
        leased, domain = False, ""
        try:
            with self._connection(write=True) as db:
                lease = db.execute("SELECT owner,expires FROM sync_lease WHERE id=1").fetchone()
                if lease and lease["expires"] > time.time():
                    raise BanlistError("Já existe uma sincronização em andamento para este banco.")
                db.execute("INSERT OR REPLACE INTO sync_lease(id,owner,expires) VALUES(1,?,?)", (token, time.time() + LEASE_SECONDS))
                leased = True
            snapshot = transport.request("snapshot")
            rules = self._snapshot_rules(snapshot)
            target = self._target(transport, snapshot)
            report.update(snapshot=snapshot, target=target)
            serialized = json.dumps(target, sort_keys=True)
            with self._connection(write=True) as db:
                old_target = db.execute("SELECT value FROM meta WHERE key='sync_target'").fetchone()
                if old_target and old_target[0] != serialized:
                    raise BanlistError("Este banco está vinculado a outro gateway. Use um banco separado para o novo equipamento.")
                db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('sync_target',?)", (serialized,))
                rows = [dict(row) for row in db.execute("SELECT * FROM sites ORDER BY domain")]
                tracked = {row["domain"]: dict(row) for row in db.execute("SELECT * FROM sync_state")}
                self._renew_lease(db, token)
            count = 0
            next_renewal = time.monotonic() + LEASE_REFRESH_SECONDS
            for row in rows:
                if cancel_event is not None and cancel_event.is_set():
                    report["cancelled"] = True
                    break
                # Observe-only batches can also outlive the lease. Refresh on
                # elapsed time rather than fsync once per unchanged record.
                if time.monotonic() >= next_renewal:
                    with self._connection(write=True) as db:
                        self._renew_lease(db, token)
                    next_renewal = time.monotonic() + LEASE_REFRESH_SECONDS
                domain, desired = row["domain"], bool(row["enabled"] and not row["deleted"])
                record = tracked.get(domain, {})
                current = rules.get(domain)
                owned = bool(record.get("owned"))
                fingerprint = record.get("fingerprint", "")
                # A pending add after a crash can never prove ownership later.
                if record.get("status") in ("adding", "uncertain_add"):
                    owned = False
                if owned and current and (not fingerprint or fingerprint != _fingerprint(current)):
                    owned = False
                if desired and current:
                    state = (int(owned), "owned" if owned else "external", fingerprint if owned else "", row["revision"])
                    if tuple(record.get(k) for k in ("owned", "status", "fingerprint", "record_revision")) != state:
                        self._set_tracking(domain, *state, outcome="Regra existente preservada" if not owned else "Regra própria confirmada", lease_token=token)
                    if not owned:
                        report["preserved"] += 1
                    continue
                if not desired and (not owned or not current):
                    state = (0, "external" if current else "absent", "", row["revision"])
                    if tuple(record.get(k) for k in ("owned", "status", "fingerprint", "record_revision")) != state:
                        self._set_tracking(domain, *state, outcome="Regra externa preservada" if current else "Sem regra própria aplicada", lease_token=token)
                    if current:
                        report["preserved"] += 1
                    continue
                if count >= limit:
                    break
                action = "add_domain" if desired else "remove_domain"
                phase = "adding" if desired else "removing"
                # Commit intent before touching the gateway. If the process or
                # final database write fails, ownership is conservative on retry.
                self._set_tracking(domain, False if desired else owned, phase, fingerprint, row["revision"], outcome="Intenção registrada; resultado de rede ainda não confirmado", lease_token=token)
                with self._connection(write=True) as db:
                    self._renew_lease(db, token)
                count += 1
                try:
                    params = {"domain": domain, "category": row["category"]} if desired else {"domain": domain}
                    updated = transport.request(action, **params)
                    new_rules = self._snapshot_rules(updated)
                    if self._target(transport, updated) != target:
                        raise BanlistError("Identidade do gateway mudou durante a operação.")
                    new_row = new_rules.get(domain)
                    new_fingerprint = _fingerprint(new_row) if desired else ""
                    # Removing our manual entry can reveal an AI-profile rule.
                    # Its continued block is correct and never grants ownership.
                    if (desired and not new_fingerprint) or (not desired and new_row and new_row.get("source") != "ai_profile"):
                        raise BanlistError("O gateway não confirmou o resultado esperado.")
                    self._set_tracking(domain, desired, "owned" if desired else "absent", new_fingerprint, row["revision"], action="Aplicar domínio" if desired else "Remover regra própria", outcome="Aplicação confirmada no gateway", lease_token=token)
                    report["applied"].append({"domain": domain, "action": action})
                    report["operations"].append({"domain": domain, "action": action, "status": "applied", "message": "Aplicação confirmada."})
                    snapshot, rules = updated, new_rules
                    report["snapshot"] = snapshot
                except Exception:
                    report["snapshot"] = None
                    try:
                        self._set_tracking(domain, False if desired else owned, "uncertain_add" if desired else "uncertain_remove", fingerprint, row["revision"], outcome="Resultado não confirmado; revisar antes de outra ação", lease_token=token)
                    except BanlistError:
                        pass
                    error = {"domain": domain, "action": action, "status": "uncertain", "message": "Resultado não confirmado. O gateway pode ter sido alterado; atualize e revise antes de repetir."}
                    report["errors"].append(error)
                    report["operations"].append(error)
                    break
            report["pending"] = self.summary()["pending"]
            return report
        except _LeaseLost as error:
            report["snapshot"] = None
            stopped = {"domain": domain, "action": "sync", "status": "stopped", "message": str(error)}
            report["errors"].append(stopped)
            report["operations"].append(stopped)
            report["pending"] = self.summary()["pending"]
            return report
        except BanlistError:
            raise
        except Exception as error:
            raise BanlistError("Não foi possível consultar ou sincronizar o banco. Atualize os dados e revise o gateway antes de repetir.") from error
        finally:
            if leased:
                try:
                    with self._connection(write=True) as db:
                        db.execute("DELETE FROM sync_lease WHERE id=1 AND owner=?", (token,))
                except BanlistError:
                    pass
            self._sync_lock.release()

    def close(self):
        """Connections are short lived; retained for application lifecycle parity."""


BanlistStore = BanlistDatabase
