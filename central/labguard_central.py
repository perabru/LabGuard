"""LabGuard Central: regras de sites e confirmação das estações gerenciadas.

O iniciador chama ``initialize(directory, password, server_host, allowed_cidr)``
uma vez, em uma pasta protegida pela TI. Nas próximas execuções,
``build_servers(directory)`` devolve ``(panel, agents)``. Execute
``serve_forever`` em uma thread para cada servidor e, no encerramento, chame
``shutdown`` e ``server_close`` em ambos. O painel escuta somente 127.0.0.1;
as estações usam HTTPS na interface e sub-rede configuradas.

Não há API para executar comandos, desinstalar jogos ou coletar navegação.
O cliente recebe apenas a política de sites e informa sua aplicação.
"""
from __future__ import annotations

from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit

CENTRAL_VERSION = "1.0.0"
POLL_SECONDS = 15
MAX_ACTIVE_RULES = 975
MAX_STORED_RULES = 10000
MAX_BODY = 16384
SESSION_SECONDS = 8 * 60 * 60
ENROLLMENT_SECONDS = 60 * 60
CATEGORIES = ("jogos", "roblox", "minecraft", "adultos", "apostas", "ia", "outros")
_APP_ID = 0x4C47434E
_COOKIE_NAME = "labguard_central_session"


def assets_directory():
    return Path(__file__).parent / "assets"


class CentralError(ValueError):
    """Erro de configuração ou entrada apresentável ao técnico."""


class AuthenticationError(CentralError):
    pass


class ConflictError(CentralError):
    pass


def _stamp(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat(timespec="seconds")


def _domain(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 254:
        raise CentralError("Informe um domínio completo, como exemplo.com, sem caminho.")
    name = value.strip().lower().removeprefix("*.").removesuffix(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise CentralError("Confira a grafia do domínio.") from None
    parts = name.split(".")
    if (len(name) > 253 or len(parts) < 2 or parts[-1].isdigit()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in parts)
            or name.endswith((".localhost", ".arpa"))):
        raise CentralError("Use somente o domínio completo, sem https://, porta ou caminho.")
    return name


def _text(value, label, maximum=128, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise CentralError(f"{label} inválido.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CentralError(f"{label} contém caracteres de controle.")
    return value.strip()


def _boolean(value, label):
    if type(value) is not bool:
        raise CentralError(f"{label} deve ser verdadeiro ou falso.")
    return value


def _fields(data, required, optional=()):
    if not isinstance(data, dict) or set(data) - set(required) - set(optional) or set(required) - set(data):
        raise CentralError("Campos ausentes ou desconhecidos na solicitação.")


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secret(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,100}", value):
        raise AuthenticationError("Credencial inválida.")
    return value


def _regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_file_attributes", 0) & 0x400:
        raise CentralError("A configuração precisa estar em arquivos locais sem vínculos.")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise CentralError("Restrinja a configuração ao proprietário (chmod 600).")


def _write_new(path, content):
    payload = content.encode("utf-8") if isinstance(content, str) else content
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _read_json(path):
    _regular(path)
    if path.stat().st_size > 32768:
        raise CentralError("Arquivo de configuração muito grande.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError):
        raise CentralError("Arquivo de configuração inválido.") from None
    if not isinstance(data, dict):
        raise CentralError("Arquivo de configuração inválido.")
    return data


def _validate_config(raw):
    _fields(raw, ("version", "server_host", "allowed_cidr", "agent_port", "panel_port"))
    if raw["version"] != 1:
        raise CentralError("Versão de configuração incompatível.")
    try:
        address = ipaddress.IPv4Address(raw["server_host"])
        network = ipaddress.IPv4Network(raw["allowed_cidr"], strict=True)
    except (ValueError, TypeError):
        raise CentralError("Use o IPv4 do computador da TI e a sub-rede CIDR real do laboratório.") from None
    if not (address.is_private or address.is_loopback) or address.is_unspecified or address.is_multicast or address.is_reserved:
        raise CentralError("O servidor deve usar um IPv4 privado da rede local.")
    if address not in network or network.prefixlen < 8 or network.is_multicast:
        raise CentralError("O IPv4 da TI deve pertencer à sub-rede autorizada, de /8 a /32.")
    if address.is_loopback != network.network_address.is_loopback:
        raise CentralError("A sub-rede precisa corresponder à interface configurada.")
    if not (network.is_private or network.is_loopback):
        raise CentralError("A sub-rede autorizada precisa ser privada.")
    for key in ("agent_port", "panel_port"):
        if type(raw[key]) is not int or not 1024 <= raw[key] <= 65535:
            raise CentralError("As portas devem estar entre 1024 e 65535.")
    if raw["agent_port"] == raw["panel_port"]:
        raise CentralError("O painel e as estações precisam usar portas diferentes.")
    return dict(raw, server_host=str(address), allowed_cidr=str(network))


def read_config(directory):
    directory = Path(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise CentralError("Use uma pasta local protegida para a Central.")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise CentralError("Restrinja a pasta da Central ao proprietário (chmod 700).")
    return _validate_config(_read_json(directory / "config.json"))


def initialize(directory, password, server_host, allowed_cidr, agent_port=8788, panel_port=8787):
    """Cria uma Central nova. Nunca substitui configuração, senha ou banco."""
    if not isinstance(password, str) or not 12 <= len(password) <= 256 or password != password.strip():
        raise CentralError("Use uma senha de 12 a 256 caracteres, sem espaços nas extremidades.")
    if any(ord(char) < 32 for char in password):
        raise CentralError("A senha não pode conter caracteres de controle.")
    config = _validate_config(dict(version=1, server_host=server_host, allowed_cidr=allowed_cidr,
                                   agent_port=agent_port, panel_port=panel_port))
    directory = Path(directory)
    if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
        raise CentralError("Pasta de configuração inválida.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any((directory / name).exists() for name in ("config.json", "secrets.json", "server-cert.pem", "server-key.pem", "central.sqlite3")):
        raise ConflictError("A Central já foi configurada. Os dados existentes foram preservados.")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LabGuard Central"),
                         x509.NameAttribute(NameOID.COMMON_NAME, config["server_host"])])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=730))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(config["server_host"]))]), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=True, data_encipherment=False, key_agreement=False,
                       key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(key, hashes.SHA256()))
    salt = secrets.token_bytes(32)
    iterations = 600000
    password_record = {"salt": salt.hex(), "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex(),
                       "iterations": iterations}
    _write_new(directory / "server-key.pem", key.private_bytes(serialization.Encoding.PEM,
               serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _write_new(directory / "server-cert.pem", certificate.public_bytes(serialization.Encoding.PEM))
    _write_new(directory / "secrets.json", json.dumps({"version": 1, "password": password_record}) + "\n")
    store = CentralStore(directory / "central.sqlite3")
    store.ensure()
    _write_new(directory / "config.json", json.dumps(config, indent=2) + "\n")
    return {"ok": True, "directory": str(directory), "server_url": f"https://{server_host}:{agent_port}",
            "panel_url": f"http://127.0.0.1:{panel_port}/", "ca_fingerprint": certificate.fingerprint(hashes.SHA256()).hex()}


class CentralStore:
    """Banco transacional. Toda alteração de sites avança uma revisão global."""
    def __init__(self, path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock

    @contextmanager
    def _open(self, *, write=False, create=False):
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists() or candidate.is_symlink():
                try:
                    _regular(candidate)
                except FileNotFoundError:
                    # SQLite removes sidecars as concurrent transactions end.
                    # The database itself must never disappear between checks.
                    if not suffix:
                        raise
        mode = "rwc" if create else "rw"
        db = sqlite3.connect(self.path.absolute().as_uri() + "?mode=" + mode, uri=True, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            if not create and (db.execute("PRAGMA application_id").fetchone()[0] != _APP_ID
                               or db.execute("PRAGMA user_version").fetchone()[0] != 1):
                raise CentralError("Banco da Central incompatível.")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def ensure(self, *, seed_rows=None):
        if self.path.exists():
            with self._open() as db:
                return self._revision(db)
        _write_new(self.path, b"")
        if seed_rows is None:
            try:
                # O EXE usa o mesmo módulo já importado pelo iniciador Windows.
                from labguard_cliente import CLIENT_CATALOG_ROWS, CLIENT_CATALOG_NOTICE
            except ImportError:
                from client.labguard_cliente import CLIENT_CATALOG_ROWS, CLIENT_CATALOG_NOTICE
            seed_rows, notice = CLIENT_CATALOG_ROWS, CLIENT_CATALOG_NOTICE
        else:
            notice = "Catálogo configurado pela TI."
        with self._open(write=True, create=True) as db:
            db.execute("CREATE TABLE settings(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,notice TEXT NOT NULL)")
            db.execute("INSERT INTO settings VALUES (1,1,?)", (notice,))
            db.execute("CREATE TABLE categories(category TEXT PRIMARY KEY,enabled INTEGER NOT NULL CHECK(enabled IN (0,1)))")
            db.executemany("INSERT INTO categories VALUES (?,1)", ((name,) for name in CATEGORIES))
            db.execute("CREATE TABLE rules(domain TEXT PRIMARY KEY,category TEXT NOT NULL REFERENCES categories(category),"
                       "action TEXT NOT NULL CHECK(action IN ('block','allow')),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),source TEXT NOT NULL)")
            db.execute("CREATE TABLE enrollments(token_hash TEXT PRIMARY KEY,created_at REAL NOT NULL,expires_at REAL NOT NULL,used_at REAL,device_id TEXT)")
            db.execute("CREATE TABLE devices(device_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,name TEXT NOT NULL,"
                       "client_version TEXT NOT NULL,created_at REAL NOT NULL,last_seen REAL NOT NULL,applied_revision INTEGER,"
                       "site_ok INTEGER CHECK(site_ok IN (0,1)),status_at TEXT,error TEXT NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN (0,1)))")
            db.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY,time REAL NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL)")
            for domain, category, source in seed_rows:
                if category not in CATEGORIES:
                    raise CentralError("Categoria inválida no catálogo inicial.")
                db.execute("INSERT INTO rules VALUES (?,?, 'block',1,?)", (_domain(domain), category, _text(source, "Origem", 2048)))
            self._validate_rules(db)
            db.execute(f"PRAGMA application_id={_APP_ID}")
            db.execute("PRAGMA user_version=1")
        return 1

    @staticmethod
    def _revision(db):
        return db.execute("SELECT revision FROM settings WHERE id=1").fetchone()[0]

    @staticmethod
    def _advance(db):
        db.execute("UPDATE settings SET revision=revision+1 WHERE id=1")

    def _audit(self, db, action, detail):
        db.execute("INSERT INTO audit(time,action,detail) VALUES (?,?,?)", (self.clock(), action, detail))
        db.execute("DELETE FROM audit WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM audit)")

    @staticmethod
    def _configured(db):
        return list(db.execute("SELECT r.domain,r.action FROM rules r JOIN categories c USING(category) WHERE r.enabled=1 AND c.enabled=1 ORDER BY r.domain"))

    @staticmethod
    def _allowed_parent(domain, allowed):
        parts = domain.split(".")
        return next((".".join(parts[index:]) for index in range(len(parts) - 1) if ".".join(parts[index:]) in allowed), None)

    @classmethod
    def _active(cls, db):
        configured = cls._configured(db)
        allowed = {row["domain"] for row in configured if row["action"] == "allow"}
        return [row for row in configured if row["action"] == "allow" or not cls._allowed_parent(row["domain"], allowed)]

    @classmethod
    def _validate_rules(cls, db):
        if db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] > MAX_STORED_RULES:
            raise CentralError(f"O banco permite até {MAX_STORED_RULES} registros.")
        active = cls._configured(db)
        if len(active) > MAX_ACTIVE_RULES:
            raise CentralError(f"Use no máximo {MAX_ACTIVE_RULES} regras ativas, somando bloqueios e permissões.")

    def put_rule(self, domain, category, action, enabled=True, *, original=None):
        domain = _domain(domain)
        if category not in CATEGORIES or action not in ("block", "allow"):
            raise CentralError("Categoria ou ação inválida.")
        _boolean(enabled, "Estado da regra")
        if original is not None:
            original = _domain(original)
        with self._open(write=True) as db:
            target = db.execute("SELECT * FROM rules WHERE domain=?", (domain,)).fetchone()
            if target and original != domain:
                raise ConflictError("Domínio já cadastrado. Use os controles da linha para editá-lo.")
            if action == "block" and enabled:
                allowed = {row["domain"] for row in self._configured(db) if row["action"] == "allow" and row["domain"] != original}
                if self._allowed_parent(domain, allowed):
                    raise CentralError("Bloqueie ou remova a liberação do domínio pai primeiro; ela também libera os subdomínios.")
            if original is not None:
                previous = db.execute("SELECT * FROM rules WHERE domain=?", (original,)).fetchone()
                if not previous:
                    raise ConflictError("A regra original foi excluída. Atualize a lista.")
                if original != domain:
                    db.execute("DELETE FROM rules WHERE domain=?", (original,))
                elif previous["category"] == category and previous["action"] == action and bool(previous["enabled"]) == enabled:
                    return self._revision(db)
            db.execute("INSERT INTO rules VALUES (?,?,?,?, 'TI') ON CONFLICT(domain) DO UPDATE SET "
                       "category=excluded.category,action=excluded.action,enabled=excluded.enabled,source='TI'", (domain, category, action, int(enabled)))
            self._validate_rules(db)
            self._advance(db)
            self._audit(db, "rule_saved", domain + " " + action)
            return self._revision(db)

    def delete_rule(self, domain):
        domain = _domain(domain)
        with self._open(write=True) as db:
            if not db.execute("DELETE FROM rules WHERE domain=?", (domain,)).rowcount:
                raise ConflictError("Este domínio já foi excluído.")
            self._advance(db)
            self._audit(db, "rule_deleted", domain)
            return self._revision(db)

    def set_category(self, category, enabled):
        if category not in CATEGORIES:
            raise CentralError("Categoria inválida.")
        _boolean(enabled, "Estado da categoria")
        with self._open(write=True) as db:
            changed = db.execute("UPDATE categories SET enabled=? WHERE category=? AND enabled!=?", (int(enabled), category, int(enabled))).rowcount
            if changed:
                self._validate_rules(db)
                self._advance(db)
                self._audit(db, "category_changed", category + (" enabled" if enabled else " paused"))
            return self._revision(db)

    @classmethod
    def _snapshot(cls, db):
        active = cls._active(db)
        return {"ok": True, "revision": cls._revision(db), "poll_seconds": POLL_SECONDS,
                "site_policy": {"mode": "bloqueados", "catalog_enabled": False,
                    "domains": [row["domain"] for row in active if row["action"] == "block"],
                    "allowed_domains": [row["domain"] for row in active if row["action"] == "allow"]}}

    def snapshot(self):
        with self._open() as db:
            return self._snapshot(db)

    def issue_enrollment(self):
        token = secrets.token_urlsafe(32)
        now = self.clock()
        with self._open(write=True) as db:
            db.execute("DELETE FROM enrollments WHERE expires_at<?", (now,))
            if db.execute("SELECT COUNT(*) FROM enrollments WHERE used_at IS NULL").fetchone()[0] >= 100:
                raise CentralError("Já existem 100 arquivos de vínculo válidos. Aguarde a expiração para gerar outros.")
            db.execute("INSERT INTO enrollments VALUES (?,?,?,NULL,NULL)", (_digest(token), now, now + ENROLLMENT_SECONDS))
            self._audit(db, "enrollment_created", "Arquivo de vínculo individual")
        return token, _stamp(now + ENROLLMENT_SECONDS)

    def enroll(self, enrollment_token, name, client_version):
        token_hash = _digest(_secret(enrollment_token))
        name = _text(name, "Nome da estação")
        client_version = _text(client_version, "Versão do cliente", 64)
        now, device_token = self.clock(), secrets.token_urlsafe(32)
        device_id = secrets.token_hex(16)
        with self._open(write=True) as db:
            candidate = db.execute("SELECT * FROM enrollments WHERE token_hash=?", (token_hash,)).fetchone()
            if not candidate or candidate["used_at"] is not None or candidate["expires_at"] <= now:
                raise AuthenticationError("Vínculo inválido, utilizado ou expirado. Gere outro arquivo na Central.")
            if db.execute("SELECT COUNT(*) FROM devices WHERE revoked=0").fetchone()[0] >= 2000:
                raise CentralError("A Central atingiu o limite de 2000 estações vinculadas.")
            db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,NULL,NULL,NULL,'',0)",
                       (device_id, _digest(device_token), name, client_version, now, now))
            db.execute("UPDATE enrollments SET used_at=?,device_id=? WHERE token_hash=?", (now, device_id, token_hash))
            self._audit(db, "device_enrolled", name)
            return dict(self._snapshot(db), device_id=device_id, device_token=device_token)

    def poll(self, device_token, report):
        _fields(report, ("device_id", "name", "client_version", "applied_revision", "error", "site_ok", "status_at"))
        token_hash = _digest(_secret(device_token))
        device_id = _text(report["device_id"], "Identificação", 64)
        name = _text(report["name"], "Nome da estação")
        version = _text(report["client_version"], "Versão", 64)
        error = _text(report["error"], "Diagnóstico", 512, empty=True)
        applied, site_ok, status_at = report["applied_revision"], report["site_ok"], report["status_at"]
        if applied is not None and (type(applied) is not int or applied < 1):
            raise CentralError("Revisão aplicada inválida.")
        if site_ok is not None and type(site_ok) is not bool:
            raise CentralError("Estado da proteção inválido.")
        if site_ok is True and applied is None:
            raise CentralError("A confirmação de proteção precisa informar a revisão aplicada.")
        if status_at is not None:
            status_at = _text(status_at, "Horário de aplicação", 64)
            try:
                parsed = datetime.fromisoformat(status_at.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError()
                # Relógios de estações podem estar defasados; o painel usa last_seen do servidor.
            except ValueError:
                raise CentralError("Horário de aplicação inválido.") from None
        with self._open(write=True) as db:
            device = db.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if not device or device["revoked"] or not hmac.compare_digest(device["token_hash"], token_hash):
                raise AuthenticationError("Vínculo da estação inválido ou revogado.")
            if applied is not None and applied > self._revision(db):
                raise CentralError("A revisão informada não existe nesta Central.")
            db.execute("UPDATE devices SET name=?,client_version=?,last_seen=?,applied_revision=?,site_ok=?,status_at=?,error=? WHERE device_id=?",
                       (name, version, self.clock(), applied, None if site_ok is None else int(site_ok), status_at, error, device_id))
            return self._snapshot(db)

    def revoke_device(self, device_id):
        device_id = _text(device_id, "Identificação", 64)
        with self._open(write=True) as db:
            device = db.execute("SELECT name FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if not device:
                raise ConflictError("Estação não encontrada.")
            db.execute("UPDATE devices SET revoked=1 WHERE device_id=?", (device_id,))
            self._audit(db, "device_revoked", device["name"])

    def state(self):
        now = self.clock()
        with self._open() as db:
            revision = self._revision(db)
            rules = [dict(row, enabled=bool(row["enabled"]), effective=bool(row["effective"])) for row in db.execute(
                "SELECT r.*,(r.enabled AND c.enabled) AS effective FROM rules r JOIN categories c USING(category) ORDER BY domain")]
            allowed = {row["domain"] for row in rules if row["effective"] and row["action"] == "allow"}
            configured_count = sum(row["effective"] for row in rules)
            for rule in rules:
                inherited = self._allowed_parent(rule["domain"], allowed) if rule["action"] == "block" and rule["effective"] else None
                rule["overridden_by"] = inherited
                if inherited:
                    rule["effective"] = False
            categories = [dict(row, enabled=bool(row["enabled"])) for row in db.execute(
                "SELECT c.category,c.enabled,COUNT(r.domain) AS total,"
                "COALESCE(SUM(r.enabled*c.enabled*(r.action='block')),0) AS blocked,"
                "COALESCE(SUM(r.enabled*c.enabled*(r.action='allow')),0) AS allowed "
                "FROM categories c LEFT JOIN rules r USING(category) GROUP BY c.category,c.enabled ORDER BY c.category")]
            for category in categories:
                category["blocked"] = sum(rule["category"] == category["category"] and rule["effective"] and rule["action"] == "block" for rule in rules)
                category["allowed"] = sum(rule["category"] == category["category"] and rule["effective"] and rule["action"] == "allow" for rule in rules)
            devices = []
            for row in db.execute("SELECT device_id,name,client_version,last_seen,applied_revision,site_ok,status_at,error,revoked FROM devices ORDER BY name,device_id"):
                item = dict(row, revoked=bool(row["revoked"]), last_seen=_stamp(row["last_seen"]))
                item["site_ok"] = None if row["site_ok"] is None else bool(row["site_ok"])
                if row["revoked"]:
                    status = "revoked"
                elif now - row["last_seen"] > 90:
                    status = "offline"
                elif row["applied_revision"] is None and row["status_at"] is None:
                    status = "pending"
                elif row["site_ok"] == 0:
                    status = "error"
                elif row["site_ok"] == 1 and row["applied_revision"] == revision:
                    status = "online"
                else:
                    status = "pending"
                item["status"] = status
                devices.append(item)
            counts = {"rules": len(rules), "blocked": sum(row["effective"] and row["action"] == "block" for row in rules),
                      "allowed": sum(row["effective"] and row["action"] == "allow" for row in rules),
                      "devices": len(devices), "online": sum(row["status"] == "online" for row in devices), "configured": configured_count}
            audit = [dict(row, time=_stamp(row["time"])) for row in db.execute("SELECT time,action,detail FROM audit ORDER BY id DESC LIMIT 100")]
        return {"ok": True, "version": CENTRAL_VERSION, "revision": revision, "rules": rules, "categories": categories,
                "devices": devices, "counts": counts, "poll_seconds": POLL_SECONDS, "active_limit": MAX_ACTIVE_RULES, "audit": audit}


class CentralApplication:
    def __init__(self, directory, assets_dir=None):
        self.directory = Path(directory)
        self.config = read_config(self.directory)
        self.store = CentralStore(self.directory / "central.sqlite3")
        self.store.ensure()
        raw = _read_json(self.directory / "secrets.json")
        _fields(raw, ("version", "password"))
        if raw["version"] != 1:
            raise CentralError("Formato de senha incompatível.")
        _fields(raw["password"], ("salt", "hash", "iterations"))
        self.password = raw["password"]
        if (not isinstance(self.password["salt"], str) or not re.fullmatch("[0-9a-f]{64}", self.password["salt"])
                or not isinstance(self.password["hash"], str) or not re.fullmatch("[0-9a-f]{64}", self.password["hash"])
                or self.password["iterations"] != 600000):
            raise CentralError("Formato de senha incompatível.")
        self.server_url = f'https://{self.config["server_host"]}:{self.config["agent_port"]}'
        self.assets_dir = Path(assets_dir) if assets_dir else assets_directory()
        self.sessions = {}
        self.rates = defaultdict(deque)
        self.lock = threading.Lock()

    def check_rate(self, key, limit=8, seconds=300):
        now = time.monotonic()
        with self.lock:
            events = self.rates[key]
            while events and events[0] < now - seconds:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            if len(self.rates) > 4096:
                for name in list(self.rates):
                    if self.rates[name] and self.rates[name][-1] < now - 300:
                        del self.rates[name]
            return True

    def login(self, password):
        if not isinstance(password, str) or not 1 <= len(password) <= 256:
            raise AuthenticationError("Senha incorreta.")
        calculated = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(self.password["salt"]), self.password["iterations"]).hex()
        if not hmac.compare_digest(calculated, self.password["hash"]):
            raise AuthenticationError("Senha incorreta.")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            now = time.monotonic()
            self.sessions = {key: value for key, value in self.sessions.items() if value["expires"] > now}
            if len(self.sessions) >= 16:
                self.sessions.pop(next(iter(self.sessions)))
            self.sessions[_digest(token)] = {"csrf": csrf, "expires": now + SESSION_SECONDS}
        return token, csrf

    def session(self, token):
        if not token or len(token) > 100:
            return None
        with self.lock:
            session = self.sessions.get(_digest(token))
            return dict(session) if session and session["expires"] > time.monotonic() else None

    def logout(self, token):
        with self.lock:
            self.sessions.pop(_digest(token), None)

    def enrollment(self):
        token, expires = self.store.issue_enrollment()
        cert_file = self.directory / "server-cert.pem"
        _regular(cert_file)
        return {"ok": True, "filename": "LabGuard-Vinculo-" + secrets.token_hex(4) + ".json", "expires_at": expires,
                "config": {"format": "labguard-central-v1", "server_url": self.server_url,
                           "ca_pem": cert_file.read_text(encoding="ascii"), "enrollment_token": token}}


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    allow_reuse_address = False

    def __init__(self, address, application, *, agent=False, tls_context=None):
        self.application = application
        self.agent = agent
        self.tls_context = tls_context
        self.slots = threading.BoundedSemaphore(32)
        self.network = ipaddress.ip_network(application.config["allowed_cidr"])
        super().__init__(address, _Handler)

    def get_request(self):
        incoming, address = super().get_request()
        incoming.settimeout(10)
        if self.tls_context:
            try:
                incoming = self.tls_context.wrap_socket(incoming, server_side=True, do_handshake_on_connect=False)
            except BaseException:
                incoming.close()
                raise
        return incoming, address

    def verify_request(self, request, address):
        try:
            ip = ipaddress.ip_address(address[0])
            return ip in self.network if self.agent else ip.is_loopback
        except ValueError:
            return False

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Nunca envie credenciais, dados de estação ou rastros para o console.
        pass


class _Handler(BaseHTTPRequestHandler):
    server_version = "LabGuardCentral"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        pass

    def _send(self, status, value, *, content_type="application/json; charset=utf-8", cookie=None):
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") if isinstance(value, dict) else value
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _host(self):
        hosts = self.headers.get_all("Host", [])
        port = self.server.server_port
        allowed = {f'{self.server.application.config["server_host"]}:{port}'} if self.server.agent else {f"127.0.0.1:{port}", f"localhost:{port}"}
        if len(hosts) != 1 or hosts[0] not in allowed:
            raise AuthenticationError("Endereço de acesso inválido.")
        return hosts[0]

    def _origin(self):
        host = self._host()
        origins = self.headers.get_all("Origin", [])
        if len(origins) != 1 or origins[0] != "http://" + host:
            raise AuthenticationError("Origem da solicitação inválida. Reabra o painel local.")

    def _cookie(self):
        raw = self.headers.get("Cookie", "")
        if len(raw) > 2048:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            return ""
        return cookie[_COOKIE_NAME].value if _COOKIE_NAME in cookie else ""

    def _session(self, *, mutate=False):
        session = self.server.application.session(self._cookie())
        if not session:
            raise AuthenticationError("Entre com a senha do técnico.")
        if mutate:
            self._origin()
            values = self.headers.get_all("X-CSRF-Token", [])
            if len(values) != 1 or not hmac.compare_digest(values[0], session["csrf"]):
                raise AuthenticationError("A sessão mudou. Atualize o painel e tente novamente.")
        return session

    def _body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
            raise CentralError("Tamanho da solicitação inválido.")
        try:
            count = int(lengths[0])
        except ValueError:
            raise CentralError("Tamanho da solicitação inválido.") from None
        if not 0 < count <= MAX_BODY or self.headers.get_content_type() != "application/json":
            raise CentralError("Envie uma solicitação JSON de até 16 KiB.")
        try:
            raw = self.rfile.read(count)
            if len(raw) != count:
                raise ValueError()
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise CentralError("JSON inválido.") from None
        if not isinstance(data, dict):
            raise CentralError("Formato da solicitação inválido.")
        return data

    def do_GET(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def _dispatch(self):
        try:
            if len(self.path) > 2048 or len(str(self.headers)) > 16384:
                raise CentralError("Solicitação muito grande.")
            self._host()
            path = urlsplit(self.path)
            if path.scheme or path.netloc or path.query or path.fragment or path.path != self.path:
                raise CentralError("Caminho inválido.")
            if self.server.agent:
                self._agent(path.path)
            else:
                self._panel(path.path)
        except AuthenticationError as error:
            self._send(401, {"ok": False, "error": str(error)})
        except ConflictError as error:
            self._send(409, {"ok": False, "error": str(error)})
        except CentralError as error:
            self._send(400, {"ok": False, "error": str(error)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError, ssl.SSLError):
            pass
        except Exception:
            self._send(500, {"ok": False, "error": "A operação não pôde ser concluída. Confira o serviço e a pasta de dados da Central."})

    def _panel(self, path):
        app = self.server.application
        if self.command in ("GET", "HEAD"):
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                      "/app.css": ("app.css", "text/css; charset=utf-8")}
            if path in assets:
                name, content_type = assets[path]
                source = app.assets_dir / name
                if not source.is_file() or source.is_symlink() or source.stat().st_size > 1024 * 1024:
                    raise CentralError("Recurso do painel ausente. Reinstale a Central preservando sua pasta de dados.")
                self._send(200, source.read_bytes(), content_type=content_type)
            elif path == "/healthz":
                self._send(200, {"ok": True, "app": "LabGuardCentral", "version": CENTRAL_VERSION})
            elif path == "/api/session":
                session = app.session(self._cookie())
                self._send(200, {"ok": True, "authenticated": bool(session), **({"csrf": session["csrf"]} if session else {})})
            elif path == "/api/state":
                session = self._session()
                self._send(200, dict(app.store.state(), csrf=session["csrf"], server_url=app.server_url))
            else:
                self._send(404, {"ok": False, "error": "Recurso não encontrado."})
            return
        if self.command != "POST":
            self._send(405, {"ok": False, "error": "Método não permitido."})
            return
        self._origin()
        if path == "/api/login":
            if not app.check_rate(("login", self.client_address[0])):
                self._send(429, {"ok": False, "error": "Muitas tentativas. Aguarde cinco minutos antes de tentar novamente."})
                return
            body = self._body()
            _fields(body, ("password",))
            token, csrf = app.login(body["password"])
            self._send(200, {"ok": True, "csrf": csrf}, cookie=f"{_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}")
            return
        self._session(mutate=True)
        body = self._body()
        if path == "/api/logout":
            _fields(body, ())
            app.logout(self._cookie())
            self._send(200, {"ok": True}, cookie=f"{_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        elif path == "/api/rules":
            _fields(body, ("domain", "category", "action", "enabled"), ("original",))
            self._send(200, {"ok": True, "revision": app.store.put_rule(**body)})
        elif path == "/api/rules/delete":
            _fields(body, ("domain",))
            self._send(200, {"ok": True, "revision": app.store.delete_rule(body["domain"])})
        elif path == "/api/categories":
            _fields(body, ("category", "enabled"))
            self._send(200, {"ok": True, "revision": app.store.set_category(**body)})
        elif path == "/api/enrollment":
            _fields(body, ())
            self._send(200, app.enrollment())
        elif path == "/api/devices/revoke":
            _fields(body, ("device_id",))
            app.store.revoke_device(body["device_id"])
            self._send(200, {"ok": True})
        else:
            self._send(404, {"ok": False, "error": "Operação não encontrada."})

    def _agent(self, path):
        if self.command != "POST" or path not in ("/api/agent/enroll", "/api/agent/poll"):
            self._send(404, {"ok": False, "error": "Operação não encontrada."})
            return
        app = self.server.application
        if path == "/api/agent/enroll":
            if not app.check_rate(("enroll", self.client_address[0]), 15, 60):
                self._send(429, {"ok": False, "error": "Muitas tentativas de vínculo. Aguarde um minuto."})
                return
            body = self._body()
            _fields(body, ("enrollment_token", "name", "client_version"))
            result = app.store.enroll(**body)
        else:
            auth = self.headers.get_all("Authorization", [])
            if len(auth) != 1 or not auth[0].startswith("Bearer "):
                raise AuthenticationError("Credencial da estação ausente.")
            token = _secret(auth[0][7:])
            if not app.check_rate(("poll", self.client_address[0], _digest(token)), 30, 60):
                self._send(429, {"ok": False, "error": "Aguarde o intervalo de sincronização."})
                return
            result = app.store.poll(token, self._body())
        self._send(200, result)


def build_servers(directory, assets_dir=None):
    """Abre os dois listeners; fecha o primeiro se o segundo não puder abrir."""
    app = CentralApplication(directory, assets_dir=assets_dir)
    for name in ("server-cert.pem", "server-key.pem"):
        _regular(app.directory / name)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(app.directory / "server-cert.pem", app.directory / "server-key.pem")
    panel = _HTTPServer(("127.0.0.1", app.config["panel_port"]), app)
    try:
        agents = _HTTPServer((app.config["server_host"], app.config["agent_port"]), app, agent=True, tls_context=tls)
    except BaseException:
        panel.server_close()
        raise
    return panel, agents
