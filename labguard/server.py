"""Administração local por observação ou equipamento autorizado.

O computador não precisa encaminhar o tráfego. Controles dependem das
capacidades reais do equipamento; o gateway SSH antigo continua opcional.
O HTTP permanece restrito ao loopback.
"""
from __future__ import annotations

from collections import defaultdict, deque
import copy
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .banlist import BanlistDatabase, BanlistError
from .demo import DemoTransport, normalize_domain
from .inventory import collection_recency, summarize_inventory
from .reports import ReportError, export_report, network_map_svg

BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY = 8192
MAX_HEADERS = 16384
MAX_RESPONSE = 4 * 1024 * 1024
MAX_CONFIG = 32768
MAX_AGE = 20.0
MAX_REPORT_ROWS = 500
MAX_REPORT_RULES = 1000
CAPABILITIES = {"inventory", "domain_filtering", "device_internet_cut", "address_blocking", "ai_block", "dns_history", "port_control"}
ACTION_CAPABILITIES = {"add_domain": ("domain_filtering",), "remove_domain": ("domain_filtering",),
                       "set_ai_block": ("domain_filtering", "ai_block"), "set_device_block": ("device_internet_cut",),
                       "set_address_block": ("address_blocking",)}
ASSET_TYPES = {"/": ("index.html", "text/html; charset=utf-8"),
               "/app.css": ("app.css", "text/css; charset=utf-8"),
               "/app.js": ("app.js", "application/javascript; charset=utf-8")}
PARAMS = {"snapshot": set(), "add_domain": {"domain", "category"},
          "remove_domain": {"domain"}, "set_ai_block": {"enabled"},
          "set_device_block": {"ip", "blocked"},
          "set_address_block": {"kind", "address", "blocked"}}
PUBLIC_FIELDS = {"mode", "version", "timestamp", "gateway", "health", "devices", "domains",
                 "events", "connections", "audit", "metrics", "warnings", "policies", "address_blocks",
                 "capabilities", "controller", "source", "source_type", "dns_service"}


class ServerError(RuntimeError):
    pass


def asset_directory() -> Path:
    return Path(__file__).resolve().parents[1] / "server" / "assets"


def _private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ServerError(f"Arquivo de configuração ausente ou inválido: {path.name}.")
    info = path.stat()
    if info.st_size > MAX_CONFIG:
        raise ServerError("Arquivo de configuração excede o limite.")
    if os.name != "nt":
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ServerError(f"Restrinja {path.name} ao proprietário (chmod 600).")
        if info.st_uid not in {0, os.getuid()}:
            raise ServerError(f"Proprietário inesperado em {path.name}.")


def _read_json(path: Path) -> dict:
    _private_file(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ServerError(f"JSON inválido em {path.name}.") from error
    if not isinstance(data, dict):
        raise ServerError(f"Formato inválido em {path.name}.")
    return data


def _new_private(path: Path, content: str) -> None:
    # O_EXCL preserva configurações e tokens existentes.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def initialize(directory: Path) -> dict:
    directory = Path(directory).expanduser()
    if directory.is_symlink():
        raise ServerError("Diretório de configuração não pode ser um link.")
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any((directory / name).exists() for name in ("config.json", "secrets.json", "access-tokens.txt")):
        raise ServerError("A configuração já existe. Nenhum token foi substituído.")
    tokens = {role: secrets.token_urlsafe(32) for role in ("viewer", "admin")}
    config = {"version": 1, "port": DEFAULT_PORT, "controller": {"kind": "observation"}}
    hashes = {"version": 1, "tokens": {role: hashlib.sha256(value.encode()).hexdigest() for role, value in tokens.items()},
              "controller_password": ""}
    _new_private(directory / "config.json", json.dumps(config, indent=2) + "\n")
    _new_private(directory / "secrets.json", json.dumps(hashes, indent=2) + "\n")
    _new_private(directory / "access-tokens.txt", "LabGuard Server - guarde este arquivo como credencial administrativa.\n"
                 "Não envie tokens por URL, e-mail ou pelo histórico de comandos.\n\n"
                 f"Consulta (viewer): {tokens['viewer']}\nAdministração (admin): {tokens['admin']}\n")
    (directory / "logs").mkdir(mode=0o700, exist_ok=True)
    (directory / "data").mkdir(mode=0o700, exist_ok=True)
    return {"ok": True, "directory": str(directory), "config": str(directory / "config.json"),
            "tokens_file": str(directory / "access-tokens.txt"),
            "message": "Configuração criada. O modo observação inicia sem alterar a rede; controles exigem um equipamento compatível configurado."}


class ServerConfig:
    def __init__(self, directory: Path, *, demo: bool = False):
        supplied = Path(directory).expanduser()
        if supplied.is_symlink():
            raise ServerError("Diretório de configuração não pode ser um link.")
        self.directory = supplied.resolve()
        if not self.directory.is_dir():
            raise ServerError("Inicialize primeiro o diretório de configuração.")
        if os.name != "nt" and stat.S_IMODE(self.directory.stat().st_mode) & 0o022:
            raise ServerError("O diretório de configuração não pode permitir escrita de outros usuários.")
        data = _read_json(self.directory / "config.json")
        secret = _read_json(self.directory / "secrets.json")
        if data.get("version") != 1 or set(data) - {"version", "port", "gateway", "controller"}:
            raise ServerError("Configuração de servidor incompatível.")
        self.port = data.get("port", DEFAULT_PORT)
        if type(self.port) is not int or not 1024 <= self.port <= 65535:
            raise ServerError("A porta local precisa estar entre 1024 e 65535.")
        self.gateway = data.get("gateway", {"host": "", "port": 22, "user": "labguard", "key_path": "", "known_hosts": ""})
        allowed = {"host", "port", "user", "key_path", "known_hosts"}
        if not isinstance(self.gateway, dict) or set(self.gateway) != allowed:
            raise ServerError("Configuração SSH do gateway incompleta.")
        if any(not isinstance(self.gateway.get(key), str) for key in ("host", "user", "key_path", "known_hosts")):
            raise ServerError("Os campos SSH precisam ser textos.")
        if type(self.gateway.get("port")) is not int or not 1 <= self.gateway["port"] <= 65535:
            raise ServerError("A porta SSH precisa estar entre 1 e 65535.")
        controller = data.get("controller", {"kind": "legacy" if "gateway" in data else "observation"})
        fields = {"kind", "host", "port", "user", "ca_file", "protected_ips", "protected_macs", "manage_rules", "lab_cidr", "wan_interface_list", "upstream"}
        if not isinstance(controller, dict) or set(controller) - fields:
            raise ServerError("Configuração de controlador incompatível; a senha pertence somente a secrets.json.")
        kind = controller.get("kind", "observation")
        if kind not in ("observation", "routeros", "legacy", "local_dns"):
            raise ServerError("Use controlador observation, routeros ou legacy.")
        if kind != "local_dns" and "upstream" in controller:raise ServerError("upstream pertence apenas ao filtro DNS local.")
        self.controller = {"kind": kind}
        if kind == "local_dns":
            from .local_dns import validate_config, DNSError
            if set(controller) - {'kind','host','port','lab_cidr','upstream','manage_rules'} or controller.get('manage_rules') is not True:
                raise ServerError('DNS local exige campos próprios e manage_rules=true explícito no arquivo privado.')
            try:host, net, upstream, dns_port, _ = validate_config(controller.get('host'), controller.get('lab_cidr'), controller.get('upstream','1.1.1.1'), controller.get('port',53))
            except DNSError as error:raise ServerError('IP, segmento ou DNS de saída inválidos para o filtro local.') from error
            self.controller.update(host=host, lab_cidr=str(net), upstream=upstream, port=dns_port, manage_rules=True)
        elif kind != "legacy":
            self.controller.update(host=controller.get("host", ""), port=controller.get("port", 443),
                                   user=controller.get("user", ""), ca_file=controller.get("ca_file", ""),
                                   protected_ips=controller.get("protected_ips", []), protected_macs=controller.get("protected_macs", []),
                                   manage_rules=controller.get("manage_rules", False), lab_cidr=controller.get("lab_cidr", ""),
                                   wan_interface_list=controller.get("wan_interface_list", "WAN"))
            if any(not isinstance(self.controller[key], str) for key in ("host", "user", "ca_file", "lab_cidr", "wan_interface_list")):
                raise ServerError("Host, usuário e autoridade certificadora precisam ser textos.")
            if self.controller["lab_cidr"]:
                try:
                    self.controller["lab_cidr"] = str(ipaddress.IPv4Network(self.controller["lab_cidr"], strict=True))
                except ValueError as error:
                    raise ServerError("A sub-rede do controlador precisa ser um CIDR IPv4 válido.") from error
            if not 1 <= len(self.controller["wan_interface_list"]) <= 64 or any(ord(char) < 32 for char in self.controller["wan_interface_list"]):
                raise ServerError("Lista de interfaces WAN inválida.")
            if type(self.controller["port"]) is not int or not 1 <= self.controller["port"] <= 65535 or type(self.controller["manage_rules"]) is not bool:
                raise ServerError("Porta ou autorização de regras do controlador inválida.")
            for key in ("protected_ips", "protected_macs"):
                if not isinstance(self.controller[key], list) or len(self.controller[key]) > 256 or any(not isinstance(value, str) for value in self.controller[key]):
                    raise ServerError("Endereços administrativos protegidos inválidos.")
            try:
                self.controller["protected_ips"] = [str(ipaddress.IPv4Address(value)) for value in self.controller["protected_ips"]]
                self.controller["protected_macs"] = [validate_action("set_address_block", {"kind": "mac", "address": value, "blocked": True})[1]["address"] for value in self.controller["protected_macs"]]
            except (ValueError, ServerError) as error:
                raise ServerError("Endereços administrativos protegidos inválidos.") from error
        if kind == "legacy" and not demo and (not self.gateway.get("host") or not self.gateway.get("key_path") or not self.gateway.get("known_hosts")):
            raise ServerError("Configure host, chave SSH e known_hosts antes de iniciar o servidor real. Use --demo somente para demonstração.")
        password = secret.get("controller_password", "")
        if not isinstance(password, str) or len(password) > 4096 or any(ord(char) < 32 for char in password):
            raise ServerError("Credencial do controlador inválida em secrets.json.")
        if kind == "routeros" and not demo and (not self.controller["host"] or not self.controller["user"] or not password):
            raise ServerError("Configure host e usuário do RouterOS; guarde a senha somente em secrets.json, no campo controller_password.")
        self.controller_password = password
        tokens = secret.get("tokens")
        if secret.get("version") != 1 or not isinstance(tokens, dict) or set(tokens) != {"viewer", "admin"}:
            raise ServerError("Credenciais administrativas incompatíveis.")
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in tokens.values()):
            raise ServerError("Hashes de credenciais inválidos.")
        if tokens["viewer"] == tokens["admin"]:
            raise ServerError("Consulta e administração precisam de credenciais diferentes.")
        self.token_hashes = dict(tokens)
        self.demo = bool(demo)


def create_controller_transport(config):
    if config.demo:
        return DemoTransport()
    try:
        # Runtime import keeps init/configuration independent of platform
        # optional inventory modules. An incomplete package fails explicitly.
        from .controller import create_transport
    except ImportError as error:
        raise ServerError("Controlador ausente no pacote. Reinstale a aplicação completa.") from error
    try:
        options = dict(config.controller)
        if options["kind"] == "legacy":
            options.update(config.gateway)
        elif options["kind"] == "routeros":
            options["password"] = config.controller_password
        if options['kind'] == 'local_dns':options['data_dir'] = config.directory/'data'/'dns-policy'
        return create_transport(**options)
    except Exception as error:
        raise ServerError("Não foi possível preparar o controlador. Confira o tipo, endereço, certificado e credenciais nos arquivos privados.") from error


def validate_action(action, params) -> tuple[str, dict]:
    if not isinstance(action, str) or action not in PARAMS or not isinstance(params, dict) or set(params) - PARAMS[action]:
        raise ServerError("Operação ou parâmetro não permitido.")
    clean = dict(params)
    if action in {"add_domain", "remove_domain"}:
        clean["domain"] = normalize_domain(clean.get("domain", ""))
    if action == "add_domain":
        category = clean.get("category", "Outros")
        if not isinstance(category, str) or not 1 <= len(category.strip()) <= 60 or any(ord(c) < 32 for c in category):
            raise ServerError("Categoria inválida.")
        clean["category"] = category.strip()
    if action == "set_ai_block" and type(clean.get("enabled")) is not bool:
        raise ServerError("enabled precisa ser true ou false.")
    if action == "set_device_block":
        if type(clean.get("blocked")) is not bool:
            raise ServerError("blocked precisa ser true ou false.")
        try:
            clean["ip"] = str(ipaddress.IPv4Address(clean.get("ip")))
        except (ValueError, TypeError) as error:
            raise ServerError("IP da máquina inválido.") from error
    if action == "set_address_block":
        if clean.get("kind") not in ("ip", "mac") or type(clean.get("blocked")) is not bool:
            raise ServerError("Informe kind=ip ou mac e blocked=true ou false.")
        address = clean.get("address")
        if not isinstance(address, str):
            raise ServerError("Endereço inválido.")
        if clean["kind"] == "ip":
            try:
                clean["address"] = str(ipaddress.IPv4Address(address))
            except ValueError as error:
                raise ServerError("Informe um endereço IPv4 válido.") from error
        else:
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", address):
                raise ServerError("Informe um MAC válido, separado por dois-pontos.")
            address = address.lower()
            if address in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} or int(address[:2], 16) & 1:
                raise ServerError("Informe um MAC unicast válido.")
            clean["address"] = address
    return action, clean


class Limits:
    """Janelas pequenas e limitadas; todos os clientes são locais ou túneis."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.bad_auth = deque(maxlen=20)
        self.requests = {role: deque(maxlen=90) for role in ("viewer", "admin")}
        self.actions = {role: deque(maxlen=20) for role in ("viewer", "admin")}

    def auth_blocked(self) -> bool:
        with self.lock:
            moment = self.clock()
            while self.bad_auth and self.bad_auth[0] < moment - 60:
                self.bad_auth.popleft()
            return len(self.bad_auth) >= 20

    def reject_auth(self) -> None:
        with self.lock:
            self.bad_auth.append(self.clock())

    def accept(self, role: str, *, mutation=False) -> bool:
        with self.lock:
            moment = self.clock()
            bucket = self.actions[role] if mutation else self.requests[role]
            maximum = 20 if mutation else 90
            while bucket and bucket[0] < moment - 60:
                bucket.popleft()
            if len(bucket) >= maximum:
                return False
            bucket.append(moment)
            return True


class Application:
    def __init__(self, config: ServerConfig, transport=None, *, logging_enabled=True, banlist_path=None):
        self.config = config
        self.transport = transport or create_controller_transport(config)
        self._closed = False
        from .station_web import StationOperations
        self.stations = StationOperations()
        self.limits = Limits()
        self.network_lock = threading.Lock()
        self.report_lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.cancel_sync = threading.Event()
        self.sync_thread = None
        self.sync_job = {"running": False, "job_id": None, "report": None, "error": None}
        try:
            self.banlist = BanlistDatabase(banlist_path if banlist_path is not None else config.directory / "data" / "banlist.sqlite3")
        except BanlistError as error:
            close = getattr(self.transport, "close", None)
            if callable(close):
                close()
            config.controller_password = ""
            raise ServerError(str(error)) from error
        self.last_snapshot = None
        self.last_success = 0.0
        self.stale = True
        self.logger = logging.getLogger(f"labguard-server-{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        if logging_enabled:
            log_dir = config.directory / "logs"
            log_dir.mkdir(mode=0o700, exist_ok=True)
            handler = RotatingFileHandler(log_dir / "server.log", maxBytes=500_000, backupCount=3, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)sZ %(message)s", "%Y-%m-%dT%H:%M:%S"))
            handler.formatter.converter = time.gmtime
            self.logger.addHandler(handler)
            if os.name != "nt":
                os.chmod(log_dir / "server.log", 0o600)
        else:
            self.logger.addHandler(logging.NullHandler())

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.stations.close()
        self.cancel_sync.set()
        close = getattr(self.transport, "close", None)
        if callable(close):
            close()
        self.config.controller_password = ""
        if self.sync_thread and self.sync_thread.is_alive():
            # Invalidate the connection before waiting so the controller cannot
            # start a mutation after an in-flight preflight completes. A request
            # already sent may finish and be recorded by the synchronizer.
            self.sync_thread.join(timeout=55)
        self.banlist.close()
        for handler in list(self.logger.handlers):
            handler.close()
            self.logger.removeHandler(handler)

    def role(self, authorization: str) -> str | None:
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
            return None
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        role = None
        for name in ("viewer", "admin"):
            if hmac.compare_digest(digest, self.config.token_hashes[name]):
                role = name
        return role

    def audit(self, action: str, role: str, result: str):
        # Nunca registra cabeçalhos, tokens, corpo, senha ou caminho de chave.
        self.logger.info("action=%s role=%s result=%s", action, role, result)

    def public_snapshot(self, snapshot):
        if not isinstance(snapshot, dict) or snapshot.get("mode") not in {"observation", "equipment", "gateway", "demo"}:
            raise ServerError("Resposta incompatível do controlador.")
        expected = "demo" if self.config.demo else {"observation": "observation", "routeros": "equipment", "legacy": "gateway", "local_dns": "equipment"}[self.config.controller["kind"]]
        if snapshot["mode"] != expected:
            raise ServerError("O controlador retornou um modo diferente da configuração autorizada.")
        def clean(value):
            if isinstance(value, dict):
                return {key: clean(item) for key, item in value.items() if str(key).casefold() not in {"password", "controller_password", "authorization", "token", "tokens", "access_token", "secret", "private_key", "key_path", "known_hosts"}}
            if isinstance(value, list):
                return [clean(item) for item in value]
            return value
        data = clean({key: value for key, value in snapshot.items() if key in PUBLIC_FIELDS})
        supplied = snapshot.get("capabilities", {})
        data["capabilities"] = {key: supplied.get(key) is True for key in CAPABILITIES} if isinstance(supplied, dict) else {key: False for key in CAPABILITIES}
        # Older demo fixtures have no capabilities; their actions are explicitly
        # simulated. Real transports always fail closed when a flag is absent.
        if snapshot["mode"] == "demo" and "capabilities" not in snapshot:
            data["capabilities"] = {key: key != "port_control" for key in CAPABILITIES}
        if snapshot["mode"] == "observation":
            data["capabilities"] = {key: key == "inventory" for key in CAPABILITIES}
        elif self.config.controller["kind"] == "routeros" and self.config.controller.get("manage_rules") is not True:
            for flags in ACTION_CAPABILITIES.values():
                for key in flags:
                    data["capabilities"][key] = False
            data["capabilities"]["port_control"] = False
        # A fonte não pode fornecer um resumo pronto nem usar esse diagnóstico
        # para conceder capacidades. Só contagens e textos estáticos do motor
        # local chegam ao painel; interfaces/discovery brutos ficam privados.
        data["identification"] = summarize_inventory(snapshot)
        return data

    def collection_current(self, cached):
        """Combina idade e falha técnica, sem exigir clientes observados.

        ``cached`` é o DTO produzido por public_snapshot; identification nunca
        é aceito diretamente da fonte. Falta de metadados não cria uma falha.
        """
        if self.config.demo:
            return True
        summary = cached.get("identification") if isinstance(cached, dict) else None
        facts = summary.get("facts") if isinstance(summary, dict) else None
        if isinstance(facts, dict) and (facts.get("read_success") is False or facts.get("collection_metadata_valid") is False):
            return False
        return collection_recency(cached, max_age_seconds=MAX_AGE)["fresh"] is True

    def check_mutation(self, action):
        if self.config.demo and self.last_snapshot is None:
            return
        if self.stale or not self.last_snapshot or time.monotonic() - self.last_success > MAX_AGE:
            raise ServerError("Atualize o estado do controlador antes de alterar regras.")
        if self.last_snapshot.get("mode") == "observation" or (not self.config.demo and self.config.controller["kind"] == "routeros" and self.config.controller.get("manage_rules") is not True):
            raise ServerError("O controlador está em observação ou consulta somente leitura; nenhuma regra de rede será alterada.")
        if not self.collection_current(self.last_snapshot):
            raise ServerError("A coleta da fonte está indisponível, antiga ou sem horário confirmado. Atualize a fonte e confira o relógio antes de alterar regras.")
        capabilities = self.last_snapshot.get("capabilities", {})
        if not isinstance(capabilities, dict) or not all(capabilities.get(key) is True for key in ACTION_CAPABILITIES[action]):
            raise ServerError("O controlador não disponibiliza essa operação. A observação e os equipamentos somente leitura não alteram a rede.")
        if self.config.demo:
            return
        required = ("firewall", "forwarding") if action in {"set_device_block", "set_address_block"} else ("dns",)
        if not all(self.last_snapshot.get("health", {}).get(key) is True for key in required):
            raise ServerError("O serviço necessário está indisponível. Confira a saúde do equipamento.")

    def sync_status(self):
        with self.job_lock:
            return dict(self.sync_job)

    def protect_school(self, payload):
        from .school_policy import apply_school_policy
        if not isinstance(payload, dict) or set(payload) != {'confirm'} or payload['confirm'] is not True:
            raise ServerError('Confirme a lista de domínios da escola antes de aplicar.')
        if not self.network_lock.acquire(timeout=0.1):
            raise ServerError('Há uma operação em andamento. Aguarde antes de aplicar a lista.')
        try:
            snapshot = self.stations.current_dns_snapshot(self)
            if snapshot.get('capabilities', {}).get('domain_filtering') is not True:
                raise ServerError('A fonte atual não oferece bloqueio de domínios.')
            token = snapshot['dns_service']['check_token']
            self.stale = True
            return apply_school_policy(self.transport, authorized=True, expected_token=token)
        finally:
            self.network_lock.release()

    def report(self, format):
        if format not in {"svg", "html", "csv", "pdf"}:
            raise ServerError("Formato de relatório inválido.")
        if not self.report_lock.acquire(blocking=False):
            raise ServerError("Há uma exportação em andamento. Aguarde.")
        try:
            cached = self.last_snapshot
            if not isinstance(cached, dict):
                raise ServerError("Atualize a fonte antes de exportar a primeira amostra.")
            source = copy.deepcopy(cached)
            source_recent = self.collection_current(cached)
            state = "stale" if self.stale or time.monotonic() - self.last_success > MAX_AGE or not source_recent else "fresh"
            original = len(source.get("devices", []))
            source["devices"] = source.get("devices", [])[:MAX_REPORT_ROWS]
            source["events"] = source.get("events", [])[:1000]
            source["address_blocks"] = source.get("address_blocks", [])[:MAX_REPORT_RULES]
            notes = []
            if state == "stale":
                notes.append("dados anteriores; atualização da fonte não confirmada")
            if original > MAX_REPORT_ROWS:
                notes.append(f"exportação do servidor limitada a {MAX_REPORT_ROWS} de {original} registros")
            if notes:
                source["timestamp"] = str(source.get("timestamp", "Não informado")) + " | " + "; ".join(notes)
            if format == "svg":
                body = network_map_svg(source).encode("utf-8")
            else:
                # Dedicated private directory also works under the service
                # filesystem restrictions. No user-controlled output path.
                with tempfile.TemporaryDirectory(prefix="report-", dir=self.config.directory / "data") as temporary:
                    path = Path(temporary) / ("report." + format)
                    export_report(source, path, format)
                    with path.open("rb") as stream:
                        body = stream.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise ServerError("O relatório excedeu 4 MiB. Reduza a amostra ou use outra exportação.")
            return body, state
        finally:
            self.report_lock.release()

    def edit_banlist(self, operation, payload):
        with self.job_lock:
            if self.sync_job["running"]:
                raise ServerError("Aguarde o lote em andamento antes de editar o banco.")
            if operation == "upsert":
                allowed = {"domain", "category", "enabled", "notes", "expected_revision"}
            elif operation == "delete":
                allowed = {"domain", "expected_revision"}
            else:
                allowed = {"domains", "category"}
            if not isinstance(payload, dict) or set(payload) - allowed:
                raise ServerError("Parâmetros do banco inválidos.")
            if operation == "import":
                domains = payload.get("domains")
                if not isinstance(domains, list) or not 1 <= len(domains) <= 100 or any(not isinstance(item, str) for item in domains):
                    raise ServerError("Importe de 1 a 100 domínios por lote de até 8 KiB.")
                return self.banlist.import_domains(domains, payload.get("category", "Outros"))
            if not isinstance(payload.get("domain"), str):
                raise ServerError("Informe um domínio válido.")
            if "expected_revision" in payload and (type(payload["expected_revision"]) is not int or payload["expected_revision"] < 0):
                raise ServerError("Revisão inválida.")
            function = self.banlist.upsert if operation == "upsert" else self.banlist.delete
            return {"site": function(**payload)}

    def start_sync(self, payload, role):
        if not isinstance(payload, dict) or set(payload) - {"limit"}:
            raise ServerError("Parâmetros do lote inválidos.")
        limit = payload.get("limit", 20)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ServerError("Aplique de 1 a 100 operações por lote.")
        with self.job_lock:
            if self.sync_job["running"] or self.cancel_sync.is_set():
                raise ServerError("Há um lote em andamento ou o serviço está encerrando.")
            if not self.network_lock.acquire(blocking=False):
                raise ServerError("Há uma operação de rede em andamento. Aguarde e atualize.")
            try:
                self.check_mutation("add_domain")
                self.check_mutation("remove_domain")
            except ServerError:
                self.network_lock.release()
                raise
            self.sync_job = {"running": True, "job_id": secrets.token_hex(8), "report": None, "error": None}
            application = self
            class CheckedTransport:
                host = getattr(application.transport, "host", "")
                port = getattr(application.transport, "port", "")

                def request(self, action, **params):
                    value = application.transport.request(action, **params)
                    value = application.public_snapshot(value)
                    if not all(value["capabilities"].get(key) is True for key in ACTION_CAPABILITIES["add_domain"]):
                        raise ServerError("O controlador não permite sincronizar bloqueios de domínios.")
                    return value
            def run_batch():
                report, error = None, None
                try:
                    report = self.banlist.sync(CheckedTransport(), limit=limit, cancel_event=self.cancel_sync)
                    snapshot = report.get("snapshot")
                    if isinstance(snapshot, dict):
                        self.last_snapshot = self.public_snapshot(snapshot)
                        self.last_success = time.monotonic()
                    self.stale = snapshot is None or bool(report.get("errors"))
                except (BanlistError, ServerError) as failure:
                    error = str(failure)[:250]
                    self.stale = True
                except Exception:
                    error = "O lote não foi confirmado. Atualize e revise o equipamento antes de repetir."
                    self.stale = True
                finally:
                    self.network_lock.release()
                    with self.job_lock:
                        self.sync_job.update(running=False, report=report, error=error)
                    self.audit("banlist_sync", role, "unconfirmed" if error or (report and report.get("errors")) else "completed_demo" if self.config.demo else "completed_controller")
            self.sync_thread = threading.Thread(target=run_batch, name="banlist-sync", daemon=True)
            self.sync_thread.start()
            return dict(self.sync_job)

    def execute(self, action: str, params: dict) -> dict:
        if self.cancel_sync.is_set():
            raise ServerError("O servidor foi encerrado.")
        action, params = validate_action(action, params)
        if not self.network_lock.acquire(timeout=0.1):
            raise ServerError("Há uma operação em andamento. Aguarde e atualize.")
        try:
            if action != "snapshot":
                self.check_mutation(action)
            if action == "set_address_block" and self.last_snapshot:
                devices = self.last_snapshot.get("devices", [])
                matches = [row for row in devices if isinstance(row, dict) and str(row.get(params["kind"], "")).lower() == params["address"]]
                if params["blocked"]:
                    if not any(row.get("observed", True) is not False for row in matches):
                        raise ServerError("O endereço ainda não foi observado pela fonte.")
                    protected_ips = set(self.config.controller.get("protected_ips", []))
                    protected_macs = {str(row.get("mac", "")).lower() for row in devices if isinstance(row, dict) and (row.get("protected") or row.get("ip") in protected_ips)}
                    protected_macs.update(self.config.controller.get("protected_macs", []))
                    if any(row.get("protected") or row.get("ip") in protected_ips or str(row.get("mac", "")).lower() in protected_macs - {""} for row in matches):
                        raise ServerError("Este endereço pertence a uma máquina protegida.")
            try:
                snapshot = self.transport.request(action, **params)
            except Exception:
                self.stale = True
                raise
            try:
                self.last_snapshot = self.public_snapshot(snapshot)
            except ServerError:
                self.stale = True
                raise
            self.last_success = time.monotonic()
            self.stale = False
            return self.last_snapshot
        finally:
            self.network_lock.release()


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16
    allow_reuse_address = True

    def __init__(self, application: Application, port=None):
        self.application = application
        self.slots = threading.BoundedSemaphore(16)
        # Nenhuma opção permite publicar 0.0.0.0 ou uma interface externa.
        super().__init__((BIND_HOST, application.config.port if port is None else port), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "LabGuardLocal"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    @property
    def app(self):
        return self.server.application

    def log_message(self, *_args):
        pass

    def _send(self, status: int, body, content_type="application/json; charset=utf-8", *, attachment=None, snapshot_state=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_RESPONSE:
            status, body = 502, b'{"ok":false,"error":"Resposta excede o limite."}'
            content_type = "application/json; charset=utf-8"
            attachment = None
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if attachment:
            filename = attachment if isinstance(attachment, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", attachment) else "labguard-sites.csv"
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        if snapshot_state in {"fresh", "stale"}:
            self.send_header("X-LabGuard-Snapshot-State", snapshot_state)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        if status == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        if self.command == "HEAD":
            self.close_connection = True
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        self.close_connection = True

    def _error(self, status, text):
        self._send(status, {"ok": False, "error": text})

    def send_error(self, code, message=None, explain=None):
        # Também padroniza erros do parser HTTP, sem página padrão do runtime.
        self._error(code, "Solicitação HTTP inválida.")

    def _request_allowed(self) -> bool:
        if len(self.path) > 2048 or sum(len(key) + len(value) for key, value in self.headers.items()) > MAX_HEADERS:
            self._error(431, "Cabeçalhos excedem o limite.")
            return False
        if len(self.headers.get_all("Host", [])) != 1:
            self._error(400, "Host inválido.")
            return False
        try:
            host = urlsplit("http://" + self.headers["Host"])
            valid = host.hostname in {"localhost", "127.0.0.1"} and host.port == self.server.server_port
            valid = valid and not host.username and not host.password and host.path == ""
        except ValueError:
            valid = False
        if not valid:
            self._error(403, "O serviço aceita somente acesso local autorizado.")
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + self.headers["Host"]:
            self._error(403, "Origem não autorizada.")
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._error(403, "Acesso entre sites não permitido.")
            return False
        parsed = urlsplit(self.path)
        query_routes = {"/api/banlist": {"q", "category", "enabled"}, "/api/report": {"format"}}
        if parsed.scheme or parsed.netloc or parsed.fragment or (parsed.query and (parsed.path not in query_routes or self.command not in {"GET", "HEAD"})):
            self._error(400, "URL inválida. Use o cabeçalho de autorização.")
            return False
        if parsed.query:
            try:
                query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True, max_num_fields=3)
                if set(query) - query_routes[parsed.path] or any(len(values) != 1 for values in query.values()):
                    raise ValueError()
            except ValueError:
                self._error(400, "Filtros de consulta inválidos.")
                return False
        return True

    def _authenticate(self, *, admin=False):
        if self.app.limits.auth_blocked():
            self._error(429, "Muitas tentativas de autenticação. Aguarde um minuto.")
            return None
        values = self.headers.get_all("Authorization", [])
        role = self.app.role(values[0]) if len(values) == 1 else None
        if role is None:
            self.app.limits.reject_auth()
            self.app.audit("authentication", "unknown", "rejected")
            self._error(401, "Credencial ausente ou inválida.")
            return None
        if not self.app.limits.accept(role, mutation=admin):
            self._error(429, "Limite de solicitações atingido. Aguarde um minuto.")
            return None
        if admin and role != "admin":
            self.app.audit("authorization", role, "rejected")
            self._error(403, "Esta credencial permite somente consulta.")
            return None
        return role

    def do_GET(self):
        if not self._request_allowed():
            return
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send(200, {"ok": True, "service": "LabGuard Server"})
            return
        if path in ASSET_TYPES:
            name, mime = ASSET_TYPES[path]
            try:
                body = (asset_directory() / name).read_bytes()
            except OSError:
                self._error(503, "Recursos do painel indisponíveis.")
            else:
                self._send(200, body, mime)
            return
        if path not in {"/api/school/policy", "/api/snapshot", "/api/banlist", "/api/banlist/export", "/api/banlist/sync-status", "/api/network-map", "/api/report"}:
            self._error(404, "Recurso não encontrado.")
            return
        role = self._authenticate()
        if not role:
            return
        if path == "/api/school/policy":
            from .school_policy import SCHOOL_POLICY
            data = {"domains": [domain for domain, category in SCHOOL_POLICY],
                    "categories": list(dict.fromkeys(category for domain, category in SCHOOL_POLICY))}
            self._send(200, {"ok": True, "data": data, "role": role})
            return
        if path in {"/api/network-map", "/api/report"}:
            try:
                format = "svg" if path == "/api/network-map" else parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("format", ["html"])[0]
                if path == "/api/report" and format not in {"html", "csv", "pdf"}:
                    raise ServerError("Escolha formato html, csv ou pdf.")
                body, state = self.app.report(format)
            except (ServerError, ReportError) as error:
                self.app.audit("report_export", role, "rejected")
                self._error(400, str(error)[:250])
                return
            except Exception:
                self.app.audit("report_export", role, "failed")
                self._error(503, "Não foi possível gerar o relatório. Confira os recursos e o estado do servidor.")
                return
            mime = {"svg": "image/svg+xml; charset=utf-8", "html": "text/html; charset=utf-8", "csv": "text/csv; charset=utf-8", "pdf": "application/pdf"}[format]
            self.app.audit("report_export", role, "cached_" + state)
            self._send(200, body, mime, attachment="labguard-mapa.svg" if format == "svg" else "labguard-relatorio." + format, snapshot_state=state)
            return
        if path.startswith("/api/banlist"):
            try:
                if path == "/api/banlist/sync-status":
                    data = self.app.sync_status()
                elif path == "/api/banlist/export":
                    body = self.app.banlist.export_csv().encode("utf-8-sig")
                    self._send(200, body, "text/csv; charset=utf-8", attachment=True)
                    return
                else:
                    query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                    term = query.get("q", [""])[0]
                    category = query.get("category", [""])[0]
                    activation = query.get("enabled", [""])[0]
                    if len(term) > 200 or len(category) > 40 or activation not in {"", "true", "false"}:
                        raise ServerError("Filtros de consulta inválidos.")
                    enabled = None if not activation else activation == "true"
                    sites = self.app.banlist.list_sites(query=term, category=category, enabled=enabled, limit=1000)
                    data = {"sites": sites, "summary": self.app.banlist.summary(), "limit": 1000}
            except (BanlistError, ServerError) as error:
                self._error(400, str(error)[:250])
                return
            except Exception:
                self._error(503, "O banco de sites está indisponível.")
                return
            self._send(200, {"ok": True, "data": data, "role": role})
            return
        try:
            data = self.app.execute("snapshot", {})
        except Exception:
            self.app.audit("snapshot", role, "controller_failed")
            self._error(502, "Não foi possível atualizar a fonte. Confira o serviço de observação ou a conexão, o certificado e as credenciais do equipamento.")
            return
        self._send(200, {"ok": True, "data": data, "role": role})

    def do_POST(self):
        if not self._request_allowed():
            return
        from .station_web import STATION_ROUTES
        if self.path not in STATION_ROUTES and self.path not in {"/api/school/protect", "/api/access/prepare", "/api/action", "/api/banlist/upsert", "/api/banlist/delete", "/api/banlist/import", "/api/banlist/sync"}:
            self._error(404, "Recurso não encontrado.")
            return
        role = self._authenticate(admin=True)
        if not role:
            return
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            self._error(400, "Tamanho do corpo inválido.")
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._error(415, "Envie JSON no corpo da solicitação.")
            return
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            size = -1
        if not 0 < size <= MAX_BODY:
            self._error(413, "Corpo ausente ou maior que 8 KiB.")
            return
        audit_action = "mutation"
        if self.path in STATION_ROUTES:
            audit_action = "station_" + self.path.rsplit("/", 1)[-1]
        elif self.path == "/api/access/prepare":
            audit_action = "access_prepare"
        elif self.path == "/api/school/protect":
            audit_action = "school_protect"
        try:
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
            if self.path == "/api/school/protect":
                data = self.app.protect_school(payload)
                self.app.audit(audit_action, role, "confirmed" if data.get("ok") is True else "partial")
                self._send(200, {"ok": True, "data": data, "role": role})
                return
            if self.path == "/api/access/prepare":
                from .access_setup import prepare_access
                data = prepare_access(payload, asset_directory())
                self.app.audit(audit_action, role, "unconfirmed" if data.get("ok") is False else "generated")
                self._send(200, {"ok": True, "role": role, "data": data})
                return
            if self.path in STATION_ROUTES:
                operation = self.path.rsplit("/", 1)[-1]
                operator = hashlib.sha256(self.headers["Authorization"][7:].encode("ascii")).hexdigest()
                data = self.app.stations.run(self.app, operation, payload, operator)
                outcome = "unconfirmed"
                if data.get("ok") is True and data.get("block_confirmed") is not False:
                    outcome = "confirmed"
                elif operation == "preview" and data.get("id") and data.get("ok") is not False:
                    outcome = "preview_ready"
                self.app.audit(audit_action, role, outcome)
                self._send(200, {"ok": True, "data": data, "role": role})
                return
            if self.path.startswith("/api/banlist/"):
                operation = self.path.rsplit("/", 1)[-1]
                data = self.app.start_sync(payload, role) if operation == "sync" else self.app.edit_banlist(operation, payload)
                self.app.audit("banlist_" + operation, role, "started" if operation == "sync" else "saved_local")
                self._send(202 if operation == "sync" else 200, {"ok": True, "data": data, "role": role})
                return
            if not isinstance(payload, dict) or set(payload) != {"action", "params"}:
                raise ServerError("Formato de operação inválido.")
            action, params = validate_action(payload["action"], payload["params"])
            data = self.app.execute(action, params)
        except (ValueError, UnicodeError, ServerError, BanlistError) as error:
            self.app.audit(audit_action, role, "rejected")
            self._error(400, str(error)[:250])
            return
        except Exception:
            self.app.audit(audit_action, role, "unconfirmed" if audit_action != "mutation" else "controller_failed")
            self._error(502, "A operação não foi confirmada. Atualize o estado antes de tentar novamente.")
            return
        self.app.audit(action, role, "applied_" + data.get("mode", "controller"))
        self._send(200, {"ok": True, "data": data, "role": role})

    def do_OPTIONS(self):
        self._error(405, "Método não permitido.")

    do_HEAD = do_GET
    do_PUT = do_DELETE = do_PATCH = do_TRACE = do_CONNECT = do_OPTIONS


def build_server(directory: Path, *, demo=False, transport=None, port=None, logging_enabled=True):
    config = ServerConfig(directory, demo=demo)
    application = Application(config, transport=transport, logging_enabled=logging_enabled)
    try:
        return LocalHTTPServer(application, port=port)
    except Exception:
        application.close()
        raise
