from __future__ import annotations

import base64
import copy
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
from urllib import error, parse, request
import zipfile

from ..transport import validate_host


class IntegrationError(RuntimeError):
    pass


MAX_PROFILE_BYTES = 128 * 1024
MAX_DOWNLOAD_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
PROFILE_ID = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z")
MAC = re.compile(r"\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b|\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.I)
CLI_FAILURE = re.compile(r"(?:%\s*(?:Invalid|Error|Incomplete|Ambiguous|Authorization)|Unrecognized command|Unknown command|Permission denied|Invalid input)", re.I)
CISCO_PORT = re.compile(r"(?:Gi(?:gabitEthernet)?|Fa(?:stEthernet)?|Te(?:nGigabitEthernet)?|Twe(?:ntyFiveGigE)?|Fo(?:rtyGigabitEthernet)?|Hu(?:ndredGigE)?|Eth(?:ernet)?)\d+(?:/\d+){0,3}\Z", re.I)
TPLINK_PORT = re.compile(r"(?:(?:gigabitEthernet|fastEthernet|ten-gigabitEthernet)\s+\d+(?:/\d+){1,2}|(?:Gi|Fa|Te)\d+(?:/\d+){1,2})\Z", re.I)


def capabilities(port_control=False):
    return {"inventory": True, "port_control": port_control,
            "domain_filtering": False, "device_internet_cut": False}


BUILTINS = [
    {"id": "cisco_ios", "name": "Cisco Catalyst - IOS / IOS XE (SSH)", "vendor": "Cisco",
     "family": "cisco_ios", "transport": "ssh", "device_class": "Switch gerenciável Catalyst",
     "description": "Consulta portas/MACs e administra somente as portas de acesso explicitamente autorizadas.",
     "notes": "Exige SSH por chave, usuário já em EXEC privilegiado e CLI compatível. Não inclui IOS XR, NX-OS, Meraki nem todos os roteadores Cisco. Alterações ficam na running-config; não grava startup-config.",
     "capabilities": capabilities(True), "source_url": "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/int_hw/b_179_int_and_hw_9300_cg/configuring_interface_characteristics.html"},
    {"id": "tplink_jetstream", "name": "TP-Link JetStream - CLI standalone (SSH)", "vendor": "TP-Link",
     "family": "tplink_jetstream", "transport": "ssh", "device_class": "Switch gerenciável JetStream compatível",
     "description": "Consulta portas/MACs e envia shutdown/no shutdown a portas autorizadas.",
     "notes": "Referência T1500/T1600/T1700/T2500/T2600 compatíveis com o guia CLI. Não inclui roteadores domésticos, switches não gerenciáveis ou API Omada Controller. Omada pode reaplicar configuração; confirme modo standalone. Exige SSH por chave e usuário privilegiado.",
     "capabilities": capabilities(True), "source_url": "https://www.tp-link.com/us/configuration-guides/managing_physical_interface/"},
    {"id": "mikrotik_routeros7", "name": "MikroTik RouterOS 7 - REST HTTPS (consulta)", "vendor": "MikroTik",
     "family": "routeros_rest", "transport": "https", "device_class": "Roteador RouterOS 7 com REST habilitado",
     "description": "Lê interfaces, concessões DHCP e ARP diretamente do roteador.",
     "notes": "Somente consulta nesta versão; não instala regras no roteador. Exige www-ssl, certificado válido e usuário REST/API com permissão read.",
     "capabilities": capabilities(), "source_url": "https://manual.mikrotik.com/docs/developer-guides/rest-api/"},
    {"id": "openwrt_ssh", "name": "OpenWrt - SSH (consulta)", "vendor": "OpenWrt",
     "family": "openwrt_ssh", "transport": "ssh", "device_class": "Roteador com OpenWrt e dnsmasq",
     "description": "Lê interfaces e concessões DHCPv4 diretamente do OpenWrt.",
     "notes": "Somente consulta. Usa ubus call network.interface dump e /tmp/dhcp.leases. O caminho de leases pode variar em configurações personalizadas.",
     "capabilities": capabilities(), "source_url": "https://openwrt.org/docs/techref/ubus"},
]


def _text(value, label, maximum=300):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise IntegrationError(f"{label} inválido.")
    return value.strip()


def _https_url(value):
    value = _text(value, "URL HTTPS", 2048)
    url = parse.urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
        raise IntegrationError("Use uma URL HTTPS sem credenciais nem fragmento.")
    try:
        url.port
    except ValueError as exc:
        raise IntegrationError("Porta da URL inválida.") from exc
    return value


def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".profile-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            set_descriptor_mode = getattr(os, "fchmod", None)
            if callable(set_descriptor_mode):
                set_descriptor_mode(stream.fileno(), 0o600)
            else:
                # Windows has no fchmod. The file inherits the user's profile
                # directory ACL; chmod only clears/sets its read-only flag.
                os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate_profile(profile):
    if not isinstance(profile, dict) or profile.get("schema_version") != 1:
        raise IntegrationError("O perfil precisa de schema_version=1.")
    allowed = {"schema_version", "id", "name", "vendor", "family", "device_class", "description", "notes", "source_url", "inventory_commands"}
    if set(profile) - allowed:
        raise IntegrationError("O perfil contém campos não permitidos; código e dependências não são aceitos.")
    result = dict(profile)
    identifier = profile.get("id", "")
    if not isinstance(identifier, str) or not PROFILE_ID.fullmatch(identifier):
        raise IntegrationError("ID do perfil inválido; use letras minúsculas, números, _ ou -.")
    for field in ("name", "vendor", "device_class", "description"):
        result[field] = _text(profile.get(field), field)
    result["notes"] = _text(profile.get("notes", "Confira modelo e firmware antes de usar."), "notes", 1500)
    result["source_url"] = _https_url(profile.get("source_url"))
    family = profile.get("family")
    if family not in {"cisco_ios", "tplink_jetstream", "routeros_rest", "openwrt_ssh", "ssh_inventory"}:
        raise IntegrationError("Família de protocolo não suportada. É necessário um adaptador de software para novos protocolos.")
    commands = profile.get("inventory_commands", [])
    if family == "ssh_inventory":
        if not isinstance(commands, list) or not 1 <= len(commands) <= 5:
            raise IntegrationError("Perfil de consulta precisa de 1 a 5 inventory_commands.")
        for command in commands:
            if not isinstance(command, str) or len(command) > 160 or not re.fullmatch(r"(?:show|display|get) [A-Za-z0-9_ .:/-]+", command):
                raise IntegrationError("Comando de consulta inválido; use show/display/get sem operadores de shell.")
        result["inventory_commands"] = commands
    elif commands:
        raise IntegrationError("Comandos personalizados só são aceitos em perfis ssh_inventory de consulta.")
    result["transport"] = "https" if family == "routeros_rest" else "ssh"
    result["capabilities"] = capabilities(family in {"cisco_ios", "tplink_jetstream"})
    result["custom"] = True
    return result


class _HTTPSOnlyRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class IntegrationManager:
    def __init__(self, profile_dir=None):
        self.profile_dir = Path(profile_dir).expanduser() if profile_dir else Path.home() / ".labguard" / "integrations"

    def list_profiles(self):
        profiles = copy.deepcopy(BUILTINS)
        if self.profile_dir.is_dir():
            for path in sorted(self.profile_dir.glob("*.json"))[:100]:
                try:
                    if path.stat().st_size > MAX_PROFILE_BYTES:
                        continue
                    profile = validate_profile(json.loads(path.read_text(encoding="utf-8")))
                    if profile["id"] not in {p["id"] for p in profiles}:
                        profiles.append(profile)
                except (OSError, ValueError, IntegrationError):
                    continue
        return profiles

    def connect(self, profile_id, host, port=22, user="", key_path="", known_hosts="", allowed_access_ports="", password="", ca_file=""):
        profile = next((p for p in self.list_profiles() if p["id"] == profile_id), None)
        if not profile:
            raise IntegrationError("Perfil não encontrado.")
        if profile["family"] == "routeros_rest":
            return RouterOSSession(profile, host, port, user, password, ca_file)
        return SSHSession(profile, host, port, user, key_path, known_hosts, allowed_access_ports)

    def _install_bytes(self, data, expected_sha256=""):
        if len(data) > MAX_DOWNLOAD_BYTES:
            raise IntegrationError("Perfil excede o limite de 1 MiB.")
        if expected_sha256:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
                raise IntegrationError("Informe o SHA-256 completo, com 64 caracteres hexadecimais.")
            if hashlib.sha256(data).hexdigest() != expected_sha256.lower():
                raise IntegrationError("O SHA-256 não confere; nenhum perfil foi instalado.")
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                if len(entries) != 1 or entries[0].filename != "profile.json" or entries[0].file_size > MAX_PROFILE_BYTES or entries[0].flag_bits & 1:
                    raise IntegrationError("O ZIP deve conter apenas profile.json, sem pastas, código ou arquivos extras.")
                data = archive.read(entries[0])
        if len(data) > MAX_PROFILE_BYTES:
            raise IntegrationError("O JSON do perfil excede 128 KiB.")
        try:
            profile = validate_profile(json.loads(data.decode("utf-8-sig")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrationError("O arquivo não é um perfil JSON válido.") from exc
        if profile["id"] in {p["id"] for p in BUILTINS}:
            raise IntegrationError("Um perfil personalizado não pode substituir um adaptador incluído.")
        # Never overwrite another custom profile silently.
        target = self.profile_dir / (profile["id"] + ".json")
        if target.exists():
            raise IntegrationError("Esse ID já foi instalado. Use outro ID para conservar o perfil existente.")
        serializable = {k: v for k, v in profile.items() if k not in {"custom", "transport", "capabilities"}}
        _atomic_json(target, serializable)
        return profile

    def install_profile(self, path, expected_sha256=""):
        path = Path(path).expanduser()
        if not path.is_file() or path.stat().st_size > MAX_DOWNLOAD_BYTES:
            raise IntegrationError("Arquivo ausente ou maior que 1 MiB.")
        return self._install_bytes(path.read_bytes(), expected_sha256)

    def download_profile(self, url, sha256):
        url = _https_url(url)
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            raise IntegrationError("Baixar exige SHA-256 esperado de uma fonte confiável.")
        opener = request.build_opener(_HTTPSOnlyRedirect(), request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request.Request(url, headers={"User-Agent": "LabGuard/1.2"}), timeout=20) as response:
                data = response.read(MAX_DOWNLOAD_BYTES + 1)
        except (OSError, error.URLError, ValueError) as exc:
            raise IntegrationError(f"Não foi possível baixar o perfil: {exc}") from exc
        return self._install_bytes(data, sha256)


def canonical_port(value, family):
    if not isinstance(value, str):
        raise IntegrationError("Porta física inválida.")
    value = " ".join(value.strip().split())
    regex = TPLINK_PORT if family == "tplink_jetstream" else CISCO_PORT
    if not regex.fullmatch(value):
        raise IntegrationError("Nome de porta física não aceito pelo adaptador.")
    if family == "tplink_jetstream":
        for short, longname in (("gi", "gigabitEthernet"), ("fa", "fastEthernet"), ("te", "ten-gigabitEthernet")):
            if re.match(short + r"\d", value, re.I):
                return longname.lower() + " " + value[len(short):]
        return value.split()[0].lower() + " " + value.split()[1]
    prefixes = (("gigabitethernet", "Gi"), ("fastethernet", "Fa"), ("tengigabitethernet", "Te"), ("twentyfivegige", "Twe"), ("fortygigabitethernet", "Fo"), ("hundredgige", "Hu"), ("ethernet", "Eth"))
    for longname, short in prefixes:
        if value.lower().startswith(longname):
            return short + value[len(longname):]
    short_names = {"gi": "Gi", "fa": "Fa", "te": "Te", "twe": "Twe", "fo": "Fo", "hu": "Hu", "eth": "Eth"}
    match = re.fullmatch(r"([A-Za-z]+)([0-9/]+)", value)
    return short_names[match.group(1).lower()] + match.group(2)


def parse_ports(text, family):
    rows = []
    seen = set()
    for line in text.splitlines():
        # Catalyst: Gi1/0/1 [name with spaces] connected 10 a-full a-1000 ...
        if family == "cisco_ios":
            found = re.match(r"\s*(\S+)\s+(.*?)\s*(connected|notconnect|disabled|err-disabled|inactive|suspended|monitoring)\s+(\S+)\s+", line, re.I)
            if not found:
                continue
            raw, description, status, vlan = found.groups()
            administrative = "disabled" if status.lower() == "disabled" else "enabled"
        else:
            # JetStream: Gi1/0/1 Enable Up 1000M Full ... or port configuration table.
            found = re.match(r"\s*((?:(?:gigabitEthernet|fastEthernet|ten-gigabitEthernet)\s+)?\d+/\d+/\d+|(?:Gi|Fa|Te)\d+/\d+/\d+)\s+(Enable|Disable|Enabled|Disabled)\s+(.*)", line, re.I)
            if found:
                raw, admin, details = found.groups()
                if raw[0].isdigit():
                    raw = "gigabitEthernet " + raw
                administrative = "disabled" if admin.lower().startswith("disabl") else "enabled"
                status = admin + " " + details.strip()
                description, vlan = "", ""
            else:
                # The status table may omit Admin and start Link; use unknown admin.
                found = re.match(r"\s*((?:Gi|Fa|Te)\d+/\d+/\d+)\s+(Up|Down|LinkUp|LinkDown)\s+(.*)", line, re.I)
                if not found:
                    continue
                raw, status, details = found.groups()
                administrative, description, vlan = "unknown", details.strip(), ""
        try:
            port = canonical_port(raw, family)
        except IntegrationError:
            continue
        if port in seen:
            continue
        seen.add(port)
        rows.append({"name": port, "status": status, "administrative": administrative,
                     "macs": [], "description": description.strip(), "vlan": vlan})
    return rows


def attach_macs(rows, text, family):
    by_name = {row["name"]: row for row in rows}
    for line in text.splitlines():
        matches = MAC.findall(line)
        if not matches:
            continue
        # Names with a space are rejoined for JetStream.
        tokens = line.strip().split()
        candidates = list(tokens) + [" ".join(tokens[i:i+2]) for i in range(len(tokens)-1)]
        for token in candidates:
            try:
                name = canonical_port(token, family)
            except IntegrationError:
                continue
            if name in by_name:
                for mac in matches:
                    normalized = re.sub(r"[^0-9a-f]", "", mac.lower())
                    normalized = ":".join(normalized[i:i+2] for i in range(0, 12, 2))
                    if normalized not in by_name[name]["macs"]:
                        by_name[name]["macs"].append(normalized)


class SSHSession:
    def __init__(self, profile, host, port, user, key_path, known_hosts, allowed_access_ports):
        self.profile = profile
        self.host = validate_host(host)
        self.port = _port(port)
        if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", user):
            raise IntegrationError("Usuário SSH inválido.")
        self.user = user
        self.key_path = _file(key_path) if key_path else ""
        self.known_hosts = _file(known_hosts) if known_hosts else ""
        self.ssh = shutil.which("ssh")
        if not self.ssh:
            raise IntegrationError("Instale o Cliente OpenSSH pelo sistema operacional. Nenhum pacote Python é necessário.")
        values = allowed_access_ports.split(",") if isinstance(allowed_access_ports, str) else list(allowed_access_ports or [])
        if len(values) > 256:
            raise IntegrationError("Autorize no máximo 256 portas explicitamente.")
        self.allowed = {canonical_port(value, profile["family"]) for value in values if value.strip()} if profile["capabilities"]["port_control"] else set()

    def _command(self, pty=False):
        command = [self.ssh, "-tt" if pty else "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR", "-p", str(self.port)]
        if self.key_path:
            command += ["-o", "IdentitiesOnly=yes", "-i", self.key_path]
        if self.known_hosts:
            command += ["-o", "UserKnownHostsFile=" + self.known_hosts]
        return command + [f"{self.user}@{self.host}"]

    def _run(self, commands, *, remote_command=None):
        args = self._command(pty=remote_command is None)
        if remote_command is not None:
            args += [remote_command]
            payload = None
        else:
            payload = "\n".join(commands) + "\n"
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {}
        try:
            result = subprocess.run(args, input=payload, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=30, check=False, **options)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IntegrationError("Falha ou tempo esgotado no SSH. Confira o estado do equipamento antes de repetir uma alteração.") from exc
        output = result.stdout or ""
        if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise IntegrationError("Saída SSH maior que o limite.")
        if result.returncode:
            raise IntegrationError("SSH recusou a conexão: " + (result.stderr or "sem detalhe")[-700:].strip())
        if CLI_FAILURE.search(output):
            raise IntegrationError("O equipamento rejeitou um comando. Confira modelo, firmware, modo privilegiado e sintaxe do perfil.")
        if re.search(r"--+\s*More\s*--+|Press (?:any key|SPACE)|More:\s*<", output, re.I):
            raise IntegrationError("A CLI paginou a saída. Desative a paginação da sessão no equipamento e teste novamente; nenhuma saída parcial será usada para autorizar cortes.")
        return output

    def snapshot(self):
        family = self.profile["family"]
        warnings = ["Adaptador baseado na CLI documentada; confirme modelo/firmware e valide uma porta de teste antes de usar com a turma."]
        devices, ports, summary = [], [], ""
        if family == "openwrt_ssh":
            interfaces = self._run([], remote_command="ubus call network.interface dump")
            leases = self._run([], remote_command="cat /tmp/dhcp.leases")
            try:
                document = json.loads(interfaces)
                for entry in document.get("interface", []):
                    ports.append({"name": entry.get("interface", ""), "status": "up" if entry.get("up") else "down", "macs": [], "description": entry.get("device", ""), "administrative": "unknown"})
            except (ValueError, TypeError):
                warnings.append("A resposta ubus não pôde ser interpretada.")
            for line in leases.splitlines():
                fields = line.split()
                if len(fields) >= 4:
                    try:
                        ipaddress.IPv4Address(fields[2])
                    except ValueError:
                        continue
                    devices.append({"ip": fields[2], "mac": fields[1], "name": "" if fields[3] == "*" else fields[3], "state": "Concessão observada"})
        elif family == "ssh_inventory":
            results = []
            for command in self.profile["inventory_commands"]:
                results.append(command + "\n" + self._run([], remote_command=command))
            summary = "\n\n".join(results)[:16000]
            warnings.append("Perfil personalizado de consulta: dados brutos, sem controle de portas nem regras de domínio.")
        else:
            if family == "cisco_ios":
                status = self._run(["terminal length 0", "show interfaces status", "exit"])
                macs = self._run(["terminal length 0", "show mac address-table", "exit"])
            else:
                # JetStream CLI has configure (not configure terminal).
                status = self._run(["show interface configuration", "show interface status", "exit"])
                macs = self._run(["show mac address-table", "exit"])
                warnings.append("JetStream: a paginação da CLI precisa estar desativada no equipamento; versões sem controle de paginação podem exigir outro adaptador.")
            ports = parse_ports(status, family)
            attach_macs(ports, macs, family)
            if not ports:
                warnings.append("Nenhuma porta foi interpretada. Este modelo/firmware pode exigir outro perfil; nenhuma alteração será permitida.")
            for row in ports:
                row["controllable"] = row["name"] in self.allowed and len(row["macs"]) <= 1 and row.get("vlan", "").lower() != "trunk"
            warnings.append("Desativar porta corta toda a rede dessa porta, inclusive acesso local; não equivale a filtrar somente internet. Uplinks, trunks e gerenciamento não devem entrar na lista autorizada.")
        return {"vendor": self.profile["vendor"], "adapter": self.profile["name"], "capabilities": self.profile["capabilities"],
                "ports": ports, "devices": devices, "warnings": warnings, "raw_summary": summary}

    def set_port_enabled(self, port, enabled):
        if type(enabled) is not bool or not self.profile["capabilities"]["port_control"]:
            raise IntegrationError("Este adaptador não permite essa alteração de porta.")
        port = canonical_port(port, self.profile["family"])
        if port not in self.allowed:
            raise IntegrationError("A porta não está na lista explícita de portas de acesso autorizadas desta sessão.")
        before = self.snapshot()
        selected = next((row for row in before["ports"] if row["name"] == port), None)
        if not selected or not selected.get("controllable"):
            raise IntegrationError("Porta não observada, trunk ou múltiplos MACs; alteração recusada.")
        configure = "configure terminal" if self.profile["family"] == "cisco_ios" else "configure"
        self._run([configure, "interface " + port, "no shutdown" if enabled else "shutdown", "end", "exit"])
        after = self.snapshot()
        selected = next((row for row in after["ports"] if row["name"] == port), None)
        expected = "enabled" if enabled else "disabled"
        verified = bool(selected and selected.get("administrative") == expected)
        after["operation"] = {"verified": verified, "message": "Estado administrativo confirmado." if verified else "Comando enviado, mas o estado administrativo não pôde ser confirmado. Confira no console antes de repetir."}
        if not verified:
            after["warnings"].append(after["operation"]["message"])
        return after


def _port(value):
    try:
        port = int(value)
    except (ValueError, TypeError):
        raise IntegrationError("Porta de conexão inválida.") from None
    if not 1 <= port <= 65535:
        raise IntegrationError("Porta de conexão deve ficar entre 1 e 65535.")
    return port


def _file(value):
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise IntegrationError("Arquivo de chave, known_hosts ou CA não encontrado.")
    return str(path)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise IntegrationError("O roteador tentou redirecionar a requisição; confira o endereço HTTPS.")


class RouterOSSession:
    def __init__(self, profile, host, port, user, password, ca_file):
        self.profile = profile
        host = validate_host(host)
        # Manager default SSH port is convenient; HTTPS caller should choose443 explicitly.
        port = _port(port)
        if port == 22:
            port = 443
        if not isinstance(user, str) or not user or ":" in user or any(ord(c) < 32 for c in user):
            raise IntegrationError("Usuário REST inválido.")
        if not isinstance(password, str) or not password:
            raise IntegrationError("Informe a senha REST; ela será mantida somente nesta sessão.")
        authority = "[" + host + "]" if ":" in host else host
        self.base = f"https://{authority}:{port}/rest/"
        self.auth = "Basic " + base64.b64encode((user + ":" + password).encode()).decode("ascii")
        context = ssl.create_default_context(cafile=_file(ca_file) if ca_file else None)
        self.opener = request.build_opener(_NoRedirect(), request.HTTPSHandler(context=context))

    def _get(self, path):
        try:
            req = request.Request(self.base + path, headers={"Authorization": self.auth, "Accept": "application/json"})
            with self.opener.open(req, timeout=15) as response:
                data = response.read(MAX_OUTPUT_BYTES + 1)
            if len(data) > MAX_OUTPUT_BYTES:
                raise IntegrationError("Resposta REST excedeu o limite.")
            rows = json.loads(data)
            if not isinstance(rows, list):
                raise IntegrationError("O RouterOS não retornou uma lista de registros.")
            return rows
        except (OSError, error.URLError, ValueError) as exc:
            raise IntegrationError("Falha na consulta HTTPS RouterOS. Confira certificado/CA, serviço www-ssl e permissões REST/API; nenhuma configuração foi alterada.") from exc

    def snapshot(self):
        interfaces = self._get("interface?.proplist=name,type,running,disabled,comment")
        leases = self._get("ip/dhcp-server/lease?.proplist=address,mac-address,host-name,status")
        arp = self._get("ip/arp?.proplist=address,mac-address,interface")
        devices = {}
        for row in leases:
            ip = row.get("address", "")
            devices[ip] = {"ip": ip, "mac": row.get("mac-address", ""), "name": row.get("host-name", ""), "state": "DHCP: " + row.get("status", "observado")}
        for row in arp:
            ip = row.get("address", "")
            devices.setdefault(ip, {"ip": ip, "mac": row.get("mac-address", ""), "name": "", "state": "ARP observado"})
        ports = [{"name": row.get("name", ""), "status": "up" if row.get("running") == "true" else "down", "macs": [],
                  "description": row.get("comment", row.get("type", "")), "administrative": "disabled" if row.get("disabled") == "true" else "enabled", "controllable": False} for row in interfaces]
        return {"vendor": self.profile["vendor"], "adapter": self.profile["name"], "capabilities": self.profile["capabilities"],
                "ports": ports, "devices": list(devices.values()), "raw_summary": "", "warnings": ["Consulta direta RouterOS. Esta integração não altera firewall/DNS nem corta a internet; os controles do gateway LabGuard são independentes."]}

    def set_port_enabled(self, port, enabled):
        raise IntegrationError("O adaptador RouterOS desta versão é somente consulta.")
