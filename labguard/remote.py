"""Administração pontual por serviços nativos já habilitados no computador.

Não instala agente, não habilita serviços e não oferece execução arbitrária.
O inventário contém apenas processos reconhecidos; argumentos e arquivos do
aluno não são coletados. Remoções precisam de prévia recente e token de uso único.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import errno
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time

from .transport import OutputLimitExceeded, run_bounded, ssh_command_base, validate_host


class RemoteError(RuntimeError):
    pass


class WinRMConnectionError(RemoteError):
    """Only messages in this table may be returned by the web panel."""
    _messages = {
        "refused": "A conexão na porta 5986 foi recusada. Confira o IP e se a estação aceita WinRM HTTPS nessa porta.",
        "unreachable": "Não foi possível alcançar a estação. Confira o endereço e a rota até a rede dos alunos.",
        "network_timeout": "A conexão com a porta 5986 expirou. Confira se a estação está ligada e se o firewall permite WinRM HTTPS a partir do PC de TI.",
        "read_timeout": "O serviço na porta 5986 demorou para responder. Confira o WinRM na estação antes de repetir a operação.",
        "interrupted": "A conexão WinRM foi interrompida. Confira se a estação continua disponível antes de repetir a operação.",
        "certificate_name": "O certificado HTTPS não corresponde ao endereço da estação. Confira o alvo e o endereço registrado no certificado.",
        "certificate_time": "O certificado HTTPS está fora do período de validade. Confira a data dos computadores e a validade do certificado.",
        "certificate_trust": "O certificado HTTPS não pôde ser validado. Confira a cadeia do certificado e selecione a CA da escola usada pela estação.",
        "tls": "A negociação HTTPS falhou na porta 5986. Confira o listener WinRM HTTPS e o certificado configurado na estação.",
        "authentication": "O WinRM recusou a autenticação. Confira a senha e a conta autorizada, como DOMÍNIO\\usuário ou NOME-DO-PC\\usuário.",
        "permission": "O Windows negou acesso à operação. Confira se a conta tem permissão de administração remota nessa estação.",
        "endpoint": "O serviço HTTPS respondeu, mas não aceitou a solicitação WinRM em /wsman. Confira o listener HTTPS da estação na porta 5986.",
        "unknown": "Não foi possível concluir a conexão WinRM HTTPS. Confira certificado, credenciais e permissões do computador.",
    }

    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in self._messages else "unknown"
        super().__init__(self.public_message)

    @property
    def public_message(self):
        return self._messages.get(self.code, self._messages["unknown"])


def _winrm_failure(error):
    # requests and urllib3 nest exceptions in .reason, .args and exception chains.
    # No server-supplied text, URL, local path or credential is shown or logged.
    chain = []
    pending = [error]
    seen = set()
    while pending and len(chain) < 32:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        chain.append(current)
        nested = (current.__cause__, current.__context__, getattr(current, "reason", None), *current.args)
        pending.extend(cause for cause in nested if isinstance(cause, BaseException))

    # Windows support is optional in source installations. Use the exception types
    # without importing its HTTP stack when starting a Linux-only installation.
    types = {(type(item).__module__, type(item).__name__) for item in chain}
    for item in chain:
        if type(item).__module__ == "winrm.exceptions":
            status = getattr(item, "code", None)
            fault = getattr(item, "wsman_fault_code", None)
            wmi = getattr(item, "wmierror_code", None)
            subcode = getattr(item, "fault_subcode", None)
            if (fault in (5, 0x80070005, 0x80041003) or wmi in (5, 0x80070005, 0x80041003)
                    or (isinstance(subcode, str) and subcode.split(":")[-1] == "AccessDenied")):
                return "permission"
        else:
            status = getattr(getattr(item, "response", None), "status_code", None)
        if status == 401:
            return "authentication"
        if status == 403:
            return "permission"
        if status in (404, 405):
            return "endpoint"

    for item in chain:
        if isinstance(item, ssl.SSLCertVerificationError):
            code = getattr(item, "verify_code", None)
            if code in (62, 64):
                return "certificate_name"
            if code in (9, 10):
                return "certificate_time"
            return "certificate_trust"
    if ("urllib3.util.ssl_match_hostname", "CertificateError") in types:
        return "certificate_name"
    if (any(isinstance(item, ssl.SSLError) for item in chain)
            or types.intersection({("requests.exceptions", "SSLError"), ("urllib3.exceptions", "SSLError")})):
        return "tls"
    if types.intersection({("requests.exceptions", "ReadTimeout"), ("urllib3.exceptions", "ReadTimeoutError")}):
        return "read_timeout"

    for item in chain:
        if not isinstance(item, OSError):
            continue
        codes = {item.errno, getattr(item, "winerror", None)}
        if isinstance(item, ConnectionRefusedError) or codes.intersection({errno.ECONNREFUSED, 10061}):
            return "refused"
        if isinstance(item, socket.gaierror) or codes.intersection({errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}):
            return "unreachable"
        if isinstance(item, TimeoutError) or codes.intersection({errno.ETIMEDOUT, 10060}):
            return "network_timeout"
        if isinstance(item, (ConnectionResetError, ConnectionAbortedError)):
            return "interrupted"
    if types.intersection({("requests.exceptions", "ConnectTimeout"), ("urllib3.exceptions", "ConnectTimeoutError")}):
        return "network_timeout"
    return "unknown"


MAX_OUTPUT = 512 * 1024
PREVIEW_SECONDS = 60
NOTIFICATION_INTERVAL = 300
ROBLOX_PUBLISHER = "CN=6FEF9772-62F8-4C8B-8DE0-70F628846515"
ROBLOX_PUBLISHER_ID = "55nm5eh3cm0pr"
ROBLOX_APPX = ("ROBLOXCORPORATION.ROBLOX", "ROBLOXCorporation.RobloxGDK")
DPKG_GAMES = {"minecraft-launcher": ("minecraft", "Minecraft Launcher"),
              "steam": ("steam", "Steam"), "steam-installer": ("steam", "Steam Installer")}
FLATPAK_GAMES = {"com.valvesoftware.Steam": ("steam", "Steam (Flatpak da comunidade)"),
                 "com.mojang.Minecraft": ("minecraft", "Minecraft Launcher (Flatpak da comunidade)")}

# Nomes exatos são indicadores, não atestação de integridade de um executável.
# java/javaw e Windows10Universal não identificam sozinhos um jogo.
PROCESS_CATALOGUE = {
    "robloxplayerbeta.exe": ("roblox", "Roblox", False),
    "robloxgameclient.exe": ("roblox", "Roblox", False),
    "robloxplayer.exe": ("roblox", "Roblox", False),
    "minecraft.windows.exe": ("minecraft", "Minecraft", False),
    "minecraftlauncher.exe": ("minecraft", "Minecraft Launcher", True),
    "minecraft-launcher": ("minecraft", "Minecraft Launcher", True),
    "fortniteclient-win64-shipping.exe": ("fortnite", "Fortnite", False),
    "valorant-win64-shipping.exe": ("valorant", "Valorant", False),
    "league of legends.exe": ("league", "League of Legends", False),
    "leagueclient.exe": ("league", "League of Legends Launcher", True),
    "cs2.exe": ("cs2", "Counter-Strike 2", False),
    "cs2": ("cs2", "Counter-Strike 2", False),
    "genshinimpact.exe": ("genshin", "Genshin Impact", False),
    "steam.exe": ("steam", "Steam", True), "steam": ("steam", "Steam", True),
    "epicgameslauncher.exe": ("epic", "Epic Games Launcher", True),
}
DISPLAY_CATALOGUE = (
    ("roblox", "Roblox", r"^Roblox(?: Player| for .+| Windows| GDK)?(?:\s+\d.*)?$"),
    ("minecraft", "Minecraft", r"^Minecraft(?: Launcher| for Windows)?$"),
    ("fortnite", "Fortnite", r"^Fortnite$"),
    ("valorant", "Valorant", r"^VALORANT$"),
    ("league", "League of Legends", r"^League of Legends$"),
    ("cs2", "Counter-Strike 2", r"^Counter-Strike 2$"),
    ("genshin", "Genshin Impact", r"^Genshin Impact$"),
    ("steam", "Steam", r"^Steam$"),
    ("epic", "Epic Games Launcher", r"^Epic Games Launcher$"),
)


def _path(value, label):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise RemoteError(f"Caminho de {label} inválido.")
    result = Path(value).expanduser().resolve()
    if not result.is_file():
        raise RemoteError(f"Arquivo de {label} não encontrado.")
    return str(result)


def _clean_text(value, maximum=240):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise RemoteError("O computador retornou um registro inválido.")
    return value


def _decode(value):
    if isinstance(value, bytes):
        if len(value) > MAX_OUTPUT:
            raise RemoteError("O inventário excedeu o limite permitido.")
        try:
            value = value.decode("utf-8-sig", "strict")
        except UnicodeError:
            raise RemoteError("Resposta incompatível com o inventário remoto.") from None
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_OUTPUT:
        raise RemoteError("O inventário excedeu o limite permitido.")
    try:
        result = json.loads(value)
    except (ValueError, UnicodeError):
        raise RemoteError("Resposta incompatível com o inventário remoto.") from None
    if not isinstance(result, dict):
        raise RemoteError("Resposta incompatível com o inventário remoto.")
    return result


def _records(raw, field, maximum=500):
    records = raw.get(field, [])
    if not isinstance(records, list) or len(records) > maximum or any(not isinstance(r, dict) for r in records):
        raise RemoteError("O computador retornou um inventário inválido.")
    return records


def _processes(raw):
    result = []
    for row in _records(raw, "processes"):
        name = _clean_text(row.get("name", ""), 128)
        identity = PROCESS_CATALOGUE.get(name.casefold())
        if name.casefold() == "windows10universal.exe" and row.get("verified_store") == "ROBLOXCORPORATION.ROBLOX":
            identity = ("roblox", "Roblox (Microsoft Store legado)", False)
        if identity is None:
            continue
        pid = row.get("pid")
        if type(pid) is not int or not 1 <= pid <= 2**32 - 1:
            raise RemoteError("O computador retornou um PID inválido.")
        result.append({"name": name, "pid": pid, "game_id": identity[0],
                       "game": identity[1], "is_launcher": identity[2]})
    return result


def _game(game_id, name, install_id, method, removable=False, reason="", **identity):
    return {"id": game_id, "name": name, "install_id": install_id, "method": method,
            "can_uninstall": bool(removable), "reason": reason, "identity": identity}


def _fingerprint(game):
    return hashlib.sha256(json.dumps(game, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


class _Session:
    def __init__(self, host, platform):
        try:
            self._host = validate_host(host)
        except (ValueError, AttributeError):
            raise RemoteError("Informe somente o IP ou nome DNS do computador autorizado.") from None
        self.platform = platform
        self._closed = False
        self._snapshot = None
        self._observed = 0.0
        self._previews = {}
        self._last_notification = {}
        self._operation = threading.Lock()

    @property
    def host(self):
        return self._host

    def _check(self):
        if self._closed:
            raise RemoteError("A sessão remota foi encerrada. Conecte novamente.")

    def inspect(self):
        self._check()
        with self._operation:
            self._check()
            return self._inspect()

    def _inspect(self):
        self._snapshot = None
        raw = self._inventory()
        self._check()
        processes = _processes(raw)
        games = self._games(raw)
        # Uma instalação sem suporte ainda aparece se o processo foi reconhecido.
        installed = {g["id"] for g in games}
        for process in processes:
            if process["game_id"] not in installed:
                installed.add(process["game_id"])
                games.append(_game(process["game_id"], process["game"], "process:" + process["game_id"],
                                   "process", reason="Processo identificado; instalação não verificada. Remoção manual."))
        warnings = ["Nomes de processos são indicadores e podem ser alterados. Um launcher aberto não comprova uma partida.",
                    "O inventário é pontual. Não coleta argumentos de processos, páginas, senhas ou arquivos pessoais."]
        warnings.extend(self._warnings())
        if raw.get("partial") is True:
            warnings.append("Parte do inventário não pôde ser consultada com as permissões desta conta.")
        self._snapshot = {"host": self.host, "platform": self.platform,
                          "observed_at": datetime.now(timezone.utc).isoformat(),
                          "processes": processes, "games": games,
                          "capabilities": {"inventory": True, "uninstall": any(g["can_uninstall"] for g in games), "notify": True},
                          "warnings": warnings}
        self._observed = time.monotonic()
        return copy.deepcopy(self._snapshot)

    def preview_uninstall(self, install_id):
        self._check()
        with self._operation:
            self._check()
            if not self._snapshot or time.monotonic() - self._observed > PREVIEW_SECONDS:
                raise RemoteError("Atualize o inventário antes de preparar uma remoção (validade de 60 segundos).")
            game = next((g for g in self._snapshot["games"] if g["install_id"] == install_id), None)
            if game is None or not game["can_uninstall"]:
                raise RemoteError("Esta instalação não permite remoção remota segura pelo catálogo.")
            now = time.monotonic()
            self._previews = {key: value for key, value in self._previews.items() if now - value["created"] <= PREVIEW_SECONDS}
            if len(self._previews) >= 10:
                self._previews.clear()
            token = secrets.token_urlsafe(32)
            self._previews[token] = {"created": now, "host": self.host, "game": copy.deepcopy(game), "fingerprint": _fingerprint(game)}
            return {"token": token, "host": self.host, "game": copy.deepcopy(game), "expires_in": PREVIEW_SECONDS,
                    "data_notice": self._data_notice(game)}

    def uninstall(self, token):
        self._check()
        with self._operation:
            self._check()
            preview = self._previews.pop(token, None) if isinstance(token, str) else None
            if preview is None or preview["host"] != self.host or time.monotonic() - preview["created"] > PREVIEW_SECONDS:
                raise RemoteError("A confirmação expirou ou é inválida. Atualize e prepare uma nova prévia.")
            # Não basta a seleção antiga da interface: consulte novamente o mesmo alvo.
            snapshot = self._inspect()
            game = next((g for g in snapshot["games"] if g["install_id"] == preview["game"]["install_id"]), None)
            if game is None or not game["can_uninstall"] or _fingerprint(game) != preview["fingerprint"]:
                raise RemoteError("A instalação mudou desde a prévia. Nenhuma remoção foi enviada; atualize o inventário.")
            self._snapshot = None
            self._previews.clear()
            self._remove(game)
            return {"ok": True, "host": self.host, "install_id": game["install_id"],
                    "message": "O sistema concluiu a remoção do pacote selecionado. Atualize o inventário para conferir."}

    def notify(self, kind="games", domain=""):
        self._check()
        if kind not in {"games", "adult"}:
            raise RemoteError("Tipo de aviso inválido.")
        if domain:
            if not isinstance(domain, str) or len(domain) > 253 or "." not in domain:
                raise RemoteError("Informe um domínio válido, sem URL nem caminho.")
            try:
                domain = validate_host(domain).lower()
            except ValueError:
                raise RemoteError("Informe um domínio válido, sem URL nem caminho.") from None
        message = ("LabGuard - Laboratorio escolar: jogos nao sao permitidos durante esta atividade. Feche o jogo e retome a tarefa."
                   if kind == "games" else
                   "LabGuard - Laboratorio escolar: conteudo adulto nao e permitido. Feche a pagina e retome a atividade.")
        if domain:
            message += " Dominio sinalizado: " + domain + "."
        with self._operation:
            self._check()
            now = time.monotonic()
            previous = self._last_notification.get(kind)
            if previous is not None and now - previous < NOTIFICATION_INTERVAL:
                raise RemoteError("Aguarde cinco minutos entre avisos para este computador.")
            # Limita também tentativas falhas para não inundar uma sessão.
            self._last_notification[kind] = now
            sent, channel = self._notify(message)
            return {"sent": bool(sent), "confirmed": False, "channel": channel,
                    "message": ("Aviso entregue ao serviço de mensagens do sistema; leitura pelo aluno não confirmada."
                                if sent else "Nenhuma sessão interativa recebeu o aviso. Confira permissões e disponibilidade de mensagens.")}

    def _data_notice(self, game):
        return "Remove somente o pacote selecionado; não apaga pastas pessoais nem usa opções de limpeza de dados."

    def close(self):
        self._closed = True
        self._snapshot = None
        self._previews.clear()
        self._last_notification.clear()
        self._host = ""


def _windows_inventory_script():
    names = ",".join("'" + name + "'" for name in PROCESS_CATALOGUE if name.endswith(".exe"))
    return r"""
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$partial=$false
$allowed=@(__PROCESSES__)
$processes=@(Get-CimInstance Win32_Process -Property Name,ProcessId | Where-Object { $allowed -contains $_.Name } | Select-Object -First 200 @{n='name';e={$_.Name}},@{n='pid';e={[int]$_.ProcessId}})
$appx=@(); $store=@(); try {
 $store=@(Get-AppxPackage -AllUsers | Where-Object { $_.Name -in @('ROBLOXCORPORATION.ROBLOX','ROBLOXCorporation.RobloxGDK','Microsoft.MinecraftUWP') } | Select-Object -First 100)
 $appx=@($store | Select-Object Name,PackageFullName,PackageFamilyName,Publisher,PublisherId,SignatureKind)
 $legacy=@($store | Where-Object {$_.Name -eq 'ROBLOXCORPORATION.ROBLOX' -and $_.Publisher -ceq 'CN=6FEF9772-62F8-4C8B-8DE0-70F628846515' -and $_.PublisherId -ceq '55nm5eh3cm0pr' -and $_.SignatureKind -eq 'Store'})
 if($legacy.Count -gt 0){
  foreach($p in @(Get-CimInstance Win32_Process -Filter "Name = 'Windows10Universal.exe'" -Property Name,ProcessId,ExecutablePath | Select-Object -First 200)) {
   foreach($package in $legacy){
    if($package.InstallLocation -and $p.ExecutablePath -and $p.ExecutablePath -eq (Join-Path $package.InstallLocation 'Windows10Universal.exe')){
     if($processes.Count -lt 200){$processes+=@{name=$p.Name;pid=[int]$p.ProcessId;verified_store='ROBLOXCORPORATION.ROBLOX'}};break
    }
   }
  }
 }
} catch {$partial=$true}
$desktop=@(); foreach($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
 $desktop+=@(Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^(Roblox|Minecraft|Fortnite|VALORANT|League of Legends|Counter-Strike 2|Genshin Impact|Steam|Epic Games Launcher)' } | Select-Object -First 100 DisplayName)
}
@{processes=$processes;appx=$appx;desktop=@($desktop | Select-Object -First 200);partial=$partial} | ConvertTo-Json -Depth 5 -Compress
""".replace("__PROCESSES__", names)


class WindowsSession(_Session):
    """WinRM HTTPS/NTLM, certificado validado e proxy de ambiente desabilitado."""
    def __init__(self, host, user, password, *, ca_file="", port=5986):
        super().__init__(host, "windows")
        if not isinstance(user, str) or not user.strip() or len(user) > 200 or any(ord(c) < 32 for c in user):
            raise RemoteError("Informe a conta administrativa do Windows.")
        if not isinstance(password, str) or not password or len(password) > 1024:
            raise RemoteError("Informe a senha da conta do Windows; ela será mantida somente nesta sessão.")
        if port != 5986:
            raise RemoteError("A administração Windows usa somente WinRM HTTPS na porta 5986.")
        ca_file = _path(ca_file, "CA") if ca_file else None
        try:
            from winrm.protocol import Protocol
            from winrm.exceptions import WinRMOperationTimeoutError
        except ImportError:
            raise RemoteError("Suporte Windows indisponível. Instale a dependência opcional pywinrm>=0.5,<0.6 no painel.") from None
        host_url = "[" + self.host + "]" if ":" in self.host else self.host
        self._timeout_error = WinRMOperationTimeoutError
        self._protocol = Protocol(endpoint=f"https://{host_url}:5986/wsman", transport="ntlm", username=user,
                                  password=password, server_cert_validation="validate", ca_trust_path=ca_file,
                                  operation_timeout_sec=5, read_timeout_sec=10, proxy=None, message_encryption="always")

    def _ps(self, script):
        self._check()
        protocol = self._protocol
        shell_id = command_id = None
        output = bytearray()
        total = 0
        deadline = time.monotonic() + 45
        try:
            shell_id = protocol.open_shell()
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            command_id = protocol.run_command(shell_id, "powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], skip_cmd_shell=True)
            done = False
            while not done:
                if time.monotonic() >= deadline:
                    raise RemoteError("O Windows não concluiu a operação a tempo. Atualize o inventário antes de repetir uma alteração.")
                try:
                    stdout, stderr, code, done = protocol.get_command_output_raw(shell_id, command_id)
                except self._timeout_error:
                    continue
                total += len(stdout) + len(stderr)
                if total > MAX_OUTPUT:
                    raise RemoteError("A resposta do Windows excedeu o limite permitido.")
                output.extend(stdout)
            if code != 0:
                raise RemoteError("O Windows recusou a operação. Confira os privilégios, a sessão interativa e o estado do pacote.")
            return _decode(bytes(output))
        except RemoteError:
            raise
        except Exception as error:
            raise WinRMConnectionError(_winrm_failure(error)) from None
        finally:
            if command_id:
                try:
                    protocol.cleanup_command(shell_id, command_id)
                except Exception:
                    pass
            if shell_id:
                try:
                    protocol.close_shell(shell_id)
                except Exception:
                    pass

    def _inventory(self):
        return self._ps(_windows_inventory_script())

    def _games(self, raw):
        result = []
        for row in _records(raw, "appx", 100):
            name = _clean_text(row.get("Name", ""), 100)
            package = _clean_text(row.get("PackageFullName", ""), 240)
            if name.casefold() in {n.casefold() for n in ROBLOX_APPX}:
                publisher = row.get("Publisher")
                family = row.get("PackageFamilyName")
                match = re.fullmatch(re.escape(name) + r"_\d+\.\d+\.\d+\.\d+_(?:x64|x86|arm64|arm|neutral)_[A-Za-z0-9.]*_" + ROBLOX_PUBLISHER_ID, package, re.I)
                trusted = bool(match and publisher == ROBLOX_PUBLISHER and
                               row.get("PublisherId") == ROBLOX_PUBLISHER_ID and
                               isinstance(family, str) and family.casefold() == (name + "_" + ROBLOX_PUBLISHER_ID).casefold() and
                               row.get("SignatureKind") in ("Store", 3))
                result.append(_game("roblox", "Roblox (Microsoft Store)", "appx:" + package, "appx", trusted,
                                    "Pacote Store com identidade permitida. O Windows poderá redefinir dados locais do app." if trusted else "Identidade ou assinatura Store não corresponde ao catálogo; remoção manual.",
                                    package=package, package_name=name, publisher=publisher if isinstance(publisher, str) else "", family=family if isinstance(family, str) else ""))
            elif name == "Microsoft.MinecraftUWP":
                result.append(_game("minecraft", "Minecraft for Windows", "appx:" + package, "appx", reason="Remoção manual com backup dos mundos; dados locais podem ser perdidos na desinstalação do Windows."))
        for row in _records(raw, "desktop", 200):
            name = _clean_text(row.get("DisplayName", ""), 200)
            for game_id, label, pattern in DISPLAY_CATALOGUE:
                if re.fullmatch(pattern, name, re.I):
                    install_id = "desktop:" + game_id
                    if not any(g["install_id"] == install_id for g in result):
                        result.append(_game(game_id, label + " (desktop)", install_id, "desktop", reason="Instalador fora do catálogo de remoção segura. Desinstale pelas Configurações do Windows."))
                    break
        return result

    def _remove(self, game):
        package = game["identity"]["package"]
        # package já passou por regex estrita e a identidade é conferida no alvo.
        script = r"""
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$p=@(Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -ceq '__PACKAGE__'})
if($p.Count -ne 1){throw 'Package changed'}
if($p[0].Name -notin @('ROBLOXCORPORATION.ROBLOX','ROBLOXCorporation.RobloxGDK') -or $p[0].Publisher -cne 'CN=6FEF9772-62F8-4C8B-8DE0-70F628846515' -or $p[0].PublisherId -cne '55nm5eh3cm0pr' -or $p[0].SignatureKind -ne 'Store'){throw 'Identity rejected'}
Remove-AppxPackage -Package $p[0].PackageFullName -AllUsers -Confirm:$false -ErrorAction Stop
@{ok=$true} | ConvertTo-Json -Compress
""".replace("__PACKAGE__", package)
        if self._ps(script).get("ok") is not True:
            raise RemoteError("O Windows não confirmou a remoção do pacote.")

    def _notify(self, message):
        # Texto fixo + domínio validado; sem aspas, operadores ou caminho fornecido.
        script = r"""
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$sessions=@(Get-CimInstance Win32_LogonSession | Where-Object {$_.LogonType -in @(2,10)})
if($sessions.Count -eq 0){@{sent=$false}|ConvertTo-Json -Compress;exit}
& "$env:SystemRoot\System32\msg.exe" '*' '/time:45' '__MESSAGE__' 2>$null | Out-Null
@{sent=($LASTEXITCODE -eq 0)} | ConvertTo-Json -Compress
""".replace("__MESSAGE__", message)
        return self._ps(script).get("sent") is True, "windows-message"

    def _warnings(self):
        return ["WinRM HTTPS deve estar previamente habilitado e autorizado. Instalações por usuário podem não aparecer.",
                "Avisos usam msg.exe e dependem de sessão interativa e permissão de mensagens; não há confirmação de leitura."]

    def _data_notice(self, game):
        return "O Windows removerá este app Store de todas as contas e poderá redefinir seus dados locais. Não remove Roblox Studio nem apaga pastas pessoais por comandos próprios."

    def close(self):
        protocol = getattr(self, "_protocol", None)
        self._protocol = None
        if protocol is not None:
            transport = getattr(protocol, "transport", None)
            if transport is not None:
                session = getattr(transport, "session", None)
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass
                    session.auth = None
                for name in ("password", "username", "session", "encryption"):
                    if hasattr(transport, name):
                        setattr(transport, name, None)
        super().close()


LINUX_COMMON = r'''
import json, os, subprocess
def command(args, limit=65536):
    try:
        p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        import threading
        timer=threading.Timer(12,p.kill);timer.start()
        try:
            data=p.stdout.read(limit+1)
            if len(data)>limit:p.kill();raise RuntimeError('output limit')
            code=p.wait(timeout=2)
        finally:
            timer.cancel();p.stdout.close()
        return code,data.decode('utf-8','replace')
    except (OSError,subprocess.TimeoutExpired):
        return 127,''
'''


class LinuxSession(_Session):
    def __init__(self, host, user, *, key_path="", known_hosts="", port=22):
        super().__init__(host, "linux")
        if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise RemoteError("Usuário SSH inválido.")
        if type(port) is not int or not 1 <= port <= 65535:
            raise RemoteError("Porta SSH inválida.")
        self._user = user
        self._port = port
        self._key_path = _path(key_path, "chave SSH") if key_path else ""
        self._known_hosts = _path(known_hosts, "known_hosts") if known_hosts else ""
        self._ssh = shutil.which("ssh")
        if not self._ssh:
            raise RemoteError("Instale o cliente OpenSSH no computador do administrador.")

    def _python(self, script, *, timeout=45):
        self._check()
        command = ssh_command_base(self._ssh, self._port, key_path=self._key_path, known_hosts=self._known_hosts)
        command += [f"{self._user}@{self.host}", "/usr/bin/python3", "-I", "-"]
        try:
            result = run_bounded(command, input=script, timeout=timeout, max_output_bytes=MAX_OUTPUT)
        except subprocess.TimeoutExpired:
            raise RemoteError("O Linux não concluiu a operação a tempo. Confira o estado do pacote antes de repetir uma alteração.") from None
        except (OSError, OutputLimitExceeded):
            raise RemoteError("Não foi possível concluir a operação SSH; confira conectividade e os limites de resposta.") from None
        if result.returncode:
            raise RemoteError("O Linux recusou a operação. Confira chave, known_hosts, Python 3 e permissões sudo autorizadas.")
        return _decode(result.stdout)

    def _inventory(self):
        script = LINUX_COMMON + "\nallowed=" + repr(tuple(PROCESS_CATALOGUE)) + r'''
processes=[];partial=False
try:
    with os.scandir('/proc') as entries:
        for index,entry in enumerate(entries):
            if index>=20000:partial=True;break
            if not entry.name.isdecimal():continue
            try:
                with open('/proc/'+entry.name+'/comm') as f:name=f.read(128).strip()
                if name.lower() in allowed and len(processes)<200:processes.append({'name':name,'pid':int(entry.name)})
            except (OSError,ValueError):pass
except OSError:partial=True
dpkg=[]
for package in ('minecraft-launcher','steam','steam-installer'):
    code,data=command(['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}\\t${Version}',package])
    if code==0:
        parts=data.split('\t',1)
        if len(parts)==2 and parts[0]=='installed':dpkg.append({'package':package,'version':parts[1].strip()})
flatpak=[]
code,data=command(['/usr/bin/flatpak','list','--system','--app','--columns=application,branch,arch,version,active:f'])
if code==0:
    for line in data.splitlines()[:200]:
        parts=line.split('\t')
        if len(parts)>=5:flatpak.append({'package':parts[0],'branch':parts[1],'arch':parts[2],'version':parts[3],'commit':parts[4]})
print(json.dumps({'processes':processes,'dpkg':dpkg,'flatpak':flatpak,'partial':partial}))
'''
        return self._python(script)

    def _games(self, raw):
        games = []
        for row in _records(raw, "dpkg", 20):
            package = row.get("package")
            if not isinstance(package, str) or package not in DPKG_GAMES:
                continue
            version = _clean_text(row.get("version", ""), 150)
            game_id, name = DPKG_GAMES[package]
            games.append(_game(game_id, name + " (Debian)", "dpkg:" + package, "dpkg", True,
                               "Remove o pacote do sistema por dpkg, sem --purge. Jogos e dados na pasta pessoal permanecem.",
                               package=package, version=version))
        for row in _records(raw, "flatpak", 200):
            package = row.get("package")
            if not isinstance(package, str) or package not in FLATPAK_GAMES:
                continue
            branch = _clean_text(row.get("branch", ""), 60)
            arch = _clean_text(row.get("arch", ""), 30)
            version = _clean_text(row.get("version", ""), 150)
            commit = _clean_text(row.get("commit", ""), 64)
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", branch) or arch not in {"x86_64", "aarch64", "arm", "i386"} or not re.fullmatch(r"[0-9a-f]{64}", commit):
                raise RemoteError("Identidade Flatpak inválida.")
            game_id, name = FLATPAK_GAMES[package]
            games.append(_game(game_id, name, "flatpak:" + package + "/" + arch + "/" + branch, "flatpak", True,
                               "Remove somente a instalação Flatpak do sistema, sem --delete-data.",
                               package=package, branch=branch, arch=arch, version=version, commit=commit))
        return games

    def _remove(self, game):
        identity = game["identity"]
        script = LINUX_COMMON + "\nidentity=" + repr(identity) + "\nmethod=" + repr(game["method"]) + r'''
if method=='dpkg':
    if identity['package'] not in ('minecraft-launcher','steam','steam-installer'):raise RuntimeError('catalogue')
    code,data=command(['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}\\t${Version}',identity['package']])
    if code!=0 or data.strip()!='installed\t'+identity['version']:raise RuntimeError('package changed')
    args=['/usr/bin/sudo','-n','/usr/bin/dpkg','--remove','--',identity['package']]
elif method=='flatpak':
    if identity['package'] not in ('com.valvesoftware.Steam','com.mojang.Minecraft'):raise RuntimeError('catalogue')
    ref='app/'+identity['package']+'/'+identity['arch']+'/'+identity['branch']
    code,data=command(['/usr/bin/flatpak','info','--system','--show-commit',ref])
    if code!=0 or data.strip()!=identity['commit']:raise RuntimeError('package changed')
    args=['/usr/bin/sudo','-n','/usr/bin/flatpak','uninstall','--system','--noninteractive','--assumeyes',ref]
else:raise RuntimeError('method')
# Sem shell, purge, delete-data, remoção de dependências ou pastas pessoais.
code=subprocess.call(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
print(json.dumps({'ok':code==0}))
'''
        if self._python(script, timeout=90).get("ok") is not True:
            raise RemoteError("O Linux não confirmou a remoção. Confira dependências e a autorização sudo do pacote selecionado.")

    def _notify(self, message):
        # wall usa terminais; não é apresentado como popup gráfico garantido.
        script = LINUX_COMMON + "\nmessage=" + repr(message) + r'''
code,data=command(['/usr/bin/who'])
sent=False
if code==0 and data.strip():
    try:
        p=subprocess.run(['/usr/bin/wall','--nobanner'],input=message+'\n',text=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        sent=p.returncode==0
    except (OSError,subprocess.TimeoutExpired):pass
print(json.dumps({'sent':sent}))
'''
        return self._python(script).get("sent") is True, "linux-terminal"

    def _warnings(self):
        return ["Exige SSH por chave e Python 3 já disponíveis. Somente pacotes Debian e Flatpak do sistema do catálogo são removíveis.",
                "Linux: avisos usam wall em terminais conectados; popup no ambiente gráfico não é garantido.",
                "Remover Steam/launcher não remove jogos previamente baixados em pastas pessoais. Instalações de outros usuários podem não aparecer."]

    def close(self):
        self._user = self._key_path = self._known_hosts = self._ssh = ""
        super().close()


def create_session(platform, host, user, password="", *, key_path="", known_hosts="", ca_file="", port=None):
    """Conecta a um alvo explícito; não descobre máquinas nem habilita serviços."""
    if platform == "windows":
        return WindowsSession(host, user, password, ca_file=ca_file, port=5986 if port is None else port)
    if platform == "linux":
        return LinuxSession(host, user, key_path=key_path, known_hosts=known_hosts, port=22 if port is None else port)
    raise RemoteError("Selecione Windows (WinRM HTTPS) ou Linux (SSH).")
