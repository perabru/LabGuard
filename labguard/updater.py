"""Atualização do desktop por uma release pública e fixa do próprio projeto.

Verificar e preparar nunca executam o pacote. A aplicação automática está
limitada ao instalador Windows por usuário e ao encerramento voluntário.
TLS e hashes conferem origem/transporte e integridade; não são uma assinatura.
"""
from __future__ import annotations

import copy
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

APP_ID = "br.perabru.labguard.desktop"
REPOSITORY = "perabru/LabGuard"
API_URL = "https://api.github.com/repos/" + REPOSITORY + "/releases/latest"
RELEASE_ROOT = "https://github.com/" + REPOSITORY + "/releases/download/"
VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
HOSTS = {"api.github.com", "github.com", "release-assets.githubusercontent.com",
         "objects.githubusercontent.com", "github-releases.githubusercontent.com"}
ASSETS = {"windows-x86_64": "LabGuard-Setup.exe", "linux-x86_64": "LabGuard-Linux-x86_64.tar.gz"}
MAX_ASSET = 150 * 1024 * 1024
MAX_RELEASE = 2 * 1024 * 1024
MAX_MANIFEST = 65536
MAX_CHECKSUMS = 256 * 1024
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{84474208-6606-4F7A-A421-EDC4FF33948C}_is1"


class UpdateError(RuntimeError):
    """Mensagens públicas fixas: nunca incluem URL assinada ou saída de processo."""


def _public_errors(method):
    @wraps(method)
    def guarded(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except UpdateError:
            raise
        except (OSError, ValueError, TypeError, RecursionError):
            raise UpdateError("Não foi possível preparar a atualização. A versão atual permanece disponível.") from None
    return guarded


def version_tuple(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise UpdateError("A versão da atualização não é compatível.")
    result = tuple(map(int, value.split(".")))
    if any(part > 65535 for part in result):
        raise UpdateError("A versão da atualização não é compatível.")
    return result


def allowed_url(value):
    if not isinstance(value, str) or len(value) > 8192:
        return False
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and parsed.hostname in HOSTS and parsed.port in (None, 443)
                and not parsed.username and not parsed.password and not parsed.fragment
                and not any(ord(c) < 32 for c in value))
    except ValueError:
        return False


class _SafeRedirect(HTTPRedirectHandler):
    def __init__(self, initial_url):
        self.count = 0
        self.initial_url = initial_url

    def redirect_request(self, request, fp, code, message, headers, newurl):
        self.count += 1
        parsed = urlsplit(newurl)
        if (self.initial_url == API_URL or self.count > 5 or not allowed_url(newurl)
                or parsed.hostname == "api.github.com"
                or parsed.hostname == "github.com" and parsed.path != urlsplit(self.initial_url).path):
            raise UpdateError("O endereço da atualização foi recusado.")
        return super().redirect_request(request, fp, code, message, headers, newurl)


def _reparse(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _fixed_drive(path):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel.GetDriveTypeW.restype = wintypes.UINT
    return kernel.GetDriveTypeW(Path(path).anchor) == 3


def _safe_path(path):
    path = Path(path).absolute()
    if any(ord(c) < 32 or c == '"' for c in str(path)):
        raise UpdateError("O caminho de atualização não é seguro.")
    if os.name == "nt" and (str(path).startswith("\\\\") or not _fixed_drive(path)):
        raise UpdateError("A atualização automática exige um caminho local.")
    for item in (path, *path.parents):
        try:
            if _reparse(item):
                raise UpdateError("Links ou pontos de redirecionamento não são aceitos na atualização.")
        except FileNotFoundError:
            continue
    return path


def _inside(path, directory):
    try:
        Path(path).resolve().relative_to(Path(directory).resolve())
        return True
    except (ValueError, OSError):
        return False


def _per_user(path):
    roots = [Path.home()]
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        roots.append(Path(os.environ["LOCALAPPDATA"]))
    return any(_inside(path, root) for root in roots)


def _windows_private_acl(path):
    """DACL protegida: usuário atual, SYSTEM e administradores; sem herança."""
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = wintypes.HANDLE()
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    sid_text, descriptor = wintypes.LPWSTR(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise OSError()
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 65536:
            raise OSError()
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise OSError()
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError()
        inheritance = "OICI" if Path(path).is_dir() else ""
        sddl = "D:P(A;" + inheritance + ";FA;;;" + sid_text.value + ")(A;" + inheritance + ";FA;;;SY)(A;" + inheritance + ";FA;;;BA)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise OSError()
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise OSError()
    finally:
        if token:
            kernel.CloseHandle(token)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if descriptor:
            kernel.LocalFree(descriptor)


def _secure_directory(path):
    path = _safe_path(path)
    if os.name == "nt" and not _per_user(path):
        raise UpdateError("A pasta de atualização deve pertencer ao usuário atual.")
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700)
        if os.name == "nt":
            _windows_private_acl(item)
    path = _safe_path(path)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise UpdateError("A pasta de atualização não é válida.")
    if os.name == "nt":
        _windows_private_acl(path)
    elif info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise UpdateError("A pasta de atualização precisa ser privada (0700).")
    return path


def _atomic_bytes(path, content):
    path = _safe_path(path)
    parent = _secure_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix="update-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            _windows_private_acl(Path(temporary))
        os.replace(temporary, path)
    finally:
        try:Path(temporary).unlink()
        except FileNotFoundError:pass


def _installed_windows(executable):
    if platform.system() != "Windows" or executable.name.casefold() != "labguard.exe" or not _per_user(executable):
        return False
    try:
        import winreg
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY, 0, winreg.KEY_READ | view) as key:
                    location = winreg.QueryValueEx(key, "InstallLocation")[0]
                if isinstance(location, str) and os.path.normcase(str(_safe_path(location).resolve())) == os.path.normcase(str(executable.parent.resolve())):
                    return True
            except OSError:
                continue
    except (ImportError, OSError, UpdateError, ValueError):
        pass
    return False


def _system_powershell():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    count = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < count < len(buffer):
        raise UpdateError("O diretório de componentes do Windows não foi confirmado.")
    return _safe_path(Path(buffer.value)/"WindowsPowerShell"/"v1.0"/"powershell.exe")


def _process_executable(pid):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise UpdateError("O processo que precisa encerrar não pôde ser confirmado.")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise UpdateError("O processo que precisa encerrar não pôde ser confirmado.")
        return Path(buffer.value).resolve()
    finally:
        kernel.CloseHandle(handle)


def _checksums(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise UpdateError("A verificação da atualização não pôde ser lida.") from None
    output = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]([A-Za-z0-9_.-]{1,100})", line)
        if not match or match[2] in output:
            raise UpdateError("O arquivo de verificação da atualização é inválido.")
        output[match[2]] = match[1].lower()
    return output


class UpdateManager:
    def __init__(self, current_version, data_dir=None, executable=None, frozen=None):
        self.current_version = current_version
        self._current = version_tuple(current_version)
        self.executable = Path(executable or sys.executable).absolute()
        self.frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen is True
        self._default_data_dir = data_dir is None
        self.data_dir = Path(data_dir) if data_dir is not None else Path.home()/".labguard"/"updates"
        self._closed = threading.Event()
        self._lock = threading.Lock()
        self._candidates = {}
        self._prepared = {}
        self._apply_state = "idle"

    def close(self):
        # Download/hash work never holds this lock; no wait for the worker.
        with self._lock:
            self._closed.set()

    def installation_status(self):
        key = None
        if platform.machine().casefold() in {"amd64", "x86_64"} and sys.maxsize > 2**32:
            key = {"Windows": "windows-x86_64", "Linux": "linux-x86_64"}.get(platform.system())
        if not self.frozen:
            return {"state": "source", "platform": key, "supported": False, "auto_apply": False,
                    "message": "Código-fonte: atualizações são feitas pelo repositório; nenhum pacote será executado."}
        if key is None:
            return {"state": "unsupported", "platform": None, "supported": False, "auto_apply": False,
                    "message": "Atualização automática indisponível nesta plataforma."}
        installed = key == "windows-x86_64" and _installed_windows(self.executable)
        return {"state": "installed" if installed else "manual", "platform": key, "supported": True,
                "auto_apply": bool(installed), "message": "Atualizações são preparadas em segundo plano e aplicadas ao encerrar." if installed else
                "Esta edição pode consultar versões; a instalação depende do pacote e das permissões do sistema."}

    def _open(self):
        if self._closed.is_set():
            raise UpdateError("A verificação de atualização foi encerrada.")

    def _download(self, url, maximum, deadline, target=None):
        self._open()
        if not allowed_url(url):
            raise UpdateError("A origem da atualização não é permitida.")
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = True, ssl.CERT_REQUIRED
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _SafeRedirect(url))
        request = Request(url, headers={"User-Agent": "LabGuard/" + self.current_version, "Accept": "application/octet-stream"})
        output, total, digest = [], 0, hashlib.sha256()
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:raise UpdateError("A consulta de atualização excedeu o prazo.")
            with opener.open(request, timeout=min(10, remaining)) as response:
                if (getattr(response, "status", 200) != 200 or not allowed_url(response.geturl())
                        or url == API_URL and response.geturl() != API_URL):
                    raise UpdateError("A resposta da atualização não foi confirmada.")
                length = response.headers.get("Content-Length")
                if length and (not length.isdigit() or int(length) > maximum):
                    raise UpdateError("O pacote de atualização excede o limite permitido.")
                reader = getattr(response, "read1", None)
                if not callable(reader):raise UpdateError("A resposta não permite uma leitura limitada.")
                try:sock = response.fp.raw._sock
                except AttributeError:sock = None
                while True:
                    self._open()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:raise UpdateError("A consulta de atualização excedeu o prazo.")
                    if sock is not None:sock.settimeout(min(10, remaining))
                    chunk = reader(min(65536, maximum + 1 - total))
                    if time.monotonic() >= deadline:raise UpdateError("A consulta de atualização excedeu o prazo.")
                    if not chunk:break
                    total += len(chunk)
                    if total > maximum:raise UpdateError("O pacote de atualização excede o limite permitido.")
                    digest.update(chunk)
                    if target is None:output.append(chunk)
                    else:target.write(chunk)
            return (b"".join(output) if target is None else None), total, digest.hexdigest()
        except UpdateError:
            raise
        except Exception:
            raise UpdateError("Não foi possível verificar a atualização. A versão atual continua disponível.") from None

    @_public_errors
    def check_update(self):
        self._open()
        status = self.installation_status()
        if not status["supported"]:
            return dict(status)
        deadline = time.monotonic() + 35
        raw, _, _ = self._download(API_URL, MAX_RELEASE, deadline)
        try:release = json.loads(raw)
        except (ValueError, TypeError, RecursionError):raise UpdateError("Os dados da versão publicada são inválidos.") from None
        if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
            raise UpdateError("A versão publicada não é uma atualização estável.")
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not tag.startswith("v"):
            raise UpdateError("A versão publicada não é compatível.")
        version = tag[1:]
        if version_tuple(version) <= self._current:
            return dict(status, state="current", version=self.current_version, message="Você está usando a versão disponível do LabGuard.")
        assets = release.get("assets")
        if not isinstance(assets, list) or len(assets) > 100:
            raise UpdateError("A lista de arquivos da atualização é inválida.")
        by_name = {}
        root = RELEASE_ROOT + tag + "/"
        for item in assets:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):continue
            name = item["name"]
            if name in by_name:raise UpdateError("A release possui arquivos duplicados.")
            by_name[name] = item
        required = ("labguard-update.json", "SHA256SUMS.txt", ASSETS[status["platform"]])
        for name in required:
            item = by_name.get(name, {})
            if item.get("browser_download_url") != root + name or type(item.get("size")) is not int or item["size"] <= 0:
                raise UpdateError("Os arquivos da atualização não correspondem à release oficial.")
        manifest_bytes, manifest_size, manifest_sha = self._download(root+required[0], MAX_MANIFEST, deadline)
        sums_bytes, sums_size, _ = self._download(root+required[1], MAX_CHECKSUMS, deadline)
        if manifest_size != by_name[required[0]]["size"] or sums_size != by_name[required[1]]["size"]:
            raise UpdateError("O tamanho dos dados de atualização não foi confirmado.")
        sums = _checksums(sums_bytes)
        if sums.get(required[0]) != manifest_sha:
            raise UpdateError("A integridade do manifesto não foi confirmada.")
        try:manifest = json.loads(manifest_bytes)
        except (ValueError, TypeError, RecursionError):raise UpdateError("O manifesto de atualização é inválido.") from None
        if (not isinstance(manifest, dict) or manifest.get("app_id") != APP_ID or manifest.get("channel") != "stable" or type(manifest.get("schema")) is not int
                or manifest["schema"] != 1 or manifest.get("version") != version or not isinstance(manifest.get("artifacts"), dict)):
            raise UpdateError("O manifesto não pertence a esta aplicação e versão.")
        artifact = manifest["artifacts"].get(status["platform"])
        if (not isinstance(artifact, dict) or artifact.get("name") != required[2] or not isinstance(artifact.get("sha256"), str)
                or not SHA_RE.fullmatch(artifact["sha256"]) or type(artifact.get("size")) is not int
                or not 0 < artifact["size"] <= MAX_ASSET or artifact["size"] != by_name[required[2]]["size"]
                or sums.get(required[2]) != artifact["sha256"]):
            raise UpdateError("A integridade do pacote não foi confirmada.")
        identifier = uuid4().hex
        candidate = dict(artifact, version=version, platform=status["platform"], url=root+required[2])
        with self._lock:
            self._candidates[identifier] = candidate
        return dict(status, state="available", candidate_id=identifier, version=version,
                    message="Atualização disponível. O pacote será conferido antes de ser preparado.")

    def _validate_package(self, path, candidate):
        _safe_path(path)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != candidate["size"]:
            raise UpdateError("O tamanho do pacote preparado não confere.")
        if os.name == "nt":
            _windows_private_acl(path)
        elif info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise UpdateError("O pacote preparado precisa permanecer privado.")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024*1024)
                if not chunk:break
                digest.update(chunk)
        if digest.hexdigest() != candidate["sha256"]:
            raise UpdateError("O pacote preparado não passou na verificação de integridade.")
        if candidate["platform"] == "windows-x86_64":
            with path.open("rb") as stream:
                header = stream.read(64)
                if len(header) < 64 or header[:2] != b"MZ":raise UpdateError("O instalador preparado não é válido.")
                offset = struct.unpack_from("<I", header, 0x3c)[0]
                if not 64 <= offset < info.st_size-4:raise UpdateError("O instalador preparado não é válido.")
                stream.seek(offset)
                if stream.read(4) != b"PE\0\0":raise UpdateError("O instalador preparado não é válido.")
        else:
            try:
                with tarfile.open(path, "r:gz") as archive:
                    total, count, entry = 0, 0, False
                    for member in archive:
                        count += 1;total += member.size
                        parts = Path(member.name).parts
                        if (count > 20000 or total > 600*1024*1024 or not parts or parts[0] != "LabGuard"
                                or any(part in {"..", "."} for part in parts) or member.name.startswith(("/", "\\"))
                                or "\\" in member.name or not (member.isfile() or member.isdir())):
                            raise UpdateError("O pacote Linux contém caminhos ou tipos não permitidos.")
                        entry |= member.name == "LabGuard/LabGuard" and member.isfile()
                    if not entry:raise UpdateError("O pacote Linux não contém o aplicativo esperado.")
            except (tarfile.TarError, OSError):
                raise UpdateError("O pacote Linux não pôde ser validado.") from None

    @_public_errors
    def stage_update(self, candidate):
        self._open()
        identifier = candidate.get("candidate_id") if isinstance(candidate, dict) else None
        with self._lock:
            value = copy.deepcopy(self._candidates.get(identifier)) if isinstance(identifier, str) else None
        if value is None:raise UpdateError("A atualização precisa ser verificada novamente.")
        if self._default_data_dir:
            _secure_directory(self.data_dir.parent)
        base = _secure_directory(self.data_dir)
        directory = _secure_directory(base/value["version"])
        filename = "installer.exe" if value["platform"] == "windows-x86_64" else "package.tar.gz"
        path = _safe_path(directory/filename)
        reuse = False
        if path.exists():
            try:self._validate_package(path, value);reuse=True
            except UpdateError:pass
        if not reuse:
            fd, temporary = tempfile.mkstemp(prefix="download-", suffix=".tmp", dir=directory)
            try:
                with os.fdopen(fd, "wb") as stream:
                    _, size, digest = self._download(value["url"], value["size"], time.monotonic()+180, stream)
                    stream.flush();os.fsync(stream.fileno())
                if size != value["size"] or digest != value["sha256"]:
                    raise UpdateError("O pacote recebido não passou na verificação de integridade.")
                if os.name == "nt":_windows_private_acl(Path(temporary))
                self._validate_package(Path(temporary), value)
                self._open()
                os.replace(temporary, path)
            finally:
                try:Path(temporary).unlink()
                except FileNotFoundError:pass
        self._validate_package(path, value)
        token = uuid4().hex
        with self._lock:
            self._prepared[token] = dict(value, path=str(path))
        can_apply = self.installation_status()["auto_apply"] is True and value["platform"] == "windows-x86_64"
        return {"state": "prepared", "prepared_id": token, "version": value["version"], "platform": value["platform"],
                "auto_apply": can_apply, "can_apply": can_apply,
                "message": "Atualização pronta; será aplicada quando você encerrar o programa." if can_apply else
                "Pacote conferido. A instalação desta edição requer o procedimento do sistema ou da TI."}

    @_public_errors
    def schedule_apply(self, prepared, parent_pid=None, *, consent=False):
        with self._lock:
            if self._apply_state != "idle" or self._closed.is_set() or consent is not True:
                return False
            self._apply_state = "reserved"
        try:
            scheduled = self._schedule_apply(prepared, parent_pid, consent=consent)
        except Exception:
            with self._lock:
                self._apply_state = "idle"
            raise
        with self._lock:
            self._apply_state = "scheduled" if scheduled else "idle"
        return scheduled

    def _schedule_apply(self, prepared, parent_pid=None, *, consent=False):
        if consent is not True or self._closed.is_set() or self.installation_status()["auto_apply"] is not True:
            return False
        token = prepared.get("prepared_id") if isinstance(prepared, dict) else None
        with self._lock:
            value = copy.deepcopy(self._prepared.get(token)) if isinstance(token, str) else None
        if value is None or value["platform"] != "windows-x86_64":return False
        path = _safe_path(value["path"])
        self._validate_package(path, value)
        executable = _safe_path(self.executable).resolve()
        if not executable.is_file() or not _installed_windows(executable):return False
        pid = os.getpid() if parent_pid is None else parent_pid
        if type(pid) is not int or pid != os.getpid() or not 0 < pid <= 2**31-1:
            raise UpdateError("O processo da atualização não foi confirmado.")
        if os.path.normcase(str(_process_executable(pid))) != os.path.normcase(str(executable.resolve())):
            raise UpdateError("O processo em execução não corresponde ao aplicativo instalado.")
        helper_source = Path(__file__).parent/"update_helpers"/"apply_windows.ps1"
        helper_content = helper_source.read_bytes()
        if not 100 < len(helper_content) <= 65536:
            raise UpdateError("O auxiliar de atualização não está disponível.")
        directory = _secure_directory(path.parent)
        helper, metadata = directory/"apply_windows.ps1", directory/"apply.json"
        _atomic_bytes(helper, helper_content)
        payload = {"schema": 1, "app_id": APP_ID, "consent": True, "version": value["version"], "sha256": value["sha256"],
                   "size": value["size"], "installer": str(path), "install_dir": str(executable.parent),
                   "parent_pid": pid, "parent_executable": str(executable),
                   "helper_sha256": hashlib.sha256(helper_content).hexdigest()}
        _atomic_bytes(metadata, json.dumps(payload, ensure_ascii=True).encode("ascii"))
        # Resolve only the Windows component, never a path from release data.
        powershell = _system_powershell()
        if not powershell.is_file():raise UpdateError("O auxiliar nativo do Windows não foi encontrado.")
        self._validate_package(path, value)
        if hashlib.sha256(helper.read_bytes()).hexdigest() != payload["helper_sha256"]:
            raise UpdateError("O auxiliar de atualização foi alterado.")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
        try:
            with self._lock:
                if self._closed.is_set():
                    return False
                subprocess.Popen([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                  "-File", str(helper), "-MetadataPath", str(metadata)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags)
        except OSError:
            raise UpdateError("Não foi possível agendar a atualização. A versão atual permanece instalada.") from None
        return True

    def application_result(self, prepared):
        token = prepared.get("prepared_id") if isinstance(prepared, dict) else None
        with self._lock:
            value = copy.deepcopy(self._prepared.get(token)) if isinstance(token, str) else None
        if value is None:
            raise UpdateError("A atualização preparada não foi reconhecida.")
        result = {"state": "pending", "version": value["version"], "code": ""}
        try:
            path = _safe_path(Path(value["path"]).parent/"result.json")
            if not path.exists():return result
            if path.stat().st_size > 4096 or path.stat().st_nlink != 1:return result
            receipt = json.loads(path.read_text(encoding="utf-8-sig"))
            if (isinstance(receipt, dict) and receipt.get("app_id") == APP_ID and receipt.get("version") == value["version"]
                    and receipt.get("state") in {"applied", "pending", "failed", "restart_required"}
                    and isinstance(receipt.get("code"), str) and re.fullmatch(r"[A-Z_]{0,60}", receipt["code"])):
                result.update(state=receipt["state"], code=receipt["code"])
        except (OSError, ValueError, UpdateError, RecursionError):
            pass
        return result
