"""Preferências locais sem credenciais ou autorização persistente de escrita."""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading

from .demo import normalize_mac

MAX_SETTINGS_BYTES = 32768
ROUTER_FIELDS = frozenset({"host", "port", "user", "ca_file", "lab_cidr",
                          "wan_interface_list", "protected_ips", "protected_macs"})
_PREF_FIELDS = frozenset({"schema", "auto_updates", "auto_connect", "saved_router", "local_dns"})
_INVALID = "Preferências locais inválidas; confira as opções do aplicativo."
_PRIVATE = "Não foi possível acessar as preferências com proteção local."


class PreferenceError(RuntimeError):
    pass


def default_preferences():
    return {"schema": 1, "auto_updates": True, "auto_connect": False, "saved_router": None}


def _text(value, maximum, *, allow_empty=True):
    if (not isinstance(value, str) or len(value) > maximum or
            any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value) or
            not allow_empty and not value.strip()):
        raise PreferenceError(_INVALID)
    return value


def normalize_router_profile(profile):
    """Valida somente os campos públicos da conexão RouterOS, sem alterá-la."""
    if not isinstance(profile, dict) or set(profile) - ROUTER_FIELDS:
        raise PreferenceError(_INVALID)
    try:
        host = _text(profile.get("host"), 128, allow_empty=False)
        if "%" in host:
            raise ValueError()
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError()
        port = profile.get("port", 443)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError()
        user = _text(profile.get("user"), 128, allow_empty=False)
        if ":" in user:
            raise ValueError()
        ca_file = _text(profile.get("ca_file", ""), 4096)
        lab_cidr = _text(profile.get("lab_cidr", ""), 64)
        if lab_cidr:
            network = ipaddress.IPv4Network(lab_cidr, strict=True)
            private = (ipaddress.IPv4Network(part) for part in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
            if not 16 <= network.prefixlen <= 30 or not any(network.subnet_of(part) for part in private):
                raise ValueError()
            lab_cidr = str(network)
        wan = _text(profile.get("wan_interface_list", "WAN"), 64, allow_empty=False)
        if not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", wan):
            raise ValueError()
        protected_ips, protected_macs = [], []
        for field in ("protected_ips", "protected_macs"):
            values = profile.get(field, [])
            if not isinstance(values, list) or len(values) > 256:
                raise ValueError()
            for value in values:
                if field == "protected_ips":
                    if not isinstance(value, str):
                        raise ValueError()
                    clean = str(ipaddress.IPv4Address(value))
                    if clean not in protected_ips:
                        protected_ips.append(clean)
                else:
                    clean = normalize_mac(value)
                    if clean not in protected_macs:
                        protected_macs.append(clean)
    except (ValueError, TypeError, KeyError):
        raise PreferenceError(_INVALID) from None
    return {"host": str(address), "port": port, "user": user, "ca_file": ca_file,
            "lab_cidr": lab_cidr, "wan_interface_list": wan,
            "protected_ips": protected_ips, "protected_macs": protected_macs}


def normalize_dns_profile(value):
    if not isinstance(value, dict) or set(value)-{'host','lab_cidr','upstream','start_on_open','custom_upstream'}:
        raise PreferenceError(_INVALID)
    if type(value.get('start_on_open', False)) is not bool:raise PreferenceError(_INVALID)
    from .local_dns import validate_config, DNSError
    try:
        host, net, upstream, _, _ = validate_config(_text(value.get('host'),128,allow_empty=False),
            _text(value.get('lab_cidr'),64,allow_empty=False), _text(value.get('upstream','1.1.1.1'),128,allow_empty=False))
    except DNSError:raise PreferenceError(_INVALID) from None
    profile = {'host':host,'lab_cidr':str(net),'upstream':upstream,'start_on_open':value.get('start_on_open',False)}
    if 'custom_upstream' in value:
        try:
            _, _, custom, _, _ = validate_config(host, str(net), _text(value['custom_upstream'], 128, allow_empty=False))
        except DNSError:
            raise PreferenceError(_INVALID) from None
        profile['custom_upstream'] = custom
    return profile


def normalize_preferences(data):
    if not isinstance(data, dict) or set(data) - _PREF_FIELDS:
        raise PreferenceError(_INVALID)
    if type(data.get("schema", 1)) is not int or data.get("schema", 1) != 1:
        raise PreferenceError(_INVALID)
    result = default_preferences()
    for key in ("auto_updates", "auto_connect"):
        if key in data:
            if type(data[key]) is not bool:
                raise PreferenceError(_INVALID)
            result[key] = data[key]
    if data.get("saved_router") is not None:
        result["saved_router"] = normalize_router_profile(data["saved_router"])
    if result["auto_connect"] and result["saved_router"] is None:
        raise PreferenceError(_INVALID)
    if 'local_dns' in data:result['local_dns'] = normalize_dns_profile(data['local_dns'])
    return result


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _is_reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _check_chain(path):
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise PreferenceError(_PRIVATE)


def _windows_private(path, *, directory):
    """Protege a DACL por usuário, SYSTEM e administradores; não usa subprocesso."""
    try:
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                               wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.GetTokenInformation.restype = wintypes.BOOL
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD,
                                                                              ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        advapi.SetFileSecurityW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, ctypes.c_void_p]
        advapi.SetFileSecurityW.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise OSError()
        sid_text = ctypes.c_wchar_p()
        descriptor = ctypes.c_void_p()
        try:
            size = wintypes.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not 1 <= size.value <= 65536:
                raise OSError()
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise OSError()
            sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
                raise OSError()
            sid = sid_text.value
            if not isinstance(sid, str) or not re.fullmatch(r"S-\d+(?:-\d+){2,16}", sid):
                raise OSError()
            inheritance = "OICI" if directory else ""
            dacl = "D:P" + "".join(f"(A;{inheritance};FA;;;{identity})" for identity in (sid, "SY", "BA"))
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl, 1, ctypes.byref(descriptor), None):
                raise OSError()
            if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
                raise OSError()
        finally:
            if descriptor.value:
                kernel.LocalFree(descriptor)
            if sid_text:
                kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
            kernel.CloseHandle(token)
    except Exception:
        raise PreferenceError(_PRIVATE) from None


class PreferenceStore:
    def __init__(self, directory=None):
        supplied = Path.home() / ".labguard" / "preferences" if directory is None else Path(directory).expanduser()
        self.directory = Path(os.path.abspath(supplied))
        self.path = self.directory / "settings.json"
        self._lock = threading.RLock()

    def _directory(self, *, create=False):
        _check_chain(self.path)
        if not self.directory.exists():
            if not create:
                return False
            self.directory.mkdir(parents=True, mode=0o700)
            _check_chain(self.path)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise PreferenceError(_PRIVATE)
        if os.name == "nt":
            _windows_private(self.directory, directory=True)
        elif info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise PreferenceError(_PRIVATE)
        return True

    @staticmethod
    def _check_file(info):
        if not stat.S_ISREG(info.st_mode) or _is_reparse(info) or info.st_size > MAX_SETTINGS_BYTES or info.st_nlink != 1:
            raise PreferenceError(_PRIVATE)
        if os.name != "nt" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise PreferenceError(_PRIVATE)

    def load(self):
        with self._lock:
            try:
                if not self._directory() or not self.path.exists():
                    return default_preferences()
                _check_chain(self.path)
                self._check_file(self.path.lstat())
                if os.name == "nt":
                    _windows_private(self.path, directory=False)
                descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(descriptor, "rb") as source:
                    self._check_file(os.fstat(source.fileno()))
                    raw = source.read(MAX_SETTINGS_BYTES + 1)
                if len(raw) > MAX_SETTINGS_BYTES:
                    raise PreferenceError(_PRIVATE)
                return normalize_preferences(json.loads(raw, object_pairs_hook=_json_object))
            except PreferenceError:
                raise
            except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
                raise PreferenceError(_PRIVATE) from None

    def save(self, data):
        normalized = normalize_preferences(data)
        content = json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(content) > MAX_SETTINGS_BYTES:
            raise PreferenceError(_INVALID)
        with self._lock:
            temporary = None
            try:
                self._directory(create=True)
                if self.path.exists():
                    self._check_file(self.path.lstat())
                descriptor, temporary = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=self.directory)
                with os.fdopen(descriptor, "wb") as target:
                    target.write(content)
                    target.flush()
                    os.fsync(target.fileno())
                if os.name == "nt":
                    _windows_private(Path(temporary), directory=False)
                _check_chain(self.path)
                os.replace(temporary, self.path)
                temporary = None
                self._check_file(self.path.lstat())
                return normalized
            except PreferenceError:
                raise
            except OSError:
                raise PreferenceError(_PRIVATE) from None
            finally:
                if temporary is not None:
                    try:
                        Path(temporary).unlink()
                    except OSError:
                        pass
