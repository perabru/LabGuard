"""Credencial RouterOS no cofre nativo do usuário Windows; nunca em arquivo JSON."""
from __future__ import annotations

import ctypes
import hashlib
import json
import platform

from .preferences import PreferenceError, normalize_router_profile

MAX_CREDENTIAL_BYTES = 2560
_ERROR = "O cofre de credenciais do sistema não pôde concluir a operação."
_UNAVAILABLE = "O cofre seguro para conexão automática não está disponível neste sistema. Use Observação ou conecte manualmente."


class CredentialStoreError(RuntimeError):
    pass


def credential_target(profile):
    try:
        clean = normalize_router_profile(profile)
    except PreferenceError:
        raise CredentialStoreError(_ERROR) from None
    identity = [clean["host"], clean["port"], clean["user"]]
    digest = hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    return "LabGuard/RouterOS/v1/" + digest


def _password(value):
    if (not isinstance(value, str) or not value or len(value) > 1024 or
            any(ord(char) < 32 for char in value)):
        raise CredentialStoreError(_ERROR)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise CredentialStoreError(_ERROR) from None
    if len(encoded) > MAX_CREDENTIAL_BYTES:
        raise CredentialStoreError(_ERROR)
    return encoded


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _Credential(ctypes.Structure):
    _fields_ = [("Flags", ctypes.c_uint32), ("Type", ctypes.c_uint32),
                ("TargetName", ctypes.c_wchar_p), ("Comment", ctypes.c_wchar_p),
                ("LastWritten", _FileTime), ("CredentialBlobSize", ctypes.c_uint32),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", ctypes.c_uint32),
                ("AttributeCount", ctypes.c_uint32), ("Attributes", ctypes.c_void_p),
                ("TargetAlias", ctypes.c_wchar_p), ("UserName", ctypes.c_wchar_p)]


class _WindowsCredentialAPI:
    def __init__(self):
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        self.api.CredWriteW.argtypes = [ctypes.POINTER(_Credential), ctypes.c_uint32]
        self.api.CredWriteW.restype = ctypes.c_int
        self.api.CredReadW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                     ctypes.POINTER(ctypes.POINTER(_Credential))]
        self.api.CredReadW.restype = ctypes.c_int
        self.api.CredDeleteW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        self.api.CredDeleteW.restype = ctypes.c_int
        self.api.CredFree.argtypes = [ctypes.c_void_p]
        self.api.CredFree.restype = None

    def write(self, target, username, password):
        encoded = _password(password)
        blob = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
        value = _Credential(Type=1, TargetName=target,
            Comment="LabGuard: credencial RouterOS do usuário; início somente em consulta.",
            CredentialBlobSize=len(encoded), CredentialBlob=blob, Persist=2, UserName=username)
        try:
            if not self.api.CredWriteW(ctypes.byref(value), 0):
                raise CredentialStoreError(_ERROR)
        finally:
            ctypes.memset(blob, 0, len(blob))

    def read(self, target, username):
        pointer = ctypes.POINTER(_Credential)()
        if not self.api.CredReadW(target, 1, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == 1168:
                return None
            raise CredentialStoreError(_ERROR)
        try:
            value = pointer.contents
            if (value.Type != 1 or value.TargetName != target or value.UserName != username or
                    not 1 <= value.CredentialBlobSize <= MAX_CREDENTIAL_BYTES or not value.CredentialBlob):
                raise CredentialStoreError(_ERROR)
            raw = ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize)
            try:
                password = raw.decode("utf-8", "strict")
            except UnicodeError:
                raise CredentialStoreError(_ERROR) from None
            _password(password)
            return password
        finally:
            self.api.CredFree(pointer)

    def delete(self, target):
        if self.api.CredDeleteW(target, 1, 0):
            return True
        if ctypes.get_last_error() == 1168:
            return False
        raise CredentialStoreError(_ERROR)


class CredentialStore:
    """A disponibilidade não lê credenciais; não há fallback em texto simples."""
    def __init__(self):
        self._api = None
        if platform.system() == "Windows":
            try:
                self._api = _WindowsCredentialAPI()
            except (AttributeError, OSError):
                pass
        self.reason = "" if self._api is not None else _UNAVAILABLE

    def available(self):
        return self._api is not None

    def _profile(self, profile):
        if self._api is None:
            raise CredentialStoreError(_UNAVAILABLE)
        try:
            return normalize_router_profile(profile)
        except PreferenceError:
            raise CredentialStoreError(_ERROR) from None

    def store(self, profile, password):
        clean = self._profile(profile)
        _password(password)
        try:
            self._api.write(credential_target(clean), clean["user"], password)
            return True
        except Exception:
            raise CredentialStoreError(_ERROR) from None

    def load(self, profile):
        clean = self._profile(profile)
        try:
            password = self._api.read(credential_target(clean), clean["user"])
            if password is not None:
                _password(password)
            return password
        except Exception:
            raise CredentialStoreError(_ERROR) from None

    def delete(self, profile):
        clean = self._profile(profile)
        try:
            return bool(self._api.delete(credential_target(clean)))
        except Exception:
            raise CredentialStoreError(_ERROR) from None
