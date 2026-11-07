"""Validate private preferences and the real per-user vault on Windows CI only.

The credential uses a fresh random identity, a documentation-only IP and a
temporary random secret. No network request is made. Existing user preferences
are never opened. Output contains booleans only; native failures fail the step
without exposing credential, path, target, username or exception contents.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import tempfile
import uuid

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class ValidationError(RuntimeError):
    pass


def require(condition):
    if not condition:
        raise ValidationError()


class WindowsACLReader:
    """Inspect native ACLs without PowerShell, configuration files or logging."""

    def __init__(self):
        from ctypes import wintypes

        self.wintypes = wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.LocalFree.restype = ctypes.c_void_p
        self.api.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        self.api.OpenProcessToken.restype = wintypes.BOOL
        self.api.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.api.GetTokenInformation.restype = wintypes.BOOL
        self.api.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        self.api.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.api.GetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, wintypes.DWORD,
                                                  ctypes.c_void_p, ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_void_p)]
        self.api.GetNamedSecurityInfoW.restype = wintypes.DWORD
        self.api.IsValidSecurityDescriptor.argtypes = [ctypes.c_void_p]
        self.api.IsValidSecurityDescriptor.restype = wintypes.BOOL
        self.api.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
                                                         ctypes.POINTER(wintypes.DWORD)]
        self.api.GetSecurityDescriptorControl.restype = wintypes.BOOL
        self.api.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
        self.api.GetAclInformation.restype = wintypes.BOOL
        self.api.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        self.api.GetAce.restype = wintypes.BOOL
        self.current_sid = self._current_sid()

    def _sid_string(self, pointer):
        value = ctypes.c_wchar_p()
        require(self.api.ConvertSidToStringSidW(pointer, ctypes.byref(value)))
        try:
            return value.value
        finally:
            self.kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))

    def _current_sid(self):
        token = self.wintypes.HANDLE()
        require(self.api.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
        try:
            size = self.wintypes.DWORD()
            self.api.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            require(1 <= size.value <= 65536)
            buffer = ctypes.create_string_buffer(size.value)
            require(self.api.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)))
            return self._sid_string(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0])
        finally:
            self.kernel.CloseHandle(token)

    def private_protected(self, path, *, directory):
        class ACLSizeInformation(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in ("count", "used", "free")]

        class AllowedACE(ctypes.Structure):
            _fields_ = [("kind", ctypes.c_ubyte), ("flags", ctypes.c_ubyte),
                        ("size", ctypes.c_uint16), ("mask", ctypes.c_uint32)]

        descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            require(self.api.GetNamedSecurityInfoW(str(path), 1, 4, None, None,
                                                  ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
            require(descriptor.value and dacl.value and self.api.IsValidSecurityDescriptor(descriptor))
            control, revision = self.wintypes.WORD(), self.wintypes.DWORD()
            require(self.api.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)))
            require(control.value & 0x1000)  # SE_DACL_PROTECTED: inherited access is disabled.
            info = ACLSizeInformation()
            require(self.api.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2))
            require(info.count == 3)
            expected_sids = {self.current_sid, "S-1-5-18", "S-1-5-32-544"}
            seen = set()
            for index in range(info.count):
                pointer = ctypes.c_void_p()
                require(self.api.GetAce(dacl, index, ctypes.byref(pointer)))
                require(pointer.value)
                ace = ctypes.cast(pointer, ctypes.POINTER(AllowedACE)).contents
                require(ace.kind == 0 and ace.flags == (3 if directory else 0))
                require(ace.size >= ctypes.sizeof(AllowedACE) + 8 and ace.mask == 0x1F01FF)
                sid = self._sid_string(pointer.value + ctypes.sizeof(AllowedACE))
                require(sid in expected_sids)
                seen.add(sid)
            require(seen == expected_sids)
            return True
        finally:
            if descriptor.value:
                self.kernel.LocalFree(descriptor)


def main():
    result = {key: False for key in (
        "ok", "windows_ci", "preferences_roundtrip", "directory_dacl_protected",
        "file_dacl_protected", "vault_available", "isolated_target_missing",
        "vault_roundtrip", "vault_deleted",
    )}
    try:
        require(platform.system() == "Windows" and os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("CI") == "true" and os.environ.get("RUNNER_OS") == "Windows")
        result["windows_ci"] = True
        from labguard.credential_store import CredentialStore
        from labguard.preferences import PreferenceStore, default_preferences

        with tempfile.TemporaryDirectory(prefix="labguard-startup-ci-") as temporary:
            preferences = PreferenceStore(Path(temporary) / "private-preferences")
            expected = default_preferences()
            expected["auto_updates"] = False
            require(preferences.save(expected) == expected and preferences.load() == expected)
            result["preferences_roundtrip"] = True
            reader = WindowsACLReader()
            result["directory_dacl_protected"] = reader.private_protected(preferences.directory, directory=True)
            result["file_dacl_protected"] = reader.private_protected(preferences.path, directory=False)

        vault = CredentialStore()
        require(vault.available())
        result["vault_available"] = True
        profile = {"host": "192.0.2.1", "port": 443, "user": "labguard-ci-" + uuid.uuid4().hex}
        secret = secrets.token_urlsafe(48)
        require(vault.load(profile) is None)
        result["isolated_target_missing"] = True
        try:
            require(vault.store(profile, secret))
            loaded = vault.load(profile)
            require(isinstance(loaded, str) and secrets.compare_digest(loaded, secret))
            result["vault_roundtrip"] = True
        finally:
            # The initial read confirmed the fresh identity was absent. Clean up
            # even if a write succeeded before its caller reported a failure.
            removed = vault.delete(profile)
            absent_after_delete = vault.load(profile) is None
            result["vault_deleted"] = bool(removed and absent_after_delete)
            require(result["vault_deleted"])
        result["ok"] = all(value for key, value in result.items() if key != "ok")
    except Exception:
        # The false stage flags and nonzero exit preserve native failures while
        # never publishing raw API errors, profile contents or credentials.
        result["ok"] = False
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
