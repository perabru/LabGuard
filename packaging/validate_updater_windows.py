"""Native update smoke for an isolated Windows GitHub Actions runner.

Only the HTTPS transport is replaced with local release bytes. Eligibility,
package validation, private staging, parent-process checks, the PowerShell
helper, and the two installers are real. Never run this on an operator's PC.
The old installer is pinned; no token or live update endpoint is read here.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time
from unittest.mock import patch
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

OLD_SHA256 = "cba4c69eb2cb0dbe1d76c790bdfd2303b542b73404fd98f350226bea09169165"
OLD_VERSION = "2.3.0"
NEW_VERSION = "2.4.0"
MAX_PACKAGE = 150 * 1024 * 1024


class ValidationError(RuntimeError):
    """Only fixed validation codes may be printed."""


def require(condition, code):
    if not condition:
        raise ValidationError(code)


def digest_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
            and not getattr(info, "st_file_attributes", 0) & 0x400,
            "PACKAGE_MUST_BE_REGULAR")
    require(0 < info.st_size <= MAX_PACKAGE, "PACKAGE_SIZE_INVALID")
    digest, total = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= MAX_PACKAGE, "PACKAGE_SIZE_INVALID")
            digest.update(block)
    require(total == info.st_size, "PACKAGE_CHANGED")
    return digest.hexdigest(), total


def file_version(path):
    """Read the native fixed-file version without launching the GUI."""
    version = ctypes.WinDLL("version", use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    version.GetFileVersionInfoW.restype = wintypes.BOOL
    version.VerQueryValueW.argtypes = [wintypes.LPCVOID, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.UINT)]
    version.VerQueryValueW.restype = wintypes.BOOL
    ignored = wintypes.DWORD()
    size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
    require(0 < size <= 1024 * 1024, "EXE_VERSION_UNAVAILABLE")
    buffer = ctypes.create_string_buffer(size)
    require(version.GetFileVersionInfoW(str(path), 0, size, buffer), "EXE_VERSION_READ_FAILED")
    address, length = wintypes.LPVOID(), wintypes.UINT()
    require(version.VerQueryValueW(buffer, "\\", ctypes.byref(address), ctypes.byref(length))
            and length.value >= 52, "EXE_VERSION_QUERY_FAILED")
    words = ctypes.cast(address, ctypes.POINTER(wintypes.DWORD))
    require(words[0] == 0xFEEF04BD, "EXE_VERSION_SIGNATURE_INVALID")
    return words[2] >> 16, words[2] & 0xFFFF, words[3] >> 16, words[3] & 0xFFFF


def registry_record(updater):
    import winreg
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, updater.UNINSTALL_KEY, 0, winreg.KEY_READ | view) as key:
                return {name: winreg.QueryValueEx(key, name)[0] for name in ("InstallLocation", "DisplayVersion")}
        except FileNotFoundError:
            continue
    return None


def main_windows(process):
    """Find top-level windows belonging only to the exact launched process."""
    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user.EnumWindows.restype = wintypes.BOOL
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.IsWindowVisible.restype = wintypes.BOOL
    handles = []

    @callback_type
    def visit(handle, ignored):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(handle, ctypes.byref(owner))
        if owner.value == process.pid and user.IsWindowVisible(handle):
            handles.append(handle)
        return True

    require(user.EnumWindows(visit, 0), "WINDOW_ENUMERATION_FAILED")
    return handles


def wait_window(process, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(process.poll() is None, "OLD_DEMO_EXITED_EARLY")
        if main_windows(process):
            return
        time.sleep(0.2)
    raise ValidationError("OLD_DEMO_WINDOW_UNAVAILABLE")


def close_gracefully(process, timeout=30):
    if process is None or process.poll() is not None:
        return
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.PostMessageW.restype = wintypes.BOOL
    handles = main_windows(process)
    require(handles, "OLD_DEMO_CLOSE_WINDOW_UNAVAILABLE")
    for handle in handles:
        require(user.PostMessageW(handle, 0x0010, 0, 0), "OLD_DEMO_CLOSE_REQUEST_FAILED")
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValidationError("OLD_DEMO_DID_NOT_CLOSE") from None
    require(code == 0, "OLD_DEMO_EXIT_FAILED")


def fixture_download(updater, new_setup, new_sha, new_size, counts):
    root = updater.RELEASE_ROOT + "v" + NEW_VERSION + "/"
    manifest = json.dumps({"schema": 1, "app_id": updater.APP_ID, "channel": "stable", "version": NEW_VERSION,
        "artifacts": {"windows-x86_64": {"name": "LabGuard-Setup.exe", "sha256": new_sha, "size": new_size}}},
        sort_keys=True).encode("ascii")
    sums = (hashlib.sha256(manifest).hexdigest() + "  labguard-update.json\n" + new_sha + "  LabGuard-Setup.exe\n").encode("ascii")
    sizes = {"labguard-update.json": len(manifest), "SHA256SUMS.txt": len(sums), "LabGuard-Setup.exe": new_size}
    release = json.dumps({"tag_name": "v" + NEW_VERSION, "draft": False, "prerelease": False,
        "assets": [{"name": name, "size": size, "browser_download_url": root + name} for name, size in sizes.items()]},
        sort_keys=True).encode("ascii")
    bodies = {updater.API_URL: release, root + "labguard-update.json": manifest, root + "SHA256SUMS.txt": sums}

    def download(url, maximum, deadline, target=None):
        require(time.monotonic() < deadline, "FIXTURE_DEADLINE_EXPIRED")
        require(updater.allowed_url(url), "FIXTURE_ORIGIN_REJECTED")
        counts["fixture_requests"] += 1
        if url == root + "LabGuard-Setup.exe":
            require(target is not None and new_size <= maximum, "FIXTURE_PACKAGE_CONTRACT_INVALID")
            digest, total = hashlib.sha256(), 0
            with new_setup.open("rb") as source:
                while True:
                    block = source.read(65536)
                    if not block:
                        break
                    total += len(block)
                    require(total <= maximum and time.monotonic() < deadline, "FIXTURE_PACKAGE_BOUND_EXCEEDED")
                    digest.update(block)
                    target.write(block)
            require(total == new_size and digest.hexdigest() == new_sha, "FIXTURE_PACKAGE_CHANGED")
            return None, total, digest.hexdigest()
        require(url in bodies and target is None, "UNEXPECTED_FIXTURE_REQUEST")
        body = bodies[url]
        require(len(body) <= maximum, "FIXTURE_METADATA_BOUND_EXCEEDED")
        return body, len(body), hashlib.sha256(body).hexdigest()

    return download


def launch_real_helper(updater, manager, prepared, old_process):
    """Exercise the helper with real staging and the already installed old app.

    Production scheduling accepts only the calling frozen application's PID.
    This standalone validator is Python, so it constructs that same private
    contract here; it does not weaken the production scheduler for a test PID.
    """
    value = manager._prepared.get(prepared.get("prepared_id"))
    require(isinstance(value, dict), "PREPARED_RECORD_UNAVAILABLE")
    path = updater._safe_path(value["path"])
    manager._validate_package(path, value)
    executable = updater._safe_path(manager.executable).resolve()
    require(old_process.poll() is None
            and os.path.normcase(str(updater._process_executable(old_process.pid))) == os.path.normcase(str(executable)),
            "REAL_PARENT_IMAGE_MISMATCH")
    directory = updater._secure_directory(path.parent)
    helper_source = Path(updater.__file__).parent / "update_helpers" / "apply_windows.ps1"
    helper_content = helper_source.read_bytes()
    require(100 < len(helper_content) <= 65536, "REAL_HELPER_UNAVAILABLE")
    helper, metadata = directory / "apply_windows.ps1", directory / "apply.json"
    updater._atomic_bytes(helper, helper_content)
    payload = {"schema": 1, "app_id": updater.APP_ID, "consent": True, "version": value["version"],
        "sha256": value["sha256"], "size": value["size"], "installer": str(path),
        "install_dir": str(executable.parent), "parent_pid": old_process.pid,
        "parent_executable": str(executable), "helper_sha256": hashlib.sha256(helper_content).hexdigest()}
    updater._atomic_bytes(metadata, json.dumps(payload, ensure_ascii=True).encode("ascii"))
    powershell = updater._system_powershell()
    require(powershell.is_file(), "SYSTEM_POWERSHELL_UNAVAILABLE")
    return subprocess.Popen([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(helper), "-MetadataPath", str(metadata)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def uninstall_own(updater, install_dir):
    """Remove only this fresh, scoped installation before regular CI tests."""
    record = registry_record(updater)
    if record is None:
        return
    require(Path(record["InstallLocation"]).resolve() == install_dir.resolve(), "CLEANUP_DIFFERENT_INSTALLATION_REFUSED")
    uninstaller = updater._safe_path(install_dir / "unins000.exe")
    require(uninstaller.is_file(), "CLEANUP_UNINSTALLER_UNAVAILABLE")
    result = subprocess.run([str(uninstaller), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    require(result.returncode == 0, "CLEANUP_UNINSTALL_FAILED")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if registry_record(updater) is None and not (install_dir / "LabGuard.exe").exists():
            return
        time.sleep(0.2)
    raise ValidationError("CLEANUP_INSTALLATION_STILL_PRESENT")


def native_smoke(args):
    require(platform.system() == "Windows" and platform.machine().casefold() in {"amd64", "x86_64"}
            and sys.maxsize > 2**32, "WINDOWS_X64_RUNNER_REQUIRED")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Windows",
            "ISOLATED_GITHUB_RUNNER_REQUIRED")
    from labguard import updater

    old_setup = updater._safe_path(Path(args.old_setup).absolute())
    new_setup = updater._safe_path(Path(args.new_setup).absolute())
    require(digest_file(old_setup)[0] == OLD_SHA256, "OLD_SETUP_HASH_MISMATCH")
    new_sha, new_size = digest_file(new_setup)
    require(new_sha != OLD_SHA256, "NEW_SETUP_EQUALS_OLD")
    require(file_version(new_setup) == tuple(map(int, NEW_VERSION.split("."))) + (0,), "NEW_SETUP_FILE_VERSION_MISMATCH")
    local = updater._safe_path(Path(os.environ["LOCALAPPDATA"]).absolute()).resolve()
    scope = (local / "LabGuardUpdateSmoke").resolve()
    install_dir = updater._safe_path(Path(args.install_dir).absolute()).resolve()
    updater._safe_path(install_dir)
    require(install_dir.is_relative_to(scope) and len(install_dir.relative_to(scope).parts) >= 1,
            "INSTALL_DIRECTORY_NOT_SCOPED")
    require(not install_dir.exists(), "INSTALL_DIRECTORY_ALREADY_EXISTS")
    require(" " in str(install_dir), "INSTALL_DIRECTORY_MUST_TEST_SPACES")
    require(registry_record(updater) is None, "EXISTING_INSTALLATION_REFUSED")
    install_dir.parent.mkdir(parents=True, exist_ok=True)
    updater._safe_path(install_dir.parent)
    stage = scope / ("Private Updates " + uuid4().hex)
    output = Path(args.output).absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    selftest_path = stage / "installed-selftest.json"
    executable = install_dir / "LabGuard.exe"
    old_process, helper_process, manager = None, None, None
    installed_own = False
    counts = {"fixture_requests": 0}
    try:
        old_run = subprocess.run([str(old_setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/NOCLOSEAPPLICATIONS", "/NORESTARTAPPLICATIONS", "/DIR=" + str(install_dir)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
        installed_own = executable.is_file()
        require(old_run.returncode == 0 and executable.is_file(), "OLD_INSTALL_FAILED")
        require(file_version(executable) == tuple(map(int, OLD_VERSION.split("."))) + (0,), "OLD_EXE_VERSION_MISMATCH")
        old_record = registry_record(updater)
        require(old_record and old_record["DisplayVersion"] == OLD_VERSION
                and Path(old_record["InstallLocation"]).resolve() == install_dir.resolve(), "OLD_REGISTRY_MISMATCH")
        old_process = subprocess.Popen([str(executable), "--demo"], cwd=install_dir,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_window(old_process)
        manager = updater.UpdateManager(OLD_VERSION, data_dir=stage, executable=executable, frozen=True)
        status = manager.installation_status()
        require(status.get("auto_apply") is True and status.get("state") == "installed", "REAL_INSTALLATION_INELIGIBLE")
        with patch.object(manager, "_download", side_effect=fixture_download(updater, new_setup, new_sha, new_size, counts)):
            candidate = manager.check_update()
            require(candidate.get("state") == "available" and candidate.get("version") == NEW_VERSION, "UPDATE_CHECK_FAILED")
            prepared = manager.stage_update(candidate)
        require(prepared.get("state") == "prepared" and prepared.get("can_apply") is True,
                "UPDATE_STAGE_FAILED")
        require(counts["fixture_requests"] == 4, "FIXTURE_REQUEST_COUNT_MISMATCH")
        helper_process = launch_real_helper(updater, manager, prepared, old_process)
        # A default pending DTO is not evidence that the helper started. Wait
        # for its private receipt while keeping the old application open.
        ready_deadline = time.monotonic() + 30
        result = manager.application_result(prepared)
        while result["state"] == "pending" and result["code"] != "WAITING_FOR_EXIT":
            require(helper_process.poll() is None, "REAL_HELPER_EXIT_WITHOUT_WAIT_RECEIPT")
            require(time.monotonic() < ready_deadline, "REAL_HELPER_WAIT_RECEIPT_MISSING")
            time.sleep(0.1)
            result = manager.application_result(prepared)
        require(result["state"] == "pending" and result["code"] == "WAITING_FOR_EXIT",
                "REAL_HELPER_" + (result["code"] or result["state"].upper()))
        # The helper must leave the active parent untouched and wait for WM_CLOSE.
        time.sleep(1)
        result = manager.application_result(prepared)
        require(result["state"] == "pending" and result["code"] == "WAITING_FOR_EXIT",
                "REAL_HELPER_" + (result["code"] or result["state"].upper()))
        require(old_process.poll() is None and helper_process.poll() is None
                and file_version(executable) == tuple(map(int, OLD_VERSION.split("."))) + (0,), "UPDATE_DID_NOT_WAIT_FOR_PARENT")
        close_gracefully(old_process)
        deadline = time.monotonic() + 180
        result = manager.application_result(prepared)
        while result["state"] == "pending" and time.monotonic() < deadline:
            time.sleep(0.3)
            result = manager.application_result(prepared)
        require(result["state"] == "applied", "REAL_HELPER_" + (result["code"] or result["state"].upper()))
        require(helper_process.wait(timeout=15) == 0, "REAL_HELPER_EXIT_FAILED")
        require(file_version(executable) == tuple(map(int, NEW_VERSION.split("."))) + (0,), "NEW_EXE_VERSION_MISMATCH")
        new_record = registry_record(updater)
        require(new_record and new_record["DisplayVersion"] == NEW_VERSION
                and Path(new_record["InstallLocation"]).resolve() == install_dir.resolve(), "NEW_REGISTRY_MISMATCH")
        selftest = subprocess.run([str(executable), "--self-test", "--output", str(selftest_path)], cwd=install_dir,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
        require(selftest.returncode == 0 and selftest_path.is_file(), "UPDATED_SELFTEST_FAILED")
        payload = json.loads(selftest_path.read_text(encoding="utf-8"))
        require(payload.get("ok") is True and payload.get("version") == NEW_VERSION, "UPDATED_SELFTEST_VERSION_MISMATCH")
        evidence = {"ok": True, "old_version": OLD_VERSION, "new_version": NEW_VERSION,
            "old_setup_hash_pinned": True, "transport_fixture_only": True, "fixture_requests": counts["fixture_requests"],
            "real_per_user_install": True, "install_path_spaces": True, "parent_closed_gracefully": True,
            "waited_for_parent": True, "explicit_wait_receipt": True, "real_powershell_helper": True, "receipt_applied": True,
            "exe_file_version_verified": True, "hkcu_version_verified": True, "updated_package_selftest": True,
            "new_setup_file_version_verified": True, "production_scheduler_unchanged": True}
        uninstall_own(updater, install_dir)
        installed_own = False
        evidence["scoped_installation_removed"] = True
        output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(evidence, sort_keys=True))
        return 0
    finally:
        if manager is not None:
            manager.close()
        # No taskkill/TerminateProcess: only ask this test's own demo to close.
        if old_process is not None and old_process.poll() is None:
            close_gracefully(old_process)
        if helper_process is not None and helper_process.poll() is None:
            try:
                helper_process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                raise ValidationError("CLEANUP_HELPER_STILL_RUNNING") from None
        if installed_own:
            uninstall_own(updater, install_dir)
        # Private receipt remains in the isolated runner for diagnosis; runner
        # disposal removes it. No process is forcibly stopped or tree deleted.


def main():
    parser = argparse.ArgumentParser(description="Validate the real per-user Windows updater on an isolated CI runner.")
    parser.add_argument("--old-setup", required=True)
    parser.add_argument("--new-setup", required=True)
    parser.add_argument("--install-dir", required=True)
    parser.add_argument("--output", default=str(PROJECT_ROOT / "dist" / "release" / "update-validation.json"))
    args = parser.parse_args()
    try:
        return native_smoke(args)
    except ValidationError as error:
        print("FAIL: native update validation: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: native update validation did not complete.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
