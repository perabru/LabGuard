import base64
import copy
import io
import json
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

from labguard import remote


def appx(name="ROBLOXCORPORATION.ROBLOX"):
    return {"Name": name, "PackageFullName": name + "_2.650.1.0_x64__55nm5eh3cm0pr",
            "PackageFamilyName": name + "_55nm5eh3cm0pr", "Publisher": remote.ROBLOX_PUBLISHER,
            "PublisherId": "55nm5eh3cm0pr", "SignatureKind": "Store"}


def windows_raw():
    return {"processes": [{"name": "RobloxPlayerBeta.exe", "pid": 234},
                          {"name": "javaw.exe", "pid": 235},
                          {"name": "steam.exe", "pid": 236}],
            "appx": [appx()], "desktop": [{"DisplayName": "Fortnite"}]}


class OperationTimeout(Exception):
    pass


class ProtocolFake:
    instances = []

    def __init__(self, **kwargs):
        self.settings = kwargs
        self.transport = types.SimpleNamespace(password=kwargs["password"], username=kwargs["username"],
                                               encryption=object(), session=types.SimpleNamespace(close=Mock(), auth="NTLM"))
        self.queue = []
        self.scripts = []
        self.cleaned = []
        self.instances.append(self)

    def open_shell(self):
        return "shell"

    def run_command(self, shell, command, args, **kwargs):
        self.scripts.append(base64.b64decode(args[-1]).decode("utf-16le"))
        self.command = (command, args, kwargs)
        return "command"

    def get_command_output_raw(self, shell, command):
        entry = self.queue.pop(0)
        if isinstance(entry, Exception):
            raise entry
        return entry

    def cleanup_command(self, shell, command):
        self.cleaned.append((shell, command))

    def close_shell(self, shell):
        self.cleaned.append(shell)

    def respond(self, value):
        self.queue.append((json.dumps(value).encode(), b"", 0, True))


class RemoteWindowsTests(unittest.TestCase):
    def setUp(self):
        self.module_patch = patch.dict(sys.modules, {
            "winrm": types.ModuleType("winrm"),
            "winrm.protocol": types.SimpleNamespace(Protocol=ProtocolFake),
            "winrm.exceptions": types.SimpleNamespace(WinRMOperationTimeoutError=OperationTimeout)})
        self.module_patch.start()
        self.session = remote.create_session("windows", "192.168.50.24", "SCHOOL\\admin", "secret-pass")
        self.protocol = self.session._protocol

    def tearDown(self):
        self.session.close()
        self.module_patch.stop()

    def inspect(self, raw=None):
        self.protocol.respond(windows_raw() if raw is None else raw)
        return self.session.inspect()

    def test_https_ntlm_certificate_validation_and_no_environment_proxy(self):
        config = self.protocol.settings
        self.assertEqual(config["endpoint"], "https://192.168.50.24:5986/wsman")
        self.assertEqual(config["server_cert_validation"], "validate")
        self.assertEqual(config["transport"], "ntlm")
        self.assertEqual(config["message_encryption"], "always")
        self.assertIsNone(config["proxy"])
        self.assertGreater(config["read_timeout_sec"], config["operation_timeout_sec"])
        with self.assertRaises(remote.RemoteError):
            remote.create_session("windows", "192.168.50.24", "admin", "secret", port=5985)

    def test_catalogue_classifies_launchers_without_guessing_java_and_omits_arguments(self):
        snapshot = self.inspect()
        self.assertEqual([p["game_id"] for p in snapshot["processes"]], ["roblox", "steam"])
        self.assertFalse(snapshot["processes"][0]["is_launcher"])
        self.assertTrue(snapshot["processes"][1]["is_launcher"])
        script = self.protocol.scripts[-1]
        self.assertNotIn("CommandLine", script)
        self.assertNotIn("UninstallString", script)
        self.assertNotIn("HKCU", script)
        self.assertNotIn("secret-pass", json.dumps(snapshot))
        self.assertFalse(next(g for g in snapshot["games"] if g["id"] == "fortnite")["can_uninstall"])

    def test_both_signed_store_roblox_identities_are_allowed(self):
        for name in remote.ROBLOX_APPX:
            snapshot = self.inspect({"appx": [appx(name)]})
            self.assertTrue(snapshot["games"][0]["can_uninstall"])

    def test_generic_legacy_store_process_needs_package_location_attestation(self):
        raw = {"processes": [{"name": "Windows10Universal.exe", "pid": 80},
                             {"name": "Windows10Universal.exe", "pid": 81, "verified_store": "ROBLOXCORPORATION.ROBLOX"}]}
        snapshot = self.inspect(raw)
        self.assertEqual([p["pid"] for p in snapshot["processes"]], [81])
        self.assertEqual(snapshot["processes"][0]["game_id"], "roblox")
        self.assertIn("Join-Path $package.InstallLocation", self.protocol.scripts[-1])

    def test_wrong_store_name_publisher_family_or_signature_cannot_be_removed(self):
        for field, wrong in [("Publisher", "CN=Other"), ("PublisherId", "other"),
                             ("PackageFamilyName", "ROBLOX_other"), ("SignatureKind", "Developer"),
                             ("PackageFullName", "ROBLOXCORPORATION.ROBLOX_bad';whoami")]:
            row = appx()
            row[field] = wrong
            with self.subTest(field=field):
                snapshot = self.inspect({"appx": [row]})
                self.assertFalse(snapshot["games"][0]["can_uninstall"])
                with self.assertRaises(remote.RemoteError):
                    self.session.preview_uninstall(snapshot["games"][0]["install_id"])

    def test_store_minecraft_is_manual_to_protect_worlds(self):
        snapshot = self.inspect({"appx": [{"Name": "Microsoft.MinecraftUWP", "PackageFullName": "Minecraft_package"}]})
        game = snapshot["games"][0]
        self.assertFalse(game["can_uninstall"])
        self.assertIn("mundos", game["reason"])

    def test_successful_uninstall_rechecks_same_package_and_token_is_single_use(self):
        snapshot = self.inspect()
        game = next(g for g in snapshot["games"] if g["method"] == "appx")
        preview = self.session.preview_uninstall(game["install_id"])
        self.assertEqual(preview["host"], "192.168.50.24")
        self.assertIn("dados locais", preview["data_notice"])
        self.protocol.respond(windows_raw())
        self.protocol.respond({"ok": True})
        result = self.session.uninstall(preview["token"])
        self.assertTrue(result["ok"])
        script = self.protocol.scripts[-1]
        self.assertIn("Remove-AppxPackage", script)
        self.assertIn("-AllUsers", script)
        self.assertNotIn("UninstallString", script)
        self.assertIn(game["identity"]["package"], script)
        with self.assertRaises(remote.RemoteError):
            self.session.uninstall(preview["token"])

    def test_changed_installation_aborts_before_removal(self):
        snapshot = self.inspect()
        preview = self.session.preview_uninstall(snapshot["games"][0]["install_id"])
        self.protocol.respond({"appx": []})
        with self.assertRaisesRegex(remote.RemoteError, "mudou"):
            self.session.uninstall(preview["token"])
        self.assertEqual(len(self.protocol.scripts), 2)

    def test_preview_and_token_expire_without_any_remote_mutation(self):
        with patch("labguard.remote.time.monotonic", return_value=100):
            snapshot = self.inspect()
            preview = self.session.preview_uninstall(snapshot["games"][0]["install_id"])
        with patch("labguard.remote.time.monotonic", return_value=161):
            with self.assertRaises(remote.RemoteError):
                self.session.preview_uninstall(snapshot["games"][0]["install_id"])
            with self.assertRaises(remote.RemoteError):
                self.session.uninstall(preview["token"])
        self.assertEqual(len(self.protocol.scripts), 1)

    def test_copy_of_snapshot_cannot_change_removal_policy(self):
        snapshot = self.inspect()
        manual = next(g for g in snapshot["games"] if g["method"] == "desktop")
        manual["can_uninstall"] = True
        with self.assertRaises(remote.RemoteError):
            self.session.preview_uninstall(manual["install_id"])

    def test_notification_uses_fixed_text_and_rate_limit_without_false_read_confirmation(self):
        self.protocol.respond({"sent": True})
        result = self.session.notify("adult", "example.org")
        self.assertTrue(result["sent"])
        self.assertFalse(result["confirmed"])
        self.assertIn("msg.exe", self.protocol.scripts[-1])
        self.assertIn("example.org", self.protocol.scripts[-1])
        with self.assertRaisesRegex(remote.RemoteError, "cinco minutos"):
            self.session.notify("adult")

    def test_no_interactive_session_does_not_report_delivered(self):
        self.protocol.respond({"sent": False})
        result = self.session.notify("games")
        self.assertFalse(result["sent"])
        self.assertFalse(result["confirmed"])

    def test_notification_rejects_injection_and_unknown_type(self):
        for kind, domain in [("run", ""), ("adult", "example.org';Stop-Computer"),
                             ("adult", "https://example.org"), ("adult", "-x")]:
            with self.subTest(kind=kind, domain=domain), self.assertRaises(remote.RemoteError):
                self.session.notify(kind, domain)
        self.assertEqual(self.protocol.scripts, [])

    def test_bounded_winrm_output_and_failure_redaction_cleanup(self):
        self.protocol.queue.append((b"x" * (remote.MAX_OUTPUT + 1), b"", 0, True))
        with self.assertRaisesRegex(remote.RemoteError, "limite"):
            self.session.inspect()
        self.assertEqual(self.protocol.cleaned[-1], "shell")
        self.protocol.queue.append(RuntimeError("secret-pass in HTTP environment"))
        with self.assertRaises(remote.RemoteError) as caught:
            self.session.inspect()
        self.assertNotIn("secret-pass", str(caught.exception))
        self.assertIsNone(self.session._snapshot)

    def test_invalid_utf8_becomes_redacted_protocol_error(self):
        self.protocol.queue.append((b'\xff', b'', 0, True))
        with self.assertRaises(remote.RemoteError):
            self.session.inspect()

    def test_operation_timeout_loop_has_total_deadline_and_cleanup(self):
        self.protocol.queue.append(OperationTimeout())
        with patch("labguard.remote.time.monotonic", side_effect=[0, 1, 46]):
            with self.assertRaisesRegex(remote.RemoteError, "tempo"):
                self.session.inspect()
        self.assertEqual(self.protocol.cleaned[-1], "shell")

    def test_close_drops_credentials_and_rejects_future_actions(self):
        transport = self.protocol.transport
        http = transport.session
        self.inspect()
        self.session.close()
        self.assertIsNone(transport.password)
        self.assertIsNone(transport.username)
        self.assertIsNone(http.auth)
        http.close.assert_called_once()
        self.assertIsNone(self.session._snapshot)
        with self.assertRaises(remote.RemoteError):
            self.session.inspect()


class RemoteLinuxTests(unittest.TestCase):
    def setUp(self):
        self.ssh_patch = patch("labguard.remote.shutil.which", return_value="/usr/bin/ssh")
        self.ssh_patch.start()
        self.session = remote.create_session("linux", "192.168.50.25", "schooladmin")

    def tearDown(self):
        self.session.close()
        self.ssh_patch.stop()

    def test_linux_uses_hardened_ssh_without_shell_and_no_script_saved(self):
        response = subprocess.CompletedProcess([], 0, json.dumps({"processes": [], "dpkg": [], "flatpak": []}), "")
        with patch("labguard.remote.run_bounded", return_value=response) as runner:
            snapshot = self.session.inspect()
        args = runner.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ClearAllForwardings=yes", args)
        self.assertIn("ProxyCommand=none", args)
        self.assertEqual(args[-4:], ["schooladmin@192.168.50.25", "/usr/bin/python3", "-I", "-"])
        compile(runner.call_args.kwargs["input"], "remote-inventory", "exec")
        self.assertEqual(snapshot["host"], "192.168.50.25")

    def test_linux_catalogue_ignores_unrecognized_packages(self):
        raw = {"dpkg": [{"package": "minecraft-launcher", "version": "3.1"},
                        {"package": "important-school-package", "version": "1"}],
               "flatpak": [{"package": "com.valvesoftware.Steam", "branch": "stable", "arch": "x86_64", "version": "1", "commit": "a" * 64},
                           {"package": "org.school.Important", "branch": "stable", "arch": "x86_64"}]}
        with patch.object(self.session, "_inventory", return_value=raw):
            snapshot = self.session.inspect()
        self.assertEqual([g["id"] for g in snapshot["games"]], ["minecraft", "steam"])
        self.assertTrue(all(g["can_uninstall"] for g in snapshot["games"]))

    def test_dpkg_remove_script_checks_version_and_does_not_purge_data(self):
        raw = {"dpkg": [{"package": "minecraft-launcher", "version": "3.1"}]}
        with patch.object(self.session, "_inventory", return_value=raw):
            snapshot = self.session.inspect()
            preview = self.session.preview_uninstall(snapshot["games"][0]["install_id"])
            with patch.object(self.session, "_python", return_value={"ok": True}) as runner:
                self.session.uninstall(preview["token"])
        script = runner.call_args.args[0]
        self.assertIn("'/usr/bin/dpkg','--remove'", script)
        self.assertIn("package changed", script)
        self.assertNotIn("--purge", script)
        self.assertNotIn("--delete-data", script)
        self.assertNotIn("rm -", script)
        compile(script, "remote-remove", "exec")

    def test_inventory_script_parses_real_dpkg_tabs_and_keeps_fixed_catalogue(self):
        captured = []
        with patch.object(self.session, "_python", side_effect=lambda script: captured.append(script) or {}):
            self.session._inventory()
        script = captured[0]
        # Execute its inventory logic with fake OS reads and fixed command results.
        logic = script.split("processes=[];partial=False", 1)[1]
        class Entries:
            def __enter__(self):
                return iter([])
            def __exit__(self, *args):
                pass
        calls = []
        def command(args):
            calls.append(args)
            return (0, "installed\t3.1") if "minecraft-launcher" in args else (1, "")
        env = {"os": types.SimpleNamespace(scandir=lambda path: Entries()), "json": json,
               "command": command, "allowed": (), "processes": [], "partial": False}
        out = io.StringIO()
        with patch("sys.stdout", out):
            exec(compile(logic, "inventory-logic", "exec"), env)
        self.assertEqual(json.loads(out.getvalue())["dpkg"], [{"package": "minecraft-launcher", "version": "3.1"}])
        self.assertNotIn("shell=True", script)

    def test_linux_notification_is_explicitly_terminal_only(self):
        with patch.object(self.session, "_python", return_value={"sent": True}) as runner:
            result = self.session.notify("games")
        self.assertEqual(result["channel"], "linux-terminal")
        self.assertFalse(result["confirmed"])
        self.assertIn("'/usr/bin/wall'", runner.call_args.args[0])
        self.assertIn("terminais", " ".join(self.session._warnings()))

    def test_linux_timeout_is_redacted_and_unknown_hosts_rejected(self):
        with patch("labguard.remote.run_bounded", side_effect=subprocess.TimeoutExpired("ssh secret", 45)):
            with self.assertRaises(remote.RemoteError) as caught:
                self.session.inspect()
        self.assertNotIn("secret", str(caught.exception))
        for host in ("-oProxyCommand=evil", "https://example.org", "host;command"):
            with self.assertRaises(remote.RemoteError):
                remote.create_session("linux", host, "admin")

    def test_malformed_records_do_not_become_policy(self):
        for raw in ({"processes": ["bad"]}, {"processes": [{"name": "cs2", "pid": True}]},
                    {"flatpak": [{"package": "com.valvesoftware.Steam", "branch": "../../x", "arch": "x86_64"}]}):
            with self.subTest(raw=raw), patch.object(self.session, "_inventory", return_value=raw):
                with self.assertRaises(remote.RemoteError):
                    self.session.inspect()


if __name__ == "__main__":
    unittest.main()
