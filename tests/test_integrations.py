import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from labguard.integrations import IntegrationManager, IntegrationError
from labguard.integrations.core import BUILTINS, SSHSession, canonical_port, parse_ports, attach_macs, validate_profile, RouterOSSession, _HTTPSOnlyRedirect


def custom_profile():
    return {"schema_version": 1, "id": "custom_fortigate", "name": "FortiGate consulta", "vendor": "Fortinet",
            "device_class": "Firewall", "family": "ssh_inventory", "description": "Consulta autorizada por SSH",
            "inventory_commands": ["get system interface physical"], "source_url": "https://docs.fortinet.com/"}


class IntegrationProfilesTests(unittest.TestCase):
    def test_data_profile_installs_without_code_or_dependencies(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "profile.json"
            source.write_text(json.dumps(custom_profile()))
            manager = IntegrationManager(Path(root) / "registry")
            installed = manager.install_profile(source)
            self.assertFalse(installed["capabilities"]["port_control"])
            self.assertEqual(manager.list_profiles()[-1]["id"], "custom_fortigate")
            with self.assertRaises(IntegrationError):
                manager.install_profile(source)

    def test_manifest_rejects_code_shell_injection_and_builtin_override(self):
        for field, value in [("pip", "malware"), ("inventory_commands", ["show interfaces; reboot"]), ("inventory_commands", ["show $(id)"]), ("inventory_commands", ["erase startup-config"])]:
            data = custom_profile()
            data[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(IntegrationError):
                validate_profile(data)
        with tempfile.TemporaryDirectory() as root:
            data = custom_profile()
            data["id"] = "cisco_ios"
            with self.assertRaises(IntegrationError):
                IntegrationManager(root)._install_bytes(json.dumps(data).encode())

    def test_zip_path_traversal_and_executable_extras_are_refused(self):
        for entries in [[("../profile.json", b"{}")], [("profile.json", b"{}"), ("install.py", b"print('bad')")]]:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                for name, data in entries:
                    archive.writestr(name, data)
            with tempfile.TemporaryDirectory() as root, self.assertRaises(IntegrationError):
                IntegrationManager(root)._install_bytes(buffer.getvalue())

    def test_hash_mismatch_installs_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            manager = IntegrationManager(Path(root)/"registry")
            with self.assertRaisesRegex(IntegrationError, "SHA-256 não confere"):
                manager._install_bytes(json.dumps(custom_profile()).encode(), "0" * 64)
            self.assertFalse(manager.profile_dir.exists())

    def test_download_requires_https_and_hash_before_network(self):
        manager = IntegrationManager()
        for url, sha in [("http://example.com/profile.json", "0"*64), ("https://example.com/profile.json", "")]:
            with patch("labguard.integrations.core.request.build_opener") as opener:
                with self.assertRaises(IntegrationError):
                    manager.download_profile(url, sha)
                opener.assert_not_called()

    def test_https_download_with_matching_hash_installs_json(self):
        payload = json.dumps(custom_profile()).encode()
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as root:
            manager = IntegrationManager(root)
            with patch("labguard.integrations.core.request.build_opener") as builder:
                builder.return_value.open.return_value = io.BytesIO(payload)
                profile = manager.download_profile("https://trusted.example/profile.json", digest)
            self.assertEqual(profile["id"], "custom_fortigate")
            self.assertTrue((Path(root) / "custom_fortigate.json").is_file())

    def test_https_redirect_cannot_downgrade_to_http(self):
        with self.assertRaisesRegex(IntegrationError, "HTTPS"):
            _HTTPSOnlyRedirect().redirect_request(None, None, 302, "Found", {}, "http://untrusted.example/profile.json")

    def test_valid_zip_installs_only_declarative_profile(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("profile.json", json.dumps(custom_profile()))
        data = buffer.getvalue()
        with tempfile.TemporaryDirectory() as root:
            manager = IntegrationManager(root)
            profile = manager._install_bytes(data, hashlib.sha256(data).hexdigest())
            self.assertEqual(profile["family"], "ssh_inventory")
            self.assertEqual([p.name for p in Path(root).iterdir()], ["custom_fortigate.json"])


class SwitchTests(unittest.TestCase):
    def session(self, family="cisco_ios", allowed="Gi1/0/1"):
        profile = copy.deepcopy(next(p for p in BUILTINS if p["family"] == family))
        with patch("labguard.integrations.core.shutil.which", return_value="/usr/bin/ssh"):
            return SSHSession(profile, "192.168.50.2", 22, "admin", "", "", allowed)

    def test_cisco_and_tplink_port_and_mac_parsing(self):
        cisco = parse_ports("Gi1/0/1  LAB01 connected 10 a-full a-1000 10/100/1000BaseTX\nGi1/0/2  UPLINK connected trunk a-full a-1000 ...", "cisco_ios")
        attach_macs(cisco, "10 0011.2233.4455 DYNAMIC Gi1/0/1", "cisco_ios")
        self.assertEqual(cisco[0]["name"], "Gi1/0/1")
        self.assertEqual(cisco[0]["macs"], ["00:11:22:33:44:55"])
        self.assertEqual(cisco[1]["vlan"], "trunk")
        tplink = parse_ports("Gi1/0/1 Enable Up 1000M Full\nGi1/0/2 Disable Down Auto Auto", "tplink_jetstream")
        self.assertEqual(tplink[1]["administrative"], "disabled")
        self.assertEqual(canonical_port("Gi1/0/1", "tplink_jetstream"), canonical_port("gigabitEthernet 1/0/1", "tplink_jetstream"))

    def test_port_control_refuses_unlisted_and_injected_names(self):
        session = self.session()
        for port in ["Gi1/0/2", "Gi1/0/1\nreload", "Gi1/0/1;reload", "Port-channel1"]:
            with self.subTest(port=port), patch.object(session, "_run") as run, self.assertRaises(IntegrationError):
                session.set_port_enabled(port, False)
            run.assert_not_called()

    def test_trunk_and_multiple_mac_ports_are_not_controllable(self):
        session = self.session(allowed="Gi1/0/1,Gi1/0/2")
        outputs = ["Gi1/0/1 UPLINK connected trunk a-full a-1000 type\nGi1/0/2 PCs connected 10 a-full a-1000 type", "10 0011.2233.4455 DYNAMIC Gi1/0/2\n10 0011.2233.4466 DYNAMIC Gi1/0/2"]
        with patch.object(session, "_run", side_effect=outputs):
            state = session.snapshot()
        self.assertFalse(any(p["controllable"] for p in state["ports"]))

    def test_shutdown_is_verified_from_later_snapshot(self):
        session = self.session()
        before = {"ports": [{"name": "Gi1/0/1", "controllable": True, "administrative": "enabled"}], "warnings": []}
        after = {"ports": [{"name": "Gi1/0/1", "controllable": True, "administrative": "disabled"}], "warnings": []}
        with patch.object(session, "snapshot", side_effect=[before, after]), patch.object(session, "_run") as run:
            state = session.set_port_enabled("Gi1/0/1", False)
        self.assertTrue(state["operation"]["verified"])
        self.assertEqual(run.call_args.args[0], ["configure terminal", "interface Gi1/0/1", "shutdown", "end", "exit"])

    def test_ssh_uses_strict_known_host_check_and_shell_false(self):
        session = self.session()
        with patch("labguard.integrations.core.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "OK", "")) as run:
            session._run(["show interfaces status", "exit"])
        self.assertIn("StrictHostKeyChecking=yes", run.call_args.args[0])
        self.assertIn("-tt", run.call_args.args[0])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_cli_error_is_not_reported_as_success(self):
        session = self.session()
        with patch("labguard.integrations.core.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "% Invalid input detected", "")):
            with self.assertRaisesRegex(IntegrationError, "rejeitou"):
                session._run(["show interfaces status", "exit"])

    def test_paged_mac_output_cannot_authorize_a_cut(self):
        session = self.session()
        with patch("labguard.integrations.core.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "10 0011.2233.4455 DYNAMIC Gi1/0/1\n--More--", "")):
            with self.assertRaisesRegex(IntegrationError, "paginou"):
                session._run(["show mac address-table", "exit"])

    def test_tplink_uses_configure_and_declares_unverified_operation(self):
        session = self.session("tplink_jetstream", "Gi1/0/1")
        name = canonical_port("Gi1/0/1", "tplink_jetstream")
        before = {"ports": [{"name": name, "controllable": True, "administrative": "enabled"}], "warnings": []}
        after = {"ports": [{"name": name, "controllable": True, "administrative": "unknown"}], "warnings": []}
        with patch.object(session, "snapshot", side_effect=[before, after]), patch.object(session, "_run") as run:
            state = session.set_port_enabled(name, False)
        self.assertFalse(state["operation"]["verified"])
        self.assertEqual(run.call_args.args[0][0], "configure")
        self.assertIn("não pôde ser confirmado", state["operation"]["message"])


class RouterOSTests(unittest.TestCase):
    def test_readonly_inventory_uses_documented_rest_menus(self):
        profile = copy.deepcopy(next(p for p in BUILTINS if p["family"] == "routeros_rest"))
        session = RouterOSSession(profile, "192.168.88.1", 443, "monitor", "test-secret", "")
        with patch.object(session, "_get", side_effect=[[{"name": "ether1", "running": "true", "disabled": "false"}], [{"address": "192.168.88.10", "mac-address": "00:11:22:33:44:55", "host-name": "LAB01", "status": "bound"}], []]) as get:
            state = session.snapshot()
        self.assertEqual(len(get.call_args_list), 3)
        self.assertIn("ip/dhcp-server/lease", get.call_args_list[1].args[0])
        self.assertEqual(state["devices"][0]["name"], "LAB01")
        self.assertNotIn("test-secret", json.dumps(state))
        with self.assertRaises(IntegrationError):
            session.set_port_enabled("ether1", False)


if __name__ == "__main__":
    unittest.main()
