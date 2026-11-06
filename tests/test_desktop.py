import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labguard.demo import DemoTransport, normalize_domain
from labguard.transport import SSHTransport, TransportError, validate_host, run_bounded, OutputLimitExceeded, ssh_command_base


class DomainTests(unittest.TestCase):
    def test_normalization_and_subdomain_policy(self):
        self.assertEqual(normalize_domain(" Poki.com. "), "poki.com")
        self.assertEqual(normalize_domain("ação.com.br"), "xn--ao-siap.com.br")

    def test_injection_urls_ips_and_invalid_labels_rejected(self):
        for value in ["*.poki.com", "poki.com\nserver=evil", "poki.com/", "https://poki.com", "192.168.50.1", "-bad.com", "bad..com", "com", "a.123", "poki.com; reboot"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)


class DemoTests(unittest.TestCase):
    def test_ip_mac_and_legacy_scopes_are_independent(self):
        demo = DemoTransport()
        ip, mac = "192.168.50.101", "02:00:00:00:00:01"
        demo.request("set_device_block", ip=ip, blocked=True)
        demo.request("set_address_block", kind="ip", address=ip, blocked=True)
        data = demo.request("set_address_block", kind="mac", address=mac, blocked=True)
        device = next(row for row in data["devices"] if row["ip"] == ip)
        self.assertEqual(device["blocked_by"], ["device", "ip", "mac"])
        data = demo.request("set_address_block", kind="ip", address=ip, blocked=False)
        self.assertEqual(next(row for row in data["devices"] if row["ip"] == ip)["blocked_by"], ["device", "mac"])
        data = demo.request("set_device_block", ip=ip, blocked=False)
        self.assertEqual(next(row for row in data["devices"] if row["ip"] == ip)["blocked_by"], ["mac"])
        data = demo.request("set_address_block", kind="mac", address=mac, blocked=False)
        self.assertFalse(next(row for row in data["devices"] if row["ip"] == ip)["blocked"])

    def test_mac_follows_dhcp_while_explicit_ip_does_not(self):
        demo = DemoTransport()
        demo.request("set_address_block", kind="ip", address="192.168.50.101", blocked=True)
        demo.request("set_address_block", kind="mac", address="02:00:00:00:00:01", blocked=True)
        demo.state["devices"][0]["ip"] = "192.168.50.150"
        demo.state["devices"][1]["ip"] = "192.168.50.101"
        data = demo.request("snapshot")
        self.assertEqual(next(row for row in data["devices"] if row["ip"].endswith(".150"))["blocked_by"], ["mac"])
        self.assertEqual(next(row for row in data["devices"] if row["ip"].endswith(".101"))["blocked_by"], ["ip"])

    def test_address_rules_can_be_removed_offline(self):
        demo = DemoTransport()
        demo.request("set_address_block", kind="ip", address="192.168.50.101", blocked=True)
        demo.request("set_address_block", kind="mac", address="02:00:00:00:00:01", blocked=True)
        demo.state["devices"] = [row for row in demo.state["devices"] if row["ip"] != "192.168.50.101"]
        placeholder = next(row for row in demo.request("snapshot")["devices"] if row["ip"] == "192.168.50.101")
        self.assertFalse(placeholder["observed"])
        demo.request("set_address_block", kind="ip", address="192.168.50.101", blocked=False)
        data = demo.request("set_address_block", kind="mac", address="02:00:00:00:00:01", blocked=False)
        self.assertEqual(data["address_blocks"], [])
        with self.assertRaises(ValueError):
            demo.request("set_address_block", kind="ip", address="192.168.50.101", blocked=True)

    def test_new_address_action_rejects_invalid_unobserved_protected_and_extra_params(self):
        demo = DemoTransport()
        for kind, address in (("ip", "192.168.50.10"), ("ip", "192.168.50.150"), ("ip", "192.168.51.101"),
                              ("ip", "192.168.50.255"), ("mac", "02:00:00:00:00:0c"), ("mac", "02:00:00:00:00:99"),
                              ("mac", "00:00:00:00:00:00"), ("mac", "ff:ff:ff:ff:ff:ff"), ("mac", "01:00:5e:00:00:01")):
            with self.subTest(kind=kind, address=address), self.assertRaises(ValueError):
                demo.request("set_address_block", kind=kind, address=address, blocked=True)
        for extra in ({"blocked": "false"}, {"kind": "both"}, {"shell": "whoami"}):
            params = dict(kind="ip", address="192.168.50.101", blocked=True)
            params.update(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                demo.request("set_address_block", **params)
        self.assertEqual(demo.request("snapshot")["address_blocks"], [])

    def test_admin_mac_on_another_ip_is_still_protected(self):
        demo = DemoTransport()
        demo.state["devices"][0]["mac"] = demo.state["devices"][-1]["mac"]
        with self.assertRaisesRegex(ValueError, "protegida"):
            demo.request("set_address_block", kind="ip", address="192.168.50.101", blocked=True)

    def test_ai_profile_toggle_preserves_manual_overlap_and_history(self):
        demo = DemoTransport()
        before = demo.request("snapshot")
        self.assertFalse(before["policies"]["ai_block"]["enabled"])
        demo.request("add_domain", domain="chatgpt.com", category="Inteligência artificial")
        enabled = demo.request("set_ai_block", enabled=True)
        self.assertTrue(enabled["policies"]["ai_block"]["enabled"])
        self.assertGreater(enabled["policies"]["ai_block"]["domain_count"], 10)
        self.assertEqual(len([d for d in enabled["domains"] if d["domain"] == "chatgpt.com"]), 1)
        self.assertEqual(next(d for d in enabled["domains"] if d["domain"] == "chatgpt.com")["source"], "manual")
        with self.assertRaisesRegex(ValueError, "perfil"):
            demo.request("remove_domain", domain="claude.ai")
        disabled = demo.request("set_ai_block", enabled=False)
        self.assertIn("chatgpt.com", [d["domain"] for d in disabled["domains"]])
        self.assertNotIn("claude.ai", [d["domain"] for d in disabled["domains"]])
        self.assertEqual(len(enabled["events"]), len(disabled["events"]))
        with self.assertRaises(ValueError):
            demo.request("set_ai_block", enabled="false")

    def test_catalog_avoids_entire_shared_search_or_code_hosts(self):
        catalog = DemoTransport().request("snapshot")["policies"]["ai_block"]
        for domain in ["google.com", "bing.com", "microsoft.com", "github.com", "x.com", "cloudflare.com"]:
            self.assertNotIn(domain, catalog["domains"])

    def test_demo_has_no_real_network_and_independent_snapshots(self):
        demo = DemoTransport()
        snapshot = demo.request("snapshot")
        snapshot["devices"].clear()
        self.assertEqual(len(demo.request("snapshot")["devices"]), 12)
        self.assertEqual(snapshot["mode"], "demo")

    def test_domain_add_duplicate_remove(self):
        demo = DemoTransport()
        data = demo.request("add_domain", domain="newgame.example", category="Jogos")
        self.assertIn("newgame.example", [d["domain"] for d in data["domains"]])
        with self.assertRaises(ValueError):
            demo.request("add_domain", domain="newgame.example")
        data = demo.request("remove_domain", domain="newgame.example")
        self.assertNotIn("newgame.example", [d["domain"] for d in data["domains"]])

    def test_teacher_protected_and_observed_only(self):
        demo = DemoTransport()
        for ip in ["192.168.50.10", "10.1.1.1", "192.168.50.222"]:
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                demo.request("set_device_block", ip=ip, blocked=True)
        data = demo.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.assertTrue(next(d for d in data["devices"] if d["ip"].endswith(".101"))["blocked"])
        with self.assertRaises(ValueError):
            demo.request("set_device_block", ip="192.168.50.101", blocked="false")


class TransportTests(unittest.TestCase):
    def test_ssh_rejects_option_injection(self):
        for host in ["-oProxyCommand=evil", "host;evil", "a\nb", "user@host", "https://host", "$(id)"]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate_host(host)

    def test_ssh_strict_host_verification_and_json_no_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key with spaces"
            key.write_text("not an actual key")
            with patch("labguard.transport.shutil.which", return_value="/usr/bin/ssh"):
                transport = SSHTransport("192.168.50.1", key_path=str(key))
            cmd = transport.command()
            self.assertIn("StrictHostKeyChecking=yes", cmd)
            self.assertIn("BatchMode=yes", cmd)
            self.assertIn(str(key.resolve()), cmd)
            with patch("labguard.transport.run_bounded") as run:
                run.return_value = subprocess.CompletedProcess(cmd, 0, '{"ok":false,"error":"Máquina protegida"}', "")
                with self.assertRaisesRegex(TransportError, "protegida"):
                    transport.request("set_device_block", ip="192.168.50.10", blocked=True)
                self.assertNotIn("shell", run.call_args.kwargs)
                self.assertIn('"version": 1', run.call_args.kwargs["input"])

    def test_demo_data_never_accepted_as_live(self):
        import json
        with patch("labguard.transport.shutil.which", return_value="/usr/bin/ssh"):
            transport = SSHTransport("gateway.local")
        response = json.dumps({"ok": True, "data": DemoTransport().request("snapshot")})
        with patch("labguard.transport.run_bounded", return_value=subprocess.CompletedProcess([], 0, response, "")):
            with self.assertRaisesRegex(TransportError, "estado real"):
                transport.request("snapshot")

    def test_malformed_service_state_is_not_accepted_as_healthy(self):
        import json
        state = DemoTransport().request("snapshot")
        state["mode"] = "gateway"
        state["health"]["firewall"] = "false"
        with patch("labguard.transport.shutil.which", return_value="/usr/bin/ssh"):
            transport = SSHTransport("gateway.local")
        response = json.dumps({"ok": True, "data": state})
        with patch("labguard.transport.run_bounded", return_value=subprocess.CompletedProcess([], 0, response, "")):
            with self.assertRaisesRegex(TransportError, "estado válido"):
                transport.request("snapshot")

    def test_nonzero_exit_keeps_gateway_rejection_message(self):
        with patch("labguard.transport.shutil.which", return_value="/usr/bin/ssh"):
            transport = SSHTransport("gateway.local")
        with patch("labguard.transport.run_bounded", return_value=subprocess.CompletedProcess([], 1, '{"ok":false,"error":"Máquina protegida"}', "")):
            with self.assertRaisesRegex(TransportError, "^Máquina protegida$"):
                transport.request("set_device_block", ip="192.168.50.10", blocked=True)

    def test_closed_gateway_cannot_issue_more_requests(self):
        with patch("labguard.transport.shutil.which", return_value="/usr/bin/ssh"):
            transport = SSHTransport("gateway.local")
        transport.close()
        with patch("labguard.transport.run_bounded") as run:
            with self.assertRaisesRegex(TransportError, "encerrada"):
                transport.request("snapshot")
        run.assert_not_called()
        self.assertEqual(transport.host, "")

    def test_timeout_explains_mutation_uncertainty(self):
        with patch("labguard.transport.shutil.which", return_value="/usr/bin/ssh"):
            transport = SSHTransport("gateway.local")
        with patch("labguard.transport.run_bounded", side_effect=subprocess.TimeoutExpired("ssh", 35)):
            with self.assertRaisesRegex(TransportError, "conferir"):
                transport.request("add_domain", domain="poki.com")



class ProcessBoundaryTests(unittest.TestCase):
    def test_live_child_output_is_bounded_before_return(self):
        with self.assertRaises(OutputLimitExceeded):
            run_bounded([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*200000); sys.stdout.flush()"], max_output_bytes=1024, timeout=5)

    def test_live_child_timeout_stops_process(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded([sys.executable, "-c", "import time; time.sleep(3)"], timeout=.1)

    def test_stdin_that_is_never_read_is_covered_by_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded([sys.executable, "-c", "import time; time.sleep(3)"], input="x" * 65536, timeout=.1)

    def test_both_streams_and_utf8_input_are_preserved(self):
        result = run_bounded([sys.executable, "-c", "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'notice')"], input="ação", timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ação")
        self.assertEqual(result.stderr, "notice")

    def test_ssh_configuration_cannot_add_local_commands_or_forwarding(self):
        command = ssh_command_base("ssh", 22, known_hosts="known hosts")
        self.assertEqual(command[1:3], ["-F", "none"])
        for option in ["ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes", "PermitLocalCommand=no", "ControlMaster=no", "ProxyCommand=none", "StrictHostKeyChecking=yes"]:
            self.assertIn(option, command)
        self.assertIn('UserKnownHostsFile="known hosts"', command)


if __name__ == "__main__":
    unittest.main()
