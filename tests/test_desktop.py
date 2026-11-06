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
