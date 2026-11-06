import copy
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("labguard_gateway", Path(__file__).parents[1] / "gateway" / "agent.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def config_data(directory):
    return {"lab_cidr": "192.168.50.0/24", "gateway_ip": "192.168.50.1",
            "lan_interface": "enp2s0", "wan_interface": "enp1s0",
            "dhcp_start": "192.168.50.100", "dhcp_end": "192.168.50.220",
            "protected_ips": ["192.168.50.10"], "upstream_dns": ["1.1.1.1"],
            "state_dir": str(Path(directory) / "state"), "log_dir": str(Path(directory) / "log"),
            "dnsmasq_config": str(Path(directory) / "dnsmasq.conf")}


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.table = True
        self.fail_restarts = 0
        self.fail_apply = False
        self.ruleset = "table inet other {}"
        self.kernel_ips = []
        self.neighbors = [{"dst": "192.168.50.101", "lladdr": "02:00:00:00:00:01", "state": ["REACHABLE"]}]

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        rc, stdout, stderr = 0, "", ""
        if args[:3] == ["nft", "list", "table"]:
            rc = 0 if self.table else 1
        elif args == ["nft", "list", "ruleset"]:
            stdout = self.ruleset
        elif args == ["nft", "-j", "list", "set", "inet", "labguard", "blocked_v4"]:
            stdout = json.dumps({"nftables": [{"set": {"name": "blocked_v4", "elem": self.kernel_ips}}]})
        elif args[:3] == ["ip", "-j", "neigh"]:
            stdout = json.dumps(self.neighbors)
        elif args[:2] == ["systemctl", "restart"] and self.fail_restarts:
            self.fail_restarts -= 1
            rc, stderr = 1, "DNS failed to start"
        elif args == ["nft", "-f", "-"] and self.fail_apply:
            self.fail_apply = False
            rc, stderr = 1, "mock nft failure"
        elif args == ["nft", "-f", "-"]:
            section = re.search(r"set blocked_v4 \{(.*?)\}", kwargs.get("input", ""), re.S)
            self.kernel_ips = re.findall(r"\b192\.168\.50\.\d+\b", section.group(1)) if section else []
        return subprocess.CompletedProcess(args, rc, stdout, stderr)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = config_data(self.temp.name)
        self.catalog_path = Path(self.temp.name) / "ai_services.json"
        self.catalog = {"version": 1, "updated_at": "2026-11-06", "services": [
            {"name": "Chat de teste", "domains": ["chatgpt.example", "api.chatgpt.example"], "source_url": "https://docs.example/chat"},
            {"name": "Outro chat", "domains": ["claude.example", "api.chatgpt.example"], "source_url": "https://docs.example/other"},
        ]}
        self.catalog_path.write_text(json.dumps(self.catalog))
        self.catalog_patch = patch.object(g, "AI_CATALOG", self.catalog_path)
        self.catalog_patch.start()
        self.addCleanup(self.catalog_patch.stop)
        self.config = g.Config(self.data)
        self.runner = FakeRunner()
        self.agent = g.Agent(self.config, self.runner)

    def request(self, action, **params):
        return self.agent.handle({"version": 1, "action": action, "params": params})

    def test_rejects_config_injection_and_nonprivate_network(self):
        for fields in ({"lan_interface": 'enp2s0"; flush ruleset'}, {"log_dir": "/tmp/x\nserver=evil"},
                       {"lab_cidr": "127.0.0.0/24", "gateway_ip": "127.0.0.1", "dhcp_start": "127.0.0.100", "dhcp_end": "127.0.0.200", "protected_ips": []},
                       {"upstream_dns": ["192.168.50.3"]}, {"protected_ips": ["192.168.50.105"]}):
            with self.subTest(fields=fields):
                with self.assertRaises(g.AgentError):
                    g.Config(dict(self.data, **fields))

    def test_domains_subdomains_and_dns_types_use_nxdomain_directive(self):
        state = g.default_state()
        state["domains"] = [{"domain": "games.example", "category": "Jogos"}]
        rendered = g.render_dnsmasq(self.config, state)
        self.assertIn("server=/games.example/\n", rendered)
        self.assertNotIn("address=/", rendered)
        self.assertIn("log-queries=extra", rendered)
        self.assertIn("dhcp-option=option:router,192.168.50.1", rendered)

    def test_domain_input_rejects_url_wildcard_ip_and_newline(self):
        for value in ("https://game.example", "*.game.example", "1.2.3.4", "game.123", "evil.example\nserver=8.8.8.8", "game.example/path", "game.example:53", "com", "-game.example"):
            with self.subTest(value=value):
                with self.assertRaises(g.AgentError):
                    g.domain_name(value)
        self.assertEqual(g.domain_name("EXAMPLE.COM."), "example.com")
        self.assertEqual(g.domain_name("jogos.ação.com"), "jogos.xn--ao-siap.com")

    def test_cuts_precede_established_and_only_managed_table_changes(self):
        state = g.default_state()
        state["blocked"] = {"192.168.50.101": {"mac": "02:00:00:00:00:01"}}
        nft = g.render_nft(self.config, state, True)
        self.assertTrue(nft.startswith("delete table inet labguard\n"))
        self.assertNotIn("flush ruleset", nft)
        for needle in ("ether saddr @blocked_mac counter drop", "ip saddr @blocked_v4 counter drop", "ip daddr @blocked_v4 counter drop", "meta nfproto ipv6 counter drop"):
            self.assertLess(nft.index(needle), nft.index("\n    ct state established,related accept"))
        self.assertIn('oifname "enp2s0" counter drop', nft)
        self.assertIn("udp dport 53 redirect", nft)
        self.assertIn("tcp dport 53 redirect", nft)
        self.assertIn("udp dport 853 counter reject", nft)

    def test_protected_unknown_and_out_of_scope_machines_are_refused(self):
        for ip in ("192.168.50.1", "192.168.50.10", "192.168.50.0", "192.168.50.255", "192.168.51.101", "192.168.50.150"):
            with self.subTest(ip=ip):
                with self.assertRaises(g.AgentError):
                    self.request("set_device_block", ip=ip, blocked=True)
        self.assertFalse(any(args[:2] == ["nft", "-f"] for args, _ in self.runner.calls))

    def test_machine_cut_is_persisted_and_can_be_released(self):
        result = self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.assertTrue(result["devices"][0]["blocked"])
        saved = self.agent.load_state()
        self.assertEqual(saved["blocked"]["192.168.50.101"]["mac"], "02:00:00:00:00:01")
        result = self.request("set_device_block", ip="192.168.50.101", blocked=False)
        self.assertFalse(result["devices"][0]["blocked"])
        self.assertEqual(self.agent.load_state()["blocked"], {})

    def test_bool_strings_and_arbitrary_actions_are_refused(self):
        for action, params in (("set_device_block", {"ip": "192.168.50.101", "blocked": "false"}),
                               ("snapshot", {"shell": "whoami"}), ("exec", {})):
            with self.subTest(action=action):
                with self.assertRaises(g.AgentError):
                    self.request(action, **params)

    def test_failed_dns_restart_restores_previous_config_and_state(self):
        previous = g.default_state()
        self.agent.save_state(previous)
        original = g.render_dnsmasq(self.config, previous)
        g.atomic_write(self.config.dnsmasq_config, original)
        self.runner.fail_restarts = 1
        with self.assertRaisesRegex(g.AgentError, "anterior foi restaurada"):
            self.request("add_domain", domain="games.example", category="Jogos")
        self.assertEqual(self.config.dnsmasq_config.read_text(), original)
        self.assertEqual(self.agent.load_state(), previous)
        self.assertEqual(sum(args == ["systemctl", "restart", "labguard-dnsmasq"] for args, _ in self.runner.calls), 2)

    def test_failed_firewall_apply_restores_previous_state(self):
        previous = g.default_state()
        self.agent.save_state(previous)
        self.runner.fail_apply = True
        with self.assertRaisesRegex(g.AgentError, "anterior foi restaurada"):
            self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.assertEqual(self.agent.load_state(), previous)
        nft_writes = [kwargs["input"] for args, kwargs in self.runner.calls if args == ["nft", "-f", "-"]]
        self.assertIn("192.168.50.101", nft_writes[0])
        self.assertNotIn("192.168.50.101", nft_writes[-1])

    def test_flowtable_refuses_cut_without_removing_external_rules(self):
        self.runner.ruleset = "table inet external { flowtable fast { hook ingress priority 0; } }"
        with self.assertRaisesRegex(g.AgentError, "Desative flowtable"):
            self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.assertNotIn("192.168.50.101", self.agent.load_state()["blocked"])
        self.assertFalse(any("external" in str(kwargs.get("input", "")) for _, kwargs in self.runner.calls))

    def test_mac_block_follows_changed_ip_but_does_not_cut_reallocated_ip(self):
        state = g.default_state()
        state["blocked"] = {"192.168.50.101": {"mac": "02:00:00:00:00:01", "name": "Old"}}
        self.runner.neighbors = [{"dst": "192.168.50.101", "lladdr": "02:00:00:00:00:02", "state": ["REACHABLE"]},
                                 {"dst": "192.168.50.102", "lladdr": "02:00:00:00:00:01", "state": ["REACHABLE"]}]
        devices, _ = self.agent.devices(state)
        self.assertFalse(next(row for row in devices if row["ip"].endswith(".101"))["blocked"])
        self.assertTrue(next(row for row in devices if row["ip"].endswith(".102"))["blocked"])
        self.assertEqual(self.agent.current_block_ips(state), ["192.168.50.102"])

    def test_query_log_correlates_serials_not_current_rules(self):
        text = "\n".join([
            "Nov  6 12:00:01 dnsmasq[12]: 1 192.168.50.101/123 query[A] games.example from 192.168.50.101",
            "Nov  6 12:00:01 dnsmasq[12]: 2 192.168.50.102/125 query[AAAA] allowed.example from 192.168.50.102",
            "Nov  6 12:00:01 dnsmasq[12]: 1 192.168.50.101/123 config games.example is NXDOMAIN",
            "Nov  6 12:00:01 dnsmasq[12]: 2 192.168.50.102/125 reply allowed.example is 203.0.113.10",
            "Nov  6 12:00:01 dnsmasq[12]: 3 192.168.99.1/125 query[A] other.example from 192.168.99.1",
        ])
        events = g.parse_events(text, self.config.network)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["status"], "Consulta")
        self.assertEqual(events[1]["status"], "Bloqueio DNS confirmado")
        self.assertEqual(events[1]["client_ip"], "192.168.50.101")

    def test_connections_only_external_original_direction_in_lab(self):
        text = "\n".join([
            "ipv4 2 tcp 6 120 ESTABLISHED src=192.168.50.101 dst=203.0.113.7 sport=52000 dport=443 src=203.0.113.7 dst=192.168.1.2 sport=443 dport=52000 [ASSURED]",
            "ipv4 2 udp 17 60 src=192.168.50.101 dst=192.168.50.1 sport=52000 dport=53",
            "ipv4 2 udp 17 60 src=192.168.99.101 dst=203.0.113.2 sport=52000 dport=53",
        ])
        rows = g.parse_connections(text, self.config)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["destination_ip"], "203.0.113.7")
        self.assertEqual(rows[0]["port"], 443)

    def test_boot_apply_does_not_restart_dns_service(self):
        self.agent.apply_startup()
        self.assertTrue(self.config.dnsmasq_config.exists())
        self.assertFalse(any(args[:2] == ["systemctl", "restart"] for args, _ in self.runner.calls))

    def test_snapshot_reconciles_dhcp_change_in_applied_firewall(self):
        self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.assertEqual(self.runner.kernel_ips, ["192.168.50.101"])
        self.runner.neighbors = [{"dst": "192.168.50.101", "lladdr": "02:00:00:00:00:02", "state": ["REACHABLE"]},
                                 {"dst": "192.168.50.102", "lladdr": "02:00:00:00:00:01", "state": ["REACHABLE"]}]
        self.request("snapshot")
        self.assertEqual(self.runner.kernel_ips, ["192.168.50.102"])

    def test_reallocated_ip_does_not_overwrite_previous_mac_policy(self):
        self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.runner.neighbors = [{"dst": "192.168.50.101", "lladdr": "02:00:00:00:00:02", "state": ["REACHABLE"]},
                                 {"dst": "192.168.50.102", "lladdr": "02:00:00:00:00:01", "state": ["REACHABLE"]}]
        result = self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.assertEqual(len(self.agent.load_state()["blocked"]), 2)
        self.assertTrue(all(row["blocked"] for row in result["devices"]))
        result = self.request("set_device_block", ip="192.168.50.101", blocked=False)
        self.assertFalse(next(row for row in result["devices"] if row["ip"].endswith(".101"))["blocked"])
        self.assertTrue(next(row for row in result["devices"] if row["ip"].endswith(".102"))["blocked"])

    def test_protected_ip_exemption_precedes_mac_drop(self):
        rendered = g.render_nft(self.config, g.default_state())
        self.assertLess(rendered.index("192.168.50.10"), rendered.index("ether saddr @blocked_mac"))

    def test_reconcile_failure_is_visible_health_error(self):
        self.request("set_device_block", ip="192.168.50.101", blocked=True)
        self.runner.kernel_ips = []
        self.runner.fail_apply = True
        result = self.request("snapshot")
        self.assertFalse(result["health"]["firewall"])
        self.assertTrue(any("Falha ao sincronizar" in warning for warning in result["warnings"]))

    def test_malformed_saved_state_is_reported_not_traceback(self):
        for replacement in ({"domains": ["not-a-dict"]}, {"domains": [{"domain": "games.example", "category": []}]},
                            {"blocked": {"192.168.50.101": "not-a-dict"}}, {"blocked": {"192.168.50.101": {"mac": ["bad"]}}},
                            {"audit": ["not-a-dict"]}):
            state = g.default_state()
            state.update(replacement)
            self.agent.save_state(state)
            with self.subTest(replacement=replacement):
                with self.assertRaises(g.AgentError):
                    self.agent.load_state()

    def test_encrypted_dns_restriction_includes_protected_ip(self):
        rendered = g.render_nft(self.config, g.default_state())
        self.assertLess(rendered.index("udp dport 853 counter reject"), rendered.index("ip saddr {"))

    def test_bounded_log_tail_drops_partial_first_line(self):
        path = Path(self.temp.name) / "logfile"
        path.write_text("first full line\nsecond full line\nthird line\n")
        self.assertEqual(g.read_tail(path, 20), "third line\n")

    def test_ai_profile_toggle_applies_all_domains_once_and_persists(self):
        result = self.request("set_ai_block", enabled=True)
        policy = result["policies"]["ai_block"]
        self.assertTrue(policy["enabled"])
        self.assertEqual(policy["domain_count"], 3)
        self.assertEqual(len(policy["services"]), 2)
        self.assertTrue(self.agent.load_state()["ai_block_enabled"])
        rendered = self.config.dnsmasq_config.read_text()
        for domain in policy["domains"]:
            self.assertEqual(rendered.count(f"server=/{domain}/\n"), 1)
        self.assertEqual(sum(args == ["systemctl", "restart", "labguard-dnsmasq"] for args, _ in self.runner.calls), 1)
        self.assertTrue(all(row["source"] == "ai_profile" for row in result["domains"]))
        self.assertEqual(result["audit"][0]["action"], "Ativar bloqueio de IA")

    def test_ai_profile_disabling_preserves_manual_overlapping_domains(self):
        self.request("add_domain", domain="chatgpt.example", category="Regra manual")
        enabled = self.request("set_ai_block", enabled=True)
        overlap = next(row for row in enabled["domains"] if row["domain"] == "chatgpt.example")
        self.assertEqual(overlap["source"], "manual")
        result = self.request("set_ai_block", enabled=False)
        self.assertFalse(result["policies"]["ai_block"]["enabled"])
        self.assertEqual([row["domain"] for row in result["domains"]], ["chatgpt.example"])
        rendered = self.config.dnsmasq_config.read_text()
        self.assertIn("server=/chatgpt.example/", rendered)
        self.assertNotIn("server=/claude.example/", rendered)

    def test_ai_profile_failed_dns_restart_restores_state_and_rules(self):
        previous = g.default_state()
        self.agent.save_state(previous)
        original = g.render_dnsmasq(self.config, previous)
        g.atomic_write(self.config.dnsmasq_config, original)
        self.runner.fail_restarts = 1
        with self.assertRaisesRegex(g.AgentError, "anterior foi restaurada"):
            self.request("set_ai_block", enabled=True)
        self.assertEqual(self.agent.load_state(), previous)
        self.assertEqual(self.config.dnsmasq_config.read_text(), original)

    def test_ai_state_migrates_old_files_and_rejects_non_boolean_flag(self):
        old = g.default_state()
        old.pop("ai_block_enabled")
        self.agent.save_state(old)
        self.assertFalse(self.agent.load_state()["ai_block_enabled"])
        for value in ("false", 1, None, []):
            invalid = dict(old, ai_block_enabled=value)
            self.agent.save_state(invalid)
            with self.subTest(value=value), self.assertRaises(g.AgentError):
                self.agent.load_state()

    def test_ai_api_requires_boolean_and_exact_parameters(self):
        for params in ({}, {"enabled": "true"}, {"enabled": 1}, {"enabled": True, "domains": ["injected.example"]}):
            with self.subTest(params=params), self.assertRaises(g.AgentError):
                self.request("set_ai_block", **params)
        self.assertFalse(any(args[:2] == ["systemctl", "restart"] for args, _ in self.runner.calls))

    def test_disabled_ai_profile_is_visible_but_does_not_block_domains(self):
        result = self.request("snapshot")
        self.assertFalse(result["policies"]["ai_block"]["enabled"])
        self.assertEqual(result["policies"]["ai_block"]["domain_count"], 3)
        self.assertEqual(result["domains"], [])

    def test_profile_owned_domain_requires_disabling_profile(self):
        self.request("set_ai_block", enabled=True)
        with self.assertRaisesRegex(g.AgentError, "Desative o perfil IA"):
            self.request("remove_domain", domain="claude.example")
        self.assertTrue(self.agent.load_state()["ai_block_enabled"])

    def test_ai_catalog_rejects_injection_invalid_json_and_oversize(self):
        invalid = copy.deepcopy(self.catalog)
        invalid["services"][0]["domains"] = ["bad.example\nserver=evil"]
        self.catalog_path.write_text(json.dumps(invalid))
        with self.assertRaises(g.AgentError):
            g.load_ai_catalog()
        self.catalog_path.write_text("{")
        with self.assertRaisesRegex(g.AgentError, "catálogo"):
            g.load_ai_catalog()
        self.catalog_path.write_bytes(b" " * (g.MAX_AI_CATALOG_BYTES + 1))
        with self.assertRaisesRegex(g.AgentError, "tamanho"):
            g.load_ai_catalog()


if __name__ == "__main__":
    unittest.main()
