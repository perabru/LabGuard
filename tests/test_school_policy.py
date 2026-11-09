import tempfile
import unittest
from unittest.mock import Mock, patch

from dnslib import DNSRecord, RCODE

from labguard.banlist import BanlistError
from labguard.controller import ControllerError, ControllerTransport
from labguard.local_dns import LocalDNSTransport, DNSError
from labguard.school_policy import SCHOOL_POLICY, apply_school_policy, sample_blocked_domain
from test_local_dns import free_port


class SchoolPolicyTests(unittest.TestCase):
    def setUp(self):
        data = tempfile.TemporaryDirectory()
        self.addCleanup(data.cleanup)
        self.raw = LocalDNSTransport(host="127.0.0.1", lab_cidr="127.0.0.0/8", data_dir=data.name,
                                     port=free_port(), manage_rules=True)
        self.raw._observation.request = Mock(return_value={"devices": [], "interfaces": []})
        self.control = ControllerTransport("local_dns", self.raw)
        self.addCleanup(self.control.close)
        self.token = self.raw.filter.check_token
        self.domains = {domain for domain, _ in SCHOOL_POLICY}

    def apply(self, transport=None):
        return apply_school_policy(transport or self.control, authorized=True, expected_token=self.token)

    def test_real_filter_preserves_rules_categories_and_idempotence(self):
        self.control.request("add_domain", domain="roblox.com", category="Outros")
        self.control.request("add_domain", domain="custom.example", category="Inteligência artificial")
        result = self.apply()
        self.assertTrue(result["ok"])
        self.assertEqual(set(result["added"]), self.domains - {"roblox.com"})
        self.assertEqual(result["already_present"], ["roblox.com"])
        domains = {row["domain"]: row["category"] for row in self.control.request("snapshot")["domains"]}
        self.assertEqual(domains["roblox.com"], "Outros")
        self.assertEqual(domains["custom.example"], "Inteligência artificial")
        for host, kind in (("assets.rbxcdn.com", "A"), ("www.xvideos.com", "AAAA")):
            q = DNSRecord.question(host, kind)
            self.assertEqual(DNSRecord.parse(q.send("127.0.0.1", self.raw.port, timeout=2)).header.rcode, RCODE.NXDOMAIN)
        with patch.object(self.raw.database, "import_domains", side_effect=AssertionError("unexpected write")):
            repeat = self.apply()
        self.assertTrue(repeat["ok"])
        self.assertEqual(repeat["added"], [])
        self.assertEqual(set(repeat["already_present"]), self.domains)

    def test_manual_removal_stays_removed_across_repeated_application(self):
        self.apply()
        self.control.request("remove_domain", domain="roblox.com")
        result = self.apply()
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing"], ["roblox.com"])
        self.assertEqual(result["added"], [])
        self.assertNotIn("roblox.com", self.raw._rules)

    def test_concurrent_manual_add_wins_without_category_overwrite(self):
        def call(action, **params):
            if action == "apply_school_policy":
                self.control.request("add_domain", domain="poki.com", category="Outros")
            return self.control.request(action, **params)
        proxy = Mock(kind="local_dns")
        proxy.request.side_effect = call
        result = self.apply(proxy)
        self.assertTrue(result["ok"])
        self.assertIn("poki.com", result["already_present"])
        self.assertNotIn("poki.com", result["added"])
        self.assertEqual(self.raw._rules["poki.com"], "Outros")

    def test_partial_failure_is_re_read_and_retry_only_fills_missing(self):
        original = self.raw.database.import_domains
        def fail_second(domains, *, category):
            if category == "Adultos":
                raise BanlistError("Write failed")
            return original(domains, category=category)
        with patch.object(self.raw.database, "import_domains", side_effect=fail_second):
            partial = self.apply()
        self.assertFalse(partial["ok"])
        self.assertEqual(set(partial["missing"]), {domain for domain, cat in SCHOOL_POLICY if cat == "Adultos"})
        self.assertEqual(partial["unconfirmed"], [])
        retry = self.apply()
        self.assertTrue(retry["ok"])
        self.assertEqual(set(retry["added"]), set(partial["missing"]))

    def test_failed_confirmation_never_reports_a_verified_block(self):
        reads = 0
        def call(action, **params):
            nonlocal reads
            if action == "snapshot":
                reads += 1
                if reads == 2:
                    raise DNSError("closed")
            return self.control.request(action, **params)
        proxy = Mock(kind="local_dns")
        proxy.request.side_effect = call
        result = self.apply(proxy)
        self.assertFalse(result["ok"])
        self.assertEqual(result["added"], [])
        self.assertEqual(set(result["unconfirmed"]), self.domains)
        self.assertEqual(result["missing"], [])

    def test_wrong_source_authority_or_session_cannot_write(self):
        for kind, auth, token in (("routeros", True, self.token), ("local_dns", False, self.token),
                                  ("local_dns", True, "LabGuard-0000000000000000")):
            proxy = self.control if kind == "local_dns" else Mock(kind=kind)
            with self.subTest(kind=kind, auth=auth), self.assertRaises(ControllerError):
                apply_school_policy(proxy, authorized=auth, expected_token=token)
        with self.assertRaises(DNSError):
            self.control.request("apply_school_policy", authorized=True, expected_token="other")
        self.assertEqual(self.raw._rules, {})

    def test_select_only_an_applied_site_and_prefer_roblox(self):
        self.assertIsNone(sample_blocked_domain({"domains": [{"domain":"fake.invalid"},{"domain":"example.com","enabled":False}]}))
        snapshot = {"domains":[{"domain":"manual.example"}, {"domain":"poki.com"}]}
        self.assertEqual(sample_blocked_domain(snapshot), "poki.com")
        snapshot["domains"].append({"domain":"roblox.com"})
        self.assertEqual(sample_blocked_domain(snapshot), "roblox.com")


if __name__ == "__main__":
    unittest.main()
