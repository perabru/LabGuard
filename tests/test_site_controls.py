"""Persistent, explicit site toggles with real loopback DNS queries."""
from datetime import datetime, timezone
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from dnslib import A, AAAA, DNSRecord, QTYPE, RCODE, RR

from labguard.banlist import BanlistDatabase, BanlistError
from labguard.controller import ControllerTransport
from labguard.local_dns import LocalDNSTransport
from labguard.site_controls import apply_site_change, builtin_sites, filter_sites, site_rows


def snapshot(**extra):
    return {"mode": "equipment", "source_type": "local_dns", "timestamp": datetime.now(timezone.utc).isoformat(),
            "capabilities": {"domain_filtering": True}, "health": {"dns": True}, "domains": [],
            "gateway": {"hostname": "LabGuard DNS", "lab_cidr": "127.0.0.0/8"}, **extra}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class SitePresentationTests(unittest.TestCase):
    def test_packaged_catalog_is_visible_without_applying_or_seeding_it(self):
        rows = site_rows(snapshot())
        indexed = {row["domain"]: row for row in rows}
        self.assertEqual(len(builtin_sites()), 31)
        self.assertIn("poki.com", indexed)
        self.assertEqual(indexed["poki.com"]["category"], "Jogos")
        self.assertIn("xvideos.com", indexed)
        self.assertEqual(indexed["xvideos.com"]["category"], "Adultos")
        self.assertTrue(all(row["state"] == "Sem bloqueio neste filtro" for row in rows))
        self.assertTrue(all(row["can_block"] and not row["can_release"] for row in rows))

    def test_custom_inactive_records_and_filter_entries_remain_visible(self):
        rows = site_rows(snapshot(site_entries=[{"domain": "local.example", "category": "Outros", "enabled": False}]),
                         [{"domain": "school.example", "category": "Outros", "enabled": False}], catalog=())
        self.assertEqual([row["domain"] for row in rows], ["local.example", "school.example"])
        self.assertTrue(all(row["blocked"] is False for row in rows))

    def test_parent_and_ai_rules_cannot_be_mislabeled_as_released(self):
        data = snapshot(domains=[{"domain": "example.org", "source": "manual", "category": "Outros"},
                                 {"domain": "child.example.org", "source": "manual", "category": "Outros"}],
                        policies={"ai_block": {"enabled": True, "domains": ["openai.com"]}})
        rows = {row["domain"]: row for row in site_rows(data, catalog=(
            {"domain": "child.example.org", "category": "Outros"},
            {"domain": "chat.openai.com", "category": "Inteligência artificial"}))}
        self.assertEqual(rows["child.example.org"]["state"], "Bloqueado por domínio pai")
        self.assertFalse(rows["child.example.org"]["can_release"])
        self.assertEqual(rows["chat.openai.com"]["state"], "Bloqueado pelo perfil de IA")
        self.assertFalse(rows["chat.openai.com"]["can_release"])

    def test_parent_coverage_requires_a_complete_domain_suffix(self):
        data = snapshot(domains=[{"domain": "example.org", "source": "manual", "category": "Outros"}])
        row = next(row for row in site_rows(data, catalog=({"domain": "notexample.org", "category": "Outros"},))
                   if row["domain"] == "notexample.org")
        self.assertFalse(row["blocked"])
        self.assertTrue(row["can_block"])

    def test_external_parent_requires_confirmed_subdomain_scope(self):
        for scope, blocked, state in ((True, True, "Bloqueado por domínio pai"),
                                       (False, False, "Sem bloqueio neste filtro"),
                                       (None, None, "Sem confirmação")):
            with self.subTest(scope=scope):
                data = snapshot(domains=[{"domain": "example.org", "source": "external", "match_subdomains": scope}])
                row = next(row for row in site_rows(data, catalog=({"domain": "child.example.org", "category": "Outros"},))
                           if row["domain"] == "child.example.org")
                self.assertIs(row["blocked"], blocked)
                self.assertEqual(row["state"], state)
                self.assertIs(row["can_block"], scope is False)
                self.assertFalse(row["can_release"])

    def test_stale_or_observation_never_claims_an_unblocked_site(self):
        data = snapshot(domains=[{"domain": "poki.com", "source": "manual"}])
        for view, fresh in ((data, False), ({**data, "mode": "observation"}, True)):
            with self.subTest(mode=view["mode"], fresh=fresh):
                rows = site_rows(view, fresh=fresh)
                self.assertTrue(all(row["blocked"] is None for row in rows))
                self.assertTrue(all(not row["can_block"] and not row["can_release"] for row in rows))

    def test_external_duplicate_rules_are_visible_but_not_mutable(self):
        rows = site_rows(snapshot(domains=[{"domain": "x.example", "source": "external"},
                                          {"domain": "x.example", "source": "manual"}]), catalog=())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "Regras sobrepostas")
        self.assertFalse(rows[0]["can_block"] or rows[0]["can_release"])

    def test_search_category_and_state_can_find_demonstration_site(self):
        rows = site_rows(snapshot(domains=[{"domain": "poki.com", "source": "manual", "category": "Jogos"}]))
        selected = filter_sites(rows, query="PoKi", category="Jogos", state="Bloqueados")
        self.assertEqual([row["domain"] for row in selected], ["poki.com"])
        self.assertEqual(filter_sites(rows, query="poki", state="Sem bloqueio"), [])


class PersistentSiteControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.observation = patch("labguard.discovery.LocalObservationTransport.request",
                                 return_value={"devices": [], "interfaces": []})
        self.observation.start()
        self.port = free_port()
        self.database = BanlistDatabase(self.root / "policy" / "policy.sqlite3")
        self.start_transport()

    def start_transport(self):
        self.raw = LocalDNSTransport(host="127.0.0.1", lab_cidr="127.0.0.0/8", port=self.port,
                                     manage_rules=True, data_dir=self.root / "filter")
        self.transport = ControllerTransport("local_dns", self.raw)
        self.forward = patch.object(self.raw.filter, "_forward", side_effect=self.allowed_answer)
        self.forward.start()

    @staticmethod
    def allowed_answer(question, _tcp):
        reply = question.reply()
        if question.q.qtype == QTYPE.A:
            reply.add_answer(RR(question.q.qname, QTYPE.A, rdata=A("192.0.2.10")))
        elif question.q.qtype == QTYPE.AAAA:
            reply.add_answer(RR(question.q.qname, QTYPE.AAAA, rdata=AAAA("2001:db8::10")))
        return reply

    def tearDown(self):
        self.forward.stop()
        self.transport.close()
        self.database.close()
        self.observation.stop()
        self.temp.cleanup()

    def query(self, name, kind):
        return DNSRecord.parse(DNSRecord.question(name, kind).send("127.0.0.1", self.port, timeout=2))

    def change(self, domain="poki.com", blocked=True, category="Jogos"):
        return apply_site_change(self.transport, self.database, domain=domain, category=category, blocked=blocked)

    def test_before_after_release_and_reblock_affect_a_and_aaaa_and_keep_records(self):
        for kind in ("A", "AAAA"):
            self.assertEqual(self.query("poki.com", kind).header.rcode, RCODE.NOERROR)
        for blocked in (True, False, True, False):
            report = self.change(blocked=blocked)
            for kind in ("A", "AAAA"):
                response = self.query("poki.com", kind)
                self.assertEqual(response.header.rcode, RCODE.NXDOMAIN if blocked else RCODE.NOERROR)
            row = next(row for row in site_rows(report["snapshot"], self.database.list_sites()) if row["domain"] == "poki.com")
            self.assertEqual(row["blocked"], blocked)
            self.assertEqual(self.database.list_sites()[0]["enabled"], blocked)
            self.assertFalse(self.database.list_sites()[0]["deleted"])
            self.assertEqual(report["warning"], "")
        sync = self.database.sync(self.transport)
        self.assertEqual(sync["applied"], [])
        self.assertEqual(self.database.summary()["pending"], 0)
        self.assertEqual(self.query("poki.com", "AAAA").header.rcode, RCODE.NOERROR)

    def test_restart_and_starter_policy_do_not_reactivate_a_released_site(self):
        self.change(blocked=True)
        self.change(blocked=False)
        self.forward.stop(); self.transport.close()
        self.start_transport()
        after = self.transport.request("snapshot")
        self.assertNotIn("poki.com", {row["domain"] for row in after["domains"]})
        self.assertTrue(any(row["domain"] == "poki.com" and row["enabled"] is False for row in after["site_entries"]))
        after = self.transport.request("apply_school_policy", authorized=True,
                                       expected_token=after["dns_service"]["check_token"])
        self.assertNotIn("poki.com", {row["domain"] for row in after["domains"]})
        self.assertEqual(self.query("poki.com", "A").header.rcode, RCODE.NOERROR)
        self.assertEqual(self.database.sync(self.transport)["applied"], [])

    def test_custom_domain_stays_in_filter_catalog_after_release(self):
        self.change("new.example", True, "Outros")
        report = self.change("new.example", False, "Outros")
        stored = next(row for row in report["snapshot"]["site_entries"] if row["domain"] == "new.example")
        self.assertFalse(stored["enabled"])
        row = next(row for row in site_rows(report["snapshot"], catalog=()) if row["domain"] == "new.example")
        self.assertEqual(row["state"], "Sem bloqueio neste filtro")
        self.assertTrue(row["can_block"])

    def test_new_catalog_render_does_not_write_rules_or_database(self):
        before = self.transport.request("snapshot")
        site_rows(before, self.database.list_sites())
        self.assertEqual(self.raw.database.list_sites(), [])
        self.assertEqual(self.database.list_sites(), [])
        self.assertEqual(self.transport.request("snapshot")["domains"], [])

    def test_parent_release_is_explicit_and_child_is_not_falsely_released(self):
        self.change("example.org", True, "Outros")
        self.change("child.example.org", True, "Outros")
        with self.assertRaises(BanlistError):
            self.change("child.example.org", False, "Outros")
        self.assertEqual(self.query("child.example.org", "AAAA").header.rcode, RCODE.NXDOMAIN)
        self.change("example.org", False, "Outros")
        self.change("child.example.org", False, "Outros")
        self.assertEqual(self.query("child.example.org", "AAAA").header.rcode, RCODE.NOERROR)

    def test_transport_failure_records_uncertainty_without_claiming_release(self):
        self.change(blocked=True)
        real = self.transport.request
        def fail(action, **params):
            if action == "remove_domain":
                raise OSError("connection lost before mutation")
            return real(action, **params)
        with patch.object(self.transport, "request", side_effect=fail), self.assertRaises(OSError):
            self.change(blocked=False)
        self.assertEqual(self.query("poki.com", "A").header.rcode, RCODE.NXDOMAIN)
        self.assertFalse(self.database.list_sites()[0]["enabled"])
        self.assertEqual(self.database.summary()["uncertain"], 1)
        row = next(row for row in site_rows(real("snapshot"), self.database.list_sites()) if row["domain"] == "poki.com")
        self.assertEqual(row["state"], "Bloqueado neste filtro")

    def test_batch_sync_lease_prevents_an_overlapping_toggle(self):
        import time
        with self.database._connection(write=True) as db:
            db.execute("INSERT INTO sync_lease(id,owner,expires) VALUES(1,?,?)", ("other", time.time() + 60))
        with self.assertRaises(BanlistError):
            self.change()
        self.assertEqual(self.raw.database.list_sites(), [])


class SiteSelectionGuardTests(unittest.TestCase):
    def test_expired_snapshot_cannot_trigger_selected_block(self):
        from tests.test_simple_gui import SimpleUiTests
        app = SimpleUiTests.app(domain_filtering=True)
        app._snapshot_stale = True
        app.domains_table = Mock(selection=Mock(return_value=("poki.com",)))
        app._domain_rows = {"poki.com": {"domain": "poki.com", "category": "Jogos", "can_block": True}}
        app._change_site = Mock()
        self.assertFalse(app._change_selected_site(True))
        app._change_site.assert_not_called()

    def test_profile_or_parent_covered_row_explains_why_release_is_disabled(self):
        from tests.test_simple_gui import SimpleUiTests
        app = SimpleUiTests.app(domain_filtering=True)
        app.domains_table = Mock(selection=Mock(return_value=("child.example",)))
        app._domain_rows = {"child.example": {"can_release": False, "detail": "Revise o domínio pai."}}
        app._change_site = Mock()
        self.assertFalse(app._change_selected_site(False))
        app._change_site.assert_not_called()
        app.status.set.assert_called_with("Revise o domínio pai.")


class GatewayCompatibilityTests(unittest.TestCase):
    def test_custom_gateway_category_can_be_released_and_reblocked(self):
        from labguard.demo import DemoTransport
        transport = DemoTransport()
        transport.request("add_domain", domain="social.example.test", category="Redes sociais")
        with tempfile.TemporaryDirectory() as folder:
            database = BanlistDatabase(Path(folder) / "policy.sqlite3")
            try:
                released = apply_site_change(transport, database, domain="social.example.test", category="Redes sociais", blocked=False)
                self.assertNotIn("social.example.test", {row["domain"] for row in released["snapshot"]["domains"]})
                self.assertEqual(database.list_sites()[0]["category"], "Outros")
                self.assertFalse(database.list_sites()[0]["enabled"])
                restored = apply_site_change(transport, database, domain="social.example.test", category="Redes sociais", blocked=True)
                row = next(row for row in restored["snapshot"]["domains"] if row["domain"] == "social.example.test")
                self.assertEqual(row["category"], "Redes sociais")
                self.assertEqual(database.sync(transport)["applied"], [])
            finally:
                database.close()

    def test_explicit_block_of_existing_rule_is_idempotent_and_preserves_metadata(self):
        from labguard.demo import DemoTransport
        transport = DemoTransport()
        before = next(row for row in transport.request("snapshot")["domains"] if row["domain"] == "poki.com")
        with tempfile.TemporaryDirectory() as folder:
            database = BanlistDatabase(Path(folder) / "policy.sqlite3")
            try:
                after = apply_site_change(transport, database, domain="poki.com", category="Outros", blocked=True)
                row = next(row for row in after["snapshot"]["domains"] if row["domain"] == "poki.com")
                self.assertEqual(row, before)
                self.assertTrue(database.list_sites()[0]["enabled"])
                self.assertEqual(database.summary()["uncertain"], 0)
            finally:
                database.close()


if __name__ == "__main__":
    unittest.main()
