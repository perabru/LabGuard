"""SQLite intent and ownership checks; no sockets or privileged operations."""
from __future__ import annotations

import copy
from contextlib import closing
import csv
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from labguard.banlist import BanlistDatabase, BanlistError, _journal_mode
from labguard.demo import DemoTransport


class RecordingTransport(DemoTransport):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.host = "gateway.school.example"
        self.port = 22
        self.fail_domain = None
        self.fail_after_mutation = False

    def request(self, action, **params):
        self.calls.append((action, copy.deepcopy(params)))
        if action != "snapshot" and self.fail_domain is not None and params.get("domain") == self.fail_domain:
            if self.fail_after_mutation:
                super().request(action, **params)
            raise RuntimeError("sensitive-password-that-must-not-appear")
        return super().request(action, **params)

    @property
    def mutations(self):
        return [(action, params) for action, params in self.calls if action != "snapshot"]


class BanlistTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "private" / "sites.sqlite3"
        self.store = BanlistDatabase(self.path)
        self.transport = RecordingTransport()

    def test_crud_normalization_persistence_and_revision_conflicts(self):
        first = self.store.upsert(" BÜCHER.example. ", "IA", notes="Uso em avaliação", expected_revision=0)
        self.assertEqual(first["domain"], "xn--bcher-kva.example")
        self.assertEqual(first["category"], "Inteligência artificial")
        self.assertTrue(first["enabled"])
        with self.assertRaises(BanlistError):
            self.store.upsert(first["domain"], expected_revision=0)
        second = self.store.upsert(first["domain"], "Jogos", enabled=False, expected_revision=1)
        self.assertEqual((second["id"], second["revision"]), (first["id"], 2))
        self.assertEqual(self.store.list_sites(enabled=False), [second])
        with self.assertRaises(BanlistError):
            self.store.delete(first["domain"], expected_revision=1)
        removed = self.store.delete(first["domain"], expected_revision=2)
        self.assertTrue(removed["deleted"])
        self.assertFalse(removed["enabled"])
        self.assertEqual(self.store.list_sites(), [])
        self.assertEqual(BanlistDatabase(self.path).list_sites(include_deleted=True), [removed])
        restored = self.store.upsert(first["domain"], expected_revision=3)
        self.assertFalse(restored["deleted"])
        self.assertEqual(restored["revision"], 4)
        self.assertEqual(self.transport.mutations, [])

    def test_sql_parameters_and_validation(self):
        note = "'); DROP TABLE sites; --"
        self.store.upsert("safe.example", notes=note)
        self.assertEqual(self.store.list_sites()[0]["notes"], note)
        self.assertEqual(self.store.list_sites(query="' OR 1=1 --"), [])
        self.assertEqual(len(self.store.list_sites(category="Outros")), 1)
        for value in ("https://bad.example", "1.2.3.4", "bad.example;DROP", "*.bad.example", None):
            with self.subTest(value=value), self.assertRaises(BanlistError):
                self.store.upsert(value)
        for kwargs in ({"enabled": 1}, {"notes": "x" * 501}, {"notes": "bad\x00"}, {"category": "Unknown"}, {"expected_revision": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(BanlistError):
                self.store.upsert("bad.example", **kwargs)
        for kwargs in ({"limit": 50001}, {"offset": -1}, {"enabled": 1}, {"include_deleted": 1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(BanlistError):
                self.store.list_sites(**kwargs)

    def test_import_deduplicates_and_preserves_existing_disabled_intent(self):
        existing = self.store.upsert("existing.example", "Adultos", enabled=False, notes="Revisão")
        report = self.store.import_domains(["NEW.example", "new.example.", "invalid", "existing.example"], "Jogos")
        self.assertEqual(report["added"], ["new.example"])
        self.assertEqual(report["existing"], ["existing.example"])
        self.assertEqual(report["errors"], [{"index": 3, "message": "Domínio inválido"}])
        self.assertEqual(self.store.list_sites(query="existing"), [existing])
        with self.assertRaises(BanlistError):
            self.store.import_domains(["large.example"] * 1001)
        with patch("labguard.banlist.MAX_SITES", 3), self.assertRaises(BanlistError):
            self.store.import_domains(["overflow.example", "overflow2.example"])
        self.assertFalse(self.store.list_sites(query="overflow"))

    def test_supported_journaling_and_bounded_audit_retention(self):
        for version, expected in (((3, 40, 1), "DELETE"), ((3, 51, 2), "DELETE"), ((3, 51, 3), "WAL"), ((3, 50, 7), "WAL"), ((3, 44, 6), "WAL"), ((3, 52, 0), "WAL")):
            with self.subTest(version=version):
                self.assertEqual(_journal_mode(version), expected)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executemany("INSERT INTO audit(time,action,domain,outcome) VALUES('time','action','','ok')", [()] * 10004)
        self.store.upsert("audit.example")
        self.assertEqual(len(self.store.audit(limit=10000)), 10000)
        self.assertEqual(self.store.audit(limit=1)[0]["domain"], "audit.example")

    def test_csv_formula_neutralization_and_round_trip(self):
        for index, prefix in enumerate(("=", "+", "-", "@", "  =", "\t@", "\n+")):
            self.store.upsert(f"site{index}.example", notes=prefix + 'SUM(1;2) "texto"')
        self.store.upsert("normal.example", notes="Conteúdo; sem fórmula\nlinha 2")
        rows = list(csv.DictReader(io.StringIO(self.store.export_csv()), delimiter=";"))
        self.assertEqual(len(rows), 8)
        for row in rows:
            self.assertTrue(row["observacoes"].startswith("'") if row["dominio"].startswith("site") else row["observacoes"].startswith("Conteúdo"))
        self.assertIn("\nlinha 2", rows[0]["observacoes"])

    @unittest.skipIf(os.name == "nt", "Permissões POSIX")
    def test_private_permissions_and_symlink_rejection(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        link = self.path.parent / "linked.sqlite3"
        link.symlink_to(self.path)
        with self.assertRaises(BanlistError):
            BanlistDatabase(link)
        public = Path(self.directory.name) / "public"
        public.mkdir(mode=0o755)
        with self.assertRaises(BanlistError):
            BanlistDatabase(public / "sites.sqlite3")
        self.path.chmod(0o644)
        with self.assertRaises(BanlistError):
            BanlistDatabase(self.path)

    def test_sync_owned_add_disable_and_soft_delete(self):
        self.store.upsert("school-game.example", "Jogos")
        report = self.store.sync(self.transport)
        self.assertEqual(report["applied"], [{"domain": "school-game.example", "action": "add_domain"}])
        self.assertEqual(self.store.summary()["owned_rules"], 1)
        self.assertEqual(report["pending"], 0)
        self.store.upsert("school-game.example", enabled=False)
        self.assertEqual(self.store.summary()["pending"], 1)
        removed = self.store.sync(self.transport)
        self.assertEqual(removed["applied"], [{"domain": "school-game.example", "action": "remove_domain"}])
        self.assertEqual(self.store.summary()["owned_rules"], 0)
        self.store.upsert("school-game.example")
        self.store.sync(self.transport)
        self.store.delete("school-game.example")
        report = self.store.sync(self.transport)
        self.assertEqual(report["applied"][0]["action"], "remove_domain")
        self.assertEqual(self.store.list_sites(), [])

    def test_existing_manual_and_ai_rules_never_become_owned(self):
        self.transport.request("set_ai_block", enabled=True)
        self.transport.calls.clear()
        for domain in ("poki.com", "chatgpt.com"):
            self.store.upsert(domain, "IA")
        report = self.store.sync(self.transport)
        self.assertEqual(report["applied"], [])
        self.assertEqual(self.store.summary()["owned_rules"], 0)
        for domain in ("poki.com", "chatgpt.com"):
            self.store.delete(domain)
        self.store.sync(self.transport)
        self.assertEqual(self.transport.mutations, [])
        self.assertTrue(self.transport.state["ai_block_enabled"])
        self.assertTrue(any(row["domain"] == "poki.com" for row in self.transport.state["domains"]))

    def test_ai_profile_remains_when_owned_manual_rule_is_removed(self):
        self.store.upsert("chatgpt.com", "IA")
        self.store.sync(self.transport)
        self.transport.request("set_ai_block", enabled=True)
        self.store.delete("chatgpt.com")
        report = self.store.sync(self.transport)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["applied"], [{"domain": "chatgpt.com", "action": "remove_domain"}])
        remaining = next(row for row in report["snapshot"]["domains"] if row["domain"] == "chatgpt.com")
        self.assertEqual(remaining["source"], "ai_profile")
        self.assertTrue(self.transport.state["ai_block_enabled"])

    def test_changed_rule_metadata_loses_ownership(self):
        self.store.upsert("changed.example")
        self.store.sync(self.transport)
        self.transport.state["domains"][-1]["created_at"] = "2030-01-01T00:00:00+00:00"
        self.store.upsert("changed.example", enabled=False)
        self.transport.calls.clear()
        self.store.sync(self.transport)
        self.assertEqual(self.transport.mutations, [])
        self.assertEqual(self.store.summary()["owned_rules"], 0)

    def test_target_change_refuses_before_mutations(self):
        self.store.upsert("bound.example")
        self.store.sync(self.transport)
        self.store.delete("bound.example")
        for attribute, value in (("host", "other-gateway.example"), ("port", 2222)):
            old = getattr(self.transport, attribute)
            setattr(self.transport, attribute, value)
            self.transport.calls.clear()
            with self.subTest(attribute=attribute), self.assertRaises(BanlistError):
                self.store.sync(self.transport)
            self.assertEqual(self.transport.mutations, [])
            setattr(self.transport, attribute, old)
        self.transport.state["gateway"]["lab_cidr"] = "192.168.99.0/24"
        with self.assertRaises(BanlistError):
            self.store.sync(self.transport)
        self.assertEqual(self.transport.mutations, [])

    def test_unhealthy_stale_and_malformed_snapshots_refuse(self):
        self.store.upsert("fresh.example")
        baseline = self.transport.request("snapshot")
        changes = [
            {"health": {"dns": False}}, {"health": []}, {"mode": "unknown"},
            {"timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()},
            {"timestamp": None}, {"domains": ["invalid"]}, {"gateway": None},
        ]
        for change in changes:
            snapshot = dict(baseline, **change)
            with self.subTest(change=change), patch.object(self.transport, "request", return_value=snapshot), self.assertRaises(BanlistError):
                self.store.sync(self.transport)
        self.assertEqual(self.transport.mutations, [])

    def test_partial_failures_preserve_results_and_hide_sensitive_error(self):
        for domain in ("a.example", "b.example", "c.example"):
            self.store.upsert(domain)
        self.transport.fail_domain = "b.example"
        self.transport.fail_after_mutation = True
        report = self.store.sync(self.transport)
        self.assertEqual(report["applied"], [{"domain": "a.example", "action": "add_domain"}])
        self.assertEqual(report["errors"][0]["domain"], "b.example")
        self.assertIsNone(report["snapshot"])
        self.assertFalse(any(params.get("domain") == "c.example" for _, params in self.transport.mutations))
        self.assertEqual(self.store.summary()["uncertain"], 1)
        self.assertNotIn("sensitive-password", str(report) + str(self.store.audit()))
        self.transport.fail_domain = None
        retry = self.store.sync(self.transport)
        self.assertEqual(retry["applied"], [{"domain": "c.example", "action": "add_domain"}])
        # The uncertain successful add is now external, even after restart.
        self.store.delete("b.example")
        self.transport.calls.clear()
        BanlistDatabase(self.path).sync(self.transport)
        self.assertEqual(self.transport.mutations, [])

    def test_commit_failure_after_remote_add_never_claims_ownership(self):
        self.store.upsert("uncertain.example")
        original = self.store._set_tracking

        def tracking(domain, owned, status, *args, **kwargs):
            if status == "owned":
                raise BanlistError("Simulated disk failure")
            return original(domain, owned, status, *args, **kwargs)

        with patch.object(self.store, "_set_tracking", side_effect=tracking):
            report = self.store.sync(self.transport)
        self.assertEqual(report["applied"], [])
        self.assertEqual(report["errors"][0]["status"], "uncertain")
        self.assertEqual(self.store.summary()["owned_rules"], 0)
        self.store.delete("uncertain.example")
        self.transport.calls.clear()
        BanlistDatabase(self.path).sync(self.transport)
        self.assertEqual(self.transport.mutations, [])

    def test_bounded_batches_and_cancellation(self):
        for domain in ("a.example", "b.example", "c.example"):
            self.store.upsert(domain)
        report = self.store.sync(self.transport, limit=2)
        self.assertEqual(len(report["applied"]), 2)
        self.assertEqual(report["pending"], 1)
        event = threading.Event()
        event.set()
        report = self.store.sync(self.transport, cancel_event=event)
        self.assertTrue(report["cancelled"])
        self.assertEqual(report["applied"], [])
        self.assertEqual(report["pending"], 1)
        self.assertEqual(len(self.store.sync(self.transport)["applied"]), 1)
        for invalid in (0, 101, True):
            with self.assertRaises(BanlistError):
                self.store.sync(self.transport, limit=invalid)

    def test_edit_during_sync_remains_pending_for_followup(self):
        self.store.upsert("changed-intent.example")
        original = self.transport.request

        def request(action, **params):
            if action == "add_domain":
                self.store.upsert("changed-intent.example", enabled=False)
            return original(action, **params)

        with patch.object(self.transport, "request", side_effect=request):
            report = self.store.sync(self.transport)
        self.assertEqual(len(report["applied"]), 1)
        self.assertEqual(report["pending"], 1)
        followup = self.store.sync(self.transport)
        self.assertEqual(followup["applied"], [{"domain": "changed-intent.example", "action": "remove_domain"}])
        self.assertEqual(followup["pending"], 0)

    def test_other_process_lease_prevents_duplicate_network_batches(self):
        self.store.upsert("leased.example")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO sync_lease(id,owner,expires) VALUES(1,'other',strftime('%s','now')+180)")
        with self.assertRaises(BanlistError):
            BanlistDatabase(self.path).sync(self.transport)
        self.assertEqual(self.transport.calls, [])

    def test_lease_loss_during_observation_stops_next_mutation_and_keeps_partial_report(self):
        for domain in ("a-added.example", "poki.com", "z-never-added.example"):
            self.store.upsert(domain)
        clock = [1000.0]
        original = self.store._set_tracking

        def tracking(domain, *args, **kwargs):
            result = original(domain, *args, **kwargs)
            if domain == "poki.com":
                clock[0] += 181
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute("UPDATE sync_lease SET owner='new-worker',expires=? WHERE id=1", (clock[0] + 180,))
            return result

        with patch("labguard.banlist.time.time", side_effect=lambda: clock[0]), patch("labguard.banlist.time.monotonic", side_effect=lambda: clock[0]), patch.object(self.store, "_set_tracking", side_effect=tracking):
            report = self.store.sync(self.transport)
        self.assertEqual(report["applied"], [{"domain": "a-added.example", "action": "add_domain"}])
        self.assertEqual([item[1]["domain"] for item in self.transport.mutations], ["a-added.example"])
        self.assertEqual(report["errors"][0]["status"], "stopped")
        self.assertIsNone(report["snapshot"])
        self.assertEqual(report["operations"][0]["status"], "applied")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT owner FROM sync_lease").fetchone()[0], "new-worker")

    def test_unchanged_observations_renew_lease_without_waiting(self):
        for domain in ("crazygames.com", "friv.com", "poki.com", "roblox.com"):
            self.store.upsert(domain)
        self.store.sync(self.transport)
        clock = [1000.0]

        def monotonic():
            clock[0] += 40
            return clock[0]

        original = self.store._renew_lease
        with patch("labguard.banlist.time.time", side_effect=lambda: clock[0]), patch("labguard.banlist.time.monotonic", side_effect=monotonic), patch.object(self.store, "_renew_lease", wraps=original) as renew:
            report = self.store.sync(self.transport)
        self.assertGreater(clock[0] - 1000, 180)
        self.assertGreaterEqual(renew.call_count, 5)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["preserved"], 4)

    def test_lease_loss_after_network_response_never_overwrites_new_worker_tracking(self):
        self.store.upsert("inflight.example")
        original = self.transport.request

        def request(action, **params):
            snapshot = original(action, **params)
            if action == "add_domain":
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute("UPDATE sync_lease SET owner='new-worker' WHERE id=1")
                    db.execute("UPDATE sync_state SET status='external',owned=0 WHERE domain='inflight.example'")
            return snapshot

        with patch.object(self.transport, "request", side_effect=request):
            report = self.store.sync(self.transport)
        self.assertEqual(report["applied"], [])
        self.assertEqual(report["errors"][0]["status"], "uncertain")
        self.assertIsNone(report["snapshot"])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT owned,status FROM sync_state").fetchone(), (0, "external"))

    def test_initial_transport_failure_is_sanitized_and_lease_released(self):
        self.store.upsert("offline.example")
        with patch.object(self.transport, "request", side_effect=RuntimeError("secret-key")):
            with self.assertRaises(BanlistError) as raised:
                self.store.sync(self.transport)
        self.assertNotIn("secret-key", str(raised.exception))
        self.assertEqual(len(self.store.sync(self.transport)["applied"]), 1)


if __name__ == "__main__":
    unittest.main()
