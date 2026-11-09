"""Testes de regras, autorização e transporte real HTTP/HTTPS da Central."""
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from central.labguard_central import (
    AuthenticationError, CentralError, CentralStore, ConflictError,
    MAX_ACTIVE_RULES, build_servers, initialize, read_config,
)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.now = 2000000000.0
        self.store = CentralStore(Path(self.folder.name) / "central.sqlite3", clock=lambda: self.now)
        self.seed = [("game.example", "jogos", "Teste"), ("api.game.example", "jogos", "Teste"),
                     ("school.example", "outros", "Teste")]
        self.store.ensure(seed_rows=self.seed)

    def tearDown(self):
        self.folder.cleanup()

    def test_parent_allow_suppresses_children_and_delete_restores(self):
        self.store.put_rule("game.example", "jogos", "allow", original="game.example")
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["revision"], 2)
        self.assertEqual(snapshot["site_policy"]["domains"], ["school.example"])
        self.assertEqual(snapshot["site_policy"]["allowed_domains"], ["game.example"])
        child = next(row for row in self.store.state()["rules"] if row["domain"] == "api.game.example")
        self.assertFalse(child["effective"])
        self.assertTrue(child["enabled"])
        self.assertEqual(child["overridden_by"], "game.example")
        self.store.delete_rule("game.example")
        self.assertIn("api.game.example", self.store.snapshot()["site_policy"]["domains"])

    def test_blocked_child_under_allow_rejected_and_child_allow_supported(self):
        self.store.put_rule("learn.game.example", "jogos", "allow")
        self.assertIn("game.example", self.store.snapshot()["site_policy"]["domains"])
        self.assertIn("learn.game.example", self.store.snapshot()["site_policy"]["allowed_domains"])
        revision = self.store.snapshot()["revision"]
        with self.assertRaises(CentralError):
            self.store.put_rule("files.learn.game.example", "jogos", "block")
        self.assertEqual(self.store.snapshot()["revision"], revision)
        self.assertNotIn("files.learn.game.example", [rule["domain"] for rule in self.store.state()["rules"]])

    def test_categories_suspend_both_actions_and_restore(self):
        self.store.put_rule("game.example", "jogos", "allow", original="game.example")
        self.store.set_category("jogos", False)
        self.assertEqual(self.store.snapshot()["site_policy"]["allowed_domains"], [])
        self.assertEqual(self.store.snapshot()["site_policy"]["domains"], ["school.example"])
        self.store.set_category("jogos", True)
        self.assertEqual(self.store.snapshot()["site_policy"]["allowed_domains"], ["game.example"])
        self.assertNotIn("api.game.example", self.store.snapshot()["site_policy"]["domains"])

    def test_deleted_seed_stays_deleted_across_restart(self):
        self.store.delete_rule("game.example")
        reopened = CentralStore(self.store.path)
        reopened.ensure(seed_rows=self.seed)
        self.assertNotIn("game.example", reopened.snapshot()["site_policy"]["domains"])

    def test_rules_are_atomic_at_browser_capacity(self):
        for index in range(MAX_ACTIVE_RULES - len(self.seed)):
            self.store.put_rule(f"site-{index}.example", "outros", "block")
        prior = self.store.snapshot()
        with self.assertRaises(CentralError):
            self.store.put_rule("over-limit.example", "outros", "block")
        self.assertEqual(self.store.snapshot(), prior)
        self.store.put_rule("over-limit.example", "outros", "block", enabled=False)
        with self.assertRaises(CentralError):
            self.store.put_rule("over-limit.example", "outros", "block", original="over-limit.example")
        self.assertFalse(next(rule["enabled"] for rule in self.store.state()["rules"] if rule["domain"] == "over-limit.example"))

    def test_duplicate_and_rename_conflicts_preserve_original(self):
        with self.assertRaises(ConflictError):
            self.store.put_rule("game.example", "jogos", "allow")
        with self.assertRaises(ConflictError):
            self.store.put_rule("school.example", "outros", "block", original="game.example")
        self.assertEqual(len(self.store.state()["rules"]), 3)
        for invalid in ("https://game.example/path", "game.example:443", "127.0.0.1", "game.example\r\n", "*.invalid"):
            with self.assertRaises(CentralError):
                self.store.put_rule(invalid, "jogos", "block")

    def _enroll(self):
        token, _ = self.store.issue_enrollment()
        return self.store.enroll(token, "LAB-01", "1.2.0")

    def _report(self, enrolled, **changes):
        report = {"device_id": enrolled["device_id"], "name": "LAB-01", "client_version": "1.2.0",
                  "applied_revision": None, "site_ok": None, "status_at": None, "error": ""}
        report.update(changes)
        return report

    def test_pairing_one_use_expiry_unique_credentials_and_revocation(self):
        token, _ = self.store.issue_enrollment()
        enrolled = self.store.enroll(token, "LAB-01", "1.2.0")
        with self.assertRaises(AuthenticationError):
            self.store.enroll(token, "LAB-02", "1.2.0")
        second = self._enroll()
        self.assertNotEqual(enrolled["device_token"], second["device_token"])
        with self.assertRaises(AuthenticationError):
            self.store.poll(enrolled["device_token"], self._report(second))
        self.store.revoke_device(enrolled["device_id"])
        with self.assertRaises(AuthenticationError):
            self.store.poll(enrolled["device_token"], self._report(enrolled))
        expiring, _ = self.store.issue_enrollment()
        self.now += 3601
        with self.assertRaises(AuthenticationError):
            self.store.enroll(expiring, "LAB-03", "1.2.0")

    def test_acknowledgement_distinguishes_pending_applied_new_revision_and_offline(self):
        enrolled = self._enroll()
        self.assertEqual(self.store.state()["devices"][0]["status"], "pending")
        self.store.poll(enrolled["device_token"], self._report(enrolled, site_ok=False, error="Aplicação pendente"))
        self.assertEqual(self.store.state()["devices"][0]["status"], "pending")
        report = self._report(enrolled, applied_revision=1, site_ok=True, status_at="2033-05-18T03:33:20+00:00")
        self.store.poll(enrolled["device_token"], report)
        self.assertEqual(self.store.state()["devices"][0]["status"], "online")
        self.store.put_rule("new.example", "outros", "block")
        self.assertEqual(self.store.state()["devices"][0]["status"], "pending")
        self.assertEqual(self.store.poll(enrolled["device_token"], report)["revision"], 2)
        self.now += 91
        self.assertEqual(self.store.state()["devices"][0]["status"], "offline")
        with self.assertRaises(CentralError):
            self.store.poll(enrolled["device_token"], self._report(enrolled, applied_revision=999, site_ok=True))
        with self.assertRaises(CentralError):
            self.store.poll(enrolled["device_token"], self._report(enrolled, site_ok=True))

    def test_public_state_does_not_contain_credentials(self):
        enrolled = self._enroll()
        payload = json.dumps(self.store.state())
        self.assertNotIn(enrolled["device_token"], payload)
        self.assertNotIn("token_hash", payload)
        self.assertNotIn("enrollment_token", payload)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.folder.name)
        cls.panel_port, cls.agent_port = free_port(), free_port()
        while cls.panel_port == cls.agent_port:
            cls.agent_port = free_port()
        cls.password = "uma-senha-de-teste-muito-forte"
        initialize(cls.directory, cls.password, "127.0.0.1", "127.0.0.0/8", cls.agent_port, cls.panel_port)
        cls.panel, cls.agents = build_servers(cls.directory)
        cls.threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (cls.panel, cls.agents)]
        for thread in cls.threads:
            thread.start()
        cls.context = ssl.create_default_context(cafile=str(cls.directory / "server-cert.pem"))
        cls.app = cls.panel.application

    @classmethod
    def tearDownClass(cls):
        for server in (cls.panel, cls.agents):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=5)
        cls.folder.cleanup()

    def setUp(self):
        self.app.rates.clear()
        self.cookie = ""
        self.csrf = ""

    def request(self, path, data=None, *, agent=False, headers=None, context=None):
        port = self.agent_port if agent else self.panel_port
        if agent:
            connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context or self.context)
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        request_headers = {"Host": f"127.0.0.1:{port}"}
        if data is not None:
            request_headers.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.panel_port}"})
        if self.cookie:
            request_headers["Cookie"] = self.cookie
        if self.csrf:
            request_headers["X-CSRF-Token"] = self.csrf
        request_headers.update(headers or {})
        try:
            connection.request("POST" if data is not None else "GET", path, None if data is None else json.dumps(data), request_headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw), dict(response.getheaders())
        finally:
            connection.close()

    def login(self):
        status, data, headers = self.request("/api/login", {"password": self.password})
        self.assertEqual(status, 200)
        self.cookie = headers["Set-Cookie"].partition(";")[0]
        self.csrf = data["csrf"]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])

    def test_auth_origin_csrf_and_logout(self):
        self.assertEqual(self.request("/api/state")[0], 401)
        self.assertEqual(self.request("/api/session")[1]["authenticated"], False)
        self.assertEqual(self.request("/api/login", {"password": self.password}, headers={"Origin": "https://hostile.invalid"})[0], 401)
        self.login()
        self.assertEqual(self.request("/api/state", headers={"Host": "hostile.invalid"})[0], 401)
        rule = {"domain": "transport.example", "category": "outros", "action": "block", "enabled": True}
        self.assertEqual(self.request("/api/rules", rule, headers={"X-CSRF-Token": "wrong"})[0], 401)
        self.assertEqual(self.request("/api/rules", rule)[0], 200)
        self.assertEqual(self.request("/api/rules/delete", {"domain": "transport.example"})[0], 200)
        self.assertEqual(self.request("/api/logout", {})[0], 200)
        self.assertEqual(self.request("/api/state")[0], 401)

    def test_real_tls_pairing_and_actual_ack(self):
        self.login()
        status, issued, _ = self.request("/api/enrollment", {})
        self.assertEqual(status, 200)
        self.assertEqual(set(issued["config"]), {"format", "server_url", "ca_pem", "enrollment_token"})
        status, enrolled, _ = self.request("/api/agent/enroll", {"enrollment_token": issued["config"]["enrollment_token"],
                          "name": "HTTPS-TEST", "client_version": "1.2.0"}, agent=True)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(enrolled["revision"], 1)
        self.assertEqual(enrolled["poll_seconds"], 15)
        self.assertEqual(self.request("/api/state", agent=True)[0], 404)
        report = {"device_id": enrolled["device_id"], "name": "HTTPS-TEST", "client_version": "1.2.0", "applied_revision": enrolled["revision"],
                  "site_ok": True, "status_at": "2026-11-09T12:00:00+00:00", "error": ""}
        self.assertEqual(self.request("/api/agent/poll", report, agent=True)[0], 401)
        self.assertEqual(self.request("/api/agent/poll", report, agent=True, headers={"Authorization": "Bearer " + enrolled["device_token"]})[0], 200)
        state = self.request("/api/state")[1]
        device = next(row for row in state["devices"] if row["device_id"] == enrolled["device_id"])
        self.assertEqual(device["status"], "online")
        self.assertEqual(device["applied_revision"], enrolled["revision"])
        self.assertEqual(self.request("/api/devices/revoke", {"device_id": enrolled["device_id"]})[0], 200)
        self.assertEqual(self.request("/api/agent/poll", report, agent=True, headers={"Authorization": "Bearer " + enrolled["device_token"]})[0], 401)

    def test_untrusted_tls_refused(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request("/api/agent/enroll", {}, agent=True, context=ssl.create_default_context())

    def test_health_is_local_and_non_sensitive(self):
        status, data, _ = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"ok": True, "app": "LabGuardCentral", "version": "1.0.0"})
        self.assertEqual(self.request("/healthz", agent=True)[0], 404)

    def test_login_throttle_and_configuration_preserved(self):
        for _ in range(8):
            self.assertEqual(self.request("/api/login", {"password": "incorrect"})[0], 401)
        self.assertEqual(self.request("/api/login", {"password": self.password})[0], 429)
        before = (self.directory / "server-cert.pem").read_bytes()
        with self.assertRaises(ConflictError):
            initialize(self.directory, self.password, "127.0.0.1", "127.0.0.0/8", self.agent_port, self.panel_port)
        self.assertEqual((self.directory / "server-cert.pem").read_bytes(), before)
        self.assertEqual(read_config(self.directory)["agent_port"], self.agent_port)


if __name__ == "__main__":
    unittest.main()
