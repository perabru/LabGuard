import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from labguard.demo import DemoTransport
from labguard.server import (Application, Limits, LocalHTTPServer, ServerConfig, ServerError,
                             initialize, validate_action)
from labguard.server_service import run_service


class ConfigTests(unittest.TestCase):
    def test_init_generates_two_private_tokens_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            result = initialize(path)
            secret = json.loads((path / "secrets.json").read_text())
            plain = (path / "access-tokens.txt").read_text()
            self.assertEqual(set(secret["tokens"]), {"viewer", "admin"})
            self.assertNotEqual(secret["tokens"]["viewer"], secret["tokens"]["admin"])
            self.assertNotIn("Administração (admin):", json.dumps(result))
            self.assertNotIn(plain, json.dumps(secret))
            if os.name != "nt":
                self.assertEqual((path / "secrets.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ServerError, "já existe"):
                initialize(path)

    def test_unconfigured_production_refuses_start_demo_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            initialize(Path(directory))
            with self.assertRaisesRegex(ServerError, "Configure host"):
                ServerConfig(Path(directory))
            self.assertTrue(ServerConfig(Path(directory), demo=True).demo)

    @unittest.skipIf(os.name == "nt", "Modo POSIX; ACLs Windows são aplicadas no instalador.")
    def test_insecure_secret_permissions_and_symlink_config_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            initialize(path)
            (path / "secrets.json").chmod(0o644)
            with self.assertRaisesRegex(ServerError, "chmod 600"):
                ServerConfig(path, demo=True)
            (path / "secrets.json").chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(path, target_is_directory=True)
            with self.assertRaisesRegex(ServerError, "link"):
                ServerConfig(link, demo=True)
            with self.assertRaisesRegex(ServerError, "link"):
                initialize(link)

    def test_action_allowlist_and_types(self):
        for action, params in [("reboot", {}), ("set_ai_block", {"enabled": "false"}),
                               ("set_device_block", {"ip": "::1", "blocked": True}),
                               ("snapshot", {"command": "id"}),
                               ("add_domain", {"domain": "https://example.com"})]:
            with self.subTest(action=action, params=params), self.assertRaises((ValueError, ServerError)):
                validate_action(action, params)

    def test_address_actions_require_typed_unicast_addresses(self):
        for params in ({"kind": "ip", "address": "::1", "blocked": True},
                       {"kind": "mac", "address": "ff:ff:ff:ff:ff:ff", "blocked": True},
                       {"kind": "mac", "address": "01:00:5e:00:00:01", "blocked": True},
                       {"kind": "mac", "address": "00:00:00:00:00:00", "blocked": True},
                       {"kind": "mac", "address": "02:00:00:00:00:01", "blocked": "true"},
                       {"kind": "command", "address": "echo", "blocked": True}):
            with self.subTest(params=params), self.assertRaises(ServerError):
                validate_action("set_address_block", params)
        self.assertEqual(validate_action("set_address_block", {"kind": "mac", "address": "02:AA:BB:CC:DD:01", "blocked": True})[1]["address"], "02:aa:bb:cc:dd:01")

    @unittest.skipIf(os.name == "nt", "SCM nativo é testado no Windows CI.")
    def test_scm_mode_never_executes_on_linux(self):
        with self.assertRaisesRegex(ValueError, "exclusivo"):
            run_service("unused")


class LimitTests(unittest.TestCase):
    def test_auth_backoff_and_action_limits_expire(self):
        moment = [0.0]
        limiter = Limits(clock=lambda: moment[0])
        for _ in range(20):
            limiter.reject_auth()
        self.assertTrue(limiter.auth_blocked())
        for _ in range(20):
            self.assertTrue(limiter.accept("admin", mutation=True))
        self.assertFalse(limiter.accept("admin", mutation=True))
        moment[0] = 61
        self.assertFalse(limiter.auth_blocked())
        self.assertTrue(limiter.accept("admin", mutation=True))


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        initialize(self.directory)
        self.viewer = "v" * 43
        self.admin = "a" * 43
        secret = {"version": 1, "tokens": {"viewer": hashlib.sha256(self.viewer.encode()).hexdigest(),
                                               "admin": hashlib.sha256(self.admin.encode()).hexdigest()}}
        (self.directory / "secrets.json").write_text(json.dumps(secret))
        self.config = ServerConfig(self.directory, demo=True)
        self.app = Application(self.config, logging_enabled=False)
        self.httpd = LocalHTTPServer(self.app, port=0)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.app.close()
        self.thread.join(timeout=1)
        self.temporary.cleanup()

    def request(self, path, *, token=None, method="GET", payload=None, headers=None):
        options = dict(headers or {})
        if token:
            options["Authorization"] = "Bearer " + token
        body = json.dumps(payload).encode() if payload is not None else None
        if body:
            options.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=2)
        connection.request(method, path, body=body, headers=options)
        response = connection.getresponse()
        result = (response.status, dict(response.getheaders()), response.read())
        connection.close()
        return result

    def test_binds_only_loopback_and_health_is_minimal(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")
        status, _headers, body = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True, "service": "LabGuard Server"})
        self.assertNotIn(self.admin.encode(), body)

    def test_snapshot_requires_auth_and_viewer_cannot_change_rules(self):
        self.assertEqual(self.request("/api/snapshot")[0], 401)
        status, _headers, body = self.request("/api/snapshot", token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["role"], "viewer")
        self.assertEqual(self.request("/api/action", token=self.viewer, method="POST",
                                     payload={"action": "set_ai_block", "params": {"enabled": True}})[0], 403)

    def test_admin_change_is_explicit_demo_and_no_token_in_response(self):
        status, _headers, body = self.request("/api/action", token=self.admin, method="POST",
                                             payload={"action": "set_ai_block", "params": {"enabled": True}})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["data"]["mode"], "demo")
        self.assertTrue(data["data"]["policies"]["ai_block"]["enabled"])
        self.assertNotIn(self.admin.encode(), body)

    def test_dns_rebinding_cross_origin_query_tokens_and_paths_are_rejected(self):
        self.assertEqual(self.request("/api/snapshot", token=self.viewer, headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.request("/api/action", token=self.admin, method="POST",
                                     payload={"action": "set_ai_block", "params": {"enabled": True}},
                                     headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("/api/snapshot?token=" + self.admin)[0], 400)
        self.assertEqual(self.request("/../secrets.json", token=self.admin)[0], 404)
        self.assertEqual(self.request("/secrets.json", token=self.admin)[0], 404)

    def test_security_headers_and_csp_assets_are_present(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"LabGuard", body)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(self.request("/app.js")[0], 200)
        status, headers, body = self.request("/", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_oversized_and_arbitrary_commands_never_reach_transport(self):
        self.assertEqual(self.request("/api/action", token=self.admin, method="POST",
                                     payload={"action": "reboot", "params": {}})[0], 400)
        self.assertEqual(self.request("/api/action", token=self.admin, method="POST",
                                     payload={"action": "add_domain", "params": {"domain": "x" * 9000}})[0], 413)

    def test_real_mutations_require_fresh_healthy_snapshot(self):
        snapshot = copy.deepcopy(DemoTransport().request("snapshot"))
        snapshot["mode"] = "gateway"
        class Fake:
            def request(self, _action, **_params):
                return snapshot
        self.app.config.demo = False
        self.app.transport = Fake()
        with self.assertRaisesRegex(ServerError, "Atualize"):
            self.app.execute("set_ai_block", {"enabled": True})
        self.app.execute("snapshot", {})
        self.assertEqual(self.app.execute("set_ai_block", {"enabled": True})["mode"], "gateway")
        self.app.last_success = -100
        with self.assertRaisesRegex(ServerError, "Atualize"):
            self.app.execute("set_ai_block", {"enabled": False})
        self.app.execute("snapshot", {})
        self.app.last_snapshot["health"]["dns"] = False
        with self.assertRaisesRegex(ServerError, "indisponível"):
            self.app.execute("set_ai_block", {"enabled": False})

    def test_banlist_roles_crud_filters_revision_and_csv(self):
        self.assertEqual(self.request("/api/banlist")[0], 401)
        payload = {"domain": "school-games.example", "category": "Jogos", "enabled": True, "notes": "Revisado"}
        self.assertEqual(self.request("/api/banlist/upsert", token=self.viewer, method="POST", payload=payload)[0], 403)
        status, _, body = self.request("/api/banlist/upsert", token=self.admin, method="POST", payload=payload)
        self.assertEqual(status, 200)
        row = json.loads(body)["data"]["site"]
        status, _, body = self.request("/api/banlist?q=school&category=Jogos&enabled=true", token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["data"]["sites"][0]["domain"], payload["domain"])
        payload.update(enabled=False, expected_revision=row["revision"])
        self.assertEqual(self.request("/api/banlist/upsert", token=self.admin, method="POST", payload=payload)[0], 200)
        self.assertEqual(self.request("/api/banlist/upsert", token=self.admin, method="POST", payload=payload)[0], 400)
        status, headers, body = self.request("/api/banlist/export", token=self.viewer)
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(b"school-games.example", body)
        self.assertEqual(self.request("/api/banlist/delete", token=self.admin, method="POST", payload={"domain": payload["domain"], "expected_revision": row["revision"] + 1})[0], 200)
        self.assertEqual(self.app.banlist.summary()["deleted"], 1)

    def test_banlist_queries_import_and_no_implicit_network_write(self):
        with patch.object(self.app.transport, "request", side_effect=RuntimeError("offline")) as network:
            status, _, body = self.request("/api/banlist/import", token=self.admin, method="POST", payload={"domains": ["ai.example", "https://invalid.example"], "category": "IA"})
            self.assertEqual(status, 200)
            self.assertEqual(len(json.loads(body)["data"]["added"]), 1)
            self.assertEqual(self.request("/api/banlist", token=self.viewer)[0], 200)
            network.assert_not_called()
        for query in ["?token=secret", "?q=a&q=b", "?enabled=maybe", "?unknown=true"]:
            self.assertEqual(self.request("/api/banlist" + query, token=self.admin)[0], 400)
        self.assertEqual(self.request("/api/banlist/import", token=self.admin, method="POST", payload={"domains": ["a.example"] * 101})[0], 400)
        self.assertEqual(self.request("/api/banlist/upsert", token=self.admin, method="POST", payload={"domain": "a.example", "enabled": "false"})[0], 400)

    def test_banlist_sync_runs_explicit_job_and_preserves_external_rule(self):
        self.app.banlist.upsert("new-games.example", category="Jogos")
        external = self.app.transport.request("snapshot")["domains"][0]["domain"]
        self.app.banlist.upsert(external)
        status, _, body = self.request("/api/banlist/sync", token=self.admin, method="POST", payload={"limit": 20})
        self.assertEqual(status, 202)
        self.assertTrue(json.loads(body)["data"]["job_id"])
        self.app.sync_thread.join(timeout=3)
        status, _, body = self.request("/api/banlist/sync-status", token=self.viewer)
        job = json.loads(body)["data"]
        self.assertEqual(status, 200)
        self.assertFalse(job["running"])
        self.assertIsNone(job["error"])
        self.assertEqual(job["report"]["applied"], [{"domain": "new-games.example", "action": "add_domain"}])
        self.app.banlist.delete(external)
        self.app.start_sync({}, "admin")
        self.app.sync_thread.join(timeout=3)
        self.assertIn(external, [row["domain"] for row in self.app.transport.request("snapshot")["domains"]])

    def test_banlist_busy_job_rejects_edits_and_viewer_start(self):
        self.assertEqual(self.request("/api/banlist/sync", token=self.viewer, method="POST", payload={})[0], 403)
        entered, release = threading.Event(), threading.Event()
        def blocked_sync(*_args, **_kwargs):
            entered.set()
            release.wait(2)
            return {"snapshot": self.app.transport.request("snapshot"), "applied": [], "errors": [], "pending": 0}
        with patch.object(self.app.banlist, "sync", side_effect=blocked_sync):
            try:
                self.app.start_sync({}, "admin")
                self.assertTrue(entered.wait(1))
                self.assertEqual(self.request("/api/banlist/sync-status", token=self.viewer)[0], 200)
                self.assertEqual(self.request("/api/banlist/upsert", token=self.admin, method="POST", payload={"domain": "no.example"})[0], 400)
                self.assertEqual(self.request("/api/banlist/sync", token=self.admin, method="POST", payload={})[0], 400)
            finally:
                release.set()
                self.app.sync_thread.join(timeout=3)

    def test_uncertain_real_sync_preserves_partial_report_and_requires_refresh(self):
        snapshot = self.app.transport.request("snapshot")
        snapshot["mode"] = "gateway"
        self.app.config.demo = False
        self.app.last_snapshot = snapshot
        self.app.last_success = time.monotonic()
        self.app.stale = False
        report = {"snapshot": None, "applied": [{"domain": "a.example", "action": "add_domain"}],
                  "errors": [{"domain": "b.example", "message": "Resultado não confirmado."}], "pending": 1}
        with patch.object(self.app.banlist, "sync", return_value=report):
            self.app.start_sync({}, "admin")
            self.app.sync_thread.join(timeout=3)
        status = self.app.sync_status()
        self.assertIsNone(status["error"])
        self.assertEqual(status["report"], report)
        self.assertTrue(self.app.stale)
        with self.assertRaisesRegex(ServerError, "Atualize"):
            self.app.start_sync({}, "admin")

    def test_viewer_reports_use_only_cached_snapshot_and_download_safely(self):
        self.assertEqual(self.request("/api/network-map")[0], 401)
        self.assertEqual(self.request("/api/report?format=csv", token=self.viewer)[0], 400)
        self.app.execute("snapshot", {})
        with patch.object(self.app.transport, "request", side_effect=RuntimeError("offline")) as network:
            for route, expected in (("/api/network-map", b"<svg"), ("/api/report?format=csv", b"IP;MAC"),
                                    ("/api/report?format=html", b"<!doctype html>")):
                status, headers, body = self.request(route, token=self.viewer)
                self.assertEqual(status, 200)
                self.assertIn(expected, body)
                self.assertIn("attachment", headers["Content-Disposition"])
                self.assertEqual(headers["X-LabGuard-Snapshot-State"], "fresh")
                self.assertNotIn(self.viewer.encode(), body)
            network.assert_not_called()
        for query in ("format=../../secrets.json", "format=svg", "format=csv&format=html", "format=html&token=x"):
            self.assertEqual(self.request("/api/report?" + query, token=self.viewer)[0], 400)

    def test_report_row_bytes_private_temp_and_stale_marking(self):
        source = self.app.execute("snapshot", {})
        self.app.last_snapshot["devices"] = [dict(source["devices"][0]) for _ in range(501)]
        self.app.stale = True
        captured = {}
        def generate(snapshot, path, format):
            captured.update(rows=len(snapshot["devices"]), timestamp=snapshot["timestamp"], path=Path(path), format=format)
            self.assertEqual(Path(path).parent.parent, self.directory / "data")
            if os.name != "nt":
                self.assertEqual(Path(path).parent.stat().st_mode & 0o777, 0o700)
            Path(path).write_bytes(b"bounded report")
        with patch("labguard.server.export_report", side_effect=generate):
            status, headers, body = self.request("/api/report?format=csv", token=self.viewer)
        self.assertEqual((status, body), (200, b"bounded report"))
        self.assertEqual(headers["X-LabGuard-Snapshot-State"], "stale")
        self.assertEqual(captured["rows"], 500)
        self.assertIn("500 de 501", captured["timestamp"])
        self.assertIn("dados anteriores", captured["timestamp"])
        self.assertFalse(captured["path"].parent.exists())
        self.assertEqual(len(self.app.last_snapshot["devices"]), 501)
        with patch("labguard.server.export_report", side_effect=lambda _s, path, _f: Path(path).write_bytes(b"x" * (4 * 1024 * 1024 + 1))):
            self.assertEqual(self.request("/api/report?format=csv", token=self.viewer)[0], 400)

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "PDF usa dependência opcional ReportLab.")
    def test_viewer_can_export_pdf(self):
        self.app.execute("snapshot", {})
        status, headers, body = self.request("/api/report?format=pdf", token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/pdf")
        self.assertTrue(body.startswith(b"%PDF"))

    def test_address_actions_rbac_independent_scopes_and_protected_target(self):
        snapshot = self.app.execute("snapshot", {})
        device = next(row for row in snapshot["devices"] if not row.get("protected"))
        payload = {"action": "set_address_block", "params": {"kind": "ip", "address": device["ip"], "blocked": True}}
        self.assertEqual(self.request("/api/action", token=self.viewer, method="POST", payload=payload)[0], 403)
        self.assertEqual(self.request("/api/action", token=self.admin, method="POST", payload=payload)[0], 200)
        payload["params"].update(kind="mac", address=device["mac"])
        self.assertEqual(self.request("/api/action", token=self.admin, method="POST", payload=payload)[0], 200)
        payload["params"].update(kind="ip", address=device["ip"], blocked=False)
        status, _, body = self.request("/api/action", token=self.admin, method="POST", payload=payload)
        self.assertEqual(status, 200)
        data = json.loads(body)["data"]
        changed = next(row for row in data["devices"] if row["ip"] == device["ip"])
        self.assertTrue(changed["blocked"])
        self.assertIn("mac", changed["blocked_by"])
        self.assertFalse(changed["blocked_ip"])
        protected = next(row for row in data["devices"] if row.get("protected"))
        payload["params"].update(address=protected["ip"], blocked=True)
        with patch.object(self.app.transport, "request") as network:
            self.assertEqual(self.request("/api/action", token=self.admin, method="POST", payload=payload)[0], 400)
            network.assert_not_called()
        self.assertIn("address_blocks", data)

    def test_real_address_change_requires_firewall_and_forwarding_not_dns(self):
        source = self.app.execute("snapshot", {})
        source["mode"] = "gateway"
        source["health"]["dns"] = False
        self.app.config.demo = False
        self.app.last_snapshot = source
        self.app.last_success = time.monotonic()
        target = next(row for row in source["devices"] if not row.get("protected"))
        params = {"kind": "ip", "address": target["ip"], "blocked": True}
        with patch.object(self.app.transport, "request", return_value=source) as network:
            self.app.execute("set_address_block", params)
            network.assert_called_once()
        self.app.last_snapshot["health"]["firewall"] = False
        with patch.object(self.app.transport, "request") as network:
            with self.assertRaisesRegex(ServerError, "indisponível"):
                self.app.execute("set_address_block", params)
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
