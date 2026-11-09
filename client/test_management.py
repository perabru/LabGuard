"""Central administration preserves local games and only acknowledges applied sites."""
import contextlib
import copy
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

import labguard_cliente as lg
from test_sites import MemoryRegistry


def snapshot(revision=1, domains=None, allowed=None):
    return {"revision": revision, "site_policy": {"mode": "bloqueados", "catalog_enabled": False,
            "domains": domains if domains is not None else ["game.example"],
            "allowed_domains": allowed if allowed is not None else []}}


class CentralPolicyTests(unittest.TestCase):
    def test_snapshot_rejects_remote_game_operations_and_conflicting_allow_parent(self):
        for data in (dict(snapshot(), command="execute"),
                     snapshot(0), snapshot(True),
                     snapshot(domains=["child.school.example"], allowed=["school.example"]),
                     snapshot(domains=["school.example"], allowed=["school.example"])):
            with self.subTest(data=data), self.assertRaises(ValueError):
                lg.validate_central_policy(data)
        data = snapshot()
        data["site_policy"]["remove_roblox"] = True
        with self.assertRaises(ValueError):
            lg.validate_central_policy(data)
        accepted = snapshot(domains=["game.example"], allowed=["lesson.game.example"])
        self.assertEqual(lg.validate_central_policy(accepted), accepted)

    def test_central_supports_catalog_snapshot_over_local_manual_limit(self):
        data = snapshot(domains=[f"game{i}.example" for i in range(975)])
        self.assertEqual(len(lg.validate_central_policy(data)["site_policy"]["domains"]), 975)
        data["site_policy"]["allowed_domains"] = ["school.example"]
        with self.assertRaises(ValueError):
            lg.validate_central_policy(data)

    def test_allow_exceptions_apply_in_blocked_mode_and_resolver(self):
        store, state = MemoryRegistry(), {}
        policy = {"mode": "bloqueados", "domains": ["roblox.com"], "allowed_domains": ["create.roblox.com"]}
        result = lg._browser_policy_run(policy, state, lambda: None, store)
        self.assertTrue(result["ok"])
        for browser, (base, _, allow) in lg._BROWSER_POLICIES.items():
            values = {value[0] for value in store.data[base + "\\" + allow].values()}
            self.assertEqual(values, set(lg._browser_patterns(browser, ["create.roblox.com"])))
        names = lg._hosts_names(dict(policy, domains=["roblox.com", "create.roblox.com", "www.create.roblox.com"]))
        self.assertIn("roblox.com", names)
        self.assertNotIn("create.roblox.com", names)
        self.assertNotIn("www.create.roblox.com", names)

    def test_allowed_parent_has_same_semantics_in_all_browsers(self):
        store = MemoryRegistry()
        policy = {"mode": "bloqueados", "domains": ["game.school.example", "school.example", "other.example"],
                  "allowed_domains": ["school.example"]}
        lg._browser_policy_run(policy, {}, lambda: None, store)
        for browser, (base, block, _) in lg._BROWSER_POLICIES.items():
            self.assertEqual({v[0] for v in store.data[base + "\\" + block].values()},
                             set(lg._browser_patterns(browser, ["other.example"])))
        self.assertEqual(lg._hosts_names(policy), {"other.example", "www.other.example"})

    def test_only_explicit_local_https_endpoint(self):
        self.assertEqual(lg._central_endpoint("https://192.168.15.10:8788")[1:], ("192.168.15.10", 8788))
        for value in ("http://192.168.1.2:8788", "https://public.example:8788", "https://8.8.8.8:8788",
                      "https://127.0.0.1:8788/a", "https://user@192.168.1.2:8788", "https://0.0.0.0:8788",
                      "https://192.168.1.2:8788/?token=secret", "https://169.254.0.1:8788"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lg._central_endpoint(value)

    def test_invalid_pem_is_not_silently_trusted(self):
        with self.assertRaises((ssl.SSLError, ValueError)):
            lg._central_tls("not-a-certificate" * 10)


class CentralSyncTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.config = {"format": "labguard-central-v1", "server_url": "https://192.168.15.10:8788",
                       "ca_pem": "test-pem", "device_id": "12345678-device", "device_token": "a" * 32}
        self.local = lg.validate_policy({"domains": ["local.example"], "games": ["minecraft"],
                                        "remove_roblox": False, "remove_games": []})
        lg._atomic_json(self.path / "politica.json", self.local)
        lg._atomic_json(self.path / lg._CENTRAL_CONFIG, self.config)
        lg._atomic_json(self.path / lg._CENTRAL_POLICY, snapshot())
        lg._atomic_json(self.path / lg._CENTRAL_STATUS, {"connected": True, "last_contact": lg._utc_now()})
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(lg, "client_directory", return_value=self.path))
        self.stack.enter_context(patch.object(lg, "_operation_lock", side_effect=lambda *a, **k: contextlib.nullcontext()))

    def test_central_sites_replace_local_catalog_but_preserve_games(self):
        active, revision = lg._central_effective(self.local, self.path)
        self.assertFalse(active["catalog_enabled"])
        self.assertEqual(active["domains"], ["game.example"])
        self.assertEqual(revision, 1)
        for field in ("games", "remove_games", "remove_roblox"):
            self.assertEqual(active[field], self.local[field])
        self.assertEqual(lg._json_read(self.path / "politica.json"), self.local)

    def test_offline_preserves_cache_and_reports_connection_failure(self):
        before = (self.path / lg._CENTRAL_POLICY).read_bytes()
        with patch.object(lg, "_central_request", side_effect=lg.CentralError("Central sem conexão")):
            with self.assertRaises(lg.CentralError):
                lg.sync_central()
        self.assertEqual((self.path / lg._CENTRAL_POLICY).read_bytes(), before)
        self.assertFalse(lg._json_read(self.path / lg._CENTRAL_STATUS)["connected"])
        self.assertEqual(lg._json_read(self.path / "politica.json"), self.local)

    def test_heartbeat_requires_actual_fresh_site_success(self):
        status = {"checked_at": lg._utc_now(), "central_revision": 1, "sites": {"ok": True}, "system_sites": {"ok": False}}
        lg._atomic_json(self.path / "status.json", status)
        response = {"ok": True, **snapshot(2, domains=["new.example"])}
        with patch.object(lg, "_central_request", return_value=response) as request:
            result = lg.sync_central()
            sent = request.call_args.args[2]
            self.assertFalse(sent["site_ok"])
            self.assertIsNone(sent["applied_revision"])
            self.assertEqual(result["revision"], 2)
        status["system_sites"]["ok"] = True
        lg._atomic_json(self.path / "status.json", status)
        with patch.object(lg, "_central_request", return_value=response) as request:
            lg.sync_central()
            sent = request.call_args.args[2]
            self.assertTrue(sent["site_ok"])
            self.assertEqual(sent["applied_revision"], 1)  # Received revision 2 has not been applied yet.
        status["checked_at"] = "2000-01-01T00:00:00+00:00"
        lg._atomic_json(self.path / "status.json", status)
        with patch.object(lg, "_central_request", return_value=response) as request:
            lg.sync_central()
            self.assertIsNone(request.call_args.args[2]["applied_revision"])

    def test_first_heartbeat_is_pending_not_a_false_application_error(self):
        with patch.object(lg, "_central_request", return_value={"ok": True, **snapshot()}) as request:
            lg.sync_central()
        sent = request.call_args.args[2]
        self.assertIsNone(sent["site_ok"])
        self.assertIsNone(sent["applied_revision"])
        self.assertEqual(sent["error"], "")

    def test_invalid_policy_and_rollback_do_not_overwrite_cache(self):
        lg._atomic_json(self.path / lg._CENTRAL_POLICY, snapshot(3))
        for response in ({"ok": True, **snapshot(2)}, {"ok": True, **snapshot(3, domains=["changed.example"])},
                         {"ok": True, **snapshot(4, domains=["*.example"])}, {"ok": True, "revision": 4}):
            with self.subTest(response=response), patch.object(lg, "_central_request", return_value=response):
                with self.assertRaises((lg.CentralError, ValueError)):
                    lg.sync_central()
            self.assertEqual(lg._json_read(self.path / lg._CENTRAL_POLICY), snapshot(3))

    def test_unlink_during_poll_cannot_restore_a_removed_binding(self):
        def reply(*args, **kwargs):
            (self.path / lg._CENTRAL_CONFIG).unlink()
            (self.path / lg._CENTRAL_POLICY).unlink()
            return {"ok": True, **snapshot(2)}
        with patch.object(lg, "_central_request", side_effect=reply):
            self.assertFalse(lg.sync_central()["managed"])
        self.assertFalse((self.path / lg._CENTRAL_POLICY).exists())

    def test_unlink_restores_original_local_policy_and_does_not_remove_games(self):
        with patch.object(lg, "require_client_admin"), patch.object(lg, "_lc_load"), patch.object(lg, "_effective_domains", return_value=[]):
            self.assertTrue(lg.unlink_client()["ok"])
        self.assertFalse((self.path / lg._CENTRAL_CONFIG).exists())
        active, revision = lg._central_effective(self.local, self.path)
        self.assertEqual(active, self.local)
        self.assertIsNone(revision)

    def test_worker_applies_central_sites_and_keeps_the_local_game_policy(self):
        lg._atomic_json(self.path / "estado.json", {})
        lg.ClientCatalog(self.path / "banco.sqlite3").ensure()
        def sleep(_seconds):
            (self.path / "parar.flag").touch()
        with patch.object(lg, "client_runtime_guard"), patch.object(lg, "sync_central", return_value={"ok": True}), \
             patch.object(lg, "sync_sites", return_value={"ok": True}) as sites, \
             patch.object(lg, "sync_system_sites", return_value={"ok": True}), \
             patch.object(lg, "enforce_games", return_value={"ok": True}) as games, \
             patch.object(lg.time, "sleep", side_effect=sleep):
            self.assertEqual(lg.run_client_worker(), 0)
        self.assertEqual(sites.call_args.args[0]["domains"], ["game.example"])
        self.assertEqual(games.call_args.args[0]["games"], self.local["games"])
        self.assertEqual(games.call_args.args[0]["remove_roblox"], self.local["remove_roblox"])
        report = lg._json_read(self.path / "status.json")
        self.assertEqual(report["central_revision"], 1)
        self.assertTrue(report["ok"])

    def test_status_does_not_claim_failed_sites_were_applied(self):
        (self.path / "instalacao.json").write_text("{}")
        lg.ClientCatalog(self.path / "banco.sqlite3").ensure()
        effective, _ = lg._central_effective(self.local, self.path)
        lg._atomic_json(self.path / "status.json", {"ok": False, "checked_at": lg._utc_now(),
            "policy_revision": lg._policy_revision(effective), "central_revision": 1,
            "sites": {"ok": False}, "system_sites": {"ok": True}})
        with patch.object(lg, "client_task_status", return_value={"running": True, "user_start": True, "task_registered": True}):
            status = lg.get_client_status()
        self.assertTrue(status["managed"])
        self.assertIsNone(status["central"]["applied_revision"])
        self.assertEqual(status["central"]["expected_revision"], 1)
        self.assertNotIn(self.config["device_token"], json.dumps(status))

    def test_enrollment_does_not_return_token_or_rewrite_original_policy(self):
        (self.path / lg._CENTRAL_CONFIG).unlink()
        link = {"format": "labguard-central-v1", "server_url": self.config["server_url"], "ca_pem": "test-pem",
                "enrollment_token": "e" * 32}
        path = self.path / "vinculo.json"
        lg._atomic_json(path, link)
        response = {"ok": True, "device_id": self.config["device_id"], "device_token": self.config["device_token"], **snapshot()}
        with patch.object(lg, "require_client_admin"), patch.object(lg, "_lc_load", return_value={"version": lg.CLIENT_VERSION}), \
             patch.object(lg, "_central_tls"), patch.object(lg, "_central_request", return_value=response):
            result = lg.enroll_client(path)
        self.assertNotIn(self.config["device_token"], json.dumps(result))
        self.assertEqual(lg._json_read(self.path / "politica.json"), self.local)
        if os.name != "nt":
            self.assertEqual((self.path / lg._CENTRAL_CONFIG).stat().st_mode & 0o777, 0o600)
        else:
            # Assert the actual persisted Windows ACL, not just the intended SDDL.
            import ctypes
            import struct
            adv = ctypes.windll.advapi32
            dacl, sd = ctypes.c_void_p(), ctypes.c_void_p()
            error = adv.GetNamedSecurityInfoW(ctypes.c_wchar_p(str(self.path / lg._CENTRAL_CONFIG)),
                1, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(sd))
            self.assertEqual(error, 0)
            try:
                self.assertTrue(dacl.value)
                trustees = set()
                for index in range(ctypes.c_ushort.from_address(dacl.value + 4).value):
                    ace = ctypes.c_void_p()
                    self.assertTrue(adv.GetAce(dacl, index, ctypes.byref(ace)))
                    kind, flags, size, mask = struct.unpack("<BBHI", ctypes.string_at(ace.value, 8))
                    self.assertEqual(kind, 0)
                    trustees.add(lg._lc_sid(ace.value + 8))
                self.assertEqual(trustees, {"S-1-5-18", "S-1-5-32-544", "S-1-3-4"})
                control, revision = ctypes.c_ushort(), ctypes.c_ulong()
                self.assertTrue(adv.GetSecurityDescriptorControl(sd, ctypes.byref(control), ctypes.byref(revision)))
                self.assertTrue(control.value & 0x1000, "The secret DACL must not inherit Users read access.")
            finally:
                ctypes.windll.kernel32.LocalFree(sd)


class TransportTests(unittest.TestCase):
    def test_redirect_is_rejected_and_certificate_failure_does_not_fallback_to_http(self):
        config = {"server_url": "https://192.168.1.10:8788", "ca_pem": "fixture", "device_token": "d" * 32}
        with patch.object(lg, "_central_tls", return_value=object()), patch.object(lg.http.client, "HTTPSConnection") as factory:
            connection = factory.return_value
            connection.getresponse.return_value.status = 302
            connection.getresponse.return_value.read.return_value = b""
            with self.assertRaises(lg.CentralError):
                lg._central_request(config, "/api/agent/poll", {})
            self.assertEqual(connection.request.call_count, 1)
            self.assertEqual(connection.request.call_args.kwargs["headers"]["Authorization"], "Bearer " + "d" * 32)
            connection.request.side_effect = ssl.SSLCertVerificationError("fixture")
            with self.assertRaisesRegex(lg.CentralError, "Certificado"):
                lg._central_request(config, "/api/agent/poll", {})
            self.assertEqual(connection.request.call_count, 2)


if __name__ == "__main__":
    unittest.main()
