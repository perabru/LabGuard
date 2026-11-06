"""Contratos e limites da interface simples, sem janelas ou rede reais."""
from pathlib import Path
import hashlib
import json
import os
import queue
import tempfile
from time import monotonic
import types
import unittest
from unittest.mock import Mock, patch

from labguard.simple_gui import App, DiagnosticWindow, PolicyBankSelection, mutation_reason, snapshot_capabilities


def snapshot(mode="equipment", **caps):
    return {"mode": mode, "capabilities": {"inventory": True, **caps},
            "health": {"dns": True, "firewall": True, "forwarding": True}}


class SimpleUiTests(unittest.TestCase):
    @staticmethod
    def app(mode="equipment", **caps):
        app = App.__new__(App)
        app.snapshot = snapshot(mode, **caps)
        app.transport = Mock()
        app._management_authorized = True
        app._busy = app._closed = app._snapshot_stale = False
        app._last_snapshot_monotonic = monotonic()
        app.status = Mock()
        app._run_job = Mock(return_value=True)
        app._confirm = Mock(return_value=True)
        app._selected_device = Mock(return_value={"ip": "192.168.1.30", "mac": "02:00:00:00:00:30", "name": "LAB-01"})
        app.domain_var = Mock(get=Mock(return_value="games.example"))
        app.category_var = Mock(get=Mock(return_value="Jogos"))
        return app

    def test_real_equipment_needs_explicit_boolean_capabilities(self):
        self.assertFalse(snapshot_capabilities({"mode": "equipment"})["domain_filtering"])
        self.assertFalse(snapshot_capabilities(snapshot(domain_filtering="true"))["domain_filtering"])
        self.assertTrue(snapshot_capabilities(snapshot(domain_filtering=True))["domain_filtering"])
        self.assertTrue(snapshot_capabilities({"mode": "demo"})["domain_filtering"])
        self.assertFalse(snapshot_capabilities(snapshot("observation", domain_filtering=True))["domain_filtering"])

    def test_observation_can_never_authorize_network_mutations(self):
        data = snapshot("observation", domain_filtering=True, address_blocking=True)
        self.assertIn("somente consulta", mutation_reason(data, capability="domain_filtering"))
        app = self.app("observation", domain_filtering=True, device_internet_cut=True)
        app._add_domain(); app._set_block(True)
        app._run_job.assert_not_called()
        app._confirm.assert_not_called()

    def test_stale_busy_unhealthy_or_readonly_reject_controls(self):
        data = snapshot(domain_filtering=True)
        for options in ({"stale": True}, {"age": 21}, {"busy": True}, {"authorized": False}):
            self.assertIsNotNone(mutation_reason(data, capability="domain_filtering", **options))
        data["health"]["dns"] = False
        self.assertIsNotNone(mutation_reason(data, capability="domain_filtering", required_health=("dns",)))

    def test_equipment_capabilities_are_independent(self):
        data = snapshot(domain_filtering=True, address_blocking=False)
        self.assertIsNone(mutation_reason(data, capability="domain_filtering", required_health=("dns",)))
        self.assertIsNotNone(mutation_reason(data, capability="address_blocking"))
        app = self.app(domain_filtering=True, device_internet_cut=False, address_blocking=False, ai_block=False)
        app._set_block(True); app._set_address_block("ip", "192.168.1.30", True); app._toggle_ai()
        app._run_job.assert_not_called()

    def test_domain_request_uses_normalized_domain_and_serial_worker(self):
        app = self.app(domain_filtering=True)
        app.domain_var.get.return_value = "GAMES.EXAMPLE."
        self.assertTrue(app._add_domain())
        app._run_job.call_args.args[0]()
        app.transport.request.assert_called_once_with("add_domain", domain="games.example", category="Jogos")

    def test_confirmation_cannot_reuse_expired_inventory(self):
        app = self.app(domain_filtering=True)
        def confirm(*args):
            app._snapshot_stale = True
            return True
        app._confirm.side_effect = confirm
        self.assertFalse(app._add_domain())
        app._run_job.assert_not_called()

    def test_protected_or_unobserved_device_never_suspends(self):
        for values in ({"protected": True}, {"observed": False}):
            app = self.app(device_internet_cut=True)
            app._selected_device.return_value.update(values)
            self.assertFalse(app._set_block(True))
            app._confirm.assert_not_called(); app._run_job.assert_not_called()

    def test_missing_ip_is_never_sent_as_device_action(self):
        app = self.app(device_internet_cut=True)
        app._selected_device.return_value.pop("ip")
        self.assertFalse(app._set_block(True))
        app._confirm.assert_not_called(); app._run_job.assert_not_called()

    def test_removal_uses_stable_domain_identity_after_reordering(self):
        app = self.app(domain_filtering=True)
        app.domains_table = Mock(selection=Mock(return_value=("target.example",)))
        app.snapshot["domains"] = [{"domain": "other.example"}, {"domain": "target.example"}]
        self.assertTrue(app._remove_domain())
        app._run_job.call_args.args[0]()
        app.transport.request.assert_called_once_with("remove_domain", domain="target.example")

    def test_real_confirmation_defaults_to_no_and_demo_skips_dialog(self):
        app = self.app()
        with patch("labguard.simple_gui.messagebox.askyesno", return_value=False) as confirm:
            self.assertFalse(App._confirm(app, "Teste", "Alvo"))
        self.assertEqual(confirm.call_args.kwargs["default"], "no")
        app.snapshot["mode"] = "demo"
        with patch("labguard.simple_gui.messagebox.askyesno") as confirm:
            self.assertTrue(App._confirm(app, "Teste", "Alvo"))
        confirm.assert_not_called()

    def test_router_connect_passes_numeric_port_and_explicit_management_choice(self):
        app = self.app()
        values = {"profile_var": "Controlar MikroTik via HTTPS", "port_var": "443", "host_var": "192.168.1.1", "user_var": "admin",
            "password_var": "session-only", "ca_var": "ca.pem", "key_var": "", "known_hosts_var": "", "manage_var": False,
            "wan_var": "WAN", "cidr_var": "", "protected_ips_var": "", "protected_macs_var": ""}
        for key, value in values.items():setattr(app, key, Mock(get=Mock(return_value=value)))
        app._start_transport = Mock(return_value=True)
        self.assertTrue(app._connect())
        kind, settings = app._start_transport.call_args.args
        self.assertEqual(kind, "routeros"); self.assertIs(type(settings["port"]), int)
        self.assertFalse(settings["manage_rules"])
        self.assertFalse(app._start_transport.call_args.kwargs["authorized"])

    def test_observation_is_explicitly_separate_from_demo(self):
        app = self.app(); app.password_var = Mock(); app.manage_var = Mock(); app._start_transport = Mock()
        app._observe()
        app._start_transport.assert_called_once_with("observation", {}, authorized=False)
        app.password_var.set.assert_called_with("")

    def test_remote_inventory_accepts_real_observation_but_rejects_demo_ips(self):
        app = self.app("observation")
        with patch("labguard.remote_gui.RemoteWindow") as window:
            app._open_remote()
            window.assert_called_once()
        app.snapshot["mode"] = "demo"
        with patch("labguard.remote_gui.RemoteWindow") as window:
            self.assertIsNone(app._open_remote())
            window.assert_not_called()

    def test_ai_seed_only_changes_local_database(self):
        app = self.app("observation")
        app._banlist_path = Mock(return_value=Path("local.sqlite3")); app._open_banlist = Mock()
        helper = Mock(); fake = types.SimpleNamespace(seed_ai_catalog=helper)
        with patch.dict("sys.modules", {"labguard.controller": fake}), patch("labguard.banlist.BanlistDatabase") as database:
            app._seed_ai_catalog()
        helper.assert_called_once_with(database.return_value)
        database.return_value.close.assert_called_once()
        app.transport.request.assert_not_called(); app._run_job.assert_not_called()

    def test_connection_completed_during_close_discards_session(self):
        app = self.app()
        app._generation = 0; app._refresh_mutation_controls = Mock(); app.refresh_button = Mock()
        app._executor = Mock(submit=Mock(side_effect=lambda function:function()))
        app._results = Mock()
        app._results.put.side_effect = lambda value:setattr(app, "_closed", True)
        opened = Mock()
        self.assertTrue(App._run_job(app, lambda:(opened, snapshot()), label="Conectar"))
        opened.close.assert_called_once()

    def test_diagnostic_retry_only_reads_current_connection_and_never_creates_one(self):
        app = self.app("observation")
        app._management_authorized = False
        app.transport.kind = "observation"
        with patch("labguard.simple_gui.create_transport") as factory:
            self.assertTrue(app._diagnostic_refresh())
            app._run_job.call_args.args[0]()
        app.transport.request.assert_called_once_with("snapshot")
        factory.assert_not_called(); self.assertFalse(app._management_authorized)

    def test_diagnostic_retry_rejects_legacy_snapshot_kind_or_raw_ssh(self):
        from labguard.transport import SSHTransport
        for mode, kind, raw in (("gateway", "", False), ("observation", "legacy", False), ("observation", "", True)):
            app = self.app(mode)
            app.transport = SSHTransport.__new__(SSHTransport) if raw else Mock(kind=kind)
            app.transport.request = Mock()
            self.assertFalse(app._diagnostic_refresh())
            app._run_job.assert_not_called(); app.transport.request.assert_not_called()

    def test_diagnostic_window_is_reused_without_network_or_permission_changes(self):
        app = self.app("observation"); window = Mock(); window.winfo_exists.return_value = True
        app._diagnostics_window = window
        with patch("labguard.simple_gui.DiagnosticWindow") as constructor:
            self.assertIs(app._open_diagnostics(), window)
        constructor.assert_not_called(); window.lift.assert_called_once()
        app.transport.request.assert_not_called()

    def test_worker_error_offers_help_without_opening_it_or_retaining_raw_error(self):
        app = self.app(); app._generation = 0; app._results = queue.Queue()
        app._results.put((0, False, "HTTP 401 secret-password-xyz https://admin:secret-password-xyz@router/rest", None, True))
        app.refresh_button = Mock(); app.password_var = Mock(); app.error_help_button = Mock()
        app._render_home = Mock(); app._notify_diagnostics = Mock(); app._refresh_mutation_controls = Mock()
        app.after = Mock(); app._open_diagnostics = Mock()
        with patch("labguard.simple_gui.messagebox.showerror") as dialog:
            app._drain()
        self.assertEqual(app._last_error, "authentication")
        app.error_help_button.pack.assert_called_once(); app._open_diagnostics.assert_not_called()
        self.assertNotIn("secret-password-xyz", app.status.set.call_args.args[0])
        self.assertNotIn("secret-password-xyz", dialog.call_args.args[1])
        self.assertNotIn("https://", dialog.call_args.args[1])
        self.assertIn("revise o estado", dialog.call_args.args[1])

    def test_diagnostic_navigation_is_bounded_and_does_not_request_data(self):
        window = DiagnosticWindow.__new__(DiagnosticWindow)
        window.plan = {"steps": [{"id": "start"}, {"id": "finish"}]}; window.index = 0
        window._show_step = Mock(); window.owner = Mock()
        window._back(); self.assertEqual(window.index, 0)
        window._next(); window._next(); self.assertEqual(window.index, 1)
        window._back(); self.assertEqual(window.index, 0)
        self.assertEqual(window._show_step.call_count, 2)
        window.owner._diagnostic_refresh.assert_not_called()


class PolicyBankSelectionTests(unittest.TestCase):
    def target(self, host="192.168.1.1", port=443):
        return types.SimpleNamespace(host=host, port=port, password="NEVER-PERSIST-THIS")

    def test_offline_rows_follow_first_router_and_survive_disconnect_restart(self):
        from labguard.banlist import BanlistDatabase
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyBankSelection(directory)
            prepared = store.path_for({"mode": "observation"}, self.target())
            database = BanlistDatabase(prepared)
            database.upsert("games.example", "Jogos", True, "Lista preparada offline")
            database.close()
            real = store.path_for({"mode": "equipment"}, self.target())
            self.assertEqual(prepared, real)
            self.assertEqual(BanlistDatabase(real).list_sites()[0]["domain"], "games.example")
            self.assertEqual(store.path_for({"mode": "observation"}, self.target()), real)
            restarted = PolicyBankSelection(directory)
            self.assertEqual(restarted.path_for({"mode": "observation"}, self.target()), real)
            self.assertEqual(restarted.path_for({"mode": "equipment"}, self.target()), real)

    def test_second_destination_is_separate_and_returning_uses_original_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyBankSelection(directory)
            first = store.path_for({"mode": "equipment"}, self.target())
            second = store.path_for({"mode": "equipment"}, self.target("192.168.2.1"))
            self.assertNotEqual(first, second)
            self.assertFalse(second.exists())  # Nenhum cadastro ou arquivo foi copiado.
            restarted = PolicyBankSelection(directory)
            self.assertEqual(restarted.path_for({"mode": "observation"}, self.target()), second)
            self.assertEqual(restarted.path_for({"mode": "equipment"}, self.target()), first)

    def test_demo_does_not_change_the_active_real_bank(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyBankSelection(directory)
            first = store.path_for({"mode": "equipment"}, self.target())
            demo = store.path_for({"mode": "demo"}, self.target("", ""))
            self.assertNotEqual(first, demo)
            self.assertEqual(store.path_for({"mode": "observation"}, self.target()), first)
            self.assertEqual(PolicyBankSelection(directory).path_for({"mode": "observation"}, self.target()), first)

    def test_legacy_database_name_is_preserved_and_reference_contains_no_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyBankSelection(directory)
            transport = self.target("192.168.50.1", 22)
            path = store.path_for({"mode": "gateway"}, transport)
            expected = hashlib.sha256(b"gateway|192.168.50.1|22").hexdigest()[:24]+".sqlite3"
            self.assertEqual(path.name, expected)
            data = store.state_path.read_text(encoding="utf-8")
            self.assertNotIn(transport.password, data)
            self.assertEqual(set(json.loads(data)), {"version", "active_bank", "real_target", "targets"})
            if os.name != "nt":self.assertEqual(store.state_path.stat().st_mode & 0o777, 0o600)

    def test_invalid_reference_cannot_escape_directory_or_reassign_default_to_new_router(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/"policy_state_v2.json"
            state.write_text(json.dumps({"version": 1, "active_bank": "../other.sqlite3", "real_target": None, "targets": {}}), encoding="utf-8")
            store = PolicyBankSelection(directory)
            self.assertTrue(store.warning)
            path = store.path_for({"mode": "equipment"}, self.target())
            self.assertEqual(path.parent, Path(directory))
            self.assertTrue(path.name.startswith("equipment-"))
            self.assertNotEqual(path.name, "policy2.sqlite3")


class ControllerRestUiTests(unittest.TestCase):
    def test_equipment_ip_round_trip_uses_real_controller_and_preserves_mac(self):
        from labguard.controller import ControllerTransport
        from labguard.direct_routeros import DirectRouterOSTransport
        from tests.test_direct_routeros import Router
        router = Router()
        direct = DirectRouterOSTransport("192.168.88.1", user="labguard", password="test-password", manage_rules=True)
        direct._opener = router
        controller = ControllerTransport("routeros", direct)
        try:
            data = controller.request("set_address_block", kind="mac", address="02:00:00:00:00:01", blocked=True)
            self.assertFalse(data["capabilities"]["device_internet_cut"])
            app = SimpleUiTests.app()
            app.transport, app.snapshot = controller, data
            app._selected_device.return_value = next(d for d in data["devices"] if d["ip"] == "192.168.88.101")
            for name in ("domain_add_button", "domain_remove_button", "ai_button", "block_button", "unblock_button", "device_selection_text", "connect_button", "disconnect_button"):
                setattr(app, name, Mock())
            app._refresh_mutation_controls()
            self.assertEqual(app.block_button.configure.call_args.kwargs, {"text": "Bloquear IP", "state": "normal"})
            self.assertEqual(app.unblock_button.configure.call_args.kwargs["state"], "disabled")
            self.assertTrue(app._set_block(True))
            data = app._run_job.call_args.args[0]()  # Controller + API REST simulada reais.
            selected = next(d for d in data["devices"] if d["ip"] == "192.168.88.101")
            self.assertTrue(selected["blocked_ip"]); self.assertTrue(selected["blocked_mac"])
            app.snapshot = data; app._selected_device.return_value = selected
            self.assertTrue(app._set_block(False))
            released = app._run_job.call_args.args[0]()
            selected = next(d for d in released["devices"] if d["ip"] == "192.168.88.101")
            self.assertFalse(selected["blocked_ip"]); self.assertTrue(selected["blocked_mac"])
            self.assertTrue(selected["blocked"])
            self.assertEqual([row["kind"] for row in released["address_blocks"]], ["mac"])
        finally:controller.close()

    def test_readonly_real_controller_does_not_schedule_equipment_cut(self):
        from labguard.controller import ControllerTransport
        from labguard.direct_routeros import DirectRouterOSTransport
        from tests.test_direct_routeros import Router
        router = Router(); direct = DirectRouterOSTransport("192.168.88.1", user="read", password="test-password")
        direct._opener = router; controller = ControllerTransport("routeros", direct)
        try:
            app = SimpleUiTests.app(); app.transport = controller; app.snapshot = controller.request("snapshot")
            app._selected_device.return_value = next(d for d in app.snapshot["devices"] if d["ip"] == "192.168.88.101")
            self.assertFalse(app._set_block(True))
            app._run_job.assert_not_called(); self.assertEqual(router.mutations, [])
        finally:controller.close()


if __name__ == "__main__":unittest.main()
