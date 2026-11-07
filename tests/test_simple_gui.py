"""Contratos e limites da interface simples, sem janelas ou rede reais."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import queue
import tempfile
from threading import Event
from time import monotonic
import types
import unittest
from unittest.mock import Mock, patch

from labguard.simple_gui import (App, DiagnosticWindow, PolicyBankSelection, mutation_reason,
                                snapshot_capabilities, inventory_presentation, conflicted_device_ips)


def snapshot(mode="equipment", **caps):
    return {"mode": mode, "timestamp": datetime.now(timezone.utc).isoformat(), "capabilities": {"inventory": True, **caps},
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


class InventoryUiTests(unittest.TestCase):
    def observed(self):
        data = snapshot("observation")
        data.update(interfaces=[{"name": "LAN", "ipv4": "192.168.1.10/24"}],
                    discovery={"read_success": True, "interfaces_read": True, "routes_read": True, "neighbors_read": True},
                    devices=[{"name": "Este computador", "ip": "192.168.1.10", "mac": "", "state": "Endereço local"},
                             {"name": "Estação", "ip": "192.168.1.30", "mac": "02:00:00:00:00:30"}])
        return data

    def receiver(self, mode="observation"):
        app = SimpleUiTests.app(mode)
        app._banks = Mock(); app._banks.warning = ""
        for name in ("_render_home", "_render_devices", "_render_sites", "_render_activity", "_refresh_mutation_controls", "_notify_diagnostics"):
            setattr(app, name, Mock())
        app.error_help_button = Mock(); app.refresh_button = Mock()
        return app

    def test_card_confirmed_partial_unavailable_and_local_stale_override(self):
        data = self.observed()
        view = inventory_presentation(data)
        self.assertEqual(view["state"], "Leitura confirmada · cobertura parcial")
        self.assertEqual(view["evidence"]["counts"]["observed_neighbors"], 1)
        self.assertEqual(inventory_presentation(data, stale=True)["state"], "Dados desatualizados")
        self.assertEqual(inventory_presentation(data, busy=True)["state"], "Consultando · leitura anterior")
        data["discovery"] = {"read_success": False, "interfaces_read": False, "routes_read": False, "neighbors_read": False}
        data["devices"], data["interfaces"] = [], []
        self.assertEqual(inventory_presentation(data)["state"], "Leitura indisponível")

    def test_new_failed_collection_keeps_old_rows_and_their_receipt_time(self):
        app = self.receiver(); previous = self.observed()
        app.snapshot = previous; app._snapshot_source = app._snapshot_identity(previous)
        old_clock = app._last_snapshot_monotonic
        failed = snapshot("observation")
        failed.update(devices=[], discovery={"read_success": False, "interfaces_read": False, "routes_read": False, "neighbors_read": False})
        self.assertFalse(app._apply_snapshot(failed))
        self.assertIs(app.snapshot, previous); self.assertTrue(app._snapshot_stale)
        self.assertEqual(app._last_snapshot_monotonic, old_clock)
        app._render_devices.assert_not_called(); app._banks.path_for.assert_not_called()
        self.assertIn("desatualizados", app.status.set.call_args.args[0])

    def test_failed_real_collection_never_adopts_previous_demo_inventory(self):
        app = self.receiver("demo")
        app.snapshot["devices"] = [{"ip": "192.168.50.101", "name": "Fictício"}]
        app._snapshot_source = app._snapshot_identity(app.snapshot)
        app.transport = Mock(kind="observation", host="", port="")
        failed = snapshot("observation")
        failed.update(devices=[], discovery={"read_success": False, "interfaces_read": False, "routes_read": False, "neighbors_read": False})
        self.assertTrue(app._apply_snapshot(failed))
        self.assertEqual(app.snapshot["mode"], "observation"); self.assertEqual(app.snapshot["devices"], [])
        self.assertTrue(app._snapshot_stale); app._render_devices.assert_called_once()

    def test_old_missing_naive_or_future_source_never_becomes_fresh_on_arrival(self):
        values = [None, "invalid", datetime.now().isoformat(),
                  (datetime.now(timezone.utc)-timedelta(seconds=25)).isoformat(),
                  (datetime.now(timezone.utc)+timedelta(seconds=5)).isoformat()]
        for stamp in values:
            app = SimpleUiTests.app(domain_filtering=True); app.snapshot["timestamp"] = stamp
            self.assertFalse(app._add_domain())
            app._confirm.assert_not_called(); app._run_job.assert_not_called()

    def test_failed_or_invalid_collection_metadata_cannot_authorize_dns(self):
        for metadata in ({"read_success": False}, {"read_success": "yes"}, []):
            data = snapshot(domain_filtering=True); data["discovery"] = metadata
            data["inventory_summary"] = {"fresh": True, "facts": {"read_success": True}}
            self.assertIsNotNone(mutation_reason(data, capability="domain_filtering", required_health=("dns",)))
        data = snapshot(inventory=False, domain_filtering=True)
        self.assertIsNone(mutation_reason(data, capability="domain_filtering", required_health=("dns",)))

    def test_zero_inventory_does_not_disable_legitimate_dns_after_applying_snapshot(self):
        app = self.receiver("equipment")
        data = snapshot(inventory=False, domain_filtering=True)
        self.assertTrue(app._apply_snapshot(data))
        self.assertFalse(app._snapshot_stale)
        self.assertTrue(app._mutation_allowed(("dns",), capability="domain_filtering"))

    def test_summary_is_not_an_authority_for_observation_or_missing_capability(self):
        misleading = {"fresh": True, "capabilities": {"domain_filtering": True},
                      "facts": {"read_success": True, "collection_metadata_valid": True}}
        for mode, capability in (("observation", True), ("equipment", False)):
            app = SimpleUiTests.app(mode, domain_filtering=capability)
            with patch("labguard.simple_gui.summarize_inventory", return_value=misleading):
                self.assertFalse(app._add_domain())
            app._run_job.assert_not_called()

    def test_duplicate_device_and_domain_records_keep_distinct_table_keys(self):
        app = SimpleUiTests.app("observation")
        own = {"ip": "192.168.1.10", "mac": "", "state": "Endereço local", "name": "LAN"}
        app.snapshot["devices"] = [dict(own), dict(own)]
        app.device_search = Mock(get=Mock(return_value="")); app.devices_table = Mock(); app.devices_note = Mock()
        app._fill = Mock(); app._render_devices()
        rows = app._fill.call_args.args[1]
        self.assertEqual(len(rows), 2); self.assertEqual(len({key for key, _ in rows}), 2)
        app.snapshot["domains"] = [{"domain": "same.example", "source": "external"}, {"domain": "same.example", "source": "external"}]
        app.domains_table = Mock(); app.site_note = Mock(); app.ai_button = Mock()
        app._render_sites(); rows = app._fill.call_args.args[1]
        self.assertEqual(len(rows), 2); self.assertEqual(len({key for key, _ in rows}), 2)

    def test_identity_conflicts_are_visible_and_block_device_address_and_remote_actions(self):
        app = SimpleUiTests.app(address_blocking=True)
        one = {"ip": "192.168.1.30", "mac": "02:00:00:00:00:30", "name": "A"}
        two = {"ip": "192.168.1.30", "mac": "02:00:00:00:00:31", "name": "B"}
        app.snapshot["devices"] = [one, two]; app._selected_device.return_value = one
        self.assertEqual(conflicted_device_ips(app.snapshot), {"192.168.1.30"})
        for blocked in (True, False):
            self.assertFalse(app._set_block(blocked))
            self.assertFalse(app._set_address_block("ip", one["ip"], blocked))
            self.assertFalse(app._set_address_block("mac", one["mac"], blocked))
        with patch("labguard.remote_gui.RemoteWindow") as remote:
            self.assertIsNone(app._open_remote()); remote.assert_not_called()
        app._run_job.assert_not_called(); app._confirm.assert_not_called()
        app.device_search = Mock(get=Mock(return_value="")); app.devices_table = Mock(); app.devices_note = Mock(); app._fill = Mock()
        app._render_devices()
        self.assertTrue(all("Identidade incerta" in row[1][3] for row in app._fill.call_args.args[1]))

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


class StartupAndUpdateUiTests(unittest.TestCase):
    """Fluxos locais sem rede, cofre real ou execução de instaladores."""
    @staticmethod
    def profile(**changes):
        from labguard.preferences import normalize_router_profile
        return normalize_router_profile({"host": "192.168.88.1", "port": 8443, "user": "lab-read", **changes})

    def app(self, mode="observation"):
        from labguard.preferences import default_preferences, normalize_preferences
        app = SimpleUiTests.app(mode)
        app._generation = 0; app._updates_enabled = True; app._demo_requested = mode == "demo"
        app._preferences = default_preferences()
        app._preference_store = Mock(save=Mock(side_effect=normalize_preferences))
        app._credential_store = Mock(load=Mock(return_value="vault-secret-sentinel"))
        app._vault_available = True
        app._startup_observation_pending = True; app._startup_attempted = False
        app._auto_connect_in_progress = False; app._restore_id = None
        app._startup_message = ""; app._startup_status = Mock()
        app._update_manager = Mock()
        app._update_manager.check_update.return_value = {"state": "current"}
        app._update_manager.stage_update.return_value = {"state": "prepared", "prepared_id": "verified", "can_apply": True, "auto_apply": True}
        app._update_manager.schedule_apply.return_value = True
        app._update_installation = {"supported": True, "auto_apply": True}
        app._update_generation = 0; app._update_results = queue.Queue(); app._update_busy = False
        app._update_thread = None; app._prepared_update = None; app._update_start_pending = True
        app._render_background_options = Mock(); app._profile_changed = Mock()
        app._start_transport = Mock(return_value=True)
        app.after_idle = Mock(return_value="restore-timer"); app.after_cancel = Mock()
        app.winfo_children = Mock(return_value=[])
        for field in ("manage_var", "profile_var", "port_var", "password_var", "remember_profile_var", "store_password_var", "auto_connect_var", "auto_updates_var"):
            setattr(app, field, Mock())
        return app

    def saved(self, app):
        app._preferences.update(saved_router=self.profile(), auto_connect=True)

    def finish_update(self, app):
        app._update_thread.join(timeout=2)
        self.assertFalse(app._update_thread.is_alive())
        app._drain_update_results()

    def test_observation_queues_one_optional_readonly_startup_attempt(self):
        app = self.app(); self.saved(app)
        app._queue_saved_startup(); app._queue_saved_startup()
        app.after_idle.assert_called_once_with(app._restore_saved_connection)
        self.assertTrue(app._restore_saved_connection())
        self.assertFalse(app._restore_saved_connection())
        app._start_transport.assert_called_once()
        kind, settings = app._start_transport.call_args.args
        self.assertEqual(kind, "routeros"); self.assertFalse(settings["manage_rules"])
        self.assertEqual(settings["password"], "vault-secret-sentinel")
        self.assertFalse(app._start_transport.call_args.kwargs["authorized"])
        self.assertIsNone(app._start_transport.call_args.kwargs.get("remember_options"))
        app.manage_var.set.assert_called_with(False); app.port_var.set.assert_called_with("8443")
        app.transport.request.assert_not_called(); app._run_job.assert_not_called()

    def test_no_automatic_connection_without_optin_vault_or_secret(self):
        for setting in ("optout", "unavailable", "missing", "error", "demo"):
            app = self.app("demo" if setting == "demo" else "observation"); self.saved(app)
            if setting == "optout":app._preferences["auto_connect"] = False
            if setting == "unavailable":app._vault_available = False
            if setting == "missing":app._credential_store.load.return_value = None
            if setting == "error":app._credential_store.load.side_effect = RuntimeError("secret-sentinel")
            self.assertFalse(app._restore_saved_connection(), setting)
            app._start_transport.assert_not_called()
            self.assertNotIn("secret-sentinel", app._startup_message)
            self.assertEqual(app.snapshot["mode"], "demo" if setting == "demo" else "observation")

    def test_failed_saved_attempt_keeps_observation_and_does_not_loop(self):
        app = self.app(); self.saved(app); old = app.snapshot
        app._restore_saved_connection()
        app._start_transport.call_args.kwargs["on_error"]("authentication")
        self.assertIs(app.snapshot, old); self.assertFalse(app._auto_connect_in_progress)
        self.assertFalse(app._restore_saved_connection())
        app._start_transport.assert_called_once(); app._confirm.assert_not_called()

    def test_user_choice_cancels_pending_and_late_automatic_session(self):
        app = self.app(); self.saved(app)
        app._restore_id = "pending"; app._auto_connect_in_progress = True; app._busy = True
        app._cancel_saved_startup()
        self.assertEqual(app._generation, 1); self.assertFalse(app._busy)
        self.assertFalse(app._auto_connect_in_progress); self.assertFalse(app._startup_observation_pending)
        app.after_cancel.assert_called_once_with("pending")
        app._results = queue.Queue(); late = Mock()
        app._results.put((0, True, (late, snapshot()), Mock(), False))
        app.refresh_button = Mock(); app.after = Mock()
        app._drain()
        late.close.assert_called_once(); self.assertEqual(app.snapshot["mode"], "observation")

    def test_save_success_records_public_profile_and_explicit_vault_only(self):
        for store, automatic in ((False, False), (True, True)):
            app = self.app()
            settings = dict(self.profile(), password="vault-secret-sentinel", manage_rules=True)
            app._remember_successful_router(settings, {"remember": True, "store_password": store, "auto_connect": automatic})
            data = app._preference_store.save.call_args.args[0]
            encoded = json.dumps(data)
            self.assertNotIn("vault-secret-sentinel", encoded); self.assertNotIn("manage_rules", encoded)
            self.assertEqual(data["auto_connect"], automatic)
            self.assertEqual(app._credential_store.store.call_count, int(store))
            app.transport.request.assert_not_called()

    def test_changed_ca_does_not_delete_same_vault_identity(self):
        app = self.app(); self.saved(app)
        settings = dict(self.profile(ca_file="new-ca.pem"), password="vault-secret-sentinel")
        app._remember_successful_router(settings, {"remember": True, "store_password": True, "auto_connect": True})
        app._credential_store.store.assert_called_once(); app._credential_store.delete.assert_not_called()
        self.assertTrue(app._preferences["auto_connect"])

    def test_changed_target_removes_old_vault_reference_after_public_save(self):
        app = self.app(); self.saved(app); old = app._preferences["saved_router"]
        settings = dict(self.profile(host="192.168.88.2"), password="vault-secret-sentinel")
        app._remember_successful_router(settings, {"remember": True, "store_password": True, "auto_connect": True})
        app._credential_store.delete.assert_called_once_with(old)
        self.assertEqual(app._preferences["saved_router"]["host"], "192.168.88.2")

    def test_forget_access_is_local_and_disables_reference_even_if_vault_delete_fails(self):
        app = self.app(); self.saved(app)
        app._credential_store.delete.side_effect = RuntimeError("secret-sentinel")
        self.assertTrue(app._forget_saved_access())
        self.assertIsNone(app._preferences["saved_router"]); self.assertFalse(app._preferences["auto_connect"])
        self.assertIn("não foi confirmada", app._startup_message)
        self.assertNotIn("secret-sentinel", app._startup_message)
        app.transport.request.assert_not_called(); app._run_job.assert_not_called()

    def test_malformed_local_options_fall_back_without_network_or_secrets(self):
        app = App.__new__(App)
        with patch("labguard.preferences.PreferenceStore") as store, patch("labguard.credential_store.CredentialStore") as vault, patch("labguard.updater.UpdateManager") as updater:
            store.return_value.load.side_effect = RuntimeError("secret-sentinel")
            vault.return_value.available.return_value = False
            updater.return_value.installation_status.return_value = {"supported": False, "auto_apply": False}
            app._load_local_options()
        self.assertFalse(app._preferences["auto_connect"]); self.assertIsNone(app._preferences["saved_router"])
        self.assertFalse(app._preferences["auto_updates"])
        self.assertNotIn("secret-sentinel", app._startup_message)
        updater.return_value.check_update.assert_not_called(); vault.return_value.load.assert_not_called()

    def test_local_options_use_delivered_credential_store_module(self):
        app = App.__new__(App)
        with patch("labguard.preferences.PreferenceStore") as store, patch("labguard.credential_store.CredentialStore") as vault, patch("labguard.updater.UpdateManager"):
            from labguard.preferences import default_preferences
            store.return_value.load.return_value = default_preferences()
            vault.return_value.available.return_value = True
            app._load_local_options()
        self.assertIs(app._credential_store, vault.return_value)
        self.assertTrue(app._vault_available); self.assertTrue(app._preferences["auto_updates"])

    def test_forget_or_disable_automatic_access_cancels_inflight_restore(self):
        for action in ("_forget_saved_access", "_disable_saved_autoconnect"):
            app = self.app(); self.saved(app)
            app._auto_connect_in_progress = True; app._busy = True
            getattr(app, action)()
            self.assertEqual(app._generation, 1, action)
            self.assertFalse(app._auto_connect_in_progress)
            self.assertFalse(app._preferences["auto_connect"])

    def test_reenable_updates_requeues_one_check_after_old_worker_cancels(self):
        app = self.app(); app._update_start_pending = False
        app.auto_updates_var.get.return_value = True
        app._save_update_preference(); self.finish_update(app)
        app._update_manager.check_update.assert_called_once()
        self.assertFalse(app._update_start_pending)

    def test_source_demo_cli_and_portable_do_not_automatically_check_or_download(self):
        for kind in ("source", "demo", "cli", "portable", "optout"):
            app = self.app("demo" if kind == "demo" else "observation")
            if kind == "source":app._update_installation = {"supported": False, "auto_apply": False}
            if kind == "portable":app._update_installation = {"supported": True, "auto_apply": False}
            if kind == "cli":app._updates_enabled = False
            if kind == "optout":app._preferences["auto_updates"] = False
            self.assertFalse(app._automatic_update_check(), kind)
            app._update_manager.check_update.assert_not_called(); app._update_manager.stage_update.assert_not_called()

    def test_update_worker_is_daemon_and_independent_of_busy_router(self):
        app = self.app(); app._busy = True
        app._update_manager.check_update.return_value = {"state": "available", "candidate_id": "fixed-repository"}
        self.assertTrue(app._automatic_update_check()); self.finish_update(app)
        self.assertTrue(app._update_thread.daemon); self.assertTrue(app._busy)
        app._run_job.assert_not_called(); app.transport.request.assert_not_called()
        self.assertEqual(app._prepared_update["prepared_id"], "verified")
        app._update_manager.schedule_apply.assert_not_called()
        self.assertFalse(app._schedule_update_on_close())

    def test_offline_update_preserves_inventory_and_never_exposes_raw_error(self):
        app = self.app(); old = app.snapshot
        app._update_manager.check_update.side_effect = RuntimeError("https://secret-sentinel@invalid/")
        self.assertTrue(app._automatic_update_check()); self.finish_update(app)
        self.assertIs(app.snapshot, old); self.assertFalse(app._snapshot_stale)
        self.assertNotIn("secret-sentinel", app._update_message); self.assertIn("continuar", app._update_message)
        app._update_manager.schedule_apply.assert_not_called(); app._run_job.assert_not_called()

    def test_frozen_portable_manual_check_never_stages(self):
        app = self.app(); app._update_installation["auto_apply"] = False
        app._update_manager.check_update.return_value = {"state": "available", "candidate_id": "fixed"}
        self.assertTrue(app._check_for_updates()); self.finish_update(app)
        app._update_manager.stage_update.assert_not_called(); self.assertIsNone(app._prepared_update)

    def test_prepared_update_schedules_only_at_close_and_with_current_consent(self):
        app = self.app(); manager = app._update_manager
        app._update_manager.check_update.return_value = {"state": "available", "candidate_id": "fixed"}
        app._automatic_update_check(); self.finish_update(app)
        manager.schedule_apply.assert_not_called()
        self.assertTrue(app._schedule_update_on_close())
        manager.schedule_apply.assert_called_once_with(app._prepared_update, os.getpid(), consent=True)
        for state in ("demo", "optout", "partial", "busy"):
            blocked = self.app(); blocked._prepared_update = dict(app._prepared_update)
            if state == "demo":blocked.snapshot["mode"] = "demo"
            if state == "optout":blocked._preferences["auto_updates"] = False
            if state == "partial":blocked._prepared_update = None; blocked._update_busy = True
            if state == "busy":blocked._busy = True
            self.assertFalse(blocked._schedule_update_on_close(), state)
            blocked._update_manager.schedule_apply.assert_not_called()

    def test_optout_cancels_download_and_late_queue_cannot_prepare_or_apply(self):
        app = self.app(); manager = app._update_manager
        app.auto_updates_var.get.return_value = False
        app._save_update_preference()
        manager.close.assert_called_once(); self.assertFalse(app._preferences["auto_updates"])
        app._update_results.put((0, "done", {"state": "prepared", "prepared_id": "late", "can_apply": True, "auto_apply": True}))
        app._drain_update_results(); self.assertIsNone(app._prepared_update)
        self.assertFalse(app._schedule_update_on_close()); manager.schedule_apply.assert_not_called()

    def test_update_return_after_close_is_ignored_without_worker_blocking(self):
        app = self.app(); manager = app._update_manager
        started, finish = Event(), Event()
        def delayed():
            started.set(); finish.wait(2)
            return {"state": "available", "candidate_id": "fixed"}
        manager.check_update.side_effect = delayed
        app._automatic_update_check(); self.assertTrue(started.wait(1))
        app._closed = True; app._stop_update_manager(); finish.set()
        app._update_thread.join(timeout=2)
        self.assertTrue(app._update_results.empty()); manager.stage_update.assert_not_called()
        manager.schedule_apply.assert_not_called(); self.assertIsNone(app._prepared_update)


if __name__ == "__main__":unittest.main()
