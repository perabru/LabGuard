"""Fronteiras da administração sem agente, sem abrir conexões nem janelas."""
import unittest
from time import monotonic
from unittest.mock import Mock, patch

from labguard.remote_gui import RemoteWindow, package_removable, warning_categories


class RemoteUiTests(unittest.TestCase):
    def app(self, protected=False):
        app = RemoteWindow.__new__(RemoteWindow)
        app.target_ip = "192.168.50.101"
        app.protected = protected
        app.session = Mock()
        app.snapshot = {"capabilities": {"inventory": True, "uninstall": True, "notify": True}}
        app._busy = False
        app._closed = False
        app._stale = False
        app._last_snapshot = monotonic()
        app._last_activity = monotonic()
        app._last_warning = {}
        app._seen_dns = set()
        app._pending_warnings = set()
        app.status = Mock()
        app.package_table = Mock()
        app.package_table.selection.return_value = ("pkg:0",)
        app._packages = {"pkg:0": {"id": "roblox", "name": "Roblox", "install_id": "STORE-ROBLOX-EXACT",
                                   "method": "appx", "can_uninstall": True}}
        app._run = Mock(return_value=True)
        app._append_log = Mock()
        app._show = Mock()
        return app

    def test_removal_requires_supported_package_and_unprotected_target(self):
        self.assertTrue(package_removable({"can_uninstall": True}))
        self.assertFalse(package_removable({"can_uninstall": "true"}))
        self.assertFalse(package_removable({"can_uninstall": True}, protected=True))
        for protected, supported in ((True, True), (False, False)):
            app = self.app(protected)
            app._packages["pkg:0"]["can_uninstall"] = supported
            with patch("labguard.remote_gui.messagebox.askyesno") as confirm:
                app._uninstall()
            app._run.assert_not_called()
            confirm.assert_not_called()

    def test_removal_gets_preview_and_passes_only_confirmed_opaque_token(self):
        app = self.app()
        app.session.preview_uninstall.return_value = {"host": app.target_ip, "token": "opaque-confirmation",
            "game": app._packages["pkg:0"], "expires_in": 60, "data_notice": "Dados locais podem ser removidos."}
        app._uninstall()
        first_function = app._run.call_args.args[0]
        callback = app._run.call_args.args[1]
        preview = first_function()
        app.session.preview_uninstall.assert_called_once_with("STORE-ROBLOX-EXACT")
        with patch("labguard.remote_gui.messagebox.askyesno", return_value=True) as confirm:
            callback(preview)
        self.assertIn(app.target_ip, confirm.call_args.args[1])
        self.assertIn("Dados locais podem ser removidos", confirm.call_args.args[1])
        self.assertEqual(confirm.call_args.kwargs["default"], "no")
        second_function = app._run.call_args.args[0]
        second_function()
        app.session.uninstall.assert_called_once_with("opaque-confirmation")

    def test_preview_target_mismatch_and_decline_never_uninstall(self):
        for host, answer in (("192.168.50.222", True), ("192.168.50.101", False)):
            app = self.app()
            app._uninstall()
            preview = {"host": host, "token": "opaque", "game": app._packages["pkg:0"]}
            with patch("labguard.remote_gui.messagebox.askyesno", return_value=answer):
                app._run.call_args.args[1](preview)
            self.assertEqual(app._run.call_count, 1)
            app.session.uninstall.assert_not_called()
        app = self.app()
        app._uninstall()
        with patch("labguard.remote_gui.messagebox.askyesno") as confirm:
            app._run.call_args.args[1](None)
        confirm.assert_not_called()

    def test_connection_passes_numeric_port_and_rejects_invalid_port(self):
        for port, valid in (("5986", True), ("22", True), ("0", False), ("oops", False)):
            app = self.app()
            app._generation = 0
            app.protocol_var = Mock(get=Mock(return_value="Windows · WinRM HTTPS"))
            app.port_var = Mock(get=Mock(return_value=port))
            for name in ("user_var", "password_var", "ca_var", "key_var", "known_hosts_var"):
                setattr(app, name, Mock(get=Mock(return_value="")))
            app.session_factory = Mock(return_value=Mock())
            app._connect()
            if valid:
                app._run.call_args.args[0]()
                self.assertIs(type(app.session_factory.call_args.kwargs["port"]), int)
                self.assertEqual(app.session_factory.call_args.kwargs["port"], int(port))
            else:
                app._run.assert_not_called()

    def test_old_inventory_disables_mutations(self):
        app = self.app()
        app._last_snapshot = monotonic() - 61
        self.assertFalse(app._fresh())
        app._uninstall()
        self.assertFalse(app._send_warning("games"))
        app._run.assert_not_called()

    def test_warning_rate_limit_and_no_automatic_removal(self):
        app = self.app()
        self.assertTrue(app._send_warning("games", automatic=True))
        app._run.call_args.args[0]()
        app.session.notify.assert_called_once_with(kind="games")
        self.assertFalse(app._send_warning("games", automatic=True))
        self.assertEqual(app._run.call_count, 1)
        app.session.uninstall.assert_not_called()
        app.session.preview_uninstall.assert_not_called()

    def test_dns_signals_match_target_and_domain_boundary(self):
        target = "192.168.50.101"
        rules = [{"domain": "games.example", "category": "Jogos"},
                 {"domain": "adult.example", "category": "Adultos"}]
        events = [{"time": "now", "client_ip": target, "domain": "www.games.example"},
                  {"time": "now", "client_ip": "192.168.50.102", "domain": "adult.example"},
                  {"time": "now", "client_ip": target, "domain": "notadult.example"}]
        self.assertEqual(warning_categories(events, rules, target), {"games"})
        self.assertEqual(warning_categories([], rules, target, [{"game": "Minecraft", "is_launcher": True}]), set())
        self.assertEqual(warning_categories([], rules, target, [{"game": "Minecraft", "is_launcher": False}]), {"games"})

    def test_simultaneous_game_and_adult_signals_survive_serial_worker(self):
        app = self.app()
        app.events_callback = Mock(return_value=[
            {"time": "now", "client_ip": app.target_ip, "domain": "games.example"},
            {"time": "now", "client_ip": app.target_ip, "domain": "adult.example"}])
        app.domains_callback = Mock(return_value=[
            {"domain": "games.example", "category": "Jogos"},
            {"domain": "adult.example", "category": "Adultos"}])
        app._send_warning = Mock(return_value=True)
        app._monitor_signals()
        self.assertEqual(app._pending_warnings, {"adult"})
        app._monitor_signals()
        self.assertEqual(app._pending_warnings, set())
        self.assertEqual([call.args[0] for call in app._send_warning.call_args_list], ["games", "adult"])
        app.session.uninstall.assert_not_called()
        app.session.preview_uninstall.assert_not_called()

    def test_inactivity_expires_session(self):
        app = self.app()
        app._last_activity = monotonic() - 601
        app._disconnect = Mock()
        app._controls = Mock()
        app.after = Mock()
        app._check_idle()
        app._disconnect.assert_called_once_with(expired=True)


if __name__ == "__main__":
    unittest.main()
