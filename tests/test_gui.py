"""Testes sem servidor gráfico das fronteiras de exportação e falha assíncrona."""
import queue
import unittest
from unittest.mock import Mock, patch

from labguard.gui import App, csv_safe
from labguard.transport import TransportError


class ImmediateExecutor:
    def submit(self, function):
        function()


class GuiBoundaryTests(unittest.TestCase):
    @staticmethod
    def ai_app(enabled=False):
        app = App.__new__(App)
        app._busy = False
        app.snapshot = {"mode": "gateway", "domains": [], "policies": {"ai_block": {
            "enabled": enabled, "domains": ["chatgpt.com", "claude.ai"],
            "services": [{"name": "ChatGPT", "domains": ["chatgpt.com"]}]}}}
        app.transport = Mock()
        app.status = Mock()
        app._live_confirmation = Mock(return_value=True)
        app._run_job = Mock(return_value=True)
        return app

    def test_csv_network_values_cannot_become_formulas(self):
        for value in ("=1+1", "+SUM(A1)", "-1+2", "@SUM(A1)", "\t =cmd", "\n=cmd"):
            with self.subTest(value=value):
                self.assertTrue(csv_safe(value).startswith("'"))
        self.assertEqual(csv_safe("LAB-01"), "LAB-01")
        self.assertEqual(csv_safe("jogos.exemplo.com"), "jogos.exemplo.com")
        self.assertEqual(csv_safe(None), "")

    def test_failed_live_request_keeps_gateway_and_marks_snapshot_stale(self):
        # No Tk widgets are created: exercise the actual queue completion path.
        app = App.__new__(App)
        app._closed = False
        app._busy = False
        app._generation = 5
        app._results = queue.Queue()
        app._executor = ImmediateExecutor()
        app.after = Mock()
        app.status = Mock()
        app.refresh_button = Mock()
        app.mode_banner = Mock()
        app._apply_snapshot = Mock()
        transport = Mock()
        transport.request.side_effect = TransportError("SSH indisponível")
        app.transport = transport
        snapshot = {"mode": "gateway", "timestamp": "2026-11-06T10:00:00Z"}
        app.snapshot = snapshot
        self.assertTrue(app._run_job(lambda: transport.request("snapshot"), label="Atualizando"))
        app._drain()
        self.assertIs(app.transport, transport)
        self.assertIs(app.snapshot, snapshot)
        self.assertFalse(app._busy)
        app._apply_snapshot.assert_not_called()
        self.assertIn("SEM ATUALIZAÇÃO", app.mode_banner.configure.call_args.kwargs["text"])
        self.assertIn("SSH indisponível", app.status.set.call_args.args[0])

    def test_stale_generation_response_is_ignored(self):
        app = App.__new__(App)
        app._closed = False
        app._busy = True
        app._generation = 7
        app._results = queue.Queue()
        app.after = Mock()
        app._apply_snapshot = Mock()
        app._results.put((6, True, {"mode": "demo"}, None, False, "Atualizando"))
        app._drain()
        app._apply_snapshot.assert_not_called()
        self.assertTrue(app._busy)

    def test_ai_toggle_sends_bool_and_requests_global_confirmation(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                app = self.ai_app(enabled)
                app._toggle_ai_block()
                app._live_confirmation.assert_called_once()
                self.assertIn("todo o laboratório", app._live_confirmation.call_args.args[1])
                self.assertIn("Regras manuais permanecem", app._live_confirmation.call_args.args[1])
                app._run_job.call_args.args[0]()
                app.transport.request.assert_called_once_with("set_ai_block", enabled=not enabled)

    def test_ai_confirmation_decline_and_busy_do_not_submit(self):
        app = self.ai_app()
        app._live_confirmation.return_value = False
        app._toggle_ai_block()
        app._run_job.assert_not_called()
        app._live_confirmation.reset_mock()
        app._busy = True
        app._toggle_ai_block()
        app._live_confirmation.assert_not_called()
        app._run_job.assert_not_called()

    def test_older_gateway_disables_ai_controls(self):
        app = self.ai_app()
        app.snapshot.pop("policies")
        app.ai_state_text = Mock()
        app.ai_state_label = Mock()
        app.ai_toggle_button = Mock()
        app.ai_catalog_button = Mock()
        app._render_ai_policy()
        self.assertIn("Atualize", app.ai_state_text.set.call_args.args[0])
        self.assertEqual(app.ai_toggle_button.configure.call_args.kwargs["state"], "disabled")
        app._toggle_ai_block()
        app._run_job.assert_not_called()

    def test_profile_domain_is_not_removed_as_manual_rule(self):
        app = self.ai_app(True)
        app.snapshot["domains"] = [{"domain": "chatgpt.com", "source": "ai_profile"}]
        app.domains_table = Mock()
        app.domains_table.selection.return_value = ("chatgpt.com",)
        with patch("labguard.gui.messagebox.showinfo") as info:
            app._remove_domain()
        info.assert_called_once()
        app._live_confirmation.assert_not_called()
        app._run_job.assert_not_called()

    def test_removing_manual_overlap_explains_profile_stays_active(self):
        app = self.ai_app(True)
        app.snapshot["domains"] = [{"domain": "chatgpt.com", "source": "manual"}]
        app.domains_table = Mock()
        app.domains_table.selection.return_value = ("chatgpt.com",)
        app._remove_domain()
        self.assertIn("continuará bloqueado pelo perfil", app._live_confirmation.call_args.args[1])
        app._run_job.call_args.args[0]()
        app.transport.request.assert_called_once_with("remove_domain", domain="chatgpt.com")


if __name__ == "__main__":
    unittest.main()
