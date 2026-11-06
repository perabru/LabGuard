import unittest
from threading import Event
from unittest.mock import Mock, patch

from labguard.banlist import BanlistError
from labguard.banlist_gui import BanlistWindow


class BanlistUiSafetyTests(unittest.TestCase):
    def window(self):
        window = BanlistWindow.__new__(BanlistWindow)
        window._closed = window._syncing = False
        window._cancel_sync = Event()
        window.can_sync_callback = Mock(return_value=True)
        window.buttons = [Mock(), Mock()]
        window.status = Mock()
        window.db, window.transport, window.owner = Mock(), Mock(), Mock()
        window.owner.snapshot = {"mode": "gateway"}
        window.refresh = Mock()
        return window

    def test_gateway_is_rechecked_after_confirmation(self):
        window = self.window()
        window.can_sync_callback.side_effect = [True, False]
        with patch("labguard.banlist_gui.messagebox.askyesno", return_value=True) as confirm:
            window._sync()
        self.assertEqual(confirm.call_args.kwargs["default"], "no")
        self.assertFalse(window._syncing)
        window.owner._run_job.assert_not_called()
        window.db.sync.assert_not_called()

    def test_failed_database_and_failed_summary_do_not_leave_controls_locked(self):
        window = self.window()
        window.db.sync.side_effect = BanlistError("Falha no banco")
        window.db.summary.side_effect = BanlistError("Resumo indisponível")
        def run(function, **kwargs):
            kwargs["on_success"](function())
            return True
        window.owner._run_job.side_effect = run
        with patch("labguard.banlist_gui.messagebox.askyesno", return_value=True):
            window._sync()
        self.assertFalse(window._syncing)
        self.assertTrue(window.owner._snapshot_stale)
        for button in window.buttons:
            self.assertEqual(button.configure.call_args.kwargs["state"], "normal")
        window.db.sync.assert_called_once_with(window.transport, limit=20, cancel_event=window._cancel_sync)

    def test_closing_cancels_remaining_batch_operations(self):
        window = self.window()
        window.destroy = Mock()
        window.close()
        self.assertTrue(window._closed)
        self.assertTrue(window._cancel_sync.is_set())
        window.db.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
