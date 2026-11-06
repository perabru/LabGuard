import unittest
import queue
from types import SimpleNamespace
from unittest.mock import Mock, patch

from labguard.integration_gui import IntegrationWindow, capability_text, inventory_rows


class IntegrationUiTests(unittest.TestCase):
    def test_inventory_keeps_ports_distinct_from_machines(self):
        rows = inventory_rows({"ports": [{"name": "GigabitEthernet1/0/2", "status": "connected", "macs": ["00:11:22:33:44:55"]}],
                               "devices": [{"name": "LAB-01", "ip": "192.168.50.101", "mac": "00:aa:bb:cc:dd:ee"}]})
        self.assertEqual([row[1] for row in rows], ["port", "device"])
        self.assertNotEqual(rows[0][0], rows[1][0])
        self.assertEqual(rows[1][3][2], "192.168.50.101")

    def test_readonly_capabilities_do_not_claim_domain_filtering(self):
        self.assertEqual(capability_text({"inventory": True, "domain_filtering": False}), "inventário")

    def test_machine_row_never_triggers_port_control(self):
        fake = Mock()
        fake._busy = False
        fake.session = Mock()
        fake.table.selection.return_value = ["device:0"]
        fake._row_data = {"device:0": ("device", {"name": "LAB-01"})}
        fake.snapshot = {"capabilities": {"port_control": True}}
        with patch("labguard.integration_gui.messagebox.askyesno") as confirm:
            IntegrationWindow._set_port(fake, False)
        confirm.assert_not_called()
        fake._run.assert_not_called()

    def test_protected_port_never_triggers_dialog_or_request(self):
        fake = Mock()
        fake._busy = False
        fake.session = Mock()
        fake.table.selection.return_value = ["port:0"]
        fake._row_data = {"port:0": ("port", {"name": "GigabitEthernet1/0/1", "controllable": False})}
        fake.snapshot = {"capabilities": {"port_control": True}}
        with patch("labguard.integration_gui.messagebox.askyesno") as confirm:
            IntegrationWindow._set_port(fake, False)
        confirm.assert_not_called()
        fake._run.assert_not_called()


    def test_stale_inventory_never_confirms_port_mutation(self):
        fake = SimpleNamespace(_busy=False, session=Mock(), table=Mock(),
            _row_data={"port:0": ("port", {"name": "Gi1/0/1", "controllable": True})},
            snapshot={"capabilities": {"port_control": True}},
            _inventory_fresh=lambda: False, status=Mock(), _run=Mock())
        fake.table.selection.return_value = ["port:0"]
        with patch("labguard.integration_gui.messagebox.askyesno") as confirm:
            IntegrationWindow._set_port(fake, False)
        confirm.assert_not_called()
        fake._run.assert_not_called()
        self.assertIn("Atualize", fake.status.set.call_args.args[0])

    def test_fresh_inventory_expires_after_sixty_seconds(self):
        fake = SimpleNamespace(session=object(), _stale=False, _last_snapshot=950)
        with patch("labguard.integration_gui.monotonic", return_value=1000):
            self.assertTrue(IntegrationWindow._inventory_fresh(fake))
            fake._last_snapshot = 939
            self.assertFalse(IntegrationWindow._inventory_fresh(fake))
            fake._last_snapshot, fake._stale = 999, True
            self.assertFalse(IntegrationWindow._inventory_fresh(fake))

    def test_idle_session_expires_without_starting_a_new_connection(self):
        fake = SimpleNamespace(_closed=False, session=object(), _last_activity=0, _busy=False,
                               _disconnect=Mock(), after=Mock(), _check_idle=Mock())
        with patch("labguard.integration_gui.monotonic", return_value=601):
            IntegrationWindow._check_idle(fake)
        fake._disconnect.assert_called_once()
        self.assertIn("inatividade", fake._disconnect.call_args.args[0])

    def test_disconnect_clears_credentials_data_and_calls_session_close(self):
        session = Mock()
        fake = SimpleNamespace(_generation=1, session=session, password_var=Mock(), snapshot={"ports": [1]},
            _row_data={"port:0": object()}, table=Mock(), raw_button=Mock(), refresh_button=Mock(),
            off_button=Mock(), on_button=Mock(), disconnect_button=Mock(), active_summary=Mock(),
            session_notice=Mock(), status=Mock(), _detail_windows=[])
        fake.table.get_children.return_value = ["port:0"]
        IntegrationWindow._disconnect(fake)
        session.close.assert_called_once()
        self.assertIsNone(fake.session)
        self.assertEqual(fake.snapshot, {})
        self.assertTrue(fake._stale)
        self.assertEqual(fake._generation, 2)
        fake.password_var.set.assert_called_once_with("")

    def test_late_connection_result_is_closed_after_window_close(self):
        session = Mock()
        fake = SimpleNamespace(_busy=False, _closed=False, _generation=1, status=Mock(),
            connect_button=Mock(), refresh_button=Mock(), off_button=Mock(), on_button=Mock(),
            disconnect_button=Mock(), profile_combo=Mock(), _results=queue.Queue(), _executor=Mock())
        def completed_after_close():
            fake._closed = True
            return session, {}
        fake._executor.submit.side_effect = lambda work: work()
        self.assertTrue(IntegrationWindow._run(fake, completed_after_close, Mock(), "Conectando"))
        session.close.assert_called_once()
        self.assertTrue(fake._results.empty())


if __name__ == "__main__":
    unittest.main()
