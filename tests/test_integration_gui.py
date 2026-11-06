import unittest
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


if __name__ == "__main__":
    unittest.main()
