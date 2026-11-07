"""Fronteiras do mapa: evidências, regras independentes e controles protegidos."""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from labguard.network_map_gui import (NetworkMapWindow, address_is_blocked,
                                     block_description, observed_devices, valid_address)


class MapDataTests(unittest.TestCase):
    def test_search_matches_name_ip_mac_and_preserves_expired_evidence(self):
        snapshot = {"devices": [{"name": "LAB-01", "ip": "192.168.50.1", "mac": "02:00:00:00:00:01", "state": "Concessão expirada"},
                                {"name": "Professor", "ip": "192.168.50.2"}]}
        for query in ("lab-01", "192.168.50.1", "00:00:01", "EXPIRADA"):
            self.assertEqual(len(observed_devices(snapshot, query)), 1)
        self.assertEqual(observed_devices(snapshot)[0]["state"], "Concessão expirada")

    def test_saved_unobserved_rules_remain_visible_without_inventing_ip_or_mac(self):
        snapshot = {"devices": [], "address_blocks": [{"kind": "mac", "address": "02:11:22:33:44:55"}]}
        record, = observed_devices(snapshot)
        self.assertFalse(record["observed"])
        self.assertNotIn("ip", record)
        self.assertEqual(record["state"], "Sem observação recente")
        self.assertTrue(address_is_blocked(snapshot, record, "mac"))

    def test_saved_rules_do_not_duplicate_existing_matching_machine(self):
        snapshot = {"devices": [{"ip": "192.168.50.1", "mac": "02:AA:BB:CC:DD:EE"}],
                    "address_blocks": [{"kind": "mac", "address": "02:aa:bb:cc:dd:ee"},
                                       {"kind": "ip", "address": "192.168.50.1"}]}
        self.assertEqual(len(observed_devices(snapshot)), 1)

    def test_ip_and_mac_blocks_are_independent_and_canonical(self):
        d = {"ip": "192.168.50.1", "mac": "02:00:00:00:00:01", "blocked": True, "blocked_by": ["ip"]}
        snapshot = {"address_blocks": [{"kind": "mac", "address": d["mac"]}]}
        self.assertFalse(address_is_blocked(snapshot, d, "ip"))
        self.assertTrue(address_is_blocked(snapshot, d, "mac"))
        self.assertEqual(block_description(snapshot, d), "Bloqueio: MAC")
        self.assertFalse(address_is_blocked({"address_blocks": []}, d, "mac"))

    def test_legacy_boolean_does_not_invent_an_ip_scope(self):
        d = {"blocked": True, "ip": "192.168.50.1"}
        self.assertFalse(address_is_blocked({}, d, "ip"))
        self.assertIn("origem não informada", block_description({}, d))

    def test_addresses_must_be_complete_and_protocol_appropriate(self):
        self.assertTrue(valid_address("ip", "192.168.50.10"))
        self.assertTrue(valid_address("mac", "02:aa:bb:cc:dd:ee"))
        for kind, value in (("ip", "::1"), ("ip", "999.1.2.3"), ("mac", "aa:bb"), ("dns", "example.com")):
            self.assertFalse(valid_address(kind, value))

    def test_wireless_fields_only_describe_source_evidence(self):
        self.assertIn("não informados", NetworkMapWindow._wireless_details({"mac": "02:00:00:00:00:01"}))
        detail = NetworkMapWindow._wireless_details({"connection_type": "wifi", "ssid": "LAB", "ap": "AP-01"})
        self.assertIn("Wi-Fi", detail)
        self.assertIn("SSID: LAB", detail)
        self.assertIn("AP: AP-01", detail)


class MapActionTests(unittest.TestCase):
    def window(self, device, *, stale=False, demo=False):
        win = NetworkMapWindow.__new__(NetworkMapWindow)
        win.parent = Mock(_busy=False, _session_locked=False, _snapshot_stale=stale)
        win.snapshot = {"mode": "demo" if demo else "gateway", "address_blocks": [],
                        "devices": [device], "timestamp": datetime.now(timezone.utc).isoformat()}
        win.action_callback = Mock()
        win._source_error = False
        win._selected_key = "selected"
        win._devices_by_key = {"selected": device}
        win.refresh = Mock()
        win.status = Mock()
        return win

    def test_protected_machine_cannot_be_blocked_or_unblocked(self):
        win = self.window({"ip": "192.168.50.1", "protected": True})
        win._act("ip", True)
        win._act("ip", False)
        win.action_callback.assert_not_called()

    def test_conflicting_identity_disables_map_actions_before_dispatch(self):
        device = {"ip": "192.168.50.1", "mac": "02:00:00:00:00:01"}
        win = self.window(device)
        win.snapshot["devices"].append(dict(device, mac="02:00:00:00:00:02"))
        self.assertFalse(win._allowed(device))
        win._act("ip", True)
        win.action_callback.assert_not_called()
        win.snapshot["devices"] = [dict(device, identity_conflict=True)]
        self.assertFalse(win._allowed(device))
        offline = self.window({"mac": "02:00:00:00:00:01", "observed": False})
        offline.snapshot["devices"].append({"mac": "02:00:00:00:00:02", "observed": False})
        self.assertTrue(offline._allowed(offline._selected()))

    def test_old_missing_or_future_source_time_disables_map_without_parent_error(self):
        for stamp in (None, (datetime.now(timezone.utc)-timedelta(seconds=30)).isoformat(),
                      (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()):
            with self.subTest(stamp=stamp):
                win = self.window({"ip": "192.168.50.1"})
                win.snapshot["timestamp"] = stamp
                self.assertTrue(win._stale())
                win._act("ip", True)
                win.action_callback.assert_not_called()

    def test_stale_live_snapshot_cannot_dispatch_actions(self):
        win = self.window({"ip": "192.168.50.1"}, stale=True)
        win._act("ip", True)
        win.action_callback.assert_not_called()

    def test_ip_action_dispatches_only_selected_ip_and_boolean(self):
        win = self.window({"ip": "192.168.50.1", "mac": "02:00:00:00:00:01"})
        win._act("ip", True)
        win.action_callback.assert_called_once_with("ip", "192.168.50.1", True)

    def test_saved_offline_rule_can_be_removed_but_not_newly_blocked(self):
        d = {"mac": "02:00:00:00:00:01", "observed": False}
        win = self.window(d)
        win.snapshot["address_blocks"] = [{"kind": "mac", "address": d["mac"]}]
        win._act("mac", False)
        win.action_callback.assert_called_once_with("mac", d["mac"], False)
        win.snapshot["address_blocks"] = []
        win._act("mac", True)
        self.assertEqual(win.action_callback.call_count, 1)

    def test_locked_demo_session_also_refuses_action(self):
        win = self.window({"ip": "192.168.50.1"}, demo=True)
        win.parent._session_locked = True
        win._act("ip", True)
        win.action_callback.assert_not_called()

    def test_local_observation_refuses_actions_even_with_injected_capability(self):
        win = self.window({"ip": "192.168.50.1"})
        win.snapshot.update(mode="observation", capabilities={"address_blocking": True})
        win._act("ip", True)
        win.action_callback.assert_not_called()
        self.assertEqual(block_description(win.snapshot, {"blocked": False}), "Bloqueio não verificado")

    def test_equipment_requires_confirmed_address_blocking_capability(self):
        win = self.window({"ip": "192.168.50.1"})
        win.snapshot.update(mode="equipment", capabilities={"address_blocking": False})
        win._act("ip", True)
        win.action_callback.assert_not_called()
        win.snapshot["capabilities"]["address_blocking"] = True
        win._act("ip", True)
        win.action_callback.assert_called_once_with("ip", "192.168.50.1", True)

    def test_dual_scope_unblock_does_not_remove_other_scope(self):
        d = {"ip": "192.168.50.1", "mac": "02:00:00:00:00:01"}
        win = self.window(d)
        win.snapshot["address_blocks"] = [{"kind": kind, "address": d[kind]} for kind in ("ip", "mac")]
        win._act("ip", False)
        win.action_callback.assert_called_once_with("ip", d["ip"], False)
        self.assertTrue(address_is_blocked(win.snapshot, d, "mac"))


if __name__ == "__main__":
    unittest.main()
