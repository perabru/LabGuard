from concurrent.futures import Future
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from labguard.remote import RemoteError
from labguard.station_dns_gui import StationDNSWindow, station_target
from labguard.station_policy import StationScope, station_target_from_snapshot


def snapshot():
    return {
        "mode": "equipment", "source_type": "local_dns",
        "dns_service": {"listen": "192.168.10.5", "network": "192.168.10.0/24",
                        "service_running": True, "port": 53, "check_token": "LabGuard-0000000000000001"},
        "local": {"interface_ips": ["192.168.10.5", "192.168.10.7"],
                  "default_gateway": "192.168.10.1", "interfaces_read": True, "routes_read": True},
        "gateway": {"management_host": "192.168.10.5"}, "interfaces": [],
        "devices": [
            {"ip": "192.168.10.8", "protected": True},
            {"ip": "192.168.10.21", "mac": "02:00:00:00:00:21"},
            {"ip": "192.168.10.19", "mac": "02:00:00:00:00:19"},
            {"ip": "192.168.10.19", "mac": "02:00:00:00:00:20"},
            {"ip": "192.168.10.20", "identity_conflict": True},
        ],
    }


class StationPolicyTests(unittest.TestCase):
    def test_inventory_and_manual_targets_exclude_protected_and_conflicting_addresses(self):
        scope = StationScope(snapshot())
        self.assertEqual(scope.inventory(), ["192.168.10.21"])
        self.assertEqual(scope.target("192.168.10.30").address, "192.168.10.30")
        for ip in ("192.168.10.0", "192.168.10.255", "192.168.12.8", "localhost", "192.168.10.1",
                   "192.168.10.5", "192.168.10.7", "192.168.10.8", "192.168.10.19", "192.168.10.20"):
            with self.subTest(ip=ip), self.assertRaises(RemoteError):
                scope.target(ip)

    def test_incomplete_route_read_only_allows_testing(self):
        source = snapshot()
        source["local"]["routes_read"] = False
        self.assertEqual(station_target_from_snapshot(source, "192.168.10.40").address, "192.168.10.40")
        with self.assertRaises(RemoteError):
            station_target_from_snapshot(source, "192.168.10.40", for_change=True)

    def test_active_listener_and_standard_port_are_required(self):
        for field, value in (("port", 5353), ("service_running", False), ("check_token", "")):
            source = snapshot()
            source["dns_service"][field] = value
            with self.subTest(field=field), self.assertRaises(RemoteError):
                station_target_from_snapshot(source, "192.168.10.40")

    def test_replaced_source_or_stale_snapshot_prevent_dispatch(self):
        transport = SimpleNamespace(kind="local_dns")
        owner = SimpleNamespace(_closed=False, transport=transport, snapshot=snapshot(),
                                _management_authorized=True, _snapshot_stale=False,
                                _last_snapshot_monotonic=monotonic())
        self.assertEqual(station_target(owner, transport, "192.168.10.21").macs, ("02:00:00:00:00:21",))
        owner.transport = SimpleNamespace(kind="local_dns")
        with self.assertRaises(RemoteError):
            station_target(owner, transport, "192.168.10.21")
        owner.transport = transport
        owner._snapshot_stale = True
        with self.assertRaises(RemoteError):
            station_target(owner, transport, "192.168.10.21")

    def test_delayed_remote_result_cannot_attach_to_changed_filter_session(self):
        window = StationDNSWindow.__new__(StationDNSWindow)
        window._session = None
        window._pending_target = station_target_from_snapshot(snapshot(), "192.168.10.21")
        changed = snapshot()
        changed["dns_service"]["check_token"] = "LabGuard-0000000000000002"
        window._target = Mock(return_value=station_target_from_snapshot(changed, "192.168.10.21"))
        window._future = Future()
        session = Mock()
        window._future.set_result((session, Mock(), {"ok": True}))
        window._callback = Mock()
        window._buttons = Mock()
        window.direct = Mock()
        window.default = Mock()
        window.blocked = Mock()
        window.detail = Mock()
        window.status = Mock()
        window._finish()
        session.close.assert_called_once()
        window._callback.assert_not_called()
        self.assertIsNone(window._session)

    def test_declining_preview_confirmation_does_not_write(self):
        window = StationDNSWindow.__new__(StationDNSWindow)
        window._preview = {"id": "preview-1", "message": "Adaptador 4"}
        window._start = Mock()
        with patch("labguard.station_dns_gui.messagebox.askyesno", return_value=False):
            window.apply()
        window._start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
