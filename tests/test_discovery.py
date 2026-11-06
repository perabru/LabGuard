import copy
import json
import subprocess
import unittest
from unittest.mock import patch

from labguard.discovery import LocalObservationTransport, WINDOWS_SCRIPT, discover_local_network
from labguard.transport import OutputLimitExceeded, TransportError


ADDRESSES = [{"ifindex": 3, "ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.15.10", "prefixlen": 24}]},
             {"ifindex": 1, "ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]}]
ROUTES = [{"dst": "default", "gateway": "192.168.15.1", "dev": "eth0", "metric": 100}]
NEIGHBORS = [{"dst": "192.168.15.1", "lladdr": "02:10:20:30:40:01", "dev": "eth0", "state": ["REACHABLE"]},
             {"dst": "192.168.15.20", "lladdr": "02:10:20:30:40:02", "dev": "eth0", "state": ["STALE"]}]


def completed(value):
    return subprocess.CompletedProcess([], 0, json.dumps(value), "")


class DiscoveryTests(unittest.TestCase):
    def linux(self, addresses=None, routes=None, neighbors=None):
        runner = patch("labguard.discovery.run_bounded", side_effect=[completed(ADDRESSES if addresses is None else addresses),
                       completed(ROUTES if routes is None else routes), completed(NEIGHBORS if neighbors is None else neighbors)])
        with patch("labguard.discovery.platform.system", return_value="Linux"), \
             patch("labguard.discovery.shutil.which", return_value="/usr/sbin/ip"), \
             patch("labguard.discovery._resolv_dns", return_value=["127.0.0.53", "1.1.1.1"]), runner as call:
            result = discover_local_network()
        return result, call

    def test_linux_reads_only_local_fixed_tables_and_real_gateway(self):
        result, runner = self.linux()
        self.assertEqual(result["gateway"], "192.168.15.1")
        self.assertEqual(result["interfaces"], [{"name": "eth0", "ipv4": "192.168.15.10", "prefixlen": 24}])
        self.assertEqual(result["source"], "local")
        self.assertEqual(len(result["neighbors"]), 2)
        self.assertEqual([call.args[0] for call in runner.call_args_list], [
            ["/usr/sbin/ip", "-j", "-4", "address", "show", "up"],
            ["/usr/sbin/ip", "-j", "-4", "route", "show", "default"],
            ["/usr/sbin/ip", "-j", "-4", "neigh", "show"]])
        for call in runner.call_args_list:
            self.assertEqual(call.kwargs["timeout"], 8)
            self.assertLessEqual(call.kwargs["max_output_bytes"], 512 * 1024)
        self.assertIn("STALE", " ".join(result["warnings"]))

    def test_public_other_subnet_bad_mac_broadcast_and_wrong_adapter_are_excluded(self):
        extra = [dict(NEIGHBORS[1], dst=ip) for ip in ("8.8.8.8", "192.168.16.3", "192.168.15.0", "192.168.15.255", "127.0.0.1", "169.254.0.8", "0.0.0.2")]
        extra += [dict(NEIGHBORS[1], lladdr=mac) for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "bad")]
        extra += [dict(NEIGHBORS[1], dev="other"), dict(NEIGHBORS[1], state=["FAILED"])]
        result, _ = self.linux(neighbors=NEIGHBORS + extra)
        self.assertEqual([r["ip"] for r in result["neighbors"]], ["192.168.15.1", "192.168.15.20"])

    def test_gateway_uses_valid_route_metric_and_reports_multiple_routes(self):
        routes = ROUTES + [dict(ROUTES[0], gateway="192.168.15.2", metric=20),
                           dict(ROUTES[0], gateway="8.8.8.8", metric=0)]
        result, _ = self.linux(routes=routes)
        self.assertEqual(result["gateway"], "192.168.15.2")
        self.assertIn("mais de uma rota", " ".join(result["warnings"]))

    def test_windows_normalizes_json_without_claiming_brand_or_neighbor_names(self):
        raw = {"interfaces": [{"name": "Ethernet", "ipv4": "192.168.15.10", "prefixlen": 24, "ifindex": 12}],
               "routes": [{"gateway": "192.168.15.1", "metric": 25, "ifindex": 12}],
               "neighbors": [{"ip": "192.168.15.22", "mac": "02-AA-BB-CC-DD-EE", "state": "Reachable", "ifindex": 12},
                             {"ip": "192.168.15.23", "mac": "02-AA-BB-CC-DD-EF", "state": "Reachable", "ifindex": 99}],
               "dns": ["192.168.15.1", "2001:4860:4860::8888", "bad", "192.168.15.1"], "partial": True}
        with patch("labguard.discovery.platform.system", return_value="Windows"), \
             patch("labguard.discovery.shutil.which", return_value="powershell.exe"), \
             patch("labguard.discovery.run_bounded", return_value=completed(raw)) as runner:
            result = discover_local_network()
        self.assertEqual(result["gateway"], "192.168.15.1")
        self.assertEqual(result["neighbors"], [{"ip": "192.168.15.22", "mac": "02:aa:bb:cc:dd:ee", "state": "Reachable"}])
        self.assertEqual(result["dns"], ["192.168.15.1", "2001:4860:4860::8888"])
        self.assertIn("indisponível", " ".join(result["warnings"]))
        args = runner.call_args.args[0]
        self.assertEqual(args[-2:], ["-Command", WINDOWS_SCRIPT])
        self.assertIn("Get-NetIPConfiguration", args[-1])
        self.assertIn("Get-NetNeighbor", args[-1])
        self.assertNotIn("Set-Net", args[-1])
        self.assertNotIn("Test-Connection", args[-1])

    def test_missing_os_tools_and_unsupported_platform_return_partial_diagnosis(self):
        for system in ("Windows", "Linux", "Other"):
            with self.subTest(system=system), patch("labguard.discovery.platform.system", return_value=system), \
                 patch("labguard.discovery.shutil.which", return_value=None), \
                 patch("labguard.discovery._resolv_dns", return_value=[]), \
                 patch("labguard.discovery.run_bounded") as runner:
                result = discover_local_network()
                self.assertEqual(result["gateway"], "")
                self.assertEqual(result["neighbors"], [])
                self.assertTrue(result["warnings"])
                runner.assert_not_called()

    def test_command_timeout_bad_json_and_output_limit_do_not_break_readonly_mode(self):
        for failure in (subprocess.TimeoutExpired("ip", 8), OutputLimitExceeded("limit"), OSError("missing")):
            with self.subTest(failure=type(failure).__name__), patch("labguard.discovery.platform.system", return_value="Windows"), \
                 patch("labguard.discovery.shutil.which", return_value="powershell.exe"), \
                 patch("labguard.discovery.run_bounded", side_effect=failure):
                self.assertEqual(discover_local_network()["neighbors"], [])
        with patch("labguard.discovery.platform.system", return_value="Windows"), \
             patch("labguard.discovery.shutil.which", return_value="powershell.exe"), \
             patch("labguard.discovery.run_bounded", return_value=subprocess.CompletedProcess([], 0, "not JSON", "")):
            self.assertEqual(discover_local_network()["interfaces"], [])

    def test_malformed_prefix_and_public_adapter_cannot_expand_neighbor_scope(self):
        malformed = ADDRESSES + [{"ifname": "fake", "addr_info": [{"family": "inet", "local": "8.8.8.8", "prefixlen": 0},
                                                                   {"family": "inet", "local": "10.0.0.1", "prefixlen": True}]}]
        result, _ = self.linux(addresses=malformed, neighbors=NEIGHBORS + [dict(NEIGHBORS[1], dst="10.20.30.1", dev="fake")])
        self.assertEqual(len(result["interfaces"]), 1)
        self.assertEqual(len(result["neighbors"]), 2)

    def test_snapshot_is_readonly_and_self_and_gateway_are_protected(self):
        local, _ = self.linux()
        transport = LocalObservationTransport()
        with patch("labguard.discovery.discover_local_network", return_value=local):
            snapshot = transport.request("snapshot")
        self.assertEqual(snapshot["mode"], "observation")
        self.assertEqual(snapshot["gateway"]["model"], "Desconhecido")
        self.assertEqual(snapshot["gateway"]["lab_cidr"], "192.168.15.0/24")
        self.assertTrue(snapshot["capabilities"].pop("inventory"))
        self.assertFalse(any(snapshot["capabilities"].values()))
        self.assertEqual({r["ip"] for r in snapshot["devices"] if r["protected"]}, {"192.168.15.1", "192.168.15.10"})
        self.assertEqual(snapshot["events"], [])
        self.assertEqual(snapshot["connections"], [])
        cached = next(row for row in snapshot["devices"] if row["ip"] == "192.168.15.20")
        self.assertEqual(cached["last_seen"], "")
        self.assertEqual(cached["sampled_at"], local["timestamp"])
        for action in ("add_domain", "remove_domain", "set_ai_block", "set_device_block", "set_address_block", "reboot"):
            with self.subTest(action=action), self.assertRaises(TransportError):
                transport.request(action)
        with self.assertRaises(TransportError):
            transport.request("snapshot", command="ip")
        transport.close()
        with self.assertRaises(TransportError):
            transport.request("snapshot")


if __name__ == "__main__":
    unittest.main()
