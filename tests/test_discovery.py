import copy
import errno
from io import StringIO
import json
import socket
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from labguard.discovery import (LocalObservationTransport, WINDOWS_SCRIPT, CIM_SCRIPT, discover_local_network,
    _linux_interfaces_ioctl, _linux_proc_routes, _linux_proc_neighbors, _read_local_text, _sys_interface_mac)
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
                 patch("labguard.discovery._linux_interfaces_ioctl", return_value=None), \
                 patch("labguard.discovery._linux_proc_routes", return_value=None), \
                 patch("labguard.discovery._linux_proc_neighbors", return_value=None), \
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

    def test_linux_fallback_joins_only_valid_private_interfaces_routes_and_cache(self):
        interfaces = [{"name": "eth0", "ipv4": "192.168.15.10", "prefixlen": 24, "mac": "02:00:00:00:00:10"}]
        routes = [{"name": "eth0", "gateway": "192.168.15.1", "metric": 12}]
        neighbors = [{"name": "eth0", "ip": "192.168.15.21", "mac": "02:00:00:00:00:21", "state": "Cache ARP (presença não verificada)"},
                     {"name": "other", "ip": "192.168.15.22", "mac": "02:00:00:00:00:22"},
                     {"name": "eth0", "ip": "192.168.16.23", "mac": "02:00:00:00:00:23"}]
        with patch("labguard.discovery.platform.system", return_value="Linux"), \
             patch("labguard.discovery.shutil.which", return_value=None), \
             patch("labguard.discovery._linux_interfaces_ioctl", return_value=interfaces), \
             patch("labguard.discovery._linux_proc_routes", return_value=routes), \
             patch("labguard.discovery._linux_proc_neighbors", return_value=neighbors), \
             patch("labguard.discovery._resolv_dns", return_value=[]), \
             patch("labguard.discovery.run_bounded") as runner:
            result = discover_local_network()
        runner.assert_not_called()
        self.assertEqual(result["gateway"], "192.168.15.1")
        self.assertEqual([r["ip"] for r in result["neighbors"]], ["192.168.15.21"])
        self.assertTrue(result["discovery"]["read_success"])
        self.assertEqual(result["discovery"]["sources"], ["linux-ioctl", "linux-sysfs-mac", "linux-proc-route", "linux-proc-arp"])
        self.assertEqual(result["interfaces"][0]["mac"], "02:00:00:00:00:10")

    def test_successfully_empty_linux_tables_do_not_invent_or_fallback(self):
        with patch("labguard.discovery.platform.system", return_value="Linux"), \
             patch("labguard.discovery.shutil.which", return_value="/usr/bin/ip"), \
             patch("labguard.discovery.run_bounded", side_effect=[completed([]), completed([]), completed([])]), \
             patch("labguard.discovery._resolv_dns", return_value=[]), \
             patch("labguard.discovery._linux_interfaces_ioctl") as interfaces, \
             patch("labguard.discovery._linux_proc_routes") as routes, \
             patch("labguard.discovery._linux_proc_neighbors") as neighbors:
            result = discover_local_network()
        for fallback in (interfaces, routes, neighbors):fallback.assert_not_called()
        self.assertEqual(result["neighbors"], [])
        self.assertEqual(result["interfaces"], [])
        self.assertEqual(result["discovery"], {"source": "local", "read_success": True, "interfaces_read": True,
            "routes_read": True, "neighbors_read": True, "sources": ["linux-iproute2"]})

    def test_linux_malformed_table_and_failed_component_use_only_required_fallback(self):
        with patch("labguard.discovery.platform.system", return_value="Linux"), \
             patch("labguard.discovery.shutil.which", return_value="/usr/bin/ip"), \
             patch("labguard.discovery.run_bounded", side_effect=[completed(ADDRESSES), completed({}), subprocess.TimeoutExpired("ip", 8)]), \
             patch("labguard.discovery._resolv_dns", return_value=[]), \
             patch("labguard.discovery._linux_interfaces_ioctl") as interfaces, \
             patch("labguard.discovery._linux_proc_routes", return_value=[]) as routes, \
             patch("labguard.discovery._linux_proc_neighbors", return_value=None) as neighbors:
            result = discover_local_network()
        interfaces.assert_not_called(); routes.assert_called_once(); neighbors.assert_called_once()
        self.assertTrue(result["discovery"]["interfaces_read"])
        self.assertTrue(result["discovery"]["routes_read"])
        self.assertFalse(result["discovery"]["neighbors_read"])
        self.assertIn("Formato inesperado", " ".join(result["warnings"]))

    def test_proc_routes_require_default_active_gateway_and_little_endian(self):
        text = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" + "\n".join([
            "eth0 00000000 010FA8C0 0003 0 0 12 00000000 0 0 0",
            "eth0 00000000 020FA8C0 0001 0 0 0 00000000 0 0 0",
            "eth0 00000000 030FA8C0 0002 0 0 0 00000000 0 0 0",
            "eth0 00000000 040FA8C0 0203 0 0 0 00000000 0 0 0",
            "eth0 00000000 00000000 0003 0 0 0 00000000 0 0 0",
            "eth0 00000000 050FA8C0 0003 0 0 -1 00000000 0 0 0",
            "eth0 000FA8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0"])
        with patch("labguard.discovery._read_local_text", return_value=text):
            self.assertEqual(_linux_proc_routes([]), [{"name": "eth0", "gateway": "192.168.15.1", "metric": 12}])

    def test_proc_arp_accepts_only_complete_ethernet_cache_entries(self):
        text = "IP address HW type Flags HW address Mask Device\n" + "\n".join([
            "192.168.15.20 0x1 0x2 02:00:00:00:00:20 * eth0",
            "192.168.15.21 0x1 0x0 02:00:00:00:00:21 * eth0",
            "192.168.15.22 0x2 0x2 02:00:00:00:00:22 * eth0",
            "192.168.15.23 bad bad 02:00:00:00:00:23 * eth0"])
        with patch("labguard.discovery._read_local_text", return_value=text):
            rows = _linux_proc_neighbors([])
        self.assertEqual([r["ip"] for r in rows], ["192.168.15.20"])
        self.assertNotIn("online", rows[0]["state"].lower())

    def test_ioctl_uses_only_getters_with_bounded_names_and_reads_explicit_mac(self):
        content = "Inter-| Receive | Transmit\n face |bytes packets\n lo: 0\n eth0: 0\n ../secret: 0\n toolonginterfacename: 0\n"
        calls = []
        def ioctl(fd, command, request):
            name = request[:16].split(b"\0", 1)[0].decode()
            calls.append((name, command))
            result = bytearray(40)
            if command == 0x8913:struct.pack_into("H", result, 16, 1)
            else:
                struct.pack_into("H", result, 16, socket.AF_INET)
                address = "127.0.0.1" if name == "lo" else "192.168.15.10"
                result[20:24] = socket.inet_aton("255.255.255.0" if command == 0x891B else address)
            return bytes(result)
        descriptor = Mock();descriptor.__enter__ = Mock(return_value=descriptor);descriptor.__exit__ = Mock(return_value=False)
        descriptor.fileno.return_value = 7
        with patch("labguard.discovery._read_local_text", return_value=content), \
             patch("socket.socket", return_value=descriptor), \
             patch.dict("sys.modules", {"fcntl": SimpleNamespace(ioctl=ioctl)}), \
             patch("labguard.discovery._sys_interface_mac", side_effect=lambda n:"02:00:00:00:00:10" if n=="eth0" else ""):
            result = _linux_interfaces_ioctl([])
        self.assertEqual({c[0] for c in calls}, {"lo", "eth0"})
        self.assertEqual({c[1] for c in calls}, {0x8913, 0x8915, 0x891B})
        self.assertEqual(next(r for r in result if r["name"] == "eth0")["prefixlen"], 24)
        self.assertEqual(next(r for r in result if r["name"] == "eth0")["mac"], "02:00:00:00:00:10")

    def test_local_kernel_reads_are_bounded_and_sysfs_paths_are_not_user_controlled(self):
        warnings=[]
        with patch("pathlib.Path.open", return_value=StringIO("x"*11)) as reader:
            self.assertIsNone(_read_local_text("/proc/net/arp", warnings, "test", maximum=10))
        self.assertTrue(warnings)
        for name in ("../secret", "..", "/etc/passwd", "eth0/../../", "a"*16):
            with patch("pathlib.Path.open") as reader:
                self.assertEqual(_sys_interface_mac(name), "")
                reader.assert_not_called()
        for value, expected in (("02:aa:bb:cc:dd:ee\n", "02:aa:bb:cc:dd:ee"), ("01:00:5e:00:00:01\n", ""), ("00:00:00:00:00:00\n", "")):
            with patch("pathlib.Path.open", return_value=StringIO(value)):
                self.assertEqual(_sys_interface_mac("eth0"), expected)

    def test_all_failed_ioctls_are_unavailable_not_successfully_empty(self):
        content="Inter-| Receive | Transmit\n face |bytes packets\n eth0: 0\n"
        descriptor=Mock();descriptor.__enter__=Mock(return_value=descriptor);descriptor.__exit__=Mock(return_value=False)
        descriptor.fileno.return_value=7
        with patch("labguard.discovery._read_local_text",return_value=content), \
             patch("socket.socket",return_value=descriptor), \
             patch.dict("sys.modules",{"fcntl":SimpleNamespace(ioctl=Mock(side_effect=OSError(errno.EPERM,"denied")))}):
            warnings=[]
            self.assertIsNone(_linux_interfaces_ioctl(warnings))
        self.assertIn("Nenhuma interface pôde", " ".join(warnings))

    def test_windows_cim_fallback_preserves_active_index_mask_and_no_command_injection(self):
        alternative={"interfaces":[{"name":"Ethernet", "ipv4":"192.168.15.10", "netmask":"255.255.255.0", "ifindex":12, "mac":"02-AA-BB-CC-DD-10"},
                                    {"name":"bad", "ipv4":"192.168.15.11", "netmask":"255.0.255.0", "ifindex":99}],
                     "routes":[{"gateway":"192.168.15.1", "ifindex":12, "metric":4}], "routes_read":True,"dns":["192.168.15.1"]}
        with patch("labguard.discovery.platform.system", return_value="Windows"), \
             patch("labguard.discovery.shutil.which", side_effect=lambda n:"powershell.exe" if n=="powershell.exe" else None), \
             patch("labguard.discovery.run_bounded", side_effect=[OSError("unavailable"),completed(alternative)]) as runner:
            result=discover_local_network()
        self.assertEqual(result["gateway"], "192.168.15.1")
        self.assertEqual(len(result["interfaces"]),1)
        self.assertFalse(result["discovery"]["neighbors_read"])
        self.assertIn("windows-cim",result["discovery"]["sources"])
        self.assertEqual(runner.call_args_list[1].args[0][-1],CIM_SCRIPT)
        self.assertIn("InterfaceIndex",CIM_SCRIPT);self.assertIn("route.Type -eq 4",CIM_SCRIPT)
        for forbidden in ("Set-Net", "Invoke-Command", "Test-Connection", "-ComputerName", "EnableDHCP"):
            self.assertNotIn(forbidden,CIM_SCRIPT)

    def test_windows_cache_fallback_parses_localized_headers_but_requires_matching_ip_and_index(self):
        raw={"interfaces":[{"name":"Ethernet","ipv4":"192.168.15.10","prefixlen":24,"ifindex":12}],"routes":[],"neighbors":[],"dns":[],"partial":True}
        cache="""Schnittstelle: 192.168.15.10 --- 0xc
 Internetadresse Physische Adresse Typ
 192.168.15.20 02-aa-bb-cc-dd-20 dynamisch
 192.168.15.30 01-00-5e-00-00-01 statisch
Interface: 192.168.15.10 --- 0xd
 192.168.15.21 02-aa-bb-cc-dd-21 dynamic
Interface: 192.168.16.10 --- 0xc
 192.168.15.22 02-aa-bb-cc-dd-22 dynamic
"""
        with patch("labguard.discovery.platform.system", return_value="Windows"), \
             patch("labguard.discovery.shutil.which", side_effect=lambda n:n if n in {"powershell.exe","arp.exe"} else None), \
             patch("labguard.discovery.run_bounded", side_effect=[completed(raw),subprocess.CompletedProcess([],0,cache,"")]) as runner:
            result=discover_local_network()
        self.assertEqual([r["ip"] for r in result["neighbors"]],["192.168.15.20"])
        self.assertEqual(runner.call_args_list[1].args[0],["arp.exe","-a"])
        self.assertIn("windows-arp",result["discovery"]["sources"])
        self.assertTrue(result["discovery"]["neighbors_read"])

    def test_empty_windows_tables_do_not_trigger_cim_or_arp(self):
        raw={"interfaces":[],"routes":[],"neighbors":[],"dns":[]}
        with patch("labguard.discovery.platform.system", return_value="Windows"), \
             patch("labguard.discovery.shutil.which", return_value="powershell.exe"), \
             patch("labguard.discovery.run_bounded", return_value=completed(raw)) as runner:
            result=discover_local_network()
        self.assertEqual(runner.call_count,1)
        self.assertTrue(result["discovery"]["read_success"])
        self.assertEqual(result["neighbors"],[])

    def test_bad_windows_parts_are_not_silently_reported_as_empty_success(self):
        with patch("labguard.discovery.platform.system", return_value="Windows"), \
             patch("labguard.discovery.shutil.which", side_effect=lambda n:"powershell.exe" if n=="powershell.exe" else None), \
             patch("labguard.discovery.run_bounded", side_effect=[completed({}),completed({})]):
            result=discover_local_network()
        self.assertFalse(result["discovery"]["read_success"])
        self.assertFalse(result["discovery"]["interfaces_read"])
        self.assertFalse(result["discovery"]["routes_read"])
        self.assertFalse(result["discovery"]["neighbors_read"])

    def test_self_mac_is_kept_only_when_explicit_and_does_not_grant_control(self):
        addresses=copy.deepcopy(ADDRESSES);addresses[0]["address"]="02:00:00:00:00:10"
        local,_=self.linux(addresses=addresses)
        transport=LocalObservationTransport()
        with patch("labguard.discovery.discover_local_network",return_value=local):
            data=transport.request("snapshot")
        own=next(r for r in data["devices"] if r["ip"]=="192.168.15.10")
        self.assertEqual(own["mac"],"02:00:00:00:00:10")
        self.assertTrue(own["protected"])
        self.assertEqual(own["evidence"],["Interface local"])
        self.assertFalse(any(v for k,v in data["capabilities"].items() if k!="inventory"))


if __name__ == "__main__":
    unittest.main()
