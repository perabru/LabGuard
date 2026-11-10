from __future__ import annotations

import copy
from email.message import Message
from io import BytesIO
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit

from labguard.direct_routeros import DirectRouterOSTransport, DirectRouterOSError, _metadata, _NoRedirect


class Response:
    def __init__(self, value, status=200):
        self.stream = BytesIO(json.dumps(value).encode())
        self.status = status
        self.headers = {"Content-Length": str(len(self.stream.getvalue()))}
        sock = SimpleNamespace(getsockname=lambda: ("192.168.88.10", 50000), settimeout=lambda value: None)
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=sock))
        self.closed = False

    def read1(self, size):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class Router:
    def __init__(self):
        self.calls, self.counter, self.fail = [], 32, set()
        self.before_delete_get = None
        self.data = {
            "system/resource": {"version": "7.18.2 (stable)", "board-name": "hAP ax2"},
            "system/identity": [{"name": "escola"}],
            "ip/address": [{"address": "192.168.88.1/24", "interface": "bridge-LAN"}, {"address": "192.168.15.2/24", "interface": "ether1"}],
            "ip/dhcp-server/network": [{"address": "192.168.88.0/24", "dns-server": "192.168.88.1", "gateway": "192.168.88.1"}],
            "ip/dhcp-server/lease": [{"address": "192.168.88.101", "mac-address": "02:00:00:00:00:01", "host-name": "Aluno", "status": "bound"},
                                       {"address": "192.168.88.10", "mac-address": "02:00:00:00:00:0a", "host-name": "TI", "status": "bound"}],
            "ip/arp": [{"address": "192.168.88.101", "mac-address": "02:00:00:00:00:01", "interface": "bridge-LAN", "complete": "true"}],
            "ip/firewall/filter": [{".id": "*1", "chain": "forward", "action": "accept", "connection-state": "established,related", "comment": "existing-admin-rule"}],
            "interface/list": [{"name": "WAN"}], "interface/list/member": [{"list": "WAN", "interface": "ether1"}],
            "interface": [{"name": "ether1", "mac-address": "02:aa:00:00:00:01"}, {"name": "bridge-LAN", "mac-address": "02:bb:00:00:00:01"}],
            "ip/dhcp-server": [{"name": "dhcp1", "interface": "bridge-LAN"}],
            "ip/dns": [{"allow-remote-requests": "true"}], "ip/dns/static": [],
            "ipv6/settings": [{"disable-ipv6": "true", "forward": "false"}],
            "ip/settings": [{"ip-forward": "true", "ipv4-fasttrack-active": "false"}],
            "interface/ethernet/switch": [{"name": "switch1", "l3-hw-offloading": "false"}],
        }

    def open(self, request, timeout):
        path = unquote(urlsplit(request.full_url).path.removeprefix("/rest/"))
        method = request.get_method()
        body = json.loads(request.data) if request.data else None
        self.calls.append((method, path, body, timeout))
        if path in self.fail:
            raise HTTPError(request.full_url, 403, "secret-must-not-appear", Message(), None)
        if "/" in path and path.rsplit("/", 1)[1].startswith("*"):
            menu, identifier = path.rsplit("/", 1)
            if method == "GET" and self.before_delete_get:
                self.before_delete_get(menu, identifier)
            row = next((row for row in self.data[menu] if row[".id"] == identifier), None)
            if method == "DELETE":
                self.data[menu] = [row for row in self.data[menu] if row[".id"] != identifier]
                return Response([])
            return Response(copy.deepcopy(row))
        if method == "PUT":
            self.counter += 1
            row = dict(body, **{".id": "*%X" % self.counter})
            before = row.pop("place-before", None)
            if before:
                self.data[path].insert(0, row)
            else:
                self.data[path].append(row)
            return Response(copy.deepcopy(row), 201)
        return Response(copy.deepcopy(self.data[path]))

    @property
    def mutations(self):
        return [call for call in self.calls if call[0] != "GET"]


class DirectRouterOSTests(unittest.TestCase):
    def setUp(self):
        self.router = Router()
        self.transport = DirectRouterOSTransport("192.168.88.1", user="labguard", password="test-password", manage_rules=True)
        self.transport._opener = self.router

    def test_inventory_has_observation_sources_and_explicit_capabilities(self):
        data = self.transport.request("snapshot")
        self.assertEqual(data["mode"], "equipment")
        self.assertEqual(data["gateway"]["lab_cidr"], "192.168.88.0/24")
        self.assertTrue(data["capabilities"]["address_blocking"])
        self.assertFalse(data["capabilities"]["device_internet_cut"])
        self.assertTrue(data["capabilities"]["domain_filtering"])
        self.assertFalse(data["capabilities"]["dns_history"])
        self.assertEqual(data["events"], [])
        student = next(row for row in data["devices"] if row["ip"].endswith(".101"))
        self.assertEqual(student["evidence"], ["DHCP", "ARP"])
        self.assertIsNone(student["ssid"])
        self.assertTrue(next(row for row in data["devices"] if row["ip"].endswith(".10"))["protected"])

    def test_read_only_default_never_sends_mutation(self):
        transport = DirectRouterOSTransport("192.168.88.1", user="read", password="password")
        transport._opener = self.router
        self.assertFalse(transport.request("snapshot")["capabilities"]["address_blocking"])
        for action, params in (("add_domain", {"domain": "poki.com"}), ("set_address_block", {"kind": "ip", "address": "192.168.88.101", "blocked": True})):
            with self.assertRaises(DirectRouterOSError):
                transport.request(action, **params)
        self.assertEqual(self.router.mutations, [])

    def test_independent_ip_and_mac_rules_and_safe_placement(self):
        self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=True)
        result = self.transport.request("set_address_block", kind="mac", address="02:00:00:00:00:01", blocked=True)
        student = next(row for row in result["devices"] if row["ip"].endswith(".101"))
        self.assertEqual(student["blocked_by"], ["ip", "mac"])
        puts = [call for call in self.router.mutations if call[0] == "PUT"]
        self.assertEqual(len(puts), 3)
        self.assertEqual(puts[0][2]["place-before"], "*1")
        self.assertTrue(any(call[2].get("dst-address") == "192.168.88.101" for call in puts))
        result = self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=False)
        self.assertEqual(next(row for row in result["devices"] if row["ip"].endswith(".101"))["blocked_by"], ["mac"])
        self.assertTrue(any(row.get("comment") == "existing-admin-rule" for row in self.router.data["ip/firewall/filter"]))

    def test_protected_unobserved_and_invalid_addresses_never_mutate(self):
        for kind, address in (("ip", "192.168.88.1"), ("ip", "192.168.88.10"), ("ip", "192.168.88.150"),
                              ("ip", "192.168.15.2"), ("mac", "02:00:00:00:00:0a"), ("mac", "ff:ff:ff:ff:ff:ff")):
            with self.subTest(kind=kind, address=address), self.assertRaises((ValueError, DirectRouterOSError)):
                self.transport.request("set_address_block", kind=kind, address=address, blocked=True)
        self.assertEqual(self.router.mutations, [])

    def test_ipv6_fasttrack_gateway_and_wan_ambiguity_disable_cut(self):
        changes = (("ipv6/settings", [{"disable-ipv6": "false", "forward": "true"}]),
                   ("ip/settings", [{"ip-forward": "true", "ipv4-fasttrack-active": "true"}]),
                   ("ip/dhcp-server/network", [{"address": "192.168.88.0/24", "gateway": "192.168.88.254", "dns-server": "192.168.88.1"}]),
                   ("interface/list/member", [{"list": "WAN", "interface": "bridge-LAN"}]),
                   ("interface/ethernet/switch", [{"l3-hw-offloading": "true"}]),
                   ("interface/ethernet/switch", [{"l3-hw-offloading": "true", "l3-hw-offload": "false"}]),
                   ("interface/ethernet/switch", [{"name": "switch1"}]))
        for path, changed in changes:
            old = self.router.data[path]
            self.router.data[path] = changed
            with self.subTest(path=path):
                self.assertFalse(self.transport.request("snapshot")["capabilities"]["address_blocking"])
                with self.assertRaises(DirectRouterOSError):
                    self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=True)
            self.router.data[path] = old
        self.assertEqual(self.router.mutations, [])

    def test_legacy_machine_action_is_not_advertised_or_accepted(self):
        snapshot = self.transport.request("snapshot")
        self.assertFalse(snapshot["capabilities"]["device_internet_cut"])
        self.assertTrue(snapshot["capabilities"]["address_blocking"])
        with self.assertRaises(ValueError):
            self.transport.request("set_device_block", ip="192.168.88.101", blocked=True)
        self.assertEqual(self.router.mutations, [])

    def test_unknown_prerequisite_is_readonly_and_does_not_enable_router_services(self):
        self.router.fail.add("ipv6/settings")
        result = self.transport.request("snapshot")
        self.assertTrue(result["capabilities"]["inventory"])
        self.assertFalse(result["capabilities"]["address_blocking"])
        self.assertNotIn("secret-must-not-appear", str(result))
        self.assertEqual(self.router.mutations, [])

    def test_dns_uses_nxdomain_subdomains_metadata_and_preserves_external(self):
        self.router.data["ip/dns/static"].append({".id": "*A", "name": "internal.example", "type": "A", "address": "192.168.88.4"})
        result = self.transport.request("add_domain", domain="GAMES.example", category="Jogos")
        row = next(row for row in result["domains"] if row["domain"] == "games.example")
        self.assertEqual((row["category"], row["source"]), ("Jogos", "manual"))
        self.assertTrue(row["created_at"])
        body = self.router.mutations[-1][2]
        self.assertEqual((body["type"], body["match-subdomain"]), ("NXDOMAIN", "true"))
        self.transport.request("remove_domain", domain="games.example")
        self.assertEqual(self.router.data["ip/dns/static"][0][".id"], "*A")
        with self.assertRaises(DirectRouterOSError):
            self.transport.request("remove_domain", domain="internal.example")

    def test_external_dns_overlap_old_version_and_external_dns_advertisement_refuse(self):
        self.router.data["ip/dns/static"].append({".id": "*A", "name": "games.example", "type": "NXDOMAIN", "match-subdomain": "true"})
        with self.assertRaises(DirectRouterOSError):
            self.transport.request("add_domain", domain="games.example")
        self.router.data["system/resource"]["version"] = "7.17.2"
        self.assertFalse(self.transport.request("snapshot")["capabilities"]["domain_filtering"])
        self.router.data["system/resource"]["version"] = "7.18.2"
        self.router.data["ip/dhcp-server/network"][0]["dns-server"] = "8.8.8.8"
        self.assertFalse(self.transport.request("snapshot")["capabilities"]["domain_filtering"])
        self.assertEqual(self.router.mutations, [])

    def test_external_exact_dns_rule_does_not_claim_subdomain_coverage(self):
        from labguard.site_controls import site_rows
        self.router.data["ip/dns/static"].append({".id": "*A", "name": "example.org", "type": "NXDOMAIN", "match-subdomain": "false"})
        snapshot = self.transport.request("snapshot")
        external = next(row for row in snapshot["domains"] if row["domain"] == "example.org")
        self.assertIs(external["match_subdomains"], False)
        child = next(row for row in site_rows(snapshot, catalog=({"domain": "child.example.org", "category": "Outros"},))
                     if row["domain"] == "child.example.org")
        self.assertEqual(child["state"], "Sem bloqueio neste filtro")
        self.assertTrue(child["can_block"])
        after = self.transport.request("add_domain", domain="child.example.org", category="Outros")
        added = next(row for row in after["domains"] if row["domain"] == "child.example.org")
        self.assertIs(added["match_subdomains"], True)
        self.assertEqual(added["source"], "manual")

    def test_incomplete_duplicate_and_edited_own_filter_are_not_confirmed_or_removed(self):
        self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=True)
        original = copy.deepcopy(self.router.data["ip/firewall/filter"])
        own = [row for row in original if row.get("comment", "").startswith("LabGuard2:")]
        variants = [original[1:], original + [dict(own[0], **{".id": "*FF"})],
                    [dict(row, protocol="tcp") if row.get(".id") == own[0][".id"] else row for row in original]]
        for rows in variants:
            self.router.data["ip/firewall/filter"] = copy.deepcopy(rows)
            before = len(self.router.mutations)
            with self.subTest(rows=rows):
                self.assertFalse(self.transport.request("snapshot")["capabilities"]["address_blocking"])
                with self.assertRaises(DirectRouterOSError):
                    self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=False)
                self.assertEqual(len(self.router.mutations), before)

    def test_delete_rechecks_record_and_preserves_concurrently_changed_rule(self):
        self.transport.request("add_domain", domain="games.example")
        def change(menu, identifier):
            if menu == "ip/dns/static":
                self.router.data[menu][0]["comment"] = "manual replacement"
        self.router.before_delete_get = change
        before = len(self.router.mutations)
        with self.assertRaises(DirectRouterOSError):
            self.transport.request("remove_domain", domain="games.example")
        self.assertEqual(len(self.router.mutations), before)

    def test_final_read_failure_never_confirms_a_removal(self):
        for kind in ("domain", "ip"):
            with self.subTest(kind=kind):
                self.router = Router()
                self.transport._opener = self.router
                if kind == "domain":
                    self.transport.request("add_domain", domain="games.example")
                    endpoint, action, params = "ip/dns/static", "remove_domain", {"domain": "games.example"}
                else:
                    self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=True)
                    endpoint, action, params = "ip/firewall/filter", "set_address_block", {"kind": "ip", "address": "192.168.88.101", "blocked": False}
                original = self.router.open
                def open_request(request, timeout):
                    result = original(request, timeout)
                    if request.get_method() == "DELETE":
                        self.router.fail.add(endpoint)
                    return result
                with patch.object(self.router, "open", side_effect=open_request):
                    with self.assertRaisesRegex(DirectRouterOSError, "consulta final"):
                        self.transport.request(action, **params)
                self.assertTrue(self.transport._audit[-1]["outcome"].startswith("Não confirmado"))

    def test_close_after_fresh_inventory_prevents_mutation(self):
        original = self.transport._view
        def view(*args):
            result = original(*args)
            self.transport.close()
            return result
        with patch.object(self.transport, "_view", side_effect=view), self.assertRaises(DirectRouterOSError):
            self.transport.request("add_domain", domain="games.example")
        self.assertEqual(self.router.mutations, [])

    def test_owned_unblock_works_when_device_is_offline(self):
        self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=True)
        self.router.data["ip/dhcp-server/lease"] = []
        self.router.data["ip/arp"] = []
        result = self.transport.request("set_address_block", kind="ip", address="192.168.88.101", blocked=False)
        self.assertEqual(result["address_blocks"], [])

    def test_close_invalidates_credentials_and_never_waits_for_worker_lock(self):
        self.transport._lock.acquire()
        self.transport.close()
        self.transport._lock.release()
        self.assertEqual(self.transport.password, "")
        with self.assertRaises(DirectRouterOSError):
            self.transport.request("snapshot")

    def test_http_redirect_rejected_and_response_limit(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "", {}, "https://other/"))
        response = Response({})
        response.headers["Content-Length"] = str(3 * 1024 * 1024)
        self.transport._opener = SimpleNamespace(open=lambda *args, **kwargs: response)
        with self.assertRaises(DirectRouterOSError):
            self.transport._http("GET", "system/resource", 1e20)
        self.assertTrue(response.closed)

    def test_slow_drip_obeys_global_deadline_between_read1_calls(self):
        clock = [0.0]
        response = Response({})
        response.headers = {}
        def drip(size):
            clock[0] += 2.5
            return b" "
        response.read1 = drip
        self.transport._opener = SimpleNamespace(open=lambda *args, **kwargs: response)
        with patch("labguard.direct_routeros.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(DirectRouterOSError, "Tempo total"):
                self.transport._http("GET", "system/resource", 5)
        self.assertEqual(clock[0], 5)
        self.assertTrue(response.closed)

    def test_input_validation_and_tls_context_never_disable_verification(self):
        for kwargs in ({"host": "https://evil"}, {"host": "router.example"}, {"port": True}, {"manage_rules": "true"}, {"user": "a:b"}, {"wan_interface_list": "WAN;reboot"}):
            params = dict(host="192.168.88.1", user="admin", password="password")
            params.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                DirectRouterOSTransport(**params)
        with patch("labguard.direct_routeros.build_opener") as build:
            DirectRouterOSTransport("192.168.88.1", user="admin", password="password")
            handlers = build.call_args.args
            self.assertTrue(any(getattr(handler, "proxies", None) == {} for handler in handlers))
            https = next(handler for handler in handlers if hasattr(handler, "_context"))
            self.assertTrue(https._context.check_hostname)
            self.assertEqual(https._context.verify_mode, 2)


if __name__ == "__main__":
    unittest.main()
