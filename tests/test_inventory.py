import copy
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import patch

from labguard.inventory import collection_recency, summarize_inventory


NOW = datetime(2026, 11, 7, 15, 0, 0, tzinfo=timezone.utc)


def snapshot(**extra):
    result = {"mode": "observation", "timestamp": NOW.isoformat(), "interfaces": [], "devices": [],
              "capabilities": {"inventory": True, "address_blocking": False},
              "discovery": {"read_success": True, "interfaces_read": True, "routes_read": True,
                            "neighbors_read": True, "sources": ["linux-iproute2"]}}
    result.update(extra)
    return result


class RecencyTests(unittest.TestCase):
    def test_age_uses_source_timestamp_and_twenty_seconds_is_inclusive(self):
        current = collection_recency({"timestamp": (NOW-timedelta(seconds=20)).isoformat(), "received_at": NOW.isoformat()}, now=NOW)
        self.assertTrue(current["fresh"])
        self.assertEqual(current["age_seconds"], 20)
        old = collection_recency({"timestamp": (NOW-timedelta(seconds=21)).isoformat(), "received_at": NOW.isoformat()}, now=NOW)
        self.assertFalse(old["fresh"])
        self.assertEqual(old["time_status"], "stale")
        self.assertTrue(collection_recency(old["timestamp"], now=NOW, max_age_seconds=25)["fresh"])

    def test_any_future_naive_missing_or_bad_timestamp_is_never_recent(self):
        future = (NOW+timedelta(microseconds=1)).isoformat()
        values = [None, "", "bad", "2026-11-07T15:00:00", "2026-11-07", future, [], {}, True, 123]
        for value in values:
            with self.subTest(value=value):
                result = collection_recency(value, now=NOW)
                self.assertFalse(result["fresh"])
                self.assertIsNone(result["age_seconds"])
        self.assertEqual(collection_recency(future, now=NOW)["time_status"], "future")

    def test_timezone_is_normalized_without_making_collection_presence(self):
        result = collection_recency("2026-11-07T12:00:00-03:00", now=NOW)
        self.assertTrue(result["fresh"])
        self.assertEqual(result["age_seconds"], 0)
        self.assertTrue(result["timestamp"].endswith("+00:00"))
        summary = summarize_inventory(snapshot(devices=[{"ip": "192.168.1.3", "state": "online", "mac": "02:00:00:00:00:03"}]), now=NOW)
        self.assertTrue(summary["facts"]["collection_recent"])
        self.assertFalse(summary["facts"]["presence_confirmed"])

    def test_invalid_clock_or_limits_do_not_bypass_freshness(self):
        for limit in (True, -1, float("nan"), float("inf"), "20", None):
            self.assertFalse(collection_recency(NOW.isoformat(), now=NOW, max_age_seconds=limit)["fresh"])
        self.assertFalse(collection_recency(NOW.isoformat(), now=NOW.replace(tzinfo=None))["fresh"])
        self.assertFalse(collection_recency(NOW.isoformat(), now="now")["fresh"])


class InventoryTests(unittest.TestCase):
    def test_deduplicates_endpoint_addresses_and_does_not_count_saved_rules(self):
        data = snapshot(interfaces=[{"name": "eth0", "ipv4": "192.168.1.10"}, {"name": "eth0", "ipv4": "192.168.1.11"}], devices=[
            {"ip": "192.168.1.10", "mac": "", "state": "Endereço local"},
            {"ip": "192.168.1.20", "mac": "02:00:00:00:00:20", "evidence": ["ARP"]},
            {"ip": "192.168.1.20", "mac": "02-00-00-00-00-20", "evidence": ["DHCP"]},
            {"ip": "192.168.1.21", "mac": "02:00:00:00:00:20"},
            {"ip": "192.168.1.30", "mac": "02:00:00:00:00:30", "observed": False}])
        result = summarize_inventory(data, now=NOW)
        self.assertEqual(result["counts"]["devices"], 4)
        self.assertEqual(result["counts"]["unique_ips"], 4)
        self.assertEqual(result["counts"]["local_interfaces"], 1)
        self.assertEqual(result["counts"]["local_devices"], 2)
        self.assertEqual(result["counts"]["observed_neighbors"], 2)
        self.assertEqual(result["counts"]["known_macs"], 1)
        self.assertEqual(result["counts"]["identity_conflicts"], 0)
        self.assertEqual(result["counts"]["missing_neighbor_macs"], 0)
        self.assertEqual(result["counts"]["addresses_without_observation"], 1)
        self.assertFalse(result["facts"]["people_identified"])

    def test_same_ip_with_distinct_macs_is_ambiguous_not_two_people(self):
        result = summarize_inventory(snapshot(devices=[
            {"ip": "192.168.1.20", "mac": "02:00:00:00:00:20"},
            {"ip": "192.168.1.20", "mac": "02:00:00:00:00:21"},
            {"ip": "192.168.1.21", "mac": "02:00:00:00:00:22", "identity_conflict": True}]), now=NOW)
        self.assertEqual(result["counts"]["unique_ips"], 2)
        self.assertEqual(result["counts"]["identity_conflicts"], 2)
        self.assertIn("identidades conflitantes", result["next_action"])
        self.assertFalse(result["facts"]["people_identified"])

    def test_explicit_local_macs_are_used_and_empty_self_mac_is_not_failure(self):
        result = summarize_inventory(snapshot(interfaces=[
            {"name": "eth0", "ipv4": "192.168.1.10", "mac": "02:00:00:00:00:10"},
            {"name": "eth1", "ipv4": "192.168.1.10", "mac": "02:00:00:00:00:11"}],
            devices=[{"ip": "192.168.1.10", "state": "Endereço local", "mac": ""}]), now=NOW)
        self.assertEqual(result["counts"]["local_devices"], 1)
        self.assertEqual(result["counts"]["observed_neighbors"], 0)
        self.assertEqual(result["counts"]["known_macs"], 2)
        self.assertEqual(result["counts"]["identity_conflicts"], 1)
        self.assertEqual(result["counts"]["missing_neighbor_macs"], 0)
        no_mac = summarize_inventory(snapshot(interfaces=[{"name": "eth0", "ipv4": "192.168.1.10"}], devices=[{"ip": "192.168.1.10", "state": "Endereço local", "mac": ""}]), now=NOW)
        self.assertEqual(no_mac["counts"]["identity_conflicts"], 0)
        self.assertEqual(no_mac["counts"]["missing_neighbor_macs"], 0)

    def test_empty_cache_read_success_is_partial_not_unavailable(self):
        result = summarize_inventory(snapshot(), now=NOW)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["devices"], 0)
        self.assertTrue(result["facts"]["read_confirmed"])
        self.assertTrue(result["fresh"])
        self.assertIn("cache vazio", " ".join(result["gaps"]))
        self.assertFalse(result["facts"]["coverage_complete"])

    def test_failed_collection_is_not_hidden_by_recent_timestamp_or_cached_rows(self):
        data = snapshot(devices=[{"ip": "192.168.1.20", "mac": "02:00:00:00:00:20"}], discovery={
            "read_success": False, "interfaces_read": False, "routes_read": False, "neighbors_read": False})
        result = summarize_inventory(data, now=NOW)
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["facts"]["read_confirmed"])
        self.assertFalse(result["fresh"])
        self.assertFalse(result["facts"]["collection_recent"])
        self.assertEqual(result["counts"]["devices"], 1)

    def test_dns_only_or_contradictory_metadata_does_not_confirm_inventory(self):
        result = summarize_inventory(snapshot(discovery={"read_success": True, "dns_read": True,
            "interfaces_read": False, "routes_read": False, "neighbors_read": False}), now=NOW)
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["facts"]["read_confirmed"])

    def test_fallback_success_precedes_old_errors_and_remains_partial(self):
        result = summarize_inventory(snapshot(interfaces=[{"name": "eth0", "ipv4": "192.168.1.10"}],
            warnings=["old failure with secret"], discovery={"read_success": True, "interfaces_read": True,
                "routes_read": True, "neighbors_read": False, "sources": ["linux-ioctl", "linux-proc-route"]}), now=NOW)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["facts"]["fallback_used"])
        self.assertTrue(result["facts"]["read_confirmed"])
        self.assertIn("vizinhos não pôde", " ".join(result["gaps"]))
        self.assertNotIn("secret", json.dumps(result))

    def test_absent_metadata_is_unknown_but_bad_technical_metadata_is_unavailable(self):
        absent = snapshot()
        del absent["discovery"]
        result = summarize_inventory(absent, now=NOW)
        self.assertIsNone(result["facts"]["collection_metadata_valid"])
        self.assertEqual(result["status"], "partial")
        for metadata in (None, [], "bad", {"read_success": "true"}, {"interfaces_read": 1},
                         {"read_success": False, "neighbors_read": True}):
            with self.subTest(metadata=metadata):
                result = summarize_inventory(snapshot(discovery=metadata), now=NOW)
                self.assertFalse(result["facts"]["collection_metadata_valid"])
                self.assertFalse(result["fresh"])
                self.assertFalse(result["facts"]["read_confirmed"])
                self.assertEqual(result["status"], "unavailable")

    def test_local_sysfs_mac_provenance_is_whitelisted(self):
        result = summarize_inventory(snapshot(discovery={"read_success": True, "interfaces_read": True,
            "sources": ["linux-sysfs-mac", "secret", "linux-sysfs-mac"]}), now=NOW)
        self.assertEqual(result["facts"]["source_methods"], ["linux-sysfs-mac"])
        self.assertTrue(result["facts"]["fallback_used"])

    def test_equipment_without_discovery_metadata_never_becomes_complete(self):
        result = summarize_inventory({"mode": "equipment", "timestamp": NOW.isoformat(), "devices": [],
            "capabilities": {"inventory": True, "address_blocking": True},
            "gateway": {"management_host": "192.168.1.1", "vendor": "MikroTik", "model": "Router"}}, now=NOW)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["facts"]["read_confirmed"])
        self.assertTrue(result["facts"]["gateway_identified"])
        self.assertTrue(result["facts"]["model_identified"])
        self.assertFalse(result["facts"]["coverage_complete"])
        self.assertIsNone(result["facts"]["read_success"])

    def test_demo_cannot_look_like_real_identification(self):
        result = summarize_inventory({"mode": "demo", "timestamp": NOW.isoformat(), "devices": [{"ip": "192.168.1.20", "mac": "02:00:00:00:00:20"}]}, now=NOW)
        self.assertEqual(result["status"], "demo")
        self.assertIn("fictício", result["summary"])
        self.assertFalse(result["facts"]["coverage_complete"])
        self.assertFalse(result["facts"]["presence_confirmed"])

    def test_invalid_or_missing_source_time_never_looks_current(self):
        for value in (None, "invalid", NOW.replace(tzinfo=None).isoformat(), (NOW+timedelta(seconds=1)).isoformat(), (NOW-timedelta(seconds=21)).isoformat()):
            with self.subTest(value=value):
                result = summarize_inventory(snapshot(timestamp=value), now=NOW)
                self.assertEqual(result["status"], "partial")
                self.assertFalse(result["fresh"])
                self.assertFalse(result["facts"]["collection_recent"])
                self.assertIn("Atualize a fonte", result["next_action"])

    def test_counts_ignore_malformed_rows_multicast_and_unobserved_data(self):
        data = snapshot(devices=[None, {}, "bad", {"ip": "hostname"}, {"ip": "::ffff:127.0.0.1"},
             {"ip": "224.0.0.1"}, {"ip": "192.168.1.20", "observed": "true"},
             {"ip": "192.168.1.21", "mac": "ff:ff:ff:ff:ff:ff"},
             {"ip": "192.168.1.21", "mac": "02:00:00:00:00:21"}])
        result = summarize_inventory(data, now=NOW)
        self.assertEqual(result["counts"]["records_ignored"], 7)
        self.assertEqual(result["counts"]["devices"], 1)
        self.assertEqual(result["counts"]["missing_neighbor_macs"], 0)

    def test_untrusted_text_and_secrets_are_not_returned_and_snapshot_is_unchanged(self):
        secret = "test-password-and-private-key"
        data = snapshot(source=secret, warnings=[secret], last_error=secret,
            interfaces=[{"name": secret, "ipv4": "192.168.1.10"}],
            devices=[{"ip": "192.168.1.20", "mac": "02:00:00:00:00:20", "name": secret, "state": secret}],
            discovery={"read_success": True, "source": secret, "sources": [secret, "linux-iproute2"], "interfaces_read": True})
        before = copy.deepcopy(data)
        with patch("socket.socket", side_effect=AssertionError("No network collection")), patch("subprocess.Popen", side_effect=AssertionError("No commands")), patch("pathlib.Path.open", side_effect=AssertionError("No file reads")):
            result = summarize_inventory(data, now=NOW)
        rendered = json.dumps(result, ensure_ascii=False)
        for value in (secret, "192.168.1.10", "192.168.1.20", "02:00:00:00:00:20"):
            self.assertNotIn(value, rendered)
        self.assertEqual(data, before)
        self.assertEqual(data["capabilities"], {"inventory": True, "address_blocking": False})

    def test_malformed_container_types_and_large_input_remain_bounded(self):
        for data in (None, [], "secret", {"mode": [], "devices": [None], "timestamp": {}},
                     {"mode": "observation", "capabilities": {"inventory": 1}, "discovery": []}):
            result = summarize_inventory(data, now=NOW)
            self.assertEqual(result["status"], "unavailable")
            self.assertFalse(result["fresh"])
        result = summarize_inventory(snapshot(devices=[{"ip": "192.168.1.20"}]*10001), now=NOW)
        self.assertEqual(result["counts"]["devices"], 1)
        self.assertIn("dez mil", " ".join(result["gaps"]))


if __name__ == "__main__":
    unittest.main()
