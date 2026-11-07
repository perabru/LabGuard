import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from labguard.preferences import (PreferenceError, PreferenceStore, default_preferences,
                                 normalize_preferences, normalize_router_profile)


def router(**changes):
    return dict({"host": "192.168.88.1", "port": 443, "user": "TI", "ca_file": "", "lab_cidr": "192.168.88.0/24",
                 "wan_interface_list": "WAN", "protected_ips": ["192.168.88.10"],
                 "protected_macs": ["02:AA:BB:CC:DD:10"]}, **changes)


class PreferenceTests(unittest.TestCase):
    def test_missing_file_returns_independent_safe_defaults_without_creating_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = PreferenceStore(Path(temporary)/"missing")
            first = store.load(); first["auto_updates"] = False
            self.assertEqual(store.load(), default_preferences())
            self.assertFalse(store.directory.exists())
            self.assertFalse(store.path.exists())

    def test_round_trip_keeps_only_public_router_settings_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = PreferenceStore(Path(temporary)/"private")
            saved = store.save({"schema": 1, "auto_updates": False, "auto_connect": True, "saved_router": router()})
            self.assertEqual(store.load(), saved)
            self.assertEqual(saved["saved_router"]["protected_macs"], ["02:aa:bb:cc:dd:10"])
            self.assertNotIn("manage_rules", store.path.read_text(encoding="utf-8"))
            self.assertEqual(set(saved), {"schema", "auto_updates", "auto_connect", "saved_router"})
            if os.name != "nt":
                self.assertEqual(store.directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)

    def test_secret_and_authorization_fields_are_rejected_before_any_write(self):
        for key in ("password", "token", "private_key", "manage_rules", "mode", "auto_apply"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                store = PreferenceStore(Path(temporary)/"private")
                data = default_preferences(); data[key] = "secret-sentinel"
                with self.assertRaises(PreferenceError) as caught:
                    store.save(data)
                self.assertNotIn("secret-sentinel", str(caught.exception))
                self.assertFalse(store.directory.exists())
                data = default_preferences(); data["saved_router"] = dict(router(), **{key: "secret-sentinel"})
                with self.assertRaises(PreferenceError):store.save(data)
                self.assertFalse(store.directory.exists())

    def test_auto_connect_requires_a_profile_and_exact_boolean_values(self):
        for data in ({"auto_connect": True}, {"auto_connect": "true"}, {"auto_updates": 1}, {"schema": True},
                     {"schema": 2}, {"saved_router": []}):
            with self.subTest(data=data), self.assertRaises(PreferenceError):normalize_preferences(data)
        public = normalize_preferences({"saved_router": router()})
        self.assertFalse(public["auto_connect"])
        self.assertTrue(public["auto_updates"])

    def test_profile_canonicalizes_only_identity_addresses_and_preserves_username_case(self):
        value = router(); value["host"] = "2001:0db8:0000::1"
        value["protected_ips"] = ["192.168.88.10", "192.168.88.10"]
        clean = normalize_router_profile(value)
        self.assertEqual(clean["host"], "2001:db8::1")
        self.assertEqual(clean["user"], "TI")
        self.assertEqual(clean["protected_ips"], ["192.168.88.10"])
        self.assertEqual(value["host"], "2001:0db8:0000::1")

    def test_invalid_targets_cannot_redirect_a_saved_account(self):
        for host in ("router.school", "https://192.168.88.1/", "user:secret@192.168.88.1", "::", "224.0.0.1", "fe80::1%eth0"):
            with self.subTest(host=host), self.assertRaises(PreferenceError):
                normalize_router_profile(dict(router(), host=host))
        for change in ({"port": True}, {"port": "443"}, {"port": 0}, {"user": ""}, {"user": "a:b"},
                       {"user": "TI\nsecret"}, {"lab_cidr": "192.168.88.1/24"},
                       {"lab_cidr": "0.0.0.0/0"}, {"wan_interface_list": "WAN;command"},
                       {"protected_macs": ["ff:ff:ff:ff:ff:ff"]}, {"protected_ips": ["::1"]}):
            with self.subTest(change=change), self.assertRaises(PreferenceError):
                normalize_router_profile(dict(router(), **change))

    def test_corrupt_or_oversized_file_never_becomes_an_auto_connection(self):
        for raw in (b"not json", b"x"*32769, b"["*2000 + b"0" + b"]"*2000,
                    json.dumps({"schema": 1, "auto_connect": True}).encode(),
                    b'{"schema":1,"auto_connect":false,"auto_connect":true}',
                    json.dumps({"schema": 1, "password": "secret-sentinel"}).encode()):
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as temporary:
                store = PreferenceStore(Path(temporary)/"private"); store.save(default_preferences())
                store.path.write_bytes(raw)
                with self.assertRaises(PreferenceError) as caught:store.load()
                self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_atomic_write_failure_keeps_previous_preferences(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = PreferenceStore(Path(temporary)/"private"); before = store.save(default_preferences())
            with patch("labguard.preferences.os.replace", side_effect=OSError("private-path-sentinel")):
                with self.assertRaises(PreferenceError) as caught:store.save(dict(before, auto_updates=False))
            self.assertNotIn("private-path-sentinel", str(caught.exception))
            self.assertEqual(store.load(), before)
            self.assertEqual([p.name for p in store.directory.iterdir()], ["settings.json"])

    def test_symbolic_and_reparse_paths_are_refused_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root/"target"; target.mkdir(mode=0o700)
            linked = root/"linked"
            try:linked.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):pass
            else:
                with self.assertRaises(PreferenceError):PreferenceStore(linked).save(default_preferences())
                self.assertFalse((target/"settings.json").exists())
            with patch("labguard.preferences._is_reparse", return_value=True):
                with self.assertRaises(PreferenceError):PreferenceStore(root/"fresh").load()

    @unittest.skipIf(os.name == "nt", "Permissões POSIX")
    def test_non_private_directory_or_file_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = PreferenceStore(Path(temporary)/"private"); store.save(default_preferences())
            store.path.chmod(0o644)
            with self.assertRaises(PreferenceError):store.load()
            store.path.chmod(0o600); store.directory.chmod(0o755)
            with self.assertRaises(PreferenceError):store.load()

    def test_hardlinked_settings_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = PreferenceStore(Path(temporary)/"private"); store.save(default_preferences())
            link = Path(temporary)/"other.json"
            try:os.link(store.path, link)
            except (OSError, NotImplementedError):self.skipTest("Hardlink indisponível")
            with self.assertRaises(PreferenceError):store.load()


if __name__ == "__main__":unittest.main()
