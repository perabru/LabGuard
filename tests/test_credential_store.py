import ctypes
import unittest
from unittest.mock import Mock, patch

from labguard.credential_store import (CredentialStore, CredentialStoreError, _Credential,
                                      _WindowsCredentialAPI, credential_target)


def router(**changes):
    return dict({"host": "192.168.88.1", "port": 443, "user": "TI"}, **changes)


class CredentialTests(unittest.TestCase):
    def store(self, provider):
        with patch("labguard.credential_store.platform.system", return_value="Windows"), \
             patch("labguard.credential_store._WindowsCredentialAPI", return_value=provider):
            return CredentialStore()

    def test_unavailable_system_never_reads_files_or_attempts_plaintext_fallback(self):
        with patch("labguard.credential_store.platform.system", return_value="Linux"), \
             patch("labguard.credential_store._WindowsCredentialAPI") as api:
            store = CredentialStore()
        self.assertFalse(store.available()); self.assertTrue(store.reason)
        api.assert_not_called()
        for operation in (lambda:store.store(router(), "secret-sentinel"), lambda:store.load(router()), lambda:store.delete(router())):
            with self.assertRaises(CredentialStoreError) as caught:operation()
            self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_checking_availability_does_not_read_any_account(self):
        api = Mock(); store = self.store(api)
        self.assertTrue(store.available()); self.assertEqual(store.reason, "")
        api.read.assert_not_called(); api.write.assert_not_called(); api.delete.assert_not_called()

    def test_target_binds_canonical_host_port_and_exact_username(self):
        first = credential_target(router())
        self.assertTrue(first.startswith("LabGuard/RouterOS/v1/"))
        self.assertNotIn("192.168", first)
        self.assertNotEqual(first, credential_target(router(host="192.168.88.2")))
        self.assertNotEqual(first, credential_target(router(port=8443)))
        self.assertNotEqual(first, credential_target(router(user="ti")))
        self.assertEqual(credential_target(router(host="2001:0db8::1")), credential_target(router(host="2001:db8::1")))

    def test_profile_cannot_supply_a_target_password_or_authorization(self):
        api = Mock(); store = self.store(api)
        for change in ({"target": "another-app"}, {"password": "secret-sentinel"}, {"manage_rules": True}, {"host": "https://user:secret@router/"}):
            with self.subTest(change=change), self.assertRaises(CredentialStoreError):store.load(router(**change))
        api.read.assert_not_called()

    def test_store_load_and_delete_use_only_the_same_scoped_target(self):
        api = Mock(read=Mock(return_value="secret-sentinel"), delete=Mock(return_value=True))
        store = self.store(api); profile = router()
        self.assertTrue(store.store(profile, "secret-sentinel"))
        self.assertEqual(store.load(profile), "secret-sentinel")
        self.assertTrue(store.delete(profile))
        api.write.assert_called_once_with(credential_target(profile), "TI", "secret-sentinel")
        api.read.assert_called_once_with(credential_target(profile), "TI")
        api.delete.assert_called_once_with(credential_target(profile))

    def test_wrong_host_never_loads_another_hosts_entry(self):
        original = router(); changed = router(host="192.168.88.2")
        saved = {credential_target(original): "secret-sentinel"}
        api = Mock(read=Mock(side_effect=lambda target, username:saved.get(target)))
        store = self.store(api)
        self.assertIsNone(store.load(changed))
        self.assertEqual(store.load(original), "secret-sentinel")

    def test_password_limits_and_provider_errors_have_neutral_messages(self):
        api = Mock(write=Mock(side_effect=OSError("secret-sentinel")))
        store = self.store(api)
        for password in ("", "bad\nvalue", "x"*1025, "😀"*700, "secret-sentinel\ud800", "secret-sentinel"):
            with self.subTest(size=len(password)), self.assertRaises(CredentialStoreError) as caught:
                store.store(router(), password)
            self.assertNotIn("secret-sentinel", str(caught.exception))

    def test_native_write_uses_generic_per_user_local_machine_scope_and_wipes_work_buffer(self):
        native = _WindowsCredentialAPI.__new__(_WindowsCredentialAPI)
        native.api = Mock()
        captured = {}
        def write(pointer, flags):
            value = pointer._obj
            captured.update(type=value.Type, persist=value.Persist, target=value.TargetName,
                            username=value.UserName, password=ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize), value=value)
            return True
        native.api.CredWriteW.side_effect = write
        native.write("LabGuard/test-target", "TI", "test-secret")
        self.assertEqual((captured["type"], captured["persist"]), (1, 2))
        self.assertEqual(captured["password"], b"test-secret")
        value = captured["value"]
        self.assertEqual(ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize), b"\0"*len(b"test-secret"))

    def test_native_read_always_frees_buffer_and_rejects_wrong_target_or_invalid_blob(self):
        for wrong_target, raw in ((False, b"test-secret"), (True, b"test-secret"), (False, b"\xff\xfe"), (False, b"")):
            with self.subTest(wrong_target=wrong_target, raw=raw):
                blob = (ctypes.c_ubyte * max(1,len(raw))).from_buffer_copy(raw or b"\0")
                value = _Credential(Type=1, TargetName="other-target" if wrong_target else "LabGuard/test-target",
                                    UserName="TI", CredentialBlobSize=len(raw), CredentialBlob=blob)
                native = _WindowsCredentialAPI.__new__(_WindowsCredentialAPI); native.api = Mock()
                def read(target, kind, flags, output):
                    ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(_Credential)))[0] = ctypes.pointer(value)
                    return True
                native.api.CredReadW.side_effect = read
                if wrong_target or raw in (b"\xff\xfe", b""):
                    with self.assertRaises(CredentialStoreError):native.read("LabGuard/test-target", "TI")
                else:self.assertEqual(native.read("LabGuard/test-target", "TI"), "test-secret")
                native.api.CredFree.assert_called_once()


if __name__ == "__main__":unittest.main()
