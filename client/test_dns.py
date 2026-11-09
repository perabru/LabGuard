import contextlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import labguard_cliente as client

class ManagedHostsTests(unittest.TestCase):
    def test_binary_roundtrip_and_aliases(self):
        raw = b"\xef\xbb\xbf# arquivo da TI: a\xe7\xe3o\n127.0.0.1 localhost\n9.8.7.6 escola.lan"
        own = "aa" * 24
        targets = client._hosts_names({"domains": ["roblox.com", "www.poki.com"]})
        protected, _, clashes, seen = client._hosts_block(raw, own, targets)
        self.assertFalse(seen)
        self.assertFalse(clashes)
        self.assertIn(b"0.0.0.0 gamejoin.roblox.com\n", protected)
        self.assertIn(b":: www.poki.com\n", protected)
        self.assertNotIn(b"www.www.poki.com", protected)
        self.assertEqual(client._hosts_block(protected, own, targets)[0], protected)
        self.assertEqual(client._hosts_block(protected, own, set())[0], raw)

    def test_preserves_foreign_edits_and_explicit_mappings(self):
        own = "bb" * 24
        raw = b"10.8.0.4 poki.com my-school.lan\r\n"
        protected, count, clashes, _ = client._hosts_block(raw, own, {"poki.com", "www.poki.com"})
        self.assertEqual((count, clashes), (1, 1))
        self.assertNotIn(b"0.0.0.0 poki.com", protected)
        extra = b"# adicionado por outro administrador\r\n"
        output = client._hosts_block(extra + protected + extra, own, set())[0]
        self.assertEqual(output, extra + raw + extra)

    def test_ownership_and_corruption(self):
        own = "aa" * 24
        protected = client._hosts_block(b"", own, {"example.org"})[0]
        for content, token in ((protected, "bb" * 24),
                               (protected.replace(b":: example.org", b"10.1.1.1 my.school"), own),
                               (protected + protected, own),
                               (b"\xff\xfec\x00", own)):
            with self.subTest(content=content[:20]):
                with self.assertRaises(client._HostsIssue):
                    client._hosts_block(content, token, set())

    def test_mixed_lines_comments_and_no_trailing_newline(self):
        own = "aa" * 24
        for raw in (b"", b"# test", b"# one\r\n# two\n", b"# empty line\n\n"):
            with self.subTest(raw=raw):
                changed = client._hosts_block(raw, own, {"example.org"})[0]
                self.assertEqual(client._hosts_block(changed, own, set())[0], raw)

    def test_writer_checks_ownership_and_keeps_state_on_error(self):
        with tempfile.TemporaryDirectory() as testdir:
            path = Path(testdir, "hosts")
            path.write_bytes(b"1.2.3.4 campus.lan\n")
            state, saves = {}, []

            @contextlib.contextmanager
            def read(kernel, target):
                yield target.read_bytes() if target.exists() else None

            def replace(kernel, target, backup, previous, data, erase):
                self.assertIn("system_hosts", saves[-1])
                self.assertEqual(saves[-1]["system_hosts"]["before"], client._hosts_sha(previous))
                if previous is not None:
                    os.rename(target, backup)
                if not erase:
                    target.write_bytes(data)

            def save():
                import copy
                saves.append(copy.deepcopy(state))

            with patch.object(client, "_hosts_location", return_value=(None, path, path.parent)), \
                    patch.object(client, "_hosts_read_locked", read), patch.object(client, "_hosts_apply_file", replace), \
                    patch.object(client.subprocess, "CREATE_NO_WINDOW", 0, create=True), patch.object(client.subprocess, "run") as cmd:
                cmd.return_value.returncode = 0
                policy = {"domains": ["example.org"]}
                self.assertTrue(client.sync_system_sites(policy, state, checkpoint=save)["ok"])
                self.assertFalse(client.sync_system_sites(policy, state, checkpoint=save)["changed"])
                self.assertEqual(cmd.call_count, 1)
                raw = path.read_bytes()
                path.write_bytes(raw.replace(b":: example.org", b":: another.net"))
                self.assertFalse(client.undo_system_sites(state, checkpoint=save)["ok"])
                self.assertIn("system_hosts", state)
                path.write_bytes(raw + b"# added")
                self.assertTrue(client.undo_system_sites(state, checkpoint=save)["ok"])
                self.assertEqual(path.read_bytes(), b"1.2.3.4 campus.lan\n# added")
                self.assertNotIn("system_hosts", state)


if __name__ == "__main__":
    unittest.main()
