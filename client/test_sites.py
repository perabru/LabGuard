import copy
from pathlib import Path
import types
import unittest

import labguard_cliente as client

class MemoryRegistry:
    string_type = 1

    def __init__(self):
        self.data = {}
        self.operations = []

    def inspect(self, path):
        return path in self.data, self.data.get(path, {}).copy()

    def add_if_free(self, path, slot, text):
        values = self.data.setdefault(path, {})
        if slot in values:
            raise OSError("changed")
        values[slot] = (text, 1)
        self.operations.append(("add", path, text))

    def replace_if_same(self, path, slot, expected, new):
        if self.data[path][slot] != (expected, 1):
            raise OSError("changed")
        self.data[path][slot] = (new, 1)

    def remove_if_same(self, path, slot, expected):
        if self.data.get(path, {}).get(slot) == (expected, 1):
            del self.data[path][slot]
            self.operations.append(("remove", path, expected))

    def remove_if_empty(self, path):
        if not self.data.get(path):
            self.data.pop(path, None)


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.state = {}
        self.store = MemoryRegistry()
        self.last = None
        self.edge = r"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist"
        self.allow = r"SOFTWARE\Policies\Microsoft\Edge\URLAllowlist"
        self.firefox = r"SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block"

    def checkpoint(self):
        self.last = copy.deepcopy(self.state)

    def apply(self, domains=(), allow=(), strict=False, remove=False):
        return client._browser_policy_run(
            {"mode": "permitidos" if strict else "bloqueados", "domains": list(domains),
             "allowed_domains": list(allow)}, self.state, self.checkpoint, self.store, removing=remove)

    def test_resume_and_undo_preserve_institutional_values(self):
        self.store.data[self.edge] = {"999": ("institution.example", 1)}
        self.assertTrue(self.apply(["ROBLOX.COM", "poki.com"])["ok"])
        self.assertIn(("roblox.com", 1), self.store.data[self.edge].values())
        self.assertIn(("*://*.roblox.com/*", 1), self.store.data[self.firefox].values())
        first_entry = self.store.data[self.edge]["1"]
        self.store.data[self.edge]["1"] = ("changed.example", 1)
        self.assertTrue(self.apply(["roblox.com", "poki.com"])["ok"])
        self.assertIn(first_entry, self.store.data[self.edge].values())
        self.assertTrue(self.apply(remove=True)["ok"])
        self.assertEqual(self.store.data[self.edge], {"1": ("changed.example", 1), "999": ("institution.example", 1)})
        self.assertNotIn(self.firefox, self.store.data)

    def test_identical_external_entries_not_claimed(self):
        self.store.data[self.edge] = {"1": ("roblox.com", 1)}
        self.assertTrue(self.apply(["roblox.com"])["ok"])
        self.assertTrue(self.apply(remove=True)["ok"])
        self.assertEqual(self.store.data[self.edge]["1"], ("roblox.com", 1))

    def test_strict_installs_exceptions_first_and_undo_removes_global_first(self):
        self.assertTrue(self.apply(["roblox.com"], ["school.example"], True)["ok"])
        ops = self.store.operations
        self.assertLess(ops.index(("add", self.allow, "school.example")), ops.index(("add", self.edge, "*")))
        self.assertTrue(self.apply(remove=True)["ok"])
        self.assertLess(ops.index(("remove", self.edge, "*")), ops.index(("remove", self.allow, "school.example")))
        self.assertTrue(self.apply(remove=True)["ok"])

    def test_denied_allowlist_policy_never_enables_global_block(self):
        self.store.data[self.allow] = {str(i): (str(i)+".existing", 1) for i in range(1, 1001)}
        self.assertFalse(self.apply(allow=["moodle.example"], strict=True)["ok"])
        self.assertNotIn(self.edge, self.store.data)

    def test_existing_external_exceptions_reported(self):
        self.store.data[self.allow] = {"1": ("*", 1)}
        self.assertIn("Edge:", self.apply(["roblox.com"])["warnings"][0])
        self.assertEqual(self.store.data[self.allow], {"1": ("*", 1)})

    def test_strict_with_external_allowed_urls_reports_partial(self):
        self.store.data[self.allow] = {"1": ("*", 1)}
        result = self.apply(allow=["school.example"], strict=True)
        self.assertFalse(result["ok"])
        self.assertFalse(result["browsers"]["Edge"]["ok"])
        self.assertEqual(self.store.data[self.allow]["1"], ("*", 1))

    def test_firefox_policy_order_when_switching_modes(self):
        self.assertTrue(self.apply(["poki.com", "roblox.com"])["ok"])
        self.assertTrue(self.apply(allow=["school.example"], strict=True)["ok"])
        self.assertEqual(list(self.store.data[self.firefox].items()), [("1", ("<all_urls>", 1))])
        self.assertTrue(self.apply(["roblox.com"])["ok"])
        self.assertEqual(list(self.store.data[self.firefox].items()), [("1", ("*://*.roblox.com/*", 1))])
        self.assertTrue(self.apply(remove=True)["ok"])

    def test_foreign_replacement_during_active_protection_retained(self):
        self.assertTrue(self.apply(["roblox.com"])["ok"])
        self.store.data[self.firefox]["2"] = ("*://*.school.example/*", 1)
        self.assertTrue(self.apply(remove=True)["ok"])
        self.assertEqual(set(self.store.data[self.firefox].values()), {("*://*.school.example/*", 1)})
        self.assertEqual(next(iter(self.store.data[self.firefox])), "1")

    def test_fake_crash_after_journaling_before_set(self):
        original = self.store.add_if_free
        calls = []
        def fail(path, slot, value):
            calls.append(value)
            if len(calls) == 1:
                self.assertEqual(self.last["sites"]["Edge"]["block"]["owned"][slot], value)
                raise KeyboardInterrupt()
            original(path, slot, value)
        self.store.add_if_free = fail
        with self.assertRaises(KeyboardInterrupt):
            self.apply(["roblox.com"])
        self.state = self.last
        self.assertTrue(self.apply(["roblox.com"])["ok"])
        self.assertTrue(self.apply(remove=True)["ok"])
        self.assertEqual(self.store.data, {})

    def test_empty_strict_or_injected_url_rejected_before_mutations(self):
        for domains, allowed, strict in (([], [], True), (["rbx.com/evil"], [], False),
                                        (["*"], [], False), (["*.poki.com"], [], False)):
            with self.assertRaises(ValueError):
                self.apply(domains, allowed, strict)
            self.assertFalse(self.store.operations)

if __name__ == "__main__":
    unittest.main()
