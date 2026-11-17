"""Offline checks: no network requests and no credentials required."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock
import verify_release_assets as gate

class ReleaseAssetGateTests(unittest.TestCase):
    def test_extracts_and_deduplicates_release_downloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'index.html').write_text('<a href="https://github.com/perabru/LabGuard/releases/download/ti-v2.4.6/Setup.exe">A</a><a href="https://github.com/perabru/LabGuard/releases/download/ti-v2.4.6/Setup.exe">B</a><a href="https://github.com/perabru/LabGuard/releases/tag/ti-v2.4.6">notes</a><a href="manual/">manual</a>')
            self.assertEqual(gate.release_assets(Path(tmp)), {('perabru','LabGuard','ti-v2.4.6'):{'Setup.exe'}})

    def test_missing_draft_and_empty_asset_block_publication(self):
        required = {('owner','repo','tag'):{'Setup.exe'}}
        for response in (None, {'draft':True, 'assets':[]},
                         {'assets':[{'name':'Setup.exe','state':'uploaded','size':0}]},
                         {'assets':[{'name':'Setup.exe','state':'open','size':10}]}):
            with self.subTest(response=response):
                self.assertEqual(len(gate.missing_assets(required, Mock(return_value=response))),1)

    def test_waits_for_release_then_passes(self):
        required = {('owner','repo','tag'):{'Setup.exe'}}
        fetch = Mock(side_effect=[None, {'assets':[{'name':'Setup.exe','state':'uploaded','size':10}]}])
        sleeper = Mock()
        self.assertTrue(gate.wait_for_assets(required, 1200, fetch=fetch,
                         clock=Mock(side_effect=[0, 2]), sleep=sleeper, emit=Mock()))
        sleeper.assert_called_once_with(30)
        self.assertEqual(fetch.call_count,2)

    def test_deadline_leaves_publication_blocked(self):
        sleeper = Mock()
        self.assertFalse(gate.wait_for_assets({('owner','repo','tag'):{'Setup.exe'}},
                          0, fetch=Mock(return_value=None),
                          clock=Mock(side_effect=[1,1]), sleep=sleeper, emit=Mock()))
        sleeper.assert_not_called()

if __name__ == '__main__':
    unittest.main()
