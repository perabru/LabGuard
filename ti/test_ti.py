from pathlib import Path
import sys,tempfile,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ti.app import App,NetworkApp,append_quick_sites,QUICK_SITES
from ti.bridge import panel_url,health

class AdditiveTests(unittest.TestCase):
    def test_original_methods_all_inherited(self):
        for name,method in vars(NetworkApp).items():
            if callable(method) and name!='_build':
                self.assertIs(getattr(App,name),getattr(NetworkApp,name),name)
    def test_original_views_are_constructed_first(self):
        import inspect
        self.assertIn('super()._build()',inspect.getsource(App._build))
    def test_bridge_is_loopback_only(self):
        self.assertEqual(panel_url(8787),'http://127.0.0.1:8787/')
        for bad in (0,53,65536,True,'8787','https://example.com'):
            with self.assertRaises(ValueError):panel_url(bad)
    def test_failed_central_is_not_dns_failure(self):
        with patch('ti.bridge.build_opener',side_effect=OSError('offline')):
            self.assertFalse(health()['ready'])
    def test_append_not_replace(self):
        from labguard.demo import DemoTransport
        from labguard.banlist import BanlistDatabase
        from labguard.site_controls import apply_site_change
        transport=DemoTransport()
        with tempfile.TemporaryDirectory() as tmp:
            db=BanlistDatabase(Path(tmp)/'rules.sqlite3')
            try:
                apply_site_change(transport,db,domain='keep.school.example',category='Outros',blocked=True)
                before=transport.request('snapshot');old={r['domain'] for r in before['domains']}
                one=append_quick_sites(transport,db);self.assertFalse(one['errors'])
                after={r['domain'] for r in one['snapshot']['domains']}
                self.assertTrue(old<=after);self.assertTrue({s[0] for s in QUICK_SITES}<=after)
                two=append_quick_sites(transport,db);self.assertFalse(two['errors'])
                self.assertEqual(after,{r['domain'] for r in two['snapshot']['domains']})
            finally:db.close()
    def test_no_mutations_on_import(self):
        import ti.bridge as bridge
        self.assertNotIn('install',bridge.health.__code__.co_names)

if __name__=='__main__':unittest.main(verbosity=2)
