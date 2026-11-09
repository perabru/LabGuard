"""Offline tests for the station catalog, with isolated SQLite databases."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from contextlib import closing
import sqlite3
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

try:
    import labguard_cliente as client
except ImportError:
    client = types.ModuleType('catalog_local_test')
    parts = Path(__file__).resolve().parent
    for file in ('header.part.py', 'catalog.part.py'):
        src = parts / file
        exec(compile(src.read_text(encoding='utf8'), str(src), 'exec'), client.__dict__)

SEED = (('test-games.example','jogos','escola'), ('beta.example','roblox','escola'),
        ('minecraft.example','minecraft','escola'), ('ai.example','ia','escola'))


class ClientCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'banco.sqlite3'
        self.catalog = client.ClientCatalog(self.path, seed_rows=SEED, seed_version='s1')
        self.catalog.ensure()

    def test_idempotent_persistent_read_only_search_and_index(self):
        a = self.catalog
        old = a.revision()
        self.assertEqual(a.ensure(), old)
        self.assertEqual(len(a.categories()), 7)
        self.assertEqual(len(a.effective()), len(SEED))
        self.assertEqual(a.effective_snapshot(), (old, a.effective()))
        self.assertEqual(a.search('BETA')[0]['category'], 'roblox')
        self.assertEqual(a.search('%'), [])
        self.assertEqual(len(a.search(limit=2, offset=2)), 2)
        self.assertEqual(a.search(category='roblox')[0]['source'], 'escola')
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute('pragma user_version').fetchone()[0], 1)
            self.assertTrue(db.execute("pragma index_list('domains')").fetchall())
        self.assertFalse(self.path.with_name('banco.sqlite3-wal').exists())

    def test_seed_upgrade_preserves_manual_addition_rename_delete_and_category(self):
        a = self.catalog
        a.put('suporte.example','outros')
        a.put('nuvem.example','ia',False,original='ai.example')
        a.put('beta.example','outros',False,original='beta.example')
        a.delete('test-games.example')
        a.set_category('minecraft',False)
        expanded = (*SEED,('new.example','minecraft','nova fonte'))
        b = client.ClientCatalog(self.path,seed_rows=expanded,seed_version='s2')
        b.ensure()
        self.assertEqual(b.effective(), ['suporte.example'])
        self.assertEqual(b.search('test-games.example'), [])
        self.assertEqual(b.search('ai.example'), [])
        self.assertFalse(b.search('beta.example')[0]['enabled'])
        self.assertEqual(b.search('beta.example')[0]['category'], 'outros')
        self.assertEqual(b.search('nuvem.example')[0]['source'], 'TI')
        b.set_category('minecraft',True)
        self.assertIn('new.example',b.effective())
        # Explicitly restoring a tombstoned domain works without duplicates.
        b.put('ai.example','ia')
        self.assertEqual(len(b.search('ai.example')),1)

    def test_seed_reclassification_respects_overrides_and_removes_retired_items(self):
        self.catalog.put('beta.example','ia',original='beta.example')
        newer=(('test-games.example','apostas','versão 2'), ('beta.example','adultos','origem atual'))
        second = client.ClientCatalog(self.path,seed_rows=newer,seed_version='s2')
        second.ensure()
        self.assertEqual(second.search('beta')[0]['category'],'ia')
        built = second.search('test-games')[0]
        self.assertEqual((built['category'],built['source']), ('apostas','versão 2'))
        self.assertEqual(second.search('minecraft'), [])

    def test_import_normalization_duplicates_and_atomicity(self):
        a=self.catalog
        rev=a.revision()
        text='\ufeffdominio;categoria;ativo\n NOVO.EXAMPLE ;IA;sim\nbeta.example;roblox;0\nai.example;ia;1\n'
        p=a.preview_import(text,extra_domains=['manual.example'])
        self.assertEqual((p['added'],p['updated'],p['unchanged'],p['total'],p['active']), (1,1,1,3,5))
        self.assertEqual(a.revision(),rev)
        result=a.import_csv(text,expected_revision=p['revision'],extra_domains=['manual.example'])
        self.assertEqual(result['revision'],rev+1)
        self.assertEqual(a.search('novo.example')[0]['source'],'CSV')
        self.assertFalse(a.search('beta.example')[0]['enabled'])
        self.assertNotIn('novo.example;ia;',a.export_csv())
        self.assertIn('novo.example,ia,1',a.export_csv())
        self.assertEqual(a.preview_import(a.export_csv())['unchanged'],5)
        for bad in ('novo.example,ia,sim\nNOVO.EXAMPLE.,ia,sim','bad/link,ia,1',
                    '=CMD.example,ia,1','novo.example,unknown,1','n.example,ia,talvez',
                    'n.example,ia,false,extra','"unclosed.example,ia,1'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                a.import_csv('dominio,categoria,ativo\n'+bad,expected_revision=a.revision())
        self.assertEqual(a.revision(),rev+1)

    def test_preview_conflict_never_overwrites(self):
        a=self.catalog
        data='dominio,categoria,ativo\nbeta.example,outros,0'
        preview=a.preview_import(data)
        a.put('novo.example','ia')
        with self.assertRaisesRegex(ValueError,'desde a prévia'):
            a.import_csv(data,expected_revision=preview['revision'])
        self.assertTrue(a.search('beta')[0]['enabled'])

    def test_duplicate_rename_invalid_and_budget_rollback(self):
        a=self.catalog
        with self.assertRaises(ValueError):a.put('AI.EXAMPLE.','ia')
        with self.assertRaises(ValueError):a.put('beta.example','ia',original='ai.example')
        with self.assertRaises(ValueError):a.delete('missing.example')
        with self.assertRaises(ValueError):a.put('bad/path','jogos')
        rev=a.revision()
        filler=[f'e{i}.example' for i in range(client.CATALOG_ACTIVE_LIMIT-len(SEED))]
        self.assertEqual(len(a.effective(filler + ['AI.EXAMPLE'])),client.CATALOG_ACTIVE_LIMIT)
        with self.assertRaisesRegex(ValueError,'limite'):
            a.put('one-more.example','outros',extra_domains=filler)
        self.assertEqual(a.revision(),rev)
        a.set_category('ia',False)
        a.put('one-more.example','outros',extra_domains=filler)
        rev=a.revision()
        with self.assertRaisesRegex(ValueError,'limite'):
            a.set_category('ia',True,extra_domains=filler)
        self.assertEqual(a.revision(),rev)
        self.assertFalse(a.search('ai.example')[0]['effective'])

    def test_seed_invalid_or_too_large_keeps_previous_db(self):
        for incompatible in ((('bad/path','jogos','seed'),), (('x.example','ia','orig'),('X.EXAMPLE','jogos','seed')),
                             tuple((f'x{i}.example','ia','local') for i in range(client.CATALOG_ACTIVE_LIMIT+1))):
            b=client.ClientCatalog(self.path,seed_rows=incompatible,seed_version='broken')
            with self.assertRaises(ValueError):b.ensure()
            self.assertEqual(len(self.catalog.effective()),len(SEED))
            self.assertEqual(self.catalog.revision(),1)

    def test_concurrent_writers_and_stale_preview(self):
        a=self.catalog
        csv='dominio,categoria,ativo\nx.example,ia,1'
        version=a.preview_import(csv)['revision']
        barrier=threading.Barrier(2)
        def submit():
            barrier.wait(5)
            try:return a.import_csv(csv,expected_revision=version)['revision']
            except ValueError:return 'stale'
        with ThreadPoolExecutor(2) as ex:
            results=[ex.submit(submit),ex.submit(submit)]
            self.assertCountEqual([x.result() for x in results],[version+1,'stale'])
        self.assertEqual(len(a.search('x.example')),1)

    def test_notice_updates_on_same_dataset_without_resetting_policy(self):
        a=self.catalog
        a.set_category('ia',False)
        rev=a.revision()
        with patch.object(client, 'CLIENT_CATALOG_NOTICE', 'Source X\nMIT\nText of MIT license', create=True):
            b=client.ClientCatalog(self.path,seed_rows=SEED,seed_version='s1')
            self.assertEqual(b.ensure(), rev)
            self.assertEqual(b.notices()['distribuicao'], 'Source X\nMIT\nText of MIT license')
            self.assertFalse(b.search('ai.example')[0]['effective'])
        # Exported single SQLite DB includes the full license even offline.
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM catalog_notices').fetchone()[0], 1)

    def test_unknown_db_does_not_get_modified(self):
        path=Path(self.tmp.name)/'else.sqlite3'
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE private_data(item TEXT)')
        data=path.read_bytes()
        with self.assertRaises(ValueError):
            client.ClientCatalog(path, seed_rows=SEED, seed_version='s1').ensure()
        self.assertEqual(data,path.read_bytes())


if __name__=='__main__':
    unittest.main()
