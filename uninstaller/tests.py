"""Unit tests are safe anywhere. Native component fixtures run only in GitHub CI."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'build-source'))
sys.path.insert(0,str(HERE))
import main as app
import _vendor_labguard_cliente as old

class Registry:
    string_type=1
    def __init__(self,rows):self.rows=rows
    def inspect(self,path):return path in self.rows,dict(self.rows.get(path,{}))
    def remove_if_same(self,path,slot,value):
        if self.rows.get(path,{}).get(slot)==(value,1):del self.rows[path][slot]
    def replace_if_same(self,path,slot,oldvalue,newvalue):
        if self.rows.get(path,{}).get(slot)==(oldvalue,1):self.rows[path][slot]=(newvalue,1)
    def remove_if_empty(self,path):
        if not self.rows.get(path):self.rows.pop(path,None)
    def add_if_free(self,path,slot,value):
        self.rows.setdefault(path,{})
        if slot not in self.rows[path]:self.rows[path][slot]=(value,1)

class RemovalTests(unittest.TestCase):
    def test_bundled_self_test(self):self.assertIn('PASS',app.self_test())
    def test_all_browsers_preserve_other_admin(self):
        rows={};state={'sites':{}}
        for name,(base,block,allow) in old._BROWSER_POLICIES.items():
            rows[base+'\\'+block]={'1':('youtube.com',1),'2':('external.school',1),'3':('changed-by-other-admin',1)}
            state['sites'][name]={'block':{'owned':{'1':'youtube.com','3':'original-game.com'}},'allow':{'owned':{}}}
        registry=Registry(rows)
        result=old._browser_policy_run({},state,lambda:None,registry,removing=True)
        self.assertTrue(result['ok'])
        for name,(base,block,allow) in old._BROWSER_POLICIES.items():
            remaining=registry.rows[base+'\\'+block]
            self.assertIn(('external.school',1),remaining.values())
            self.assertIn(('changed-by-other-admin',1),remaining.values())
            self.assertNotIn(('youtube.com',1),remaining.values())
            if name=='Firefox':self.assertIn('1',remaining)
    def test_repeated_youtube_uninstall(self):
        raw=b'127.0.0.1 localhost\n# BEGIN LABGUARD JOGOS YOUTUBE\n0.0.0.0 youtube.com\n# END LABGUARD JOGOS YOUTUBE\n'
        once=app.strip_youtube_hosts(raw)
        self.assertEqual(once,app.strip_youtube_hosts(once))
    def test_incomplete_markers(self):
        with self.assertRaises(ValueError):app.strip_youtube_hosts(b'# BEGIN LABGUARD JOGOS YOUTUBE\n0.0.0.0 youtube.com\n')
    def test_utf16_refused(self):
        with self.assertRaises(ValueError):app.strip_youtube_hosts('127.0.0.1 localhost'.encode('utf-16'))
    def test_scope(self):
        self.assertFalse(app.within(r'C:\Apps\LabGuardOther\x.exe',r'C:\Apps\LabGuard'))
        self.assertFalse(app.within(r'C:\Apps\LabGuard\..\Work\x.txt',r'C:\Apps\LabGuard'))
    def test_root_not_filesystem(self):
        with self.assertRaises(ValueError):app.safe_delete(Path('/'),Path('/'))
    def test_synthetic_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            top=Path(temp);root=top/'LabGuard';root.mkdir();safe=top/'school';safe.mkdir();(safe/'homework.txt').write_text('keep')
            try:(root/'outside').symlink_to(safe,target_is_directory=True)
            except (OSError,NotImplementedError):self.skipTest('symlink privilege unavailable')
            with self.assertRaises(ValueError):app.safe_delete(root,root)
            self.assertEqual((safe/'homework.txt').read_text(),'keep')

if __name__=='__main__':unittest.main(verbosity=2)
