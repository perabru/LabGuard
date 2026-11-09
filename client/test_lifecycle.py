"""Protect previously owned tasks, unrelated files, and recovery after interrupted removal."""
import contextlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import labguard_cliente as client
except ImportError:
    spec = importlib.util.spec_from_file_location('lg_lifecycle',Path(__file__).with_name('lifecycle.part.py'))
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    client.CLIENT_VERSION = '1.1.0'


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir=Path(temp.name)/'Program Files'/'LabGuardCliente'
        self.dir.mkdir(parents=True)
        self.record={'owner':'LabGuardCliente/1','mode':'exe','copy':'LabGuardCliente.exe',
                     'command':str(self.dir/'LabGuardCliente.exe'),'user_command':str(self.dir/'LabGuardCliente.exe')}
        (self.dir/'instalacao.json').write_text(json.dumps(self.record),encoding='utf8')
        (self.dir/'estado.json').write_text('{}',encoding='utf8')

    def test_task_is_named_boot_noninteractive_and_restartable(self):
        xml=client._lc_task_xml(self.dir,self.record)
        task=ET.fromstring(xml)
        ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        for expr,expected in [('t:Triggers/t:BootTrigger/t:Enabled','true'),
                              ('t:Principals/t:Principal/t:UserId','S-1-5-18'),
                              ('t:Settings/t:Hidden','false'),('t:Settings/t:ExecutionTimeLimit','PT0S'),
                              ('t:Actions/t:Exec/t:Arguments','worker')]:
            self.assertEqual(task.findtext(expr,'',ns),expected)
        client._lc_owned_task({'xml':xml},self.dir,self.record)
        with self.assertRaisesRegex(RuntimeError,'outra tarefa'):
            client._lc_owned_task({'xml':xml.decode('utf-16').replace('worker','untrusted')},self.dir,self.record)

    def test_user_mode_and_python_runtime_are_separate_from_system_job(self):
        py=dict(self.record,mode='py',user_command=str(self.dir.parent/'Python'/'pythonw.exe'))
        args=client._lc_arguments(self.dir,py,'worker')
        self.assertTrue(args.startswith('-I -S -B '))
        self.assertTrue(args.endswith(' worker'))
        user_command=client._lc_run_string(self.dir,py)
        self.assertIn('pythonw.exe',user_command)
        self.assertTrue(user_command.endswith(' usuario'))
        self.assertNotIn('worker',user_command)

    def fake_windows(self):
        stack=contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name,val in [('require_client_admin',None),('_lc_deployment_lock',contextlib.nullcontext()),
                         ('client_directory',self.dir),('_lc_task',None),('_lc_load',self.record),
                         ('_lc_user_start',None),('_lc_guard_file',None)]:
            stack.enter_context(patch.object(client,name,return_value=val))

    def test_failed_undo_preserves_recovery_record_and_state(self):
        self.fake_windows()
        def fail(directory):
            raise RuntimeError('política externa')
        with self.assertRaisesRegex(RuntimeError,'externa'):
            client.uninstall_client(fail)
        for n in ('estado.json','parar.flag','instalacao.json'):
            self.assertTrue((self.dir/n).is_file())

    def test_uninstall_leaves_unknown_files(self):
        self.fake_windows()
        note=self.dir/'nota-do-administrador.txt'
        note.write_text('registro da TI',encoding='utf8')
        result=client.uninstall_client(lambda d: None)
        self.assertFalse(result['installed'])
        self.assertEqual(result['files_preserved'],1)
        self.assertEqual([p.name for p in self.dir.iterdir()],[note.name])
        self.assertEqual(note.read_text(encoding='utf8'),'registro da TI')

    def test_foreign_task_is_never_removed(self):
        self.fake_windows()
        task={'xml':client._lc_task_xml(self.dir,self.record).decode('utf-16').replace('worker','foreign')}
        with patch.object(client,'_lc_task',return_value=task), patch.object(client,'_lc_schtasks') as sch:
            with self.assertRaisesRegex(RuntimeError,'outra tarefa'):
                client.uninstall_client(lambda d:self.fail('undo must not run'))
        sch.assert_not_called()
        self.assertFalse((self.dir/'parar.flag').exists())

    def test_uninstall_known_sqlite_files_only(self):
        self.fake_windows()
        names={'banco.sqlite3','banco.sqlite3-journal','banco.sqlite3-wal','banco.sqlite3-shm'}
        for name in names | {'outra.sqlite3'}:
            (self.dir/name).write_bytes(b'fixture')
        client.uninstall_client(lambda d: None)
        self.assertTrue((self.dir/'outra.sqlite3').exists())
        self.assertFalse(any((self.dir/name).exists() for name in names))

    def test_interrupted_upgrade_restores_only_a_matching_owned_copy(self):
        live=self.dir/self.record['copy']
        backup=self.dir/client._LC_PREVIOUS
        backup.write_bytes(b'valid old')
        self.record['sha256']=client._lc_sha(backup)
        live.write_bytes(b'new')
        with self.assertRaisesRegex(RuntimeError,'integridade'):
            client._lc_recover_copy(self.dir,self.record)
        (self.dir/'parar.flag').write_text('TI')
        backup.write_bytes(b'wrong')
        with self.assertRaisesRegex(RuntimeError,'integridade'):
            client._lc_recover_copy(self.dir,self.record)
        backup.write_bytes(b'valid old')
        client._lc_recover_copy(self.dir,self.record)
        self.assertEqual(live.read_bytes(),b'valid old')

    def upgrade_fixture(self):
        from types import SimpleNamespace
        self.fake_windows()
        dest=self.dir/self.record['copy']
        dest.write_bytes(b'old running binary')
        self.record['sha256']=client._lc_sha(dest)
        (self.dir/'instalacao.json').write_text(json.dumps(self.record), encoding='utf8')
        (self.dir/'banco.sqlite3').write_bytes(b'policy-content')
        source=self.dir.parent/'download'
        source.write_bytes(b'new binary')
        stack=contextlib.ExitStack()
        self.addCleanup(stack.close)
        for key,v in [('_lc_secure_chain',None),('_lc_runtime',{k:self.record[k] for k in ('mode','copy','command','user_command')}),
                      ('_lc_executable_source', source),('_lc_schtasks',None)]:
            stack.enter_context(patch.object(client,key,return_value=v))
        stack.enter_context(patch.object(client.ctypes,'windll',SimpleNamespace(kernel32=SimpleNamespace(GetDriveTypeW=lambda d:3)),create=True))
        stack.enter_context(patch.object(client,'_lc_task',return_value={'xml':client._lc_task_xml(self.dir,self.record),'state':3}))
        return source,dest

    def test_update_preserves_database_and_starts_from_same_task(self):
        source,dest=self.upgrade_fixture()
        response=client.install_client(lambda d:self.assertEqual((d/'banco.sqlite3').read_bytes(),b'policy-content'))
        self.assertTrue(response['updated'])
        self.assertEqual(dest.read_bytes(),source.read_bytes())
        record=json.loads((self.dir/'instalacao.json').read_text(encoding='utf8'))
        self.assertEqual(record['sha256'],client._lc_sha(dest))
        self.assertFalse((self.dir/client._LC_PREVIOUS).exists())
        self.assertFalse((self.dir/'parar.flag').exists())

    def test_failed_update_restores_previous_copy_and_restart(self):
        source,dest=self.upgrade_fixture()
        previous=dest.read_bytes()
        def fail(d):
            raise ValueError('conflito de política')
        with self.assertRaisesRegex(ValueError,'conflito'):
            client.install_client(fail)
        self.assertEqual(dest.read_bytes(),previous)
        self.assertEqual((self.dir/'banco.sqlite3').read_bytes(),b'policy-content')
        self.assertFalse((self.dir/'parar.flag').exists())
        self.assertIn(('/Run','/TN',client._LC_NAME),[call.args for call in client._lc_schtasks.call_args_list])

    def test_explicit_activation_recovers_disabled_owned_task(self):
        self.upgrade_fixture()
        task={'xml':client._lc_task_xml(self.dir,self.record),'state':1}
        with patch.object(client,'_lc_task',return_value=task):
            client.install_client(lambda d:None)
        actions=[c.args for c in client._lc_schtasks.call_args_list]
        self.assertIn(('/Change','/TN',client._LC_NAME,'/ENABLE'),actions)
        self.assertEqual(actions[-1],('/Run','/TN',client._LC_NAME))
