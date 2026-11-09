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
