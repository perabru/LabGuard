from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import labguard_cliente as lg


class ClientPolicyTests(unittest.TestCase):
    def test_partial_policy_does_not_request_uninstall(self):
        self.assertFalse(lg.validate_policy({})['remove_roblox'])
        self.assertTrue(lg.default_policy()['remove_roblox'])
        self.assertNotIn('minecraft', lg.default_policy()['remove_games'])
        self.assertEqual(lg.validate_policy({'domains':['*.ROBLOX.com.', 'roblox.com']})['domains'], ['roblox.com'])

    def test_restrictive_mode_requires_explicit_non_conflicting_sites(self):
        for p in ({'mode':'permitidos'}, {'mode':'permitidos','allowed_domains':['roblox.com']},
                  {'domains':['8.8.8.8']}, {'domains':['https://www.test.org']}, {'domains':['*']},
                  {'remove_games':['steam']}, {'remove_roblox':True,'games':[]}):
            with self.subTest(policy=p), self.assertRaises(ValueError):
                lg.validate_policy(p)
        self.assertEqual(lg.validate_policy({'mode':'permitidos','allowed_domains':['aula.example.org']})['mode'],'permitidos')

    def test_reinstall_preserves_original_journal_and_policy(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            def installer(initialize):
                initialize(path)
                return {'installed':True}
            with patch.object(lg, 'require_client_admin'), patch.object(lg, 'install_client', installer), patch.object(lg, '_operation_lock',return_value=nullcontext()):
                lg.perform_install(lg.default_policy())
                lg._atomic_json(path/'estado.json', {'sites':{'existing':'value'}})
                lg.perform_install(lg.default_policy())
                with self.assertRaises(RuntimeError):
                    lg.perform_install({'domains':['test.example']})
                self.assertEqual(lg._json_read(path/'estado.json'),{'sites':{'existing':'value'}})

    def test_ok_requires_a_live_task_and_current_policy(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            (path/'instalacao.json').write_text('{}')
            policy = lg.validate_policy({})
            lg._atomic_json(path/'politica.json',policy)
            status = {'ok':True,'checked_at':lg._utc_now(),'policy_revision':lg._policy_revision(policy)}
            lg._atomic_json(path/'status.json',status)
            task = {'running':True,'user_start':True,'task_registered':True}
            with patch.object(lg,'client_directory', return_value=path), patch.object(lg,'client_task_status', return_value=task):
                self.assertTrue(lg.get_client_status()['ok'])
                task['running']=False
                self.assertFalse(lg.get_client_status()['ok'])
                task['running']=True
                lg._atomic_json(path/'politica.json',lg.validate_policy({'domains':['novo.example']}))
                self.assertFalse(lg.get_client_status()['ok'])
