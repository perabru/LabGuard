import unittest
from labguard.access_setup import prepare_access
from labguard.server import asset_directory


class PreparationTests(unittest.TestCase):
    def test_preparation_is_scoped_to_one_private_management_address(self):
        result = prepare_access({'management_ip': '192.168.15.5'}, asset_directory())
        self.assertEqual(result['name'], 'LabGuard-Preparar-Acesso.ps1')
        self.assertIn("$managementIP = '192.168.15.5'", result['script'])
        self.assertNotIn('__MANAGEMENT_IPV4__', result['script'])

    def test_refuses_script_and_wildcard_input(self):
        for value in ['*','0.0.0.0','127.0.0.1','8.8.8.8','10.0.0.3/8',"10.0.0.3';whoami;#",None,True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare_access({'management_ip':value}, asset_directory())
