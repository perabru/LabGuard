import base64
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from labguard import access_push
from labguard.remote import RemoteError


TARGET='192.168.15.20'
ASSETS=Path(__file__).resolve().parents[1] / 'server' / 'assets'
PAYLOAD={'host':TARGET,'hostname':'pc20.school.example','user':'CAMPUS\\admin','password':'private-fixture-value','confirm':True}
SNAPSHOT={'source_type':'local_dns','mode':'equipment','dns_service':{'listen':'192.168.15.7','network':'192.168.15.0/24','port':53,'service_running':True,'check_token':'LabGuard-'+'a'*16},
          'local':{'interfaces_read':True,'routes_read':True,'interface_ips':['192.168.15.7'],'default_gateway':'192.168.15.1'},'devices':[{'ip':TARGET}]}


class TestDCOMPush(unittest.TestCase):
    def test_rejects_arbitrary_script_unconfirmed_target_and_injection(self):
        for change in ({'confirm':False}, {'script':'whoami'}, {'host':'192.168.15.1'}, {'hostname':'pc20.school.example; whoami'}, {'user':'Administrator'}):
            with self.subTest(change=change),patch.object(access_push,'run_bounded') as run:
                with self.assertRaises(RemoteError):access_push.prepare_remote_access(SNAPSHOT,dict(PAYLOAD,**change),ASSETS)
                run.assert_not_called()

    def test_fixed_script_uses_sealed_kerberos_and_verifies_https(self):
        script=access_push._PUSH
        for fragment in ("Authority=\"Kerberos:$accountDomain\\$short\"","Authentication='PacketPrivacy'",'PartOfDomain','DNSHostName','IPAddress','Test-WSMan','-UseSSL'):
            self.assertIn(fragment,script)
        self.assertNotIn('SkipCACheck',script);self.assertNotIn('SkipCNCheck',script)
        job=base64.b64decode(access_push._remote_job('Write-Output ok',SimpleNamespace(listen='192.168.15.7',address=TARGET),'a'*32)).decode('utf-16le')
        self.assertIn('Find-NetRoute',job);self.assertIn(TARGET,job);self.assertNotIn(PAYLOAD['password'],job)

    def test_only_success_on_authenticated_https_stage(self):
        result=Mock(returncode=0,stdout='{"stage":"ready"}')
        fake_os=SimpleNamespace(name='nt',environ={'SystemRoot':'C:\\Windows'})
        with patch.object(access_push,'os',fake_os),patch.object(access_push,'_powershell_path',return_value=r'C:\Windows\System32\powershell.exe'),patch.object(access_push,'run_bounded',return_value=result) as run:
            self.assertTrue(access_push.prepare_remote_access(SNAPSHOT,PAYLOAD,ASSETS)['ok'])
            self.assertNotIn(PAYLOAD['password'],str(run.call_args.args));data=json.loads(run.call_args.kwargs['input'])
            self.assertEqual(data['password'],PAYLOAD['password']);self.assertEqual(data['hostname'],PAYLOAD['hostname'])
            generated=base64.b64decode(data['encoded']).decode('utf-16le');self.assertNotIn('__MANAGEMENT_IPV4__',generated);self.assertIn('192.168.15.7',generated)
            for stage in ('identity','submitted','bootstrap','https'):
                result.stdout=json.dumps({'stage':stage});out=access_push.prepare_remote_access(SNAPSHOT,PAYLOAD,ASSETS)
                self.assertFalse(out['ok']);self.assertNotIn(PAYLOAD['password'],out['message'])

    def test_linux_gives_central_alternative(self):
        with patch.object(access_push,'os',SimpleNamespace(name='posix')),patch.object(access_push,'run_bounded') as run:
            with self.assertRaisesRegex(RemoteError,'GPO'):access_push.prepare_remote_access(SNAPSHOT,PAYLOAD,ASSETS)
            run.assert_not_called()
