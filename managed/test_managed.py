"""Tests for auth, event deduplication, bounded retention and scoped policies."""
from pathlib import Path
import sys, tempfile, unittest, secrets, json, http.client, ssl, threading
ROOT=Path(__file__).resolve().parents[1]
for d in (ROOT,ROOT/'central',ROOT/'client',ROOT/'managed'):sys.path.insert(0,str(d))
import labguard_central as core
from alerts import ManagedStore, install, _BASE_STORE

class ManagedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.now=2000000000.0
        self.path=Path(self.tmp.name)/'central.sqlite3'
        self.store=ManagedStore(self.path,clock=lambda:self.now);self.store.ensure(seed_rows=[])
        code,_=self.store.issue_enrollment();self.d=self.store.enroll(code,'LAB-01','Jogos-2.2.0')
    def tearDown(self):self.tmp.cleanup()
    def report(self):
        return dict(device_id=self.d['device_id'],name='LAB-01',client_version='Jogos-2.2.0',guard='active',cleanup='ok',youtube='blocked',applied_revision=1,events=[dict(id=secrets.token_hex(16),kind='game_closed',time='2026-11-12T18:00:00Z',process='RobloxPlayerBeta')])
    def test_deduplication(self):
        body=self.report()
        for _ in range(3):self.store.telemetry(self.d['device_token'],body)
        state=self.store.state();self.assertEqual(sum(a['kind']=='game_closed' for a in state['alerts']),1)
        self.assertEqual(state['devices'][0]['status'],'online')
    def test_unauthorized_and_revocation(self):
        with self.assertRaises(core.AuthenticationError):self.store.telemetry(secrets.token_urlsafe(32),self.report())
        self.store.revoke_device(self.d['device_id'])
        with self.assertRaises(core.AuthenticationError):self.store.telemetry(self.d['device_token'],self.report())
    def test_cannot_spoof_other_station(self):
        code,_=self.store.issue_enrollment();other=self.store.enroll(code,'LAB-02','2.2')
        body=self.report();body['device_id']=other['device_id']
        with self.assertRaises(core.AuthenticationError):self.store.telemetry(self.d['device_token'],body)
    def test_no_path_screenshot_or_arbitrary_command(self):
        for patch in ({'screenshot':'base64'},{'command':'whoami'}):
            body=self.report();body.update(patch)
            with self.assertRaises(core.CentralError):self.store.telemetry(self.d['device_token'],body)
        body=self.report();body['events'][0]['process']='C:\\Users\\Aluno\\game.exe'
        with self.assertRaises(core.CentralError):self.store.telemetry(self.d['device_token'],body)
    def test_bounded_batches(self):
        body=self.report();body['events']*=26
        with self.assertRaises(core.CentralError):self.store.telemetry(self.d['device_token'],body)
    def test_offline_and_return_once(self):
        self.store.telemetry(self.d['device_token'],self.report());self.now+=91
        for _ in range(3):state=self.store.state()
        self.assertEqual(state['devices'][0]['status'],'offline');self.assertEqual(sum(a['kind']=='offline' for a in state['alerts']),1)
        self.store.telemetry(self.d['device_token'],self.report());state=self.store.state()
        self.assertEqual(state['devices'][0]['status'],'online');self.assertEqual(sum(a['kind']=='online' for a in state['alerts']),2)
    def test_read_does_not_ack_later_events(self):
        self.store.telemetry(self.d['device_token'],self.report());through=self.store.state()['alerts'][0]['id']
        self.store.telemetry(self.d['device_token'],self.report());self.store.acknowledge(through)
        self.assertEqual(self.store.state()['unread_alerts'],1)
    def test_policy_revision_conflicts_and_bool_validation(self):
        self.store.set_managed_policy(dict(expected_revision=1,cleanup_enabled=True,close_games=True,block_youtube=False))
        with self.assertRaises(core.ConflictError):self.store.set_managed_policy(dict(expected_revision=1,cleanup_enabled=True,close_games=True,block_youtube=True))
        with self.assertRaises(core.CentralError):self.store.set_managed_policy(dict(expected_revision=2,cleanup_enabled='true',close_games=True,block_youtube=True))
        state=self.store.state();self.assertEqual(state['managed_policy']['revision'],2)
    def test_legacy_protocol_and_migration(self):
        second=Path(self.tmp.name)/'legacy.sqlite3';legacy=_BASE_STORE(second,clock=lambda:self.now);legacy.ensure(seed_rows=[('school.example','outros','teste')])
        managed=ManagedStore(second,clock=lambda:self.now);managed.ensure()
        self.assertEqual(managed.snapshot()['site_policy']['domains'],['school.example'])
        self.assertTrue(managed.state()['managed_policy']['close_games'])
    def test_retention(self):
        self.store.telemetry(self.d['device_token'],self.report());self.now+=8*86400
        self.assertFalse(any(a['kind']=='game_closed' for a in self.store.state()['alerts']))

class HTTPTests(unittest.TestCase):
    def setUp(self):
        import socket
        def port():
            with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
        self.tmp=tempfile.TemporaryDirectory();self.dir=Path(self.tmp.name)
        install();self.panel_port,self.agent_port=port(),port()
        core.initialize(self.dir,'Test password 1234567','127.0.0.1','127.0.0.0/8',self.agent_port,self.panel_port)
        self.panel,self.agent=core.build_servers(self.dir,assets_dir=ROOT/'managed/build/assets')
        for s in (self.panel,self.agent):threading.Thread(target=s.serve_forever,daemon=True).start()
    def tearDown(self):
        for s in (self.panel,self.agent):s.shutdown();s.server_close()
        self.tmp.cleanup()
    def call(self,path,body,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.panel_port,timeout=10)
        h={'Content-Type':'application/json','Origin':f'http://127.0.0.1:{self.panel_port}'};h.update(headers or {})
        c.request('POST',path,json.dumps(body),h);r=c.getresponse();data=json.loads(r.read());status=r.status;cookie=r.getheader('Set-Cookie');c.close();return status,data,cookie
    def test_policy_and_ack_require_auth_and_csrf(self):
        policy=dict(expected_revision=1,cleanup_enabled=True,close_games=True,block_youtube=False)
        self.assertEqual(self.call('/api/managed-policy',policy)[0],401)
        status,body,cookie=self.call('/api/login',{'password':'Test password 1234567'});self.assertEqual(status,200)
        self.assertEqual(self.call('/api/managed-policy',policy,{'Cookie':cookie})[0],401)
        self.assertEqual(self.call('/api/managed-policy',policy,{'Cookie':cookie,'X-CSRF-Token':body['csrf']})[0],200)
        self.assertEqual(self.call('/api/alerts/ack',{'through':1})[0],401)
    def test_https_enrollment_and_telemetry(self):
        cfg=self.panel.application.enrollment()['config']
        context=ssl.create_default_context(cadata=cfg['ca_pem'])
        def post(path,body,token=None):
            c=http.client.HTTPSConnection('127.0.0.1',self.agent_port,context=context,timeout=10);h={'Content-Type':'application/json'}
            if token:h['Authorization']='Bearer '+token
            c.request('POST',path,json.dumps(body),h);r=c.getresponse();data=json.loads(r.read());status=r.status;c.close();return status,data
        status,d=post('/api/agent/enroll',dict(enrollment_token=cfg['enrollment_token'],name='LAB-TESTE',client_version='Jogos-2.2.0'));self.assertEqual(status,200)
        body=dict(device_id=d['device_id'],name='LAB-TESTE',client_version='Jogos-2.2.0',guard='active',cleanup='ok',youtube='blocked',applied_revision=0,events=[])
        self.assertEqual(post('/api/agent/telemetry',body)[0],401)
        status,reply=post('/api/agent/telemetry',body,d['device_token']);self.assertEqual(status,200);self.assertTrue(reply['policy']['block_youtube'])

if __name__=='__main__':unittest.main(verbosity=2)
