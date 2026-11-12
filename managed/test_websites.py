"""No system policy changes: temporary DBs and local HTTP/TLS only."""
from pathlib import Path
import sys,tempfile,unittest,secrets,threading,http.client,json,socket
R=Path(__file__).resolve().parents[1]
for d in (R/'central',R/'client',R/'managed'):sys.path.insert(0,str(d))
import labguard_central as core
from websites import WebsiteStore,domains,install

class WebsiteTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.now=2000000000.0
  self.store=WebsiteStore(Path(self.tmp.name)/'db.sqlite',clock=lambda:self.now);self.store.ensure(seed_rows=[])
  code,_=self.store.issue_enrollment();self.client=self.store.enroll(code,'LAB-01','Jogos-2.3.0')
 def tearDown(self):self.tmp.cleanup()
 def change(self,key,names,blocked):
  return self.store.change_web(dict(expected_revision=self.store.state()['web_policy']['revision'],id=key,domains=names,blocked=blocked))
 def report(self,rev=1,status='applied'):
  return dict(device_id=self.client['device_id'],name='LAB-01',client_version='Jogos-2.3.0',guard='active',cleanup='ok',youtube='blocked',applied_revision=1,events=[],web_revision=rev,web_status=status)
 def test_seed_and_unknown_address(self):
  s=self.store.state();self.assertEqual(s['web_policy']['blocked_domains'],['chess.com','friv.com','friv.com.br','poki.com','term.ooo'])
  j=next(r for r in s['web_catalog'] if r['id']=='joguester');self.assertFalse(j['blocked']);self.assertEqual(j['domains'],[])
  with self.assertRaises(core.CentralError):self.change('joguester',[],True)
 def test_normalize_and_reject(self):
  self.assertEqual(domains(['https://WWW.CHESS.COM/pt/play','chess.com.']),['chess.com'])
  for d in ['*','com.br','10.0.0.1','localhost','example.local','bad site.com','https://user:pass@example.com','https://example.com:wrong','chrome://settings','*.com']:
   with self.subTest(d=d):
    with self.assertRaises(core.CentralError):domains([d])
 def test_bulk_only_known_sites_and_youtube(self):
  self.store.set_managed_policy(dict(expected_revision=1,cleanup_enabled=False,close_games=False,block_youtube=False))
  self.change('termo',['term.ooo'],False);self.change('chess',['chess.com'],False)
  s=self.store.state();r=self.store.change_web(dict(expected_revision=s['web_policy']['revision']),bulk=True)
  self.assertEqual(r['pending_names'],['Joguester']);s=self.store.state()
  self.assertTrue(s['managed_policy']['block_youtube']);self.assertFalse(s['managed_policy']['close_games']);self.assertFalse(s['managed_policy']['cleanup_enabled'])
  self.assertNotIn('*',s['web_policy']['blocked_domains']);self.assertIn('term.ooo',s['web_policy']['blocked_domains'])
 def test_bulk_idempotency(self):
  before=self.store.state()['web_policy'];self.store.change_web(dict(expected_revision=before['revision']),bulk=True)
  self.assertEqual(before,self.store.state()['web_policy'])
 def test_update_conflict(self):
  self.change('termo',['term.ooo'],False)
  with self.assertRaises(core.ConflictError):self.store.change_web(dict(expected_revision=1),bulk=True)
 def test_custom_pending_domain_and_clear(self):
  self.change('joguester',['game.example'],True)
  self.assertIn('game.example',self.store.state()['web_policy']['blocked_domains'])
  self.change('joguester',[],False)
  j=next(r for r in self.store.state()['web_catalog'] if r['id']=='joguester');self.assertTrue(j['note'])
 def test_preserve_customizations_on_restart(self):
  self.change('friv',['friv.com'],False);self.store.ensure()
  self.assertFalse(next(r for r in self.store.state()['web_catalog'] if r['id']=='friv')['blocked'])
 def test_authenticated_ack_and_new_revision(self):
  r=self.store.web_telemetry(self.client['device_token'],self.report());self.assertEqual(r['web_protocol'],1)
  self.assertTrue(self.store.state()['devices'][0]['web_confirmed'])
  self.change('termo',['term.ooo'],False);self.assertFalse(self.store.state()['devices'][0]['web_confirmed'])
  rev=self.store.state()['web_policy']['revision'];self.store.web_telemetry(self.client['device_token'],self.report(rev,'failed'));self.assertEqual(self.store.state()['devices'][0]['status'],'error')
  self.store.web_telemetry(self.client['device_token'],self.report(rev));self.assertTrue(self.store.state()['devices'][0]['web_confirmed'])
 def test_fake_and_revoked_tokens(self):
  with self.assertRaises(core.AuthenticationError):self.store.web_telemetry(secrets.token_urlsafe(32),self.report())
  self.store.revoke_device(self.client['device_id'])
  with self.assertRaises(core.AuthenticationError):self.store.web_telemetry(self.client['device_token'],self.report())
 def test_old_protocol_is_not_marked_web_confirmed(self):
  report=self.report();report.pop('web_revision');report.pop('web_status');self.store.telemetry(self.client['device_token'],report)
  s=self.store.state()['devices'][0];self.assertIsNone(s['web']);self.assertFalse(s['web_confirmed'])
 def test_migrate_without_erasing_credentials(self):
  report=self.report();self.store.web_telemetry(self.client['device_token'],report);self.store.ensure()
  self.assertTrue(self.store.web_telemetry(self.client['device_token'],report)['ok'])
 def test_reject_invalid_status_and_payload(self):
  for patch in ({'web_status':'anything'},{'web_revision':True},{'shell':'cmd'}):
   body=self.report();body.update(patch)
   with self.assertRaises(core.CentralError):self.store.web_telemetry(self.client['device_token'],body)

class WebsiteHttpTests(unittest.TestCase):
 def test_bulk_auth_csrf_and_endpoint(self):
  def port():
   with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
  install()
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);p,a=port(),port();core.initialize(root,'Website test 1234567','127.0.0.1','127.0.0.0/8',a,p)
   panel,agent=core.build_servers(root,assets_dir=R/'managed/build/assets')
   for server in (panel,agent):threading.Thread(target=server.serve_forever,daemon=True).start()
   def call(path,body,heads=None):
    c=http.client.HTTPConnection('127.0.0.1',p);h={'Origin':f'http://127.0.0.1:{p}','Content-Type':'application/json'};h.update(heads or {})
    c.request('POST',path,json.dumps(body),h);r=c.getresponse();data=json.loads(r.read());cookie=r.getheader('Set-Cookie');c.close();return r.status,data,cookie
   try:
    self.assertEqual(call('/api/web-sites/block-all',{'expected_revision':1})[0],401)
    status,data,cookie=call('/api/login',{'password':'Website test 1234567'});self.assertEqual(status,200)
    self.assertEqual(call('/api/web-sites/block-all',{'expected_revision':1},{'Cookie':cookie})[0],401)
    status,data,_=call('/api/web-sites/block-all',{'expected_revision':1},{'Cookie':cookie,'X-CSRF-Token':data['csrf']});self.assertEqual(status,200);self.assertIn('term.ooo',data['policy']['blocked_domains'])
   finally:
    for server in (panel,agent):server.shutdown();server.server_close()
if __name__=='__main__':unittest.main(verbosity=2)
