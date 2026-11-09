"""Exercise the HTTP authorization boundary and cross-request station approvals."""
import copy
from datetime import datetime, timezone
import hashlib
import http.client
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from labguard.server import Application, LocalHTTPServer, ServerConfig, initialize
from labguard.station_dns import StationDNS


class StationHTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name)
        initialize(path)
        self.admin = 'a' * 43
        self.viewer = 'v' * 43
        config = ServerConfig(path)
        config.token_hashes = {role: hashlib.sha256(value.encode()).hexdigest()
                               for role, value in [('admin', self.admin), ('viewer', self.viewer)]}
        config.controller = {'kind': 'local_dns', 'manage_rules': True}
        self.view = {'mode': 'equipment', 'source_type': 'local_dns', 'health': {'dns': True},
                     'timestamp': datetime.now(timezone.utc).isoformat(),
                     'local': {'default_gateway': '192.168.15.1', 'interfaces_read': True, 'routes_read': True,
                               'interface_ips': ['192.168.15.10', '192.168.15.11']},
                     'devices': [{'ip': '192.168.15.22', 'mac': '02:00:00:00:00:22'}],
                     'dns_service': {'service_running': True, 'listen': '192.168.15.10', 'port': 53,
                                     'network': '192.168.15.0/24', 'check_token': 'LabGuard-' + 'a'*16}}
        transport = Mock(kind='local_dns'); transport.request.side_effect = lambda action: copy.deepcopy(self.view)
        transport.station_source_current.return_value = True
        self.app = Application(config, transport, logging_enabled=False)
        self.app.audit = Mock(wraps=self.app.audit)
        self.httpd = LocalHTTPServer(self.app, port=0)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.sessions = []
        self.operations = []
        def connect(platform, host, user, password, **kw):
            session = SimpleNamespace(host=host, platform=platform, close=Mock())
            self.sessions.append(session)
            return session
        start = patch('labguard.station_web.create_session', side_effect=connect)
        self.connect = start.start(); self.addCleanup(start.stop)
        def run(station, action, expected=None):
            self.operations.append(action)
            if action == 'test':
                return {'direct': 'ok', 'default': 'nxdomain'}
            if action == 'preview':
                family = {'mode': 'auto', 'servers': []}
                state = {'target': station.target, 'guid': 'abcdefff-1234-1234-1234-abcdef123456',
                         'index': 10, 'register': 'both', 'adapter': 'Ethernet', 'ipv4': family, 'ipv6': family}
                return {'ok': True, 'state': state}
            return {'ok': True, 'message': 'Estado confirmado pela estação.'}
        remote = patch.object(StationDNS, '_run', new=run)
        remote.start(); self.addCleanup(remote.stop)

    def close_server(self):
        self.httpd.shutdown(); self.httpd.server_close(); self.thread.join(2); self.app.close()

    def post(self, action, *, token=None, headers=None, **fields):
        payload = {'host': '192.168.15.22', 'user': 'escola\\ti', 'password': 'SenhaTemporariaDeTeste'}
        payload.update(fields)
        return self.request('POST', '/api/station/' + action, token=token, headers=headers, payload=payload)

    def request(self, method, path, *, token=None, headers=None, payload=None):
        request_headers = {'Content-Type': 'application/json', **(headers or {})}
        if token:
            request_headers['Authorization'] = 'Bearer ' + token
        client = http.client.HTTPConnection('127.0.0.1', self.httpd.server_port, timeout=3)
        try:
            client.request(method, path, json.dumps(payload) if payload is not None else None, headers=request_headers)
            response = client.getresponse(); body = response.read()
            self.assertNotIn(b'SenhaTemporariaDeTeste', body)
            return response.status, json.loads(body)
        finally:
            client.close()

    def test_only_admin_may_attempt_station_and_credentials_stay_in_request(self):
        self.assertEqual(self.post('test')[0], 401)
        self.assertEqual(self.post('preview', token=self.viewer)[0], 403)
        self.assertEqual(self.post('test', token=self.admin, headers={'Origin': 'https://outro.local'})[0], 403)
        self.assertEqual(self.post('test', token=self.admin, ca_file='/tmp/custom')[0], 400)
        self.connect.assert_not_called()
        status, result = self.post('test', token=self.admin)
        self.assertEqual((status, result['role'], result['data']['direct'], result['data']['default']),
                         (200, 'admin', 'ok', 'nxdomain'))
        self.assertFalse(result['data']['ok'])
        self.app.audit.assert_called_with('station_test', 'admin', 'unconfirmed')
        self.sessions[-1].close.assert_called_once()
        self.connect.side_effect = ValueError('SenhaTemporariaDeTeste')
        self.assertEqual(self.post('test', token=self.admin)[0], 400)

    def test_preview_reconnects_with_fresh_credentials_and_is_bound_to_account_host_source(self):
        status, preview = self.post('preview', token=self.admin)
        self.assertEqual(status, 200)
        self.app.audit.assert_called_with('station_preview', 'admin', 'preview_ready')
        identifier = preview['data']['id']
        self.assertEqual(self.post('apply', token=self.admin, id=identifier, confirm=False)[0], 400)
        self.assertEqual(self.post('apply', token=self.admin, id=identifier, confirm=True, user='outra-conta')[0], 400)
        self.assertEqual(self.post('apply', token=self.admin, id=identifier, confirm=True, host='192.168.15.23')[0], 400)
        self.assertEqual(self.operations, ['preview'])
        status, result = self.post('apply', token=self.admin, id=identifier, confirm=True, password='senha-nova')
        self.assertEqual((status, result['data']['ok']), (200, True))
        self.app.audit.assert_called_with('station_apply', 'admin', 'confirmed')
        self.assertEqual(self.post('apply', token=self.admin, id=identifier, confirm=True)[0], 400)
        self.assertEqual(self.post('restore', token=self.admin, confirm=True)[0], 200)
        self.assertEqual(self.operations, ['preview', 'apply', 'restore'])
        for session in self.sessions:
            session.close.assert_called_once()

    def test_remote_access_preparation_requires_admin_scoped_target_and_confirmation(self):
        prepare = Mock(return_value={'ok': True, 'message': 'Acesso preparado.'})
        args = {'hostname': 'lab-22.escola.local', 'confirm': True}
        with patch.dict(sys.modules, {'labguard.access_push': SimpleNamespace(prepare_remote_access=prepare)}):
            self.assertEqual(self.post('prepare-access', token=self.viewer, **args)[0], 403)
            self.assertEqual(self.post('prepare-access', token=self.admin, hostname=args['hostname'], confirm=False)[0], 400)
            self.assertEqual(self.post('prepare-access', token=self.admin, host='192.168.15.1', **args)[0], 400)
            self.view['local']['routes_read'] = False
            self.assertEqual(self.post('prepare-access', token=self.admin, **args)[0], 400)
            prepare.assert_not_called()
            self.view['local']['routes_read'] = True
            status, result = self.post('prepare-access', token=self.admin, **args)
            self.assertEqual((status, result['data']['ok']), (200, True))
            self.app.audit.assert_called_with('station_prepare-access', 'admin', 'confirmed')
            snapshot, payload, assets = prepare.call_args.args
            self.assertEqual(snapshot['local']['default_gateway'], '192.168.15.1')
            self.assertEqual((payload['host'], payload['hostname']), ('192.168.15.22', args['hostname']))
            self.assertEqual(assets.name, 'assets')
            prepare.return_value = {'ok': False, 'message': 'Acesso não confirmado.'}
            self.assertFalse(self.post('prepare-access', token=self.admin, **args)[1]['data']['ok'])
            self.app.audit.assert_called_with('station_prepare-access', 'admin', 'unconfirmed')
            prepare.side_effect = RuntimeError('SenhaTemporariaDeTeste')
            self.assertEqual(self.post('prepare-access', token=self.admin, **args)[0], 400)
        self.connect.assert_not_called()

    def test_preview_invalidated_by_changed_identity_and_expiry(self):
        first = self.post('preview', token=self.admin)[1]['data']['id']
        self.view['dns_service']['check_token'] = 'LabGuard-' + 'b'*16
        self.assertEqual(self.post('apply', token=self.admin, id=first, confirm=True)[0], 400)
        second = self.post('preview', token=self.admin)[1]['data']['id']
        with patch('labguard.station_dns.monotonic', return_value=float('inf')):
            self.assertEqual(self.post('apply', token=self.admin, id=second, confirm=True)[0], 400)
        self.assertEqual(self.operations, ['preview', 'preview'])

    def test_refuses_unsafe_targets_stale_source_and_incomplete_topology(self):
        for host in ('nome.local', '192.168.15.1', '192.168.15.10', '192.168.15.11', '192.168.99.21'):
            with self.subTest(host=host):
                self.assertEqual(self.post('preview', token=self.admin, host=host)[0], 400)
        self.view['local']['routes_read'] = False
        self.assertEqual(self.post('restore', token=self.admin, confirm=True)[0], 400)
        self.view['timestamp'] = '2020-01-01T00:00:00+00:00'
        self.assertEqual(self.post('test', token=self.admin)[0], 400)
        self.app.transport.station_source_current.return_value = False
        self.assertEqual(self.post('test', token=self.admin)[0], 400)
        self.connect.assert_not_called()

    def test_station_test_uses_only_applied_domain_and_can_read_fresh_evidence(self):
        self.view['domains'] = [{'domain': 'docs.escola.local'}, {'domain': 'roblox.com'}]
        with patch.object(StationDNS, 'test', autospec=True, return_value={'ok': True}) as diagnostic:
            self.assertEqual(self.post('test', token=self.admin, blocked_domain='custom.test')[0], 400)
            self.assertEqual(self.post('test', token=self.admin)[0], 200)
            options = diagnostic.call_args.kwargs
            self.assertEqual(options['blocked_domain'], 'roblox.com')
            self.assertEqual(options['read_evidence']()['dns_service']['check_token'],
                             self.view['dns_service']['check_token'])

    def test_school_policy_preview_read_role_and_fixed_explicit_admin_mutation(self):
        from labguard.school_policy import SCHOOL_POLICY
        path = '/api/school/protect'
        self.assertEqual(self.request('GET', '/api/school/policy')[0], 401)
        status, result = self.request('GET', '/api/school/policy', token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(result['data']['domains'], [domain for domain, _ in SCHOOL_POLICY])
        self.assertEqual(result['data']['categories'], list(dict.fromkeys(category for _, category in SCHOOL_POLICY)))
        self.view['capabilities'] = {'domain_filtering': True}
        with patch('labguard.school_policy.apply_school_policy') as apply:
            self.assertEqual(self.request('POST', path, token=self.viewer, payload={'confirm': True})[0], 403)
            self.assertEqual(self.request('POST', path, token=self.admin, payload={'confirm': False})[0], 400)
            self.assertEqual(self.request('POST', path, token=self.admin, payload={'confirm': True, 'domains': []})[0], 400)
            self.view['dns_service']['service_running'] = False
            self.assertEqual(self.request('POST', path, token=self.admin, payload={'confirm': True})[0], 400)
            apply.assert_not_called()
            self.view['dns_service']['service_running'] = True
            for ok in (True, False):
                apply.return_value = {'ok': ok, 'message': 'Resultado da operação'}
                status, result = self.request('POST', path, token=self.admin, payload={'confirm': True})
                self.assertEqual((status, result['data']['ok']), (200, ok))
                self.app.audit.assert_called_with('school_protect', 'admin', 'confirmed' if ok else 'partial')
                apply.assert_called_with(self.app.transport, authorized=True, expected_token=self.view['dns_service']['check_token'])
