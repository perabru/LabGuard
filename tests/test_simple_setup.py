"""Meaningful checks for the simplified workflow and local-only diagnostic."""
import http.client
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from dnslib import DNSRecord, RR, TXT, QTYPE
from labguard.controller import ControllerTransport, ControllerError, create_transport
from labguard.desktop_web import DesktopWebSession
from labguard.server import ServerError
from labguard.local_dns import LocalDNSTransport, DNSError
from labguard.dns_gui import dns_network_choices, effective_dns_service, initial_resolver, DNSSetupWindow
from labguard.simple_gui import App, home_status
from labguard.preferences import normalize_dns_profile, PreferenceError
from test_local_dns import free_port


class SetupPresentationTests(unittest.TestCase):
    def test_waiting_wizard_tracks_completed_read_and_ignores_closed_window(self):
        owner=Mock(snapshot={}, _busy=True, _snapshot_stale=False)
        wizard=DNSSetupWindow.__new__(DNSSetupWindow);wizard.owner=owner;wizard._closed=False;wizard.refresh=Mock()
        wizard.sync_owner();self.assertEqual(wizard.refresh.call_count,1)
        wizard.sync_owner();self.assertEqual(wizard.refresh.call_count,1)
        owner._busy=False;wizard.sync_owner();self.assertEqual(wizard.refresh.call_count,2)
        owner.snapshot={};wizard.sync_owner();self.assertEqual(wizard.refresh.call_count,3)
        wizard._closed=True;owner._busy=True;wizard.sync_owner();self.assertEqual(wizard.refresh.call_count,3)

    def test_demo_and_stale_never_display_protected_network(self):
        self.assertEqual(home_status({'mode':'demo'})[0], 'Demonstração')
        snapshot={'mode':'equipment','source_type':'local_dns','dns_service':{'listen':'192.168.15.10','service_running':True}}
        self.assertEqual(home_status(snapshot,stale=True)[0], 'Atualize a conexão')
        title,hint=home_status(snapshot)
        self.assertEqual(title,'Filtro ligado neste PC');self.assertIn('teste cada estação',hint)

    def test_observation_requires_setup(self):
        self.assertEqual(home_status({'mode':'observation'})[0], 'Vamos configurar o filtro')
        self.assertEqual(home_status({'mode':'equipment','source_type':'local_dns','dns_service':{}})[0], 'Filtro parado')

    def test_network_choices_use_real_valid_interfaces_only(self):
        snapshot={'interfaces':[{'name':'Ethernet','ipv4':'192.168.15.10/24'}, {'name':'Internet','ipv4':'8.8.8.8/24'}, {'ipv4':'bad'}]}
        self.assertEqual(list(dns_network_choices(snapshot).values()),[('192.168.15.10','192.168.15.0/24')])
        self.assertEqual(dns_network_choices(dict(snapshot,mode='demo')), {})

    def test_real_discovery_format_produces_network_without_guessing_missing_prefix(self):
        snapshot = {'mode': 'observation', 'interfaces': [
            {'name': 'Laboratório', 'ipv4': '192.168.33.71', 'prefixlen': 26},
            {'name': 'Sem prefixo', 'ipv4': '192.168.34.2'}]}
        self.assertEqual(list(dns_network_choices(snapshot).values()), [('192.168.33.71', '192.168.33.64/26')])
        self.assertFalse(dns_network_choices(dict(snapshot, mode='equipment', source_type='routeros')))

    def test_station_commands_use_active_listener_and_absolute_name(self):
        wizard = DNSSetupWindow.__new__(DNSSetupWindow)
        wizard.owner = Mock(snapshot={'source_type': 'local_dns', 'dns_service': {
            'listen': '192.168.33.71', 'port': 53, 'service_running': True, 'check_token': 'LabGuard-test'}},
            _snapshot_stale=False)
        wizard.owner.transport.kind = 'local_dns'
        wizard.host = Mock()
        wizard.host.get.return_value = '192.168.33.100'
        direct, default = wizard._station_commands()
        self.assertEqual(direct, 'nslookup -type=TXT labguard-check.invalid. 192.168.33.71')
        self.assertEqual(default, 'nslookup -type=TXT labguard-check.invalid.')
        wizard.owner.snapshot['dns_service']['port'] = 8053
        self.assertIn('-port=8053', wizard._station_commands()[0])
        wizard.owner._snapshot_stale = True
        self.assertFalse(wizard._station_commands())
        wizard.owner._snapshot_stale = False
        wizard.owner.snapshot['dns_service']['service_running'] = False
        self.assertFalse(wizard._station_commands())

    def test_copy_click_rechecks_session_before_touching_clipboard(self):
        wizard = DNSSetupWindow.__new__(DNSSetupWindow)
        wizard.owner = Mock(snapshot={'mode': 'observation'})
        wizard.clipboard_append = Mock()
        wizard.clipboard_clear = Mock()
        wizard.state = Mock()
        wizard.refresh = Mock()
        wizard.copy_test()
        wizard.clipboard_append.assert_not_called()
        wizard.clipboard_clear.assert_not_called()

    def test_instructions_keep_running_ip_despite_unsaved_edit(self):
        snapshot={'source_type':'local_dns','dns_service':{'listen':'192.168.15.10','service_running':True}}
        self.assertEqual(effective_dns_service(snapshot,'192.168.15.22')[:2],(True,'192.168.15.10'))
        self.assertEqual(effective_dns_service({},'not-an-ip')[:2],(False,''))

    def test_family_override_preserves_internal_resolver_in_saved_profile(self):
        settings = {'host': '192.168.55.10', 'lab_cidr': '192.168.55.0/24', 'upstream': '1.1.1.3',
                    'start_on_open': True, 'custom_upstream': '192.168.55.2'}
        profile = normalize_dns_profile(settings)
        self.assertEqual(initial_resolver({}, profile), (True, '192.168.55.2'))
        self.assertEqual(initial_resolver({'upstream': '192.168.55.3'}, profile), (False, '192.168.55.3'))
        self.assertEqual(initial_resolver({}, {'upstream': '192.168.55.2'}), (False, '192.168.55.2'))
        with self.assertRaises(PreferenceError):
            normalize_dns_profile(dict(settings, custom_upstream='192.168.55.10'))

    def test_school_start_requires_consent_then_forwards_choices_separately(self):
        wizard = DNSSetupWindow.__new__(DNSSetupWindow)
        wizard.owner = Mock(_busy=False, snapshot={'mode': 'observation'})
        wizard.owner._start_transport.return_value = False
        for field, value in {'host':'192.168.55.10', 'network':'192.168.55.0/24',
                             'upstream':'192.168.55.2', 'family_mode':True, 'autostart':True,
                             'authorize':False}.items():
            setattr(wizard, field, Mock())
            getattr(wizard, field).get.return_value = value
        wizard.state = Mock()
        self.assertFalse(wizard.start(protect=True))
        wizard.owner._start_transport.assert_not_called()
        wizard.authorize.get.return_value = True
        wizard.owner._confirm_school_protection.return_value = False
        wizard.start(protect=True)
        wizard.owner._start_transport.assert_not_called()
        wizard.owner._confirm_school_protection.return_value = True
        wizard.start(protect=True)
        args, kwargs = wizard.owner._start_transport.call_args
        self.assertEqual(args[1]['upstream'], '1.1.1.3')
        self.assertNotIn('custom_upstream', args[1])
        self.assertEqual(kwargs['remember_options']['custom_upstream'], '192.168.55.2')
        self.assertTrue(kwargs['remember_options']['apply_school_policy'])
        wizard.family_mode.get.return_value = False
        wizard.start()
        self.assertEqual(wizard.owner._start_transport.call_args.args[1]['upstream'], '192.168.55.2')
        self.assertFalse(wizard.owner._start_transport.call_args.kwargs['remember_options']['apply_school_policy'])

    def test_demo_cannot_apply_school_protection(self):
        owner = Mock(snapshot={'mode':'demo'})
        self.assertFalse(App._open_school_protection(owner))
        owner._apply_school_protection.assert_not_called()
        owner._open_dns_setup.assert_not_called()

    def test_diagnostic_result_cannot_update_closed_or_replaced_window(self):
        owner=Mock();transport=owner.transport;transport.kind='local_dns'
        wizard=DNSSetupWindow.__new__(DNSSetupWindow);wizard.owner=owner;wizard._closed=False
        wizard.verify_button=Mock();wizard.test_result=Mock();wizard.state=Mock();wizard.refresh=Mock()
        owner._run_job.return_value=True
        self.assertTrue(wizard.verify());callback=owner._run_job.call_args.kwargs['on_success']
        owner.transport=Mock();callback({'ok':True});wizard.refresh.assert_not_called()
        owner.transport=transport;wizard._closed=True;callback({'ok':True});wizard.refresh.assert_not_called()


class LocalDiagnosticTests(unittest.TestCase):
    def test_real_udp_tcp_and_no_claim_of_station_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            raw=LocalDNSTransport(host='127.0.0.1',lab_cidr='127.0.0.0/8',port=free_port(),data_dir=directory,manage_rules=True)
            transport=ControllerTransport('local_dns',raw)
            try:
                result=transport.verify_dns()
                self.assertTrue(result['udp']);self.assertTrue(result['tcp']);self.assertTrue(result['ok'])
                self.assertEqual(result['scope'],'this_computer');self.assertIs(result['network_scope_verified'],False)
            finally:transport.close()
            with self.assertRaises(ControllerError):transport.verify_dns()
            with self.assertRaises(DNSError):raw.verify_dns()

    def test_wrong_token_is_not_success_and_target_is_fixed_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            raw=LocalDNSTransport(host='127.0.0.1',lab_cidr='127.0.0.0/8',port=free_port(),data_dir=directory,manage_rules=True)
            calls=[]
            def wrong(query,host,port,*,tcp,timeout):
                calls.append((host,port,tcp,timeout));reply=query.reply()
                reply.add_answer(RR(str(query.q.qname),QTYPE.TXT,rdata=TXT('wrong-token')));return reply.pack()
            try:
                with patch.object(DNSRecord,'send',wrong):result=raw.verify_dns()
                self.assertFalse(result['ok']);self.assertEqual([c[2] for c in calls],[False,True])
                self.assertTrue(all(c[0]=='127.0.0.1' and c[1]==raw.port and c[3]==2 for c in calls))
                with patch.object(DNSRecord,'send',side_effect=TimeoutError()):self.assertFalse(raw.verify_dns()['ok'])
            finally:raw.close()

    def test_non_dns_controller_does_not_probe(self):
        raw=Mock();transport=ControllerTransport('observation',raw)
        with self.assertRaises(ControllerError):transport.verify_dns()
        raw.verify_dns.assert_not_called()
        with self.assertRaises(ControllerError):transport.request('verify_dns',host='192.168.15.100')
        raw.request.assert_not_called()


class DesktopWebTests(unittest.TestCase):
    def call(self, session, path, *, token=None, payload=None):
        headers = {}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        connection = http.client.HTTPConnection('127.0.0.1', session.server.server_port, timeout=8)
        try:
            if payload is None:
                connection.request('GET', path, headers=headers)
            else:
                headers['Content-Type'] = 'application/json'
                connection.request('POST', path, body=json.dumps(payload), headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_authorized_loopback_panel_shares_bank_and_releases_only_its_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = LocalDNSTransport(host='127.0.0.1', lab_cidr='127.0.0.0/8', port=free_port(),
                                    manage_rules=True, data_dir=root / 'applied')
            source = ControllerTransport('local_dns', raw)
            try:
                session = DesktopWebSession(source, source.request('snapshot'), current=lambda:True,
                                            writable=lambda:True, authorized=True,
                                            bank_path=root/'bank'/'policy.sqlite3', directory=root/'web')
                try:
                    self.assertEqual(session.server.server_address[0], '127.0.0.1')
                    self.assertEqual(session.app.banlist.path, root/'bank'/'policy.sqlite3')
                    self.assertNotIn(session.token, session.url)
                    self.assertEqual(self.call(session, '/api/snapshot')[0], 401)
                    status, result = self.call(session, '/api/snapshot', token=session.token)
                    self.assertEqual(status, 200)
                    self.assertEqual(result['role'], 'admin')
                    self.assertEqual(result['data']['source_type'], 'local_dns')
                    self.assertTrue(session.source.station_source_current())
                    self.assertFalse(any(session.token.encode() in f.read_bytes()
                                         for f in (root/'web').rglob('*') if f.is_file()))
                finally:
                    session.close()
                    self.assertTrue(session.stopped.wait(8))
                self.assertFalse(session.source.station_source_current())
                with self.assertRaises(ServerError):
                    session.source.request('snapshot')
                self.assertTrue(raw.verify_dns()['ok'])
            finally:
                source.close()

    def test_consultation_token_cannot_modify_bank_and_new_source_invalidates_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = create_transport('demo')
            current = [True]
            session = DesktopWebSession(source, source.request('snapshot'), current=lambda:current[0],
                                        writable=lambda:True, authorized=False,
                                        bank_path=root/'bank'/'policy.sqlite3', directory=root/'web')
            try:
                status, _ = self.call(session, '/api/banlist/upsert', token=session.token, payload={})
                self.assertEqual(status, 403)
                self.assertEqual(session.role, 'viewer')
                with self.assertRaises(ServerError):
                    session.source.request('add_domain', domain='example.com', category='Jogos')
                current[0] = False
                self.assertEqual(self.call(session, '/api/snapshot', token=session.token)[0], 502)
            finally:
                session.close()
                self.assertTrue(session.stopped.wait(8))
                source.close()
