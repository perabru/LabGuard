"""Meaningful checks for the simplified workflow and local-only diagnostic."""
import tempfile
import unittest
from unittest.mock import Mock, patch
from dnslib import DNSRecord, RR, TXT, QTYPE
from labguard.controller import ControllerTransport, ControllerError
from labguard.local_dns import LocalDNSTransport, DNSError
from labguard.dns_gui import dns_network_choices, effective_dns_service, DNSSetupWindow
from labguard.simple_gui import home_status
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

    def test_instructions_keep_running_ip_despite_unsaved_edit(self):
        snapshot={'source_type':'local_dns','dns_service':{'listen':'192.168.15.10','service_running':True}}
        self.assertEqual(effective_dns_service(snapshot,'192.168.15.22')[:2],(True,'192.168.15.10'))
        self.assertEqual(effective_dns_service({},'not-an-ip')[:2],(False,''))

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
