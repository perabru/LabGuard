import socket
import socketserver
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from dnslib import DNSRecord, DNSQuestion, RR, A, CNAME, TXT, QTYPE, RCODE
from labguard.local_dns import DNSFilter, LocalDNSTransport, DNSError, CHECK_DOMAIN, validate_config
from labguard.controller import ControllerTransport
from labguard.dns_gui import dns_instructions, suggest_dns_settings


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1',0));return stream.getsockname()[1]


def start_filter(**kw):
    for _ in range(5):
        value=DNSFilter('127.0.0.1','127.0.0.0/8',port=free_port(),**kw)
        try:value.start();return value
        except DNSError:continue
    raise AssertionError('Could not open isolated loopback filter')


class FilterTests(unittest.TestCase):
    def setUp(self):self.filter=DNSFilter('127.0.0.1','127.0.0.0/8',port=free_port(),rules={'roblox.com':'Jogos'})
    def tearDown(self):self.filter.close()
    def query(self,name,kind='A',client='127.0.0.1'):
        data=self.filter.resolve(DNSRecord.question(name,kind).pack(),client)
        return DNSRecord.parse(data) if data else None

    def test_private_scope_and_literal_ip_config_required(self):
        for values in [('0.0.0.0','0.0.0.0/0'),('192.168.15.10','192.168.15.10/24'),('192.168.15.0','192.168.15.0/24'),('192.168.15.255','192.168.15.0/24'),('192.168.1.2','10.0.0.0/24'),('8.8.8.8','8.8.8.0/24'),('hostname','192.168.1.0/24')]:
            with self.subTest(values=values),self.assertRaises(DNSError):validate_config(*values)
        for bad in (0,True,-1,65536):
            with self.assertRaises(DNSError):validate_config('192.168.15.10','192.168.15.0/24',port=bad)
        with self.assertRaises(DNSError):validate_config('192.168.15.10','192.168.15.0/24','192.168.15.10')

    def test_exact_subdomain_and_case_block_without_false_suffixes(self):
        with patch.object(self.filter,'_forward',side_effect=OSError()) as forward:
            for host in ('roblox.com','WWW.Roblox.com','a.b.roblox.com'):
                self.assertEqual(self.query(host).header.rcode,RCODE.NXDOMAIN)
            forward.assert_not_called()
            self.assertEqual(self.query('notroblox.com').header.rcode,RCODE.SERVFAIL)
            self.assertEqual(self.query('roblox.com.evil.test').header.rcode,RCODE.SERVFAIL)

    def test_aaaa_https_and_txt_are_blocked(self):
        for kind in ('A','AAAA','HTTPS','TXT'):
            self.assertEqual(self.query('roblox.com',kind).header.rcode,RCODE.NXDOMAIN)

    def test_diagnostic_token_proves_which_filter_replied(self):
        answer=self.query(CHECK_DOMAIN,'TXT')
        self.assertEqual(answer.header.rcode,0)
        self.assertEqual(str(answer.rr[0].rdata).strip('"'),self.filter.check_token)
        self.assertEqual(self.query('blocked.'+CHECK_DOMAIN).header.rcode,RCODE.NXDOMAIN)

    def test_outside_subnet_malformed_and_response_packets_are_not_forwarded(self):
        with patch.object(self.filter,'_forward') as forward:
            self.assertIsNone(self.query('roblox.com',client='192.168.15.1'))
            for raw in (b'',b'garbage',b'\0'*5000,DNSRecord.question('roblox.com').reply().pack()):
                self.assertIsNone(self.filter.resolve(raw,'127.0.0.1'))
            forward.assert_not_called()
        self.assertEqual(self.filter.activity()['queries'],0)

    def test_any_and_transfer_and_nonstandard_class_refused(self):
        for kind in ('ANY','AXFR','IXFR'):
            self.assertEqual(self.query('roblox.com',kind).header.rcode,RCODE.REFUSED)
        query=DNSRecord(q=DNSQuestion('example.com',qclass=3))
        answer=DNSRecord.parse(self.filter.resolve(query.pack(),'127.0.0.1'))
        self.assertEqual(answer.header.rcode,RCODE.REFUSED)

    def test_alias_to_banned_domain_blocked_without_upstream_answers(self):
        q=DNSRecord.question('alias.test');answer=q.reply();answer.add_answer(RR('alias.test',QTYPE.CNAME,rdata=CNAME('www.roblox.com')))
        with patch.object(self.filter,'_forward',return_value=answer):result=self.query('alias.test')
        self.assertEqual(result.header.rcode,RCODE.NXDOMAIN);self.assertEqual(len(result.rr),0)

    def test_negative_or_timeout_never_recorded_as_confirmed_block(self):
        with patch.object(self.filter,'_forward',side_effect=socket.timeout()):self.query('example.com')
        event=self.filter.activity()['events'][0]
        self.assertEqual(event['status'],'Falha DNS');self.assertEqual(self.filter.activity()['blocked'],0)

    def test_history_bounded_and_rule_changes_take_effect(self):
        for n in range(1010):self.query('roblox.com',client='127.0.'+str(n//250)+'.'+str(n%250+1))
        info=self.filter.activity();self.assertEqual(len(info['events']),1000);self.assertLessEqual(len(info['clients']),512)
        self.filter.replace_rules({})
        with patch.object(self.filter,'_forward',side_effect=OSError()):self.assertEqual(self.query('roblox.com').header.rcode,RCODE.SERVFAIL)

    def test_rate_limit_is_bounded(self):
        with patch('labguard.local_dns.time.monotonic',return_value=0):
            for _ in range(120):self.assertTrue(self.filter._rate('127.0.0.1'))
            self.assertFalse(self.filter._rate('127.0.0.1'))

    def test_real_udp_and_tcp_service_and_port_conflict_cleanup(self):
        service=start_filter(rules={'roblox.com':'Jogos'})
        try:
            for tcp in (False,True):
                response=DNSRecord.parse(DNSRecord.question('roblox.com').send('127.0.0.1',service.port,tcp=tcp,timeout=2))
                self.assertEqual(response.header.rcode,RCODE.NXDOMAIN)
            other=DNSFilter('127.0.0.1','127.0.0.0/8',port=service.port)
            with self.assertRaises(DNSError):other.start()
            self.assertFalse(other.running)
        finally:service.close()
        self.assertFalse(service.running)

    def test_small_udp_uses_truncation_and_tcp_retains_full_reply(self):
        q=DNSRecord.question('large.test');answer=q.reply()
        for n in range(20):answer.add_answer(RR('large.test',QTYPE.TXT,rdata=TXT('x'*100)))
        with patch.object(self.filter,'_forward',return_value=answer):
            small=self.query('large.test');large=DNSRecord.parse(self.filter.resolve(q.pack(),'127.0.0.1',tcp=True))
        self.assertEqual(small.header.tc,1);self.assertEqual(len(small.rr),0);self.assertEqual(len(large.rr),20)


class UpstreamTests(unittest.TestCase):
    def test_real_forwarding_and_response_identity_validation(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                query=DNSRecord.parse(self.request[0]);answer=query.reply()
                answer.add_answer(RR(str(query.q.qname),rdata=A('192.0.2.10')))
                if str(query.q.qname).startswith('mismatch.'):answer.header.id ^= 1
                self.request[1].sendto(answer.pack(),self.client_address)
        with socketserver.UDPServer(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            service=DNSFilter('127.0.0.1','127.0.0.0/8',port=free_port(),upstream='127.0.0.1',upstream_port=server.server_address[1])
            try:
                query=DNSRecord.question('example.com');answer=DNSRecord.parse(service.resolve(query.pack(),'127.0.0.1'))
                self.assertEqual(answer.header.id,query.header.id);self.assertEqual(str(answer.rr[0].rdata),'192.0.2.10')
                bad=DNSRecord.parse(service.resolve(DNSRecord.question('mismatch.test').pack(),'127.0.0.1'))
                self.assertEqual(bad.header.rcode,RCODE.SERVFAIL)
            finally:service.close();server.shutdown();thread.join(2)


class TransportTests(unittest.TestCase):
    def test_explicit_consent_required_before_any_listener_or_database(self):
        with patch('labguard.local_dns.DNSFilter.start') as start,self.assertRaises(DNSError):
            LocalDNSTransport(host='127.0.0.1',lab_cidr='127.0.0.0/8',manage_rules=False)
        start.assert_not_called()

    def test_persistent_applied_rules_and_controller_caps_and_no_fake_cut(self):
        with tempfile.TemporaryDirectory() as directory,patch('labguard.discovery.LocalObservationTransport.request',return_value={'devices':[],'interfaces':[]}):
            port=free_port();raw=LocalDNSTransport(host='127.0.0.1',lab_cidr='127.0.0.0/8',port=port,manage_rules=True,data_dir=Path(directory)/'private')
            wrapper=ControllerTransport('local_dns',raw)
            try:
                view=wrapper.request('add_domain',domain='roblox.com',category='Jogos')
                self.assertTrue(view['capabilities']['domain_filtering']);self.assertFalse(view['capabilities']['address_blocking'])
                self.assertFalse(view['capabilities']['device_internet_cut']);self.assertFalse(view['dns_service']['network_scope_verified'])
                from labguard.controller import ControllerError
                with self.assertRaises(ControllerError):wrapper.request('set_device_block',ip='127.0.0.1',blocked=True)
            finally:wrapper.close()
            other=LocalDNSTransport(host='127.0.0.1',lab_cidr='127.0.0.0/8',port=free_port(),manage_rules=True,data_dir=Path(directory)/'private')
            try:self.assertEqual(other.request('snapshot')['domains'][0]['domain'],'roblox.com')
            finally:other.close()

    def test_setup_instructions_do_not_assume_router_api_or_dns_change(self):
        content=dns_instructions('192.168.15.10',token='LabGuard-test')
        self.assertIn('nas estações',content);self.assertIn('nslookup -type=TXT',content);self.assertIn('LabGuard-test',content)
        with self.assertRaises(ValueError):dns_instructions('8.8.8.8; dangerous')
        self.assertEqual(suggest_dns_settings({'mode':'demo','interfaces':[{'ipv4':'192.168.15.10/24'}]}),('',''))
        self.assertEqual(suggest_dns_settings({'mode':'observation','interfaces':[{'ipv4':'192.168.15.10/24'}]}),('192.168.15.10','192.168.15.0/24'))

if __name__=='__main__':unittest.main()

class ServerDNSTests(unittest.TestCase):
    def test_server_requires_explicit_optin_and_uses_only_private_state_directory(self):
        import json
        from labguard.server import initialize, ServerConfig, ServerError, create_controller_transport
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/'server';initialize(directory)
            settings=json.loads((directory/'config.json').read_text())
            settings['controller']={'kind':'local_dns','host':'127.0.0.1','lab_cidr':'127.0.0.0/8','port':free_port(),'manage_rules':False}
            (directory/'config.json').write_text(json.dumps(settings))
            with self.assertRaises(ServerError):ServerConfig(directory)
            settings['controller']['manage_rules']=True
            (directory/'config.json').write_text(json.dumps(settings))
            config=ServerConfig(directory)
            with patch('labguard.discovery.LocalObservationTransport.request',return_value={'devices':[],'interfaces':[]}):
                transport=create_controller_transport(config)
                try:
                    view=transport.request('add_domain',domain='roblox.com',category='Jogos')
                    self.assertEqual(view['source_type'],'local_dns');self.assertFalse(view['capabilities']['device_internet_cut'])
                    self.assertTrue((directory/'data'/'dns-policy').is_dir())
                finally:transport.close()

    def test_diagnostics_explain_local_dns_failure_without_raw_text(self):
        from labguard.diagnostics import classify_connection_error,safe_error_message,build_diagnostic_plan
        for code in ('dns_local_port','dns_local_config','dns_local_state','dns_local_dependency'):
            self.assertEqual(classify_connection_error(code.upper()+': password=secret'),code)
            self.assertNotIn('secret',safe_error_message(code))
            self.assertIn(code, build_diagnostic_plan(last_error=code,system='Windows')['cases'])

class TCPForwardingTests(unittest.TestCase):
    def test_udp_truncated_upstream_retries_tcp_and_direct_tcp_also_works(self):
        from labguard.local_dns import read_exact
        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                q=DNSRecord.parse(self.request[0]);reply=q.reply();reply.header.tc=1
                self.request[1].sendto(reply.pack(),self.client_address)
        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2);size=struct.unpack('!H',read_exact(self.request,2))[0]
                q=DNSRecord.parse(read_exact(self.request,size));reply=q.reply();reply.add_answer(RR(str(q.q.qname),rdata=A('192.0.2.20')))
                data=reply.pack();self.request.sendall(struct.pack('!H',len(data))+data)
        with socketserver.TCPServer(('127.0.0.1',0),TCP) as tcp:
            with socketserver.UDPServer(('127.0.0.1',tcp.server_address[1]),UDP) as udp:
                threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (tcp,udp)]
                for t in threads:t.start()
                service=DNSFilter('127.0.0.1','127.0.0.0/8',port=free_port(),upstream='127.0.0.1',upstream_port=tcp.server_address[1])
                try:
                    for is_tcp in (False,True):
                        q=DNSRecord.question('example.com');r=DNSRecord.parse(service.resolve(q.pack(),'127.0.0.1',tcp=is_tcp))
                        self.assertEqual(r.header.id,q.header.id);self.assertEqual(str(r.rr[0].rdata),'192.0.2.20')
                finally:
                    service.close();udp.shutdown();tcp.shutdown()
                    for t in threads:t.join(2)
