import json
import threading
import unittest
from unittest.mock import Mock, patch

from labguard.station_dns import StationDNS, _windows_script
from labguard.remote import RemoteError


TOKEN = 'LabGuard-1234567812345678'
SETTINGS = dict(listen='192.168.15.7', network='192.168.15.0/24', token=TOKEN)
ORIGINAL = dict(target='192.168.15.22', guid='8384c44f-8bad-4a6b-8274-f95a3e5ab9d1', index=12, adapter='Ethernet', register='primary',
                ipv4={'mode':'auto','servers':['192.168.15.1']}, ipv6={'mode':'static','servers':['fe80::1%12']})


def session(platform='windows', target=ORIGINAL['target']):
    mock=Mock(host=target, platform=platform, _operation=threading.Lock())
    return mock


class StationDNSTests(unittest.TestCase):
    def test_denies_out_of_scope_and_missing_session_token_before_remote_io(self):
        for target in ('127.0.0.1','192.168.15.0','192.168.15.255','192.168.15.7','192.168.2.1','example.com'):
            with self.subTest(target=target):
                transport=session(target=target)
                with self.assertRaises(RemoteError): StationDNS(transport, **SETTINGS)
                transport._ps.assert_not_called()
        with self.assertRaises(RemoteError): StationDNS(session(), **dict(SETTINGS, token='untrusted input'))

    def test_windows_queries_preserve_direct_and_default_results(self):
        transport=session();transport._ps.return_value={'direct':'ok','default':'nxdomain'}
        client=StationDNS(transport, **SETTINGS);result=client.test()
        self.assertEqual(result['direct'], 'ok');self.assertEqual(result['default'],'nxdomain');self.assertFalse(result['ok'])
        self.assertIn('IPv6',result['message']);self.assertIn('nslookup.exe',transport._ps.call_args.args[0])

    def test_linux_uses_read_only_ssh_and_handles_missing_tool(self):
        transport=session('linux');transport._python.return_value={'direct':'unavailable','default':'unavailable'}
        client=StationDNS(transport, **SETTINGS)
        self.assertIn('dig',client.test()['message'])
        with self.assertRaises(RemoteError): client.preview()
        self.assertEqual(transport._python.call_count,1)

    def test_preview_moves_between_sessions_without_credentials_or_replay(self):
        first=session();first._ps.return_value={'ok':True,'state':ORIGINAL};old=StationDNS(first,**SETTINGS)
        view=old.preview();plan=old.take_preview();self.assertIn('fe80::1',view['message'])
        self.assertNotIn('session',vars(plan));self.assertNotIn('password',vars(plan))
        with self.assertRaises(RemoteError):old.apply(view['id'])
        next_session=session();next_session._ps.return_value={'ok':True,'message':'DNS confirmado'};new=StationDNS(next_session,**SETTINGS)
        self.assertEqual(new.resume_preview(plan),view['id']);self.assertTrue(new.apply(view['id'])['ok'])
        with self.assertRaises(RemoteError): new.apply(view['id'])
        self.assertEqual(next_session._ps.call_count,1)

    def test_preview_expires_and_cannot_be_imported_for_other_filter_or_target(self):
        transport=session();transport._ps.return_value={'ok':True,'state':ORIGINAL};client=StationDNS(transport,**SETTINGS)
        with patch('labguard.station_dns.monotonic',return_value=100): client.preview();plan=client.take_preview()
        with patch('labguard.station_dns.monotonic',return_value=161),self.assertRaises(RemoteError):client.resume_preview(plan)
        for ref in (StationDNS(session(target='192.168.15.45'),**SETTINGS), StationDNS(transport, **dict(SETTINGS,token='LabGuard-fedcba9876543210'))):
            with patch('labguard.station_dns.monotonic',return_value=120),self.assertRaises(RemoteError):ref.resume_preview(plan)

    def test_windows_limit_refuses_oversize_preview(self):
        with self.assertRaisesRegex(RemoteError,'limite'):
            _windows_script('apply', target=ORIGINAL['target'], listen=SETTINGS['listen'], token=TOKEN, expected={'bogus':'X'*11000})

    def test_ambiguous_snapshot_and_mid_write_disconnect_fail_closed(self):
        transport=session();client=StationDNS(transport,**SETTINGS)
        transport._ps.return_value={'ok':True,'state':dict(ORIGINAL, ipv6={'mode':'unknown','servers':[]})}
        with self.assertRaisesRegex(RemoteError,'restauráveis'):client.preview()
        transport._ps.return_value={'ok':True,'state':ORIGINAL};view=client.preview()
        transport._ps.side_effect=RemoteError('WinRM')
        with self.assertRaisesRegex(RemoteError,'sem confirmação'):client.apply(view['id'])
        transport._ps.side_effect=None;transport._ps.return_value={'ok':True,'message':'DNS restaurado'}
        self.assertTrue(StationDNS(transport, **SETTINGS).restore()['ok'])
