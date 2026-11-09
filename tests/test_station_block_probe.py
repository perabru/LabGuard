from datetime import datetime, timedelta, timezone
import threading
import unittest
from unittest.mock import Mock

from labguard.remote import RemoteError
from labguard.station_dns import StationDNS

TOKEN = 'LabGuard-1234567812345678'
SITE = 'roblox.com'
TARGET = '192.168.45.17'


class ProbeTests(unittest.TestCase):
    def exercise(self, *, status='nxdomain', direct='ok', default='ok', site=SITE, event_change=None,
                 post_token=TOKEN, pre_applied=True, platform='windows'):
        session = Mock(host=TARGET, platform=platform, _operation=threading.Lock())
        station = StationDNS(session, listen='192.168.45.3', network='192.168.45.0/24', token=TOKEN)
        events = []

        def remote(script, **_kwargs):
            if '# LABGUARD_BLOCK_PROBE' in script or "domain = 'roblox.com'" in script:
                event = {'domain': SITE, 'client_ip': TARGET, 'query_type': 'A', 'status': 'Bloqueio DNS confirmado',
                         'time': datetime.now(timezone.utc).isoformat(timespec='microseconds')}
                if event_change:
                    event.update(event_change)
                events.append(event)
                return {'status': status}
            return {'direct': direct, 'default': default}

        session._ps.side_effect = remote
        session._python.side_effect = remote
        def snapshot():
            return {'source_type':'local_dns','dns_service':{'service_running':True, 'check_token':post_token if events else TOKEN},
                    'domains':[{'domain':SITE}] if pre_applied else [], 'events':list(events)}
        return station.test(blocked_domain=site,read_evidence=snapshot), events

    def test_confirmed_requires_matching_event_on_active_session(self):
        for platform in ('windows','linux'):
            with self.subTest(platform=platform):
                result, events = self.exercise(platform=platform)
                self.assertTrue(result['block_confirmed'])
                self.assertEqual(result['blocked_domain'], SITE)
                self.assertTrue(events)
                self.assertIn('Bloqueio', result['message'])

    def test_nxdomain_cannot_be_attributed_to_another_station_or_old_event(self):
        stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        for change in ({'client_ip':'192.168.45.19'}, {'domain':'example.org'}, {'query_type':'TXT'},
                       {'status':'Resposta DNS negativa'}, {'time':stale}):
            with self.subTest(change=change):
                result, _events = self.exercise(event_change=change)
                self.assertFalse(result['block_confirmed'])
                self.assertEqual(result['block_result'], 'nxdomain')

    def test_failed_txt_new_listener_or_positive_A_never_confirms(self):
        for settings in ({'default':'different'}, {'direct':'timeout'}, {'status':'resolved'},
                         {'status':'timeout'}, {'post_token':'LabGuard-1111111111111111'}):
            with self.subTest(settings=settings):
                result, _events = self.exercise(**settings)
                self.assertFalse(result['block_confirmed'])

    def test_no_A_for_unapplied_or_untrusted_name(self):
        result, events = self.exercise(pre_applied=False)
        self.assertFalse(events)
        self.assertFalse(result['block_confirmed'])
        self.assertEqual(result['block_result'],'unavailable')
        for site in ("a.com';Get-Item HKLM:", 'https://example.com', 'blocked.labguard-check.invalid.'):
            with self.subTest(site=site), self.assertRaises(RemoteError): self.exercise(site=site)
