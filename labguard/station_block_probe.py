"""Verify an applied domain from one authenticated station and its active DNS listener."""
from __future__ import annotations

from datetime import datetime, timezone

from .demo import normalize_domain
from .remote import RemoteError

_WINDOWS_A = r'''
# LABGUARD_BLOCK_PROBE
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$domain='__DOMAIN__.'
$state='failed'
try {
    $answers=@(Resolve-DnsName -Name $domain -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
    foreach ($record in $answers) {
        if ([string]$record.Type -in @('A','1') -and $record.IPAddress) {$state='resolved';break}
    }
} catch {
    if ($_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR' -or $_.Exception.NativeErrorCode -eq 9003) {$state='nxdomain'}
    elseif ($_.FullyQualifiedErrorId -match 'TIMEOUT|TIMED_OUT' -or $_.Exception.NativeErrorCode -eq 1460) {$state='timeout'}
}
@{status=$state} | ConvertTo-Json -Compress
'''


_LINUX_A = r'''
import ipaddress, json, os, re, subprocess
domain = '__DOMAIN__'
exe = next((p for p in ('/usr/bin/dig','/bin/dig') if os.path.isfile(p)), None)
status = 'unavailable'
if exe:
    try:
        p = subprocess.run([exe, '-r', '+time=2', '+tries=1', '+noall', '+comments', '+answer', domain+'.', 'A'],
                           capture_output=True, check=False, timeout=5, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        output = p.stdout[:8192].decode('ascii', 'replace')
        status = 'failed'
        if re.search(r'status:\s*NXDOMAIN\b', output):
            status = 'nxdomain'
        elif p.returncode == 9 or 'timed out' in output:
            status = 'timeout'
        elif not p.returncode and re.search(r'status:\s*NOERROR\b', output):
            for addr in re.findall(r'^\S+\s+\d+\s+IN\s+A\s+(\S+)\s*$', output, re.M | re.I):
                if ipaddress.IPv4Address(addr):
                    status = 'resolved'
                    break
    except subprocess.TimeoutExpired:
        status = 'timeout'
    except (ValueError, OSError):
        status = 'failed'
print(json.dumps({'status': status}))
'''


def applied_hostname(value):
    try:
        name = normalize_domain(value)
    except ValueError as error:
        raise RemoteError("Escolha um domínio válido da lista aplicada.") from error
    if name.endswith(('.invalid', '.localhost', '.arpa')):
        raise RemoteError("Escolha um domínio de site da lista aplicada.")
    return name


def query_station(session, domain):
    # normalize_domain permits only ASCII DNS labels; no shell metacharacters.
    domain = applied_hostname(domain)
    with session._operation:
        session._check()
        if session.platform == 'windows':
            raw = session._ps(_WINDOWS_A.replace('__DOMAIN__', domain))
        else:
            raw = session._python(_LINUX_A.replace('__DOMAIN__', domain), timeout=15)
        session._check()
    status = raw.get('status') if isinstance(raw, dict) else None
    return status if status in {'resolved','nxdomain','failed','unavailable','timeout'} else 'failed'


def rule_is_active(snapshot, domain, token):
    if not isinstance(snapshot, dict) or snapshot.get('source_type') != 'local_dns':
        return False
    service = snapshot.get('dns_service', {})
    if service.get('service_running') is not True or service.get('check_token') != token:
        return False
    return any(isinstance(row, dict) and row.get('domain') == domain for row in snapshot.get('domains', []))


def event_confirms(snapshot, *, domain, target, token, started, ended):
    if not rule_is_active(snapshot, domain, token):
        return False
    for event in snapshot.get('events', []):
        if not isinstance(event, dict) or event.get('domain') != domain or event.get('client_ip') != target:
            continue
        if event.get('query_type') != 'A' or event.get('status') != 'Bloqueio DNS confirmado':
            continue
        try:
            seen = datetime.fromisoformat(event['time'])
            if started <= seen <= ended:
                return True
        except (KeyError, TypeError, ValueError):
            continue
    return False


def test_applied_domain(station, diagnostic, domain, read_evidence=None):
    domain = applied_hostname(domain)
    try:
        active = read_evidence is not None and rule_is_active(read_evidence(), domain, station.token)
    except Exception:
        active = False
    if not active:
        return {'blocked_domain': domain, 'block_result': 'unavailable', 'block_confirmed': False,
                'block_evidence': 'A regra ou a sessão atual do filtro precisa ser confirmada para consultar o domínio.'}
    started = datetime.now(timezone.utc)
    status = query_station(station.session, domain)
    ended = datetime.now(timezone.utc)
    confirmed = False
    if diagnostic['ok'] and status == 'nxdomain' and read_evidence is not None:
        try:
            confirmed = event_confirms(read_evidence(), domain=domain, target=station.target,
                                       token=station.token, started=started, ended=ended)
        except Exception:
            # A lost controller connection cannot turn a DNS answer into proof.
            confirmed = False
    if confirmed:
        message = f'Bloqueio de {domain} confirmado. A estação recebeu NXDOMAIN e o filtro registrou a consulta A deste IP durante o teste.'
    elif status == 'nxdomain':
        message = f'A estação recebeu NXDOMAIN para {domain}. A atribuição ao filtro ficou sem confirmação.'
    elif status == 'resolved':
        message = f'O DNS padrão da estação retornou um endereço para {domain}. Confira os servidores DNS usados pela estação.'
    else:
        message = f'A consulta A para {domain} ficou sem resposta verificável.'
    return {'blocked_domain': domain, 'block_result': status, 'block_confirmed': confirmed,
            'block_evidence': message}
