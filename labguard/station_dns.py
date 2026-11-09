"""DNS diagnostics and reversible adapter configuration on an authenticated station."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import json
import secrets
import re
from time import monotonic

from .local_dns import CHECK_DOMAIN, DNSError, validate_config
from .remote import RemoteError

# All injected values are JSON data. Only fixed operations exist in the script.
_WINDOWS = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PARAMS__')) | ConvertFrom-Json
$backupKey = 'HKLM:\SOFTWARE\LabGuard\StationDNS'
function Result($ok,$message) { return @{ok=$ok;message=$message} }
function Test-Txt($server) {
    $name = [guid]::NewGuid().ToString('N') + '.labguard-check.test.'
    $options = @{Name=$name;Type='TXT';DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
    if ($server) {$options.Server=$server}
    try {
        $records = @(Resolve-DnsName @options | Where-Object {
            ([string]$_.Type -in @('TXT','16')) -and ([string]$_.Name).TrimEnd('.') -ieq $name.TrimEnd('.')
        })
        if ($records.Count -eq 1 -and ($records[0].Strings -join '') -ceq $p.token) {return 'ok'}
        if ($records.Count) {return 'different'}
        return 'failed'
    } catch {
        if ($_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR' -or $_.Exception.NativeErrorCode -eq 9003) {return 'nxdomain'}
        if ($_.FullyQualifiedErrorId -match 'TIMEOUT|TIMED_OUT' -or $_.Exception.NativeErrorCode -eq 1460) {return 'timeout'}
        return 'failed'
    }
}
function Netsh-Read($family,$index) {
    $v = @(& "$env:SystemRoot\System32\netsh.exe" interface $family show dnsservers "name=$index" 2>&1)
    if ($LASTEXITCODE -ne 0) {throw 'Leitura do modo DNS indisponivel.'}
    # Match a server-mode heading, never the adapter's quoted display name.
    $head = @($v | Where-Object {$_ -match '^\s+[^"\r\n]*\bDHCP\b[^"\r\n:]*:'})
    if ($head.Count -eq 1) {return 'auto'}
    $head = @($v | Where-Object {$_ -match '^\s+[^"\r\n]*(statically|estaticamente|est[aá]tic[oa]s?)[^"\r\n:]*:'})
    if ($head.Count -eq 1) {return 'static'}
    throw 'Modo automatico ou estatico nao reconhecido neste Windows.'
}
function Get-State {
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $p.target -ErrorAction Stop | Where-Object {$_.AddressState -eq 'Preferred'})
    if ($ips.Count -ne 1) {throw 'Adaptador ambiguo.'}
    $adapter = Get-NetAdapter -InterfaceIndex $ips[0].InterfaceIndex -ErrorAction Stop
    if ($adapter.Status -ne 'Up') {throw 'Adaptador inativo.'}
    $i = $adapter.ifIndex
    $client = Get-DnsClient -InterfaceIndex $i -ErrorAction Stop
    $reg = if (-not $client.RegisterThisConnectionsAddress) {'none'} elseif ($client.UseSuffixWhenRegistering) {'both'} else {'primary'}
    $state = [ordered]@{target=$p.target;guid=([guid]$adapter.InterfaceGuid).ToString();index=[int]$i;adapter=[string]$adapter.Name;register=$reg}
    foreach ($family in @('ipv4','ipv6')) {
        $mode = Netsh-Read $family $i
        $servers = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily $family -ErrorAction Stop).ServerAddresses | Where-Object {$_})
        if ($servers.Count -gt 12) {throw 'Lista grande.'}
        foreach ($item in $servers) {
            $addr=[IPAddress]::Parse($item)
            if (($family -eq 'ipv4') -ne ($addr.AddressFamily -eq 'InterNetwork')) {throw 'Familia de endereco divergente.'}
        }
        $state[$family]=[ordered]@{mode=$mode;servers=$servers}
    }
    return [pscustomobject]$state
}
function Same-Family($a,$b) {
    if ($a.mode -ne $b.mode) {return $false}
    if ($a.mode -eq 'auto') {return $true}
    return (($a.servers -join ',') -ceq ($b.servers -join ','))
}
function Same-Adapter($a,$b) {
    return ($a.target -eq $b.target -and $a.guid -eq $b.guid -and $a.index -eq $b.index -and $a.register -eq $b.register)
}
function Set-Family($state,$family,$setting) {
    $argsList = @('interface',$family,'set','dnsservers',('name='+$state.index),('register='+$state.register))
    if ($setting.mode -eq 'auto') { $argsList += 'source=dhcp' }
    elseif ($setting.mode -eq 'static') {
        $first = if ($setting.servers.Count) {[string]$setting.servers[0]} else {'none'}
        $argsList += @('source=static',('address='+$first),'validate=no')
    } else {throw 'Origem desconhecida.'}
    $null = & "$env:SystemRoot\System32\netsh.exe" @argsList 2>&1
    if ($LASTEXITCODE -ne 0) {throw 'O Windows recusou a configuracao DNS.'}
    if ($setting.mode -eq 'static') {
        for ($n=1;$n -lt $setting.servers.Count;$n++) {
            $null = & "$env:SystemRoot\System32\netsh.exe" interface $family add dnsservers ('name='+$state.index) ('address='+$setting.servers[$n]) ('index='+($n+1)) validate=no 2>&1
            if ($LASTEXITCODE -ne 0) {throw 'Lista DNS recusada.'}
        }
    }
}
function Read-Backup {
    if (-not (Test-Path -LiteralPath $backupKey)) {return $null}
    $acl=Get-Acl -LiteralPath $backupKey
    $trusted=@('S-1-5-18','S-1-5-32-544')
    foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ([int]$rule.RegistryRights -band 0xd0026) -and $rule.IdentityReference.Value -notin $trusted) {throw 'A copia de DNS exige uma chave de Registro protegida.'}
    }
    $saved = (Get-Item -LiteralPath $backupKey).GetValue('Pending')
    if ($null -eq $saved) {return $null}
    return ($saved | ConvertFrom-Json)
}
function Store-Backup($saved) {
    if (!(Test-Path -LiteralPath $backupKey)) {
        $null=New-Item -Path $backupKey -Force
        $acl=Get-Acl -LiteralPath $backupKey
        $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)')
        Set-Acl -LiteralPath $backupKey -AclObject $acl
    }
    $null=New-ItemProperty -LiteralPath $backupKey -Name Pending -PropertyType String -Value ($saved | ConvertTo-Json -Depth 7 -Compress) -ErrorAction Stop
}
function Update-Backup($saved) {
    Set-ItemProperty -LiteralPath $backupKey -Name Pending -Value ($saved | ConvertTo-Json -Depth 7 -Compress) -ErrorAction Stop
}
function Remove-Backup {Remove-ItemProperty -LiteralPath $backupKey -Name Pending -ErrorAction Stop}
function Desired($family) {
    $servers = if ($family -eq 'ipv4') { @($p.listen) } else { @() }
    return [pscustomobject]@{mode='static';servers=@($servers | Where-Object {$_})}
}
function Restore-Settings($saved) {
    $now = Get-State
    if ($saved.listen -ne $p.listen -or !(Same-Adapter $now $saved.before)) {throw 'Outro destino.'}
    # Preserve changes performed independently by the school administrator.
    foreach ($family in @('ipv4','ipv6')) {
        if (Same-Family $now.$family $saved.before.$family) {continue}
        # netsh restores a static list with one set and ordered additions. A retry
        # may resume an exact partial list only after the restore journal starts.
        $cur=$now.$family
        $orig=$saved.before.$family
        if ($saved.restoring -and $cur.mode -eq 'static' -and $orig.mode -eq 'static' -and $cur.servers.Count -gt 0 -and $cur.servers.Count -lt $orig.servers.Count) {
            $prefix=@($orig.servers[0..($cur.servers.Count-1)])
            if (($cur.servers -join ',') -ceq ($prefix -join ',')) {continue}
        }
        if ($null -ne $saved.after) {
            if (Same-Family $now.$family $saved.after.$family) {continue}
        } else {
            if (Same-Family $now.$family (Desired $family)) {continue}
            # A completed 'static none' may be exposed as auto with an empty list.
            if ($family -eq 'ipv6' -and $now.ipv6.mode -eq 'auto' -and $now.ipv6.servers.Count -eq 0) {continue}
        }
        throw 'DNS modificado por outra politica.'
    }
    $saved.restoring=$true
    Update-Backup $saved
    foreach ($family in @('ipv6','ipv4')) {
        if (!(Same-Family $now.$family $saved.before.$family)) {Set-Family $now $family $saved.before.$family}
    }
    $now = Get-State
    foreach ($family in @('ipv4','ipv6')) {
        if (!(Same-Family $now.$family $saved.before.$family)) {throw 'Restauracao nao confirmada.'}
    }
    Remove-Backup
}
function Manage {
    $state = Get-State
    if ($p.action -eq 'restore') {
        $saved = Read-Backup
        if ($null -eq $saved) {return Result $false 'Nenhuma copia de DNS do LabGuard foi encontrada nesta estacao.'}
        Restore-Settings $saved
        return Result $true 'DNS anterior restaurado e conferido no adaptador.'
    }
    if (Read-Backup) {return Result $false 'Ja existe uma copia pendente nesta estacao. Use Restaurar antes de uma nova alteracao.'}
    if ($p.action -eq 'preview') {return @{ok=$true;state=$state}}
    if ($p.action -ne 'apply') {throw 'Operacao invalida.'}
    if (!(Same-Adapter $state $p.expected) -or !(Same-Family $state.ipv4 $p.expected.ipv4) -or !(Same-Family $state.ipv6 $p.expected.ipv6)) {
        return Result $false 'A configuracao mudou. Gere uma nova previa.'
    }
    if ((Test-Txt $p.listen) -ne 'ok') {return Result $false 'O filtro nao respondeu com o codigo atual ao teste direto. Confira acesso, firewall e UDP/TCP 53.'}
    $saved = [pscustomobject]@{before=$state;listen=$p.listen;after=$null;restoring=$false}
    Store-Backup $saved
    try {
        Set-Family $state 'ipv4' (Desired 'ipv4')
        Set-Family $state 'ipv6' (Desired 'ipv6')
        $after=Get-State
        if (!(Same-Adapter $state $after)) {throw 'Identidade mudou.'}
        if (!(Same-Family $after.ipv4 (Desired 'ipv4')) -or $after.ipv6.servers.Count -gt 0) {throw 'Outro DNS em uso.'}
        $saved.after=$after
        Update-Backup $saved
        if ((Test-Txt $null) -ne 'ok') {throw 'Teste padrao falhou.'}
        return Result $true 'DNS configurado. O teste padrao da estacao retornou o codigo atual do filtro. A copia anterior permite restaurar.'
    } catch {
        try {Restore-Settings $saved;return Result $false 'A aplicacao ou o teste padrao falhou. O DNS anterior foi restaurado e conferido.'}
        catch {return Result $false 'Restauracao nao confirmada. A copia foi mantida na estacao. Reconecte e use Restaurar.'}
    }
}
# LABGUARD_ACTION
if ($p.action -eq 'test') {
    $result=@{direct=(Test-Txt $p.listen);default=(Test-Txt $null)}
} else {
    $guard=$null; $locked=$false
    try {
        $guard = New-Object Threading.Mutex($false,'Global\LabGuardStationDNS')
        try {$locked=$guard.WaitOne(3000)} catch [Threading.AbandonedMutexException] {$locked=$true}
        if (!$locked) {throw 'Outra operacao.'}
        $result=Manage
    } catch { $result=Result $false 'Nao foi possivel confirmar a configuracao do adaptador. Confira permissao, modo DNS, identidade do adaptador e alteracoes de outras politicas. Se houver copia pendente, reconecte e use Restaurar.' }
    finally {if ($locked) {$guard.ReleaseMutex()};if ($guard) {$guard.Dispose()}}
}
$result | ConvertTo-Json -Depth 7 -Compress
'''


def _windows_script(action, *, target, listen, token, expected=None):
    if action not in {'test', 'preview', 'apply', 'restore'}:
        raise RemoteError('Operação remota de DNS inválida.')
    params = dict(action=action, target=target, listen=listen, token=token, expected=expected)
    data = json.dumps(params, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    script = _WINDOWS.replace('__PARAMS__', base64.b64encode(data).decode('ascii'))
    if len(base64.b64encode(script.encode('utf-16le'))) > 32000:
        raise RemoteError('A configuração desta estação excede o limite do Windows para uma operação remota segura.')
    return script


_LINUX_TEST = r'''
import json
import os
import re
import subprocess
p = __PARAMS__
executable = next((s for s in ('/usr/bin/dig', '/bin/dig') if os.path.isfile(s)), None)
def test(server):
    if executable is None:
        return 'unavailable'
    args = [executable, '-r', '+time=2', '+tries=1', '+noall', '+comments', '+answer']
    if server:
        args.append('@' + server)
    args.extend(['labguard-check.invalid.', 'TXT'])
    try:
        out = subprocess.run(args, capture_output=True, timeout=5, check=False, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    except subprocess.TimeoutExpired:
        return 'timeout'
    text = out.stdout[:8192].decode('ascii','replace')
    if re.search(r'status:\s*NXDOMAIN\b', text):
        return 'nxdomain'
    if out.returncode == 9 or 'timed out' in text:
        return 'timeout'
    if out.returncode or not re.search(r'status:\s*NOERROR\b', text):
        return 'failed'
    records = re.findall(r'^labguard-check\.invalid\.\s+\d+\s+IN\s+TXT\s+"([^"\n]*)"\s*$', text, re.MULTILINE|re.IGNORECASE)
    if records == [p['token']]:
        return 'ok'
    return 'different' if records else 'failed'
print(json.dumps({'direct':test(p['listen']), 'default':test(None)}))
'''


def _status_summary(direct, default):
    if direct == 'ok' and default == 'ok':
        return 'A estação alcançou o filtro diretamente e pelo DNS padrão com o código atual.'
    if direct == 'ok':
        return 'A estação alcançou o filtro pelo IP. O DNS padrão seguiu outro caminho ou falhou. Confira os servidores IPv4 e IPv6 da estação.'
    if default == 'ok':
        return 'O DNS padrão da estação alcançou a sessão atual do filtro. A consulta direta ao IP falhou ou apresentou outro código.'
    if 'unavailable' in (direct, default):
        return 'O teste por SSH requer o comando dig no Linux da estação.'
    if 'different' in (direct, default):
        return 'A estação recebeu outro código TXT. Confira o IP e a sessão atual do filtro antes de aplicar DNS.'
    if direct == 'timeout':
        return 'O endereço do filtro não respondeu à estação dentro do prazo. Confira IP, rede autorizada e firewall UDP/TCP 53.'
    return 'Nenhum dos caminhos retornou o código esperado. Confira o IP do filtro, os servidores DNS da estação e a conectividade.'


@dataclass(frozen=True)
class _StationPlan:
    id: str
    deadline: float
    target: str
    listen: str
    network: str
    token: str
    state_json: str


class StationDNS:
    def __init__(self, session, *, listen, network, token):
        try:
            # Resolver value is not used for this operation; use a distinct literal
            # only when checking the listener/subnet constraints of the existing filter.
            upstream = '1.0.0.1' if listen == '1.1.1.1' else '1.1.1.1'
            self.listen, subnet, _, _, _ = validate_config(listen, network, upstream)
            target = ipaddress.IPv4Address(session.host)
            if subnet.is_loopback or target not in subnet or target in {subnet.network_address, subnet.broadcast_address} or str(target) == self.listen:
                raise ValueError('target')
            if session.platform not in ('windows', 'linux') or not isinstance(token, str) or not re.fullmatch(r'LabGuard-[0-9a-f]{16}',token):
                raise ValueError('session')
        except (ValueError, TypeError, DNSError, AttributeError) as error:
            raise RemoteError('Escolha uma estação do segmento autorizado, distinta do PC do filtro, e abra o DNS local ativo.') from error
        self.session = session
        self.network = str(subnet)
        self.target = str(target)
        self.token = token
        self._plan = None

    def _run(self, action, expected=None):
        with self.session._operation:
            self.session._check()
            if self.session.platform == 'windows':
                result = self.session._ps(_windows_script(action, target=self.target, listen=self.listen, token=self.token, expected=expected))
            elif action == 'test':
                data = repr({'listen':self.listen,'token':self.token})
                result = self.session._python(_LINUX_TEST.replace('__PARAMS__', data), timeout=20)
            else:
                raise RemoteError('O ajuste de DNS por este painel está disponível em estações Windows. O Linux oferece o teste via SSH.')
            self.session._check()
        if not isinstance(result, dict):
            raise RemoteError('Resposta inválida da estação.')
        return result

    def test(self, blocked_domain=None, *, read_evidence=None):
        from .station_block_probe import applied_hostname, test_applied_domain
        if blocked_domain is not None:
            blocked_domain = applied_hostname(blocked_domain)
        result = self._run('test')
        direct, default = result.get('direct'), result.get('default')
        statuses = {'ok','different','timeout','nxdomain','failed','unavailable'}
        if not isinstance(direct, str) or not isinstance(default, str) or direct not in statuses or default not in statuses:
            raise RemoteError('Resposta do diagnóstico remoto inválida.')
        diagnostic = {'ok': direct == default == 'ok', 'direct':direct, 'default':default,
                      'message':_status_summary(direct, default)}
        if blocked_domain is not None:
            block = test_applied_domain(self, diagnostic, blocked_domain, read_evidence)
            diagnostic.update(block)
            diagnostic['message'] += ' ' + block['block_evidence']
        return diagnostic

    @staticmethod
    def _outcome(raw):
        message = raw.get('message')
        if type(raw.get('ok')) is not bool or not isinstance(message, str) or not message or len(message)>480 or not message.isprintable():
            raise RemoteError('A estação retornou um resultado inválido. Confira o estado antes de repetir.')
        return {'ok':raw['ok'], 'message':message}

    def preview(self):
        self._plan = None
        raw = self._run('preview')
        if raw.get('ok') is not True:
            raise RemoteError(self._outcome(raw)['message'])
        state = raw.get('state')
        try:
            if not isinstance(state,dict) or len(state) != 7 or state['target'] != self.target or not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',state['guid']):
                raise ValueError()
            if type(state['index']) is not int or not 0 < state['index'] < 2**31 or state['register'] not in ('both','primary','none'):
                raise ValueError()
            name = state['adapter']
            if not isinstance(name,str) or not 0 < len(name) <= 128 or not name.isprintable():
                raise ValueError()
            for version in (4, 6):
                family = state['ipv'+str(version)]
                if family['mode'] not in ('auto','static') or not isinstance(family['servers'],list) or len(family['servers']) > 12:
                    raise ValueError()
                for address in family['servers']:
                    if not isinstance(address,str) or len(address)>64 or ipaddress.ip_address(address).version != version:
                        raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise RemoteError('A estação não confirmou um adaptador e uma configuração DNS restauráveis.') from None
        # Check the Windows process limit during preview, before offering Apply.
        _windows_script('apply', target=self.target, listen=self.listen, token=self.token, expected=state)
        self._plan = _StationPlan(secrets.token_urlsafe(24), monotonic()+60, self.target, self.listen, self.network, self.token, json.dumps(state))
        current = ' • '.join(f'{field.upper()} ({state[field]["mode"]}): ' + (', '.join(state[field]['servers']) or '—') for field in ('ipv4','ipv6'))
        return {'id':self._plan.id, 'target':self.target, 'adapter':name,
                'message': f'{current}\nSubstituir os servidores DNS de {name} ({self.target}) pelo filtro {self.listen}? A mudança afeta consultas IPv4 e IPv6 e pode afetar nomes internos da escola. O DNS anterior ficará salvo na estação para restauração.'}

    def take_preview(self):
        plan, self._plan = self._plan, None
        if plan is None:
            raise RemoteError('Prepare o adaptador antes de continuar.')
        return plan

    def resume_preview(self, plan):
        if not isinstance(plan, _StationPlan) or monotonic() >= plan.deadline or (self.target, self.listen, self.network, self.token) != (plan.target,plan.listen,plan.network,plan.token) or self.session.platform != 'windows':
            raise RemoteError('A prévia expirou ou pertence a outro destino. Prepare uma nova prévia.')
        self._plan = plan
        return plan.id

    def apply(self, preview_id):
        plan = self.take_preview()
        if monotonic() >= plan.deadline or not isinstance(preview_id,str) or not preview_id.isascii() or not secrets.compare_digest(plan.id, preview_id):
            raise RemoteError('Prévia inválida ou expirada. Prepare o adaptador novamente.')
        try:
            return self._outcome(self._run('apply', json.loads(plan.state_json)))
        except RemoteError as error:
            raise RemoteError('A aplicação ficou sem confirmação. Reconecte à mesma estação e use Restaurar antes de repetir.') from error

    def restore(self):
        self._plan = None
        return self._outcome(self._run('restore'))
