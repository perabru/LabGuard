"""Prepare WinRM HTTPS through an existing domain-authenticated DCOM channel."""
from __future__ import annotations

import base64
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

from .access_setup import prepare_access
from .remote import RemoteError
from .station_policy import station_target_from_snapshot
from .transport import OutputLimitExceeded, run_bounded

# Credentials enter the Windows process through stdin only. WMI APIs perform
# mutual Kerberos authentication to the requested machine principal and seal RPC.
_PUSH = r'''
$ErrorActionPreference='Stop'
[Console]::InputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$p=[Console]::In.ReadToEnd() | ConvertFrom-Json
$stage='identity'
try {
    $addresses=@([Net.Dns]::GetHostAddresses($p.hostname) | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | ForEach-Object {$_.IPAddressToString} | Select-Object -Unique)
    if ($addresses.Count -ne 1 -or $addresses[0] -ne $p.target) {throw 'DNS'}
    $short=$p.hostname.Split('.')[0]
    $accountDomain=$p.user.Split('\')[0]
    $secret=ConvertTo-SecureString -String $p.password -AsPlainText -Force
    $p.password=$null
    $cred=New-Object Management.Automation.PSCredential($p.user,$secret)
    $wmi=@{ComputerName=$p.hostname;Credential=$cred;Authority="Kerberos:$accountDomain\$short";Authentication='PacketPrivacy';Impersonation='Impersonate';ErrorAction='Stop'}
    $system=Get-WmiObject -Class Win32_ComputerSystem @wmi
    $actual=([string]$system.DNSHostName) + '.' + ([string]$system.Domain)
    if ($system.PartOfDomain -ne $true -or $system.DomainRole -ne 1 -or $actual -ine $p.hostname -or $system.Name -ine $short) {throw 'FQDN'}
    $adapters=@(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' @wmi | Where-Object {@($_.IPAddress) -contains $p.target})
    if ($adapters.Count -ne 1) {throw 'IPv4'}
    $observedMac=([string]$adapters[0].MACAddress).Replace('-',':')
    if ($p.macs.Count -gt 0 -and $observedMac -notin $p.macs) {throw 'Adapter identity'}
    $windows=(Get-WmiObject -Class Win32_OperatingSystem @wmi).WindowsDirectory
    if ($windows -notmatch '^[a-zA-Z]:\\[^"\r\n]+$') {throw 'Windows'}
    $registry=Get-WmiObject -List -Class StdRegProv -Namespace 'root\default' @wmi
    $process=Get-WmiObject -List -Class Win32_Process @wmi
    $command='"'+$windows+'\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -EncodedCommand '+$p.encoded
    if ($command.Length -gt 32500) {throw 'Size'}
    $stage='submitted'
    $launch=$process.Create($command,$null,$null)
    if ($launch.ReturnValue -ne 0 -or !$launch.ProcessId) {throw 'Create'}
    $limit=[DateTime]::UtcNow.AddSeconds(44)
    $value=$null
    do {
        Start-Sleep -Milliseconds 650
        $read=$registry.GetStringValue([uint32]2147483650,'SOFTWARE\LabGuard\AccessReceipts',$p.receipt)
        if ($read.ReturnValue -eq 0) {$value=$read.sValue}
    } until ($null -ne $value -or [DateTime]::UtcNow -ge $limit)
    if ($null -ne $value) {$null=$registry.DeleteValue([uint32]2147483650,'SOFTWARE\LabGuard\AccessReceipts',$p.receipt)}
    if ($value -ne 'ok') {if ($value -eq 'failed') {$stage='bootstrap'};throw 'Receipt'}
    $stage='https'
    # Test-WSMan validates the server certificate using Windows trust and the
    # literal station IP, with an authenticated Identify request to port 5986.
    $identify=Test-WSMan -ComputerName $p.target -Port 5986 -UseSSL -Authentication Negotiate -Credential $cred -ErrorAction Stop
    if (!$identify -or !$identify.ProtocolVersion) {throw 'WSMan'}
    $stage='ready'
} catch {
    # Return only fixed status codes. Native errors may carry account names.
} finally {
    if ($secret) {$secret.Dispose()}
    $cred=$null; $p=$null
}
@{stage=$stage} | ConvertTo-Json -Compress
'''

_MESSAGES = {
    'ready': 'Preparo confirmado. O WinRM HTTPS da estação respondeu na porta 5986 com certificado validado. Conecte pelo painel.',
    'identity': 'A identidade da estação ou o canal WMI/DCOM com Kerberos não foi confirmado. Confira FQDN, IPv4, conta DOMÍNIO\\usuário e permissões. A TI também pode distribuir o preparo por GPO ou MDM.',
    'submitted': 'O resultado do preparo por WMI ficou sem confirmação. Confira o acesso HTTPS antes de uma nova tentativa.',
    'bootstrap': 'A estação recusou o preparo. Confira o certificado de computador confiável com o IPv4 no SAN, a rota da TI, o perfil de rede e a política do WinRM. O preparo também pode ser distribuído por GPO ou MDM.',
    'https': 'O script terminou na estação, mas o WinRM HTTPS não respondeu com certificado validado. Confira confiança da CA, porta 5986 e firewall da TI.',
}


def _remote_job(template, target, receipt):
    # The selected endpoint must also own the address chosen by its return route
    # to the management PC. The fixed bootstrap independently checks its profile.
    script = "\n".join([
        "$ErrorActionPreference='Stop'",
        "$result='failed'",
        'try {',
        f"$route=@(Find-NetRoute -RemoteIPAddress '{target.listen}' | Where-Object {{$_.PSObject.Properties['IPAddress'] -and $_.IPAddress}})",
        f"if ($route.Count -ne 1 -or [string]$route[0].IPAddress -ne '{target.address}') {{throw 'Route'}}",
        '& {', template, '}', "$result='ok'", '} catch {}',
        "$key='HKLM:\\SOFTWARE\\LabGuard\\AccessReceipts'",
        'if (!(Test-Path -LiteralPath $key)) {$null=New-Item -Path $key -Force}',
        f"$null=New-ItemProperty -LiteralPath $key -Name '{receipt}' -PropertyType String -Value $result -Force",
    ])
    encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
    if len(encoded)>31500:
        raise RemoteError('O script de preparo excede o limite do processo Windows.')
    return encoded


def _powershell_path():
    # Credentials are posted to stdin of the system binary. Do not resolve the
    # interpreter from PATH or a user-controlled SystemRoot environment value.
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise RemoteError('O Windows não informou o diretório do PowerShell de sistema.')
    return str(Path(buffer.value) / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe')


def prepare_remote_access(snapshot, payload, assets):
    if not isinstance(payload,dict) or set(payload) != {'host','hostname','user','password','confirm'} or payload.get('confirm') is not True:
        raise RemoteError('Confira o destino e confirme o preparo remoto por WMI.')
    target=station_target_from_snapshot(snapshot,payload.get('host'),for_change=True)
    hostname=payload['hostname']
    user=payload['user']
    password=payload['password']
    if not isinstance(hostname,str) or len(hostname)>253 or '.' not in hostname or re.fullmatch(r'[0-9.]+',hostname) or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in hostname.split('.')):
        raise RemoteError('Informe o FQDN canônico da estação no domínio, por exemplo pc01.escola.local.')
    if not isinstance(user,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,14}\\[^\\/\x00-\x1f\x7f]{1,120}',user) or not isinstance(password,str) or not 1<=len(password)<=1024 or '\x00' in password:
        raise RemoteError('Informe a conta DOMÍNIO\\usuário do domínio da estação e sua senha de sessão.')
    if os.name!='nt':
        raise RemoteError('O preparo direto por WMI requer o painel em Windows. Use o script de computador pela GPO ou pelo MDM da escola.')
    receipt=secrets.token_hex(16)
    job=_remote_job(prepare_access({'management_ip':target.listen},assets)['script'],target,receipt)
    body=json.dumps({'hostname':hostname,'target':target.address,'macs':target.macs,'user':user,'password':password,'receipt':receipt,'encoded':job}, ensure_ascii=True)
    command=[_powershell_path(),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(_PUSH.encode('utf-16le')).decode('ascii')]
    try:
        finished=run_bounded(command,input=body,timeout=85,max_output_bytes=16384)
        status=json.loads(finished.stdout).get('stage') if finished.returncode==0 else None
    except (OSError,ValueError,AttributeError,OutputLimitExceeded,subprocess.TimeoutExpired):
        status=None
    del body, password
    if not isinstance(status, str) or status not in _MESSAGES:
        raise RemoteError('O preparo ficou sem confirmação. Confira o WinRM HTTPS e a estação antes de repetir.')
    return {'ok':status=='ready','message':_MESSAGES[status]}
