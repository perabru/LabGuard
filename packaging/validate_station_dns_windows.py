"""Exercise station PowerShell on a synthetic Windows network configuration in CI.

The generated station script runs on Windows PowerShell 5.1. A per-test
adapter and its backup exist only in a temporary directory. DNS responses
come from our loopback-only listener; no resolver on the runner is changed.
"""
from __future__ import annotations

import base64
import json
import os
import ipaddress
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from labguard.local_dns import DNSFilter, DNSError
from labguard.remote import RemoteError, WindowsSession, _Session

TARGET = "192.168.45.17"
LISTEN = "192.168.45.3"
NETWORK = "192.168.45.0/24"
MARKER = "# LABGUARD_ACTION"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class NativeFixture(WindowsSession):
    """Replace the WinRM boundary with a local Windows PowerShell process."""

    def __init__(self, directory, dns_host):
        _Session.__init__(self, TARGET, "windows")
        self.directory = Path(directory)
        self.dns_host = dns_host
        self.trace_path = self.directory / "dns-trace.log"
        self.powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        self.state_path = self.directory / "fixture.json"

    def save(self, data):
        self.state_path.write_text(json.dumps(data), encoding="utf-8")

    def read(self):
        return json.loads(self.state_path.read_text(encoding="utf-8-sig"))

    def _ps(self, script):
        encoded_length = len(base64.b64encode(script.encode("utf-16le")))
        require(encoded_length + 200 < 32767, "Encoded station command exceeds Windows process limit")
        if "# LABGUARD_BLOCK_PROBE" in script:
            require(script.count("Resolve-DnsName") == 1 and NETSH not in script,
                    "Unexpected native command in A probe")
            script = DNS_FIXTURE + script.replace("Resolve-DnsName", "Invoke-FixtureDns")
        else:
            require(script.count(MARKER) == 1, "Station action boundary missing")
            require(script.count(NETSH) == 3, "Missing or new netsh entry point; review fixture isolation")
            registry_key = r"'HKLM:\SOFTWARE\LabGuard\StationDNS'"
            require(script.count(registry_key) == 1, "Review station backup fixture isolation")
            # An accidental call to an unmocked backup command cannot reach HKLM.
            script = script.replace(registry_key, r"'LabGuardFixture:\unavailable'")
            script = script.replace(NETSH, 'Invoke-FixtureNetsh')
            require(script.count("Resolve-DnsName") == 1, "Review station lookup fixture isolation")
            script = script.replace("Resolve-DnsName", "Invoke-FixtureDns")
            script = script.replace(MARKER, FIXTURE_POWERSHELL + "\n" + DNS_FIXTURE + "\n" + MARKER)
        path = self.directory / "station-fixture.ps1"
        prelude = """
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Windows PowerShell 5.1 required'
}
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
"""
        path.write_text(prelude + script, encoding="utf-8-sig")
        completed = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(path)],
            cwd=self.directory,
            env={**os.environ, "LABGUARD_STATION_FIXTURE": str(self.state_path),
                 "LABGUARD_STATION_LOOPBACK": self.dns_host, "LABGUARD_DNS_TRACE": str(self.trace_path)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False,
        )
        if completed.returncode:
            # Inputs are synthetic and confined to the loopback fixture.
            hint = completed.stderr.decode("utf-8", errors="replace")[:1500]
            raise RemoteError(f"Windows fixture returned {completed.returncode}: {hint}")
        result = json.loads(completed.stdout.decode("utf-8-sig"))
        require(isinstance(result, dict), "PowerShell station output must be an object")
        if result.get("ok") is False or "failed" in (result.get("direct"), result.get("default"), result.get("status")):
            trace = self.trace_path.read_text(encoding="utf-8-sig")[-1500:] if self.trace_path.exists() else "no lookup trace"
            print("Synthetic Windows station trace:", result, trace, flush=True)
        return result

# Intercept the exact netsh boundary; the production argument formatting, mode
# parser, adapter identity checks and ordered server-list handling still run.
NETSH = '"$env:SystemRoot\\System32\\netsh.exe"'

# Test the same Windows DNS cmdlet and response handling used by the application.
# Only destination selection is intercepted. Every query is sent to our listener;
# the fixture's original alternate resolver returns NXDOMAIN using a second name.
DNS_FIXTURE = r"""
function Invoke-FixtureDns {
    [CmdletBinding()]
    param([string]$Name,[string]$Type,[switch]$DnsOnly,[switch]$NoHostsFile,
          [switch]$QuickTimeout,[string]$Server)
    if (!$DnsOnly -or !$NoHostsFile -or !$QuickTimeout) {throw 'unexpected resolver options'}
    $query = $Name
    $route = 'default'
    if ($Server) {
        if ($Server -ne '192.168.45.3') {throw 'unexpected explicit server'}
        $route = 'direct'
    }
    if ($Type -eq 'A') {
        if ($Name -cne 'blocked.example.org.' -or $Server) {throw 'unexpected A probe'}
    } elseif ($Type -eq 'TXT') {
        if ($Name -cnotmatch '^[a-f0-9]{32}\.labguard-check\.test\.$') {throw 'invalid diagnostic nonce'}
        if (!$Server -and ($fixture.forceDefaultFailure -or $fixture.ipv4.mode -ne 'static' -or
            $fixture.ipv4.servers -notcontains '192.168.45.3' -or $fixture.ipv6.servers.Count)) {
            $query = $Name.Split('.')[0] + '.ci-negative.test.'
        }
    } else {throw 'unexpected query type'}
    $params = @{Name=$query;Type=$Type;Server=$env:LABGUARD_STATION_LOOPBACK;
                DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
    try {
        $answers = @(DnsClient\Resolve-DnsName @params)
        $types = @($answers | ForEach-Object {"type=$($_.Type)/$($_.QueryType) fields=$($_.PSObject.Properties.Name -join ',')"})
        [IO.File]::AppendAllText($env:LABGUARD_DNS_TRACE, "$route $Type records=$($types -join ',')`n")
        return $answers
    } catch {
        [IO.File]::AppendAllText($env:LABGUARD_DNS_TRACE, "$route $Type error=$($_.FullyQualifiedErrorId) code=$($_.Exception.NativeErrorCode)`n")
        throw
    }
}
"""

FIXTURE_POWERSHELL = r"""
$fixture = Get-Content -LiteralPath $env:LABGUARD_STATION_FIXTURE -Raw -Encoding UTF8 | ConvertFrom-Json
function Save-Fixture {
    [IO.File]::WriteAllText($env:LABGUARD_STATION_FIXTURE,
        ($fixture | ConvertTo-Json -Depth 10 -Compress), [Text.Encoding]::UTF8)
}
function Get-NetIPAddress($AddressFamily,$IPAddress,$ErrorAction) {
    if ($AddressFamily -ne 'IPv4' -or $IPAddress -ne $p.target) {throw 'unexpected fixture target'}
    [pscustomobject]@{AddressState='Preferred'; InterfaceIndex=19}
}
function Get-NetAdapter($InterfaceIndex,$ErrorAction) {
    if ($InterfaceIndex -ne 19) {throw 'unexpected adapter'}
    [pscustomobject]@{Status='Up';ifIndex=19;InterfaceGuid='4ef92f25-da91-434c-ac31-fa313ac257a8';Name='Lab CI'}
}
function Get-DnsClient($InterfaceIndex,$ErrorAction) {
    [pscustomobject]@{RegisterThisConnectionsAddress=$true;UseSuffixWhenRegistering=$false}
}
function Get-DnsClientServerAddress($AddressFamily,$InterfaceIndex,$ErrorAction) {
    [pscustomobject]@{ServerAddresses=$fixture.$AddressFamily.servers}
}
function Invoke-FixtureNetsh {
    $global:LASTEXITCODE = 0
    $family = $args[1]
    if ($args[0] -ne 'interface' -or $family -notin @('ipv4','ipv6') -or
        $args[3] -ne 'dnsservers' -or $args[4] -ne 'name=19') {throw 'unexpected netsh target'}
    $setting = $fixture.$family
    switch ($args[2]) {
        'show' {
            if ($setting.mode -eq 'auto') {'    DNS servers configured through DHCP: 192.0.2.1'}
            else {'    Statically Configured DNS Servers: 192.0.2.1'}
        }
        'set' {
            if ($args -notcontains 'register=primary') {throw 'registration changed'}
            if ($args -contains 'source=dhcp') {
                $setting.mode='auto'
                $setting.servers=@($fixture.autoServers.$family)
            } elseif ($args -contains 'source=static') {
                $setting.mode='static'
                $address = @($args | Where-Object {$_ -like 'address=*'})[0].Substring(8)
                if ($address -eq 'none') {$setting.servers=@()} else {$setting.servers=@($address)}
            } else {throw 'unexpected netsh source'}
            if ($fixture.interfereAfterSet -and $family -eq 'ipv6' -and $setting.servers.Count -eq 0) {
                $fixture.ipv4.servers=@('192.168.45.222')
            }
            Save-Fixture
        }
        'add' {
            if ($fixture.failRestoreAddOnce -and $family -eq 'ipv6') {
                $fixture.failRestoreAddOnce=$false
                Save-Fixture
                $global:LASTEXITCODE=87
                return
            }
            $address = @($args | Where-Object {$_ -like 'address=*'})[0].Substring(8)
            if ($args -notcontains ('index='+($setting.servers.Count+1))) {throw 'DNS order changed'}
            $setting.servers=@($setting.servers)+@($address)
            Save-Fixture
        }
        default {throw 'unexpected netsh operation'}
    }
}
function Read-Backup {return $fixture.backup}
function Store-Backup($saved) {
    if ($null -ne $fixture.backup) {throw 'backup overwrite'}
    $fixture.backup=$saved
    Save-Fixture
}
function Update-Backup($saved) {
    if ($null -eq $fixture.backup) {throw 'missing backup'}
    $fixture.backup=$saved
    Save-Fixture
}
function Remove-Backup {$fixture.backup=$null; Save-Fixture}

"""


def check_bootstrap(fixture):
    template_path = ROOT / "server/assets/prepare-station.ps1"
    require(template_path.is_file(), "Management bootstrap missing")
    from labguard.access_push import _PUSH, _remote_job
    launch = fixture.directory / "wmi-parse-only.ps1"
    payload = fixture.directory / "station-bootstrap-parse-only.ps1"
    launch.write_text(_PUSH, encoding="utf-8-sig")
    template = template_path.read_text(encoding="utf-8-sig").replace('__MANAGEMENT_IPV4__', LISTEN)
    encoded = _remote_job(template, SimpleNamespace(listen=LISTEN, address=TARGET), 'ci-fixture')
    payload.write_text(base64.b64decode(encoded).decode('utf-16le'), encoding="utf-8-sig")
    check = r"""
$ErrorActionPreference='Stop'
foreach ($path in @($env:LABGUARD_WMI_SCRIPT,$env:LABGUARD_WMI_PAYLOAD)) {
    $tokens=$null; $errors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) {throw ('Remote bootstrap parse error: '+$errors[0].Message)}
}
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    $env:LABGUARD_BOOTSTRAP_FILE, [ref]$tokens, [ref]$errors)
if ($errors.Count) {throw ('Bootstrap parse error: '+$errors[0].Message)}
$defs=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -in @('Read-DerLength','Test-SanAddress')},$true)
if ($defs.Count -ne 2) {throw 'Missing SAN validation functions'}
foreach($def in $defs) {. ([scriptblock]::Create($def.Extent.Text))}
function Certificate([byte[]]$bytes) {
    $ext=[System.Security.Cryptography.X509Certificates.X509Extension]::new(
        [System.Security.Cryptography.Oid]::new('2.5.29.17'),$bytes,$false)
    return [pscustomobject]@{Extensions=@($ext)}
}
$ip=[ipaddress]'192.168.45.17'
$cert=Certificate ([byte[]](48,6,135,4,192,168,45,17))
if (!(Test-SanAddress $cert $ip)) {throw 'Exact IP SAN failed'}
if (Test-SanAddress $cert ([ipaddress]'192.168.45.18')) {throw 'Accepted other IP SAN'}
$cert=Certificate ([byte[]](@(48,129,137,130,129,128)+(@(97)*128)+@(135,4,192,168,45,17)))
if (!(Test-SanAddress $cert $ip)) {throw 'Long form IP SAN failed'}
$cert=Certificate ([byte[]](48,6,130,4,192,168,45,17))
if (Test-SanAddress $cert $ip) {throw 'Accepted wrong SAN tag'}
$cert=Certificate ([byte[]](48,5,135,4,192,168,45,17))
if (Test-SanAddress $cert $ip) {throw 'Accepted malformed length'}

# Reapplying the bootstrap to an already managed host must perform no changes.
$readyCert=Certificate ([byte[]](48,6,135,4,192,168,45,17))
$readyCert | Add-Member NoteProperty HasPrivateKey $true
$readyCert | Add-Member NoteProperty NotBefore ([DateTime]::Today.AddDays(-1))
$readyCert | Add-Member NoteProperty NotAfter ([DateTime]::Today.AddDays(1))
$oids=[Security.Cryptography.OidCollection]::new()
$null=$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
$eku=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false)
$readyCert.Extensions=@($readyCert.Extensions)+@($eku)
$readyCert | Add-Member NoteProperty Thumbprint ('A'*40)
$readyCert | Add-Member ScriptMethod Verify {return $true}
$readyCert | Add-Member ScriptMethod GetNameInfo {param($which,$issuer) return 'lab-ci.invalid'}
$fixturePort='5986'
$script:fixtureMutations=0
function Reject-Write {$script:fixtureMutations++; throw 'Unexpected change in bootstrap fixture'}
function New-WSManInstance {Reject-Write}
function Remove-WSManInstance {Reject-Write}
function New-Item {Reject-Write}
function Remove-Item {Reject-Write}
function Set-Service {Reject-Write}
function Start-Service {Reject-Write}
function Stop-Service {Reject-Write}
function New-NetFirewallRule {Reject-Write}
function Remove-NetFirewallRule {Reject-Write}
function Find-NetRoute($RemoteIPAddress) {
    if ($RemoteIPAddress -ne '192.168.45.3') {throw 'Wrong management IP'}
    [pscustomobject]@{IPAddress='192.168.45.17';InterfaceIndex=19}
}
function Get-NetConnectionProfile($InterfaceIndex) {[pscustomobject]@{NetworkCategory='DomainAuthenticated'}}
function Get-ChildItem($Path) {
    if ($Path -eq 'Cert:\LocalMachine\My') {return $readyCert}
    if ($Path -eq 'WSMan:\localhost\Listener') {
        return [pscustomobject]@{Name='Fixture';Keys=@('Transport=HTTPS','Address=IP:192.168.45.17')}
    }
    throw 'Unexpected provider'
}
function Get-CimInstance($ClassName,$Filter) {[pscustomobject]@{StartMode='Auto';State='Running'}}
function Get-Item($Path) {
    if ($Path -like '*\Port') {return [pscustomobject]@{Value=5986}}
    if ($Path -like '*\CertificateThumbprint') {return [pscustomobject]@{Value=$readyCert.Thumbprint}}
    throw 'Unexpected provider property'
}
function Get-NetFirewallRule($Name,$ErrorAction) {
    [pscustomobject]@{Direction='Inbound';Action='Allow';Enabled='True';Profile='Domain, Private'}
}
function Get-NetFirewallAddressFilter {
    process {[pscustomobject]@{RemoteAddress=@('192.168.45.3');LocalAddress=@('192.168.45.17')}}
}
function Get-NetFirewallPortFilter {
    process {[pscustomobject]@{LocalPort=$fixturePort;Protocol='TCP'}}
}
function Get-NetFirewallServiceFilter {process {[pscustomobject]@{Service='WinRM'}}}
$bootstrap = [scriptblock]::Create([IO.File]::ReadAllText($env:LABGUARD_BOOTSTRAP_FILE).Replace('__MANAGEMENT_IPV4__','192.168.45.3'))
$null = & $bootstrap
$null = & $bootstrap
$fixturePort='53'
$accepted = $true
try {$null = & $bootstrap} catch {$accepted = $false}
if ($accepted -or $script:fixtureMutations -ne 0) {throw 'Bootstrap altered or accepted incompatible state'}
"""
    path = fixture.directory / "verify-bootstrap.ps1"
    path.write_text(check, encoding="utf-8-sig")
    result = subprocess.run(
        [str(fixture.powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
        env={**os.environ, "LABGUARD_BOOTSTRAP_FILE": str(template_path), "LABGUARD_WMI_SCRIPT": str(launch),
             "LABGUARD_WMI_PAYLOAD": str(payload)}, capture_output=True,
        timeout=20, check=False,
    )
    require(result.returncode == 0, "Management bootstrap parser/SAN failed: " + result.stderr.decode(errors="replace")[:1200])


def initial_state():
    return {
        "ipv4": {"mode": "auto", "servers": ["192.168.45.1"]},
        "ipv6": {"mode": "static", "servers": ["fe80::1%19", "2001:db8::53"]},
        "autoServers": {"ipv4": ["192.168.45.1"], "ipv6": ["fe80::1%19"]},
        "backup": None,
        "forceDefaultFailure": False,
        "interfereAfterSet": False,
        "failRestoreAddOnce": False,
    }


def run_fixture(fixture, service):
    from labguard.station_dns import StationDNS

    def authenticated_station():
        return StationDNS(fixture, listen=LISTEN, network=NETWORK, token=service.check_token)

    original = initial_state()
    fixture.save(original)
    station = authenticated_station()
    first = station.test()
    require(first["direct"] == "ok" and first["default"] == "nxdomain", f"Unexpected initial DNS result: {first}. Loopback activity: {service.activity()}")

    preview = station.preview()
    require(preview["adapter"] == "Lab CI" and preview["target"] == TARGET, "Wrong adapter preview")
    applied = station.apply(preview["id"])
    require(applied["ok"], applied["message"])
    current = fixture.read()
    require(current["ipv4"] == {"mode": "static", "servers": [LISTEN]}, "IPv4 filter was not applied")
    require(current["ipv6"]["servers"] == [], "Old IPv6 server is still configured")
    require(current["backup"] is not None, "Backup missing after successful apply")
    require(station.test()["ok"], "Applied default query did not use current session")

    def observed_snapshot():
        return {"source_type": "local_dns", "dns_service": {"service_running": True, "check_token": service.check_token},
                "domains": [{"domain": "blocked.example.org"}], "events": service.activity()["events"]}

    # The native A query originates from the Windows runner's loopback address.
    # Preserve this fact: it differs from the simulated managed target address.
    block = station.test(blocked_domain="blocked.example.org", read_evidence=observed_snapshot)
    require(block["ok"] and block["block_result"] == "nxdomain", "Native A probe failed to report NXDOMAIN")
    require(not block["block_confirmed"], "Loopback query was misattributed to simulated remote IP")
    require(any(ipaddress.ip_address(e["client_ip"]).is_loopback and e["domain"] == "blocked.example.org"
                and e["query_type"] == "A" and e["status"] == "Bloqueio DNS confirmado"
                for e in service.activity()["events"]), "Native A query did not reach active filter rule")

    # A new StationDNS object must recover the original DNS using only the
    # station's durable backup, without depending on the previous UI session.
    restored = authenticated_station().restore()
    require(restored["ok"], restored["message"])
    require(fixture.read() == original, "Full adapter/backup state not restored")

    failed_state = {**original, "forceDefaultFailure": True}
    fixture.save(failed_state)
    preview = station.preview()
    rolled_back = station.apply(preview["id"])
    require(not rolled_back["ok"], "Unexpected success after verification failure")
    require(fixture.read() == failed_state, "Failed apply did not restore prior state")

    # Check that a fresh preview is required if another policy replaces DNS
    # between confirmation and execution.
    preview = station.preview()
    changed = fixture.read()
    changed["ipv6"] = {"mode": "static", "servers": ["2001:db8::54"]}
    fixture.save(changed)
    refused = station.apply(preview["id"])
    require(not refused["ok"] and fixture.read() == changed, "Changed adapter was overwritten")
    fixture.save({**original, "interfereAfterSet": True})
    preview = station.preview()
    require(not station.apply(preview["id"])["ok"], "Accepted an adapter changed by a separate policy")
    require(fixture.read()["ipv4"]["servers"] == ["192.168.45.222"], "External DNS edit was overwritten")
    require(fixture.read()["backup"] is not None, "Backup discarded despite conflicting DNS policy")

    fixture.save(original)
    preview = station.preview()
    require(station.apply(preview["id"])["ok"], "Could not prepare restore retry scenario")
    current = fixture.read()
    current["failRestoreAddOnce"] = True
    fixture.save(current)
    require(not station.restore()["ok"], "Partial restore was reported as confirmed")
    partial = fixture.read()
    require(partial["backup"] is not None and len(partial["ipv6"]["servers"]) == 1, "Partial restore not recorded")
    require(authenticated_station().restore()["ok"], "Restore could not resume after a failed list addition")
    require(fixture.read() == original, "Retry did not fully restore both DNS families")
    require(service.activity()["local_diagnostic_queries"] > 0, "No native TXT reached loopback filter")


def start_loopback_filter():
    # Resolve-DnsName uses port 53. Try loopback aliases if another service
    # already owns a particular local address, leaving that service untouched.
    errors = []
    for address in ("127.0.0.1", "127.0.0.2", "127.99.242.1"):
        service = DNSFilter(address, "127.0.0.0/8", port=53,
                            upstream="127.0.0.1", upstream_port=9,
                            rules={"in-addr.arpa": "Teste", "ip6.arpa": "Teste", "ci-negative.test": "Teste",
                                   "blocked.example.org": "Teste"})
        try:
            service.start()
            return service
        except DNSError as error:
            errors.append(str(error))
            service.close()
    raise AssertionError("Could not bind loopback DNS port 53: " + "; ".join(errors))


def main():
    require(os.name == "nt", "Windows runner required")
    with tempfile.TemporaryDirectory(prefix="LabGuard-Station-CI-") as directory:
        service = start_loopback_filter()
        try:
            fixture = NativeFixture(directory, service.listen)
            try:
                check_bootstrap(fixture)
                run_fixture(fixture, service)
            finally:
                fixture.close()
        finally:
            service.close()
    print(json.dumps({
        "ok": True, "powershell_5_1": True, "native_txt_loopback": True, "native_block_A_loopback": True, "adapter_fixture": True,
        "explicit_and_default": True, "apply_and_restore": True,
        "rollback_after_failed_test": True, "changed_policy_preserved": True,
        "restore_retry": True, "concurrent_dns_preserved": True,
        "bootstrap_syntax_and_san": True, "bootstrap_idempotence_fixture": True, "wmi_powershell_parsed": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
