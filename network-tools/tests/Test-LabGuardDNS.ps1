#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ReportPath)

$ErrorActionPreference = 'Stop'
$testSource = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\LabGuard-DNS-Sem-Cliente.ps1'))
$script:TestCases = New-Object 'System.Collections.Generic.List[object]'
$testReport = [ordered]@{
    SchemaVersion=1; PowerShellVersion=$PSVersionTable.PSVersion.ToString()
    ActualNetworkMutations=0; AdapterAndRegistry='in-memory fixtures'
    DnsQueries='mocked Resolve-DnsName, no remote DNS requests'
    Limits=@(
        'Transactions run against simulated adapters and backups.'
        'No binding, DNS, router or firewall setting of this runner is changed.'
        'No browser or school LAN is exercised; run the documented pilot after deployment.'
        'The native capability probe is a separate read-only report.'
    )
}

function Assert-Test([bool]$Condition,[string]$Message) {
    if (!$Condition) { throw $Message }
}
function Assert-TestEqual($Actual,$Expected,[string]$Message) {
    if ($Actual -cne $Expected) { throw $Message }
}
function Copy-TestValue($Value) {
    if ($null -eq $Value) { return $null }
    return ($Value | ConvertTo-Json -Depth 14 -Compress | ConvertFrom-Json)
}
function Get-TestJson($Value) { return ($Value | ConvertTo-Json -Depth 14 -Compress) }
function Assert-TestThrows([scriptblock]$Action,[string]$Message) {
    $raised=$false
    try { & $Action | Out-Null } catch { $raised=$true }
    Assert-Test $raised $Message
}
function Invoke-TestCase([string]$Name,[scriptblock]$Action) {
    try {
        & $Action
        [void]$script:TestCases.Add([pscustomobject]@{Name=$Name;Passed=$true})
        Write-Host ("PASS " + $Name)
    } catch {
        [void]$script:TestCases.Add([pscustomobject]@{Name=$Name;Passed=$false;Error=$_.Exception.Message})
        Write-Host ("FAIL " + $Name + ': ' + $_.Exception.Message)
    }
}
function New-TestState([bool]$BindingEnabled=$true,[string]$Mode='auto',[string[]]$Servers=@('192.168.45.1')) {
    return [pscustomobject]@{
        InterfaceIndex=19;InterfaceGuid='85982498-d52e-4f15-a465-106f8e6a0254';InterfaceAlias='Lab CI'
        Registration='primary';IPv4=[pscustomobject]@{Mode=$Mode;Servers=@($Servers)}
        IPv6BindingEnabled=$BindingEnabled
    }
}
function Reset-TestFixture($Initial=(New-TestState)) {
    $script:LGFixture=[pscustomobject]@{
        State=(Copy-TestValue $Initial);Original=(Copy-TestValue $Initial);Backup=$null
        Writes=(New-Object 'System.Collections.Generic.List[string]')
        Queries=(New-Object 'System.Collections.Generic.List[object]')
        BindingCalls=(New-Object 'System.Collections.Generic.List[object]')
        Admin=$true;DirectStatus='ok';DefaultStatus='ok';ResponseVariant='normal'
        Token='LabGuard-0123456789abcdef';DefaultFailuresRemaining=0
        PendingDownReads=0;DownReadsAfterBinding=0;AlwaysDownAfterBinding=$false
        FailBindingOnce='';FailDnsSetOnce=$false;FailDnsAddOnce=$false
        MutateDnsDuringDefault=$false;MutateBindingAfterDnsSet=$false;FailBackupSave=$false
        CacheClears=0;Sleeps=0;SleepSeconds=0;ReadCount=0;ReadHostReply='CANCELAR'
    }
}
function Get-TestArgument([string[]]$Arguments,[string]$Name) {
    $entries=@($Arguments | Where-Object {$_ -like ($Name+'=*')})
    if ($entries.Count -ne 1) { throw ('Expected one synthetic netsh argument: '+$Name) }
    return $entries[0].Substring($Name.Length+1)
}

try {
    Assert-Test ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'Windows PowerShell 5.1 is required.'
    $syntaxTokens=$null;$syntaxErrors=$null
    $syntaxTree=[Management.Automation.Language.Parser]::ParseFile($testSource,[ref]$syntaxTokens,[ref]$syntaxErrors)
    Assert-Test (@($syntaxErrors).Count -eq 0) 'The source has PowerShell parser errors.'
    $testReport.SourceSHA256=(Get-FileHash -LiteralPath $testSource -Algorithm SHA256).Hash.ToLowerInvariant()
    $testReport.SyntaxParsed=$true
    # Dot-sourcing defines the functions; it must not execute the interactive entrypoint.
    . $testSource
    # Exercise the production reader once on a real runner NIC, before any mocks.
    # This reads bindings, registration and DNS; it does not change them.
    $nativeDnsInterfaces=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {@($_.ServerAddresses).Count -gt 0} | Select-Object -ExpandProperty InterfaceIndex)
    $nativeAdapter=Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up' -and $_.ifIndex -in $nativeDnsInterfaces} |
        Sort-Object InterfaceIndex | Select-Object -First 1
    Assert-Test ($null -ne $nativeAdapter) 'No real adapter was available for read-only validation.'
    $nativeState=Get-LabGuardAdapterState -InterfaceIndex ([int]$nativeAdapter.ifIndex)
    Assert-LabGuardState $nativeState
    Assert-Test ($nativeState.IPv6BindingEnabled -is [bool]) 'The native IPv6 binding did not expose a Boolean value.'
    $testReport.NativeAdapterReadConfirmed=$true
    $testReport.NativeDnsMode=$nativeState.IPv4.Mode
    Reset-TestFixture

    # Every command that may change the network is replaced before calling a transaction.
    function Test-LabGuardAdministrator { return $script:LGFixture.Admin }
    function Get-LabGuardAdapterState {
        param([int]$InterfaceIndex)
        Assert-Test ($InterfaceIndex -eq $script:LGFixture.State.InterfaceIndex) 'The wrong interface index was read.'
        $script:LGFixture.ReadCount++
        if ($script:LGFixture.PendingDownReads -gt 0) {
            $script:LGFixture.PendingDownReads--
            throw 'Synthetic adapter is temporarily unavailable.'
        }
        if ($script:LGFixture.AlwaysDownAfterBinding -and $script:LGFixture.BindingCalls.Count -gt 0) {
            throw 'Synthetic adapter did not return.'
        }
        return (Copy-TestValue $script:LGFixture.State)
    }
    function Get-NetAdapter {
        [CmdletBinding()]
        param([int]$InterfaceIndex,[string]$Name)
        if ($PSBoundParameters.ContainsKey('InterfaceIndex')) {
            Assert-Test ($InterfaceIndex -eq $script:LGFixture.State.InterfaceIndex) 'A different adapter was requested.'
        }
        if ($PSBoundParameters.ContainsKey('Name')) {
            Assert-Test ($Name -ceq $script:LGFixture.State.InterfaceAlias) 'A different adapter name was requested.'
        }
        $status='Up'
        if ($script:LGFixture.PendingDownReads -gt 0) {$script:LGFixture.PendingDownReads--; $status='Down'}
        if ($script:LGFixture.AlwaysDownAfterBinding -and $script:LGFixture.BindingCalls.Count -gt 0) {$status='Down'}
        return [pscustomobject]@{ifIndex=$script:LGFixture.State.InterfaceIndex;InterfaceIndex=$script:LGFixture.State.InterfaceIndex
            InterfaceGuid=$script:LGFixture.State.InterfaceGuid;Name=$script:LGFixture.State.InterfaceAlias;Status=$status}
    }
    function Get-NetAdapterBinding {
        [CmdletBinding()]
        param([string]$Name,[string]$ComponentID)
        Assert-Test ($Name -ceq $script:LGFixture.State.InterfaceAlias -and $ComponentID -ceq 'ms_tcpip6') 'The wrong binding was inspected.'
        return [pscustomobject]@{Name=$Name;ComponentID=$ComponentID;Enabled=$script:LGFixture.State.IPv6BindingEnabled}
    }
    function Get-NetIPAddress {
        [CmdletBinding()]
        param([int]$InterfaceIndex,[string]$AddressFamily)
        Assert-Test ($InterfaceIndex -eq $script:LGFixture.State.InterfaceIndex -and $AddressFamily -eq 'IPv4') 'Readiness inspected an unrelated interface or family.'
        return [pscustomobject]@{AddressState='Preferred';IPAddress='192.168.45.17'}
    }
    function Set-TestBinding([bool]$Enabled,[string]$Name,[string]$ComponentID,$InputObject) {
        if ($null -ne $InputObject) {$Name=$InputObject.Name;$ComponentID=$InputObject.ComponentID}
        Assert-Test ($Name -ceq $script:LGFixture.State.InterfaceAlias -and $ComponentID -ceq 'ms_tcpip6') 'A binding outside the selected adapter was changed.'
        Assert-Test ($null -ne $script:LGFixture.Backup) 'The binding was changed before a durable backup.'
        if ($script:LGFixture.FailBindingOnce -eq 'before') {$script:LGFixture.FailBindingOnce='';throw 'Synthetic binding failure before change.'}
        $script:LGFixture.State.IPv6BindingEnabled=$Enabled
        [void]$script:LGFixture.BindingCalls.Add([pscustomobject]@{Enabled=$Enabled;Name=$Name;ComponentID=$ComponentID})
        [void]$script:LGFixture.Writes.Add('binding')
        $script:LGFixture.PendingDownReads=$script:LGFixture.DownReadsAfterBinding
        if ($script:LGFixture.FailBindingOnce -eq 'after') {$script:LGFixture.FailBindingOnce='';throw 'Synthetic binding failure after change.'}
    }
    function Disable-NetAdapterBinding {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param([string]$Name,[string]$ComponentID,$InputObject,[switch]$PassThru,[switch]$NoRestart)
        Set-TestBinding -Enabled $false -Name $Name -ComponentID $ComponentID -InputObject $InputObject
    }
    function Enable-NetAdapterBinding {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param([string]$Name,[string]$ComponentID,$InputObject,[switch]$PassThru,[switch]$NoRestart)
        Set-TestBinding -Enabled $true -Name $Name -ComponentID $ComponentID -InputObject $InputObject
    }
    function Get-DnsClientServerAddress {
        [CmdletBinding()]
        param([int]$InterfaceIndex,[string]$AddressFamily)
        Assert-Test ($InterfaceIndex -eq $script:LGFixture.State.InterfaceIndex) 'DNS inventory selected another adapter.'
        if (!$AddressFamily -or $AddressFamily -eq 'IPv4') {
            [pscustomobject]@{AddressFamily=2;ServerAddresses=@($script:LGFixture.State.IPv4.Servers)}
        }
        if (!$AddressFamily -or $AddressFamily -eq 'IPv6') {
            [pscustomobject]@{AddressFamily=23;ServerAddresses=@('fe80::1%19')}
        }
    }
    function Invoke-LabGuardNetsh {
        param([string[]]$Arguments)
        Assert-Test ($Arguments.Count -ge 5 -and $Arguments[0] -eq 'interface' -and $Arguments[1] -eq 'ipv4' -and
            $Arguments[2] -in @('set','add') -and $Arguments[3] -eq 'dnsservers') 'Unexpected native command: only selected IPv4 DNS changes are allowed.'
        Assert-Test ((Get-TestArgument $Arguments 'name') -eq [string]$script:LGFixture.State.InterfaceIndex) 'netsh selected another interface.'
        Assert-Test ($null -ne $script:LGFixture.Backup) 'DNS was changed before a durable backup.'
        if ($Arguments[2] -eq 'set') {
            Assert-Test ((Get-TestArgument $Arguments 'register') -ceq $script:LGFixture.State.Registration) 'The connection DNS registration mode was changed.'
            if ($script:LGFixture.FailDnsSetOnce) {$script:LGFixture.FailDnsSetOnce=$false;throw 'Synthetic DNS write failure.'}
            $source=Get-TestArgument $Arguments 'source'
            if ($source -eq 'dhcp') {
                $script:LGFixture.State.IPv4=[pscustomobject]@{Mode='auto';Servers=@($script:LGFixture.Original.IPv4.Servers)}
            } else {
                Assert-Test ($source -eq 'static') 'Unsupported synthetic DNS mode.'
                $address=Get-TestArgument $Arguments 'address'
                $servers=@();if ($address -ne 'none') {$servers=@($address)}
                $script:LGFixture.State.IPv4=[pscustomobject]@{Mode='static';Servers=$servers}
            }
            if ($script:LGFixture.MutateBindingAfterDnsSet) {
                $script:LGFixture.MutateBindingAfterDnsSet=$false
                $script:LGFixture.State.IPv6BindingEnabled=$false
            }
        } else {
            if ($script:LGFixture.FailDnsAddOnce) {$script:LGFixture.FailDnsAddOnce=$false;throw 'Synthetic ordered DNS addition failed.'}
            $address=Get-TestArgument $Arguments 'address'
            $position=[int](Get-TestArgument $Arguments 'index')
            Assert-Test ($position -eq @($script:LGFixture.State.IPv4.Servers).Count+1) 'The original DNS order was not preserved.'
            $script:LGFixture.State.IPv4.Servers=@($script:LGFixture.State.IPv4.Servers)+@($address)
        }
        [void]$script:LGFixture.Writes.Add('ipv4-dns')
        return @('Synthetic netsh success.')
    }
    function Read-LabGuardBackup {
        param([string]$InterfaceGuid)
        if ($null -ne $script:LGFixture.Backup -and $InterfaceGuid -ieq $script:LGFixture.Backup.InterfaceGuid) {
            return (Copy-TestValue $script:LGFixture.Backup)
        }
        return $null
    }
    function Save-LabGuardBackup {
        param($Record)
        if ($script:LGFixture.FailBackupSave) {throw 'Synthetic backup storage failure.'}
        Assert-LabGuardBackupRecord $Record
        $script:LGFixture.Backup=Copy-TestValue $Record
        [void]$script:LGFixture.Writes.Add('backup-save')
    }
    function Remove-LabGuardBackup {
        param([string]$InterfaceGuid)
        Assert-Test ($InterfaceGuid -ieq $script:LGFixture.State.InterfaceGuid) 'A different adapter backup was removed.'
        $script:LGFixture.Backup=$null
        [void]$script:LGFixture.Writes.Add('backup-remove')
    }
    function Clear-DnsClientCache {
        [CmdletBinding()]param()
        $script:LGFixture.CacheClears++
        [void]$script:LGFixture.Writes.Add('cache-clear')
    }
    function Start-Sleep {
        [CmdletBinding()]param([int]$Seconds=0,[int]$Milliseconds=0)
        $script:LGFixture.Sleeps++
        $script:LGFixture.SleepSeconds+=$Seconds+($Milliseconds/1000.0)
        if ($script:LGFixture.Sleeps -gt 100) {throw 'Retry loop exceeded the test bound.'}
        # The timeout case retains real time so the production deadline is tested.
        if ($script:LGFixture.AlwaysDownAfterBinding) {[Threading.Thread]::Sleep(500)}
    }
    function Resolve-DnsName {
        [CmdletBinding()]
        param([string]$Name,[string]$Type,[string]$Server,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout)
        [void]$script:LGFixture.Queries.Add([pscustomobject]@{Name=$Name;Type=$Type;Server=$Server;DnsOnly=[bool]$DnsOnly;NoHostsFile=[bool]$NoHostsFile})
        if ($Type -in @('A','AAAA')) {
            Write-Error 'Synthetic NXDOMAIN.' -ErrorId DNS_ERROR_RCODE_NAME_ERROR -ErrorAction Stop
        }
        Assert-Test ($Type -eq 'TXT' -and $DnsOnly -and $NoHostsFile) 'The session test did not request a DNS-only TXT record.'
        $status=$script:LGFixture.DefaultStatus
        if ($Server) {$status=$script:LGFixture.DirectStatus}
        if (!$Server -and $script:LGFixture.DefaultFailuresRemaining -gt 0) {
            $script:LGFixture.DefaultFailuresRemaining--; $status='timeout'
        }
        if (!$Server -and $script:LGFixture.MutateDnsDuringDefault) {
            $script:LGFixture.MutateDnsDuringDefault=$false
            $script:LGFixture.State.IPv4=[pscustomobject]@{Mode='static';Servers=@('192.168.45.222')}
        }
        if ($status -eq 'timeout') {Write-Error 'Synthetic timeout.' -ErrorId TIMEOUT -ErrorAction Stop}
        if ($status -eq 'nxdomain') {Write-Error 'Synthetic NXDOMAIN.' -ErrorId DNS_ERROR_RCODE_NAME_ERROR -ErrorAction Stop}
        if ($status -eq 'failed') {throw 'Synthetic DNS error.'}
        $token=$script:LGFixture.Token
        if ($status -eq 'different') {$token='LabGuard-fedcba9876543210'}
        if ($script:LGFixture.ResponseVariant -eq 'invalid-token') {$token='not-a-labguard-session'}
        $answerName=$Name.TrimEnd('.')
        if ($script:LGFixture.ResponseVariant -eq 'other-name') {$answerName='unrelated.example.test'}
        $answer=[pscustomobject]@{Type='TXT';Name=$answerName;Strings=@($token)}
        $answer
        if ($script:LGFixture.ResponseVariant -eq 'duplicate') {$answer}
    }
    function Get-LabGuardBrowserDnsPolicy { return @([pscustomobject]@{Browser='Chrome';Scope='HKLM:';DnsOverHttpsMode='Nao definida'}) }
    function Read-Host { param([string]$Prompt) return $script:LGFixture.ReadHostReply }

    Invoke-TestCase 'DNS mode parser accepts English and Portuguese and rejects ambiguity' {
        Assert-TestEqual (ConvertFrom-LabGuardDnsModeOutput @('Configuration for interface "DHCP classroom"','    Statically Configured DNS Servers: 192.168.45.1')) 'static' 'The adapter name was confused with DNS mode.'
        Assert-TestEqual (ConvertFrom-LabGuardDnsModeOutput @('    DNS servers configured through DHCP: 192.168.45.1')) 'auto' 'English automatic DNS was not recognized.'
        Assert-TestEqual (ConvertFrom-LabGuardDnsModeOutput @('    Servidores DNS configurados estaticamente: 192.168.45.1')) 'static' 'Portuguese static DNS was not recognized.'
        Assert-TestThrows {ConvertFrom-LabGuardDnsModeOutput @('    DNS through DHCP:','    Statically Configured DNS Servers:')} 'Ambiguous DNS origin was accepted.'
        Assert-TestThrows {ConvertFrom-LabGuardDnsModeOutput @('Unknown DNS layout')} 'Unknown DNS origin was accepted.'
    }
    Invoke-TestCase 'Session queries use fresh names and compare the same token' {
        Reset-TestFixture
        $direct=Test-LabGuardDnsPath -Server '192.168.45.3'
        $default=Test-LabGuardDnsPath -ExpectedToken $direct.Token
        Assert-Test ($direct.Status -eq 'ok' -and $default.Status -eq 'ok') 'Valid direct/default session evidence failed.'
        Assert-Test ($script:LGFixture.Queries.Count -eq 2 -and $script:LGFixture.Queries[0].Name -cne $script:LGFixture.Queries[1].Name) 'The two probes reused a cached query name.'
        foreach ($query in $script:LGFixture.Queries) {Assert-Test ($query.Name -match '^[0-9a-f]{32}\.labguard-check\.test\.$') 'Session query did not use a fresh fully qualified name.'}
        $script:LGFixture.DefaultStatus='different'
        Assert-TestEqual (Test-LabGuardDnsPath -ExpectedToken $direct.Token).Status 'different' 'A different filter session was accepted.'
    }
    Invoke-TestCase 'Malformed, unrelated and duplicated TXT records are rejected' {
        Reset-TestFixture
        foreach ($variant in @('invalid-token','other-name','duplicate')) {
            $script:LGFixture.ResponseVariant=$variant
            Assert-Test ((Test-LabGuardDnsPath -Server '192.168.45.3').Status -ne 'ok') ('Accepted invalid TXT response '+$variant)
        }
    }
    Invoke-TestCase 'Default diagnosis is read-only and checks A and AAAA separately' {
        Reset-TestFixture
        $result=Invoke-LabGuardDnsTool -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19 -DominioTeste 'blocked.example.test'
        Assert-Test ($result.Ok -and $result.Mode -eq 'Diagnosticar') 'Default mode was not diagnosis.'
        Assert-Test ($script:LGFixture.Writes.Count -eq 0 -and $null -eq $script:LGFixture.Backup) 'Diagnosis changed settings or saved a backup.'
        Assert-Test (@($result.DomainQueries | Where-Object {$_.Type -eq 'A'}).Count -eq 2) 'The A domain paths were not compared.'
        Assert-Test (@($result.DomainQueries | Where-Object {$_.Type -eq 'AAAA'}).Count -eq 2) 'The AAAA domain paths were not compared.'
    }
    Invoke-TestCase 'Cancellation, wrong interface and non-admin application make no changes' {
        Reset-TestFixture
        $cancelled=Invoke-LabGuardDnsTool -Modo Aplicar -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test (!$cancelled.Ok -and $script:LGFixture.Writes.Count -eq 0) 'Cancellation changed settings.'
        Assert-TestThrows {Invoke-LabGuardDnsTool -Modo Aplicar -FiltroIPv4 '192.168.45.3' -ConfirmarAlteracao} 'An unspecified interface was accepted.'
        $script:LGFixture.Admin=$false
        Assert-TestThrows {Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19} 'Non-admin application was accepted.'
        Assert-Test ($script:LGFixture.Writes.Count -eq 0) 'A rejected application changed settings.'
    }
    Invoke-TestCase 'Bad filter address and unavailable direct DNS do not change settings' {
        Reset-TestFixture
        foreach ($bad in @('8.8.8.8','::1','192.168.45.3; Write-Host bad','127.0.0.1','192.168.045.3')) {
            Assert-TestThrows {Invoke-LabGuardApply -FiltroIPv4 $bad -InterfaceIndex 19} 'Invalid or non-private filter address was accepted.'
        }
        $script:LGFixture.DirectStatus='timeout'
        Assert-TestThrows {Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19} 'Application proceeded without reaching the filter.'
        Assert-Test ($script:LGFixture.Writes.Count -eq 0) 'Direct preflight failure changed settings.'
    }
    Invoke-TestCase 'Apply uses only selected IPv4 DNS and disables only its IPv6 binding' {
        Reset-TestFixture
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test ($result.Ok -and !$result.RolledBack) 'Valid application failed.'
        Assert-TestEqual ($script:LGFixture.State.IPv4.Servers -join ',') '192.168.45.3' 'Unexpected DNS remained.'
        Assert-Test (!$script:LGFixture.State.IPv6BindingEnabled) 'IPv6 binding was not disabled.'
        Assert-Test ($script:LGFixture.Backup.Phase -eq 'applied' -and $script:LGFixture.Backup.Before.IPv6BindingEnabled) 'The original binding state was not saved.'
        Assert-Test ($script:LGFixture.BindingCalls.Count -eq 1 -and !$script:LGFixture.BindingCalls[0].Enabled) 'Unexpected binding operations occurred.'
        Assert-Test ($script:LGFixture.CacheClears -gt 0) 'Application did not clear the DNS cache.'
        Assert-Test ((Get-TestJson $script:LGFixture.Backup) -notmatch 'LabGuard-[0-9a-f]{16}') 'The session token leaked into the backup.'
        Assert-TestThrows {Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19} 'A pending backup was overwritten.'
    }
    Invoke-TestCase 'Restore returns automatic IPv4 DNS and the original enabled binding' {
        Reset-TestFixture
        $original=Get-TestJson $script:LGFixture.State
        $null=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        $result=Invoke-LabGuardRestore -InterfaceIndex 19
        Assert-Test $result.Ok 'Restore failed.'
        Assert-TestEqual (Get-TestJson $script:LGFixture.State) $original 'Restore did not recover the original adapter state.'
        Assert-Test ($null -eq $script:LGFixture.Backup) 'Completed restore did not remove its backup.'
    }
    Invoke-TestCase 'A previously disabled IPv6 binding remains disabled after restore' {
        Reset-TestFixture (New-TestState -BindingEnabled $false)
        $original=Get-TestJson $script:LGFixture.State
        $null=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        $result=Invoke-LabGuardRestore -InterfaceIndex 19
        Assert-Test $result.Ok 'Restore of an originally disabled binding failed.'
        Assert-TestEqual (Get-TestJson $script:LGFixture.State) $original 'Restore enabled IPv6 although it was originally disabled.'
        Assert-Test (@($script:LGFixture.BindingCalls | Where-Object {$_.Enabled}).Count -eq 0) 'IPv6 was temporarily enabled against its original state.'
    }
    Invoke-TestCase 'Default resolver failure rolls back DNS and binding' {
        Reset-TestFixture
        $original=Get-TestJson $script:LGFixture.State
        $script:LGFixture.DefaultStatus='different'
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test (!$result.Ok -and $result.RolledBack) 'A wrong default resolver was reported as success.'
        Assert-TestEqual (Get-TestJson $script:LGFixture.State) $original 'Failed application did not restore the original state.'
        Assert-Test ($null -eq $script:LGFixture.Backup) 'Successful rollback retained a stale backup.'
    }
    Invoke-TestCase 'Failure before saving the backup causes no network mutation' {
        Reset-TestFixture
        $script:LGFixture.FailBackupSave=$true
        Assert-TestThrows {Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19} 'Backup failure was hidden.'
        Assert-Test ($script:LGFixture.Writes.Count -eq 0 -and $script:LGFixture.BindingCalls.Count -eq 0) 'Settings changed without a backup.'
    }
    Invoke-TestCase 'Binding failure after DNS change rolls back' {
        Reset-TestFixture
        $original=Get-TestJson $script:LGFixture.State
        $script:LGFixture.FailBindingOnce='before'
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test (!$result.Ok -and $result.RolledBack) 'Binding failure was not rolled back.'
        Assert-TestEqual (Get-TestJson $script:LGFixture.State) $original 'DNS remained changed after binding failure.'
    }
    Invoke-TestCase 'A changed preview is rejected before changes' {
        Reset-TestFixture
        $preview=Copy-TestValue $script:LGFixture.State
        $script:LGFixture.State.IPv4=[pscustomobject]@{Mode='static';Servers=@('192.168.45.77')}
        Assert-TestThrows {Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19 -ExpectedState $preview} 'A changed preview was accepted.'
        Assert-Test ($script:LGFixture.Writes.Count -eq 0) 'A changed preview caused writes.'
    }
    Invoke-TestCase 'Third-party DNS during verification is not overwritten by rollback' {
        Reset-TestFixture
        $script:LGFixture.MutateDnsDuringDefault=$true
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test (!$result.Ok -and !$result.RolledBack) 'A concurrent policy was treated as safely restored.'
        Assert-TestEqual ($script:LGFixture.State.IPv4.Servers -join ',') '192.168.45.222' 'Rollback overwrote another policy.'
        Assert-Test ($null -ne $script:LGFixture.Backup) 'Conflict discarded recovery evidence.'
    }
    Invoke-TestCase 'Rollback preserves a third-party binding change before this tool touched it' {
        Reset-TestFixture
        $script:LGFixture.MutateBindingAfterDnsSet=$true
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test (!$result.Ok -and !$result.RolledBack) 'An untouched binding changed by another policy was claimed as restored.'
        Assert-Test (!$script:LGFixture.State.IPv6BindingEnabled -and $script:LGFixture.BindingCalls.Count -eq 0) 'Rollback modified the externally disabled binding.'
        Assert-Test ($null -ne $script:LGFixture.Backup -and !$script:LGFixture.Backup.Touched.IPv6Binding) 'The journal did not preserve ownership of the untouched binding.'
    }
    Invoke-TestCase 'Third-party DNS or adapter identity blocks restore without writes' {
        Reset-TestFixture
        $null=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        $script:LGFixture.State.IPv4=[pscustomobject]@{Mode='static';Servers=@('192.168.45.222')}
        $writes=$script:LGFixture.Writes.Count
        Assert-TestThrows {Invoke-LabGuardRestore -InterfaceIndex 19} 'Restore accepted another policy.'
        Assert-Test ($script:LGFixture.Writes.Count -eq $writes) 'Conflicting restore changed settings.'
        $script:LGFixture.State.InterfaceGuid='714cd3c4-fbf8-4937-b217-669e287809f6'
        Assert-TestThrows {Invoke-LabGuardRestore -InterfaceIndex 19} 'Restore accepted a different adapter GUID.'
        Assert-Test ($script:LGFixture.Writes.Count -eq $writes) 'Wrong adapter restore changed settings.'
    }
    Invoke-TestCase 'A later IPv6 binding change is preserved instead of silently restored' {
        Reset-TestFixture
        $null=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        $script:LGFixture.State.IPv6BindingEnabled=$true
        $writes=$script:LGFixture.Writes.Count
        Assert-TestThrows {Invoke-LabGuardRestore -InterfaceIndex 19} 'A later binding change was accepted as the tool state.'
        Assert-Test ($script:LGFixture.State.IPv6BindingEnabled -and $script:LGFixture.Writes.Count -eq $writes) 'Restore overwrote a later binding policy.'
        Assert-Test ($null -ne $script:LGFixture.Backup) 'The binding conflict discarded recovery evidence.'
    }
    Invoke-TestCase 'Static DNS list order survives restore and partial restore retry' {
        Reset-TestFixture (New-TestState -Mode static -Servers @('192.168.45.11','192.168.45.12','192.168.45.13'))
        $original=Get-TestJson $script:LGFixture.State
        $null=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        $script:LGFixture.FailDnsAddOnce=$true
        Assert-TestThrows {Invoke-LabGuardRestore -InterfaceIndex 19} 'A partial restore was reported as complete.'
        Assert-Test ($null -ne $script:LGFixture.Backup -and $script:LGFixture.Backup.Phase -eq 'restoring') 'Partial restore lost its journal.'
        $result=Invoke-LabGuardRestore -InterfaceIndex 19
        Assert-Test $result.Ok 'A partial restore could not resume.'
        Assert-TestEqual (Get-TestJson $script:LGFixture.State) $original 'The ordered original DNS list was not recovered.'
    }
    Invoke-TestCase 'Temporary adapter restart is retried and then verified' {
        Reset-TestFixture
        $script:LGFixture.DownReadsAfterBinding=2
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test $result.Ok 'The temporary adapter restart was not tolerated.'
        Assert-Test ($script:LGFixture.Sleeps -gt 0 -and $script:LGFixture.Sleeps -le 40) 'Adapter readiness retry was absent or unbounded.'
        Assert-Test (!$script:LGFixture.State.IPv6BindingEnabled -and $script:LGFixture.Backup.Phase -eq 'applied') 'Readiness was claimed without the desired state.'
    }
    Invoke-TestCase 'An adapter that never returns is not reported as protected' {
        Reset-TestFixture
        $script:LGFixture.AlwaysDownAfterBinding=$true
        $result=Invoke-LabGuardApply -FiltroIPv4 '192.168.45.3' -InterfaceIndex 19
        Assert-Test (!$result.Ok -and !$result.RolledBack) 'An unavailable adapter was reported as protected or restored.'
        Assert-Test ($null -ne $script:LGFixture.Backup) 'Unavailable adapter lost the recovery backup.'
        Assert-Test ($script:LGFixture.Sleeps -le 80) 'Unavailable adapter retry was unbounded.'
    }

    $failures=@($script:TestCases | Where-Object {!$_.Passed})
    $testReport.Cases=@($script:TestCases.ToArray())
    $testReport.PassedCount=$script:TestCases.Count-$failures.Count
    $testReport.FailedCount=$failures.Count
    $testReport.Ok=($failures.Count -eq 0)
    if ($failures.Count) { throw ('Failed fixture cases: '+$failures.Count) }
} catch {
    $testReport.Ok=$false
    $testReport.Error=$_.Exception.Message
    throw
} finally {
    if (!$testReport.Contains('Cases')) {$testReport.Cases=@($script:TestCases.ToArray())}
    [IO.File]::WriteAllText($ReportPath,($testReport | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
}
