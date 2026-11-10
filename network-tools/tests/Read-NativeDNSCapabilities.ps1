#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ReportPath)

$ErrorActionPreference = 'Stop'
$report = [ordered]@{
    SchemaVersion = 1
    Purpose = 'Read-only Windows DNS and IPv6 binding capability probe'
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    OSVersion = [Environment]::OSVersion.Version.ToString()
    NetworkMutations = 0
    Limits = @(
        'No network, adapter binding or DNS setting is changed.'
        'Runner observations do not establish behavior of the school network.'
        'Interface names, IP addresses and MAC addresses are omitted from this report.'
    )
}

try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw 'Use native Windows PowerShell 5.1 for this probe.'
    }
    $dnsInterfaces=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {@($_.ServerAddresses).Count -gt 0} | Select-Object -ExpandProperty InterfaceIndex)
    $adapter = Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up' -and $_.ifIndex -in $dnsInterfaces} |
        Sort-Object InterfaceIndex | Select-Object -First 1
    if ($null -eq $adapter) { throw 'The runner has no active adapter with an IPv4 DNS configuration for read-only validation.' }
    $index = [int]$adapter.ifIndex
    $ipv4 = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
    $binding = @(Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop)
    if ($binding.Count -ne 1) { throw 'The IPv6 binding of the selected adapter is ambiguous.' }
    $report.IPv4DnsReadable = ($ipv4.Count -eq 1)
    $report.IPv6BindingReadable = ($binding[0].ComponentID -eq 'ms_tcpip6')
    $report.BindingEnabledPropertyIsBoolean = ($binding[0].Enabled -is [bool])
    $report.EnableCommandAvailable = ($null -ne (Get-Command Enable-NetAdapterBinding -ErrorAction Stop))
    $report.DisableCommandAvailable = ($null -ne (Get-Command Disable-NetAdapterBinding -ErrorAction Stop))

    # The only native executable call reads the current IPv4 DNS mode.
    $lines = @(& "$env:SystemRoot\System32\netsh.exe" interface ipv4 show dnsservers "name=$index" 2>&1 |
        ForEach-Object { [string]$_ })
    $report.IPv4DnsModeExitCode = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) { throw 'The native IPv4 DNS mode could not be read.' }
    $report.SanitizedDnsModeHeadings = @($lines | Where-Object {
        $_ -match '^\s+[^"\r\n]*(DHCP|statically|estaticamente|est[aA]tic[oa]s?)[^"\r\n:]*:'
    } | ForEach-Object {
        ($_ -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b','[IPv4 omitted]').Trim()
    })
    $report.Ok = $true
} catch {
    $report.Ok = $false
    $report.Error = $_.Exception.Message
    throw
} finally {
    $json = $report | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText($ReportPath, $json, (New-Object Text.UTF8Encoding($false)))
    Write-Output $json
}
