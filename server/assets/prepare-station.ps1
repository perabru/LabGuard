#requires -Version 5.1
#requires -RunAsAdministrator
# Implantar como script de computador via GPO ou MDM. Executa na estação.
$ErrorActionPreference = 'Stop'
$managementIP = '__MANAGEMENT_IPV4__'

function Read-DerLength([byte[]]$Bytes, [ref]$Offset) {
    if ($Offset.Value -ge $Bytes.Length) { throw 'Extensao SAN invalida.' }
    $length = [int]$Bytes[$Offset.Value]; $Offset.Value++
    if ($length -lt 128) { return $length }
    $count = $length -band 127
    if ($count -lt 1 -or $count -gt 3 -or $Offset.Value + $count -gt $Bytes.Length) { throw 'Comprimento SAN invalido.' }
    $length = 0
    for ($i=0; $i -lt $count; $i++) { $length = ($length * 256) + $Bytes[$Offset.Value]; $Offset.Value++ }
    return $length
}
function Test-SanAddress($Certificate, [ipaddress]$Address) {
    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if (-not $extension) { return $false }
    $bytes = $extension.RawData
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 48) { return $false }
    $pos = 1
    $length = Read-DerLength $bytes ([ref]$pos)
    $end = $pos + $length
    if ($end -ne $bytes.Length) { return $false }
    while ($pos -lt $end) {
        $tag = $bytes[$pos]; $pos++
        $size = Read-DerLength $bytes ([ref]$pos)
        if ($pos + $size -gt $end) { return $false }
        if ($tag -eq 135 -and $size -eq 4 -and (($bytes[$pos..($pos+3)] -join '.') -eq $Address.IPAddressToString)) { return $true }
        $pos += $size
    }
    return $false
}

$routes = @(Find-NetRoute -RemoteIPAddress $managementIP | Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress })
if ($routes.Count -ne 1) { throw 'A rota para o computador da TI precisa identificar um IP local exclusivo.' }
$stationIP = [ipaddress]$routes[0].IPAddress
if ($stationIP.AddressFamily -ne 'InterNetwork' -or $stationIP.IPAddressToString -eq $managementIP) { throw 'Distribua este script nas estacoes do laboratorio.' }
$profile = Get-NetConnectionProfile -InterfaceIndex $routes[0].InterfaceIndex
if ($profile.NetworkCategory -notin @('DomainAuthenticated','Private')) { throw 'A interface do laboratorio precisa ter perfil Dominio ou Privado.' }
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) -and
    (($_.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'}).EnhancedKeyUsages.Value -contains '1.3.6.1.5.5.7.3.1') -and (Test-SanAddress $_ $stationIP) -and $_.Verify()
} | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw 'Emita um certificado de computador confiavel com chave privada, uso Server Authentication, nome do host e o IP da estacao no SAN.' }
$hostName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName,$false)
if (-not $hostName) { throw 'O certificado deve identificar o nome do computador.' }
$svc = Get-CimInstance Win32_Service -Filter "Name='WinRM'"
$startMode = @{Manual='Manual';Auto='Automatic';Disabled='Disabled'}[$svc.StartMode]
$started = $false; $changedMode = $false; $newListener = $null; $newRule = $false
$rule = "LabGuard-WinRM-$managementIP-$stationIP"
try {
    if ($svc.StartMode -eq 'Disabled') { Set-Service WinRM -StartupType Manual; $changedMode = $true }
    if ($svc.State -ne 'Running') { Start-Service WinRM; $started = $true }
    $listeners = @(Get-ChildItem WSMan:\localhost\Listener)
    if ($started -and @($listeners | Where-Object {$_.Keys -contains 'Transport=HTTP'}).Count) { throw 'Revise o listener HTTP existente com a TI antes de ativar este servico.' }
    $https = @($listeners | Where-Object {$_.Keys -contains 'Transport=HTTPS'})
    if ($https.Count -gt 0) {
        $match = @($https | Where-Object {
            ($_.Keys -contains 'Address=*' -or $_.Keys -contains "Address=IP:$stationIP") -and
            (Get-Item "WSMan:\localhost\Listener\$($_.Name)\Port").Value -eq 5986 -and
            (Get-Item "WSMan:\localhost\Listener\$($_.Name)\CertificateThumbprint").Value -eq $cert.Thumbprint
        })
        if ($match.Count -ne 1) { throw 'Existe um listener HTTPS diferente. Confira a politica existente com a TI.' }
    } else {
        $selector = @{Address="IP:$stationIP";Transport='HTTPS'}
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet $selector -ValueSet @{Hostname=$hostName;CertificateThumbprint=$cert.Thumbprint;Port='5986'} | Out-Null
        $newListener = $selector
    }
    $priorRule = Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
    if ($priorRule) {
        $addresses = $priorRule | Get-NetFirewallAddressFilter
        $ports = $priorRule | Get-NetFirewallPortFilter
        $serviceFilter = $priorRule | Get-NetFirewallServiceFilter
        $profiles = @(([string]$priorRule.Profile).Split(',') | ForEach-Object { $_.Trim() } | Sort-Object)
        if (($profiles -join ',') -ne 'Domain,Private' -or $serviceFilter.Service -ne 'WinRM') { throw 'Regra existente requer revisao do servico ou perfil de rede.' }
        if ($priorRule.Direction -ne 'Inbound' -or $priorRule.Action -ne 'Allow' -or $priorRule.Enabled -ne 'True' -or ($addresses.RemoteAddress -join ',') -ne $managementIP -or ($addresses.LocalAddress -join ',') -ne $stationIP.IPAddressToString -or ($ports.LocalPort -join ',') -ne '5986' -or $ports.Protocol -ne 'TCP') { throw 'Regra de firewall com mesmo nome e configuracao divergente.' }
    } else {
        New-NetFirewallRule -Name $rule -DisplayName 'LabGuard - WinRM HTTPS da TI' -Direction Inbound -Action Allow -Protocol TCP -Service WinRM -LocalPort 5986 -LocalAddress $stationIP.IPAddressToString -RemoteAddress $managementIP -Profile Domain,Private | Out-Null
        $newRule = $true
    }
    if ($svc.StartMode -ne 'Auto') { Set-Service WinRM -StartupType Automatic; $changedMode=$true }
    Write-Output "WinRM HTTPS preparado em $stationIP para o computador $managementIP. Confirme a conexao no painel da TI."
} catch {
    $failure = $_
    if ($newRule) { Remove-NetFirewallRule -Name $rule -ErrorAction Continue }
    if ($null -ne $newListener) { Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet $newListener -ErrorAction Continue }
    if ($started) { Stop-Service WinRM -ErrorAction Continue }
    if ($changedMode) { Set-Service WinRM -StartupType $startMode -ErrorAction Continue }
    throw $failure
}
