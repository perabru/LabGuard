#requires -Version 5.1
<#
.SYNOPSIS
Diagnostica e configura o DNS de uma estacao Windows sem instalar um cliente.
.DESCRIPTION
Diagnosticar e o modo padrao e nao altera configuracoes. Aplicar aponta o DNS
IPv4 do adaptador escolhido para o LabGuard e desabilita o binding ms_tcpip6
nesse adaptador, conforme escolha da TI. Nao altera diretamente a lista DNS
IPv6, RA, enderecos IPv4, gateway ou outros adaptadores. A placa pode reiniciar.
As configuracoes anteriores ficam em HKLM com acesso restrito a TI/SYSTEM.
Nao instala servico, tarefa, WinRM ou politicas de navegador.
.EXAMPLE
.\LabGuard-DNS-Sem-Cliente.ps1 -FiltroIPv4 192.168.15.10
.EXAMPLE
.\LabGuard-DNS-Sem-Cliente.ps1 -Modo Aplicar -FiltroIPv4 192.168.15.10 -InterfaceIndex 12
.EXAMPLE
.\LabGuard-DNS-Sem-Cliente.ps1 -Modo Restaurar -InterfaceIndex 12
#>
[CmdletBinding()]
param(
    [ValidateSet('Diagnosticar', 'Aplicar', 'Restaurar')]
    [string]$Modo = 'Diagnosticar',
    [string]$FiltroIPv4 = '',
    [ValidateRange(0, 2147483647)]
    [int]$InterfaceIndex = 0,
    [string]$DominioTeste = '',
    [switch]$ConfirmarAlteracao
)

function Test-LabGuardAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-LabGuardFilterAddress {
    param([string]$Address)
    $parsed = $null
    if (![Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $Address -cne $parsed.ToString()) {
        throw 'Informe o IPv4 literal do PC que executa o filtro LabGuard.'
    }
    $bytes = $parsed.GetAddressBytes()
    if (!(($bytes[0] -eq 10) -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168))) {
        throw 'O filtro deve usar um IPv4 privado da rede da escola.'
    }
    return $parsed.ToString()
}

function ConvertTo-LabGuardPlainText {
    param([string]$Text)
    $builder = New-Object Text.StringBuilder
    foreach ($character in $Text.Normalize([Text.NormalizationForm]::FormD).ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($character) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$builder.Append($character)
        }
    }
    return $builder.ToString().ToLowerInvariant()
}

function ConvertFrom-LabGuardDnsModeOutput {
    param([string[]]$Lines)
    $modes = @()
    foreach ($line in $Lines) {
        # Ignore the quoted adapter heading; accept only a DNS server heading.
        $plain = ConvertTo-LabGuardPlainText $line
        if ($plain -match '^\s+[^"\r\n]*\bdhcp\b[^"\r\n:]*:') { $modes += 'auto' }
        elseif ($plain -match '^\s+[^"\r\n]*(statically|estaticamente|estatic[oa]s?)[^"\r\n:]*:') { $modes += 'static' }
    }
    if ($modes.Count -ne 1) { throw 'Origem do DNS ambigua ou idioma do netsh nao reconhecido. Nada sera aplicado.' }
    return $modes[0]
}





function Invoke-LabGuardNetsh {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = @(& "$env:SystemRoot\System32\netsh.exe" @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ('O Windows recusou a operacao netsh: ' + ($Arguments[0..([Math]::Min(2, $Arguments.Count - 1))] -join ' ')) }
    return @($output | ForEach-Object { [string]$_ })
}

function Get-LabGuardIPv6Binding {
    param($State)
    $adapter = Get-NetAdapter -InterfaceIndex $State.InterfaceIndex -ErrorAction Stop
    if (@($adapter).Count -ne 1 -or ([guid]$adapter.InterfaceGuid).ToString() -ine $State.InterfaceGuid) {
        throw 'A identidade do adaptador mudou.'
    }
    # Querying a name may accept wildcards on some builds. Filter exactly and
    # mutate the resulting CIM object, never a wildcard pattern.
    $bindings = @(Get-NetAdapterBinding -Name ([string]$adapter.Name) -ComponentID 'ms_tcpip6' -ErrorAction Stop |
        Where-Object { $_.Name -ceq [string]$adapter.Name -and $_.ComponentID -ceq 'ms_tcpip6' })
    if ($bindings.Count -ne 1 -or $bindings[0].Enabled -isnot [bool]) {
        throw 'O binding IPv6 do adaptador nao foi identificado de forma unica.'
    }
    return $bindings[0]
}

function Get-LabGuardAdapterState {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)
    if ($InterfaceIndex -lt 1) { throw 'Escolha explicitamente um InterfaceIndex valido.' }
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
    if (@($adapter).Count -ne 1) { throw 'O adaptador nao foi identificado de forma unica.' }
    $client = Get-DnsClient -InterfaceIndex $InterfaceIndex -ErrorAction Stop
    $registration = if (!$client.RegisterThisConnectionsAddress) { 'none' } elseif ($client.UseSuffixWhenRegistering) { 'both' } else { 'primary' }
    $state = [ordered]@{
        InterfaceIndex = [int]$adapter.ifIndex
        InterfaceGuid = ([guid]$adapter.InterfaceGuid).ToString()
        InterfaceAlias = [string]$adapter.Name
        Registration = $registration
    }
    $mode = ConvertFrom-LabGuardDnsModeOutput @(Invoke-LabGuardNetsh @('interface', 'ipv4', 'show', 'dnsservers', ('name=' + $InterfaceIndex)))
    $servers = @((Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily 'IPv4' -ErrorAction Stop).ServerAddresses | Where-Object { $_ })
    $state.IPv4 = [pscustomobject]@{ Mode = $mode; Servers = @($servers) }
    $state.IPv6BindingEnabled = [bool](Get-LabGuardIPv6Binding ([pscustomobject]$state)).Enabled
    $result = [pscustomobject]$state
    Assert-LabGuardState $result
    return $result
}

function Assert-LabGuardState {
    param($State)
    if ($null -eq $State -or $State.InterfaceIndex -lt 1 -or
        [string]$State.InterfaceGuid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
        [string]$State.InterfaceAlias -match '[\x00-\x1f\x7f]' -or [string]$State.InterfaceAlias -eq '' -or
        ([string]$State.InterfaceAlias).Length -gt 256 -or
        $State.Registration -notin @('none', 'primary', 'both') -or
        $State.IPv6BindingEnabled -isnot [bool]) { throw 'Estado de adaptador invalido.' }
    $entry = $State.IPv4
    if ($null -eq $entry -or $entry.Mode -notin @('auto', 'static') -or
        $null -eq $entry.Servers -or @($entry.Servers).Count -gt 12) { throw 'Configuracao DNS IPv4 invalida.' }
    foreach ($server in @($entry.Servers)) {
        $address = $null
        if ($server -isnot [string] -or $server.Length -gt 15 -or
            ![Net.IPAddress]::TryParse($server, [ref]$address) -or
            $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Endereco DNS IPv4 invalido.' }
    }
}

function Get-LabGuardDnsErrorStatus {
    param($ErrorRecord)
    $native = $null
    if ($null -ne $ErrorRecord.Exception.PSObject.Properties['NativeErrorCode']) {
        $native = $ErrorRecord.Exception.NativeErrorCode
    }
    if ($ErrorRecord.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR' -or $native -eq 9003) { return 'nxdomain' }
    if ($ErrorRecord.FullyQualifiedErrorId -match 'TIMEOUT|TIMED_OUT' -or $native -eq 1460) { return 'timeout' }
    return 'failed'
}

function Test-LabGuardDnsPath {
    param([string]$Server = '', [string]$ExpectedToken = '')
    $name = [guid]::NewGuid().ToString('N') + '.labguard-check.test.'
    $options = @{ Name = $name; Type = 'TXT'; DnsOnly = $true; NoHostsFile = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
    if ($Server) { $options.Server = $Server }
    try {
        $records = @(Resolve-DnsName @options | Where-Object {
            (([string]$_.Type -in @('TXT', '16')) -or ([string]$_.QueryType -in @('TXT', '16'))) -and
            ([string]$_.Name).TrimEnd('.') -ieq $name.TrimEnd('.')
        })
        if ($records.Count -eq 1) {
            $token = $records[0].Strings -join ''
            if ($token -cmatch '^LabGuard-[0-9a-f]{16}$') {
                if (!$ExpectedToken -or $token -ceq $ExpectedToken) { return [pscustomobject]@{ Status = 'ok'; Token = $token } }
                return [pscustomobject]@{ Status = 'different'; Token = $null }
            }
        }
        return [pscustomobject]@{ Status = 'failed'; Token = $null }
    } catch {
        $status = Get-LabGuardDnsErrorStatus $_
        return [pscustomobject]@{ Status = $status; Token = $null }
    }
}

function Get-LabGuardDesiredState {
    param($Before, [string]$FiltroIPv4)
    return [pscustomobject]@{
        InterfaceIndex = $Before.InterfaceIndex; InterfaceGuid = $Before.InterfaceGuid
        InterfaceAlias = $Before.InterfaceAlias; Registration = $Before.Registration
        IPv4 = [pscustomobject]@{ Mode = 'static'; Servers = @($FiltroIPv4) }
        IPv6BindingEnabled = $false
    }
}

function Test-LabGuardSameFamily {
    param($Current, $Expected, [switch]$AllowAutomaticChanges)
    if ($Current.Mode -ne $Expected.Mode) { return $false }
    if ($AllowAutomaticChanges -and $Expected.Mode -eq 'auto') { return $true }
    return ((@($Current.Servers) -join ',') -ceq (@($Expected.Servers) -join ','))
}

function Test-LabGuardSameAdapter {
    param($Current, $Expected)
    return ($Current.InterfaceGuid -ieq $Expected.InterfaceGuid -and $Current.Registration -eq $Expected.Registration)
}

function Test-LabGuardDesiredState {
    param($Current, $Desired)
    return ((Test-LabGuardSameAdapter $Current $Desired) -and
        (Test-LabGuardSameFamily $Current.IPv4 $Desired.IPv4) -and
        $Current.IPv6BindingEnabled -eq $Desired.IPv6BindingEnabled)
}

function Set-LabGuardDnsFamily {
    param($State, [ValidateSet('IPv4')][string]$Family = 'IPv4', $Setting)
    $arguments = @('interface', 'ipv4', 'set', 'dnsservers', ('name=' + $State.InterfaceIndex), ('register=' + $State.Registration))
    if ($Setting.Mode -eq 'auto') { $arguments += 'source=dhcp' }
    elseif ($Setting.Mode -eq 'static') {
        $first = if (@($Setting.Servers).Count) { [string]$Setting.Servers[0] } else { 'none' }
        $arguments += @('source=static', ('address=' + $first), 'validate=no')
    } else { throw 'Modo DNS desconhecido.' }
    $null = Invoke-LabGuardNetsh $arguments
    if ($Setting.Mode -eq 'static') {
        for ($i = 1; $i -lt @($Setting.Servers).Count; $i++) {
            $null = Invoke-LabGuardNetsh @('interface', 'ipv4', 'add', 'dnsservers', ('name=' + $State.InterfaceIndex), ('address=' + $Setting.Servers[$i]), ('index=' + ($i + 1)), 'validate=no')
        }
    }
}

function Set-LabGuardIPv6Binding {
    param($State, [bool]$Enabled)
    $binding = Get-LabGuardIPv6Binding $State
    if ($binding.Enabled -eq $Enabled) { return }
    if ($Enabled) { $null = Enable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop }
    else { $null = Disable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop }
}

function Clear-LabGuardDnsCache {
    Clear-DnsClientCache -ErrorAction Stop
}

function Test-LabGuardIPv4Ready {
    param($State)
    $adapter = Get-NetAdapter -InterfaceIndex $State.InterfaceIndex -ErrorAction Stop
    if (([guid]$adapter.InterfaceGuid).ToString() -ine $State.InterfaceGuid) { throw 'A identidade do adaptador mudou.' }
    if ($adapter.Status -ne 'Up') { return $false }
    $addresses = @(Get-NetIPAddress -InterfaceIndex $State.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(169\.254\.|127\.|0\.)' })
    return ($addresses.Count -gt 0)
}

function Wait-LabGuardIPv4Ready {
    param($State, [int]$TimeoutSeconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try { if (Test-LabGuardIPv4Ready $State) { return } } catch { }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 500
    } while ($true)
    throw 'O adaptador nao recuperou uma conexao IPv4 pronta no prazo. Confira o cabo, DHCP e a rede antes de repetir.'
}

function Get-LabGuardBackupPath {
    param([string]$InterfaceGuid)
    $guid = ([guid]$InterfaceGuid).ToString()
    return ('HKLM:\SOFTWARE\LabGuard\NetworkDNS\' + $guid)
}

function Assert-LabGuardRegistryAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trusted) { throw 'A copia de DNS tem proprietario nao confiavel.' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ([int]$rule.RegistryRights -band 0xd0026) -and
            $rule.IdentityReference.Value -notin $trusted) { throw 'A copia de DNS exige acesso de escrita restrito a Administradores e SYSTEM.' }
    }
}

function Assert-LabGuardBackupRecord {
    param($Record)
    if ($null -eq $Record -or $Record.SchemaVersion -ne 1 -or $Record.Tool -cne 'LabGuard-DNS-Sem-Cliente' -or
        $Record.Phase -notin @('prepared', 'applied', 'restoring') -or $null -eq $Record.Touched -or
        $Record.Touched.IPv4 -isnot [bool] -or $Record.Touched.IPv6Binding -isnot [bool]) { throw 'Formato da copia de DNS invalido.' }
    $null = Assert-LabGuardFilterAddress $Record.FilterIPv4
    Assert-LabGuardState $Record.Before
    if ($Record.InterfaceGuid -ine $Record.Before.InterfaceGuid) { throw 'Identidade da copia de DNS divergente.' }
    if ($null -ne $Record.After) {
        Assert-LabGuardState $Record.After
        if (!(Test-LabGuardSameAdapter $Record.After $Record.Before)) { throw 'Identidade alterada na copia de DNS.' }
    }
}

function Read-LabGuardBackup {
    param([string]$InterfaceGuid)
    $path = Get-LabGuardBackupPath $InterfaceGuid
    if (!(Test-Path -LiteralPath $path)) { return $null }
    Assert-LabGuardRegistryAcl $path
    $json = (Get-Item -LiteralPath $path -ErrorAction Stop).GetValue('State', $null)
    if ($null -eq $json) { return $null }
    if ($json -isnot [string] -or $json.Length -gt 65536) { throw 'Copia de DNS invalida.' }
    $record = $json | ConvertFrom-Json -ErrorAction Stop
    Assert-LabGuardBackupRecord $record
    if ($record.InterfaceGuid -ine $InterfaceGuid) { throw 'A copia pertence a outro adaptador.' }
    return $record
}

function Save-LabGuardBackup {
    param($Record)
    Assert-LabGuardBackupRecord $Record
    foreach ($parent in @('HKLM:\SOFTWARE\LabGuard', 'HKLM:\SOFTWARE\LabGuard\NetworkDNS', (Get-LabGuardBackupPath $Record.InterfaceGuid))) {
        if (Test-Path -LiteralPath $parent) { Assert-LabGuardRegistryAcl $parent }
        else {
            $null = New-Item -Path $parent -ErrorAction Stop
            $acl = Get-Acl -LiteralPath $parent -ErrorAction Stop
            $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)')
            Set-Acl -LiteralPath $parent -AclObject $acl -ErrorAction Stop
            Assert-LabGuardRegistryAcl $parent
        }
    }
    $path = Get-LabGuardBackupPath $Record.InterfaceGuid
    $json = $Record | ConvertTo-Json -Depth 8 -Compress
    $null = New-ItemProperty -LiteralPath $path -Name 'State' -PropertyType String -Value $json -Force -ErrorAction Stop
}

function Remove-LabGuardBackup {
    param([string]$InterfaceGuid)
    $path = Get-LabGuardBackupPath $InterfaceGuid
    Assert-LabGuardRegistryAcl $path
    Remove-ItemProperty -LiteralPath $path -Name 'State' -ErrorAction Stop
}

function Test-LabGuardRestoreAllowed {
    param($Current, $Record)
    if (!(Test-LabGuardSameAdapter $Current $Record.Before)) { return $false }
    $desired = Get-LabGuardDesiredState $Record.Before $Record.FilterIPv4
    # Once committed, every managed value must still match our last observation.
    # A later administrator enabling IPv6 or replacing DNS is a conflict.
    if ($Record.Phase -eq 'applied') {
        return ($null -ne $Record.After -and
            (Test-LabGuardSameFamily $Current.IPv4 $Record.After.IPv4) -and
            $Current.IPv6BindingEnabled -eq $Record.After.IPv6BindingEnabled)
    }
    if (!$Record.Touched.IPv6Binding -and $Current.IPv6BindingEnabled -ne $Record.Before.IPv6BindingEnabled) { return $false }
    if (!$Record.Touched.IPv4 -and !(Test-LabGuardSameFamily $Current.IPv4 $Record.Before.IPv4 -AllowAutomaticChanges)) { return $false }
    $dnsAllowed = Test-LabGuardSameFamily $Current.IPv4 $Record.Before.IPv4 -AllowAutomaticChanges
    if (!$dnsAllowed -and $null -ne $Record.After) { $dnsAllowed = Test-LabGuardSameFamily $Current.IPv4 $Record.After.IPv4 }
    if (!$dnsAllowed -and $null -eq $Record.After) { $dnsAllowed = Test-LabGuardSameFamily $Current.IPv4 $desired.IPv4 }
    if (!$dnsAllowed -and $Record.Phase -eq 'restoring' -and $Current.IPv4.Mode -eq 'static' -and $Record.Before.IPv4.Mode -eq 'static') {
        $now = @($Current.IPv4.Servers); $original = @($Record.Before.IPv4.Servers)
        $dnsAllowed = ($now.Count -gt 0 -and $now.Count -lt $original.Count -and
            ($now -join ',') -ceq ($original[0..($now.Count - 1)] -join ','))
    }
    return ($dnsAllowed -and
        ($Current.IPv6BindingEnabled -eq $Record.Before.IPv6BindingEnabled -or $Current.IPv6BindingEnabled -eq $desired.IPv6BindingEnabled))
}

function Invoke-LabGuardRestoreRecord {
    param($Record, [int]$InterfaceIndex)
    Assert-LabGuardBackupRecord $Record
    $current = Get-LabGuardAdapterState $InterfaceIndex
    if (!(Test-LabGuardRestoreAllowed $current $Record)) {
        throw 'O adaptador, DNS ou binding IPv6 foi alterado por outra politica. A copia foi preservada; a TI deve revisar antes de restaurar.'
    }
    $Record.Phase = 'restoring'
    Save-LabGuardBackup $Record
    if ($Record.Touched.IPv4 -and !(Test-LabGuardSameFamily $current.IPv4 $Record.Before.IPv4 -AllowAutomaticChanges)) {
        Set-LabGuardDnsFamily -State $current -Family 'IPv4' -Setting $Record.Before.IPv4
    }
    $current = Get-LabGuardAdapterState $InterfaceIndex
    if (!(Test-LabGuardRestoreAllowed $current $Record)) { throw 'Outra politica alterou a configuracao durante a restauracao.' }
    if ($Record.Touched.IPv6Binding) { Set-LabGuardIPv6Binding -State $current -Enabled $Record.Before.IPv6BindingEnabled }
    Wait-LabGuardIPv4Ready $current
    Clear-LabGuardDnsCache
    $current = Get-LabGuardAdapterState $InterfaceIndex
    if (!(Test-LabGuardSameAdapter $current $Record.Before) -or
        !(Test-LabGuardSameFamily $current.IPv4 $Record.Before.IPv4 -AllowAutomaticChanges) -or
        $current.IPv6BindingEnabled -ne $Record.Before.IPv6BindingEnabled) {
        throw 'Nao foi possivel confirmar a restauracao. A copia continua guardada.'
    }
    Remove-LabGuardBackup $Record.InterfaceGuid
}

function Invoke-LabGuardApply {
    param([string]$FiltroIPv4, [int]$InterfaceIndex, $ExpectedState = $null)
    if (!(Test-LabGuardAdministrator)) { throw 'Execute o PowerShell como administrador para aplicar.' }
    $filter = Assert-LabGuardFilterAddress $FiltroIPv4
    $before = Get-LabGuardAdapterState $InterfaceIndex
    if ($null -ne (Read-LabGuardBackup $before.InterfaceGuid)) { throw 'Ja existe uma copia neste adaptador. Use Restaurar antes de aplicar novamente.' }
    if ($null -ne $ExpectedState -and (($before | ConvertTo-Json -Depth 6 -Compress) -cne ($ExpectedState | ConvertTo-Json -Depth 6 -Compress))) {
        throw 'A configuracao mudou desde a previa. Execute novamente e confira os valores.'
    }
    Wait-LabGuardIPv4Ready $before
    $direct = Test-LabGuardDnsPath -Server $filter
    if ($direct.Status -ne 'ok') { throw 'O filtro nao respondeu ao teste direto com um codigo LabGuard valido. Nada foi alterado. Confira IP e UDP/TCP 53.' }
    $record = [pscustomobject]@{
        SchemaVersion = 1; Tool = 'LabGuard-DNS-Sem-Cliente'; CreatedUtc = [DateTime]::UtcNow.ToString('o')
        FilterIPv4 = $filter; InterfaceGuid = $before.InterfaceGuid; Before = $before; After = $null; Phase = 'prepared'
        Touched = [pscustomobject]@{ IPv4 = $false; IPv6Binding = $false }
    }
    Save-LabGuardBackup $record
    $desired = Get-LabGuardDesiredState $before $filter
    try {
        $current = Get-LabGuardAdapterState $InterfaceIndex
        if (!(Test-LabGuardSameAdapter $current $before) -or
            !(Test-LabGuardSameFamily $current.IPv4 $before.IPv4) -or $current.IPv6BindingEnabled -ne $before.IPv6BindingEnabled) {
            throw 'A configuracao mudou antes da aplicacao.'
        }
        $record.Touched.IPv4 = $true
        Save-LabGuardBackup $record
        Set-LabGuardDnsFamily -State $before -Family 'IPv4' -Setting $desired.IPv4
        $current = Get-LabGuardAdapterState $InterfaceIndex
        if (!(Test-LabGuardSameAdapter $current $before) -or
            !(Test-LabGuardSameFamily $current.IPv4 $desired.IPv4) -or $current.IPv6BindingEnabled -ne $before.IPv6BindingEnabled) {
            throw 'Outra politica alterou o adaptador antes da mudanca de IPv6.'
        }
        if ($current.IPv6BindingEnabled) {
            $record.Touched.IPv6Binding = $true
            Save-LabGuardBackup $record
            Set-LabGuardIPv6Binding -State $current -Enabled $false
        }
        Wait-LabGuardIPv4Ready $current
        Clear-LabGuardDnsCache
        $after = Get-LabGuardAdapterState $InterfaceIndex
        if (!(Test-LabGuardDesiredState $after $desired)) { throw 'DNS ou binding IPv6 nao corresponde ao estado solicitado.' }
        $record.After = $after
        Save-LabGuardBackup $record
        $default = Test-LabGuardDnsPath -ExpectedToken $direct.Token
        if ($default.Status -ne 'ok') { throw 'O DNS padrao nao retornou o codigo da mesma sessao do filtro.' }
        $afterProbe = Get-LabGuardAdapterState $InterfaceIndex
        if (!(Test-LabGuardDesiredState $afterProbe $desired)) { throw 'A configuracao mudou durante a verificacao.' }
        $record.After = $afterProbe; $record.Phase = 'applied'
        Save-LabGuardBackup $record
        return [pscustomobject]@{ Ok = $true; RolledBack = $false; Message = 'DNS IPv4 aplicado, binding IPv6 desabilitado neste adaptador e teste padrao confirmado nesta estacao. Teste o navegador e repita o diagnostico depois de reiniciar.' }
    } catch {
        $reason = $_.Exception.Message
        if (!$record.Touched.IPv4 -and !$record.Touched.IPv6Binding) {
            Remove-LabGuardBackup $record.InterfaceGuid
            return [pscustomobject]@{ Ok = $false; RolledBack = $false; Message = ('Nenhuma configuracao foi alterada. Motivo: ' + $reason) }
        }
        try {
            Invoke-LabGuardRestoreRecord -Record $record -InterfaceIndex $InterfaceIndex
            return [pscustomobject]@{ Ok = $false; RolledBack = $true; Message = ('A aplicacao falhou e o DNS/binding anteriores foram restaurados. Motivo: ' + $reason) }
        } catch {
            return [pscustomobject]@{ Ok = $false; RolledBack = $false; Message = ('A aplicacao falhou e a restauracao nao foi confirmada. A copia foi preservada. Use Restaurar e revise o adaptador com a TI. Motivo: ' + $reason + ' Restauracao: ' + $_.Exception.Message) }
        }
    }
}

function Invoke-LabGuardRestore {
    param([int]$InterfaceIndex)
    if (!(Test-LabGuardAdministrator)) { throw 'Execute o PowerShell como administrador para restaurar.' }
    $current = Get-LabGuardAdapterState $InterfaceIndex
    $record = Read-LabGuardBackup $current.InterfaceGuid
    if ($null -eq $record) { throw 'Nenhuma copia do DNS foi encontrada para este adaptador.' }
    Invoke-LabGuardRestoreRecord -Record $record -InterfaceIndex $InterfaceIndex
    return [pscustomobject]@{ Ok = $true; Message = 'DNS IPv4 e binding IPv6 restaurados ao estado anterior. Nenhum cliente foi instalado.' }
}

function Get-LabGuardBrowserDnsPolicy {
    $rows = @()
    foreach ($browser in @(@{ Name = 'Chrome'; Key = 'Google\Chrome' }, @{ Name = 'Edge'; Key = 'Microsoft\Edge' })) {
        foreach ($hive in @('HKLM:', 'HKCU:')) {
            $path = $hive + '\SOFTWARE\Policies\' + $browser.Key
            $mode = 'Nao definida'
            if (Test-Path -LiteralPath $path) {
                $value = (Get-Item -LiteralPath $path -ErrorAction Stop).GetValue('DnsOverHttpsMode', $null)
                if ($null -ne $value) { $mode = [string]$value }
            }
            $rows += [pscustomobject]@{ Browser = $browser.Name; Scope = $hive; DnsOverHttpsMode = $mode }
        }
    }
    return $rows
}

function Test-LabGuardDomainQuery {
    param([string]$Domain, [ValidateSet('A', 'AAAA')][string]$Type, [string]$Server = '')
    if ($Domain.Length -gt 253 -or $Domain -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$') {
        throw 'DominioTeste deve ser somente um dominio, sem https, caminho ou espacos.'
    }
    $options = @{ Name = ($Domain + '.'); Type = $Type; DnsOnly = $true; NoHostsFile = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
    if ($Server) { $options.Server = $Server }
    try {
        $records = @(Resolve-DnsName @options)
        $answers = @($records | Where-Object { ([string]$_.Type -eq $Type -or [string]$_.QueryType -eq $Type) -and $_.IPAddress })
        $status = if ($answers.Count) { 'resolved' } else { 'no_address' }
    } catch {
        $status = Get-LabGuardDnsErrorStatus $_
    }
    return [pscustomobject]@{ Domain = $Domain; Type = $Type; Path = $(if ($Server) { 'direct' } else { 'default' }); Status = $status }
}

function Invoke-LabGuardDiagnose {
    param([string]$FiltroIPv4 = '', [int]$InterfaceIndex = 0, [string]$DominioTeste = '')
    $adapters = if ($InterfaceIndex -gt 0) { @(Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop) } else { @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }) }
    $readings = @()
    foreach ($adapter in $adapters) {
        try { $readings += [pscustomobject]@{ InterfaceIndex = $adapter.ifIndex; InterfaceAlias = $adapter.Name; State = (Get-LabGuardAdapterState $adapter.ifIndex); Dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | Select-Object AddressFamily, ServerAddresses); Error = $null } }
        catch {
            # A diagnostic remains useful when the complete adapter state cannot be read.
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Select-Object AddressFamily, ServerAddresses)
            $readings += [pscustomobject]@{ InterfaceIndex = $adapter.ifIndex; InterfaceAlias = $adapter.Name; State = $null; Dns = $dns; Error = $_.Exception.Message }
        }
    }
    $browser = @(Get-LabGuardBrowserDnsPolicy)
    $paths = [pscustomobject]@{ Direct = 'not_requested'; Default = 'not_requested'; SameSession = $false }
    $domainResults = @()
    if ($FiltroIPv4) {
        $filter = Assert-LabGuardFilterAddress $FiltroIPv4
        $direct = Test-LabGuardDnsPath -Server $filter
        $default = Test-LabGuardDnsPath -ExpectedToken $(if ($direct.Status -eq 'ok') { $direct.Token } else { '' })
        $paths = [pscustomobject]@{ Direct = $direct.Status; Default = $default.Status; SameSession = ($direct.Status -eq 'ok' -and $default.Status -eq 'ok' -and $direct.Token -ceq $default.Token) }
        if ($DominioTeste) {
            foreach ($type in @('A', 'AAAA')) {
                $domainResults += Test-LabGuardDomainQuery -Domain $DominioTeste -Type $type -Server $filter
                $domainResults += Test-LabGuardDomainQuery -Domain $DominioTeste -Type $type
            }
        }
    } elseif ($DominioTeste) { throw 'Informe FiltroIPv4 para comparar as consultas do dominio.' }
    return [pscustomobject]@{
        Ok = $true; Mode = 'Diagnosticar'; Adapters = $readings; Paths = $paths; DomainQueries = $domainResults; BrowserPolicies = $browser
        Notes = @('Diagnostico somente leitura: nenhuma configuracao alterada.', 'NXDOMAIN sozinho nao comprova bloqueio do LabGuard. Confira dominio, IP e horario em Atividade.', 'O binding IPv6 e mostrado por adaptador. Outros adaptadores, VPN e DNS seguro podem usar outro caminho; a ferramenta altera somente a interface escolhida.', 'Politica DoH ausente nao significa DoH desligado. Confira chrome://settings/security, edge://settings/privacy e as politicas efetivas do navegador.', 'Este teste DNS nao comprova que o navegador ou todos os aplicativos usam o filtro.')
    }
}

function Invoke-LabGuardDnsTool {
    [CmdletBinding()]
    param([string]$Modo = 'Diagnosticar', [string]$FiltroIPv4 = '', [int]$InterfaceIndex = 0, [string]$DominioTeste = '', [switch]$ConfirmarAlteracao)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Esta ferramenta deve ser executada no Windows.' }
    if ($Modo -eq 'Diagnosticar') { return Invoke-LabGuardDiagnose -FiltroIPv4 $FiltroIPv4 -InterfaceIndex $InterfaceIndex -DominioTeste $DominioTeste }
    if ($DominioTeste) { throw 'Use DominioTeste no modo Diagnosticar, antes ou depois da alteracao.' }
    if ($Modo -notin @('Aplicar', 'Restaurar') -or $InterfaceIndex -lt 1) { throw 'Aplicar e Restaurar exigem um InterfaceIndex explicito.' }
    if (!(Test-LabGuardAdministrator)) { throw 'Abra o PowerShell como administrador.' }
    $preview = Get-LabGuardAdapterState $InterfaceIndex
    Write-Host ('Adaptador selecionado: ' + $preview.InterfaceAlias + ' (indice ' + $preview.InterfaceIndex + ')')
    Write-Host ('DNS IPv4 atual: ' + $preview.IPv4.Mode + ' / ' + (@($preview.IPv4.Servers) -join ', '))
    Write-Host ('Binding IPv6 atual (ms_tcpip6): Enabled = ' + $preview.IPv6BindingEnabled)
    if ($Modo -eq 'Aplicar') {
        $filter = Assert-LabGuardFilterAddress $FiltroIPv4
        Write-Host ('Aplicar: somente DNS IPv4 ' + $filter + '; binding ms_tcpip6 desabilitado neste adaptador; cache DNS limpo.')
        Write-Host 'A TI deve manter nomes internos/Active Directory acessiveis pelo DNS de saida do filtro. O PC do filtro precisa permanecer ligado.'
    } else {
        $saved = Read-LabGuardBackup $preview.InterfaceGuid
        if ($null -eq $saved) { throw 'Nenhuma copia foi encontrada para este adaptador.' }
        Write-Host ('Restaurar IPv4: ' + $saved.Before.IPv4.Mode + ' / ' + (@($saved.Before.IPv4.Servers) -join ', '))
        Write-Host ('Restaurar binding IPv6: Enabled = ' + $saved.Before.IPv6BindingEnabled)
    }
    Write-Host 'A placa pode reiniciar e interromper a conexao por alguns segundos. Execute localmente na estacao piloto. IP/gateway IPv4, outros adaptadores e politicas de navegador nao serao modificados.'
    $confirmation = $Modo.ToUpperInvariant()
    if (!$ConfirmarAlteracao -and (Read-Host ('Digite ' + $confirmation + ' para confirmar esta operacao')) -cne $confirmation) {
        return [pscustomobject]@{ Ok = $false; Message = 'Cancelado. Nenhuma configuracao foi alterada.' }
    }
    $guard = New-Object Threading.Mutex($false, 'Global\LabGuardNetworkDNS')
    $locked = $false
    try {
        try { $locked = $guard.WaitOne(3000) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (!$locked) { throw 'Outra operacao de DNS LabGuard esta em andamento.' }
        if ($Modo -eq 'Aplicar') { return Invoke-LabGuardApply -FiltroIPv4 $FiltroIPv4 -InterfaceIndex $InterfaceIndex -ExpectedState $preview }
        return Invoke-LabGuardRestore -InterfaceIndex $InterfaceIndex
    } finally {
        if ($locked) { $guard.ReleaseMutex() }
        $guard.Dispose()
    }
}

# Dot-source only defines functions, so verification can replace IO wrappers safely.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = Invoke-LabGuardDnsTool @PSBoundParameters
        $result | ConvertTo-Json -Depth 10
        if (!$result.Ok) { exit 1 }
    } catch {
        Write-Error ('LabGuard: ' + $_.Exception.Message)
        exit 1
    }
}
