# Only the project's newly provisioned GitHub-hosted Windows runner.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Exe)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Execute apenas no Windows efêmero hospedado pelo GitHub.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'O teste requer o administrador da máquina de CI.'
}
$Exe = (Get-Item -LiteralPath $Exe).FullName
$taskName = 'LabGuardCliente'
$install = Join-Path $env:ProgramFiles 'LabGuardCliente'
if ((Test-Path -LiteralPath $install) -or (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'Instalação anterior encontrada. O teste exige uma máquina nova.'
}

function Invoke-Client([string[]]$ClientArguments) {
    $diagnostic = $null
    if ('--saida' -notin $ClientArguments) {
        $diagnostic = Join-Path $fixtureDir ('retorno-' + [Guid]::NewGuid().ToString('N') + '.json')
        $ClientArguments += @('--json', '--saida', $diagnostic)
    }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Exe
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    foreach ($argument in $ClientArguments) { $info.ArgumentList.Add($argument) }
    $p = [Diagnostics.Process]::Start($info)
    try {
        if (-not $p.WaitForExit(140000)) {
            $p.Kill($true)
            throw 'Tempo de execução excedido.'
        }
        if ($p.ExitCode -ne 0) {
            $detail = if ($diagnostic -and (Test-Path -LiteralPath $diagnostic)) { Get-Content -LiteralPath $diagnostic -Raw } else { '(sem relatório)' }
            throw "Comando $($ClientArguments[0]) devolveu código $($p.ExitCode). $detail"
        }
    } finally {
        $p.Dispose()
        if ($diagnostic -and (Test-Path -LiteralPath $diagnostic -PathType Leaf)) { Remove-Item -LiteralPath $diagnostic }
    }
}

function Get-RegistryStrings([string]$KeyPath) {
    $key = $base.OpenSubKey($KeyPath, $false)
    if ($null -eq $key) { return }
    try {
        foreach ($name in $key.GetValueNames()) {
            if ($key.GetValueKind($name) -eq [Microsoft.Win32.RegistryValueKind]::String) { [string]$key.GetValue($name) }
        }
    } finally { $key.Dispose() }
}

function Wait-Until([scriptblock]$Condition, [string]$Message, [int]$Timeout = 90) {
    $limit = [DateTime]::UtcNow.AddSeconds($Timeout)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $limit)
    $workerFile = Join-Path $install 'status.json'
    if (Test-Path -LiteralPath $workerFile -PathType Leaf) {
        $Message += ' ' + (Get-Content -LiteralPath $workerFile -Raw)
    }
    throw $Message
}

$fixtureDir = Join-Path $env:RUNNER_TEMP ('labguard-cliente-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -Type Directory -Path $fixtureDir
$policyFile = Join-Path $fixtureDir 'politica.json'
$reportFile = Join-Path $fixtureDir 'resultado.json'
$bankFile = Join-Path $fixtureDir 'banco.json'
$withBank = Join-Path $fixtureDir 'politica-com-banco.json'
$domain = 'jogo.labguard.test'
$fixture = @{ catalog_enabled = $false; domains = @($domain); games = @(); remove_roblox = $false; mode = 'bloqueados'; allowed_domains = @() }
$fixture | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $policyFile -Encoding utf8NoBOM
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$edge = 'SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
$chrome = 'SOFTWARE\Policies\Google\Chrome\URLBlocklist'
$firefox = 'SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block'
$sentinelName = '999'
$sentinel = 'preexistente.labguard.test'
$hostsFile = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
$originalHostsLength = (Get-Item -LiteralPath $hostsFile).Length
$originalHostsHash = (Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash
$positiveHost = 'permitido-' + [Guid]::NewGuid().ToString('N') + '.labguard.test'
$addedHostsControl = $false
$addedSentinel = $false
$installStarted = $false
try {
    # A real hosts-based allowed name distinguishes Windows NoData for a null
    # destination from a general inability to resolve names on this runner.
    $stream = [IO.File]::Open($hostsFile, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $line = [Text.Encoding]::ASCII.GetBytes("`r`n127.0.0.1 $positiveHost # prova local de CI`r`n")
        $stream.Write($line, 0, $line.Length)
        $addedHostsControl = $true
    } finally { $stream.Dispose() }
    $beforeHosts = (Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash
    Wait-Until {
        try { '127.0.0.1' -in @([Net.Dns]::GetHostAddresses($positiveHost).IPAddressToString) }
        catch { $false }
    } 'O resolvedor não encontrou o controle positivo da máquina de teste antes de instalar.' 25
    $key = $base.CreateSubKey($edge)
    try {
        if ($key.GetValueNames() -contains $sentinelName) { throw 'A chave reservada pelo teste já existia.' }
        $key.SetValue($sentinelName, $sentinel, [Microsoft.Win32.RegistryValueKind]::String)
        $addedSentinel = $true
    } finally { $key.Dispose() }
    $installStarted = $true
    $boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $requestedUtc = [DateTimeOffset]::UtcNow.AddSeconds(-2)
    Invoke-Client @('instalar', '--politica', $policyFile, '--sim')
    $t = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($t.Principal.UserId -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18') -or $t.Settings.Hidden) {
        throw 'A identidade ou a visibilidade da tarefa não corresponde ao cliente.'
    }
    if ('MSFT_TaskBootTrigger' -notin @($t.Triggers.CimClass.CimClassName)) { throw 'Inicialização no boot ausente.' }
    if (-not (Test-Path -LiteralPath (Join-Path $install 'LabGuardCliente.exe') -PathType Leaf)) { throw 'Executável instalado ausente.' }
    Wait-Until {
        $workerFile = Join-Path $install 'status.json'
        if (-not (Test-Path -LiteralPath $workerFile -PathType Leaf)) { return $false }
        $data = Get-Content -LiteralPath $workerFile -Raw | ConvertFrom-Json
        return $data.ok -eq $true
    } 'O agente não confirmou o primeiro ciclo.'
    if ((Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime -ne $boot) { throw 'O PC reiniciou durante o ensaio.' }
    $current = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ([string]$current.State -ne 'Running') { throw 'A proteção não iniciou na sessão atual.' }
    $firstCycle = Get-Content -LiteralPath (Join-Path $install 'status.json') -Raw | ConvertFrom-Json
    if ([DateTimeOffset]$firstCycle.checked_at -lt $requestedUtc) { throw 'A evidência do primeiro ciclo não pertence à instalação.' }
    Write-Output 'O Windows iniciou o cliente e aplicou o primeiro ciclo sem reiniciar ou abrir outra sessão.'
    Invoke-Client @('status', '--json', '--saida', $reportFile)
    $data = Get-Content -LiteralPath $reportFile -Raw | ConvertFrom-Json
    if (-not $data.installed -or -not $data.ok) { throw "A verificação não confirmou a instalação. $($data.situacao)" }
    foreach ($path in @($chrome, $edge)) {
        if ($domain -notin @(Get-RegistryStrings $path)) { throw "Política não aplicada a $path." }
    }
    if ("*://*.$domain/*" -notin @(Get-RegistryStrings $firefox)) { throw 'Política do Firefox ausente.' }
    if ($sentinel -notin @(Get-RegistryStrings $edge)) { throw 'A política preexistente do navegador foi removida.' }
    $hostsLines = [IO.File]::ReadAllLines($hostsFile)
    foreach ($address in @('0.0.0.0', '::')) {
        $pattern = '^\s*' + [Regex]::Escape($address) + '\s+' + [Regex]::Escape($domain) + '(?:\s|$)'
        if (-not ($hostsLines -match $pattern)) { throw "Faltou a entrada do cliente no hosts para $address." }
    }

    if ('127.0.0.1' -notin @([Net.Dns]::GetHostAddresses($positiveHost).IPAddressToString)) {
        throw 'O nome do controle positivo não foi resolvido durante o bloqueio.'
    }
    try {
        $resolved = @([Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString })
        if ($resolved.Count -eq 0 -or @($resolved | Where-Object { $_ -notin @('0.0.0.0', '::') }).Count -gt 0) {
            throw 'O domínio protegido devolveu um destino utilizável ou uma resposta inesperada.'
        }
    } catch {
        $e = $_.Exception
        while ($null -ne $e -and $e -isnot [Net.Sockets.SocketException]) { $e = $e.InnerException }
        if ($null -eq $e -or $e.NativeErrorCode -ne 11004) { throw }
        Write-Output 'WinSock devolveu WSA_NO_DATA ao nome protegido. As duas entradas do hosts e o nome de controle foram conferidos.'
    }
    python "$PSScriptRoot/smoke_browser.py" protegido
    if ($LASTEXITCODE -ne 0) { throw 'Falha no teste de navegação com o cliente ativo.' }

    # The catalog always ships locally. The initial policy isolates a single test hostname.
    $db = Join-Path $install 'banco.sqlite3'
    if (-not (Test-Path -LiteralPath $db -PathType Leaf)) { throw 'Banco do cliente ausente.' }
    @'
import pathlib, sqlite3, sys
with sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri() + "?mode=ro", uri=True) as db:
    if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise SystemExit("Falha de integridade do banco da instalação.")
'@ | python - $db
    if ($LASTEXITCODE -ne 0) { throw 'O banco SQLite do cliente não passou na verificação.' }
    Invoke-Client @('banco-listar', '--json', '--saida', $bankFile)
    $catalog = Get-Content -LiteralPath $bankFile -Raw | ConvertFrom-Json
    foreach ($category in @('jogos', 'roblox', 'minecraft', 'ia', 'adultos', 'apostas')) {
        $row = @($catalog.categories | Where-Object { $_.category -ceq $category })
        if ($row.Count -ne 1 -or [int]$row[0].total -lt 1) { throw "O banco não contém entradas de $category." }
        Write-Output "Catálogo $category - $($row[0].total) domínios iniciais."
    }
    if ('roblox.com' -in @(Get-RegistryStrings $edge)) { throw 'O catálogo foi aplicado embora desativado na política de teste.' }
    $fixture.catalog_enabled = $true
    $fixture | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $withBank -Encoding utf8NoBOM
    Invoke-Client @('politica', '--politica', $withBank, '--sim')
    Wait-Until {
        $cycle = Get-Content -LiteralPath (Join-Path $install 'status.json') -Raw | ConvertFrom-Json
        $cycle.ok -and [int]$cycle.active_domains -gt 1 -and ('roblox.com' -in @(Get-RegistryStrings $edge)) -and ('roblox.com' -in @(Get-RegistryStrings $chrome))
    } 'O catálogo local habilitado não chegou aos navegadores.' 240
    Invoke-Client @('politica', '--politica', $policyFile, '--sim')
    Wait-Until {
        $cycle = Get-Content -LiteralPath (Join-Path $install 'status.json') -Raw | ConvertFrom-Json
        $cycle.ok -and [int]$cycle.active_domains -eq 1 -and ('roblox.com' -notin @(Get-RegistryStrings $edge)) -and ('roblox.com' -notin @(Get-RegistryStrings $chrome))
    } 'O cliente não retirou as regras do catálogo após desativá-lo.' 240
    if ($domain -notin @(Get-RegistryStrings $edge) -or $sentinel -notin @(Get-RegistryStrings $edge)) {
        throw 'A troca do catálogo alterou a regra personalizada ou a regra do administrador anterior.'
    }
    Write-Output 'Conferidos SQLite local, seis categorias, aplicação e remoção das regras sem reiniciar a estação.'
    Invoke-Client @('remover', '--sim')
    $installStarted = $false
    Wait-Until { -not (Test-Path -LiteralPath $install) } 'A pasta de instalação permaneceu após desinstalar.' 40
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'A tarefa ainda existe.' }
    foreach ($path in @($edge, $chrome, $firefox)) {
        if ((@(Get-RegistryStrings $path) -contains $domain) -or (@(Get-RegistryStrings $path) -contains "*://*.$domain/*")) {
            throw 'Política do cliente permaneceu após desinstalação.'
        }
    }
    if ($sentinel -notin @(Get-RegistryStrings $edge)) { throw 'A desinstalação removeu uma regra preexistente.' }
    if ((Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash -ne $beforeHosts) { throw 'O hosts original não foi restaurado.' }
    python "$PSScriptRoot/smoke_browser.py" restaurado
    if ($LASTEXITCODE -ne 0) { throw 'Falha no teste de navegação após remover o cliente.' }
    Write-Output 'Confirmados boot, conta SYSTEM, políticas reais de site, diagnóstico e desinstalação com restauração do hosts e regra externa preservada.'
} finally {
    if ($installStarted -and (Test-Path -LiteralPath $install)) {
        try { Invoke-Client @('remover', '--sim') } catch { Write-Warning 'A desinstalação de limpeza não terminou no runner.' }
    }
    if ($addedSentinel) {
        $key = $base.OpenSubKey($edge, $true)
        if ($null -ne $key) {
            try { if ($key.GetValue($sentinelName) -eq $sentinel) { $key.DeleteValue($sentinelName) } } finally { $key.Dispose() }
        }
    }
    $base.Dispose()
    if ($addedHostsControl) {
        if ((Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash -eq $beforeHosts) {
            $stream = [IO.File]::Open($hostsFile, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $stream.SetLength($originalHostsLength) } finally { $stream.Dispose() }
            if ((Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash -ne $originalHostsHash) {
                throw 'O conteúdo original do arquivo hosts não foi reconstituído.'
            }
        } else {
            Write-Warning 'O hosts mudou durante a limpeza. A cópia atual foi preservada no runner efêmero.'
        }
    }
    foreach ($file in @($policyFile, $withBank, $bankFile, $reportFile)) {
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    if (-not (Get-ChildItem -LiteralPath $fixtureDir -Force)) { Remove-Item -LiteralPath $fixtureDir }
}
