# Synthetic fixtures, isolated HKCU policies, harmless task. Never remove real games.
$ErrorActionPreference='Stop';$root=$PSScriptRoot
$source=[IO.File]::ReadAllText((Join-Path $root 'dist\Engine.assembled.ps1')).Replace("`r`n","`n")
$entry="try {`n    if (`$Mode -eq 'Test') {";$pos=$source.IndexOf($entry,[StringComparison]::Ordinal);if($pos -lt 0){throw 'Test entrypoint not found.'}
. ([scriptblock]::Create($source.Substring(0,$pos))) -Mode Audit
Assert-Admin
$fixture=Join-Path $root ('Verify-'+[guid]::NewGuid().ToString('N'));$reg='HKCU:\Software\LabGuardVerify\'+[guid]::NewGuid().ToString('N');$script:GuardianTaskName='LabGuard-Verify-'+[guid]::NewGuid().ToString('N')
function Check([bool]$Condition,[string]$Label){if(-not $Condition){throw ('VERIFY FAILED: '+$Label)};Write-Host ('PASS: '+$Label)}
try{
    New-Item -ItemType Directory -Path $fixture|Out-Null;$Data=$fixture
    $script:BrowserKeys=@(($reg+'\Chrome\URLBlocklist'),($reg+'\Edge\URLBlocklist'),($reg+'\Mozilla\WebsiteFilter\Block'))
    foreach($path in $script:BrowserKeys){New-Item -Path $path -Force|Out-Null;New-ItemProperty -LiteralPath $path -Name '1' -Value 'intranet.escola.example' -PropertyType String|Out-Null}
    Test-Extensions;Test-WindowsGames
    Set-YouTubeBrowserPolicies $true
    $state=Join-Path $Data 'youtube-owned-rules.json';$first=[IO.File]::ReadAllText($state);Set-YouTubeBrowserPolicies $true
    Check ([IO.File]::ReadAllText($state) -eq $first) 'Browser policy application is idempotent'
    foreach($path in $script:BrowserKeys){Check ((Get-Item -LiteralPath $path).GetValue('1') -eq 'intranet.escola.example') 'Existing browser rule preserved'}
    $owned=@(Get-Content -LiteralPath $state -Raw|ConvertFrom-Json);$changed=$owned[0];Set-ItemProperty -LiteralPath $changed.Key -Name $changed.Name -Value 'external-administrator.example';Set-YouTubeBrowserPolicies $false
    Check ((Get-Item -LiteralPath $changed.Key).GetValue($changed.Name) -eq 'external-administrator.example') 'Externally changed rule is not removed'
    foreach($path in $script:BrowserKeys){Check ((Get-Item -LiteralPath $path).GetValue('1') -eq 'intranet.escola.example') 'Unblocking preserves unrelated policy'}
    $raw=[Text.Encoding]::ASCII.GetBytes('127.0.0.1 localhost');$roundtrip=Convert-YouTubeHosts (Convert-YouTubeHosts $raw $true) $false
    Check ([Convert]::ToBase64String($raw) -eq [Convert]::ToBase64String($roundtrip)) 'Hosts without final newline restores exactly'
    $ConfigPath=Join-Path $fixture 'config.json';[IO.File]::WriteAllText($ConfigPath,'{"Enabled":true,"Screenshots":false,"AdditionalFolders":[]}');Read-Config;Write-Config
    Check ($script:Config.AutoCloseGames -eq $true -and $script:Config.BlockYouTube -eq $true) 'Upgrade enables requested protections'
    # Test mutex, latest policy selection and status persistence without touching real hosts/DNS.
    function Set-YouTubeHosts([bool]$Blocked){$script:HostTestValue=$Blocked}
    function Clear-DnsClientCache{[CmdletBinding()]param()}
    Apply-YouTube $true
    $status=Get-Content -LiteralPath (Join-Path $Data 'youtube-status.json') -Raw|ConvertFrom-Json
    Check ($status.blocked -eq $true -and $script:HostTestValue -eq $true) 'YouTube full control flow writes confirmed status'
    $script:Config.BlockYouTube=$false;Write-Config;Apply-YouTube $true
    $status=Get-Content -LiteralPath (Join-Path $Data 'youtube-status.json') -Raw|ConvertFrom-Json
    Check ($status.blocked -eq $false -and $script:HostTestValue -eq $false) 'Latest saved release overrides stale cycle request'
    $Exe=Join-Path $env:windir 'System32\whoami.exe';Register-GuardianTask;$task=Get-ScheduledTask -TaskName $script:GuardianTaskName
    Check ($task.Principal.UserId -in @('S-1-5-18','SYSTEM','NT AUTHORITY\SYSTEM')) 'Guardian uses SYSTEM'
    Check ([string]$task.Principal.RunLevel -eq 'Highest') 'Guardian uses administrative run level'
    Check (@($task.Triggers|Where-Object {$_.Repetition.Interval -eq 'PT1M'}).Count -eq 1) 'Recovery trigger every minute'
    Check (@($task.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'}).Count -eq 1) 'Guardian starts at boot'
    Check ([string]$task.Settings.MultipleInstances -eq 'IgnoreNew') 'No overlapping guardians'
    Check ($task.Settings.RestartCount -eq 5) 'Restart on failure configured'
    Write-Host 'ALL V2.1 INTEGRATION CHECKS PASSED; no real games or hosts file changed.'
}finally{
    Stop-ScheduledTask -TaskName $script:GuardianTaskName -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $script:GuardianTaskName -Confirm:$false -ErrorAction SilentlyContinue
    if(Test-Path -LiteralPath $reg){Remove-Item -LiteralPath $reg -Recurse -Force}
    if((Test-Path -LiteralPath $fixture) -and (Split-Path $fixture -Leaf) -match '^Verify-[a-f0-9]{32}$'){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
