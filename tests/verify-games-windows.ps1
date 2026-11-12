# Integration verification in a disposable Windows runner. Does not scan actual installations.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$source=[IO.File]::ReadAllText((Join-Path $repo 'games\Engine.ps1')).Replace("`r`n","`n")
$policy=[IO.File]::ReadAllText((Join-Path $repo 'games\Policy.ps1')).Replace("`r`n","`n")
$entry="try {`n    if (`$Mode -eq 'Test') {"
$pos=$source.IndexOf($entry,[StringComparison]::Ordinal)
if($pos -lt 0){throw 'Entrypoint not found; no test execution allowed.'}
$helpers=$source.Substring(0,$pos)+"`n"+$policy
# Dot-source DEFINITIONS only. The real install/cycle entrypoint is never invoked.
. ([scriptblock]::Create($helpers)) -Mode Audit
Assert-Admin
$fixture=Join-Path $env:TEMP ('LabGuardVerify-'+[Guid]::NewGuid().ToString('N'))
$verificationTask='LabGuard-Verification-'+[Guid]::NewGuid().ToString('N')
$checks=New-Object 'System.Collections.Generic.List[string]'
function Verify([bool]$Condition,[string]$Label){if(-not $Condition){throw ('VERIFY FAILED: '+$Label)};$checks.Add($Label);Write-Host ('PASS: '+$Label)}
$junction=$null
try {
    New-Item -ItemType Directory -Path $fixture|Out-Null
    $script:FixedRoots=@([IO.Path]::GetPathRoot($fixture))
    $script:Protected=@($fixture,$env:windir,$env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)},$Base,$Data)|Where-Object {$_}
    $script:Preserved=@();$script:Targets=@{};$script:Deadline=[DateTime]::UtcNow.AddMinutes(3)
    Verify (-not (Safe-Target $fixture -Manual)) 'Fixture root cannot be deleted as a game'
    Verify (-not (Safe-Target $env:windir -Manual)) 'Windows protected'
    foreach($bad in @('C:\Windows\..\Users','\\server\share','C:\Game:stream','C:\Game.\save','C:\Game\..\data')){Verify (-not (Normalize $bad)) ('Reject ambiguous path: '+$bad)}
    foreach($name in @('Steam','Roblox Player for Aluno','Epic Games Launcher','Minecraft Launcher','PCSX2 2.0','RPCS3','Dolphin Emulator','RetroArch','Grand Theft Auto V')){Verify (Matches-Game $name) ('Catalog: '+$name)}
    foreach($name in @('Roblox Studio','Minecraft Education','Unreal Engine','Android Studio','Visual Studio Code','Blender','Projeto de aula')){Verify (-not (Matches-Game $name)) ('Preserve: '+$name)}
    $steam=Join-Path $fixture 'Steam';New-Item -ItemType Directory -Path $steam|Out-Null
    [IO.File]::WriteAllText((Join-Path $steam 'steam.exe'),'test fixture - not an executable')
    Add-Target $steam 'Instalacao reconhecida: Steam'
    Verify (-not $script:Targets.ContainsKey($steam)) 'Shared Steam root not scheduled for recursive deletion'
    Add-Target (Join-Path $steam 'steam.exe') 'Executavel do launcher Steam'
    Verify ($script:Targets.ContainsKey((Join-Path $steam 'steam.exe'))) 'Launcher executable selected separately'
    $game=Join-Path $fixture 'SyntheticGame';New-Item -ItemType Directory -Path (Join-Path $game 'data') -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $game 'game.exe'),'synthetic marker')
    [IO.File]::WriteAllText((Join-Path $game 'data\save.dat'),'synthetic save')
    Delete-Bounded $game $false
    Verify (-not (Test-Path -LiteralPath $game)) 'Bounded deletion removes synthetic game and children'
    $kept=Join-Path $fixture 'KeepProject';New-Item -ItemType Directory -Path $kept|Out-Null
    [IO.File]::WriteAllText((Join-Path $kept 'school.txt'),'must remain')
    $linkedGame=Join-Path $fixture 'LinkedGame';New-Item -ItemType Directory -Path $linkedGame|Out-Null
    $junction=Join-Path $linkedGame 'outside'
    & $env:ComSpec /d /c ('mklink /J "'+$junction+'" "'+$kept+'"')|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not create test junction.'}
    Verify (-not (No-Link $junction)) 'Junction target refused'
    $refused=$false;try{Delete-Bounded $linkedGame $false}catch{$refused=$true}
    Verify $refused 'Deletion stops at an internal junction'
    Verify ([IO.File]::Exists((Join-Path $kept 'school.txt'))) 'Linked school document survives'
    [IO.Directory]::Delete($junction,$false);$junction=$null
    $secure=Join-Path $fixture 'ProtectedInstall';Secure-Directory $secure
    [IO.File]::WriteAllText((Join-Path $secure 'config.json'),'{}')
    Secure-Directory $secure
    $acl=Get-Acl -LiteralPath $secure
    $userRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-5-32-545'})
    Verify ($userRules.Count -gt 0) 'Users can read visible status/configuration'
    $writable=@($userRules|Where-Object {($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0})
    Verify ($writable.Count -eq 0) 'Users cannot write administrative configuration'
    $poison=Join-Path $secure 'untrusted.txt';[IO.File]::WriteAllText($poison,'fixture')
    $pa=Get-Acl -LiteralPath $poison
    $sid=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Write','Allow')
    $pa.AddAccessRule($rule);Set-Acl -LiteralPath $poison -AclObject $pa
    $refused=$false;try{Secure-Directory $secure}catch{$refused=$true}
    Verify $refused 'Preexisting user-writable administrative file rejected'
    # Register the real schedule with a harmless placeholder. Never invoke the cleanup engine.
    $TaskName=$verificationTask;$Exe=Join-Path $env:windir 'System32\whoami.exe'
    Register-EngineTask
    $task=Get-ScheduledTask -TaskName $verificationTask
    Verify ($task.Principal.UserId -in @('S-1-5-18','SYSTEM','NT AUTHORITY\SYSTEM')) 'Scheduled principal is SYSTEM'
    Verify ([string]$task.Principal.RunLevel -eq 'Highest') 'Highest scheduled run level'
    Verify (@($task.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'}).Count -eq 1) 'Boot trigger present'
    Verify (@($task.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'}).Count -eq 1) 'Logon trigger present'
    Verify (@($task.Triggers|Where-Object {$_.Repetition.Interval -eq 'PT5M'}).Count -eq 1) 'Five-minute repetition present'
    Verify ([string]$task.Settings.MultipleInstances -eq 'IgnoreNew') 'Overlapping scheduled cycles prevented'
    Verify (-not $script:Config.Screenshots) 'Screenshots disabled by default'
    $report=Join-Path $repo 'games-verification.txt'
    @('LabGuard Windows integration verification','No actual game installs scanned or removed.',('UTC: '+[DateTime]::UtcNow.ToString('o')),('Passed checks: '+$checks.Count),'',$checks)|Set-Content -LiteralPath $report -Encoding UTF8
    Write-Host ('ALL '+$checks.Count+' CHECKS PASSED')
} finally {
    Unregister-ScheduledTask -TaskName $verificationTask -Confirm:$false -ErrorAction SilentlyContinue
    if($junction -and (Test-Path -LiteralPath $junction)){[IO.Directory]::Delete($junction,$false)}
    if((Test-Path -LiteralPath $fixture) -and (Split-Path $fixture -Leaf) -match '^LabGuardVerify-[a-f0-9]{32}$'){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
