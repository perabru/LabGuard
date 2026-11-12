# Only disposable CI machines. No real LabGuard installation may be present.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'Native integration checks are restricted to disposable GitHub runners.'}
$root=Split-Path $PSScriptRoot -Parent
$fixture=Join-Path $root ('LGU-fixture-'+[guid]::NewGuid().ToString('N'))
$regBase='Registry::HKEY_CURRENT_USER\Software\LGU-Verify-'+[guid]::NewGuid().ToString('N')
$taskFolder='\LabGuard-Uninstall-Verify-'+[guid]::NewGuid().ToString('N')+'\'
$firewallName='LabGuard-Uninstall-Verify-'+[guid]::NewGuid().ToString('N')
$service=New-Object -ComObject Schedule.Service;$service.Connect()
$script=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'operations.ps1'))
$split=$script.IndexOf('switch([string]$LGU.mode)',[StringComparison]::Ordinal)
if($split -lt 0){throw 'Definitions entrypoint not found.'}
$LGU=[pscustomobject]@{mode='';roots=@();profiles=@()}
. ([scriptblock]::Create($script.Substring(0,$split)))
$checks=New-Object 'System.Collections.Generic.List[string]'
function Verify([bool]$Ok,[string]$Message){if(-not $Ok){throw ('VERIFY FAILED: '+$Message)};$checks.Add($Message);Write-Host ('PASS: '+$Message)}
if(@(Get-Tasks).Count -or @(Get-Services).Count -or @(Get-Processes).Count){throw 'Actual LabGuard components detected; refusing native integration checks.'}
try{
    $app=Join-Path $fixture 'LabGuardJogos2';New-Item -ItemType Directory -Path $app -Force|Out-Null
    $fake=Join-Path $app 'LabGuard-Jogos.exe';[IO.File]::WriteAllText($fake,'Synthetic fixture - not an executable')
    $LGU.roots=@([pscustomobject]@{path=$app;kind='programa'})
    Verify (Owned-Path $fake) 'Expected installation path accepted'
    Verify (-not(Owned-Path ($app+'Other\game.exe'))) 'Sibling installation path refused'
    $null=$service.GetFolder('\').CreateFolder($taskFolder.Trim('\'))
    $a=New-ScheduledTaskAction -Execute $fake -Argument '--guard'
    $t=New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01T12:00:00')
    Register-ScheduledTask -TaskPath $taskFolder -TaskName 'LabGuard-Jogos2-Monitor' -Action $a -Trigger $t|Out-Null
    Disable-ScheduledTask -TaskPath $taskFolder -TaskName 'LabGuard-Jogos2-Monitor'|Out-Null
    $LGU.mode='Stop';$output=& ([scriptblock]::Create($script))
    Verify (-not(Get-ScheduledTask -TaskPath $taskFolder -TaskName 'LabGuard-Jogos2-Monitor' -ErrorAction SilentlyContinue)) 'Synthetic startup/monitor task removed'
    $run=$regBase+'\Software\Microsoft\Windows\CurrentVersion\Run'
    New-Item -Path $run -Force|Out-Null
    New-ItemProperty -LiteralPath $run -Name LabGuardJogos2 -Value ('"'+$fake+'" --monitor') -PropertyType String|Out-Null
    New-ItemProperty -LiteralPath $run -Name SchoolApp -Value 'C:\School\App.exe' -PropertyType String|Out-Null
    $un=$regBase+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\LabGuardJogos2'
    New-Item -Path $un -Force|Out-Null
    New-ItemProperty -LiteralPath $un -Name DisplayName -Value 'LabGuard Jogos 2.1.0' -PropertyType String|Out-Null
    Cleanup-Hive $regBase
    $k=Get-Item -LiteralPath $run
    Verify ($null -eq $k.GetValue('LabGuardJogos2',$null)) 'Owned Run entry removed'
    Verify ($k.GetValue('SchoolApp') -eq 'C:\School\App.exe') 'Unrelated Run entry preserved'
    $k.Close()
    Verify (-not(Test-Path -LiteralPath $un)) 'Owned uninstall registration removed'
    $home=Join-Path $fixture 'Profile';$desktop=Join-Path $home 'Desktop';New-Item -ItemType Directory -Path $desktop -Force|Out-Null
    $shell=New-Object -ComObject WScript.Shell
    $link=$shell.CreateShortcut((Join-Path $desktop 'LabGuard Jogos.lnk'));$link.TargetPath=$fake;$link.Save()
    $school=$shell.CreateShortcut((Join-Path $desktop 'SchoolApp.lnk'));$school.TargetPath=Join-Path $env:windir 'System32\notepad.exe';$school.Save()
    $LGU.profiles=@([pscustomobject]@{path=$home;sid='S-1-5-21-1-2-3-4'});$LGU.mode='Shortcuts';$null=& ([scriptblock]::Create($script))
    Verify (-not(Test-Path -LiteralPath (Join-Path $desktop 'LabGuard Jogos.lnk'))) 'Owned shortcut removed'
    Verify (Test-Path -LiteralPath (Join-Path $desktop 'SchoolApp.lnk')) 'Unrelated shortcut preserved'
    New-NetFirewallRule -Name $firewallName -DisplayName 'LabGuard integration fixture' -Direction Outbound -Action Block -Protocol TCP -RemotePort 65432 -Enabled False|Out-Null
    $LGU.mode='Firewall';$null=& ([scriptblock]::Create($script))
    Verify (-not(Get-NetFirewallRule -Name $firewallName -ErrorAction SilentlyContinue)) 'Owned synthetic firewall rule removed'
    $report=Join-Path $PSScriptRoot 'native-verification.txt'
    @('LabGuard Desinstalador - verificacao Windows','Somente tarefas/arquivos/Registro/firewall sinteticos em runner descartavel.','')+@($checks.ToArray())|Set-Content -LiteralPath $report -Encoding UTF8
}finally{
    Unregister-ScheduledTask -TaskName 'LabGuard-Jogos2-Monitor' -TaskPath $taskFolder -Confirm:$false -ErrorAction SilentlyContinue
    try{$service.GetFolder('\').DeleteFolder($taskFolder.Trim('\'),0)}catch{}
    Remove-NetFirewallRule -Name $firewallName -ErrorAction SilentlyContinue
    if(Test-Path -LiteralPath $regBase){Remove-Item -LiteralPath $regBase -Recurse -Force}
    if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
