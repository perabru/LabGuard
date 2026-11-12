# End-to-end installation of the shipping executable, in an empty disposable Windows runner.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'This installation test may only run in disposable GitHub Actions.'}
$root=Split-Path $PSScriptRoot -Parent
$exe=Join-Path $PSScriptRoot 'dist\LabGuard-Jogos.exe'
$base=Join-Path $env:ProgramFiles 'LabGuardJogos2';$data=Join-Path $env:ProgramData 'LabGuardJogos2'
$game='C:\Games\RetroArch';$gameParentExisted=Test-Path 'C:\Games'
$work=Join-Path $env:ProgramData ('LabGuard-Fixture-'+[guid]::NewGuid().ToString('N'))
$tasks=@('LabGuard-Jogos2-Limpeza','LabGuard-Jogos2-Monitor')
$browser=@('HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist','HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist','HKLM:\SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block')
if((Test-Path $base) -or (Test-Path $data) -or (Test-Path $game) -or @(Get-ScheduledTask|Where-Object {$_.TaskName -like 'LabGuard*'}).Count){throw 'Preexisting installation or game detected; refusing destructive integration test.'}
foreach($key in $browser){if(Test-Path -LiteralPath $key){throw 'Preexisting browser policy detected; disposable fixture required.'}}
$hosts=Join-Path $env:windir 'System32\drivers\etc\hosts';$hostsBefore=[IO.File]::ReadAllBytes($hosts)
$passed=New-Object 'System.Collections.Generic.List[string]'
function Diagnostics {
    $lines=@('Runtime diagnostics from disposable test VM only. No student or real lab data.')
    foreach($f in @('install-status.json','status.json','guard-status.json','web-status.json','remocoes.log','guard.log')){
        $file=Join-Path $data $f
        if(Test-Path -LiteralPath $file){$lines+='--- '+$f;try{$lines+=Get-Content -LiteralPath $file -Tail 80 -ErrorAction Stop}catch{$lines+=$_.Exception.Message}}
    }
    $lines+='--- tasks'
    foreach($name in $tasks){try{$lines+=(Get-ScheduledTaskInfo -TaskName $name|Select-Object TaskName,LastRunTime,LastTaskResult|Format-List|Out-String)}catch{}}
    $lines+='--- process sessions';try{$lines+=(Get-Process|Where-Object {$_.ProcessName -in @('LabGuard-Jogos','RobloxPlayerBeta')}|Select-Object ProcessName,Id,SessionId|Format-Table|Out-String)}catch{}
    $lines|Set-Content (Join-Path $PSScriptRoot 'build\diagnostic-runtime.txt') -Encoding UTF8
    $lines|Write-Host
}
function Verify([bool]$Ok,[string]$Label){if(-not $Ok){Diagnostics;throw ('FAILED: '+$Label)};$passed.Add($Label);Write-Host ('PASS: '+$Label)}
function Install-Actual {
    $p=Start-Process -FilePath $exe -ArgumentList '--install-auto --accept-policy' -PassThru
    if(-not $p.WaitForExit(360000)){Stop-Process -Id $p.Id -Force;Diagnostics;throw 'Automatic install timed out.'}
    if($p.ExitCode -ne 0){Diagnostics;throw ('Automatic install returned '+$p.ExitCode)}
}
$process=$null
try{
    New-Item -ItemType Directory -Path $work,$game -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $work 'school-work.txt'),'PRESERVE SCHOOL DOCUMENT')
    [IO.File]::WriteAllText((Join-Path $game 'retroarch.exe'),'SYNTHETIC GAME FILE - NOT EXECUTABLE')
    [IO.File]::WriteAllText((Join-Path $game 'synthetic-save.dat'),'TEST SAVE')
    Install-Actual
    Verify (Test-Path -LiteralPath (Join-Path $base 'LabGuard-Jogos.exe')) 'Executable installed without any enrollment file'
    $c=Get-Content (Join-Path $base 'config.json') -Raw|ConvertFrom-Json
    Verify ($c.Enabled -and $c.AutoCloseGames -and $c.BlockYouTube -and -not $c.Screenshots) 'Local protections enabled and screenshots disabled'
    foreach($d in @('term.ooo','friv.com','friv.com.br','poki.com','chess.com')){Verify ($c.CentralSiteDomains -contains $d) ('Default local site: '+$d)}
    $health=Get-Content (Join-Path $data 'install-status.json') -Raw|ConvertFrom-Json
    Verify ($health.state -eq 'ready' -and $health.monitorFresh -and $health.sites -and $health.scheduler) 'Real installation health confirms monitor, sites and task'
    Verify (-not $health.centralLinked) 'Central enrollment is not required for local protection'
    foreach($name in $tasks){$t=Get-ScheduledTask -TaskName $name;Verify ($t.Principal.UserId -in @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM')) ('SYSTEM task: '+$name);Verify (@($t.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'}).Count -eq 1) ('Boot trigger: '+$name)}
    Verify (@((Get-ScheduledTask -TaskName $tasks[0]).Triggers|Where-Object {$_.Repetition.Interval -eq 'PT5M'}).Count -eq 1) 'Five-minute cleanup repetition'
    $until=[DateTime]::UtcNow.AddSeconds(240)
    while((Test-Path $game) -and [DateTime]::UtcNow -lt $until){
        Start-Sleep -Seconds 1
        try{$cycle=Get-Content (Join-Path $data 'status.json') -Raw -ErrorAction Stop|ConvertFrom-Json;if($cycle.state -like 'Concluido*' -or $cycle.state -eq 'Falha'){break}}catch{}
    }
    Verify (-not(Test-Path $game)) 'First automatic cycle removes synthetic recognized game'
    Verify ((Get-Content (Join-Path $work 'school-work.txt') -Raw) -eq 'PRESERVE SCHOOL DOCUMENT') 'Unrelated school document preserved'
    $fixture=Join-Path $work 'RobloxPlayerBeta.exe';$compiler=Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $source=Join-Path $work 'game.cs';[IO.File]::WriteAllText($source,'using System;using System.Windows.Forms;class TestGame{[STAThread]static void Main(){Application.Run(new Form{Text="LabGuard synthetic game fixture"});}}')
    & $compiler /nologo /target:winexe /reference:System.Windows.Forms.dll ("/out:"+$fixture) $source
    if($LASTEXITCODE -ne 0){throw 'Synthetic game could not compile.'}
    $process=Start-Process -FilePath $fixture -PassThru
    Verify ($process.WaitForExit(15000)) 'Installed SYSTEM monitor closes a real synthetic game window'
    Install-Actual
    Verify ((Get-Content (Join-Path $data 'install-status.json') -Raw|ConvertFrom-Json).state -eq 'ready') 'Second install updates/repairs without manual pausing or enrollment'
    Verify ((Get-Content (Join-Path $work 'school-work.txt') -Raw) -eq 'PRESERVE SCHOOL DOCUMENT') 'School document remains after repair'
    @('AUTOMATIC CLIENT 2.4 - REAL WINDOWS INSTALLATION TEST',('UTC: '+[DateTime]::UtcNow.ToString('o')),'Disposable Windows Server 2022 runner; removal and closure assertions used synthetic game/document fixtures.','')+@($passed.ToArray())|Set-Content (Join-Path $PSScriptRoot 'dist\TESTE_INSTALACAO.txt') -Encoding UTF8
}finally{
    try{Diagnostics}catch{Write-Host ('Diagnostics unavailable: '+$_.Exception.Message)}
    foreach($name in $tasks){Disable-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue|Out-Null;Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue}
    if($process){try{if(-not $process.HasExited){Stop-Process -Id $process.Id -Force}}catch{}}
    foreach($p in @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -and $_.ExecutablePath -ieq (Join-Path $base 'LabGuard-Jogos.exe')})){Invoke-CimMethod -InputObject $p -MethodName Terminate -ErrorAction SilentlyContinue|Out-Null}
    Start-Sleep -Seconds 1
    [IO.File]::WriteAllBytes($hosts,$hostsBefore)
    foreach($key in $browser){if(Test-Path -LiteralPath $key){Remove-Item -LiteralPath $key -Recurse -Force}}
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name LabGuardJogos2 -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LabGuardJogos2' -Recurse -Force -ErrorAction SilentlyContinue
    foreach($p in @($base,$data,$game,$work)){if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue}}
    if(-not $gameParentExisted -and (Test-Path 'C:\Games') -and @(Get-ChildItem 'C:\Games' -Force).Count -eq 0){Remove-Item 'C:\Games'}
}
