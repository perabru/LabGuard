# Assemble audited base plus explicit 2.1 extensions; refuse changed anchors.
$ErrorActionPreference='Stop'
$root=$PSScriptRoot;$out=Join-Path $root 'dist';New-Item -ItemType Directory -Path $out -Force|Out-Null
function Swap([ref]$Text,[string]$Before,[string]$After){$n=[regex]::Matches($Text.Value,[regex]::Escape($Before)).Count;if($n -ne 1){throw ('Expected one assembly anchor, found '+$n+': '+$Before.Substring(0,[Math]::Min(80,$Before.Length)))};$Text.Value=$Text.Value.Replace($Before,$After)}
$ps=[IO.File]::ReadAllText((Join-Path $root 'Engine.ps1')).Replace("`r`n","`n").Replace('2.0.0','2.1.0')
$policy=[IO.File]::ReadAllText((Join-Path $root 'Policy.ps1')).Replace("`r`n","`n")
$controls=[IO.File]::ReadAllText((Join-Path $root 'extensions\Controls.ps1')).Replace("`r`n","`n")
$windows=[IO.File]::ReadAllText((Join-Path $root 'extensions\WindowsGames.ps1')).Replace("`r`n","`n")
$controls=$controls.Replace("New-Item -Path `$path -Force|Out-Null","if(-not(Test-Path -LiteralPath `$path)){New-Item -Path `$path -Force|Out-Null}")
$controls=$controls.Replace('catch[Threading.AbandonedMutexException]','catch [Threading.AbandonedMutexException]')
$controls=$controls.Replace("'LabGuard-Jogos2-Monitor'",'$script:GuardianTaskName')
$controls="`$script:GuardianTaskName='LabGuard-Jogos2-Monitor'`n"+$controls
$controls=$controls.Replace("`$encoding=[Text.Encoding]::GetEncoding(28591);`$text=`$encoding.GetString(`$Bytes)","if(`$Bytes -contains 0){throw 'Hosts em UTF-16/binario nao suportado; nenhuma alteracao realizada.'};`$encoding=[Text.Encoding]::GetEncoding(28591);`$text=`$encoding.GetString(`$Bytes)")
$controls=$controls.Replace("':: '+`$hostName","'::1 '+`$hostName").Replace("':: www","'::1 www")
$controls=$controls.Replace('($Object|ConvertTo-Json -Depth 8)','(ConvertTo-Json -InputObject $Object -Depth 8)')
Swap ([ref]$ps) "'CaptureOff','Status','Test'" "'CaptureOff','Status','Test','GuardInit','YouTubeOn','YouTubeOff','GameCloseOn','GameCloseOff'"
Swap ([ref]$ps) 'Inventory; Discover; Stop-TargetProcesses; Uninstall-Msi; Remove-Store' 'Inventory; Discover; Discover-WindowsGameFolders; Stop-TargetProcesses; Uninstall-Msi; Remove-Store'
$entry="try {`n    if (`$Mode -eq 'Test') {"
$extra=@'
$script:BaseSafeTarget=${function:Safe-Target}
function Safe-Target([string]$Path,[switch]$Manual){
    if($Path -match '(?i)\\LabGuard(?:Jogos2?|Cliente|Central|Tecnico)?(\\|$)'){return $false}
    return (& $script:BaseSafeTarget $Path -Manual:$Manual)
}
function Prepare-Upgrade {
    if([IO.Path]::GetFullPath($env:LG_SOURCE_EXE).Equals($Exe,[StringComparison]::OrdinalIgnoreCase)){return}
    $active=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if($active -and $active.State -eq 'Running'){throw 'A limpeza anterior esta em execucao. Pause a limpeza no painel, aguarde a operacao atual concluir e execute este instalador novamente.'}
    if($active){Disable-ScheduledTask -TaskName $TaskName|Out-Null}
    Stop-ScheduledTask -TaskName $script:GuardianTaskName -ErrorAction SilentlyContinue
    foreach($p in @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.Equals($Exe,[StringComparison]::OrdinalIgnoreCase)})){
        try{$current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId);if($current -and $current.CreationDate -eq $p.CreationDate -and $current.ExecutablePath -eq $p.ExecutablePath){Invoke-CimMethod -InputObject $current -MethodName Terminate|Out-Null}}catch{Log 'PENDENTE' ('Fechar painel antigo: '+$_.Exception.Message)}
    }
    Start-Sleep -Milliseconds 400
}
'@
Swap ([ref]$ps) $entry ($policy+"`n"+$controls+"`n"+$windows+"`n"+$extra+"`n"+$entry)
Swap ([ref]$ps) "if (`$Mode -eq 'Test') {" "if (`$Mode -eq 'Test') { Test-Extensions; Test-WindowsGames;"
$actions=@'
    Assert-Admin
    if($Mode -eq 'GuardInit'){Secure-Directory $Data;exit 0}
    if($Mode -in @('YouTubeOn','YouTubeOff','GameCloseOn','GameCloseOff')){
        if(-not(Test-Path -LiteralPath $ConfigPath)){throw 'Instale e ative o cliente antes de alterar os controles.'}
        Secure-Directory $Base;Secure-Directory $Data;Read-Config
        switch($Mode){
            'YouTubeOn' {$script:Config.BlockYouTube=$true;Write-Config;Apply-YouTube $true}
            'YouTubeOff' {$script:Config.BlockYouTube=$false;Write-Config;Apply-YouTube $false}
            'GameCloseOn' {$script:Config.AutoCloseGames=$true;Write-Config;Register-GuardianTask;Log 'ATIVADO' 'Fechamento de jogos ativado. A limpeza tambem precisa estar ativa.'}
            'GameCloseOff' {$script:Config.AutoCloseGames=$false;Write-Config;Log 'PAUSADO' 'Fechamento imediato pausado; a limpeza de 5 minutos continua independente.'}
        };exit 0
    }
    if ($Mode -eq 'Install') {
'@
Swap ([ref]$ps) "    Assert-Admin`n    if (`$Mode -eq 'Install') {" $actions
Swap ([ref]$ps) "        Secure-Directory `$Base; Secure-Directory `$Data`n        if (-not ([IO.Path]::GetFullPath(" "        Secure-Directory `$Base; Secure-Directory `$Data; Prepare-Upgrade`n        if (-not ([IO.Path]::GetFullPath("
Swap ([ref]$ps) '        Start-ScheduledTask -TaskName $TaskName' '        Install-Extensions; Start-ScheduledTask -TaskName $TaskName'
Swap ([ref]$ps) "'Resume' { `$script:Config.Enabled=`$true; Write-Config; Register-EngineTask;" "'Resume' { `$script:Config.Enabled=`$true; Write-Config; Register-EngineTask; Register-GuardianTask;"
Swap ([ref]$ps) "'Uninstall' { `$script:Config.Enabled=`$false;" "'Uninstall' { Remove-Extensions; `$script:Config.Enabled=`$false;"
Swap ([ref]$ps) '    Check-Defender' '    Check-Defender; if(-not $script:Dry){try{Apply-YouTube ([bool]$script:Config.BlockYouTube)}catch{Log ''PENDENTE'' (''YouTube: ''+$_.Exception.Message)}}'
$engine=Join-Path $out 'Engine.assembled.ps1';[IO.File]::WriteAllText($engine,$ps,(New-Object Text.UTF8Encoding($true)))
$cs=[IO.File]::ReadAllText((Join-Path $root 'LabGuard.cs')).Replace("`r`n","`n").Replace('2.0.0','2.1.0')
Swap ([ref]$cs) '"CaptureOff","Test"' '"CaptureOff","Test","GuardInit","YouTubeOn","YouTubeOff","GameCloseOn","GameCloseOff"'
Swap ([ref]$cs) '            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);' '            if(args.Length>0&&args[0]=="--guard")return Guardian.Run(); if(args.Length>0&&args[0]=="--guard-self-test"){WindowsGames.Test();return Guardian.SelfTest(args.Length>1?args[1]:null);} Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);'
Swap ([ref]$cs) '        tray=new NotifyIcon' '        ProtectionPanel.Attach(this,root,smoke); Size=new Size(1020,900); MinimumSize=new Size(820,790); tray=new NotifyIcon'
Swap ([ref]$cs) 'FormClosing+=(s,e)=>{closing=true;};' 'FormClosing+=(s,e)=>{if(!smoke&&!closing&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();tray.ShowBalloonTip(2500,"LabGuard ativo","Painel mantido na bandeja. Fechamento de jogos e limpeza continuam conforme a politica.",ToolTipIcon.Info);}else closing=true;};'
$cs=$cs.Replace('Use apenas em computadores que voce administra.','Use apenas em computadores que voce administra. Xbox e jogos Windows do catalogo tambem serao removidos. O fechamento de jogos e o bloqueio do YouTube ficam ligados por padrao.')
[IO.File]::WriteAllText((Join-Path $out 'LabGuard.assembled.cs'),$cs,(New-Object Text.UTF8Encoding($true)))
$guard=[IO.File]::ReadAllText((Join-Path $root 'extensions\Guardian.cs')).Replace("`r`n","`n")
Swap ([ref]$guard) 'if(!Program.NoLinks(path)||!IsGame(path,cmd,approved))return false;' 'if(!Program.NoLinks(path)||(!IsGame(path,cmd,approved)&&!WindowsGames.IsGame(path,WindowsGames.PackageOf(held))))return false;'
$guard=$guard.Replace('Nenhum navegador e encerrado.','Xbox e jogos Windows incluidos. Nenhum navegador e encerrado.')
[IO.File]::WriteAllText((Join-Path $out 'Guardian.assembled.cs'),$guard,(New-Object Text.UTF8Encoding($true)))
Write-Output 'Assembled LabGuard Jogos 2.1.0 with Guardian, YouTube and Xbox/Windows catalog.'
