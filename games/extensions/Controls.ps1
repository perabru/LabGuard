# Embedded 2.1 controls. Fixed administrative paths; no remote command channel.
$script:YouTubeDomains=@('youtube.com','youtu.be','youtube-nocookie.com','youtubekids.com','youtubeeducation.com','youtubei.googleapis.com','youtube.googleapis.com')
$script:YouTubeHosts=@('youtube.com','www.youtube.com','m.youtube.com','music.youtube.com','studio.youtube.com','gaming.youtube.com','kids.youtube.com','youtu.be','www.youtu.be','youtube-nocookie.com','www.youtube-nocookie.com','youtubekids.com','www.youtubekids.com','youtubeeducation.com','www.youtubeeducation.com','youtubei.googleapis.com','youtube.googleapis.com')
$script:BrowserKeys=@('HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist','HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist','HKLM:\SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block')
function Read-Config {
    if(Test-Path -LiteralPath $ConfigPath){if(-not(No-Link $ConfigPath)){throw 'Configuracao em link recusada.'};$script:Config=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8|ConvertFrom-Json}
    foreach($property in @('Enabled','Screenshots')){if($script:Config.$property -isnot [bool]){throw 'Configuracao invalida; operacao interrompida.'}}
    foreach($property in @('AutoCloseGames','BlockYouTube')){if($script:Config.PSObject.Properties.Name -notcontains $property){$script:Config|Add-Member -NotePropertyName $property -NotePropertyValue $true};if($script:Config.$property -isnot [bool]){throw ('Configuracao invalida: '+$property)}}
    $script:Config|Add-Member -NotePropertyName Version -NotePropertyValue '2.1.0' -Force
}
function Write-JsonAtomic([string]$Path,$Object){
    if(-not(No-Link $Path)){throw 'Destino administrativo em link recusado.'}
    $tmp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try{
        [IO.File]::WriteAllText($tmp,(ConvertTo-Json -InputObject $Object -Depth 8),(New-Object Text.UTF8Encoding($false)))
        for($attempt=0;$attempt -lt 4;$attempt++){
            try{if([IO.File]::Exists($Path)){[IO.File]::Replace($tmp,$Path,[NullString]::Value)}else{[IO.File]::Move($tmp,$Path)};return}
            catch [IO.IOException]{if($attempt -ge 3){throw};Start-Sleep -Milliseconds 70}
        }
    }finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function Write-Config { Write-JsonAtomic $ConfigPath $script:Config }
function Convert-YouTubeHosts([byte[]]$Bytes,[bool]$Blocked){
    if($Bytes -contains 0){throw 'Hosts em UTF-16/binario nao suportado; nenhuma alteracao realizada.'}
    $encoding=[Text.Encoding]::GetEncoding(28591);$text=$encoding.GetString($Bytes)
    $start='# BEGIN LABGUARD JOGOS YOUTUBE';$end='# END LABGUARD JOGOS YOUTUBE'
    $starts=[regex]::Matches($text,'(?m)^'+[regex]::Escape($start)+'\r?$').Count
    $ends=[regex]::Matches($text,'(?m)^'+[regex]::Escape($end)+'\r?$').Count
    if($starts -ne $ends -or $starts -gt 1){throw 'Bloco YouTube incompleto/duplicado no hosts; nenhuma alteracao realizada.'}
    $pattern='(?:\r?\n)?(?m)^'+[regex]::Escape($start)+'\r?\n[\s\S]*?^'+[regex]::Escape($end)+'(?:\r?\n|$)'
    $text=[regex]::Replace($text,$pattern,'')
    if($Blocked){$lines=@($start);foreach($hostName in $script:YouTubeHosts){$lines+='0.0.0.0 '+$hostName;$lines+='::1 '+$hostName};$lines+=$end;$text+="`r`n"+($lines -join "`r`n")+"`r`n"}
    return ,$encoding.GetBytes($text)
}
function Set-YouTubeHosts([bool]$Blocked){
    $path=Join-Path $env:windir 'System32\drivers\etc\hosts';if(-not(No-Link $path)){throw 'Hosts contem link/junction; operacao recusada.'}
    $original=[IO.File]::ReadAllBytes($path);$updated=Convert-YouTubeHosts $original $Blocked
    if([Convert]::ToBase64String($original) -eq [Convert]::ToBase64String($updated)){return}
    $backup=Join-Path $Data 'hosts-before-youtube.bak';if(-not [IO.File]::Exists($backup)){[IO.File]::WriteAllBytes($backup,$original)}
    $tmp=$path+'.LabGuard-'+[guid]::NewGuid().ToString('N')+'.tmp'
    try{[IO.File]::WriteAllBytes($tmp,$updated);if([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ne [Convert]::ToBase64String($original)){throw 'Hosts foi alterado durante a operacao; tente novamente.'};[IO.File]::Replace($tmp,$path,[NullString]::Value)}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function Set-YouTubeBrowserPolicies([bool]$Blocked){
    $state=Join-Path $Data 'youtube-owned-rules.json';$owned=@()
    if(Test-Path -LiteralPath $state){if(-not(No-Link $state)){throw 'Metadados em link recusados.'};$owned=@(Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json)}
    if(-not $Blocked){
        foreach($record in $owned){if($null -eq $record){continue};if($script:BrowserKeys -notcontains [string]$record.Key -or [string]$record.Name -notmatch '^\d+$'){throw 'Metadados de politica invalidos.'};if(Test-Path -LiteralPath $record.Key){$key=Get-Item -LiteralPath $record.Key;if([string]$key.GetValue([string]$record.Name) -ceq [string]$record.Value){Remove-ItemProperty -LiteralPath $record.Key -Name ([string]$record.Name) -ErrorAction Stop}}}
        Write-JsonAtomic $state @();return
    }
    foreach($path in $script:BrowserKeys){
        if(-not(Test-Path -LiteralPath $path)){New-Item -Path $path -Force|Out-Null}
        $values=if($path -like '*Mozilla*'){@($script:YouTubeDomains|ForEach-Object {'*://*.'+$_+'/*'})}else{@($script:YouTubeDomains)}
        foreach($value in $values){
            $key=Get-Item -LiteralPath $path;$names=@($key.GetValueNames());$existing=@($names|ForEach-Object {[string]$key.GetValue($_)})
            if($existing -ccontains $value){continue}
            if($names.Count -ge 990){throw 'Limite de politicas do navegador proximo de 1000; revise com a TI.'}
            $index=1;while($names -contains [string]$index){$index++}
            $record=[pscustomobject]@{Key=$path;Name=[string]$index;Value=$value}
            $owned+=@($record);Write-JsonAtomic $state @($owned)
            New-ItemProperty -LiteralPath $path -Name ([string]$index) -Value $value -PropertyType String -Force|Out-Null
        }
    }
}
function Apply-YouTube([bool]$Blocked){
    $mutex=$null;$held=$false
    try{
        $security=[Security.AccessControl.MutexSecurity]::new()
        foreach($sid in @('S-1-5-18','S-1-5-32-544')){$security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.MutexRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))}
        $created=$false;$mutex=[Threading.Mutex]::new($false,'Global\LabGuardJogos2-WebPolicy',[ref]$created,$security)
        try{$held=$mutex.WaitOne(30000)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'Outra alteracao do YouTube esta em andamento.'}
        if(Test-Path -LiteralPath $ConfigPath){Read-Config;$Blocked=[bool]$script:Config.BlockYouTube}
        Set-YouTubeHosts $Blocked;Set-YouTubeBrowserPolicies $Blocked
        try{Clear-DnsClientCache -ErrorAction Stop}catch{Log 'PENDENTE' ('Cache DNS: '+$_.Exception.Message)}
        $text=if($Blocked){'Bloqueio aplicado (hosts e politicas)'}else{'Regras do LabGuard removidas'}
        Write-JsonAtomic (Join-Path $Data 'youtube-status.json') @{state=$text;blocked=$Blocked;updatedUtc=[DateTime]::UtcNow.ToString('o');version='2.1.0'}
        Log 'YOUTUBE' ($text+'. Reinicie o navegador. Outras regras/allowlists continuam independentes.')
    }catch{try{Write-JsonAtomic (Join-Path $Data 'youtube-status.json') @{state=('FALHA: '+$_.Exception.Message);blocked=$null;updatedUtc=[DateTime]::UtcNow.ToString('o')}}catch{};throw}
    finally{if($mutex){if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}}
}
function Register-GuardianTask {
    $action=New-ScheduledTaskAction -Execute $Exe -Argument '--guard'
    $triggers=@((New-ScheduledTaskTrigger -AtStartup),(New-ScheduledTaskTrigger -AtLogOn),(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)))
    $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'LabGuard-Jogos2-Monitor' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'LabGuard: monitor administrativo de jogos, com estado visivel no painel. Checagem nominal a cada 2 segundos.' -Force|Out-Null
    Start-ScheduledTask -TaskName 'LabGuard-Jogos2-Monitor'
}
function Install-Extensions {Register-GuardianTask;try{Apply-YouTube ([bool]$script:Config.BlockYouTube)}catch{Log 'PENDENTE' ('YouTube: '+$_.Exception.Message)}}
function Remove-Extensions {
    $script:Config.AutoCloseGames=$false;$script:Config.BlockYouTube=$false;Write-Config
    Stop-ScheduledTask -TaskName 'LabGuard-Jogos2-Monitor' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'LabGuard-Jogos2-Monitor' -Confirm:$false -ErrorAction SilentlyContinue
    Apply-YouTube $false
}
function Test-Extensions {
    $raw=[Text.Encoding]::GetEncoding(28591).GetBytes("# escola`r`n127.0.0.1 localhost`r`n192.168.1.2 intranet.escola`r`n")
    $blocked=Convert-YouTubeHosts $raw $true;$again=Convert-YouTubeHosts $blocked $true;$restored=Convert-YouTubeHosts $blocked $false
    if([Convert]::ToBase64String($blocked) -ne [Convert]::ToBase64String($again)){throw 'Hosts block not idempotent.'}
    if([Convert]::ToBase64String($raw) -ne [Convert]::ToBase64String($restored)){throw 'Hosts restore changed other entries.'}
    $txt=[Text.Encoding]::GetEncoding(28591).GetString($blocked)
    if($txt -notmatch '0\.0\.0\.0 www\.youtube\.com' -or $txt -notmatch '::1 www\.youtube\.com'){throw 'IPv4/IPv6 entries missing.'}
    if($script:YouTubeDomains -contains 'google.com' -or $script:YouTubeDomains -contains 'googlevideo.com' -or $script:YouTubeDomains -contains 'ytimg.com'){throw 'Shared Google domain unexpectedly blocked.'}
    Log 'TESTE' 'YouTube hosts apply/restore/idempotency and shared-domain exclusions passed.'
}
