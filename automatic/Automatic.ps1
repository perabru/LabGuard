# Fixed local installation policy. Embedded in the executable; never sourced from user files.
$script:DefaultLocalSites=@('term.ooo','friv.com','friv.com.br','poki.com','chess.com')
$script:WasEnabled=$true
$script:HasCentral=$false
function Secure-Directory([string]$Path) {
    if(-not(No-Link $Path)){throw ('Link/junction recusado: '+$Path)}
    if(Test-Path -LiteralPath $Path){Assert-NotUserWritable $Path}
    else{New-Item -ItemType Directory -Path $Path -ErrorAction Stop|Out-Null}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach($spec in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))){
        $sid=New-Object Security.Principal.SecurityIdentifier($spec[0])
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$spec[1],'ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $Path -AclObject $acl
    foreach($entry in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)){
        try{
            $current=Get-Item -LiteralPath $entry.FullName -Force -ErrorAction Stop
            if($current.Attributes -band [IO.FileAttributes]::ReparsePoint){throw ('Link recusado na instalacao: '+$entry.FullName)}
            Assert-NotUserWritable $entry.FullName
        }catch{
            # File.Replace uses transient ~RF*.TMP files. Only a proven vanished child is
            # harmless; permission failures, links and insecure ACLs still stop the operation.
            if($_.CategoryInfo.Category -eq 'ObjectNotFound' -and -not(Test-Path -LiteralPath $entry.FullName -ErrorAction Stop)){continue}
            throw
        }
    }
}
function Prepare-Upgrade {
    $script:HasCentral=Test-Path -LiteralPath (Join-Path $Base 'Central\vinculo.dat')
    if(Test-Path -LiteralPath $ConfigPath){Read-Config;$script:WasEnabled=[bool]$script:Config.Enabled}
    $oldGuard=Get-ScheduledTask -TaskName $script:GuardianTaskName -ErrorAction SilentlyContinue
    if($oldGuard){
        if(@($oldGuard.Actions|Where-Object {$_.Execute -ieq $Exe -and $_.Arguments -eq '--guard'}).Count -ne 1){throw 'Tarefa de monitor preexistente nao pertence a esta instalacao.'}
        Disable-ScheduledTask -TaskName $script:GuardianTaskName|Out-Null
        Stop-ScheduledTask -TaskName $script:GuardianTaskName
    }
    $oldCycle=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if($oldCycle){
        if(@($oldCycle.Actions|Where-Object {$_.Execute -ieq $Exe -and $_.Arguments -eq '--cycle'}).Count -ne 1){throw 'Tarefa de limpeza preexistente nao pertence a esta instalacao.'}
        Disable-ScheduledTask -TaskName $TaskName|Out-Null
    }
    if(Test-Path -LiteralPath $ConfigPath){$script:Config.Enabled=$false;Write-Config}
    Log 'ATUALIZACAO' 'Pausando novas remocoes e aguardando a operacao atual, sem encerrar o Windows Installer.'
    $until=[DateTime]::UtcNow.AddSeconds(260)
    while($oldCycle -and (Get-ScheduledTask -TaskName $TaskName).State -eq 'Running'){
        if([DateTime]::UtcNow -ge $until){
            Read-Config;$script:Config.Enabled=$script:WasEnabled;Write-Config
            if($script:WasEnabled){Enable-ScheduledTask -TaskName $TaskName|Out-Null}
            if($oldGuard){Enable-ScheduledTask -TaskName $script:GuardianTaskName|Out-Null;Start-ScheduledTask -TaskName $script:GuardianTaskName}
            throw 'A limpeza anterior nao terminou. A configuracao anterior foi restaurada. Confira os registros antes de repetir.'
        }
        Start-Sleep -Seconds 2
    }
    if([IO.Path]::GetFullPath($env:LG_SOURCE_EXE).Equals($Exe,[StringComparison]::OrdinalIgnoreCase)){return}
    foreach($p in @(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.Equals($Exe,[StringComparison]::OrdinalIgnoreCase)})){
        $current=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$p.ProcessId)
        if($current -and $current.CreationDate -eq $p.CreationDate -and $current.ExecutablePath -eq $p.ExecutablePath){
            $answer=Invoke-CimMethod -InputObject $current -MethodName Terminate
            if($answer.ReturnValue -ne 0){throw 'Nao foi possivel fechar uma instancia antiga do LabGuard. A nova instalacao nao foi confirmada.'}
        }
    }
    Start-Sleep -Milliseconds 500
}
function Initialize-AutomaticPolicy {
    Read-Config
    $script:Config.Screenshots=$false
    if($script:HasCentral){
        $script:Config.Enabled=$script:WasEnabled
        Log 'CENTRAL' 'Vinculo e politica existentes preservados; a Central continua administrando esta estacao.'
    }else{
        $script:Config.Enabled=$true;$script:Config.AutoCloseGames=$true;$script:Config.BlockYouTube=$true
        $script:Config|Add-Member -NotePropertyName CentralSiteDomains -NotePropertyValue @($script:DefaultLocalSites) -Force
        $script:Config|Add-Member -NotePropertyName CentralSitesRevision -NotePropertyValue 0 -Force
        $script:Config|Add-Member -NotePropertyName ManagedAppliedRevision -NotePropertyValue 0 -Force
        Log 'LOCAL' 'Protecao automatica: catalogo completo LabGuard (jogos, apostas, adultos, IA), sites rapidos e YouTube. Sem vinculo obrigatorio.'
    }
    $script:Config|Add-Member -NotePropertyName Version -NotePropertyValue '2.5.0' -Force
    Write-Config
}
function Install-Extensions {
    try{
        Apply-YouTube ([bool]$script:Config.BlockYouTube)
        Apply-FullCatalog
        $revision=0;if($script:Config.PSObject.Properties.Name -contains 'CentralSitesRevision'){$revision=[int]$script:Config.CentralSitesRevision}
        Write-JsonAtomic (Join-Path $Data 'web-status.json') @{state='applied';revision=$revision;source=$(if($script:HasCentral){'central'}else{'local'});count=@(Get-CentralDomains).Count;updatedUtc=[DateTime]::UtcNow.ToString('o')}
    }catch{
        Log 'FALHA' ('Bloqueios de sites: '+$_.Exception.Message)
        Write-JsonAtomic (Join-Path $Data 'web-status.json') @{state='failed';revision=0;detail=$_.Exception.Message;updatedUtc=[DateTime]::UtcNow.ToString('o')}
    }
    # Start readers only after the initial policy journal has been committed.
    Register-GuardianTask
}
function Check-AutomaticHealth {
    if(-not(Test-Path -LiteralPath $ConfigPath)){throw 'A instalacao ainda nao possui configuracao.'}
    Read-Config
    $problems=New-Object 'System.Collections.Generic.List[string]'
    $cleanup=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $guard=Get-ScheduledTask -TaskName $script:GuardianTaskName -ErrorAction SilentlyContinue
    $scheduled=$false
    if($cleanup){
        $scheduled=($cleanup.Principal.UserId -in @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM')) -and @($cleanup.Triggers|Where-Object {$_.Repetition.Interval -eq 'PT5M'}).Count -eq 1 -and @($cleanup.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'}).Count -eq 1
        if($script:Config.Enabled -and $cleanup.State -eq 'Disabled'){$scheduled=$false}
    }
    if(-not $scheduled){$problems.Add('Agendamento SYSTEM de 5 minutos nao confirmado.')}
    $alive=$false;$monitor='Sem contato';$until=[DateTime]::UtcNow.AddSeconds(35)
    do{
        try{
            $file=Join-Path $Data 'guard-status.json'
            if(Test-Path -LiteralPath $file){$g=Get-Content -LiteralPath $file -Raw -Encoding UTF8|ConvertFrom-Json;$age=([DateTime]::UtcNow-[DateTime]::Parse($g.updatedUtc).ToUniversalTime()).TotalSeconds;$monitor=[string]$g.state;$alive=$age -ge -5 -and $age -le 15 -and $g.version -eq '2.5.0' -and $g.state -in @('Ativo','Pausado')}
        }catch{}
        if(-not $alive){Start-Sleep -Seconds 1}
    }while(-not $alive -and [DateTime]::UtcNow -lt $until)
    $guard=Get-ScheduledTask -TaskName $script:GuardianTaskName -ErrorAction SilentlyContinue
    if(-not $guard -or $guard.State -ne 'Running' -or -not $alive){$problems.Add('O monitor nao confirmou atividade recente.')}
    $sites=$true;$domains=@(Get-CentralDomains);if($script:Config.BlockYouTube){$domains+=@($script:YouTubeDomains)}
    foreach($keyPath in $script:BrowserKeys){
        if(-not $domains.Count){continue}
        if(-not(Test-Path -LiteralPath $keyPath)){$sites=$false;continue}
        $key=Get-Item -LiteralPath $keyPath
        try{$values=@($key.GetValueNames()|ForEach-Object {[string]$key.GetValue($_)})}finally{$key.Close()}
        foreach($domain in $domains){$expected=if($keyPath -like '*Mozilla*'){'*://*.'+$domain+'/*'}else{$domain};if($values -cnotcontains $expected){$sites=$false}}
    }
    try{$ws=Get-Content -LiteralPath (Join-Path $Data 'web-status.json') -Raw -Encoding UTF8|ConvertFrom-Json;if($ws.state -eq 'failed'){$sites=$false}}catch{$sites=$false}
    if(-not (Test-FullCatalog)){$sites=$false;$problems.Add('Catalogo completo de jogos, apostas, adultos e IA nao confirmado em todos os navegadores.')}
    if(-not $sites){$problems.Add('Uma ou mais regras de navegador nao foram confirmadas.')}
    $linked=Test-Path -LiteralPath (Join-Path $Base 'Central\vinculo.dat')
    $report=@{version='2.5.0';state=$(if($problems.Count){'partial'}else{'ready'});scheduler=$scheduled;monitor=$monitor;monitorFresh=$alive;sites=$sites;centralLinked=[bool]$linked;protectionEnabled=[bool]$script:Config.Enabled;updatedUtc=[DateTime]::UtcNow.ToString('o');issues=@($problems.ToArray())}
    Write-JsonAtomic (Join-Path $Data 'install-status.json') $report
    foreach($problem in $problems){Log 'FALHA' $problem}
    Log 'CONFIRMACAO' ('Monitor='+$monitor+'; agendamento='+$scheduled+'; regras de sites='+$sites+'; vinculo='+$linked)
    Log 'IMPORTANTE' 'Catalogo completo inclui dominios de IA e apostas. Regras gravadas nao substituem teste de navegacao; reabra o navegador na conta do aluno.'
    if($problems.Count){return 2};return 0
}
