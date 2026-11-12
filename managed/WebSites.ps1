# Specific game domains only. Shares the owned browser-rule journal with the uninstaller.
function Assert-CentralDomains($Values){
    if($null -eq $Values){return @()}
    if($Values -is [string] -or $Values -isnot [System.Collections.IEnumerable]){throw 'A lista de sites precisa ser um array.'}
    $result=@($Values)
    if($result.Count -gt 30){throw 'Limite de 30 dominios excedido.'}
    foreach($d in $result){
        if($d -isnot [string] -or $d.Length -gt 253 -or $d -cnotmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$' -or $d -match '\.[0-9]+$' -or $d -match '\.(?:local|localhost|arpa|internal)$' -or $d -in @('com.br','net.br','org.br','edu.br','gov.br','co.uk')){throw 'Dominio fora do escopo; nenhuma politica arbitraria e aceita.'}
    }
    return @($result|Sort-Object -Unique)
}
function Get-CentralDomains {
    if($script:Config.PSObject.Properties.Name -contains 'CentralSiteDomains'){return @(Assert-CentralDomains $script:Config.CentralSiteDomains)}
    return @()
}
function Set-YouTubeBrowserPolicies([bool]$Blocked){
    $state=Join-Path $Data 'youtube-owned-rules.json'
    $owned=New-Object 'System.Collections.Generic.List[object]'
    if(Test-Path -LiteralPath $state){
        if(-not(No-Link $state) -or (Get-Item -LiteralPath $state).Length -gt 262144){throw 'Registro de propriedade invalido.'}
        foreach($r in @(Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json)){
            if($null -eq $r){continue}
            if($script:BrowserKeys -notcontains [string]$r.Key -or [string]$r.Name -notmatch '^(?:[1-9][0-9]{0,2}|1000)$' -or $r.Value -isnot [string]){throw 'Metadados de navegador fora do escopo.'}
            $owned.Add($r)
        }
    }
    $domains=@(Get-CentralDomains)
    if($Blocked){$domains+=@($script:YouTubeDomains)}
    $domains=@($domains|Sort-Object -Unique)
    $anchor='*://*.labguard-reserved.invalid/*'
    foreach($path in $script:BrowserKeys){
        $firefox=$path -like '*Firefox*' -or $path -like '*Mozilla*'
        $desired=if($firefox){@($domains|ForEach-Object {'*://*.'+$_+'/*'})}else{@($domains)}
        if(-not(Test-Path -LiteralPath $path)){
            if(-not $desired.Count){continue}
            New-Item -Path $path -Force|Out-Null
        }
        foreach($r in @($owned.ToArray()|Where-Object {$_.Key -eq $path})){
            $key=Get-Item -LiteralPath $path
            $matches=@($key.GetValueNames()) -contains [string]$r.Name -and $key.GetValueKind([string]$r.Name) -eq [Microsoft.Win32.RegistryValueKind]::String -and [string]$key.GetValue([string]$r.Name) -ceq [string]$r.Value
            $key.Close()
            if(-not $matches){$owned.Remove($r)|Out-Null}
        }
        Write-JsonAtomic $state @($owned.ToArray())
        $key=Get-Item -LiteralPath $path;$names=@($key.GetValueNames());$key.Close()
        if($firefox -and $desired.Count -and $names.Count -and $names -notcontains '1'){throw 'Firefox: lista externa sem primeira entrada 1. Revise a politica na TI.'}
        $mine=@($owned.ToArray()|Where-Object {$_.Key -eq $path})
        $external=@($names|Where-Object {$_ -notin @($mine|ForEach-Object {$_.Name})})
        foreach($r in @($mine|Where-Object {$_.Value -cnotin $desired})){
            if($firefox -and $r.Name -eq '1' -and ($desired.Count -or $external.Count)){
                $key=Get-Item -LiteralPath $path;$current=[string]$key.GetValue('1');$key.Close()
                if($current -ceq [string]$r.Value){Set-ItemProperty -LiteralPath $path -Name '1' -Value $anchor;$r.Value=$anchor}
            }else{
                $key=Get-Item -LiteralPath $path;$current=[string]$key.GetValue([string]$r.Name);$key.Close()
                if($current -ceq [string]$r.Value){Remove-ItemProperty -LiteralPath $path -Name ([string]$r.Name) -ErrorAction Stop}
                $owned.Remove($r)|Out-Null
            }
            Write-JsonAtomic $state @($owned.ToArray())
        }
        foreach($value in $desired){
            $key=Get-Item -LiteralPath $path;$names=@($key.GetValueNames());$found=@($names|ForEach-Object {[string]$key.GetValue($_)});$key.Close()
            if($found -ccontains $value){continue}
            $index=1;while($names -contains [string]$index){$index++}
            if($index -gt 1000 -or $names.Count -ge 990){throw 'Navegador proximo do limite de regras; confira as politicas existentes.'}
            $r=[pscustomobject]@{Key=$path;Name=[string]$index;Value=$value};$owned.Add($r)
            Write-JsonAtomic $state @($owned.ToArray())
            New-ItemProperty -LiteralPath $path -Name ([string]$index) -Value $value -PropertyType String -ErrorAction Stop|Out-Null
        }
        $key=Get-Item -LiteralPath $path;$actual=@($key.GetValueNames()|ForEach-Object {[string]$key.GetValue($_)});$key.Close()
        foreach($v in $desired){if($actual -cnotcontains $v){throw 'O Windows nao confirmou todas as regras de sites.'}}
    }
    Write-JsonAtomic $state @($owned.ToArray())
}
function Apply-CentralSites($Received){
    $keys=@($Received.PSObject.Properties.Name)
    if($keys.Count -ne 2 -or @($keys|Where-Object {$_ -notin @('revision','blocked_domains')}).Count){throw 'Politica de sites fora do escopo.'}
    $rev=0;if(-not[int]::TryParse([string]$Received.revision,[ref]$rev) -or $rev -lt 1){throw 'Revisao de sites invalida.'}
    $domains=@(Assert-CentralDomains $Received.blocked_domains)
    Read-Config
    $script:Config|Add-Member -NotePropertyName CentralSiteDomains -NotePropertyValue $domains -Force
    Write-Config
    try{
        Apply-YouTube ([bool]$script:Config.BlockYouTube)
        Read-Config;$script:Config|Add-Member -NotePropertyName CentralSitesRevision -NotePropertyValue $rev -Force;Write-Config
        Write-JsonAtomic (Join-Path $Data 'web-status.json') @{state='applied';revision=$rev;count=$domains.Count;updatedUtc=[DateTime]::UtcNow.ToString('o')}
        Log 'SITES' ('Lista confirmada nos navegadores: revisao '+$rev+'; '+$domains.Count+' dominios. Reabra os navegadores. Excecoes externas podem prevalecer.')
    }catch{
        try{Write-JsonAtomic (Join-Path $Data 'web-status.json') @{state='failed';revision=$rev;detail=$_.Exception.Message;updatedUtc=[DateTime]::UtcNow.ToString('o')}}catch{}
        throw
    }
}
