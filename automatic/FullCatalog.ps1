# Embedded full catalog copied from the LabGuard network/client catalogs at build time.
# All registry writes have a bounded, per-browser ownership journal. The main TI filter is never modified.
$script:FullCatalogDomains=__FULL_CATALOG__
$script:FullCatalogRevision='2026.11.14.1'
$script:CatalogBrowsers=@(
    @('chrome','SOFTWARE\Policies\Google\Chrome\URLBlocklist'),
    @('edge','SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'),
    @('firefox','SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block')
)
function Full-CatalogValue([string]$Domain,[bool]$Firefox){
    if($Firefox){return '*://*.'+$Domain+'/*'}
    return $Domain
}
function Read-CatalogJournal([string]$Path,[bool]$Firefox){
    $result=New-Object 'System.Collections.Generic.List[object]'
    if(-not(Test-Path -LiteralPath $Path)){return ,$result}
    if(-not(No-Link $Path) -or (Get-Item -LiteralPath $Path -Force).Length -gt 262144){throw ('Registro de catalogo invalido: '+$Path)}
    $parsed=Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json
    foreach($r in $parsed){
        if($null -eq $r){continue}
        $name=[string]$r.Name;$value=[string]$r.Value
        if($name -notmatch '^(?:[1-9][0-9]{0,2}|1000)$' -or $value.Length -gt 300){
            throw 'Registro de catalogo com posicao/valor invalido.'
        }
        if($Firefox){
            if($value -cnotmatch '^\*://\*\.[a-z0-9.-]+\.[a-z]{2,}(/\*)$'){throw 'Regra Firefox do catalogo invalida.'}
        }elseif($value -cnotmatch '^[a-z0-9](?:[a-z0-9.-]{0,251})\.[a-z]{2,}$'){
            throw 'Regra Chrome/Edge do catalogo invalida.'
        }
        if(@($result.ToArray()|Where-Object {$_.Name -eq $name}).Count){throw 'Registro de catalogo com posicoes duplicadas.'}
        $result.Add([pscustomobject]@{Name=$name;Value=$value})
    }
    return ,$result
}
function Save-CatalogJournal([string]$Path,$Items){
    Write-JsonAtomic $Path @($Items.ToArray())
}
function Catalog-Browser([string]$Label,[string]$Subkey,[switch]$Remove){
    $firefox=$Label -eq 'firefox'
    $journal=Join-Path $Data ('fullcatalog-owned-'+$Label+'.json')
    $records=Read-CatalogJournal $journal $firefox
    if($Remove){
        $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Subkey,$true)
    }else{
        $key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($Subkey,$true)
    }
    if($null -eq $key){return}
    try{
        $allNames=@($key.GetValueNames());$byName=@{};$byValue=@{}
        foreach($name in $allNames){
            try{
                if($key.GetValueKind($name) -eq [Microsoft.Win32.RegistryValueKind]::String){
                    $v=[string]$key.GetValue($name)
                    $byName[$name]=$v;$byValue[$v]=$true
                }else{$byName[$name]=$null}
            }catch{$byName[$name]=$null}
        }
        $wanted=@{}
        if(-not $Remove){foreach($domain in $script:FullCatalogDomains){$wanted[(Full-CatalogValue $domain $firefox)]=$true}}
        $owned=New-Object 'System.Collections.Generic.List[object]'
        foreach($rec in $records.ToArray()){
            $actual=$byName[[string]$rec.Name]
            if($null -eq $actual -or $actual -cne [string]$rec.Value){continue}
            if($Remove -or -not $wanted.ContainsKey([string]$rec.Value)){
                $key.DeleteValue([string]$rec.Name,$false)
                $byName.Remove([string]$rec.Name);$byValue.Remove([string]$rec.Value)
                continue
            }
            $owned.Add($rec)
        }
        # Preserve a write-ahead journal for retained entries after a prior interrupted installation.
        Save-CatalogJournal $journal $owned
        if($Remove){return}
        $next=80;$plans=New-Object 'System.Collections.Generic.List[object]'
        foreach($domain in $script:FullCatalogDomains){
            $value=Full-CatalogValue $domain $firefox
            if($byValue.ContainsKey($value)){continue}
            # Firefox may require the first policy slot. Never change an existing non-LabGuard entry.
            if($firefox -and -not $byName.ContainsKey('1') -and -not $plans.Count){$name='1'}
            else{
                while($byName.ContainsKey([string]$next)){$next++}
                if($next -gt 950 -or $byName.Count -ge 950){
                    throw ('Navegador '+$Label+' sem espaco para todo o catalogo. Nenhuma regra externa foi sobrescrita.')
                }
                $name=[string]$next;$next++
            }
            $entry=[pscustomobject]@{Name=$name;Value=$value}
            $plans.Add($entry);$owned.Add($entry);$byName[$name]=$value;$byValue[$value]=$true
        }
        # Entries are journaled before changes, so a crash never leaves untracked new rules.
        Save-CatalogJournal $journal $owned
        foreach($entry in $plans.ToArray()){
            if($null -ne $key.GetValue([string]$entry.Name,$null)){throw 'Posicao de navegador ocupada durante a instalacao; confira o catalogo.'}
            $key.SetValue([string]$entry.Name,[string]$entry.Value,[Microsoft.Win32.RegistryValueKind]::String)
        }
        $values=@{};foreach($n in @($key.GetValueNames())){try{if($key.GetValueKind($n) -eq [Microsoft.Win32.RegistryValueKind]::String){$values[[string]$key.GetValue($n)]=$true}}catch{}}
        $missing=@($wanted.Keys|Where-Object {-not $values.ContainsKey($_)})
        if($missing.Count){throw ('Catalogo '+$Label+': '+$missing.Count+' dominio(s) nao confirmado(s).')}
        Log 'SITES' ($Label+': '+$wanted.Count+' bloqueios presentes; '+$plans.Count+' novo(s), sem sobrescrever regras de terceiros.')
    }finally{$key.Close()}
}
function Apply-FullCatalog {
    if(@($script:FullCatalogDomains).Count -lt 800 -or @($script:FullCatalogDomains).Count -gt 900){throw 'O catalogo completo nao passou pela validacao de tamanho.'}
    $status=Join-Path $Data 'fullcatalog-status.json'
    try{
        foreach($browser in $script:CatalogBrowsers){Catalog-Browser $browser[0] $browser[1]}
        Write-JsonAtomic $status @{state='applied';count=@($script:FullCatalogDomains).Count;revision=$script:FullCatalogRevision;updatedUtc=[DateTime]::UtcNow.ToString('o')}
    }catch{
        try{Write-JsonAtomic $status @{state='failed';detail=($_.Exception.Message+' :: '+$_.ScriptStackTrace);count=@($script:FullCatalogDomains).Count;revision=$script:FullCatalogRevision;updatedUtc=[DateTime]::UtcNow.ToString('o')}}catch{}
        throw
    }
}
function Test-FullCatalog {
    try{
        $statusFile=Join-Path $Data 'fullcatalog-status.json'
        if(-not(Test-Path -LiteralPath $statusFile) -or -not(No-Link $statusFile)){return $false}
        $status=Get-Content -LiteralPath $statusFile -Raw -Encoding UTF8|ConvertFrom-Json
        if($status.state -ne 'applied' -or $status.revision -cne $script:FullCatalogRevision -or [int]$status.count -ne @($script:FullCatalogDomains).Count){return $false}
        foreach($browser in $script:CatalogBrowsers){
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey([string]$browser[1],$false)
            if($null -eq $key){return $false}
            try{
                $values=@{};foreach($name in @($key.GetValueNames())){if($key.GetValueKind($name) -eq [Microsoft.Win32.RegistryValueKind]::String){$values[[string]$key.GetValue($name)]=$true}}
                foreach($d in $script:FullCatalogDomains){if(-not $values.ContainsKey((Full-CatalogValue $d ($browser[0] -eq 'firefox')))){return $false}}
            }finally{$key.Close()}
        }
        return $true
    }catch{return $false}
}
function Remove-FullCatalog {
    foreach($browser in $script:CatalogBrowsers){Catalog-Browser $browser[0] $browser[1] -Remove}
    Log 'SITES' 'Removidas somente as regras ainda identificadas como pertencentes ao catalogo completo LabGuard.'
}
