# Disposable Registry fixtures only. Never changes installed browser policies or hosts.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$source=[IO.File]::ReadAllText((Join-Path $root 'games\dist\Engine.assembled.ps1')).Replace("`r`n","`n")
$pos=$source.IndexOf("try {`n    if (`$Mode -eq 'Test')",[StringComparison]::Ordinal)
if($pos -lt 0){throw 'Engine entrypoint not found.'}
. ([scriptblock]::Create($source.Substring(0,$pos))) -Mode Test
$fixture=Join-Path $PSScriptRoot ('web-test-'+[guid]::NewGuid().ToString('N'))
$registry='HKCU:\Software\LabGuard-Web-Test-'+[guid]::NewGuid().ToString('N')
try {
 New-Item -ItemType Directory -Path $fixture|Out-Null
 $Data=$fixture;$script:Config=[pscustomobject]@{Enabled=$true;Screenshots=$false;BlockYouTube=$true;AutoCloseGames=$true;CentralSiteDomains=@('term.ooo','friv.com','friv.com.br','poki.com','chess.com')}
 $script:BrowserKeys=@(($registry+'\Chrome\URLBlocklist'),($registry+'\Edge\URLBlocklist'),($registry+'\Mozilla\Firefox\WebsiteFilter\Block'))
 foreach($path in $script:BrowserKeys){New-Item -Path $path -Force|Out-Null;New-ItemProperty -LiteralPath $path -Name '1' -Value 'school.example' -PropertyType String|Out-Null}
 $validated=@(Assert-CentralDomains $script:Config.CentralSiteDomains);if($validated.Count -ne 5 -or $validated[0] -isnot [string]){throw 'Domain array was nested or truncated.'}
 foreach($bad in @('*','com.br','127.0.0.1','http://term.ooo','*.poki.com','a.local')){$failed=$false;try{$null=Assert-CentralDomains @($bad)}catch{$failed=$true};if(-not $failed){throw ('Invalid domain accepted: '+$bad)}}
 Set-YouTubeBrowserPolicies $true
 $before=[IO.File]::ReadAllText((Join-Path $Data 'youtube-owned-rules.json'))
 Set-YouTubeBrowserPolicies $true
 if([IO.File]::ReadAllText((Join-Path $Data 'youtube-owned-rules.json')) -cne $before){throw 'Repeated block was not idempotent.'}
 foreach($path in $script:BrowserKeys){$key=Get-Item -LiteralPath $path;$values=@($key.GetValueNames()|ForEach-Object {$key.GetValue($_)});if($key.GetValue('1') -ne 'school.example'){throw 'External rule overwritten.'};if(-not @($values|Where-Object {$_ -match 'term\.ooo'}).Count){throw 'Termo rule missing.'};$key.Close()}
 $script:Config.CentralSiteDomains=@('poki.com');Set-YouTubeBrowserPolicies $true
 foreach($path in $script:BrowserKeys){$key=Get-Item -LiteralPath $path;$values=@($key.GetValueNames()|ForEach-Object {$key.GetValue($_)});$key.Close();if(@($values|Where-Object {$_ -match 'term\.ooo'}).Count){throw 'Released site remained blocked.'};if(-not @($values|Where-Object {$_ -match 'poki\.com'}).Count){throw 'Requested site removed.'}}
 $path=$script:BrowserKeys[0];$key=Get-Item -LiteralPath $path;$slot=@($key.GetValueNames()|Where-Object {$key.GetValue($_) -eq 'poki.com'})[0];$key.Close();Set-ItemProperty -LiteralPath $path -Name $slot -Value 'external.example'
 $script:Config.CentralSiteDomains=@();Set-YouTubeBrowserPolicies $false
 foreach($path in $script:BrowserKeys){$key=Get-Item -LiteralPath $path;if($key.GetValue('1') -ne 'school.example'){throw 'External base rule removed.'};$key.Close()}
 if((Get-Item -LiteralPath $script:BrowserKeys[0]).GetValue($slot) -ne 'external.example'){throw 'Externally changed rule removed.'}
 foreach($path in $script:BrowserKeys){Remove-Item -LiteralPath $path -Recurse -Force}
 Write-JsonAtomic (Join-Path $Data 'youtube-owned-rules.json') @();$script:Config.CentralSiteDomains=@('term.ooo');Set-YouTubeBrowserPolicies $false
 $ff=$script:BrowserKeys[2];New-ItemProperty -LiteralPath $ff -Name '2' -Value '*://*.school.example/*' -PropertyType String|Out-Null
 $script:Config.CentralSiteDomains=@();Set-YouTubeBrowserPolicies $false
 $key=Get-Item -LiteralPath $ff;if(-not $key.GetValue('1') -or $key.GetValue('2') -ne '*://*.school.example/*'){throw 'Firefox external list damaged.'};$key.Close()
 Write-Host 'PASS: five domains; individual release; bulk reconciliation; Chrome/Edge/Firefox; idempotency; external rules preserved; Firefox first slot; no real policy modified.'
} finally {
 if(Test-Path -LiteralPath $registry){Remove-Item -LiteralPath $registry -Recurse -Force}
 if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
