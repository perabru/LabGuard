$ErrorActionPreference='Stop'
$env:PYTHONUTF8='1'
$root=Split-Path $PSScriptRoot -Parent
Set-Location $root
$out=Join-Path $PSScriptRoot 'dist';New-Item -ItemType Directory -Path $out -Force|Out-Null
python -m pip install -r requirements-build.txt 'cryptography==50.0.0'
if($LASTEXITCODE -ne 0){throw 'Build dependencies failed.'}
$changed=git diff --name-only 1ef8c75859ec17e747974acb70461d89666d3dc0 HEAD -- main.py labguard gateway server_main.py server packaging/installer.iss
if($changed){throw ('Original functionality source unexpectedly changed: '+($changed -join ', '))}
$baseline=@{baseline='1ef8c75859ec17e747974acb70461d89666d3dc0';original_network_source_unchanged=$true;extension='ti';timestamp=[DateTime]::UtcNow.ToString('o')}
$baseline|ConvertTo-Json|Set-Content (Join-Path $out 'CODIGO_PRESERVADO.json') -Encoding UTF8
$payload=Join-Path $PSScriptRoot 'payload';New-Item -ItemType Directory -Path $payload -Force|Out-Null
$previous=Join-Path $PSScriptRoot 'previous';New-Item -ItemType Directory -Path $previous -Force|Out-Null
gh release download gerenciado-v2.3.0 --pattern LabGuardTecnico.exe --dir $payload --clobber
if($LASTEXITCODE -ne 0){throw 'Published Central download failed.'}
$hash=(Get-FileHash (Join-Path $payload 'LabGuardTecnico.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
if($hash -ne '4693103f63e9265342f77689a160e35dcb52fffdfdc45e8ecd36e0d786f16e88'){throw 'Central checksum does not match the verified published component.'}
gh release download v2.4.4 --pattern LabGuard-Setup.exe --dir $previous --clobber
if($LASTEXITCODE -ne 0){throw 'Previous network installer download failed.'}
python -m unittest discover -s ti -p 'test_*.py' -v
if($LASTEXITCODE -ne 0){throw 'TI additive tests failed.'}
$patterns=@('test_desktop.py','test_gui.py','test_integrations.py','test_integration_gui.py','test_server.py','test_banlist.py','test_banlist_gui.py','test_remote.py','test_remote_gui.py','test_network_map_gui.py','test_reports.py','test_controller.py','test_discovery.py','test_inventory.py','test_updater.py','test_preferences.py','test_credential_store.py','test_update_manifest.py','test_local_dns.py','test_simple_setup.py','test_station*.py','test_access_setup.py','test_access_push.py','test_school_policy.py','test_diagnostics.py','test_direct_routeros.py','test_simple_gui.py','test_site_controls.py')
foreach($pattern in $patterns){python -m unittest discover -s tests -p $pattern -v;if($LASTEXITCODE -ne 0){throw ('Original regression failed: '+$pattern)}}
python packaging/make_assets.py
if($LASTEXITCODE -ne 0){throw 'Assets failed.'}
$versionfile=Join-Path $PSScriptRoot 'version.generated.txt'
([IO.File]::ReadAllText((Join-Path $root 'packaging/windows-version.txt')).Replace('2, 4, 4','2, 4, 5').Replace('2.4.4','2.4.5'))|Set-Content $versionfile -Encoding UTF8
$arguments=@('--noconfirm','--clean','--onedir','--windowed','--noupx','--name','LabGuard','--distpath',(Join-Path $root 'dist'),'--workpath',(Join-Path $PSScriptRoot 'work'),'--specpath',$PSScriptRoot,'--paths',$root,'--icon',(Join-Path $root 'packaging/generated/LabGuard.ico'),'--version-file',$versionfile,'--collect-data','reportlab','--collect-submodules','labguard','--collect-submodules','winrm','--collect-submodules','ti','--hidden-import','main')
foreach($pair in @(@('gateway/ai_services.json','gateway'),@('docs','docs'),@('server/assets','server/assets'),@('README.md','.'),@('labguard/update_helpers','labguard/update_helpers'),@('ti/payload','ti/payload'))){$arguments+=@('--add-data',((Join-Path $root $pair[0])+';'+$pair[1]))}
if(Test-Path labguard/assets){$arguments+=@('--add-data',((Join-Path $root 'labguard/assets')+';labguard/assets'))}
$arguments+=(Join-Path $PSScriptRoot 'entry.py')
python -m PyInstaller @arguments
if($LASTEXITCODE -ne 0){throw 'TI executable build failed.'}
Copy-Item packaging/LEIA-ME.html dist/LabGuard/LEIA-ME.html -Force
Copy-Item ti/README.md dist/LabGuard/LEIA-ME-TI.md -Force
Copy-Item docs dist/LabGuard/docs -Recurse -Force
$compiler=@("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe","${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe","$env:ProgramFiles\Inno Setup 6\ISCC.exe","$env:ProgramFiles\Inno Setup 7\ISCC.exe")|Where-Object {Test-Path $_}|Select-Object -First 1
if(-not $compiler){choco install innosetup --yes --no-progress;if($LASTEXITCODE -ne 0){throw 'Inno Setup installation failed.'};$compiler="${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"}
& $compiler '/DAppVersion=2.4.5' ("/O"+$out) '/FLabGuard-TI-Setup' packaging/installer.iss
if($LASTEXITCODE -ne 0){throw 'TI installer build failed.'}
python ti/verify_windows.py
if($LASTEXITCODE -ne 0){throw 'Actual upgrade and concurrent DNS/Central verification failed.'}
Copy-Item ti/README.md (Join-Path $out 'LEIA-ME-TI.md') -Force
Compress-Archive -Path dist/LabGuard -DestinationPath (Join-Path $out 'LabGuard-TI-Portable.zip') -Force
Get-ChildItem $out -File|Where-Object {$_.Name -ne 'SHA256SUMS.txt'}|ForEach-Object {((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.Name)}|Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII
$global:LASTEXITCODE=0
