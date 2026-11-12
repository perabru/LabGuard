$ErrorActionPreference='Stop'
$env:PYTHONUTF8='1'
$root=Split-Path $PSScriptRoot -Parent
Set-Location $root
$out=Join-Path $PSScriptRoot 'dist';New-Item -ItemType Directory -Path $out -Force|Out-Null
python -m pip install --disable-pip-version-check 'cryptography==50.0.0' 'pyinstaller==6.16.0' 'playwright==1.56.0'
if($LASTEXITCODE -ne 0){throw 'Build dependencies failed.'}
& ./games/build.ps1
python ./managed/prepare.py
if($LASTEXITCODE -ne 0){throw 'Base assembly failed.'}
python ./managed/web_prepare.py
if($LASTEXITCODE -ne 0){throw 'Managed assembly failed.'}
python -m unittest discover -s managed -p 'test_*.py' -v
if($LASTEXITCODE -ne 0){throw 'Managed protocol tests failed.'}
python -m unittest discover -s central -p 'test_*.py' -v
if($LASTEXITCODE -ne 0){throw 'Legacy Central regression tests failed.'}
$engine=Join-Path $root 'games\dist\Engine.assembled.ps1';$tokens=$null;$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($engine,[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count){throw ($errors|Out-String)}
$compiler=Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$client=Join-Path $out 'LabGuard-Jogos.exe'
$sources=@('games\dist\LabGuard.assembled.cs','games\dist\Guardian.assembled.cs','games\extensions\WindowsGames.cs','managed\build\ManagedClient.cs')|ForEach-Object {Join-Path $root $_}
foreach($source in $sources){if(-not(Test-Path -LiteralPath $source)){throw ('Missing compiler input: '+$source)}}
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /reference:System.dll /reference:System.Core.dll /reference:System.Security.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:System.Management.dll ("/win32manifest:"+(Join-Path $root 'games\app.manifest')) ("/resource:"+$engine+',LabGuard.Engine') ("/out:"+$client) @sources
if($LASTEXITCODE -ne 0){throw 'Managed client C# build failed.'}
function Check-Exe([string]$File,[string]$Arguments,[int]$Timeout=40000){$p=Start-Process $File -ArgumentList $Arguments -PassThru;if(-not $p.WaitForExit($Timeout)){Stop-Process -Id $p.Id -Force;throw ('Timeout: '+$Arguments)};if($p.ExitCode -ne 0){throw ('EXE test failed: '+$Arguments+'; '+$p.ExitCode)};Write-Host ('PASS: '+$Arguments)}
Check-Exe $client '--self-test'
Check-Exe $client '--central-self-test'
Check-Exe $client '--setup-smoke'
Check-Exe $client '--ui-smoke'
& ./managed/verify-websites.ps1
python ./managed/integration_windows.py
if($LASTEXITCODE -ne 0){throw 'Real C# / TLS integration test failed.'}
$prepared=Join-Path $PSScriptRoot 'build'
$assets=(Join-Path $prepared 'assets')+';assets'
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --noupx --name LabGuardTecnico --distpath $out --workpath (Join-Path $PSScriptRoot 'work') --specpath $PSScriptRoot --paths $prepared --paths (Join-Path $root 'client') --paths $PSScriptRoot --add-data $assets (Join-Path $PSScriptRoot 'tecnico.py')
if($LASTEXITCODE -ne 0){throw 'Central EXE build failed.'}
$central=Join-Path $out 'LabGuardTecnico.exe';$testOutput=Join-Path $out 'central-self-test.json'
Check-Exe $central ('--self-test --output "'+$testOutput+'"') 90000
python ./managed/smoke_websites.py
if($LASTEXITCODE -ne 0){throw 'Quick site browser UI test failed.'}
Copy-Item ./managed/README.md (Join-Path $out 'LEIA-ME.md') -Force
$sum=@();foreach($file in @($client,$central)){$sum+=(Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($file)}
$sum|Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII
@('LABGUARD GERENCIADO - CLIENTE 2.3 / CENTRAL 1.2',('UTC: '+[DateTime]::UtcNow.ToString('o')),'','PASS: testes da base de jogos 2.1 e compatibilidade PowerShell 5.1','PASS: testes de protocolo, autenticacao, CSRF, revogacao e retencao','PASS: testes de regressao da Central anterior','PASS: compilacao C# x64 e abertura das interfaces','PASS: cliente C# conectado a Central HTTPS descartavel','PASS: certificado incorreto recusado e eventos repetidos deduplicados','PASS: empacotamento e recursos internos do painel Windows','PASS: sites rapidos e Bloquear tudo no painel Edge de teste','PASS: politicas nativas Chrome/Edge/Firefox em Registro sintetico','','Nenhum cliente foi instalado nos PCs reais do laboratorio. As verificacoes usaram componentes e estacoes ficticias.')|Set-Content (Join-Path $out 'VERIFICACAO.txt') -Encoding UTF8
Compress-Archive -Path $client,$central,(Join-Path $out 'LEIA-ME.md'),(Join-Path $out 'VERIFICACAO.txt'),(Join-Path $out 'SHA256SUMS.txt') -DestinationPath (Join-Path $out 'LabGuard-Gerenciado-Windows.zip') -Force
Write-Host 'READY: managed client and Central'
$global:LASTEXITCODE=0
