$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$out=Join-Path $root 'dist'
New-Item -ItemType Directory -Path $out -Force|Out-Null
python -m pip install --disable-pip-version-check 'pyinstaller==6.16.0'
if($LASTEXITCODE -ne 0){throw 'PyInstaller installation failed.'}
python (Join-Path $root 'prepare.py')
if($LASTEXITCODE -ne 0){throw 'Source assembly failed.'}
python (Join-Path $root 'tests-assembled.py')
if($LASTEXITCODE -ne 0){throw 'Uninstaller unit tests failed.'}
$tokens=$null;$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'operations.ps1'),[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count){$errors|Format-List|Out-String|Write-Host;throw 'PowerShell operation syntax error.'}
& (Join-Path $root 'verify-native.ps1')
$prepared=Join-Path $root 'build-source'
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name LabGuard-Desinstalador --distpath $out --workpath (Join-Path $root 'work') --specpath $root --paths $prepared --add-data ((Join-Path $prepared 'resources')+';resources') (Join-Path $prepared 'main.py')
if($LASTEXITCODE -ne 0){throw 'Executable compilation failed.'}
$exe=Join-Path $out 'LabGuard-Desinstalador.exe'
$test=Join-Path $out 'self-test.txt'
$p=Start-Process -FilePath $exe -ArgumentList @('--self-test','--result',('"'+$test+'"')) -PassThru
if(-not $p.WaitForExit(90000)){Stop-Process -Id $p.Id -Force;throw 'EXE self-test timeout.'}
if($p.ExitCode -ne 0 -or -not(Test-Path -LiteralPath $test)){throw 'Embedded EXE self-test failed.'}
$p=Start-Process -FilePath $exe -ArgumentList '--ui-smoke' -PassThru
if(-not $p.WaitForExit(45000)){Stop-Process -Id $p.Id -Force;throw 'UI smoke timeout.'}
if($p.ExitCode -ne 0){throw 'UI smoke failed.'}
Copy-Item (Join-Path $root 'README.md') (Join-Path $out 'LEIA-ME.md') -Force
$hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
($hash+'  LabGuard-Desinstalador.exe')|Set-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII
$report=@('LABGUARD DESINSTALADOR 1.0.0','Compilacao Windows x64 / Python 3.12 / PyInstaller 6.16.0',('UTC: '+[DateTime]::UtcNow.ToString('o')),'','Testes unitarios: PASS','Parser PowerShell 5.1: PASS','EXE com recursos internos: PASS','Abertura da interface: PASS','')+@(Get-Content (Join-Path $root 'native-verification.txt'))+@('','Nao executado nos PCs reais do laboratorio.','DNS/IPv6 reais nao alterados durante os testes; restauracao depende dos registros e da configuracao da estacao.')
$report|Set-Content -LiteralPath (Join-Path $out 'VERIFICACAO.txt') -Encoding UTF8
Copy-Item (Join-Path $prepared 'main.py') (Join-Path $out 'codigo-executado.py') -Force
Compress-Archive -Path $exe,(Join-Path $out 'LEIA-ME.md'),(Join-Path $out 'SHA256SUMS.txt'),(Join-Path $out 'VERIFICACAO.txt') -DestinationPath (Join-Path $out 'LabGuard-Desinstalador-Windows.zip') -Force
Write-Host ('READY: '+$exe)
$global:LASTEXITCODE=0
