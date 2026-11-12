$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$out=Join-Path $root 'dist'
New-Item -ItemType Directory -Path $out -Force|Out-Null
# Assemble auditable policy definitions before the engine entrypoint.
$source=[IO.File]::ReadAllText((Join-Path $root 'Engine.ps1')).Replace("`r`n","`n")
$policy=[IO.File]::ReadAllText((Join-Path $root 'Policy.ps1')).Replace("`r`n","`n")
$entry="try {`n    if (`$Mode -eq 'Test') {"
if(-not $source.Contains($entry)){throw 'Engine entrypoint not found; refusing incomplete build.'}
$source=$source.Replace($entry,$policy+"`n"+$entry)
$assembled=Join-Path $out 'Engine.assembled.ps1'
[IO.File]::WriteAllText($assembled,$source,(New-Object Text.UTF8Encoding($true)))
$tokens=$null; $errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($assembled,[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count -gt 0){$errors|Format-List|Out-String|Write-Host;throw 'Motor PowerShell com erros de sintaxe.'}
# In-process self-test provides readable output; the EXE test checks embedded-resource execution too.
& (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $assembled -Mode Test
if($LASTEXITCODE -ne 0){throw 'Engine self-test failed.'}
$compiler=Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path $compiler)){throw 'Compilador .NET Framework 4.x x64 nao encontrado.'}
$exe=Join-Path $out 'LabGuard-Jogos.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll ("/win32manifest:"+(Join-Path $root 'app.manifest')) ("/resource:"+$assembled+',LabGuard.Engine') ("/out:"+$exe) (Join-Path $root 'LabGuard.cs')
if($LASTEXITCODE -ne 0){throw 'Falha ao compilar o EXE.'}
$p=Start-Process $exe -ArgumentList '--self-test' -PassThru
if(-not $p.WaitForExit(30000)){Stop-Process -Id $p.Id -Force;throw 'EXE self-test timeout.'}
if($p.ExitCode -ne 0){throw ('Autoteste do EXE falhou: '+$p.ExitCode)}
$p=Start-Process $exe -ArgumentList '--ui-smoke' -PassThru
if(-not $p.WaitForExit(20000)){Stop-Process -Id $p.Id -Force;throw 'Smoke test da interface excedeu o limite.'}
if($p.ExitCode -ne 0){throw ('Smoke test da interface falhou: '+$p.ExitCode)}
Copy-Item (Join-Path $root 'README.md') (Join-Path $out 'LEIA-ME.md') -Force
$hash=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
($hash+'  LabGuard-Jogos.exe')|Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII
@{version='2.0.0';builtUtc=[DateTime]::UtcNow.ToString('o');sha256=$hash;tests=@('PowerShell 5.1 parse','Catalogo e exclusoes','Traversal/UNC/ADS','Compilacao C# x64','EXE self-test','WinForms smoke sem remocao');labTested=$false}|ConvertTo-Json|Set-Content (Join-Path $out 'build-info.json') -Encoding UTF8
Compress-Archive -Path (Join-Path $out 'LabGuard-Jogos.exe'),(Join-Path $out 'LEIA-ME.md'),(Join-Path $out 'SHA256SUMS.txt'),(Join-Path $out 'build-info.json') -DestinationPath (Join-Path $out 'LabGuard-Jogos-Windows.zip') -Force
Write-Output ('Compilacao e testes concluidos: '+$exe)
