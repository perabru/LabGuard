$ErrorActionPreference='Stop'
$root=$PSScriptRoot;$out=Join-Path $root 'dist'
& (Join-Path $root 'assemble.ps1')
# Keep the complete control panel accessible on common 1366x768 laboratory displays.
$csPath=Join-Path $out 'LabGuard.assembled.cs';$cs=[IO.File]::ReadAllText($csPath).Replace('Size=new Size(1020,900); MinimumSize=new Size(820,790);','Size=new Size(1020,760); MinimumSize=new Size(820,690);').Replace('void Capture(){','void CaptureEvidence(){').Replace('Capture();','CaptureEvidence();')
[IO.File]::WriteAllText($csPath,$cs,(New-Object Text.UTF8Encoding($true)))
$assembled=Join-Path $out 'Engine.assembled.ps1';$tokens=$null;$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($assembled,[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count -gt 0){$errors|Format-List|Out-String|Write-Host;throw 'Motor PowerShell com erros de sintaxe.'}
& (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $assembled -Mode Test
if($LASTEXITCODE -ne 0){throw 'Engine self-test failed.'}
$compiler=Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe';if(-not(Test-Path $compiler)){throw 'Compilador .NET Framework x64 nao encontrado.'}
$exe=Join-Path $out 'LabGuard-Jogos.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:System.Management.dll ("/win32manifest:"+(Join-Path $root 'app.manifest')) ("/resource:"+$assembled+',LabGuard.Engine') ("/out:"+$exe) $csPath (Join-Path $out 'Guardian.assembled.cs') (Join-Path $root 'extensions\WindowsGames.cs')
if($LASTEXITCODE -ne 0){throw 'Falha ao compilar o EXE.'}
function Run-Checked([string]$File,[string]$Arguments,[int]$Timeout=30000){$p=Start-Process $File -ArgumentList $Arguments -PassThru;if(-not $p.WaitForExit($Timeout)){Stop-Process -Id $p.Id -Force;throw ('Teste excedeu limite: '+$Arguments)};if($p.ExitCode -ne 0){throw ('Teste falhou: '+$Arguments+'; codigo '+$p.ExitCode)};Write-Host ('PASS EXE: '+$Arguments)}
Run-Checked $exe '--self-test';Run-Checked $exe '--ui-smoke'
$fixtures=Join-Path $out 'test-fixtures';New-Item -ItemType Directory -Path $fixtures -Force|Out-Null
$dummy=Join-Path $fixtures 'Dummy.cs';'using System; using System.Windows.Forms; class Dummy { [STAThread] static void Main(){Application.EnableVisualStyles();Application.Run(new Form{Text="LabGuard synthetic game test",Width=250,Height=120});} }'|Set-Content $dummy -Encoding UTF8
$game=Join-Path $fixtures 'RobloxPlayerBeta.exe'
& $compiler /nologo /target:winexe /platform:x64 /reference:System.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll ("/out:"+$game) $dummy
if($LASTEXITCODE -ne 0){throw 'Synthetic game compilation failed.'}
Run-Checked $exe ('--guard-self-test "'+$game+'"')
& (Join-Path $root 'verify-v21.ps1')
Copy-Item (Join-Path $root 'README.md') (Join-Path $out 'LEIA-ME.md') -Force
$hash=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant();($hash+'  LabGuard-Jogos.exe')|Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII
@{version='2.1.0';builtUtc=[DateTime]::UtcNow.ToString('o');sha256=$hash;tests=@('PowerShell 5.1 parse','Catalogo e exclusoes','Xbox/Windows package identities','Hosts reversivel e idempotente','Politicas de navegador com preservacao de regras','Compilacao C# x64','EXE self-test','WinForms smoke','Fechamento de janela sintetica','Tarefa SYSTEM e recuperacao');labTested=$false}|ConvertTo-Json|Set-Content (Join-Path $out 'build-info.json') -Encoding UTF8
Compress-Archive -Path $exe,(Join-Path $out 'LEIA-ME.md'),(Join-Path $out 'SHA256SUMS.txt'),(Join-Path $out 'build-info.json') -DestinationPath (Join-Path $out 'LabGuard-Jogos-Windows.zip') -Force
Write-Output ('Compilacao e testes concluidos: '+$exe)
