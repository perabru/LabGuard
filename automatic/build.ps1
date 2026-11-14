$ErrorActionPreference='Stop';$env:PYTHONUTF8='1'
$root=Split-Path $PSScriptRoot -Parent;Set-Location $root
# Preserve all previous game, network protocol and UI regression checks.
& ./managed/build.ps1
if($LASTEXITCODE -ne 0){throw 'Managed regression build failed.'}
python ./automatic/prepare.py
if($LASTEXITCODE -ne 0){throw 'Automatic assembly failed.'}
$out=Join-Path $PSScriptRoot 'dist';New-Item -ItemType Directory -Path $out -Force|Out-Null
$prepared=Join-Path $PSScriptRoot 'build';$engine=Join-Path $prepared 'Engine.ps1'
$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile($engine,[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count){throw ($errors|Out-String)}
$exe=Join-Path $out 'LabGuard-Jogos.exe';$compiler=Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$sources=@((Join-Path $prepared 'Program.cs'),(Join-Path $prepared 'Guardian.cs'),(Join-Path $prepared 'CentralLink.cs'),(Join-Path $root 'games\extensions\WindowsGames.cs'),(Join-Path $PSScriptRoot 'AutomaticSetup.cs'))
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /reference:System.dll /reference:System.Core.dll /reference:System.Security.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:System.Management.dll ("/win32manifest:"+(Join-Path $root 'games\app.manifest')) ("/resource:"+$engine+',LabGuard.Engine') ("/out:"+$exe) @sources
if($LASTEXITCODE -ne 0){throw 'Automatic client compilation failed.'}
foreach($argument in @('--self-test','--central-self-test','--setup-smoke','--ui-smoke')){
    $p=Start-Process $exe -ArgumentList $argument -PassThru
    if(-not $p.WaitForExit(40000)){Stop-Process -Id $p.Id -Force;throw ('Test timeout: '+$argument)}
    if($p.ExitCode -ne 0){throw ('Executable test failed: '+$argument)}
}
& ./automatic/verify-install.ps1
Copy-Item ./managed/dist/LabGuardTecnico.exe (Join-Path $out 'LabGuardTecnico.exe') -Force
$meta=(Get-Content (Join-Path $prepared 'CATALOGO_COMPLETO.json') -Raw|ConvertFrom-Json)
if($meta.full_catalog_browsers -lt 800 -or $meta.full_catalog_browsers -gt 900){throw 'Full catalog metadata invalid.'}
Copy-Item (Join-Path $prepared 'CATALOGO_COMPLETO.json') (Join-Path $out 'CATALOGO_COMPLETO.json') -Force
Copy-Item ./automatic/README.md (Join-Path $out 'LEIA-ME.md') -Force
python -m pip install --disable-pip-version-check 'reportlab==4.4.3'
if($LASTEXITCODE -ne 0){throw 'Guide dependency failed.'}
python ./automatic/guide.py
if($LASTEXITCODE -ne 0){throw 'Quick guide generation failed.'}
$sum=@();foreach($name in @('LabGuard-Jogos.exe','LabGuardTecnico.exe','LabGuard_Guia_Rapido_2.5.pdf')){$sum+=(Get-FileHash (Join-Path $out $name) -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$name};$sum|Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII
@('LABGUARD AUTOMATICO - CLIENTE 2.5 / CENTRAL 1.2',('UTC: '+[DateTime]::UtcNow.ToString('o')),'','Regressao da base de jogos, HTTPS, autenticacao, CSRF, Sites rapidos e painel: PASS','Motor PowerShell 5.1 e interfaces do EXE: PASS','Instalacao real sem vinculo e catalogo completo de sites no Windows descartavel: PASS','Inicializacao automatica e tarefas SYSTEM: PASS','Primeira limpeza de jogo ficticio e preservacao de trabalho escolar: PASS','Fechamento de janela de jogo ficticio pelo monitor instalado: PASS','Reinstalacao/reparo sem configuracao manual: PASS','','Consulte TESTE_INSTALACAO.txt para cada verificacao. Nao testado nos PCs reais do laboratorio. Windows Server 2022 nao cobre todas as configuracoes de Windows 10/11.')|Set-Content (Join-Path $out 'VERIFICACAO.txt') -Encoding UTF8
Compress-Archive -Path (Join-Path $out 'LabGuard-Jogos.exe'),(Join-Path $out 'LabGuardTecnico.exe'),(Join-Path $out 'LabGuard_Guia_Rapido_2.5.pdf'),(Join-Path $out 'LEIA-ME.md'),(Join-Path $out 'VERIFICACAO.txt'),(Join-Path $out 'TESTE_INSTALACAO.txt'),(Join-Path $out 'CATALOGO_COMPLETO.json'),(Join-Path $out 'SHA256SUMS.txt') -DestinationPath (Join-Path $out 'LabGuard-Automatico-2.5-Windows.zip') -Force
$global:LASTEXITCODE=0
