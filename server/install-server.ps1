param(
    [string]$Executable = (Join-Path $PSScriptRoot "..\LabGuardServer.exe"),
    [string]$Directory = (Join-Path $env:ProgramData "LabGuardServer"),
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles "LabGuardServer"),
    [switch]$Demo,
    [switch]$Start
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Execute este instalador em um PowerShell elevado." }
if (Get-Service LabGuardServer -ErrorAction SilentlyContinue) { throw "LabGuardServer já existe. Pare e atualize a instalação conforme o guia." }
$sourceExecutable = (Resolve-Path $Executable).Path
if ([IO.Path]::GetFileName($sourceExecutable) -ne "LabGuardServer.exe") { throw "Use o executável LabGuardServer.exe do pacote de servidor." }
$sourceDirectory = Split-Path -Parent $sourceExecutable
New-Item -ItemType Directory -Force $InstallDirectory | Out-Null
if ([IO.Path]::GetFullPath($sourceDirectory).TrimEnd('\') -ne [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')) {
    Get-ChildItem -LiteralPath $sourceDirectory -Force | Copy-Item -Destination $InstallDirectory -Recurse -Force
}
$installedExecutable = Join-Path $InstallDirectory "LabGuardServer.exe"
New-Item -ItemType Directory -Force $Directory | Out-Null
if (-not (Test-Path (Join-Path $Directory "config.json"))) {
    & $installedExecutable init --directory $Directory
    if ($LASTEXITCODE -ne 0) { throw "Não foi possível criar a configuração local." }
}
$Directory = [IO.Path]::GetFullPath($Directory)
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)
# SIDs não dependem do idioma do Windows. O serviço não executa como administrador.
& icacls.exe $Directory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Falha ao restringir a configuração." }
foreach ($file in @("config.json", "secrets.json")) {
    & icacls.exe (Join-Path $Directory $file) /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' '*S-1-5-19:R' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Falha ao restringir $file." }
}
$logs = Join-Path $Directory "logs"
New-Item -ItemType Directory -Force $logs | Out-Null
& icacls.exe $logs /grant:r '*S-1-5-19:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Falha ao permitir o registro do serviço." }
$dataDirectory = Join-Path $Directory "data"
New-Item -ItemType Directory -Force $dataDirectory | Out-Null
& icacls.exe $dataDirectory /grant:r '*S-1-5-19:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Falha ao permitir a gravação do banco de sites." }
$tokens = Join-Path $Directory "access-tokens.txt"
if (Test-Path $tokens) {
    & icacls.exe $tokens /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Falha ao proteger as credenciais de acesso." }
}
& icacls.exe $InstallDirectory /grant '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Falha ao permitir a execução do serviço." }
$command = '"' + $installedExecutable + '" run --service --directory "' + $Directory + '"'
if ($Demo) { $command += " --demo" }
& sc.exe create LabGuardServer binPath= $command start= auto obj= 'NT AUTHORITY\LocalService' DisplayName= 'LabGuard Server'
if ($LASTEXITCODE -ne 0) { throw "Não foi possível registrar o serviço." }
& sc.exe description LabGuardServer 'Administração local autenticada de um gateway LabGuard. Não é um firewall nativo do Windows.' | Out-Null
if ($Start) {
    Start-Service LabGuardServer
    Write-Output "Serviço iniciado. Acesse http://127.0.0.1:8765/ no servidor."
} else {
    Write-Output "Serviço instalado, sem iniciar. Preencha config.json, chave SSH e known_hosts; depois use Start-Service LabGuardServer."
}
Write-Output "Credenciais locais: $tokens (não compartilhe o conteúdo)."
if ($Demo) { Write-Output "DEMONSTRAÇÃO EXPLÍCITA: dados fictícios; nenhuma regra é aplicada à rede." }
