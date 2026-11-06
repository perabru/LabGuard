param([string]$Version = "1.3.0", [switch]$SkipInstaller)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw "Gere o executável em um Windows x64." }
python packaging/make_assets.py
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar os recursos visuais." }

$arguments = @("--noconfirm", "--clean", "--onedir", "--windowed", "--noupx", "--name", "LabGuard", "--icon", "packaging/generated/LabGuard.ico", "--version-file", "packaging/windows-version.txt", "--add-data", "gateway/ai_services.json:gateway", "--add-data", "docs:docs", "--add-data", "README.md:.", "--collect-submodules", "labguard")
if (Test-Path "labguard/assets") { $arguments += @("--add-data", "labguard/assets:labguard/assets") }
$arguments += "main.py"
python -m PyInstaller @arguments
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou." }

$bundle = Join-Path $projectRoot "dist/LabGuard"
Copy-Item "packaging/LEIA-ME.html" (Join-Path $bundle "LEIA-ME.html") -Force
Copy-Item "docs" (Join-Path $bundle "docs") -Recurse -Force
Copy-Item "README.md" (Join-Path $bundle "README.md") -Force
New-Item -ItemType Directory -Force "dist/release" | Out-Null
if (-not $SkipInstaller) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1
    if (-not $compiler) {
        $candidates = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 7\ISCC.exe")
        $compiler = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $compiler) { throw "Inno Setup não encontrado. Instale-o antes de gerar o instalador." }
    & $compiler "/DAppVersion=$Version" "packaging/installer.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup falhou." }
}

$portable = Join-Path $projectRoot "dist/release/LabGuard-Portable.zip"
if (Test-Path $portable) { Remove-Item $portable }
Compress-Archive -Path $bundle -DestinationPath $portable -CompressionLevel Optimal
$hashes = Get-ChildItem "dist/release" -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
    "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
}
$hashes | Set-Content "dist/release/SHA256SUMS.txt" -Encoding ascii
Get-ChildItem "dist/release" -File | Select-Object Name, Length
