param(
    [Parameter(Mandatory = $true)][string]$OldSetup,
    [Parameter(Mandatory = $true)][string]$NewSetup,
    [Parameter(Mandatory = $true)][string]$InstallDir
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw "A validacao exige Windows PowerShell 5.1."
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$helper = Join-Path $projectRoot "labguard\update_helpers\apply_windows.ps1"
$tokens = $null
$parseErrors = $null
# Parse the exact shipped helper without executing it during syntax validation.
[System.Management.Automation.Language.Parser]::ParseFile(
    $helper, [ref]$tokens, [ref]$parseErrors
) | Out-Null
if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
    throw ("Sintaxe invalida no auxiliar; linha {0}." -f $parseErrors[0].Extent.StartLineNumber)
}
Write-Output "PASS: auxiliar passou no parser PowerShell 5.1, sem execucao na fase de parser."

Push-Location -LiteralPath $projectRoot
try {
    & python packaging/validate_updater_windows.py --old-setup $OldSetup --new-setup $NewSetup --install-dir $InstallDir
    if ($LASTEXITCODE -ne 0) { throw "A validacao nativa da atualizacao falhou." }
} finally {
    Pop-Location
}
