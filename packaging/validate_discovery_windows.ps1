$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

# Parse the exact packaged collector strings. Parsing does not execute them.
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $jsonLines = & python -c 'import json; from labguard.discovery import WINDOWS_SCRIPT, CIM_SCRIPT; print(json.dumps(dict(WINDOWS_SCRIPT=WINDOWS_SCRIPT, CIM_SCRIPT=CIM_SCRIPT), ensure_ascii=True))'
    if ($LASTEXITCODE -ne 0) { throw "Nao foi possivel importar os coletores locais." }
    $scripts = ($jsonLines -join "`n") | ConvertFrom-Json
    foreach ($name in @("WINDOWS_SCRIPT", "CIM_SCRIPT")) {
        $entry = $scripts.PSObject.Properties[$name]
        if ($null -eq $entry -or -not ($entry.Value -is [string])) {
            throw "Coletor ausente ou invalido para validacao."
        }
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseInput(
            [string]$entry.Value, [ref]$tokens, [ref]$parseErrors
        ) | Out-Null
        if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
            throw ("Sintaxe invalida em {0}; linha {1}." -f $name, $parseErrors[0].Extent.StartLineNumber)
        }
    }
    Write-Output "PASS: os dois coletores passaram no parser PowerShell, sem execucao."

    # A separate Python process exercises only local CIM/ARP reads on this runner.
    & python packaging/validate_discovery_windows.py
    if ($LASTEXITCODE -ne 0) { throw "A validacao nativa da leitura alternativa falhou." }
} finally {
    Pop-Location
}
