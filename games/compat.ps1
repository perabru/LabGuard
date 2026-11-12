# PowerShell 5.1 emits JSON arrays as a single pipeline object. Normalize explicitly.
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'dist\Engine.assembled.ps1'
$text=[IO.File]::ReadAllText($path)
$before='$owned=@(Get-Content -LiteralPath $state -Raw -Encoding UTF8|ConvertFrom-Json)'
$after='$parsed=ConvertFrom-Json -InputObject (Get-Content -LiteralPath $state -Raw -Encoding UTF8);$owned=@($parsed)'
if([regex]::Matches($text,[regex]::Escape($before)).Count -ne 1){throw 'Expected exactly one owned-policy JSON reader.'}
$text=$text.Replace($before,$after)
[IO.File]::WriteAllText($path,$text,(New-Object Text.UTF8Encoding($true)))
