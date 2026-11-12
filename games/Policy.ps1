# Defensive policy overrides, assembled AFTER helper definitions and BEFORE entrypoint.
# This file is embedded into the EXE by build.ps1; not loaded from a writable runtime path.
function Add-Target([string]$Path,[string]$Reason,[switch]$Manual) {
    $p=Normalize $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { return }
    # Registry identity for a launcher must never imply deletion of its whole shared library.
    if (-not $Manual -and $Reason.StartsWith('Instalacao reconhecida: ') -and ((Split-Path $p -Leaf) -match '^(?i:Steam|SteamLibrary|Epic Games)$')) {
        Log 'INFO' ('Biblioteca compartilhada preservada; launcher e jogos sao tratados separadamente: '+$p); return
    }
    if (-not (Safe-Target $p -Manual:$Manual)) { Log 'PENDENTE' ('Pasta protegida, compartilhada ou link: '+$p); return }
    $script:Targets[$p]=[pscustomobject]@{Path=$p; Reason=$Reason; Manual=[bool]$Manual}
}
function Assert-NotUserWritable([string]$Path) {
    $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $writes=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $a=Get-Acl -LiteralPath $Path
    $owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $allowed) { throw ('Pasta/arquivo administrativo tem proprietario inesperado. Corrija como administrador antes de instalar: '+$Path) }
    foreach($rule in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -eq 'Allow' -and (($rule.FileSystemRights -band $writes) -ne 0) -and $rule.IdentityReference.Value -notin $allowed -and $rule.IdentityReference.Value -ne 'S-1-3-0') {
            throw ('Caminho administrativo preexistente permite escrita de usuarios. Instalacao recusada para seguranca: '+$Path)
        }
    }
}
function Secure-Directory([string]$Path) {
    if (-not (No-Link $Path)) { throw ('Link/junction recusado: '+$Path) }
    if (Test-Path -LiteralPath $Path) { Assert-NotUserWritable $Path }
    else { New-Item -ItemType Directory -Path $Path -ErrorAction Stop|Out-Null }
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($spec in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))) {
        $sid=New-Object Security.Principal.SecurityIdentifier($spec[0]); $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$spec[1],'ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'))); Set-Acl -LiteralPath $Path -AclObject $acl
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Force)) {
        if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Link recusado na instalacao: '+$f.FullName) }
        Assert-NotUserWritable $f.FullName
    }
}
