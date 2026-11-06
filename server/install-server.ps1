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

$administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
$system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$localService = [Security.Principal.SecurityIdentifier]::new("S-1-5-19")

function Assert-NoReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Links, junctions e outros reparse points não são permitidos: $current"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Get-ManagedTree([string]$Path) {
    Assert-NoReparsePath $Path
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        Get-Item -LiteralPath $current -Force
        foreach ($child in @(Get-ChildItem -LiteralPath $current -Force)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A instalação não pode conter links ou junctions: $($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) } else { $child }
        }
    }
}

function Set-ExactAcl([string]$Path, [string]$ServiceAccess) {
    Assert-NoReparsePath $Path
    $item = Get-Item -LiteralPath $Path -Force
    $inherit = [Security.AccessControl.InheritanceFlags]::None
    if ($item.PSIsContainer) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
    }
    # DACL nova: nenhuma ACE explícita de Everyone/Users é preservada.
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in @($administrators, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    if ($ServiceAccess -ne "None") {
        $rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
        $serviceInherit = $inherit
        if ($ServiceAccess -eq "Read") {
            if (-not $item.PSIsContainer) { $rights = [Security.AccessControl.FileSystemRights]::Read }
            # Novos arquivos, inclusive tokens criados por init, nascem privados
            # para Administradores/SYSTEM. Leitura é concedida a cada arquivo.
            $serviceInherit = [Security.AccessControl.InheritanceFlags]::None
        } elseif ($ServiceAccess -eq "Modify") {
            $rights = [Security.AccessControl.FileSystemRights]::Modify
        }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($localService, $rights, $serviceInherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ManagedTreeAcl([string]$Path, [string]$Kind) {
    # Inspecione toda a árvore antes de alterar permissões. A enumeração manual
    # recusa reparse points sem atravessar diretórios externos ao pacote.
    $items = @(Get-ManagedTree $Path)
    foreach ($item in $items) {
        $access = "ReadExecute"
        if ($Kind -eq "config") {
            $access = "Read"
            $relative = $item.FullName.Substring($Path.Length).TrimStart('\')
            if ($relative -eq "access-tokens.txt") { $access = "None" }
            if ($relative -match '^(logs|data)(\\|$)') { $access = "Modify" }
        }
        Set-ExactAcl $item.FullName $access
    }
}

$Directory = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
foreach ($path in @($Directory, $InstallDirectory)) {
    if ($path -notmatch '^[A-Za-z]:\\.+') { throw "Use um diretório local dedicado ao LabGuard, fora da raiz do volume." }
    foreach ($shared in @($env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot, $env:USERPROFILE, $env:TEMP)) {
        if ($shared -and [IO.Path]::GetFullPath($shared).TrimEnd('\') -eq $path) { throw "Use uma subpasta dedicada, sem alterar permissões de uma pasta compartilhada do sistema." }
    }
    Assert-NoReparsePath $path
}
if ($Directory -eq $InstallDirectory -or $Directory.StartsWith($InstallDirectory + '\', [StringComparison]::OrdinalIgnoreCase) -or $InstallDirectory.StartsWith($Directory + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Separe os diretórios de instalação e configuração."
}
$sourceExecutable = (Resolve-Path -LiteralPath $Executable).Path
if ([IO.Path]::GetFileName($sourceExecutable) -ne "LabGuardServer.exe") { throw "Use o executável LabGuardServer.exe do pacote de servidor." }
$sourceDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $sourceExecutable)).TrimEnd('\')
$null = @(Get-ManagedTree $sourceDirectory)
if ($sourceDirectory -ne $InstallDirectory -and ($InstallDirectory.StartsWith($sourceDirectory + '\', [StringComparison]::OrdinalIgnoreCase) -or $sourceDirectory.StartsWith($InstallDirectory + '\', [StringComparison]::OrdinalIgnoreCase))) {
    throw "O destino de instalação não pode conter o pacote de origem nem ficar dentro dele."
}
New-Item -ItemType Directory -Force $InstallDirectory | Out-Null
Set-ManagedTreeAcl $InstallDirectory "application"
if ([IO.Path]::GetFullPath($sourceDirectory).TrimEnd('\') -ne [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')) {
    Get-ChildItem -LiteralPath $sourceDirectory -Force | Copy-Item -Destination $InstallDirectory -Recurse -Force
}
Set-ManagedTreeAcl $InstallDirectory "application"
$installedExecutable = Join-Path $InstallDirectory "LabGuardServer.exe"
New-Item -ItemType Directory -Force $Directory | Out-Null
# Restrinja antes de gerar segredos; arquivos novos não herdam leitura do serviço.
Set-ManagedTreeAcl $Directory "config"
if (-not (Test-Path -LiteralPath (Join-Path $Directory "config.json"))) {
    & $installedExecutable init --directory $Directory
    if ($LASTEXITCODE -ne 0) { throw "Não foi possível criar a configuração local." }
}
$logs = Join-Path $Directory "logs"
New-Item -ItemType Directory -Force $logs | Out-Null
$dataDirectory = Join-Path $Directory "data"
New-Item -ItemType Directory -Force $dataDirectory | Out-Null
Set-ManagedTreeAcl $Directory "config"
$tokens = Join-Path $Directory "access-tokens.txt"
$command = '"' + $installedExecutable + '" run --service --directory "' + $Directory + '"'
if ($Demo) { $command += " --demo" }
# API gerenciada preserva as aspas também no Windows PowerShell 5.1.
$emptyPassword = [Security.SecureString]::new()
try {
    $credential = [Management.Automation.PSCredential]::new('NT AUTHORITY\LocalService', $emptyPassword)
    New-Service -Name LabGuardServer -BinaryPathName $command -StartupType Automatic -Credential $credential -DisplayName 'LabGuard Server' -Description 'Administração local autenticada da rede e de equipamentos compatíveis.' | Out-Null
} finally {
    $emptyPassword.Dispose()
}
$registeredCommand = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LabGuardServer' -Name ImagePath).ImagePath
if ($registeredCommand -cne $command) {
    & sc.exe delete LabGuardServer | Out-Null
    throw "O serviço não preservou o comando esperado. O registro foi removido; confira os caminhos."
}
if ($Start) {
    Start-Service LabGuardServer
    Write-Output "Serviço iniciado. Acesse http://127.0.0.1:8765/ no servidor."
} else {
    Write-Output "Serviço instalado, sem iniciar. O modo observação pode iniciar sem roteador configurado. Para controle, configure um equipamento compatível; depois use Start-Service LabGuardServer."
}
Write-Output "Credenciais locais: $tokens (não compartilhe o conteúdo)."
if ($Demo) { Write-Output "DEMONSTRAÇÃO EXPLÍCITA: dados fictícios; nenhuma regra é aplicada à rede." }
