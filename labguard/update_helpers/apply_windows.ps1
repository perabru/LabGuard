# Fixed, packaged helper. This script does not download, elevate, kill or restart.
param([Parameter(Mandatory = $true)][string]$MetadataPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$receiptPath = $null
$targetVersion = $null
$installerStream = $null
$parentHandle = [IntPtr]::Zero

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace LabGuardUpdate {
 public static class Native {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetDriveType(string root);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref uint length);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
  [StructLayout(LayoutKind.Sequential)] public struct FileInfo {
   public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
   public System.Runtime.InteropServices.ComTypes.FILETIME Access; public System.Runtime.InteropServices.ComTypes.FILETIME Write;
   public uint VolumeSerial; public uint SizeHigh; public uint SizeLow; public uint Links; public uint IndexHigh; public uint IndexLow;
  }
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(IntPtr file, out FileInfo info);
 }
}
'@

function Safe-Path([string]$Path) {
 if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[\x00-\x1f"]' -or $Path.StartsWith('\\')) { throw 'PATH' }
 $full = [IO.Path]::GetFullPath($Path)
 if (-not [IO.Path]::IsPathRooted($Path) -or [LabGuardUpdate.Native]::GetDriveType([IO.Path]::GetPathRoot($full)) -ne 3) { throw 'LOCAL_PATH' }
 $cursor = $full
 while ($cursor) {
  if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
   if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE' }
  }
  $next = [IO.Path]::GetDirectoryName($cursor)
  if ($next -eq $cursor) { break }
  $cursor = $next
 }
 return $full.TrimEnd('\')
}
function Same-Path([string]$Left, [string]$Right) {
 return [string]::Equals((Safe-Path $Left), (Safe-Path $Right), [StringComparison]::OrdinalIgnoreCase)
}
function Private-Acl([string]$Path) {
 $acl = Get-Acl -LiteralPath $Path
 $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $allowed = @($current, 'S-1-5-18', 'S-1-5-32-544')
 if (-not $acl.AreAccessRulesProtected -or $allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'ACL' }
 foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
  if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'ACL' }
 }
}
function Set-PrivateFile([string]$Path) {
 $acl = New-Object Security.AccessControl.FileSecurity
 $acl.SetAccessRuleProtection($true, $false)
 $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
 foreach ($sid in @($current, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $Path -AclObject $acl
}
function Receipt([string]$State, [string]$Code) {
 if ($null -eq $receiptPath -or $null -eq $targetVersion) { return }
 try {
  [void](Safe-Path $receiptPath)
  $temporary = Join-Path ([IO.Path]::GetDirectoryName($receiptPath)) ('result-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  $json = @{ app_id='br.perabru.labguard.desktop'; version=$targetVersion; state=$State; code=$Code } | ConvertTo-Json -Compress
  [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
  Set-PrivateFile $temporary
  if ([IO.File]::Exists($receiptPath)) { [IO.File]::Delete($receiptPath) }
  [IO.File]::Move($temporary, $receiptPath)
 } catch { }
}
function File-Hash([string]$Path) {
 $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
 $sha = [Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
 finally { $sha.Dispose(); $stream.Dispose() }
}
function Version-Matches([string]$Path, [string]$Expected) {
 $actual = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
 return ($actual -eq $Expected -or $actual -eq ($Expected + '.0'))
}

try {
 $metadataFile = Safe-Path $MetadataPath
 $stage = Safe-Path ([IO.Path]::GetDirectoryName($metadataFile))
 $ownPath = Safe-Path $PSCommandPath
 if ([IO.Path]::GetFileName($metadataFile) -cne 'apply.json' -or [IO.Path]::GetFileName($ownPath) -cne 'apply_windows.ps1' -or -not (Same-Path ([IO.Path]::GetDirectoryName($ownPath)) $stage)) { throw 'NAMES' }
 Private-Acl $stage; Private-Acl $metadataFile; Private-Acl $ownPath
 if ((Get-Item -LiteralPath $metadataFile).Length -gt 65536 -or (Get-Item -LiteralPath $ownPath).Length -gt 65536) { throw 'SIZE' }
 $m = [IO.File]::ReadAllText($metadataFile) | ConvertFrom-Json
 if ($m.schema -ne 1 -or $m.app_id -cne 'br.perabru.labguard.desktop' -or $m.consent -isnot [bool] -or -not $m.consent) { throw 'IDENTITY' }
 if ($m.version -isnot [string] -or $m.version -cnotmatch '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$') { throw 'VERSION' }
 foreach ($part in $m.version.Split('.')) { if ([int]$part -gt 65535) { throw 'VERSION' } }
 if ($m.sha256 -isnot [string] -or $m.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $m.helper_sha256 -isnot [string] -or $m.helper_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'HASH' }
 if (($m.size -isnot [long] -and $m.size -isnot [int]) -or $m.size -le 0 -or $m.size -gt 157286400 -or ($m.parent_pid -isnot [long] -and $m.parent_pid -isnot [int]) -or $m.parent_pid -le 0 -or $m.parent_pid -gt 2147483647) { throw 'NUMBERS' }
 if ((File-Hash $ownPath) -cne $m.helper_sha256) { throw 'HELPER_HASH' }
 $installer = Safe-Path $m.installer
 $installDir = Safe-Path $m.install_dir
 $parentExe = Safe-Path $m.parent_executable
 if (-not (Same-Path $installer (Join-Path $stage 'installer.exe')) -or -not (Same-Path $parentExe (Join-Path $installDir 'LabGuard.exe'))) { throw 'PAYLOAD_PATH' }
 $perUser = $false
 foreach ($root in @([Environment]::GetFolderPath('UserProfile'), [Environment]::GetFolderPath('LocalApplicationData'))) {
  if ($root -and $installDir.StartsWith(((Safe-Path $root) + '\'), [StringComparison]::OrdinalIgnoreCase)) { $perUser = $true }
 }
 if (-not $perUser -or -not [IO.File]::Exists($parentExe)) { throw 'PER_USER' }
 $registered = $false
 foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
  $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
  try {
   $key = $baseKey.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall\{84474208-6606-4F7A-A421-EDC4FF33948C}_is1')
   if ($null -ne $key) { try { $location = $key.GetValue('InstallLocation'); if ($location -is [string] -and (Same-Path $location $installDir)) { $registered = $true } } finally { $key.Dispose() } }
  } finally { $baseKey.Dispose() }
 }
 if (-not $registered) { throw 'REGISTRY' }
 Private-Acl $installer
 $targetVersion = $m.version
 $receiptPath = Join-Path $stage 'result.json'
 Receipt 'pending' 'WAITING_FOR_EXIT'
 # Keep a handle to the original process: PID reuse cannot make us close or kill anything.
 $parentHandle = [LabGuardUpdate.Native]::OpenProcess(0x101000, $false, [uint32]$m.parent_pid)
 if ($parentHandle -eq [IntPtr]::Zero) {
  if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -ne 87) { throw 'PROCESS_ACCESS' }
 } else {
  $buffer = New-Object Text.StringBuilder(32768)
  [uint32]$length = $buffer.Capacity
  if (-not [LabGuardUpdate.Native]::QueryFullProcessImageName($parentHandle, 0, $buffer, [ref]$length) -or -not (Same-Path $buffer.ToString() $parentExe)) { throw 'PROCESS_IDENTITY' }
  $wait = [LabGuardUpdate.Native]::WaitForSingleObject($parentHandle, 120000)
  if ($wait -ne 0) { Receipt 'pending' 'APPLICATION_STILL_OPEN'; exit 2 }
  [void][LabGuardUpdate.Native]::CloseHandle($parentHandle); $parentHandle = [IntPtr]::Zero
 }
 foreach ($process in @(Get-Process -Name 'LabGuard' -ErrorAction SilentlyContinue)) {
  try {
   if (-not $process.HasExited -and (Same-Path $process.Path $parentExe)) { Receipt 'pending' 'ANOTHER_INSTANCE_OPEN'; exit 2 }
  } finally { $process.Dispose() }
 }
 [void](Safe-Path $installer); [void](Safe-Path $installDir); Private-Acl $installer; Private-Acl $stage
 # Deny writes/deletion while hashing and starting the already-verified executable.
 $installerStream = [IO.File]::Open($installer, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
 $fileInfo = New-Object LabGuardUpdate.Native+FileInfo
 if (-not [LabGuardUpdate.Native]::GetFileInformationByHandle($installerStream.SafeFileHandle.DangerousGetHandle(), [ref]$fileInfo) -or $fileInfo.Links -ne 1 -or $installerStream.Length -ne $m.size) { throw 'INSTALLER_SIZE' }
 $sha = [Security.Cryptography.SHA256]::Create()
 try { $hash = ([BitConverter]::ToString($sha.ComputeHash($installerStream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
 if ($hash -cne $m.sha256 -or -not (Version-Matches $installer $m.version)) { throw 'INSTALLER_HASH' }
 $installerStream.Position = 0
 $header = New-Object byte[] 64
 if ($installerStream.Read($header, 0, 64) -ne 64 -or $header[0] -ne 77 -or $header[1] -ne 90) { throw 'INSTALLER_TYPE' }
 $offset = [BitConverter]::ToUInt32($header, 60)
 if ($offset -lt 64 -or $offset -ge ($installerStream.Length - 4)) { throw 'INSTALLER_TYPE' }
 $installerStream.Position = $offset
 $pe = New-Object byte[] 4
 if ($installerStream.Read($pe, 0, 4) -ne 4 -or [BitConverter]::ToUInt32($pe, 0) -ne 17744) { throw 'INSTALLER_TYPE' }
 # Explicitly disable Inno's application closing/restarting behavior in silent mode.
 $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/SP-', '/NORESTART', '/NOCLOSEAPPLICATIONS', '/NORESTARTAPPLICATIONS', ('/DIR="' + $installDir + '"'))
 $startInfo = New-Object Diagnostics.ProcessStartInfo
 $startInfo.FileName = $installer
 $startInfo.Arguments = $arguments -join ' '
 $startInfo.UseShellExecute = $false
 $startInfo.CreateNoWindow = $true
 $child = [Diagnostics.Process]::Start($startInfo)
 try { $child.WaitForExit(); $exitCode = $child.ExitCode } finally { $child.Dispose() }
 if ($exitCode -eq 3010) { Receipt 'restart_required' 'INSTALLER_RESTART_REQUESTED'; exit 3 }
 if ($exitCode -ne 0) { Receipt 'failed' 'INSTALLER_FAILED'; exit 4 }
 if (-not (Version-Matches $parentExe $m.version)) { Receipt 'failed' 'INSTALLED_VERSION_MISMATCH'; exit 5 }
 Receipt 'applied' 'OK'
 exit 0
} catch {
 Receipt 'failed' 'VALIDATION_FAILED'
 exit 1
} finally {
 if ($null -ne $installerStream) { $installerStream.Dispose() }
 if ($parentHandle -ne [IntPtr]::Zero) { [void][LabGuardUpdate.Native]::CloseHandle($parentHandle) }
}
