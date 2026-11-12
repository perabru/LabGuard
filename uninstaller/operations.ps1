# Static operations used only by the explicit LabGuard uninstaller. Payload is JSON data.
$ErrorActionPreference='Stop'
$notes=New-Object 'System.Collections.Generic.List[object]'
$exeNames=@('LabGuard.exe','LabGuard-Jogos.exe','LabGuardCliente.exe','LabGuardTecnico.exe','LabGuardServer.exe')
$taskNames=@('LabGuard-RemoverJogos','LabGuard-Jogos2-Limpeza','LabGuard-Jogos2-Monitor','LabGuardCliente','LabGuardCentral')
$runNames=@('LabGuard','LabGuardJogos2','LabGuardCliente','LabGuardCentral','LabGuardServer')
$uninstallIds=@('{84474208-6606-4F7A-A421-EDC4FF33948C}_is1','LabGuardJogos2','LabGuardCliente','LabGuardCentral','LabGuardServer')
function Note([bool]$Ok,[string]$Message){$notes.Add([pscustomobject]@{ok=$Ok;message=$Message})}
function No-Link([string]$Path){
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')){return $false}
    try{$p=[IO.Path]::GetFullPath($Path);while($p -and $p.Length -gt 3){if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){return $false}};$p=[IO.Path]::GetDirectoryName($p)};return $true}catch{return $false}
}
function Owned-Path([string]$Path){
    if(-not $Path){return $false}
    try{$p=[IO.Path]::GetFullPath($Path);foreach($r in @($LGU.roots)){$root=[string]$r.path;if($p.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){return $true}}}catch{}
    return $false
}
function Owned-Task($Task){
    if($taskNames -notcontains $Task.TaskName){return $false}
    foreach($a in $Task.Actions){
        if($exeNames -contains [IO.Path]::GetFileName(([string]$a.Execute).Trim('"'))){return $true}
        if(([string]$a.Arguments) -match '(?i)LabGuardCore\.ps1|LabGuard_Remover_Jogos\.bat|LabGuardCliente\.py'){return $true}
    }
    return $false
}
function Owned-Process($Process){
    if(-not $Process.ExecutablePath){return $false}
    if($exeNames -contains $Process.Name){
        if(Owned-Path $Process.ExecutablePath){return $true}
        try{$v=[Diagnostics.FileVersionInfo]::GetVersionInfo($Process.ExecutablePath);if($v.ProductName -match '^LabGuard(?: |$)' -or $v.CompanyName -eq 'LabGuard'){return $true}}catch{}
    }
    if($Process.Name -match '^(pythonw?|powershell)\.exe$' -and ([string]$Process.CommandLine) -match '(?i)LabGuardCore\.ps1|LabGuardCliente\.py'){
        foreach($r in @($LGU.roots)){if(([string]$Process.CommandLine).IndexOf([string]$r.path,[StringComparison]::OrdinalIgnoreCase) -ge 0){return $true}}
    }
    return $false
}
function Get-Tasks {return @(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -match '^LabGuard(?:$|[-_]|Cliente|Central)'})}
function Get-Services {return @(Get-CimInstance Win32_Service -Filter "Name LIKE 'LabGuard%'" -ErrorAction Stop)}
function Get-Processes {return @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {Owned-Process $_})}
function Owned-Service($Service){return $Service.Name -eq 'LabGuardServer' -and ([string]$Service.PathName) -match '(?i)^"[^"\r\n]+\\LabGuardServer\.exe"\s+run\s+--service(?:\s|$)'}
function Cleanup-Hive([string]$Hive){
    foreach($runSuffix in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')){
        $path=$Hive+'\'+$runSuffix
        if(-not(Test-Path -LiteralPath $path)){continue}
        $key=Get-Item -LiteralPath $path
        foreach($name in @($key.GetValueNames())){
            if($runNames -notcontains $name){continue}
            $value=[string]$key.GetValue($name)
            if($value -notmatch '(?i)LabGuard(?:[-\w]*\.(?:exe|py)|Jogos2|Cliente|Central|Server)') {Note $false ('Inicializacao com nome coincidente preservada: '+$name);continue}
            Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
            Note $true ('Inicializacao removida: '+$name)
        }
        $key.Close()
    }
    foreach($suffix in @('Software\Microsoft\Windows\CurrentVersion\Uninstall','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
        $base=$Hive+'\'+$suffix
        if(-not(Test-Path -LiteralPath $base)){continue}
        foreach($key in @(Get-ChildItem -LiteralPath $base)){
            if($uninstallIds -notcontains $key.PSChildName){$key.Close();continue}
            $name=[string]$key.GetValue('DisplayName')
            if($name -notmatch '^LabGuard(?:\s|$)'){$key.Close();continue}
            $path=$key.PSPath;$key.Close()
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            Note $true ('Cadastro desinstalado: '+$name)
        }
    }
}
switch([string]$LGU.mode){
    'Inventory' {
        $tasks=@(Get-Tasks|Select-Object TaskName,TaskPath,State)
        $services=@(Get-Services|Select-Object Name,PathName,State)
        $processes=@(Get-Processes|Select-Object Name,ProcessId)
        $installed=@()
        foreach($root in @('Registry::HKEY_LOCAL_MACHINE','Registry::HKEY_CURRENT_USER')){
            foreach($s in @('Software\Microsoft\Windows\CurrentVersion\Uninstall','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
                foreach($id in $uninstallIds){$p=$root+'\'+$s+'\'+$id;if(Test-Path -LiteralPath $p){$k=Get-Item -LiteralPath $p;$loc=[string]$k.GetValue('InstallLocation');if($loc){$installed+=@{path=$loc;name=[string]$k.GetValue('DisplayName')}};$k.Close()}}
            }
        }
        @{tasks=@($tasks);services=@($services);processes=@($processes);installed=@($installed)}|ConvertTo-Json -Depth 6 -Compress
        break
    }
    'Stop' {
        $all=@(Get-CimInstance Win32_Process)
        $owned=@{};foreach($p in $all){if(Owned-Process $p){$owned[[int]$p.ProcessId]=$p}}
        # Capture children before stopping tasks. MSI and system brokers are never terminated.
        for($round=0;$round -lt 6;$round++){
            foreach($p in $all){if($owned.ContainsKey([int]$p.ParentProcessId) -and $p.Name -in @('powershell.exe','python.exe','pythonw.exe','LabGuard-Jogos.exe','LabGuardCliente.exe','LabGuardTecnico.exe','LabGuardServer.exe','LabGuard.exe')){$owned[[int]$p.ProcessId]=$p}}
        }
        foreach($t in @(Get-Tasks)){
            try{
                if(-not(Owned-Task $t)){throw ('Tarefa nao reconhecida, preservada: '+$t.TaskName)}
                Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath|Out-Null
                Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false
                Note $true ('Tarefa removida: '+$t.TaskName)
            }catch{Note $false $_.Exception.Message}
        }
        foreach($s in @(Get-Services)){
            try{
                if(-not(Owned-Service $s)){throw ('Servico nao reconhecido, preservado: '+$s.Name)}
                Set-Service -Name $s.Name -StartupType Disabled
                $svc=Get-Service -Name $s.Name
                if($svc.Status -ne 'Stopped'){Stop-Service -Name $s.Name -Force; $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))}
                $answer=& "$env:SystemRoot\System32\sc.exe" delete $s.Name 2>&1
                if($LASTEXITCODE -ne 0){throw ('Servico nao removido: '+$s.Name)}
                Note $true ('Servico removido: '+$s.Name)
            }catch{Note $false $_.Exception.Message}
        }
        Start-Sleep -Milliseconds 650
        foreach($p in @($owned.Values|Sort-Object CreationDate -Descending)){
            try{
                $fresh=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$p.ProcessId)
                if(-not $fresh){continue}
                if($fresh.CreationDate -ne $p.CreationDate -or $fresh.ExecutablePath -ne $p.ExecutablePath){continue}
                $result=Invoke-CimMethod -InputObject $fresh -MethodName Terminate
                if($result.ReturnValue -ne 0){throw ('Processo nao encerrado: '+$p.Name)}
                Note $true ('Processo encerrado: '+$p.Name)
            }catch{Note $false $_.Exception.Message}
        }
        ConvertTo-Json -InputObject @($notes.ToArray()) -Depth 5 -Compress
        break
    }
    'Firewall' {
        foreach($rule in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)){
            $owned=([string]$rule.Name -match '^LabGuard(?:[-_]|Central-)' -or [string]$rule.Group -in @('LabGuard','LabGuard Central'))
            if(-not $owned -and [string]$rule.DisplayName -match '^LabGuard(?:\s|$)'){
                $app=$rule|Get-NetFirewallApplicationFilter
                $owned=Owned-Path ([string]$app.Program)
            }
            if($owned){try{Remove-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore;Note $true ('Regra removida: '+$rule.DisplayName)}catch{Note $false $_.Exception.Message}}
        }
        ConvertTo-Json -InputObject @($notes.ToArray()) -Depth 5 -Compress
        break
    }
    'Registry' {
        Cleanup-Hive 'Registry::HKEY_LOCAL_MACHINE'
        $processed=@{}
        foreach($profile in @($LGU.profiles)){
            $sid=[string]$profile.sid;$hive='Registry::HKEY_USERS\'+$sid;$mount=$null
            try{
                if($sid -notmatch '^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$'){throw 'SID de perfil invalido.'}
                if(-not(Test-Path -LiteralPath $hive)){
                    $file=Join-Path ([string]$profile.path) 'NTUSER.DAT'
                    if(-not(Test-Path -LiteralPath $file)){continue}
                    if(-not(No-Link $file)){throw 'Hive de perfil com link recusado.'}
                    $mount='LabGuardUninstall-'+[guid]::NewGuid().ToString('N')
                    $null=& "$env:SystemRoot\System32\reg.exe" load ('HKU\'+$mount) $file 2>&1
                    if($LASTEXITCODE -ne 0){$mount=$null;throw ('Perfil nao pode ser aberto: '+[string]$profile.path)}
                    $hive='Registry::HKEY_USERS\'+$mount
                }
                Cleanup-Hive $hive;$processed[$sid]=$true
            }catch{Note $false $_.Exception.Message}
            finally{
                if($mount){[GC]::Collect();[GC]::WaitForPendingFinalizers();$null=& "$env:SystemRoot\System32\reg.exe" unload ('HKU\'+$mount) 2>&1;if($LASTEXITCODE -ne 0){Note $false ('Hive temporario pendente de fechamento: '+$mount+'; reinicie o Windows.')}}
            }
        }
        $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if(-not $processed.ContainsKey($current)){Cleanup-Hive 'Registry::HKEY_CURRENT_USER'}
        # Delete only empty backup containers. Never discard an unresolved network journal.
        $network='HKLM:\SOFTWARE\LabGuard\NetworkDNS'
        if(Test-Path -LiteralPath $network){foreach($k in @(Get-ChildItem -LiteralPath $network)){if($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0){$path=$k.PSPath;$k.Close();Remove-Item -LiteralPath $path}else{$k.Close()}}}
        foreach($path in @('HKLM:\SOFTWARE\LabGuard\NetworkDNS','HKLM:\SOFTWARE\LabGuard\StationDNS','HKLM:\SOFTWARE\LabGuard')){
            if(Test-Path -LiteralPath $path){$k=Get-Item -LiteralPath $path;$empty=$k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0;$k.Close();if($empty){Remove-Item -LiteralPath $path}}
        }
        ConvertTo-Json -InputObject @($notes.ToArray()) -Depth 5 -Compress
        break
    }
    'Shortcuts' {
        $shell=New-Object -ComObject WScript.Shell
        $locations=@((Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Windows\Start Menu\Programs'),[Environment]::GetFolderPath('CommonDesktopDirectory'))
        foreach($p in @($LGU.profiles)){$locations+=Join-Path ([string]$p.path) 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs';$locations+=Join-Path ([string]$p.path) 'Desktop'}
        foreach($loc in @($locations|Sort-Object -Unique)){
            if(-not $loc -or -not(Test-Path -LiteralPath $loc) -or -not(No-Link $loc)){continue}
            $scan=@($loc,(Join-Path $loc 'Startup'),(Join-Path $loc 'LabGuard'))
            foreach($dir in $scan){
                if(-not(Test-Path -LiteralPath $dir) -or -not(No-Link $dir)){continue}
                foreach($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -File)){
                    if($file.BaseName -notmatch '^LabGuard' -and (Split-Path $dir -Leaf) -ne 'LabGuard'){continue}
                    try{
                        if(-not(No-Link $file.FullName)){throw 'Atalho em link recusado.'}
                        $link=$shell.CreateShortcut($file.FullName);$target=[string]$link.TargetPath
                        if(Owned-Path $target){Remove-Item -LiteralPath $file.FullName -Force;Note $true ('Atalho removido: '+$file.Name)}
                    }catch{Note $false $_.Exception.Message}
                }
                if((Split-Path $dir -Leaf) -eq 'LabGuard' -and @(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0){Remove-Item -LiteralPath $dir}
            }
        }
        ConvertTo-Json -InputObject @($notes.ToArray()) -Depth 5 -Compress
        break
    }
    'Credentials' {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LGUCredentials {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Cred { public uint Flags,Type; public IntPtr TargetName,Comment; public long LastWritten; public uint BlobSize; public IntPtr Blob; public uint Persist,Count; public IntPtr Attributes,Alias,User; }
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CredEnumerateW(string filter,uint flags,out uint count,out IntPtr p);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CredDeleteW(string name,uint type,uint flags);
 [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
 public static int Remove(){uint n;IntPtr p;if(!CredEnumerateW("LabGuard/*",0,out n,out p)){int e=Marshal.GetLastWin32Error();if(e==1168)return 0;throw new System.ComponentModel.Win32Exception(e);}int removed=0;try{for(uint i=0;i<n;i++){IntPtr c=Marshal.ReadIntPtr(p,checked((int)i*IntPtr.Size));Cred v=(Cred)Marshal.PtrToStructure(c,typeof(Cred));string name=Marshal.PtrToStringUni(v.TargetName);if(name!=null && name.StartsWith("LabGuard/RouterOS/v1/",StringComparison.Ordinal) && v.Type==1){if(!CredDeleteW(name,v.Type,0))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());removed++;}}}finally{CredFree(p);}return removed;}
}
'@
        @{removed=[LGUCredentials]::Remove()}|ConvertTo-Json -Compress
        break
    }
    default {throw 'Operacao nao permitida.'}
}
