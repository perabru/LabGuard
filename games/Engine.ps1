param([ValidateSet('Install','Cycle','Audit','Pause','Resume','Uninstall','AddFolder','CaptureOn','CaptureOff','Status','Test')][string]$Mode='Audit')
# LabGuard Jogos 2.0.0 -- Windows PowerShell 5.1. Embedded in the signed-path launcher.
# No arbitrary registry command execution, no generic ISO deletion, no remote screenshot upload.
$ErrorActionPreference='Stop'
$Base=Join-Path $env:ProgramFiles 'LabGuardJogos2'
$Data=Join-Path $env:ProgramData 'LabGuardJogos2'
$Exe=Join-Path $Base 'LabGuard-Jogos.exe'
$ConfigPath=Join-Path $Base 'config.json'
$TaskName='LabGuard-Jogos2-Limpeza'
$script:Dry=$Mode -in @('Audit','Test')
$script:StatusPath=$null
$script:LogPath=$null
$script:Removed=0; $script:Pending=0; $script:Failures=0
$script:Started=[DateTime]::UtcNow
$script:Deadline=[DateTime]::UtcNow.AddSeconds(220)
$script:Targets=@{}; $script:Profiles=@(); $script:Protected=@(); $script:Preserved=@()
$script:Config=[pscustomobject]@{Enabled=$true; Screenshots=$false; IntervalSeconds=300; AdditionalFolders=@(); Version='2.0.0'}
$script:GamePattern='^(?:Steam(?:\s|$)|Roblox Player(?:\s|$)|Epic Games Launcher(?:\s|$)|Minecraft(?: Launcher| for Windows| Java| Bedrock| Preview|$)|TLauncher(?:\s|$)|Prism Launcher(?:\s|$)|MultiMC(?:\s|$)|Lunar Client(?:\s|$)|Badlion Client(?:\s|$)|Modrinth App(?:\s|$)|GDLauncher(?:\s|$)|ATLauncher(?:\s|$)|Dolphin(?: Emulator|\s+[0-9]|$)|RetroArch(?:\s|$)|PCSX2(?:\s|$)|RPCS3(?:\s|$)|PPSSPP(?:\s|$)|DuckStation(?:\s|$)|Cemu(?:\s|$)|Ryujinx(?:\s|$)|Yuzu(?:\s|$)|Citra(?:\s|$)|Snes9x(?:\s|$)|mGBA(?:\s|$)|DeSmuME(?:\s|$)|melonDS(?:\s|$)|VisualBoyAdvance(?:\s|\-|$)|MAME(?:\s|$)|BlueStacks(?:\s|$)|LDPlayer(?:\s|$)|Nox(?:Player|\s|$)|MEmu(?:\s|$)|MuMu Player(?:\s|$)|GameLoop(?:\s|$)|Grand Theft Auto(?:\s|$)|GTA (?:V|IV|III|San Andreas|Vice City)(?:\s|$)|Red Dead Redemption(?:\s|$)|Cyberpunk 2077(?:\s|$)|The Witcher(?:\s|$)|The Elder Scrolls(?:\s|$)|Fallout (?:3|4|76|New Vegas)(?:\s|$)|Counter-Strike(?:\s|:|$)|Counter Strike(?:\s|$)|Half-Life(?:\s|$)|Dota 2(?:\s|$)|Fortnite(?:\s|$)|Rocket League(?:\s|$)|League of Legends(?:\s|$)|VALORANT(?:\s|$)|Overwatch(?:\s|$)|World of Warcraft(?:\s|$)|Diablo (?:II|III|IV|2|3|4)(?:\s|$)|StarCraft(?:\s|$)|Call of Duty(?:\s|:|$)|Battlefield(?:\s|$)|EA SPORTS FC(?:\s|$)|FIFA [0-9]|Pro Evolution Soccer(?:\s|$)|PES [0-9]|eFootball(?:\s|$)|NBA 2K[0-9]|Need for Speed(?:\s|:|$)|Forza (?:Horizon|Motorsport)(?:\s|$)|Assetto Corsa(?:\s|$)|Euro Truck Simulator(?:\s|$)|American Truck Simulator(?:\s|$)|Resident Evil(?:\s|$)|Silent Hill(?:\s|$)|Assassin.s Creed(?:\s|$)|Far Cry(?:\s|$)|Watch Dogs(?:\s|$)|Mortal Kombat(?:\s|$)|TEKKEN(?:\s|$)|Street Fighter(?:\s|$)|Hogwarts Legacy(?:\s|$)|Elden Ring(?:\s|$)|Dark Souls(?:\s|$)|Sekiro(?:\s|$)|Terraria(?:\s|$)|Stardew Valley(?:\s|$)|Hollow Knight(?:\s|$)|Cuphead(?:\s|$)|Among Us(?:\s|$)|Brawlhalla(?:\s|$)|The Sims(?:\s|$)|Cities Skylines(?:\s|$)|Baldur.s Gate(?:\s|$)|God of War(?:\s|$)|Black Myth Wukong(?:\s|$)|Palworld(?:\s|$)|Genshin Impact(?:\s|$)|Honkai(?:\s|$))'
$script:PreservePattern='(?i)(Roblox Studio|Minecraft Education|Unreal Engine|Twinmotion|RealityCapture|RealityScan|Blender|Godot|Unity Hub|Android Studio|Visual Studio|Visual Studio Code|OBS Studio|Krita|Aseprite|GameMaker|RPG Maker|Wallpaper Engine|Steamworks|SteamVR|Windows SDK|Microsoft .NET|Microsoft Visual C\+\+)'
$script:StoreNames=@('ROBLOXCORPORATION.ROBLOX','Microsoft.MinecraftUWP','Microsoft.MinecraftWindowsBeta','Microsoft.4297127D64EC6','Microsoft.MinecraftJavaEdition')
$script:KnownExecutables=@('RobloxPlayerBeta.exe','RobloxPlayerLauncher.exe','MinecraftLauncher.exe','Minecraft.exe','TLauncher.exe','PrismLauncher.exe','MultiMC.exe','Lunar Client.exe','Badlion Client.exe','steam.exe','EpicGamesLauncher.exe','Dolphin.exe','retroarch.exe','pcsx2.exe','pcsx2-qt.exe','rpcs3.exe','PPSSPPWindows.exe','PPSSPPWindows64.exe','duckstation-qt-x64-ReleaseLTCG.exe','Cemu.exe','Ryujinx.exe','yuzu.exe','citra-qt.exe','snes9x-x64.exe','mGBA.exe','DeSmuME.exe','melonDS.exe','mame.exe','GTA5.exe','GTAIV.exe','gta_sa.exe','gta-vc.exe','RDR2.exe','Cyberpunk2077.exe','witcher3.exe','FortniteClient-Win64-Shipping.exe','RocketLeague.exe','cs2.exe','hl.exe','hl2.exe','Terraria.exe','Stardew Valley.exe','Cuphead.exe','Among Us.exe','VALORANT-Win64-Shipping.exe')
function Is-Admin { $p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Assert-Admin { if (-not (Is-Admin)) { throw 'Autorize a elevacao de administrador (UAC) para alterar a instalacao.' } }
function Normalize([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p=$Path.Replace('/','\').TrimEnd('\')
    if ($p -notmatch '^[A-Za-z]:\\' -or $p -match '[*?<>|"~\x00-\x1f]' -or $p.Substring(2).Contains(':')) { return $null }
    foreach ($part in $p.Substring(3).Split('\')) { if ($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')) { return $null } }
    try { return [IO.Path]::GetFullPath($p).TrimEnd('\') } catch { return $null }
}
function Inside([string]$Child,[string]$Parent) { if (-not $Child -or -not $Parent) { return $false }; return $Child.Equals($Parent,[StringComparison]::OrdinalIgnoreCase) -or $Child.StartsWith($Parent.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) }
function No-Link([string]$Path) {
    $p=Normalize $Path; if (-not $p) { return $false }
    try { while ($p -and $p.Length -gt 3) { if (Test-Path -LiteralPath $p) { if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false } }; $p=[IO.Path]::GetDirectoryName($p) }; return $true } catch { return $false }
}
function Log([string]$Kind,[string]$Text) {
    if ($Kind -eq 'FALHA') { $script:Failures++ }; if ($Kind -eq 'PENDENTE') { $script:Pending++ }
    $line=('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Kind,($Text -replace '[\r\n]+',' '))
    Write-Output $line
    if ($script:LogPath) { try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 } catch { $script:Failures++ } }
}
function Save-Status([string]$State,[string]$Detail) {
    if (-not $script:StatusPath) { return }
    $s=[ordered]@{version='2.0.0'; state=$State; detail=$Detail; startedUtc=$script:Started.ToString('o'); updatedUtc=[DateTime]::UtcNow.ToString('o'); removed=$script:Removed; pending=$script:Pending; failures=$script:Failures; intervalSeconds=300}
    $tmp=$script:StatusPath+'.tmp'; [IO.File]::WriteAllText($tmp,($s|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath $tmp -Destination $script:StatusPath -Force
}
function Secure-Directory([string]$Path) {
    if (-not (No-Link $Path)) { throw ('Link/junction recusado: '+$Path) }
    New-Item -ItemType Directory -Path $Path -Force|Out-Null
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($spec in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))) {
        $sid=New-Object Security.Principal.SecurityIdentifier($spec[0]); $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$spec[1],'ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'))); Set-Acl -LiteralPath $Path -AclObject $acl
    # Reject preexisting child links before any privileged writes.
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Force)) { if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Link recusado na instalacao: '+$f.FullName) } }
}
function Read-Config {
    if (Test-Path -LiteralPath $ConfigPath) {
        if (-not (No-Link $ConfigPath)) { throw 'Configuracao em link recusada.' }
        $c=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8|ConvertFrom-Json
        if ($c.Enabled -isnot [bool] -or $c.Screenshots -isnot [bool]) { throw 'Configuracao invalida; limpeza interrompida.' }
        $script:Config=$c
    }
}
function Write-Config { $script:Config|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $ConfigPath -Encoding UTF8 }
function Inventory {
    $script:Profiles=@(Get-CimInstance Win32_UserProfile|Where-Object {-not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath)}|ForEach-Object {Normalize $_.LocalPath}|Where-Object {$_})
    $script:ProgramRoots=@($env:ProgramFiles,${env:ProgramFiles(x86)})|Where-Object {$_}|Sort-Object -Unique
    $script:FixedRoots=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|ForEach-Object {$_.DeviceID+'\'})
    $script:Protected=@($env:windir,$env:ProgramData,$Base,$Data)+$script:ProgramRoots
    foreach ($profile in $script:Profiles) { $script:Protected+=$profile; foreach ($p in @('Desktop','Documents','Downloads','Pictures','Videos','Music','OneDrive','AppData','AppData\Local','AppData\Roaming','AppData\LocalLow','AppData\Local\Programs','AppData\Local\Packages','Saved Games','Documents\My Games')) { $script:Protected+=Join-Path $profile $p } }
}
function Safe-Target([string]$Path,[switch]$Manual) {
    $p=Normalize $Path; if (-not $p -or $p.Length -le 3 -or -not (No-Link $p)) { return $false }
    if ($script:FixedRoots -notcontains [IO.Path]::GetPathRoot($p)) { return $false }
    if ($p -match '(?i)\\(WindowsApps|System Volume Information|\$Recycle\.Bin|Windows|LabGuardJogos2)(\\|$)') { return $false }
    if ($p -match '(?i)\\(Documents|Desktop|Downloads|Pictures|Videos|Music|OneDrive)(\\|$)' -and -not $Manual) { return $false }
    foreach ($protected in $script:Protected) { if (Inside $protected $p) { return $false } }
    foreach ($keep in $script:Preserved) { if ((Inside $keep $p) -or (Inside $p $keep)) { return $false } }
    if ((Split-Path $p -Leaf) -match '^(?i:Games|Jogos|Emulators|Emuladores|SteamLibrary|Epic Games|GOG Games|Users|Common Files|Microsoft|Java|NVIDIA Corporation|AMD|Intel)$') { return $false }
    return $true
}
function Add-Target([string]$Path,[string]$Reason,[switch]$Manual) {
    $p=Normalize $Path; if (-not $p -or -not (Test-Path -LiteralPath $p)) { return }
    if (-not (Safe-Target $p -Manual:$Manual)) { Log 'PENDENTE' ('Pasta protegida, compartilhada ou link: '+$p); return }
    $script:Targets[$p]=[pscustomobject]@{Path=$p; Reason=$Reason; Manual=[bool]$Manual}
}
function Read-Small([string]$Path) { if (-not (No-Link $Path)) { throw 'Manifesto com link.' }; $f=Get-Item -LiteralPath $Path; if ($f.Length -gt 4194304) { throw 'Manifesto acima do limite.' }; return [IO.File]::ReadAllText($Path) }
function Matches-Game([string]$Name) { return $Name -and $Name -notmatch $script:PreservePattern -and $Name -match $script:GamePattern }
function Marker-In([string]$Path) {
    if (-not (No-Link $Path)) { return $false }
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -File -Filter '*.exe' -ErrorAction SilentlyContinue)) { if ($script:KnownExecutables -contains $f.Name) { return $true } }
    return $false
}
function Discover {
    # Machine uninstall registry only: never run user-controlled uninstall strings as SYSTEM.
    $script:Apps=@()
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($app in @(Get-ItemProperty ($key+'\*') -ErrorAction SilentlyContinue)) {
            if ($app.DisplayName -match $script:PreservePattern -and $app.InstallLocation) { $script:Preserved+=Normalize ([string]$app.InstallLocation) }
            if (Matches-Game ([string]$app.DisplayName)) { $script:Apps+=$app; if ($app.InstallLocation) { Add-Target ([string]$app.InstallLocation) ('Instalacao reconhecida: '+$app.DisplayName) } }
        }
    }
    foreach ($profile in $script:Profiles) {
        $roaming=Join-Path $profile 'AppData\Roaming'; $local=Join-Path $profile 'AppData\Local'
        foreach ($part in @('.minecraft','.tlauncher','PrismLauncher','MultiMC','ATLauncher','GDLauncher','Ryujinx','yuzu','Citra','RetroArch','modrinth-app','Lunar Client')) { Add-Target (Join-Path $roaming $part) ('Dados de jogo/emulador conhecido: '+$part) }
        foreach ($part in @('Programs\PrismLauncher','Programs\MultiMC','Programs\GDLauncher','Programs\Modrinth App','Programs\Lunar Client','Programs\Badlion Client','Programs\Ryujinx','Programs\yuzu','Programs\Citra')) { Add-Target (Join-Path $local $part) ('Instalacao por usuario: '+$part) }
        $versions=Join-Path $local 'Roblox\Versions'
        if ((Test-Path -LiteralPath $versions) -and (No-Link $versions)) {
            foreach ($dir in @(Get-ChildItem -LiteralPath $versions -Directory)) { if ((Test-Path -LiteralPath (Join-Path $dir.FullName 'RobloxPlayerBeta.exe')) -and -not (Test-Path -LiteralPath (Join-Path $dir.FullName 'RobloxStudioBeta.exe'))) { Add-Target $dir.FullName 'Roblox Player (preserva Studio)' } }
        }
    }
    $steam=@(); foreach ($root in $script:ProgramRoots) { $steam+=Join-Path $root 'Steam' }
    foreach ($key in @('HKLM:\SOFTWARE\Valve\Steam','HKLM:\SOFTWARE\WOW6432Node\Valve\Steam')) { $s=Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue; if ($s.InstallPath) { $steam+=[string]$s.InstallPath } }
    foreach ($root in $script:FixedRoots) { $steam+=Join-Path $root 'Steam'; $steam+=Join-Path $root 'SteamLibrary' }
    $libraries=@($steam)
    foreach ($root in @($steam|Sort-Object -Unique)) {
        foreach ($rel in @('steamapps\libraryfolders.vdf','config\libraryfolders.vdf')) { $file=Join-Path $root $rel; if (Test-Path -LiteralPath $file) { try { foreach ($m in [regex]::Matches((Read-Small $file),'"path"\s+"([^"\r\n]+)"')) { $libraries+=$m.Groups[1].Value.Replace('\\','\') } } catch { Log 'PENDENTE' $_.Exception.Message } } }
    }
    foreach ($lib in @($libraries|Sort-Object -Unique)) {
        if (-not (No-Link $lib)) { continue }; $apps=Join-Path $lib 'steamapps'
        foreach ($f in @(Get-ChildItem -LiteralPath $apps -Filter 'appmanifest_*.acf' -File -ErrorAction SilentlyContinue)) {
            try { $text=Read-Small $f.FullName; $dir=[regex]::Match($text,'"installdir"\s+"([^"\r\n]+)"').Groups[1].Value; $name=[regex]::Match($text,'"name"\s+"([^"\r\n]+)"').Groups[1].Value
                if ($dir -and $dir -notmatch '[\\/:*?<>|]' -and $dir -notin @('.','..')) {
                    $dest=Join-Path $apps ('common\'+$dir)
                    if ($name -match $script:PreservePattern) { $script:Preserved+=$dest; Log 'MANTIDO' ('Ferramenta educacional/criacao: '+$name) }
                    elseif (Matches-Game $name) { Add-Target $dest ('Jogo Steam: '+$name) }
                    else { Log 'PENDENTE' ('Steam: conteudo fora do catalogo; aprove a pasta para remover: '+$dest) }
                }
            } catch { Log 'PENDENTE' ('Steam: '+$_.Exception.Message) }
        }
        # Launcher only. Never delete steamapps or shared software as a side effect.
        foreach ($file in @('steam.exe','steamservice.exe','steamwebhelper.exe')) { Add-Target (Join-Path $lib $file) 'Executavel do launcher Steam' }
    }
    $man=Join-Path $env:ProgramData 'Epic\EpicGamesLauncher\Data\Manifests'
    foreach ($f in @(Get-ChildItem -LiteralPath $man -Filter '*.item' -File -ErrorAction SilentlyContinue)) {
        try { $m=Read-Small $f.FullName|ConvertFrom-Json; if ($m.DisplayName -match $script:PreservePattern) { $script:Preserved+=Normalize ([string]$m.InstallLocation) } elseif (Matches-Game ([string]$m.DisplayName)) { Add-Target ([string]$m.InstallLocation) ('Jogo Epic: '+$m.DisplayName) } else { Log 'PENDENTE' ('Epic fora do catalogo: '+$m.DisplayName+'; '+$m.InstallLocation) } } catch { Log 'PENDENTE' $_.Exception.Message }
    }
    foreach ($root in $script:ProgramRoots) {
        Add-Target (Join-Path $root 'Epic Games\Launcher') 'Epic Games Launcher'
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) { if ((Matches-Game $dir.Name) -and (Marker-In $dir.FullName)) { Add-Target $dir.FullName ('Pasta e executavel reconhecidos: '+$dir.Name) } }
    }
    # Games installed from ISO are discovered by installed identity, not by their installation medium.
    foreach ($drive in $script:FixedRoots) {
        foreach ($part in @('Games','Jogos','Emulators','Emuladores','GOG Games')) {
            $root=Join-Path $drive $part; if (-not (No-Link $root)) { continue }
            foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) { if ((Matches-Game $dir.Name) -and (Marker-In $dir.FullName)) { Add-Target $dir.FullName ('Jogo/emulador reconhecido, inclusive instalacao ISO: '+$dir.Name) } else { Log 'PENDENTE' ('Pasta nao classificada; aprovar manualmente: '+$dir.FullName) } }
        }
    }
    foreach ($path in @($script:Config.AdditionalFolders)) { if ($path -is [string]) { Add-Target $path 'Pasta exclusiva aprovada pelo administrador' -Manual } }
    # ISO files themselves are reported, not deleted merely because of their extension.
    foreach ($profile in $script:Profiles) { foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $profile 'Downloads') -Filter '*.iso' -File -ErrorAction SilentlyContinue|Select-Object -First 5)) { Log 'PENDENTE' ('ISO nao classificada (nao removida): '+$f.FullName) } }
}
function Delete-Bounded([string]$Path,[bool]$Manual) {
    if ([DateTime]::UtcNow -gt $script:Deadline) { throw 'Limite do ciclo atingido; alvo sera retomado na proxima checagem.' }
    if (-not (Safe-Target $Path -Manual:$Manual)) { throw ('Caminho protegido ou link: '+$Path) }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item=Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force)) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Link interno recusado: '+$child.FullName) }
            Delete-Bounded $child.FullName $Manual
        }
        # No recursive removal: junctions are never traversed.
        if ((No-Link $Path) -and @(Get-ChildItem -LiteralPath $Path -Force).Count -eq 0) { [IO.Directory]::Delete($Path,$false) }
    } else { if (-not (No-Link $Path)) { throw 'Link recusado.' }; [IO.File]::SetAttributes($Path,[IO.FileAttributes]::Normal); [IO.File]::Delete($Path) }
}
function Stop-TargetProcesses {
    foreach ($p in @(Get-CimInstance Win32_Process)) {
        if (-not $p.ExecutablePath -or $p.Name -match 'RobloxStudio|LabGuard') { continue }
        $target=$false
        foreach ($t in $script:Targets.Values) { if (Inside $p.ExecutablePath $t.Path) { $target=$true; break } }
        if (-not $target) { continue }
        if ($script:Dry) { Log 'SIMULACAO' ('Encerraria: '+$p.Name); continue }
        try { $fresh=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId); if ($fresh -and $fresh.ExecutablePath -eq $p.ExecutablePath) { $r=Invoke-CimMethod -InputObject $fresh -MethodName Terminate; if ($r.ReturnValue -ne 0) { throw ('Codigo '+$r.ReturnValue) }; Log 'ENCERRADO' $p.Name } } catch { Log 'FALHA' ('Processo '+$p.Name+': '+$_.Exception.Message) }
    }
}
function Uninstall-Msi {
    foreach ($app in $script:Apps) {
        if ([DateTime]::UtcNow -gt $script:Deadline) { break }
        if ($app.WindowsInstaller -ne 1 -or $app.PSChildName -notmatch '^\{[0-9a-fA-F-]{36}\}$') { continue }
        if ($script:Dry) { Log 'SIMULACAO' ('Desinstalaria MSI: '+$app.DisplayName); continue }
        try {
            $p=Start-Process -FilePath (Join-Path $env:windir 'System32\msiexec.exe') -ArgumentList @('/x',$app.PSChildName,'/qn','/norestart') -PassThru
            if (-not $p.WaitForExit(35000)) { Log 'PENDENTE' ('Windows Installer continua trabalhando: '+$app.DisplayName); $script:Deadline=[DateTime]::UtcNow; return }
            if ($p.ExitCode -in @(0,1605,1614,3010)) { Log 'DESINSTALADO' ($app.DisplayName+'; codigo '+$p.ExitCode); $script:Removed++ } else { Log 'FALHA' ('MSI '+$app.DisplayName+'; codigo '+$p.ExitCode) }
        } catch { Log 'FALHA' $_.Exception.Message }
    }
}
function Remove-Store {
    foreach ($name in $script:StoreNames) {
        foreach ($pkg in @(Get-AppxPackage -AllUsers -Name $name -ErrorAction SilentlyContinue)) {
            if ($pkg.Name -ne $name) { continue }
            if ($script:Dry) { Log 'SIMULACAO' ('Removeria pacote Store: '+$pkg.PackageFullName); continue }
            try { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop; Log 'DESINSTALADO' $pkg.Name; $script:Removed++ } catch { Log 'FALHA' ('Store '+$pkg.Name+': '+$_.Exception.Message) }
        }
    }
}
function Check-Defender {
    try {
        $mp=Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.AntivirusEnabled) { Log 'PENDENTE' 'Microsoft Defender inativo. Nenhum arquivo foi declarado seguro por esta verificacao.'; return }
        Log 'DEFENDER' ('Antivirus ativo; protecao em tempo real: '+$mp.RealTimeProtectionEnabled)
        foreach ($threat in @(Get-MpThreat -ErrorAction Stop|Where-Object {$_.IsActive})) { Log 'ALERTA' ('Ameaca ativa detectada pelo Defender: '+$threat.ThreatName) }
        $cacheFile=Join-Path $Data 'defender-cache.json'; $cache=@{}
        if (Test-Path -LiteralPath $cacheFile) { try { $obj=Get-Content -LiteralPath $cacheFile -Raw|ConvertFrom-Json; foreach ($p in $obj.PSObject.Properties) { $cache[$p.Name]=[string]$p.Value } } catch {} }
        $count=0
        foreach ($profile in $script:Profiles) {
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $profile 'Downloads') -File -ErrorAction SilentlyContinue|Where-Object {$_.Extension -in @('.exe','.msi','.scr','.dll','.bat','.cmd','.ps1','.vbs','.js','.zip','.iso')}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 8)) {
                if ($count -ge 2 -or [DateTime]::UtcNow -gt $script:Deadline) { break }
                if (-not (No-Link $f.FullName)) { continue }
                $stamp=[string]$f.Length+'|'+$f.LastWriteTimeUtc.Ticks
                if ($cache[$f.FullName] -eq $stamp) { continue }
                if ($script:Dry) { Log 'SIMULACAO' ('Solicitaria analise Defender: '+$f.FullName); $count++; continue }
                $job=Start-MpScan -ScanType CustomScan -ScanPath $f.FullName -AsJob -ErrorAction Stop
                $done=Wait-Job -Job $job -Timeout 20
                if ($done -and $job.State -eq 'Completed') { Receive-Job -Job $job -ErrorAction Stop|Out-Null; $cache[$f.FullName]=$stamp; Log 'DEFENDER' ('Analise concluida: '+$f.FullName+'; remediacao segue a politica do antivirus.') }
                else { Log 'PENDENTE' ('Analise Defender nao concluiu neste ciclo: '+$f.FullName) }
                Stop-Job -Job $job -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue; $count++
            }
        }
        if (-not $script:Dry) { if ($cache.Count -gt 200) { $cache=@{} }; $cache|ConvertTo-Json|Set-Content -LiteralPath $cacheFile -Encoding UTF8 }
    } catch { Log 'PENDENTE' ('Defender indisponivel/erro: '+$_.Exception.Message) }
}
function Register-EngineTask {
    $a=New-ScheduledTaskAction -Execute $Exe -Argument '--cycle'
    $boot=New-ScheduledTaskTrigger -AtStartup
    $logon=New-ScheduledTaskTrigger -AtLogOn
    $repeat=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger @($boot,$logon,$repeat) -Principal $principal -Settings $settings -Description 'LabGuard Jogos 2.0: verificacao de jogos a cada 5 minutos. Painel e captura visiveis na sessao do usuario.' -Force|Out-Null
}
try {
    if ($Mode -eq 'Test') {
        if (Normalize 'C:\Windows\..\Users') { throw 'Traversal aceito.' }
        if (Normalize '\\server\share') { throw 'UNC aceito.' }
        if (Normalize 'C:\Game:stream') { throw 'ADS aceito.' }
        foreach ($name in @('Steam','Roblox Player for Aluno','Epic Games Launcher','Minecraft Launcher','PCSX2 2.0','Grand Theft Auto V','FIFA 23','RetroArch')) { if (-not (Matches-Game $name)) { throw ('Catalogo nao reconhece '+$name) } }
        foreach ($name in @('Roblox Studio','Minecraft Education','Unreal Engine','Android Studio','Visual Studio Code','Microsoft Visual C++','Blender','Projeto de aula')) { if (Matches-Game $name) { throw ('Falso positivo: '+$name) } }
        Write-Output 'TESTES OK: catalogo, exclusoes educacionais, traversal, UNC e ADS.'; exit 0
    }
    if ($Mode -eq 'Status') { if (Test-Path -LiteralPath (Join-Path $Data 'status.json')) { Get-Content -LiteralPath (Join-Path $Data 'status.json') }; exit 0 }
    Assert-Admin
    if ($Mode -eq 'Install') {
        if (-not $env:LG_SOURCE_EXE -or -not [IO.File]::Exists($env:LG_SOURCE_EXE)) { throw 'Executavel de origem nao encontrado.' }
        Secure-Directory $Base; Secure-Directory $Data
        if (-not ([IO.Path]::GetFullPath($env:LG_SOURCE_EXE).Equals($Exe,[StringComparison]::OrdinalIgnoreCase))) { Copy-Item -LiteralPath $env:LG_SOURCE_EXE -Destination $Exe -Force }
        Read-Config; $script:Config.Enabled=$true; Write-Config
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LabGuardJogos2' -Value ('"'+$Exe+'" --monitor') -PropertyType String -Force|Out-Null
        $un='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LabGuardJogos2'; New-Item $un -Force|Out-Null
        foreach ($kv in @{DisplayName='LabGuard Jogos 2.0.0';DisplayVersion='2.0.0';Publisher='LabGuard - projeto de Bruno Michel Pera';InstallLocation=$Base;UninstallString=('"'+$Exe+'" --admin');DisplayIcon=$Exe}.GetEnumerator()) { New-ItemProperty -Path $un -Name $kv.Key -Value $kv.Value -PropertyType String -Force|Out-Null }
        Register-EngineTask
        # Disable the old routine only when its recorded action belongs to LabGuardJogos.
        $old=Get-ScheduledTask -TaskName 'LabGuard-RemoverJogos' -ErrorAction SilentlyContinue
        if ($old -and (($old.Actions|Out-String) -match 'LabGuardJogos|LabGuardCore')) { Disable-ScheduledTask -TaskName $old.TaskName|Out-Null; Stop-ScheduledTask -TaskName $old.TaskName -ErrorAction SilentlyContinue; Log 'INFO' 'Rotina antiga desativada para evitar duas limpezas simultaneas.' }
        Start-ScheduledTask -TaskName $TaskName
        Log 'INSTALADO' 'Tarefa SYSTEM no inicio, login e a cada 5 minutos; painel visivel no login. Capturas desligadas por padrao.'; exit 0
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { if ($Mode -ne 'Audit') { throw 'Instale pelo painel antes de usar esta acao.' } }
    Read-Config
    if ($Mode -in @('Pause','Resume','CaptureOn','CaptureOff','AddFolder','Uninstall')) {
        Secure-Directory $Base; Secure-Directory $Data
        switch ($Mode) {
            'Pause' { $script:Config.Enabled=$false; Write-Config; Disable-ScheduledTask -TaskName $TaskName|Out-Null; Log 'PAUSADO' 'A limpeza ativa conclui a operacao corrente; novos alvos nao serao iniciados.' }
            'Resume' { $script:Config.Enabled=$true; Write-Config; Register-EngineTask; Start-ScheduledTask -TaskName $TaskName; Log 'ATIVADO' 'Verificacao a cada 5 minutos reativada.' }
            'CaptureOn' { $script:Config.Screenshots=$true; Write-Config; Log 'CAPTURA' 'Capturas locais autorizadas; dependem do painel visivel na sessao do usuario.' }
            'CaptureOff' { $script:Config.Screenshots=$false; Write-Config; Log 'CAPTURA' 'Capturas desligadas.' }
            'AddFolder' { Inventory; $p=Normalize $env:LG_APPROVED_FOLDER; if (-not (Safe-Target $p -Manual)) { throw 'Pasta generica, protegida, link ou unidade nao permitida.' }; if (-not [IO.Directory]::Exists($p)) { throw 'Selecione uma pasta existente e exclusiva do jogo.' }; $script:Config.AdditionalFolders=@(@($script:Config.AdditionalFolders)+$p|Sort-Object -Unique); Write-Config; Log 'APROVADO' ('Remocao recorrente autorizada somente para: '+$p) }
            'Uninstall' { $script:Config.Enabled=$false; $script:Config.Screenshots=$false; Write-Config; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LabGuardJogos2' -ErrorAction SilentlyContinue; Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LabGuardJogos2' -Recurse -ErrorAction SilentlyContinue; Log 'DESATIVADO' 'Tarefa e inicializacao removidas. Arquivos administrativos e registros mantidos para auditoria; jogos apagados nao sao restaurados.' }
        }; exit 0
    }
    if ($Mode -eq 'Cycle' -and -not $script:Config.Enabled) { exit 0 }
    if ($Mode -eq 'Cycle') {
        Secure-Directory $Data; $script:LogPath=Join-Path $Data 'remocoes.log'; $script:StatusPath=Join-Path $Data 'status.json'
        if ((Test-Path -LiteralPath $script:LogPath) -and (Get-Item -LiteralPath $script:LogPath).Length -gt 2097152) { Move-Item -LiteralPath $script:LogPath -Destination ($script:LogPath+'.1') -Force }
        Save-Status 'Executando' 'Inventariando instalacoes reconhecidas.'
    }
    Inventory; Discover; Stop-TargetProcesses; Uninstall-Msi; Remove-Store
    foreach ($t in @($script:Targets.Values|Sort-Object {$_.Path.Length} -Descending)) {
        if ([DateTime]::UtcNow -gt $script:Deadline) { Log 'PENDENTE' 'Tempo do ciclo atingido; os alvos restantes serao retomados.'; break }
        if ($script:Dry) { Log 'SIMULACAO' ($t.Reason+' -> '+$t.Path); continue }
        Read-Config; if (-not $script:Config.Enabled) { break }
        if (-not (Test-Path -LiteralPath $t.Path)) { continue }
        try { Save-Status 'Executando' $t.Reason; Delete-Bounded $t.Path $t.Manual; if (Test-Path -LiteralPath $t.Path) { throw 'Alvo ainda existe.' }; $script:Removed++; Log 'REMOVIDO' ($t.Reason+' -> '+$t.Path) } catch { Log 'FALHA' ($t.Path+': '+$_.Exception.Message) }
    }
    if (-not $script:Dry) { Save-Status 'Executando' 'Conferindo Microsoft Defender.' }
    Check-Defender
    $state=if($script:Failures -gt 0){'Concluido com falhas'}elseif($script:Pending -gt 0){'Concluido com pendencias'}else{'Concluido'}
    Save-Status $state 'Proxima checagem agendada em ate 5 minutos; confira os registros.'
    Log 'RESUMO' ('Removidos='+$script:Removed+'; pendencias='+$script:Pending+'; falhas='+$script:Failures)
    if($script:Failures -gt 0){exit 2}; exit 0
} catch { Log 'FALHA' $_.Exception.Message; try { Save-Status 'Falha' $_.Exception.Message } catch {}; exit 1 }
