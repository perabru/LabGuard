"""Assemble automatic 2.4 on top of the tested managed 2.3 engine, without replacing the network edition."""
from pathlib import Path
import sys
import ast
import json
import re
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'managed'))
from prepare import one
D=R/'games/dist'; B=R/'managed/build'; O=R/'automatic/build';O.mkdir(parents=True,exist_ok=True)
# Build the complete local list from the *existing* LabGuard catalogs, not from an external or guessed list.
def ast_catalog(path,name):
    module=ast.parse(path.read_text(encoding='utf-8-sig'))
    matches=[node for node in module.body if isinstance(node,ast.Assign)
             and any(isinstance(t,ast.Name) and t.id==name for t in node.targets)]
    if len(matches)!=1:raise RuntimeError('Catalog source changed: '+name)
    return ast.literal_eval(matches[0].value)

client=ast_catalog(R/'client/labguard_cliente.py','CLIENT_CATALOG_ROWS')
school=ast_catalog(R/'labguard/school_policy.py','SCHOOL_POLICY')
ai=json.loads((R/'gateway/ai_services.json').read_text(encoding='utf-8'))
quick=set(('term.ooo','friv.com','friv.com.br','poki.com','chess.com',
           'youtube.com','youtube-nocookie.com','youtu.be','youtubei.googleapis.com',
           'youtube.googleapis.com','youtubekids.com'))
combined={row[0] for row in client}|{row[0] for row in school}|{d for service in ai['services'] for d in service['domains']}
domains=sorted(d for d in combined if not any(d==q or d.endswith('.'+q) for q in quick))
assert len(client)==831 and 800 <= len(domains) <= 900, 'Catalog counts require review before deployment'
assert all(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251})\.[a-z]{2,}',d) for d in domains), 'Unexpected domain'
payload='@('+','.join("'"+d+"'" for d in domains)+')'
(O/'CATALOGO_COMPLETO.json').write_text(json.dumps({'version':'2.5.0','source_rows':len(client),
    'categories':{c:sum(x[1]==c for x in client) for c in sorted({x[1] for x in client})},
    'full_catalog_browsers':len(domains),'dynamic_quick_sites':sorted(quick),
    'all_sites':domains},ensure_ascii=False,indent=2),encoding='utf-8')
catalog=(R/'automatic/FullCatalog.ps1').read_text(encoding='utf-8')
assert catalog.count('__FULL_CATALOG__')==1
catalog=catalog.replace('__FULL_CATALOG__',payload)
ps=(D/'Engine.assembled.ps1').read_text(encoding='utf-8-sig').replace('2.3.0','2.5.0')
ps=one(ps,"'ManagedWeb')][string]$Mode","'ManagedWeb','InstallHealth')][string]$Mode")
entry="try {\n    if ($Mode -eq 'Test')"
helpers=(R/'automatic/Automatic.ps1').read_text(encoding='utf-8')+'\n'+catalog+'\n'+(R/'automatic/PortablePass.ps1').read_text(encoding='utf-8')
ps=one(ps,entry,helpers+'\n'+entry)
# Known game stores and emulators use exact registry display-name identities; no arbitrary wildcard file deletion.
launcher_pattern=r'|EA app(?:\\s|$)|EA Desktop(?:\\s|$)|Battle\\.net(?:\\s|$)|Blizzard Battle\\.net(?:\\s|$)|Ubisoft Connect(?:\\s|$)|Uplay(?:\\s|$)|GOG GALAXY(?:\\s|$)|Rockstar Games Launcher(?:\\s|$)|Riot Client(?:\\s|$)|Amazon Games(?:\\s|$)|Heroic Games Launcher(?:\\s|$)|Playnite(?:\\s|$)|HoYoPlay(?:\\s|$)|Game Jolt Client(?:\\s|$)|itch(?:\\.io)?(?:\\s|$)'
pattern_line=next((line for line in ps.splitlines() if line.startswith("$script:GamePattern='")),None)
if not pattern_line or not pattern_line.endswith(")'"):raise RuntimeError('Game catalog anchor changed')
ps=ps.replace(pattern_line,pattern_line[:-2]+launcher_pattern+")'")
# Names used by the live guard are exact filenames and verified against the existing protected-process list.
ps=one(ps,'Inventory; Discover; Discover-WindowsGameFolders; Stop-TargetProcesses; Uninstall-Msi; Remove-Store','Inventory; Discover; Discover-WindowsGameFolders; Stop-TargetProcesses; Remove-NonInstallerTargets; Uninstall-Msi; Remove-Store')
# Recheck persistent browser policies once per cleanup cycle (without touching unrelated site controls).
ps=one(ps,"Check-Defender; if(-not $script:Dry){try{Apply-YouTube ([bool]$script:Config.BlockYouTube)}catch{Log 'PENDENTE' ('YouTube: '+$_.Exception.Message)}}",
          "Check-Defender; if(-not $script:Dry){try{Apply-YouTube ([bool]$script:Config.BlockYouTube);Apply-FullCatalog}catch{Log 'PENDENTE' ('Sites: '+$_.Exception.Message)}}")
ps=one(ps,"'Uninstall' { Remove-Extensions;", "'Uninstall' { Remove-FullCatalog; Remove-Extensions;")
# Pause is checked again between MSI operations, never by terminating msiexec.
ps=one(ps,"        if ($script:Dry) { Log 'SIMULACAO' ('Desinstalaria MSI: '+$app.DisplayName); continue }","        if ($script:Dry) { Log 'SIMULACAO' ('Desinstalaria MSI: '+$app.DisplayName); continue }\n        Read-Config; if(-not $script:Config.Enabled){return}")
ps=one(ps,"    Assert-Admin\n    if($Mode -eq 'ManagedWeb')","    Assert-Admin\n    if($Mode -eq 'InstallHealth'){$r=@(Check-AutomaticHealth);for($i=0;$i -lt $r.Count-1;$i++){Write-Output $r[$i]};exit ([int]$r[-1])}\n    if($Mode -eq 'ManagedWeb')")
ps=one(ps,'Read-Config; $script:Config.Enabled=$true; $script:Config.Screenshots=$false; Write-Config','Initialize-AutomaticPolicy')
ps=one(ps,'Install-Extensions; Start-ScheduledTask -TaskName $TaskName','Install-Extensions; if($script:Config.Enabled){Start-ScheduledTask -TaskName $TaskName}else{Disable-ScheduledTask -TaskName $TaskName|Out-Null}')
ps=one(ps,"        Log 'INSTALADO' 'Tarefa SYSTEM no inicio, login e a cada 5 minutos; painel visivel no login. Capturas desligadas por padrao.'; exit 0","        Log 'INSTALADO' 'Rotinas locais registradas. Conferindo atividade e bloqueios; capturas desligadas.'; if($script:Failures -gt 0){exit 2};exit 0")
ps=ps.replace("UninstallString=('\"'+$Exe+'\" --admin')","UninstallString=('\"'+$Exe+'\" --do Uninstall')")
(O/'Engine.ps1').write_text(ps,encoding='utf-8-sig')
cs=(D/'LabGuard.assembled.cs').read_text(encoding='utf-8-sig').replace('2.3.0','2.5.0')
cs=one(cs,'"ManagedWeb"};','"ManagedWeb","InstallHealth"};')
cs=one(cs,'            if(args.Length>0&&args[0]=="--central-self-test")', '''            if(args.Length==2&&args[0]=="--install-auto"&&args[1]=="--accept-policy")return AutomaticInstaller.Run(delegate(string text){});
            if(args.Length>0&&args[0]=="--central-self-test")''')
cs=one(cs,'Application.Run(new ManagedSetup(true))','Application.Run(new AutomaticSetup(true,false))')
cs=one(cs,'using(var setup=new ManagedSetup(false))','using(var setup=new AutomaticSetup(false,!args.Contains("--setup")))')
cs=one(cs,'new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--setup")','new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,args.Contains("--setup")?"--setup":"--activate")')
cs=cs.replace('string wrapper="$OutputEncoding=', 'string wrapper="$ProgressPreference=\'SilentlyContinue\';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=')
# Prevent module autoload from a writable user path in the elevated engine.
cs=one(cs,'            info.EnvironmentVariables["LG_SOURCE_EXE"]=', '''            info.WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.System);
            info.EnvironmentVariables["PSModulePath"]=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell\\\\v1.0\\\\Modules");
            info.EnvironmentVariables["LG_SOURCE_EXE"]=''')
(O/'Program.cs').write_text(cs,encoding='utf-8-sig')
guard=(D/'Guardian.assembled.cs').read_text(encoding='utf-8-sig').replace('2.3.0','2.5.0')
guard=one(guard,'|EpicGamesLauncher|','|EpicGamesLauncher|EADesktop|EALauncher|Battle.net|UbisoftConnect|upc|GalaxyClient|GalaxyClientService|RiotClientServices|RiotClientUx|RockstarGamesLauncher|Amazon Games|Heroic|Playnite.DesktopApp|HoYoPlay|')
(O/'Guardian.cs').write_text(guard,encoding='utf-8-sig')
client=(B/'ManagedClient.cs').read_text(encoding='utf-8-sig').replace('2.3.0','2.5.0').replace('Cliente 2.3','Cliente 2.5')
(O/'CentralLink.cs').write_text(client,encoding='utf-8-sig')
print(f'Automatic client 2.5 assembled: {len(domains)} packaged domains + dynamic quick sites. Central 1.2 retained.')
