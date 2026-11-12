"""Assemble automatic 2.4 on top of the tested managed 2.3 engine, without replacing the network edition."""
from pathlib import Path
import sys
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'managed'))
from prepare import one
D=R/'games/dist'; B=R/'managed/build'; O=R/'automatic/build';O.mkdir(parents=True,exist_ok=True)
ps=(D/'Engine.assembled.ps1').read_text(encoding='utf-8-sig').replace('2.3.0','2.4.0')
ps=one(ps,"'ManagedWeb')][string]$Mode","'ManagedWeb','InstallHealth')][string]$Mode")
entry="try {\n    if ($Mode -eq 'Test')"
ps=one(ps,entry,(R/'automatic/Automatic.ps1').read_text(encoding='utf-8')+'\n'+entry)
ps=one(ps,"    Assert-Admin\n    if($Mode -eq 'ManagedWeb')","    Assert-Admin\n    if($Mode -eq 'InstallHealth'){$r=@(Check-AutomaticHealth);for($i=0;$i -lt $r.Count-1;$i++){Write-Output $r[$i]};exit ([int]$r[-1])}\n    if($Mode -eq 'ManagedWeb')")
ps=one(ps,'Read-Config; $script:Config.Enabled=$true; $script:Config.Screenshots=$false; Write-Config','Initialize-AutomaticPolicy')
ps=one(ps,'Install-Extensions; Start-ScheduledTask -TaskName $TaskName','Install-Extensions; if($script:Config.Enabled){Start-ScheduledTask -TaskName $TaskName}else{Disable-ScheduledTask -TaskName $TaskName|Out-Null}')
ps=one(ps,"        Log 'INSTALADO' 'Tarefa SYSTEM no inicio, login e a cada 5 minutos; painel visivel no login. Capturas desligadas por padrao.'; exit 0","        Log 'INSTALADO' 'Rotinas locais registradas. Conferindo atividade e bloqueios; capturas desligadas.'; if($script:Failures -gt 0){exit 2};exit 0")
ps=ps.replace("UninstallString=('\"'+$Exe+'\" --admin')","UninstallString=('\"'+$Exe+'\" --do Uninstall')")
(O/'Engine.ps1').write_text(ps,encoding='utf-8-sig')
cs=(D/'LabGuard.assembled.cs').read_text(encoding='utf-8-sig').replace('2.3.0','2.4.0')
cs=one(cs,'"ManagedWeb"};','"ManagedWeb","InstallHealth"};')
cs=one(cs,'            if(args.Length>0&&args[0]=="--central-self-test")', '''            if(args.Length==2&&args[0]=="--install-auto"&&args[1]=="--accept-policy")return AutomaticInstaller.Run(delegate(string text){});
            if(args.Length>0&&args[0]=="--central-self-test")''')
cs=one(cs,'Application.Run(new ManagedSetup(true))','Application.Run(new AutomaticSetup(true,false))')
cs=one(cs,'using(var setup=new ManagedSetup(false))','using(var setup=new AutomaticSetup(false,!args.Contains("--setup")))')
cs=one(cs,'new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--setup")','new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,args.Contains("--setup")?"--setup":"--activate")')
cs=cs.replace('string wrapper="$OutputEncoding=', 'string wrapper="[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=')
# Prevent module autoload from a writable user path in the elevated engine.
cs=one(cs,'            info.EnvironmentVariables["LG_SOURCE_EXE"]=', '''            info.WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.System);
            info.EnvironmentVariables["PSModulePath"]=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell\\\\v1.0\\\\Modules");
            info.EnvironmentVariables["LG_SOURCE_EXE"]=''')
(O/'Program.cs').write_text(cs,encoding='utf-8-sig')
(O/'Guardian.cs').write_text((D/'Guardian.assembled.cs').read_text(encoding='utf-8-sig').replace('2.3.0','2.4.0'),encoding='utf-8-sig')
client=(B/'ManagedClient.cs').read_text(encoding='utf-8-sig').replace('2.3.0','2.4.0').replace('Cliente 2.3','Cliente 2.4')
(O/'CentralLink.cs').write_text(client,encoding='utf-8-sig')
print('Automatic client 2.4 assembled. Central 1.2 protocol retained.')
