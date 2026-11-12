using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Drawing;
using System.Windows.Forms;
namespace LabGuardGames {
// Visible administrative protection. No remote command channel or screenshot classification.
static class Guardian {
    static readonly HashSet<string> Games=new HashSet<string>(("RobloxPlayerBeta|RobloxPlayerLauncher|Minecraft|Minecraft.Windows|MinecraftLauncher|TLauncher|PrismLauncher|MultiMC|Lunar Client|Badlion Client|steam|EpicGamesLauncher|Dolphin|retroarch|pcsx2|pcsx2-qt|pcsx2-qt-avx2|rpcs3|PPSSPPWindows|PPSSPPWindows64|duckstation-qt-x64-ReleaseLTCG|duckstation-qt-x64-Release|Cemu|Ryujinx|yuzu|citra-qt|snes9x|snes9x-x64|mGBA|DeSmuME|melonDS|mame|GTA5|GTAIV|gta_sa|gta-vc|RDR2|Cyberpunk2077|witcher3|FortniteClient-Win64-Shipping|RocketLeague|cs2|hl|hl2|Terraria|Stardew Valley|Cuphead|Among Us|VALORANT-Win64-Shipping").Split('|'),StringComparer.OrdinalIgnoreCase);
    static readonly HashSet<string> Protected=new HashSet<string>(("LabGuard-Jogos|LabGuard-Setup|LabGuard|LabGuard-Tecnico|LabGuard-Cliente|chrome|msedge|firefox|brave|opera|iexplore|explorer|svchost|services|wininit|winlogon|lsass|csrss|smss|dwm|conhost|RuntimeBroker|SearchHost|MsMpEng|SecurityHealthService|powershell|pwsh|cmd|notepad|Code|devenv|RobloxStudioBeta|MinecraftEducation|UnrealEditor|Unity|blender|godot").Split('|'),StringComparer.OrdinalIgnoreCase);
    static readonly Regex Educational=new Regex(@"(?i)(MinecraftEducation|Minecraft Education|RobloxStudio|Unreal Engine|UnrealEditor|Android Studio)");
    internal static bool Inside(string child,string parent) {
        if(String.IsNullOrWhiteSpace(child)||String.IsNullOrWhiteSpace(parent))return false;
        try {string c=Path.GetFullPath(child),p=Path.GetFullPath(parent).TrimEnd('\\');return c.Equals(p,StringComparison.OrdinalIgnoreCase)||c.StartsWith(p+"\\",StringComparison.OrdinalIgnoreCase);}catch{return false;}
    }
    internal static bool ValidFolder(string path){
        try{if(String.IsNullOrEmpty(path)||!Regex.IsMatch(path,@"^[A-Za-z]:\\")||path.Contains("..")||path.Contains("~")||path.Substring(2).Contains(":"))return false;string full=Path.GetFullPath(path).TrimEnd('\\');
            if(full.Length<4||Inside(full,Environment.GetFolderPath(Environment.SpecialFolder.Windows))||Inside(full,Program.BaseDir))return false;
            if(Regex.IsMatch(full,@"(?i)\\(Users|Program Files(?: \(x86\))?|ProgramData|AppData|Local|Roaming|Documents|Desktop|Downloads|OneDrive|Games|Jogos|Emuladores|Emulators)$"))return false;
            return Program.NoLinks(full);
        }catch{return false;}
    }
    internal static bool IsGame(string path,string commandLine,IEnumerable<string> approved){
        if(String.IsNullOrWhiteSpace(path))return false;
        string name=Path.GetFileNameWithoutExtension(path);
        if(name.StartsWith("LabGuard",StringComparison.OrdinalIgnoreCase)||Protected.Contains(name)||Educational.IsMatch(path)||Inside(path,Program.BaseDir)||Inside(path,Environment.GetFolderPath(Environment.SpecialFolder.Windows)))return false;
        if(Games.Contains(name))return true;
        if((name.Equals("javaw",StringComparison.OrdinalIgnoreCase)||name.Equals("java",StringComparison.OrdinalIgnoreCase))&&!String.IsNullOrEmpty(commandLine)){
            // Read only for Minecraft identity. Never record a command line (it may contain account tokens).
            if(Regex.IsMatch(commandLine,@"(?i)(net\.minecraft\.client\.main\.Main|net\.minecraft\.launchwrapper\.Launch|org\.multimc\.EntryPoint)")&&Regex.IsMatch(commandLine,@"(?i)[\\/]\.minecraft[\\/]"))return true;
        }
        return approved!=null&&approved.Any(folder=>ValidFolder(folder)&&Inside(path,folder));
    }
    static string JavaCommand(Process p){try{using(var o=new ManagementObject("Win32_Process.Handle='"+p.Id+"'")){o.Get();return Convert.ToString(o["CommandLine"]);}}catch{return "";}}
    static List<string> Folders(Dictionary<string,object> c){object raw;var result=new List<string>();if(c.TryGetValue("AdditionalFolders",out raw)&&raw is IEnumerable&&!(raw is string)){foreach(object value in (IEnumerable)raw)if(value is string&&ValidFolder((string)value))result.Add((string)value);}return result;}
    internal static bool CloseGame(Process p,IEnumerable<string> approved,Action<string> log){
        try{
            if(p.HasExited||p.Id==Process.GetCurrentProcess().Id)return false;
            // Keep the original process handle, so a recycled PID is never selected later.
            IntPtr held=p.Handle;
            string path=p.MainModule.FileName;
            string name=Path.GetFileNameWithoutExtension(path);
            string cmd=(name.Equals("javaw",StringComparison.OrdinalIgnoreCase)||name.Equals("java",StringComparison.OrdinalIgnoreCase))?JavaCommand(p):"";
            if(!Program.NoLinks(path)||!IsGame(path,cmd,approved))return false;
            bool closed=false;
            if(p.SessionId==Process.GetCurrentProcess().SessionId){try{closed=p.CloseMainWindow()&&p.WaitForExit(400);}catch{}}
            if(!closed&&!p.HasExited){p.Kill();closed=p.WaitForExit(1000);}
            if(closed||p.HasExited){log("FECHADO | "+name+" | "+path);return true;}
            log("PENDENTE | Processo ainda ativo: "+name);return false;
        }catch(System.ComponentModel.Win32Exception){return false;}catch(InvalidOperationException){return false;}catch(Exception ex){log("FALHA | "+ex.Message);return false;}
    }
    static void WriteLog(string text){try{string path=Path.Combine(Program.DataDir,"guard.log");if(!Program.NoLinks(path))return;if(File.Exists(path)&&new FileInfo(path).Length>2097152){string old=path+".1";if(File.Exists(old))File.Delete(old);File.Move(path,old);}File.AppendAllText(path,DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")+" | "+text.Replace("\r"," ").Replace("\n"," ")+Environment.NewLine,Encoding.UTF8);}catch{}}
    static void Heartbeat(string state,int count,string detail){
        string path=Path.Combine(Program.DataDir,"guard-status.json"),tmp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{if(!Program.NoLinks(path))return;var data=new Dictionary<string,object>{{"version","2.1.0"},{"state",state},{"closed",count},{"detail",detail},{"updatedUtc",DateTime.UtcNow.ToString("o")},{"intervalSeconds",2}};File.WriteAllText(tmp,new JavaScriptSerializer().Serialize(data),new UTF8Encoding(false));if(File.Exists(path))File.Replace(tmp,path,null);else File.Move(tmp,path);}catch{}finally{try{if(File.Exists(tmp))File.Delete(tmp);}catch{}}
    }
    internal static int Run(){
        if(!Program.Admin)return 1;
        bool created,owned=false;var security=new MutexSecurity();foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid),MutexRights.FullControl,AccessControlType.Allow));
        using(var mutex=new Mutex(false,"Global\\LabGuardJogos2-Guardian",out created,security)){
            try{try{owned=mutex.WaitOne(0);}catch(AbandonedMutexException){owned=true;}if(!owned)return 0;
                if(Program.RunEngine("GuardInit",null,WriteLog)!=0)return 2;
                WriteLog("INICIADO | Monitor administrativo de jogos; intervalo nominal 2 segundos.");int total=0;
                while(true){try{
                    var c=Program.ReadJson(Path.Combine(Program.BaseDir,"config.json"));
                    if(c.Count==0){Heartbeat("Falha",total,"Configuracao ausente; nenhuma acao realizada.");Thread.Sleep(2000);continue;}
                    bool active=Program.Flag(c,"Enabled")&&Program.Flag(c,"AutoCloseGames");
                    if(active){var folders=Folders(c);foreach(var p in Process.GetProcesses()){using(p){try{if(p.SessionId<=0)continue;if(CloseGame(p,folders,WriteLog))total++;}catch{}}}}
                    Heartbeat(active?"Ativo":"Pausado",total,active?"Jogos reconhecidos sao encerrados. Limpeza de arquivos continua a cada 5 minutos.":"Fechamento imediato pausado. Consulte tambem o estado da limpeza.");
                }catch(Exception ex){WriteLog("FALHA | "+ex.Message);Heartbeat("Falha",total,ex.Message);}Thread.Sleep(2000);}
            }finally{if(owned)mutex.ReleaseMutex();}
        }
    }
    internal static int SelfTest(string fixture){
        Action<bool,string> check=(ok,label)=>{if(!ok)throw new Exception("Guardian test failed: "+label);};
        foreach(string n in new[]{"RobloxPlayerBeta","steam","EpicGamesLauncher","pcsx2-qt","MinecraftLauncher","rpcs3"})check(IsGame("C:\\TestGames\\"+n+".exe","",null),n);
        foreach(string n in new[]{"chrome","msedge","firefox","LabGuard-Jogos","RobloxStudioBeta","Code","MsMpEng"})check(!IsGame("C:\\TestGames\\"+n+".exe","",new[]{"C:\\TestGames"}),"Preserve "+n);
        check(!IsGame("C:\\Apps\\MinecraftEducation\\Minecraft.Windows.exe","",null),"Minecraft Education");
        check(!IsGame("C:\\Apps\\Java\\javaw.exe","-jar lesson.jar",null),"Generic Java");
        check(IsGame("C:\\Apps\\Java\\javaw.exe","net.minecraft.client.main.Main --gameDir C:\\Users\\Aluno\\AppData\\Roaming\\.minecraft\\",null),"Minecraft Java identity");
        check(!ValidFolder("C:\\Users"),"Generic profile root");check(!ValidFolder("C:\\Games"),"Generic games root");
        if(!String.IsNullOrEmpty(fixture)){
            string root=Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location),"test-fixtures");
            check(Inside(fixture,root)&&Path.GetFileName(fixture)=="RobloxPlayerBeta.exe","Dedicated synthetic fixture only");
            using(var p=Process.Start(new ProcessStartInfo(fixture){UseShellExecute=false})){try{Thread.Sleep(800);check(CloseGame(p,new string[0],Console.WriteLine),"Automatically close synthetic game window");check(p.HasExited,"Synthetic game stopped");}finally{try{if(!p.HasExited)p.Kill();}catch{}}}
        }
        Console.WriteLine("Guardian classification, exclusions and process closure tests passed.");return 0;
    }
}
static class ProtectionPanel {
    internal static void Attach(Form owner,TableLayoutPanel root,bool smoke){
        int row=root.RowCount;root.RowCount=row+1;root.RowStyles.Add(new RowStyle(SizeType.Absolute,120));
        var box=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=2,ColumnCount=1,BackColor=Color.White,Padding=new Padding(8)};box.RowStyles.Add(new RowStyle(SizeType.Absolute,43));box.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoScroll=true};var status=new Label{Dock=DockStyle.Fill,Font=new Font("Segoe UI",9),Text="YouTube e fechamento automatico: consultando..."};box.Controls.Add(buttons,0,0);box.Controls.Add(status,0,1);root.Controls.Add(box,0,row);
        foreach(var pair in new[]{new[]{"Bloquear YouTube","YouTubeOn"},new[]{"Liberar YouTube","YouTubeOff"},new[]{"Ativar fechamento","GameCloseOn"},new[]{"Pausar fechamento","GameCloseOff"}}){string action=pair[1];var b=new Button{Text=pair[0],AutoSize=true,Padding=new Padding(6),Margin=new Padding(2),Enabled=!smoke};b.Click+=(s,e)=>{try{Program.RunAction(action);}catch(Exception ex){MessageBox.Show(owner,ex.Message,"LabGuard");}};buttons.Controls.Add(b);}
        var timer=new System.Windows.Forms.Timer{Interval=2000};Action refresh=()=>{try{
            var c=Program.ReadJson(Path.Combine(Program.BaseDir,"config.json"));if(c.Count==0){status.Text="Instale e ative: YouTube bloqueado e fechamento de jogos ficam ligados por padrao. Nenhum navegador e encerrado.";return;}
            var g=Program.ReadJson(Path.Combine(Program.DataDir,"guard-status.json"));DateTime dt;bool fresh=DateTime.TryParse(Program.Get(g,"updatedUtc"),null,System.Globalization.DateTimeStyles.RoundtripKind,out dt)&&(DateTime.UtcNow-dt.ToUniversalTime()).TotalSeconds<15;
            string guard=fresh?Program.Get(g,"state"):"SEM CONFIRMACAO RECENTE";
            var web=Program.ReadJson(Path.Combine(Program.DataDir,"youtube-status.json"));bool desired=Program.Flag(c,"BlockYouTube");string ws=web.Count==0?"aguardando aplicacao":Program.Get(web,"state","sem confirmacao");
            status.Text="Fechamento de jogos: "+guard+" | Encerrados nesta execucao: "+Program.Get(g,"closed","0")+" | Intervalo nominal: 2 s"+Environment.NewLine+"YouTube: "+(desired?"bloqueio solicitado":"liberacao solicitada")+" | "+ws+". Reabra o navegador apos alterar.\nFechar a janela do painel mantem o monitor na bandeja; a rotina SYSTEM continua ativa.";
        }catch(Exception ex){status.Text="Falha ao consultar protecao: "+ex.Message;}};
        timer.Tick+=(s,e)=>refresh();owner.Shown+=(s,e)=>refresh();owner.FormClosed+=(s,e)=>timer.Dispose();timer.Start();
    }
}
}
