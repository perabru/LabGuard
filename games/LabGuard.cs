using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Drawing.Imaging;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
[assembly: AssemblyTitle("LabGuard Jogos")]
[assembly: AssemblyDescription("Administracao visivel de jogos em computadores escolares")]
[assembly: AssemblyCompany("LabGuard")]
[assembly: AssemblyProduct("LabGuard Jogos")]
[assembly: AssemblyVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.0.0")]
namespace LabGuardGames {
static class Program {
    internal static readonly string BaseDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"LabGuardJogos2");
    internal static readonly string DataDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"LabGuardJogos2");
    internal static readonly string SessionDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"LabGuardJogos2");
    internal static readonly string[] Actions={"Install","Cycle","Audit","Pause","Resume","Uninstall","AddFolder","CaptureOn","CaptureOff","Test"};
    internal static bool Admin {get {using(var i=WindowsIdentity.GetCurrent())return new WindowsPrincipal(i).IsInRole(WindowsBuiltInRole.Administrator);}}
    internal static Dictionary<string,object> ReadJson(string path) {
        if(!File.Exists(path))return new Dictionary<string,object>();
        var f=new FileInfo(path); if(f.Length>1048576)throw new IOException("JSON acima do limite.");
        return new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(path,Encoding.UTF8));
    }
    internal static string Get(Dictionary<string,object> data,string key,string fallback="") { object value; return data.TryGetValue(key,out value)&&value!=null?Convert.ToString(value):fallback; }
    internal static bool Flag(Dictionary<string,object> data,string key) {object value;return data.TryGetValue(key,out value)&&value is bool&&(bool)value;}
    [STAThread] static int Main(string[] args) {
        try {
            if(args.Length>0&&args[0]=="--self-test")return RunEngine("Test",null,Console.WriteLine);
            if(args.Length>0&&args[0]=="--cycle")return RunEngine("Cycle",null,delegate(string s){});
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            if(args.Length>1&&args[0]=="--do") {
                if(!Actions.Contains(args[1]))throw new ArgumentException("Acao invalida.");
                if(!Admin)throw new UnauthorizedAccessException("Autorizacao administrativa nao concedida.");
                string folder=args.Length>2?Encoding.UTF8.GetString(Convert.FromBase64String(args[2])):null;
                using(var form=new OperationForm(args[1],folder)) { Application.Run(form); return form.Result; }
            }
            bool smoke=args.Contains("--ui-smoke");
            using(var form=new MainForm(smoke)){Application.Run(form);}
            return 0;
        } catch(Exception ex) { if(Environment.UserInteractive)MessageBox.Show(ex.Message,"LabGuard - erro",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1; }
    }
    internal static int RunEngine(string mode,string folder,Action<string> output) {
        if(!Actions.Contains(mode))throw new ArgumentException("Acao invalida.");
        if(mode!="Test"&&!Admin)throw new UnauthorizedAccessException("Acao exige administrador.");
        Mutex mutex=null; bool acquired=false;
        try {
            if(mode=="Cycle") {
                var security=new MutexSecurity();
                foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid),MutexRights.FullControl,AccessControlType.Allow));
                bool created;mutex=new Mutex(false,"Global\\LabGuardJogos2-Cycle",out created,security);
                try{acquired=mutex.WaitOne(0);}catch(AbandonedMutexException){acquired=true;}
                if(!acquired){output("Ja existe uma checagem em execucao. Nao sera iniciada outra em paralelo.");return 5;}
            }
            string script;
            using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("LabGuard.Engine")) {
                if(stream==null)throw new IOException("Motor interno nao encontrado.");
                using(var reader=new StreamReader(stream,Encoding.UTF8))script=reader.ReadToEnd();
            }
            string wrapper="$OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=$OutputEncoding;& ([scriptblock]::Create([Console]::In.ReadToEnd())) -Mode '"+mode+"'";
            string ps=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            var info=new ProcessStartInfo(ps,"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(wrapper)));
            info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardInput=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
            info.StandardOutputEncoding=Encoding.UTF8;info.StandardErrorEncoding=Encoding.UTF8;
            info.EnvironmentVariables["LG_SOURCE_EXE"]=Assembly.GetExecutingAssembly().Location;
            info.EnvironmentVariables["LG_APPROVED_FOLDER"]=folder??"";
            using(var proc=new Process()){proc.StartInfo=info;proc.OutputDataReceived+=(s,e)=>{if(e.Data!=null)output(e.Data);};proc.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)output("ERRO: "+e.Data);};
                proc.Start();proc.BeginOutputReadLine();proc.BeginErrorReadLine();proc.StandardInput.Write(script);proc.StandardInput.Close();
                if(!proc.WaitForExit(540000)){try{proc.Kill();}catch{}output("Tempo limite excedido. Confira o Agendador e os registros.");return 124;}
                proc.WaitForExit();return proc.ExitCode;
            }
        } finally {if(mutex!=null){if(acquired)mutex.ReleaseMutex();mutex.Dispose();}}
    }
    internal static void RunAction(string action,string folder=null) {
        if(!Actions.Contains(action))throw new ArgumentException("Acao invalida.");
        var p=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--do "+action+(folder==null?"":" "+Convert.ToBase64String(Encoding.UTF8.GetBytes(folder))));p.UseShellExecute=true;p.Verb="runas";Process.Start(p);
    }
    internal static bool NoLinks(string path) {
        try{string p=Path.GetFullPath(path);while(!String.IsNullOrEmpty(p)&&p.Length>3){if((File.Exists(p)||Directory.Exists(p))&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)return false;p=Path.GetDirectoryName(p);}return true;}catch{return false;}
    }
}
sealed class OperationForm:Form {
    readonly string action,folder;readonly TextBox log;readonly Label state;readonly Button close;public int Result=1;
    public OperationForm(string action,string folder){
        this.action=action;this.folder=folder;Text="LabGuard - administracao autorizada";Size=new Size(850,570);MinimumSize=new Size(650,450);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);BackColor=Color.White;
        state=new Label{Text="Preparando operacao...",Dock=DockStyle.Top,Height=65,Padding=new Padding(16),Font=new Font("Segoe UI",14,FontStyle.Bold)};
        log=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,Dock=DockStyle.Fill,Font=new Font("Consolas",10),WordWrap=false};
        close=new Button{Text="Fechar",Dock=DockStyle.Bottom,Height=45,Enabled=false};close.Click+=(s,e)=>Close();Controls.Add(log);Controls.Add(close);Controls.Add(state);
        Shown+=(s,e)=>Begin();FormClosing+=(s,e)=>{if(!close.Enabled)e.Cancel=true;};
    }
    void Append(string text){if(IsDisposed)return;try{BeginInvoke((Action)(()=>{if(log.TextLength>120000)log.Clear();log.AppendText(text+Environment.NewLine);}));}catch(InvalidOperationException){}}
    void Begin(){
        string warning=null;
        if(action=="Install")warning="Instalar a rotina como SYSTEM, no inicio do Windows, login e a cada 5 minutos?\n\nJogos reconhecidos e pastas aprovadas serao removidos permanentemente. Saves e mundos podem ser perdidos. Faca backup antes. Use apenas em computadores que voce administra.\n\nCapturas de tela ficam DESLIGADAS ate autorizacao separada.";
        if(action=="AddFolder")warning="Autorizar a exclusao permanente e recorrente de TODO o conteudo desta pasta?\n\n"+folder+"\n\nA pasta deve ser exclusiva do jogo/emulador. Nao selecione uma pasta de trabalhos ou programas compartilhados.";
        if(action=="CaptureOn")warning="Voce confirma a autorizacao da instituicao e o aviso aos usuarios para capturas locais desta estacao?\n\nSera mostrado aviso visivel. As imagens ficam locais, com limite de 24 e retencao maxima de 24 horas. Nao sao enviadas a servidor e nao causam exclusao por IA. O usuario pode pausar as imagens da sessao.";
        if(action=="Uninstall")warning="Desativar o LabGuard Jogos? A tarefa e a inicializacao serao removidas. Binario e registros ficam para auditoria. Jogos e dados ja removidos nao sao restaurados.";
        if(warning!=null&&MessageBox.Show(this,warning,"Confirmar administracao",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes){Result=0;close.Enabled=true;Close();return;}
        state.Text="Operacao em execucao: "+action;
        ThreadPool.QueueUserWorkItem(delegate{int result;try{result=Program.RunEngine(action,folder,Append);}catch(Exception ex){Append(ex.ToString());result=1;}Result=result;
            try{BeginInvoke((Action)(()=>{state.Text=result==0?"Operacao concluida. Confira os detalhes abaixo.":result==5?"Ja existe uma checagem em execucao.":"Operacao com erro ou falhas (codigo "+result+").";close.Enabled=true;}));}catch(InvalidOperationException){}
        });
    }
}
sealed class MainForm:Form {
    readonly Label status,detail,captureInfo;readonly TextBox logs;readonly NotifyIcon tray;readonly System.Windows.Forms.Timer timer;
    readonly bool smoke;Form banner;bool pausedImages=false,locked=false,closing=false;DateTime nextCapture=DateTime.UtcNow.AddSeconds(20);int logCounter=0;
    public MainForm(bool smoke){
        this.smoke=smoke;Text="LabGuard Jogos 2.0.0 - acompanhamento";Size=new Size(960,760);MinimumSize=new Size(780,640);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(245,247,252);AutoScaleMode=AutoScaleMode.Font;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=6,ColumnCount=1,Padding=new Padding(20)};
        root.RowStyles.Add(new RowStyle(SizeType.Absolute,75));root.RowStyles.Add(new RowStyle(SizeType.Absolute,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,125));root.RowStyles.Add(new RowStyle(SizeType.Absolute,55));root.RowStyles.Add(new RowStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,40));Controls.Add(root);
        var title=new Label{Text="LabGuard Jogos\nControle local do laboratorio | 2.0.0",Dock=DockStyle.Fill,Font=new Font("Segoe UI",20,FontStyle.Bold),ForeColor=Color.FromArgb(96,54,190)};root.Controls.Add(title,0,0);
        var statusBox=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=2,ColumnCount=1,BackColor=Color.White,Padding=new Padding(12)};
        statusBox.RowStyles.Add(new RowStyle(SizeType.Absolute,33));statusBox.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        status=new Label{Text="Consultando a instalacao...",Dock=DockStyle.Fill,Font=new Font("Segoe UI",15,FontStyle.Bold)};detail=new Label{Text="",Dock=DockStyle.Fill};statusBox.Controls.Add(status,0,0);statusBox.Controls.Add(detail,0,1);root.Controls.Add(statusBox,0,1);
        var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoScroll=true,Padding=new Padding(0,8,0,0)};
        AddButton(actions,"Instalar e ativar",()=>Act("Install"));AddButton(actions,"Simular sem apagar",()=>Act("Audit"));AddButton(actions,"Verificar agora",()=>Act("Cycle"));AddButton(actions,"Pausar limpeza",()=>Act("Pause"));AddButton(actions,"Retomar limpeza",()=>Act("Resume"));
        AddButton(actions,"Aprovar pasta de jogo",ApproveFolder);AddButton(actions,"Autorizar capturas",()=>Act("CaptureOn"));AddButton(actions,"Desligar capturas",()=>Act("CaptureOff"));AddButton(actions,"Ver capturas locais",OpenCaptures);AddButton(actions,"Ver registros",OpenLogs);AddButton(actions,"Desativar instalacao",()=>Act("Uninstall"));root.Controls.Add(actions,0,2);
        captureInfo=new Label{Dock=DockStyle.Fill,Padding=new Padding(6,7,6,0),Text="Capturas: desligadas. Nenhuma imagem e enviada a servidor.",BackColor=Color.FromArgb(255,245,212)};root.Controls.Add(captureInfo,0,3);
        logs=new TextBox{Dock=DockStyle.Fill,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,WordWrap=false,Font=new Font("Consolas",9),BackColor=Color.White};root.Controls.Add(logs,0,4);
        root.Controls.Add(new Label{Dock=DockStyle.Fill,Text="Checagem agendada: 5 minutos | Remocao por catalogo e pasta aprovada | Suspeitas: Microsoft Defender",Padding=new Padding(0,10,0,0)},0,5);
        tray=new NotifyIcon{Icon=SystemIcons.Shield,Text="LabGuard Jogos - painel visivel",Visible=!smoke};tray.DoubleClick+=(s,e)=>Restore();
        var menu=new ContextMenuStrip();menu.Items.Add("Abrir painel",null,(s,e)=>Restore());menu.Items.Add("Pausar imagens desta sessao",null,(s,e)=>PauseImages());menu.Items.Add("Fechar painel desta sessao",null,(s,e)=>{closing=true;Close();});tray.ContextMenuStrip=menu;
        Resize+=(s,e)=>{if(WindowState==FormWindowState.Minimized&&!smoke){Hide();tray.ShowBalloonTip(2500,"LabGuard Jogos","Painel na bandeja. A rotina administrativa continua conforme o status.",ToolTipIcon.Info);}};
        FormClosing+=(s,e)=>{closing=true;};FormClosed+=(s,e)=>{timer.Stop();tray.Visible=false;tray.Dispose();if(banner!=null)banner.Close();SystemEvents.SessionSwitch-=SessionChanged;};
        SystemEvents.SessionSwitch+=SessionChanged;
        timer=new System.Windows.Forms.Timer{Interval=2000};timer.Tick+=(s,e)=>RefreshStatus();timer.Start();Shown+=(s,e)=>RefreshStatus();
        if(smoke){var t=new System.Windows.Forms.Timer{Interval=2500};t.Tick+=(s,e)=>{t.Stop();t.Dispose();Close();};Shown+=(s,e)=>t.Start();}
    }
    void AddButton(FlowLayoutPanel parent,string text,Action action){var b=new Button{Text=text,AutoSize=true,Height=35,Padding=new Padding(9,3,9,3),Margin=new Padding(0,0,7,7),FlatStyle=FlatStyle.Flat,BackColor=Color.White};b.Click+=(s,e)=>{try{action();}catch(Exception ex){MessageBox.Show(this,ex.Message,"LabGuard",MessageBoxButtons.OK,MessageBoxIcon.Warning);}};parent.Controls.Add(b);}
    void Act(string action){if(smoke)return;Program.RunAction(action);}
    void ApproveFolder(){using(var d=new FolderBrowserDialog{Description="Selecione somente a pasta exclusiva do jogo ou emulador a remover.",ShowNewFolderButton=false}){if(d.ShowDialog(this)==DialogResult.OK)Program.RunAction("AddFolder",d.SelectedPath);}}
    void OpenLogs(){string p=Path.Combine(Program.DataDir,"remocoes.log");if(File.Exists(p))Process.Start(new ProcessStartInfo("notepad.exe","\""+p+"\""){UseShellExecute=true});else MessageBox.Show("Nenhum registro de limpeza foi gravado ainda.","LabGuard");}
    void OpenCaptures(){string p=Path.Combine(Program.SessionDir,"Capturas");if(Directory.Exists(p))Process.Start(new ProcessStartInfo("explorer.exe","\""+p+"\""){UseShellExecute=true});else MessageBox.Show("Nao existem capturas nesta conta. Autorize-as no painel administrativo, quando permitido.","LabGuard");}
    void Restore(){Show();WindowState=FormWindowState.Normal;Activate();}
    void PauseImages(){pausedImages=true;if(banner!=null){banner.Close();banner=null;}captureInfo.Text="Capturas pausadas nesta sessao. A limpeza administrativa continua independente das imagens.";}
    void SessionChanged(object sender,SessionSwitchEventArgs e){if(e.Reason==SessionSwitchReason.SessionLock||e.Reason==SessionSwitchReason.RemoteDisconnect)locked=true;if(e.Reason==SessionSwitchReason.SessionUnlock||e.Reason==SessionSwitchReason.RemoteConnect)locked=false;}
    void ShowBanner(){
        if(banner!=null&&!banner.IsDisposed)return;
        banner=new Form{Text="LabGuard - capturas autorizadas",FormBorderStyle=FormBorderStyle.FixedToolWindow,ControlBox=false,ShowInTaskbar=false,TopMost=true,StartPosition=FormStartPosition.Manual,Size=new Size(490,76),BackColor=Color.FromArgb(96,54,190)};
        var label=new Label{Text="LabGuard | Capturas locais autorizadas\nIntervalo: 5 min. Nenhum envio a servidor.",Dock=DockStyle.Fill,ForeColor=Color.White,Padding=new Padding(8),Font=new Font("Segoe UI",9)};
        var pause=new Button{Text="Pausar\nimagens",Dock=DockStyle.Right,Width=90};pause.Click+=(s,e)=>PauseImages();banner.Controls.Add(label);banner.Controls.Add(pause);
        var area=Screen.PrimaryScreen.WorkingArea;banner.Location=new Point(area.Right-banner.Width-10,area.Bottom-banner.Height-10);banner.Show();
    }
    void RefreshStatus(){
        if(closing)return;
        try {
            var c=Program.ReadJson(Path.Combine(Program.BaseDir,"config.json"));bool installed=c.Count>0;bool enabled=Program.Flag(c,"Enabled");
            if(!installed){status.Text="Pronto para instalar";detail.Text="Abra Instalar e ativar e autorize a conta administrativa. Nada foi removido por abrir este painel.";}
            else if(!enabled){status.Text="Limpeza pausada ou desativada";detail.Text="Use Retomar limpeza para recriar/reativar o agendamento. Uma operacao ja iniciada pode estar concluindo.";}
            else {
                var s=Program.ReadJson(Path.Combine(Program.DataDir,"status.json"));DateTime updated;
                if(s.Count==0){status.Text="Instalado - aguardando primeira verificacao";detail.Text="A tarefa deve iniciar no boot, login e a cada 5 minutos. Confira o Agendador se este estado persistir.";}
                else if(!DateTime.TryParse(Program.Get(s,"updatedUtc"),null,System.Globalization.DateTimeStyles.RoundtripKind,out updated)){status.Text="Falha ao interpretar o status";detail.Text="Confira os registros e a tarefa LabGuard-Jogos2-Limpeza.";}
                else {
                    double age=(DateTime.UtcNow-updated.ToUniversalTime()).TotalMinutes;string state=Program.Get(s,"state");
                    status.Text=age>12?"ATENCAO: rotina sem atualizacao recente":state=="Executando"?"EM EXECUCAO - verificando o computador":"Ativo - "+state;
                    int seconds=Math.Max(0,300-(int)(DateTime.UtcNow-updated.ToUniversalTime()).TotalSeconds);
                    detail.Text="Ultimo status: "+updated.ToLocalTime().ToString("dd/MM HH:mm:ss")+" | Removidos: "+Program.Get(s,"removed","0")+" | Pendencias: "+Program.Get(s,"pending","0")+" | Falhas: "+Program.Get(s,"failures","0")+Environment.NewLine+Program.Get(s,"detail")+" (Intervalo: 5 min; nao e contagem do Agendador.)";
                }
            }
            bool capturing=installed&&enabled&&Program.Flag(c,"Screenshots")&&!pausedImages&&!smoke;
            if(capturing){ShowBanner();captureInfo.Text=locked?"Sessao bloqueada: captura suspensa.":"CAPTURAS LOCAIS ATIVAS | Aviso visivel | Sem IA visual e sem envio de imagens. Voce pode pausar no aviso.";if(!locked&&DateTime.UtcNow>=nextCapture){nextCapture=DateTime.UtcNow.AddMinutes(5);Capture();}}
            else {if(banner!=null){banner.Close();banner=null;}captureInfo.Text=pausedImages?"Capturas pausadas nesta sessao. A limpeza nao depende das imagens.":"Capturas desligadas. Nao se apagam arquivos com base em uma imagem.";nextCapture=DateTime.UtcNow.AddSeconds(20);}
            if(logCounter++%5==0){string path=Path.Combine(Program.DataDir,"remocoes.log");if(File.Exists(path)){using(var fs=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){if(fs.Length>35000)fs.Seek(-35000,SeekOrigin.End);using(var r=new StreamReader(fs,Encoding.UTF8))logs.Text=r.ReadToEnd();}logs.SelectionStart=logs.TextLength;logs.ScrollToCaret();}else logs.Text="Aguardando o primeiro ciclo. A simulacao abre seu resultado em uma janela separada.";}
        }catch(Exception ex){status.Text="Erro ao consultar o estado";detail.Text=ex.Message;}
    }
    void Capture(){
        try{
            if(!Environment.UserInteractive||locked)return;
            string dir=Path.Combine(Program.SessionDir,"Capturas");if(!Program.NoLinks(dir))throw new IOException("Pasta de capturas contem link; captura recusada.");Directory.CreateDirectory(dir);
            var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
            var ids=new[]{WindowsIdentity.GetCurrent().User,new SecurityIdentifier("S-1-5-18"),new SecurityIdentifier("S-1-5-32-544")};
            foreach(var id in ids)acl.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.SetAccessControl(dir,acl);
            // No OCR, keystrokes, browser history or cloud upload. The image is local evidence only.
            string idName=DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8);string file=Path.Combine(dir,idName+".jpg");
            Rectangle bounds=Screen.PrimaryScreen.Bounds;
            using(var source=new Bitmap(bounds.Width,bounds.Height)){using(var g=Graphics.FromImage(source))g.CopyFromScreen(bounds.Location,Point.Empty,bounds.Size);int width=Math.Min(1600,source.Width);int height=Math.Max(1,source.Height*width/source.Width);using(var img=new Bitmap(source,new Size(width,height))){using(var fs=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None))img.Save(fs,ImageFormat.Jpeg);}}
            string[] names={"RobloxPlayerBeta","Minecraft","MinecraftLauncher","steam","EpicGamesLauncher","Dolphin","retroarch","pcsx2","pcsx2-qt","rpcs3","PPSSPPWindows64","Cemu","Ryujinx","yuzu","citra-qt","GTA5","GTAIV","gta_sa","FortniteClient-Win64-Shipping","cs2"};
            var found=new List<string>();foreach(var p in Process.GetProcesses()){using(p){try{if(p.SessionId==Process.GetCurrentProcess().SessionId&&names.Contains(p.ProcessName,StringComparer.OrdinalIgnoreCase))found.Add(p.ProcessName);}catch{}}}
            string evidence="Captura local autorizada: "+DateTime.Now.ToString("o")+Environment.NewLine+"Indicios de processos do catalogo (nao classificacao visual): "+(found.Count>0?String.Join(", ",found.Distinct()):"nenhum reconhecido; isso nao garante ausencia de jogo.")+Environment.NewLine+"Nenhuma exclusao e decidida por esta imagem.";
            using(var fs=new FileStream(Path.Combine(dir,idName+".txt"),FileMode.CreateNew,FileAccess.Write,FileShare.None))using(var writer=new StreamWriter(fs,Encoding.UTF8))writer.Write(evidence);
            var images=new DirectoryInfo(dir).GetFiles("*.jpg").OrderByDescending(f=>f.CreationTimeUtc).ToArray();for(int i=0;i<images.Length;i++){if(i>=24||images[i].CreationTimeUtc<DateTime.UtcNow.AddHours(-24)){if(Program.NoLinks(images[i].FullName)){string meta=Path.ChangeExtension(images[i].FullName,".txt");images[i].Delete();if(Program.NoLinks(meta)&&File.Exists(meta))File.Delete(meta);}}}
        }catch(Exception ex){captureInfo.Text="Falha de captura (nenhuma conclusao sobre jogo): "+ex.Message;}
    }
}
}
