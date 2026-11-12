using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Collections;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Drawing;
namespace LabGuardGames {
// A fixed authenticated event/policy protocol; never a remote command shell.
static class CentralLink {
    static readonly string PrivateDir=Path.Combine(Program.BaseDir,"Central");
    static readonly object Gate=new object();
    static JavaScriptSerializer Json { get { return new JavaScriptSerializer{MaxJsonLength=524288}; } }
    static List<Dictionary<string,object>> queue=new List<Dictionary<string,object>>();
    static readonly Dictionary<string,DateTime> dedup=new Dictionary<string,DateTime>();
    static int running=0;
    static int dropped=0;
    internal static bool PrivateAddress(string value){
        IPAddress ip;if(!IPAddress.TryParse(value,out ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)return false;
        byte[] b=ip.GetAddressBytes();return b[0]==10||b[0]==127||(b[0]==192&&b[1]==168)||(b[0]==172&&b[1]>=16&&b[1]<=31);
    }
    internal static Uri ValidateServer(string value){
        Uri u;if(!Uri.TryCreate(value,UriKind.Absolute,out u)||u.Scheme!="https"||u.Port<1||u.Port>65535||u.UserInfo!=""||u.Query!=""||u.Fragment!=""||u.AbsolutePath!="/"||!PrivateAddress(u.Host))throw new InvalidDataException("O vínculo deve apontar para o HTTPS/IPv4 local da Central.");return u;
    }
    static Dictionary<string,object> Parse(string text){var d=Json.Deserialize<Dictionary<string,object>>(text);if(d==null)throw new InvalidDataException("JSON inválido.");return d;}
    static byte[] Certificate(string pem){
        if(pem.Length>12000)throw new InvalidDataException("Certificado acima do limite.");
        string raw=pem.Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","");
        byte[] data=Convert.FromBase64String(raw);using(var c=new X509Certificate2(data)){if(c.NotAfter.ToUniversalTime()<DateTime.UtcNow||c.NotBefore.ToUniversalTime()>DateTime.UtcNow)throw new InvalidDataException("Certificado da Central fora da validade. Confira o relógio dos PCs.");return c.RawData;}
    }
    internal static bool CheckCertificate(byte[] pinned,X509Certificate certificate,SslPolicyErrors errors){
        if(certificate==null||(errors&SslPolicyErrors.RemoteCertificateNameMismatch)!=0||(errors&SslPolicyErrors.RemoteCertificateNotAvailable)!=0)return false;
        using(var c=new X509Certificate2(certificate)){if(c.NotBefore.ToUniversalTime()>DateTime.UtcNow||c.NotAfter.ToUniversalTime()<DateTime.UtcNow)return false;byte[] actual=c.RawData;if(actual.Length!=pinned.Length)return false;int diff=0;for(int i=0;i<actual.Length;i++)diff|=actual[i]^pinned[i];return diff==0;}
    }
    internal static Dictionary<string,object> Request(string server,byte[] pinned,string endpoint,object body,string token){
        Uri baseUrl=ValidateServer(server);
        if(!new[]{"/api/agent/managed-info","/api/agent/enroll","/api/agent/telemetry"}.Contains(endpoint))throw new InvalidDataException("Operação de conexão não permitida.");
        ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
        var req=(HttpWebRequest)WebRequest.Create(new Uri(baseUrl,endpoint));req.Method="POST";req.ContentType="application/json";req.Accept="application/json";req.AllowAutoRedirect=false;req.Proxy=null;req.Timeout=8000;req.ReadWriteTimeout=8000;req.KeepAlive=false;
        req.ServerCertificateValidationCallback=(sender,cert,chain,errors)=>CheckCertificate(pinned,cert,errors);
        if(!String.IsNullOrEmpty(token)){if(!Regex.IsMatch(token,@"^[A-Za-z0-9_-]{32,100}$"))throw new InvalidDataException("Credencial inválida.");req.Headers[HttpRequestHeader.Authorization]="Bearer "+token;}
        byte[] payload=Encoding.UTF8.GetBytes(Json.Serialize(body));if(payload.Length>16000)throw new InvalidDataException("Avisos acima do limite.");req.ContentLength=payload.Length;
        try {using(var s=req.GetRequestStream())s.Write(payload,0,payload.Length);
            using(var response=(HttpWebResponse)req.GetResponse()){
                if(response.StatusCode!=HttpStatusCode.OK)throw new IOException("A Central não confirmou a operação.");
                using(var ms=new MemoryStream())using(var s=response.GetResponseStream()){
                    byte[] buffer=new byte[8192];int n;while((n=s.Read(buffer,0,buffer.Length))>0){if(ms.Length+n>524288)throw new InvalidDataException("Resposta da Central acima do limite.");ms.Write(buffer,0,n);}
                    var result=Parse(Encoding.UTF8.GetString(ms.ToArray()));if(!Program.Flag(result,"ok"))throw new IOException("Operação não confirmada pela Central.");return result;
                }
            }
        }catch(WebException e){var r=e.Response as HttpWebResponse;if(r!=null){int code=(int)r.StatusCode;r.Close();if(code==401)throw new UnauthorizedAccessException("Vínculo inválido, utilizado ou revogado. Gere outro arquivo no painel.");if(code==404)throw new IOException("Atualize o painel do técnico para a Central 1.1 antes de vincular.");}throw new IOException("Sem comunicação segura com a Central. Confira IP, porta 8788, rede e certificado.");}
    }
    static void EnsurePrivate(){
        if(!Program.Admin)throw new UnauthorizedAccessException("Autorização administrativa necessária.");
        if(!Program.NoLinks(PrivateDir))throw new IOException("Pasta de vínculo contém link. Operação recusada.");
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        if(Directory.Exists(PrivateDir)){
            var existing=Directory.GetAccessControl(PrivateDir);
            foreach(FileSystemAccessRule rule in existing.GetAccessRules(true,true,typeof(SecurityIdentifier))){string sid=rule.IdentityReference.Value;if(rule.AccessControlType==AccessControlType.Allow&&(rule.FileSystemRights&FileSystemRights.Write)!=0&&sid!="S-1-5-18"&&sid!="S-1-5-32-544")throw new IOException("Pasta de vínculo permite escrita não administrativa. Corrija a instalação.");}
            Directory.SetAccessControl(PrivateDir,acl);
        }else Directory.CreateDirectory(PrivateDir,acl);
    }
    static void Atomic(string path,byte[] bytes){
        if(!Program.NoLinks(path))throw new IOException("Arquivo administrativo contém link.");string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{using(var s=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)){s.Write(bytes,0,bytes.Length);s.Flush(true);}if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);}finally{try{if(File.Exists(temp))File.Delete(temp);}catch{}}
    }
    static Dictionary<string,object> ReadLink(){
        string file=Path.Combine(PrivateDir,"vinculo.dat");if(!File.Exists(file))return null;if(!Program.NoLinks(file)||new FileInfo(file).Length>65536)throw new IOException("Vínculo local inválido.");
        return Parse(Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(file),Encoding.UTF8.GetBytes("LabGuard-Central-v1"),DataProtectionScope.LocalMachine)));
    }
    internal static void Pair(string path,string name,Action<string> report){
        if(!Program.Admin)throw new UnauthorizedAccessException("Abra como administrador.");
        if(String.IsNullOrWhiteSpace(name)||name.Length>64||name.Any(c=>Char.IsControl(c)))throw new InvalidDataException("Informe um nome de estação com até 64 caracteres.");
        if(!Program.NoLinks(path)||new FileInfo(path).Length>32768)throw new InvalidDataException("Arquivo de vínculo inválido.");
        var cfg=Parse(File.ReadAllText(path,Encoding.UTF8));if(Program.Get(cfg,"format")!="labguard-central-v1")throw new InvalidDataException("Selecione o arquivo gerado em Computadores > Vincular computador.");
        string server=ValidateServer(Program.Get(cfg,"server_url")).GetLeftPart(UriPartial.Authority);byte[] cert=Certificate(Program.Get(cfg,"ca_pem"));
        report("Conferindo a Central e seu certificado...");
        var info=Request(server,cert,"/api/agent/managed-info",new Dictionary<string,object>(),null);
        if(Program.Get(info,"managed_protocol")!="1")throw new IOException("A Central precisa da atualização de avisos.");
        EnsurePrivate();
        var response=Request(server,cert,"/api/agent/enroll",new{enrollment_token=Program.Get(cfg,"enrollment_token"),name=name.Trim(),client_version="Jogos-2.2.0"},null);
        string token=Program.Get(response,"device_token"),id=Program.Get(response,"device_id");
        if(!Regex.IsMatch(token,@"^[A-Za-z0-9_-]{32,100}$")||!Regex.IsMatch(id,@"^[a-f0-9]{32}$"))throw new IOException("Credenciais retornadas inválidas.");
        var link=new{server=server,certificate=Convert.ToBase64String(cert),token=token,device_id=id,name=name.Trim()};
        Atomic(Path.Combine(PrivateDir,"vinculo.dat"),ProtectedData.Protect(Encoding.UTF8.GetBytes(Json.Serialize(link)),Encoding.UTF8.GetBytes("LabGuard-Central-v1"),DataProtectionScope.LocalMachine));
        var config=Program.ReadJson(Path.Combine(Program.BaseDir,"config.json"));config["ManagedAppliedRevision"]=0;Atomic(Path.Combine(Program.BaseDir,"config.json"),Encoding.UTF8.GetBytes(Json.Serialize(config)));
        report("Vínculo salvo. O monitor enviará o primeiro contato em aproximadamente 15 segundos.");
    }
    static void Persist(){Atomic(Path.Combine(PrivateDir,"outbox.json"),Encoding.UTF8.GetBytes(Json.Serialize(queue)));}
    internal static void Enqueue(string kind,string process){
        if(running==0)return;
        if(!new[]{"game_closed","client_started","protection_error","cleanup_error","protection_paused"}.Contains(kind))return;
        process=Regex.Replace(process??"",@"[^A-Za-z0-9 ._()\-]","");if(process.Length>96)process=process.Substring(0,96);
        lock(Gate){try{
            string key=kind+"|"+process;DateTime last;if(dedup.TryGetValue(key,out last)&&(DateTime.UtcNow-last).TotalSeconds<10)return;dedup[key]=DateTime.UtcNow;
            if(dedup.Count>500)dedup.Clear();
            if(queue.Count>=500){queue.RemoveAt(0);dropped++;}
            queue.Add(new Dictionary<string,object>{{"id",Guid.NewGuid().ToString("N")},{"kind",kind},{"time",DateTime.UtcNow.ToString("o")},{"process",process}});Persist();
        }catch{dropped++;}}
    }
    internal static void OnLog(string text){if(text.StartsWith("FECHADO | ")){var parts=text.Split('|');if(parts.Length>1)Enqueue("game_closed",parts[1].Trim());}else if(text.StartsWith("FALHA | "))Enqueue("protection_error","");}
    static void Status(string state,string detail){try{var data=new{state=state,detail=detail,updatedUtc=DateTime.UtcNow.ToString("o"),queued=queue.Count,dropped=dropped,version="2.2.0"};Atomic(Path.Combine(Program.DataDir,"central-status.json"),Encoding.UTF8.GetBytes(Json.Serialize(data)));}catch{}}
    static bool Fresh(Dictionary<string,object>d,int seconds){DateTime t;return DateTime.TryParse(Program.Get(d,"updatedUtc"),null,System.Globalization.DateTimeStyles.RoundtripKind,out t)&&(DateTime.UtcNow-t.ToUniversalTime()).TotalSeconds>=-30&&(DateTime.UtcNow-t.ToUniversalTime()).TotalSeconds<seconds;}
    internal static void Start(){
        if(Interlocked.Exchange(ref running,1)!=0)return;
        try{EnsurePrivate();string p=Path.Combine(PrivateDir,"outbox.json");if(File.Exists(p)&&Program.NoLinks(p)&&new FileInfo(p).Length<=262144){var list=Json.Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(p));if(list!=null)queue=list.Take(500).Where(e=>{DateTime t;return DateTime.TryParse(Program.Get(e,"time"),out t)&&t.ToUniversalTime()>DateTime.UtcNow.AddDays(-7);}).ToList();}}
        catch{Status("Falha","Não foi possível preparar o vínculo protegido.");Interlocked.Exchange(ref running,0);return;}
        Enqueue("client_started","");var worker=new Thread(Loop){IsBackground=true,Name="LabGuard Central"};worker.Start();
    }
    static void Loop(){
        string priorGuard="",priorClean="";
        while(true){try{
            var link=ReadLink();if(link==null){Status("Sem vínculo","Importe um vínculo no instalador com a conta administrativa.");Thread.Sleep(15000);continue;}
            var c=Program.ReadJson(Path.Combine(Program.BaseDir,"config.json"));var g=Program.ReadJson(Path.Combine(Program.DataDir,"guard-status.json"));var clean=Program.ReadJson(Path.Combine(Program.DataDir,"status.json"));var youtube=Program.ReadJson(Path.Combine(Program.DataDir,"youtube-status.json"));
            string gs=!Fresh(g,45)?"unknown":Program.Get(g,"state")=="Ativo"?"active":Program.Get(g,"state")=="Pausado"?"paused":"failed";
            string cs=!Fresh(clean,900)?"unknown":Program.Get(clean,"state").IndexOf("falha",StringComparison.OrdinalIgnoreCase)>=0?"failed":Program.Get(clean,"state").IndexOf("pend",StringComparison.OrdinalIgnoreCase)>=0?"pending":Program.Get(clean,"state")=="Executando"?"pending":"ok";
            string ys=youtube.Count==0?"unknown":Program.Get(youtube,"state").StartsWith("FALHA")?"failed":Program.Flag(youtube,"blocked")?"blocked":"allowed";
            if(gs!=priorGuard){if(gs=="failed")Enqueue("protection_error","");if(gs=="paused")Enqueue("protection_paused","");priorGuard=gs;}
            if(cs!=priorClean){if(cs=="failed")Enqueue("cleanup_error","");priorClean=cs;}
            List<Dictionary<string,object>> batch;lock(Gate){queue.RemoveAll(e=>{DateTime t;return !DateTime.TryParse(Program.Get(e,"time"),out t)||t.ToUniversalTime()<DateTime.UtcNow.AddDays(-7);});batch=queue.Take(25).ToList();}
            int revision;Int32.TryParse(Program.Get(c,"ManagedAppliedRevision"),out revision);
            var body=new{device_id=Program.Get(link,"device_id"),name=Program.Get(link,"name"),client_version="Jogos-2.2.0",guard=gs,cleanup=cs,youtube=ys,applied_revision=revision,events=batch};
            var response=Request(Program.Get(link,"server"),Convert.FromBase64String(Program.Get(link,"certificate")),"/api/agent/telemetry",body,Program.Get(link,"token"));
            object ackRaw;var ack=new HashSet<string>();if(response.TryGetValue("ack",out ackRaw)&&ackRaw is IEnumerable){foreach(object v in (IEnumerable)ackRaw)if(v is string)ack.Add((string)v);}
            lock(Gate){queue.RemoveAll(e=>ack.Contains(Program.Get(e,"id")));Persist();}
            object raw;var policy=response.TryGetValue("policy",out raw)?raw as Dictionary<string,object>:null;
            if(policy==null||policy.Keys.Count!=4||!policy.ContainsKey("revision")||!new[]{"cleanup_enabled","close_games","block_youtube"}.All(f=>policy.ContainsKey(f)&&policy[f] is bool))throw new InvalidDataException("Política inesperada; nenhuma alteração aplicada.");
            int remote=Convert.ToInt32(policy["revision"]);if(remote<1)throw new InvalidDataException("Revisão inválida.");
            bool changed=remote!=revision||Program.Flag(c,"Enabled")!=Program.Flag(policy,"cleanup_enabled")||Program.Flag(c,"AutoCloseGames")!=Program.Flag(policy,"close_games")||Program.Flag(c,"BlockYouTube")!=Program.Flag(policy,"block_youtube");
            if(changed){Status("Aplicando","Recebendo as três opções de proteção do administrador.");int code=Program.RunEngine("ManagedApply",Json.Serialize(policy),s=>{});if(code!=0){Enqueue("protection_error","");Status("Falha de aplicação","A Central recebeu o contato, mas a política não foi confirmada. Consulte os registros locais.");Thread.Sleep(15000);continue;}}
            Status("Conectado","Contato confirmado com a Central. Sem envio de imagens ou navegação.");
        }catch(UnauthorizedAccessException){Status("Vínculo revogado","Gere outro vínculo no painel. A proteção local foi mantida.");}catch{Status("Sem contato","Proteção local mantida. Confira o PC administrador, IP, porta 8788 e certificado.");}Thread.Sleep(15000);}
    }
    internal static void SelfTest(){
        foreach(string v in new[]{"https://192.168.15.2:8788","https://127.0.0.1:8788"})ValidateServer(v);
        foreach(string v in new[]{"http://192.168.1.1:8788","https://8.8.8.8","https://192.168.1.1/path","https://user:pass@192.168.1.1","https://example.com"}){bool failed=false;try{ValidateServer(v);}catch{failed=true;}if(!failed)throw new Exception("Invalid server accepted");}
        if(CheckCertificate(new byte[0],null,SslPolicyErrors.None))throw new Exception("Missing certificate accepted");
    }
    internal static int IntegrationTest(string configPath,string output){
        var cfg=Parse(File.ReadAllText(configPath));byte[] cert=Certificate(Program.Get(cfg,"ca_pem"));string server=Program.Get(cfg,"server_url");
        Request(server,cert,"/api/agent/managed-info",new{},null);
        bool refused=false;byte[] wrong=(byte[])cert.Clone();wrong[wrong.Length-1]^=1;
        try{Request(server,wrong,"/api/agent/managed-info",new{},null);}catch{refused=true;}if(!refused)throw new Exception("Wrong certificate accepted");
        var enrolled=Request(server,cert,"/api/agent/enroll",new{enrollment_token=Program.Get(cfg,"enrollment_token"),name="LAB-TESTE",client_version="Jogos-2.2.0"},null);
        string id=Guid.NewGuid().ToString("N");var body=new{device_id=Program.Get(enrolled,"device_id"),name="LAB-TESTE",client_version="Jogos-2.2.0",guard="active",cleanup="ok",youtube="blocked",applied_revision=0,events=new[]{new{id=id,kind="game_closed",time=DateTime.UtcNow.ToString("o"),process="RobloxPlayerBeta"}}};
        var response=Request(server,cert,"/api/agent/telemetry",body,Program.Get(enrolled,"device_token"));Request(server,cert,"/api/agent/telemetry",body,Program.Get(enrolled,"device_token"));
        File.WriteAllText(output,Json.Serialize(response));return 0;
    }
}
sealed class ManagedTray:ApplicationContext {
    readonly NotifyIcon icon;
    internal ManagedTray(){
        icon=new NotifyIcon{Icon=SystemIcons.Shield,Visible=true,Text="LabGuard - computador gerenciado"};
        var menu=new ContextMenuStrip();menu.Items.Add("Computador gerenciado pela instituição",null,(s,e)=>ShowStatus());
        menu.Items.Add("Administração (exige autorização)",null,(s,e)=>{try{Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--setup"){UseShellExecute=true,Verb="runas"});}catch{}});
        icon.ContextMenuStrip=menu;icon.DoubleClick+=(s,e)=>ShowStatus();
        Application.ApplicationExit+=(s,e)=>{icon.Visible=false;icon.Dispose();};
    }
    void ShowStatus(){var state=Program.ReadJson(Path.Combine(Program.DataDir,"central-status.json"));MessageBox.Show("Este computador usa a política de jogos da instituição.\n\nCentral: "+Program.Get(state,"state","aguardando contato")+"\nNão são enviadas capturas de tela ou histórico de navegação por esta conexão.\n\nAs alterações de proteção exigem a conta administrativa.","LabGuard",MessageBoxButtons.OK,MessageBoxIcon.Information);}
}
sealed class ManagedSetup:Form {
    readonly TextBox file,name,log;readonly Button install,pick,advanced;readonly Label status;bool busy;
    internal ManagedSetup(bool smoke){
        Text="LabGuard Cliente 2.2 - instalar e conectar";Size=new Size(760,640);MinimumSize=new Size(680,590);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(246,244,251);
        var panel=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=8,Padding=new Padding(24)};Controls.Add(panel);
        foreach(int h in new[]{65,64,42,65,40,50,0,35})panel.RowStyles.Add(h==0?new RowStyle(SizeType.Percent,100):new RowStyle(SizeType.Absolute,h));
        panel.Controls.Add(new Label{Text="LabGuard Cliente\nInstalação e conexão em uma única tela",Font=new Font("Segoe UI",16,FontStyle.Bold),Dock=DockStyle.Fill,ForeColor=Color.FromArgb(84,46,163)},0,0);
        panel.Controls.Add(new Label{Text="Depois de instalar, inicia com o Windows, sem abrir o painel para o aluno.\nOs avisos aparecem na Central do administrador. O programa continua identificado no Windows.",Dock=DockStyle.Fill},0,1);
        var row=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2};row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,170));
        file=new TextBox{ReadOnly=true,Dock=DockStyle.Fill};pick=new Button{Text="Selecionar vínculo…",Dock=DockStyle.Fill};pick.Click+=(s,e)=>{using(var d=new OpenFileDialog{Filter="Vínculo LabGuard (*.json)|*.json",Title="Arquivo gerado na Central do administrador"})if(d.ShowDialog(this)==DialogResult.OK)file.Text=d.FileName;};row.Controls.Add(file,0,0);row.Controls.Add(pick,1,0);panel.Controls.Add(row,0,2);
        var nr=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=2};nr.RowStyles.Add(new RowStyle(SizeType.Absolute,25));nr.RowStyles.Add(new RowStyle(SizeType.Percent,100));nr.Controls.Add(new Label{Text="Nome desta estação (ex.: LAB-01)",Dock=DockStyle.Fill},0,0);name=new TextBox{Text=Environment.MachineName,MaxLength=64,Dock=DockStyle.Fill};nr.Controls.Add(name,0,1);panel.Controls.Add(nr,0,3);
        status=new Label{Text="Selecione um vínculo individual gerado em Computadores → Vincular computador.",Dock=DockStyle.Fill};panel.Controls.Add(status,0,4);
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill};install=new Button{Text="Instalar e conectar",AutoSize=true,Padding=new Padding(12,6,12,6),Enabled=!smoke};advanced=new Button{Text="Opções avançadas",AutoSize=true,Padding=new Padding(8,6,8,6),Enabled=!smoke};buttons.Controls.Add(install);buttons.Controls.Add(advanced);panel.Controls.Add(buttons,0,5);
        log=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,Font=new Font("Consolas",9)};panel.Controls.Add(log,0,6);
        panel.Controls.Add(new Label{Text="Jogos: fechamento nominal 2 s • Limpeza: 5 min • Central: 15 s • Sem capturas",Dock=DockStyle.Fill,Padding=new Padding(0,8,0,0)},0,7);
        install.Click+=(s,e)=>BeginInstall();advanced.Click+=(s,e)=>Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--advanced"){UseShellExecute=true,Verb="runas"});FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};
        if(smoke){var timer=new System.Windows.Forms.Timer{Interval=1700};timer.Tick+=(s,e)=>{timer.Stop();Close();timer.Dispose();};Shown+=(s,e)=>timer.Start();}
    }
    void Append(string text){if(IsDisposed)return;try{BeginInvoke((Action)(()=>{if(log.TextLength>50000)log.Clear();log.AppendText(text+Environment.NewLine);log.SelectionStart=log.TextLength;log.ScrollToCaret();}));}catch{}}
    void BeginInstall(){
        if(busy)return;if(String.IsNullOrWhiteSpace(file.Text)){MessageBox.Show(this,"Selecione o arquivo de vínculo gerado pelo painel atualizado do administrador.");return;}
        if(MessageBox.Show(this,"Instalar proteção e conectar esta estação à Central?\n\nJogos reconhecidos serão fechados e removidos permanentemente; saves/mundos podem ser perdidos. Faça backup antes.\n\nO cliente enviará nome da estação, estado da proteção e nome do jogo encerrado. Não enviará telas, arquivos ou histórico de navegação.\n\nUse apenas nos computadores administrados pela instituição.","Confirmar política",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
        string path=file.Text,alias=name.Text;busy=true;install.Enabled=false;pick.Enabled=false;advanced.Enabled=false;status.Text="Instalando e conectando…";
        ThreadPool.QueueUserWorkItem(delegate{bool ok=false;string result;try{int code=Program.RunEngine("Install",null,Append);if(code!=0)throw new IOException("A instalação não foi concluída. Confira o registro e pause a limpeza anterior antes de atualizar, se solicitado.");CentralLink.Pair(path,alias,Append);ok=true;result="Instalado. Confira o primeiro contato e os avisos no PC administrador.";}catch(Exception ex){result=ex.Message;Append(result);}try{BeginInvoke((Action)(()=>{busy=false;install.Enabled=true;pick.Enabled=true;advanced.Enabled=true;status.Text=result;if(ok)MessageBox.Show(this,"Cliente instalado e vinculado. Você pode fechar esta janela.\n\nA proteção continua automaticamente; o primeiro contato aparecerá na Central.","LabGuard");}));}catch{}});
    }
}
}
