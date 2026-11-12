using System;
using System.IO;
using System.Drawing;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;
namespace LabGuardGames {
static class AutomaticInstaller {
    internal static int Run(Action<string> report){
        if(!Program.Admin)throw new UnauthorizedAccessException("Autorize uma conta administrativa no UAC do Windows.");
        bool created,owned=false;var security=new MutexSecurity();
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid),MutexRights.FullControl,AccessControlType.Allow));
        using(var mutex=new Mutex(false,"Global\\LabGuardJogos2-Installation",out created,security)){
            try{
                try{owned=mutex.WaitOne(0);}catch(AbandonedMutexException){owned=true;}
                if(!owned){report("Outra instalacao do LabGuard esta em andamento.");return 5;}
                report("Preparando instalacao e atualizacao automatica...");
                int code=Program.RunEngine("Install",null,report);
                if(code!=0&&code!=2)return code;
                report("Conferindo o monitor, o inicio com o Windows e os bloqueios...");
                int health=Program.RunEngine("InstallHealth",null,report);
                return health==0&&code==0?0:2;
            }finally{if(owned)mutex.ReleaseMutex();}
        }
    }
}
sealed class AutomaticSetup:Form {
    readonly Button start,connect,advanced,close;
    readonly TextBox log;readonly Label state;readonly ProgressBar progress;
    readonly bool smoke,autoStart;bool busy;
    internal AutomaticSetup(bool smoke,bool autoStart){
        this.smoke=smoke;this.autoStart=autoStart;
        Text="LabGuard 2.4 - protecao automatica";Size=new Size(820,650);MinimumSize=new Size(700,570);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(247,245,251);AutoScaleMode=AutoScaleMode.Dpi;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=7,Padding=new Padding(24)};
        foreach(int height in new[]{68,94,54,38,56,0,38})root.RowStyles.Add(height==0?new RowStyle(SizeType.Percent,100):new RowStyle(SizeType.Absolute,height));Controls.Add(root);
        root.Controls.Add(new Label{Text="LabGuard\nProtecao automatica em um passo",Dock=DockStyle.Fill,Font=new Font("Segoe UI",19,FontStyle.Bold),ForeColor=Color.FromArgb(91,48,173)},0,0);
        root.Controls.Add(new Label{Text="Fechamento de jogos reconhecidos + limpeza a cada 5 minutos.\nBloqueios locais: YouTube, Termo, Friv, Poki e Chess.com.\nInicia com o Windows. Nao exige arquivo de vinculo ou painel aberto.\nJoguester: informe o endereco correto no painel para inclui-lo.",Dock=DockStyle.Fill},0,1);
        state=new Label{Text="Pronto para ativar neste computador.",Dock=DockStyle.Fill,Font=new Font("Segoe UI",12,FontStyle.Bold),ForeColor=Color.FromArgb(51,39,73)};root.Controls.Add(state,0,2);
        progress=new ProgressBar{Dock=DockStyle.Top,Height=12,Style=ProgressBarStyle.Marquee,MarqueeAnimationSpeed=0};root.Controls.Add(progress,0,3);
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoScroll=true};start=new Button{Text="Instalar / atualizar e ativar",AutoSize=true,Padding=new Padding(8),Enabled=!smoke};connect=new Button{Text="Conectar ao painel (opcional)",AutoSize=true,Padding=new Padding(8),Enabled=!smoke};advanced=new Button{Text="Opcoes avancadas",AutoSize=true,Padding=new Padding(8),Enabled=!smoke};buttons.Controls.Add(start);buttons.Controls.Add(connect);buttons.Controls.Add(advanced);root.Controls.Add(buttons,0,4);
        log=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,BackColor=Color.White,Font=new Font("Consolas",9)};root.Controls.Add(log,0,5);
        close=new Button{Text="Fechar",Dock=DockStyle.Right,Width=125};close.Click+=(s,e)=>Close();root.Controls.Add(close,0,6);
        start.Click+=(s,e)=>BeginInstall();advanced.Click+=(s,e)=>OpenAdvanced();connect.Click+=(s,e)=>Pair();FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};
        Shown+=(s,e)=>{
            if(smoke){var timer=new System.Windows.Forms.Timer{Interval=1400};timer.Tick+=(a,b)=>{timer.Stop();timer.Dispose();Close();};timer.Start();}
            else if(autoStart)BeginInvoke((Action)BeginInstall);
            else ShowSavedStatus();
        };
    }
    void ShowSavedStatus(){try{var s=Program.ReadJson(Path.Combine(Program.DataDir,"install-status.json"));if(s.Count>0)state.Text=Program.Get(s,"state")=="ready"?"Instalacao confirmada. Use o painel para administrar.":"A instalacao tem pendencias. Confira os registros.";}catch{state.Text="Nao foi possivel ler a confirmacao anterior.";}}
    void Append(string message){if(IsDisposed)return;try{BeginInvoke((Action)(()=>{if(log.TextLength>90000)log.Clear();log.AppendText(message+Environment.NewLine);log.SelectionStart=log.TextLength;log.ScrollToCaret();}));}catch(InvalidOperationException){}}
    void SetBusy(bool value){busy=value;start.Enabled=!value;connect.Enabled=!value;advanced.Enabled=!value;close.Enabled=!value;progress.MarqueeAnimationSpeed=value?25:0;}
    void BeginInstall(){
        if(busy||smoke)return;
        string warning="Ativar o LabGuard automaticamente neste computador?\n\nJogos reconhecidos serao fechados e removidos. Saves e mundos podem ser perdidos permanentemente. Faca backup antes.\n\nSem vinculo: jogos e os sites listados ficam bloqueados por padrao. Com vinculo existente: a politica do administrador e preservada.\n\nO programa fica identificado no Windows. Nao ha capturas ocultas. Instale somente nos computadores administrados pela instituicao.";
        if(MessageBox.Show(this,warning,"Confirmar ativacao",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes){state.Text="Nenhuma instalacao iniciada.";return;}
        SetBusy(true);state.Text="Instalando e verificando automaticamente...";
        ThreadPool.QueueUserWorkItem(delegate{int code=1;string error=null;try{code=AutomaticInstaller.Run(Append);}catch(Exception ex){error=ex.Message;Append("ERRO: "+error);}int result=code;
            try{BeginInvoke((Action)(()=>{SetBusy(false);
                if(result==0){var saved=Program.ReadJson(Path.Combine(Program.DataDir,"install-status.json"));state.Text=Program.Flag(saved,"protectionEnabled")?"Protecao local confirmada. Pode fechar esta janela.":"Instalado. A politica da Central esta pausada.";Append("Instalacao concluida. A limpeza e o monitor continuam sem esta janela. Reabra os navegadores para testar os bloqueios.");}
                else state.Text=result==2?"Instalado com pendencias. Veja os detalhes abaixo.":error??"Nao foi possivel concluir. Confira os registros e tente novamente.";
            }));}catch(InvalidOperationException){}
        });
    }
    void OpenAdvanced(){try{Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--advanced"){UseShellExecute=true,Verb="runas"});}catch(Exception ex){MessageBox.Show(this,ex.Message,"LabGuard");}}
    void Pair(){
        if(!File.Exists(Path.Combine(Program.BaseDir,"config.json"))){MessageBox.Show(this,"Ative primeiro a protecao neste computador. O vinculo e opcional e pode ser feito depois.","LabGuard");return;}
        string path;using(var d=new OpenFileDialog{Filter="Vinculo LabGuard (*.json)|*.json",Title="Selecione o vinculo individual gerado na Central 1.2"}){if(d.ShowDialog(this)!=DialogResult.OK)return;path=d.FileName;}
        if(MessageBox.Show(this,"Conectar este computador a Central indicada no arquivo?\n\nO painel passara a definir a politica e recebera o nome da estacao, o estado e eventos de jogos encerrados. Nao sao enviados telas, arquivos ou historico de navegacao.","Vincular estacao",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
        SetBusy(true);state.Text="Conectando a Central...";
        ThreadPool.QueueUserWorkItem(delegate{string result;try{CentralLink.Pair(path,Environment.MachineName,Append);result="Vinculo salvo. Confira o primeiro contato na Central.";}catch(Exception ex){result="Protecao local mantida. Vinculo: "+ex.Message;}try{BeginInvoke((Action)(()=>{SetBusy(false);state.Text=result;Append(result);}));}catch{}});
    }
}
}
