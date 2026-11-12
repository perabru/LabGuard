"""Build-time assembly of the reviewed games engine and managed UI extensions."""
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parents[1]
D=ROOT/'games/dist'
BUILD=ROOT/'managed/build'
ASSETS=BUILD/'assets'
ASSETS.mkdir(parents=True,exist_ok=True)
def one(text,before,after):
    if text.count(before)!=1: raise RuntimeError('Assembly anchor missing/ambiguous: '+before[:100])
    return text.replace(before,after)

def prepare_games():
    ps=(D/'Engine.assembled.ps1').read_text(encoding='utf-8-sig').replace('2.1.0','2.2.0')
    ps=one(ps,"'GameCloseOff')][string]$Mode", "'GameCloseOff','ManagedApply')][string]$Mode")
    entry="    Assert-Admin\n    if($Mode -eq 'GuardInit')"
    code=r'''    Assert-Admin
    if($Mode -eq 'ManagedApply'){
        $received=ConvertFrom-Json -InputObject $env:LG_APPROVED_FOLDER
        $keys=@($received.PSObject.Properties.Name)
        if($keys.Count -ne 4 -or @($keys|Where-Object {$_ -notin @('revision','cleanup_enabled','close_games','block_youtube')}).Count -ne 0){throw 'Politica remota fora do escopo.'}
        foreach($k in @('cleanup_enabled','close_games','block_youtube')){if($received.$k -isnot [bool]){throw 'Politica deve conter somente opcoes booleanas.'}}
        $revision=0;if(-not[int]::TryParse([string]$received.revision,[ref]$revision) -or $revision -lt 1){throw 'Revisao de politica invalida.'}
        Read-Config
        $script:Config.Enabled=$received.cleanup_enabled
        $script:Config.AutoCloseGames=$received.close_games
        $script:Config.BlockYouTube=$received.block_youtube
        $script:Config.Screenshots=$false
        Write-Config
        Apply-YouTube ([bool]$received.block_youtube)
        if($received.cleanup_enabled){Enable-ScheduledTask -TaskName $TaskName|Out-Null}else{Disable-ScheduledTask -TaskName $TaskName|Out-Null}
        Read-Config;$script:Config|Add-Member -NotePropertyName ManagedAppliedRevision -NotePropertyValue $revision -Force;Write-Config
        Log 'CENTRAL' ('Politica de protecao confirmada: '+$revision);exit 0
    }
    if($Mode -eq 'GuardInit')'''
    ps=one(ps,entry,code)
    ps=one(ps,'Read-Config; $script:Config.Enabled=$true; Write-Config','Read-Config; $script:Config.Enabled=$true; $script:Config.Screenshots=$false; Write-Config')
    (D/'Engine.assembled.ps1').write_text(ps,encoding='utf-8-sig')
    cs=(D/'LabGuard.assembled.cs').read_text(encoding='utf-8-sig').replace('2.1.0','2.2.0')
    cs=one(cs,'"GameCloseOff"};','"GameCloseOff","ManagedApply"};')
    cs=one(cs,'            if(args.Length>0&&args[0]=="--self-test")', '''            if(args.Length>0&&args[0]=="--central-self-test"){CentralLink.SelfTest();return 0;}
            if(args.Length==3&&args[0]=="--central-integration")return CentralLink.IntegrationTest(args[1],args[2]);
            if(args.Length>0&&args[0]=="--self-test")''')
    cs=one(cs,'            bool smoke=args.Contains("--ui-smoke");', '''            if(args.Contains("--monitor")){Application.Run(new ManagedTray());return 0;}
            if(args.Contains("--setup-smoke")){Application.Run(new ManagedSetup(true));return 0;}
            if(!args.Contains("--ui-smoke")&&!args.Contains("--advanced")){
                if(!Admin){try{Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--setup"){UseShellExecute=true,Verb="runas"});}catch{}return 0;}
                using(var setup=new ManagedSetup(false)){Application.Run(setup);}return 0;
            }
            bool smoke=args.Contains("--ui-smoke");''')
    (D/'LabGuard.assembled.cs').write_text(cs,encoding='utf-8-sig')
    guard=(D/'Guardian.assembled.cs').read_text(encoding='utf-8-sig').replace('2.1.0','2.2.0')
    guard=one(guard,'static void WriteLog(string text){try{','static void WriteLog(string text){CentralLink.OnLog(text);try{')
    guard=one(guard,'if(Program.RunEngine("GuardInit",null,WriteLog)!=0)return 2;','if(Program.RunEngine("GuardInit",null,WriteLog)!=0)return 2; CentralLink.Start();')
    (D/'Guardian.assembled.cs').write_text(guard,encoding='utf-8-sig')

def prepare_panel():
    for f in ('index.html','app.js','app.css'):shutil.copy2(ROOT/'central/assets'/f,ASSETS/f)
    html=(ASSETS/'index.html').read_text()
    html=one(html,'        <button class="nav-link" data-view="help">','        <button class="nav-link" data-view="alerts"><span class="nav-symbol" aria-hidden="true">!</span><span>Avisos e proteção</span><span id="nav-alert-count" class="nav-count">0</span></button>\n        <button class="nav-link" data-view="help">')
    html=one(html,'      <section class="stats"', '''      <div id="alert-banner" class="notice info-notice" role="status" hidden><strong id="alert-banner-text"></strong><button class="button secondary compact" data-view="alerts">Ver avisos</button></div>
      <section class="stats"''')
    section='''      <section id="view-alerts" class="view" hidden aria-labelledby="alerts-heading">
        <div class="panel"><div class="panel-heading"><div><h2 id="alerts-heading">Avisos dos computadores</h2><p>Jogo encerrado, falha de proteção, pausa ou perda de comunicação. Sem capturas de tela.</p></div><button id="ack-alerts" class="button secondary">Marcar como conferidos</button></div>
        <div class="device-note"><button id="enable-alert-notifications" class="button secondary compact">Ativar notificações neste navegador</button><p id="notification-state">Mantenha este painel aberto e autenticado para ver novos avisos.</p></div>
        <div class="table-scroll"><table><thead><tr><th>Recebido</th><th>Computador</th><th>Ocorrência</th><th>Estado</th></tr></thead><tbody id="alerts-body"></tbody></table></div><p id="alerts-empty" class="panel-footnote">Nenhum aviso recebido. Vincule uma estação e confira o primeiro contato.</p><p class="panel-footnote">Últimos 200 avisos; retenção de até 7 dias e limite de 10 mil eventos. A falta de contato não prova que um aluno desligou a proteção.</p></div>
        <div class="panel"><div class="panel-heading"><div><h2>Proteção dos clientes Jogos 2.2</h2><p id="managed-policy-revision"></p></div></div><form id="managed-policy-form" class="managed-form">
        <label class="check-label"><input type="checkbox" id="managed-cleanup_enabled"> Proteção e limpeza automática a cada 5 minutos</label>
        <label class="check-label"><input type="checkbox" id="managed-close_games"> Fechar jogos reconhecidos (depende da proteção ativa)</label>
        <label class="check-label"><input type="checkbox" id="managed-block_youtube"> Bloquear YouTube</label>
        <p>Aplica-se a todos os clientes Jogos 2.2 vinculados. Não reinstala jogos removidos. Capturas não fazem parte deste canal.</p>
        <button type="submit" id="save-managed-policy" class="button primary">Aplicar proteção</button><p id="managed-policy-result" role="status"></p></form></div>
      </section>
'''
    html=one(html,'      <section id="view-help"',section+'      <section id="view-help"')
    html=html.replace('Técnico → Importar vínculo','Selecionar vínculo → Instalar e conectar (Jogos 2.2)').replace('Abra o LabGuard Cliente atualizado como administrador. Após instalar a proteção, acesse','Abra o cliente Jogos 2.2 como administrador e use')
    html=html.replace('Os sites da escola,<br>sob seu controle.','Seu laboratório,<br>com avisos em tempo real.').replace('Gestão de sites da escola','Sites, proteção e avisos da escola')
    (ASSETS/'index.html').write_text(html)
    js=(ASSETS/'app.js').read_text()
    js=one(js,'      help: ["Como usar",','      alerts: ["Avisos e proteção", "Acompanhe jogos encerrados, falhas e computadores sem contato."],\n      help: ["Como usar",')
    js=one(js,'    snapshot = result;','    snapshot = result;\n    renderManaged(result);')
    js=one(js,' + " com regras atualizadas"',' + " com estado confirmado"')
    js=one(js,'    }, 15000);','    }, 5000);')
    js=one(js,'      if (document.querySelector("dialog[open]") || document.hidden)','      if (document.querySelector("dialog[open]"))')
    before='''      revisionCell.append(textNode("span", device.applied_revision == null ? "Ainda não aplicada" : "#" + number(device.applied_revision), "revision-value"));
      if (device.applied_revision !== snapshot.revision && !device.revoked) revisionCell.append(textNode("span", "Atual: #" + number(snapshot.revision), "row-subtitle"));'''
    after='''      if (device.managed) {
        revisionCell.append(textNode("span", "Proteção #" + number(device.managed.applied_revision), "revision-value"));
        revisionCell.append(textNode("span", "Atual: #" + number(snapshot.managed_policy?.revision) + " · Jogos/YouTube", "row-subtitle"));
        statusCell.append(textNode("span", "Monitor: " + ({active:"ativo",paused:"pausado",failed:"falha",unknown:"sem confirmação"}[device.managed.guard] || "sem confirmação"), "row-subtitle"));
      } else {
        revisionCell.append(textNode("span", device.applied_revision == null ? "Ainda não aplicada" : "#" + number(device.applied_revision), "revision-value"));
        if (device.applied_revision !== snapshot.revision && !device.revoked) revisionCell.append(textNode("span", "Atual: #" + number(snapshot.revision), "row-subtitle"));
      }'''
    js=one(js,before,after)
    js=one(js,'  function renderState(result) {',(ROOT/'managed/panel.js').read_text()+'\n  function renderState(result) {')
    (ASSETS/'app.js').write_text(js)
    css=(ASSETS/'app.css').read_text()+'\n.managed-form{padding:0 24px 24px;display:grid;gap:16px}.managed-form p{max-width:75ch;color:var(--muted,#62596d)}#alert-banner{display:flex;align-items:center;justify-content:space-between;gap:20px}#alert-banner[hidden]{display:none}#view-alerts>.panel{margin-bottom:24px}\n'
    (ASSETS/'app.css').write_text(css)
    source=(ROOT/'central/labguard_tecnico.py').read_text().replace('CENTRAL_VERSION = "1.0.0"','CENTRAL_VERSION = "1.1.0"').replace('Controle os sites de todos os computadores vinculados.','Sites, proteção e avisos dos computadores vinculados.')
    (BUILD/'labguard_tecnico.py').write_text(source)
    core=(ROOT/'central/labguard_central.py').read_text()
    (BUILD/'labguard_central.py').write_text(core)

if __name__=='__main__':
    import sys
    if '--panel-only' not in sys.argv:prepare_games()
    prepare_panel()
    print('Prepared managed client 2.2 and Central 1.1 assets.')
