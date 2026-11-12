"""Add versioned quick-site support after the maintained 2.2 assembly stage."""
from pathlib import Path
import sys
from prepare import one
R=Path(__file__).resolve().parents[1]
D=R/'games/dist';B=R/'managed/build';A=B/'assets'

def panel():
    html=(A/'index.html').read_text(encoding='utf-8')
    html=one(html,'        <button class="nav-link" data-view="alerts">','        <button class="nav-link" data-view="websites"><span class="nav-symbol" aria-hidden="true">▣</span><span>Sites rápidos</span></button>\n        <button class="nav-link" data-view="alerts">')
    section='''      <section id="view-websites" class="view" hidden aria-labelledby="web-heading">
        <div class="panel"><div class="panel-heading"><div><h2 id="web-heading">Sites rápidos</h2><p>Termo, Friv, Poki, Chess.com, Joguester (após informar o endereço) e YouTube.</p></div><button id="web-block-all" class="button primary">Bloquear tudo</button></div>
        <p class="panel-footnote"><strong>Bloquear tudo = todos os sites desta lista.</strong> Não corta a internet inteira, não ativa desinstalações e não altera as outras categorias do catálogo legado.</p>
        <p id="web-status-line" class="panel-footnote" role="status"></p>
        <div class="table-scroll"><table><thead><tr><th>Site</th><th>Domínios</th><th>Regra solicitada</th><th>Ações</th></tr></thead><tbody id="web-sites-body"></tbody></table></div>
        <p id="web-result" class="panel-footnote" role="status"></p>
        <p class="panel-footnote">Requer Cliente Jogos 2.3. Aplica políticas a Chrome, Edge e Firefox, incluindo subdomínios. Reabra os navegadores e teste na conta do aluno. Liberar retira somente esta regra; exceções ou bloqueios de outros administradores continuam independentes.</p></div>
      </section>
      <dialog id="web-edit-dialog"><form id="web-edit-form"><h2>Editar endereço: <span id="web-edit-label"></span></h2><input id="web-edit-id" type="hidden"><label for="web-edit-domains">Domínios ou links do site, um por linha (até 6)</label><textarea id="web-edit-domains" rows="4" maxlength="3000" placeholder="exemplo.com"></textarea><label class="check-label"><input id="web-edit-blocked" type="checkbox"> Solicitar bloqueio após salvar</label><p>Não use * nem o domínio de um provedor inteiro. Informe somente o endereço do jogo.</p><p id="web-edit-error" role="alert"></p><div class="dialog-actions"><button type="button" id="web-edit-cancel" class="button secondary">Cancelar</button><button type="submit" id="web-edit-save" class="button primary">Salvar endereço</button></div></form></dialog>
'''
    html=one(html,'      <section id="view-alerts"',section+'      <section id="view-alerts"')
    html=html.replace('Jogos 2.2','Jogos 2.3').replace('<span>Sites e regras</span>','<span>Sites — Cliente 1.x</span>')
    (A/'index.html').write_text(html,encoding='utf-8')
    js=(A/'app.js').read_text(encoding='utf-8')
    js=one(js,'      alerts: [','      websites: ["Sites rápidos", "Bloqueie os sites de jogos em lote ou individualmente nos clientes 2.3."],\n      alerts: [')
    js=one(js,'    renderManaged(result);','    renderManaged(result);\n    renderWebSites(result);')
    js=one(js,'  function renderState(result) {',(R/'managed/webpanel.js').read_text(encoding='utf-8')+'\n  function renderState(result) {')
    js=one(js,'        statusCell.append(textNode("span", "Monitor: "', '''        const webText = !device.web ? "Sites: atualize o cliente para 2.3" : "Sites #" + number(device.web.revision) + " · " + (device.web_confirmed ? "lista aplicada" : device.web.status === "failed" ? "falha de aplicação" : "aguardando confirmação");
        revisionCell.append(textNode("span", webText, "row-subtitle"));
        statusCell.append(textNode("span", "Monitor: "''')
    js=js.replace('Jogos 2.2','Jogos 2.3')
    (A/'app.js').write_text(js,encoding='utf-8')
    with (A/'app.css').open('a',encoding='utf-8') as f:f.write('\n#web-edit-dialog{max-width:560px;width:calc(100vw - 40px);border:1px solid #d5caeb;border-radius:16px;padding:24px}#web-edit-form{display:grid;gap:16px}#web-edit-domains{width:100%;padding:12px;font:inherit}#web-edit-error{color:#a72a3d}.web-domain{overflow-wrap:anywhere}#web-sites-body td{vertical-align:top}#web-sites-body td:last-child{min-width:230px}#web-block-all{white-space:nowrap}\n')
    p=B/'labguard_tecnico.py';p.write_text(p.read_text(encoding='utf-8').replace('1.1.0','1.2.0'),encoding='utf-8')

def games():
    ps=(D/'Engine.assembled.ps1').read_text(encoding='utf-8-sig').replace('2.2.0','2.3.0')
    ps=one(ps,"'ManagedApply')][string]$Mode","'ManagedApply','ManagedWeb')][string]$Mode")
    ps=one(ps,'    Assert-Admin\n    if($Mode',"    Assert-Admin\n    if($Mode -eq 'ManagedWeb'){Apply-CentralSites (ConvertFrom-Json -InputObject $env:LG_APPROVED_FOLDER);exit 0}\n    if($Mode")
    entry="try {\n    if ($Mode -eq 'Test')"
    ps=one(ps,entry,(R/'managed/WebSites.ps1').read_text(encoding='utf-8')+'\n'+entry)
    ps=one(ps,'function Remove-Extensions {\n','function Remove-Extensions {\n    $script:Config|Add-Member -NotePropertyName CentralSiteDomains -NotePropertyValue @() -Force\n')
    (D/'Engine.assembled.ps1').write_text(ps,encoding='utf-8-sig')
    cs=(D/'LabGuard.assembled.cs').read_text(encoding='utf-8-sig').replace('2.2.0','2.3.0')
    cs=one(cs,'"ManagedApply"};','"ManagedApply","ManagedWeb"};')
    (D/'LabGuard.assembled.cs').write_text(cs,encoding='utf-8-sig')
    p=D/'Guardian.assembled.cs';p.write_text(p.read_text(encoding='utf-8-sig').replace('2.2.0','2.3.0'),encoding='utf-8-sig')
    cs=(R/'managed/ManagedClient.cs').read_text(encoding='utf-8').replace('2.2.0','2.3.0').replace('Cliente 2.2','Cliente 2.3')
    cs=cs.replace('"/api/agent/telemetry"','"/api/agent/telemetry-web"')
    cs=one(cs,'if(Program.Get(info,"managed_protocol")!="1")','if(Program.Get(info,"managed_protocol")!="1"||Program.Get(info,"web_protocol")!="1")')
    cs=one(cs,'        string priorGuard="",priorClean="";','        string priorGuard="",priorClean="";DateTime nextWebCheck=DateTime.MinValue;')
    cs=one(cs,'            int revision;Int32.TryParse', '            int webRevision;Int32.TryParse(Program.Get(c,"CentralSitesRevision"),out webRevision);\n            var ws=Program.ReadJson(Path.Combine(Program.DataDir,"web-status.json"));string webState=Program.Get(ws,"state","unknown");if(!new[]{"applied","pending","failed","unknown"}.Contains(webState))webState="unknown";\n            int revision;Int32.TryParse')
    cs=one(cs,'applied_revision=revision,events=batch','applied_revision=revision,events=batch,web_revision=webRevision,web_status=webState')
    anchor='            Status("Conectado","Contato confirmado com a Central. Sem envio de imagens ou navegação.");'
    insert='''            object webRaw;var wp=response.TryGetValue("web_policy",out webRaw)?webRaw as Dictionary<string,object>:null;
            if(wp==null||wp.Count!=2||!wp.ContainsKey("revision")||!wp.ContainsKey("blocked_domains")||!(wp["blocked_domains"] is IEnumerable)||wp["blocked_domains"] is string)throw new InvalidDataException("Política de sites inválida.");
            int wr=Convert.ToInt32(wp["revision"]);if(wr<1)throw new InvalidDataException("Revisão de sites inválida.");
            var domains=new List<string>();foreach(object d in (IEnumerable)wp["blocked_domains"]){if(!(d is string)||((string)d).Length>253||!Regex.IsMatch((string)d,@"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"))throw new InvalidDataException("Domínio inválido.");domains.Add((string)d);}if(domains.Count>30)throw new InvalidDataException("Lista acima do limite.");
            if(wr!=webRevision||webState!="applied"||DateTime.UtcNow>=nextWebCheck){
                int code=Program.RunEngine("ManagedWeb",Json.Serialize(wp),s=>{});nextWebCheck=DateTime.UtcNow.AddMinutes(5);
                if(code!=0){Status("Falha nos sites","A lista de sites não foi confirmada. Confira os registros locais e a Central.");Thread.Sleep(15000);continue;}
            }
'''+anchor
    cs=one(cs,anchor,insert)
    cs=one(cs,'applied_revision=0,events=new[]{','applied_revision=0,web_revision=0,web_status="unknown",events=new[]{')
    cs=one(cs,'config["ManagedAppliedRevision"]=0;','config["ManagedAppliedRevision"]=0;config["CentralSitesRevision"]=0;')
    cs=one(cs,'    internal static void Pair(string path,string name,Action<string> report){','    internal static bool HasSavedLink { get {return File.Exists(Path.Combine(PrivateDir,"vinculo.dat"));} }\n    internal static void Pair(string path,string name,Action<string> report){')
    cs=one(cs,'if(String.IsNullOrWhiteSpace(file.Text)){MessageBox.Show', 'if(String.IsNullOrWhiteSpace(file.Text)&&!CentralLink.HasSavedLink){MessageBox.Show')
    cs=one(cs,'CentralLink.Pair(path,alias,Append);','if(!String.IsNullOrWhiteSpace(path))CentralLink.Pair(path,alias,Append);else Append("Vínculo administrativo existente preservado. Confira o primeiro contato na Central 1.2.");')
    cs=one(cs,'        install.Click+=(s,e)=>BeginInstall();','        if(CentralLink.HasSavedLink){install.Text="Atualizar e manter vínculo";status.Text="Vínculo existente encontrado. Selecione outro arquivo somente para trocar de Central.";}\n        install.Click+=(s,e)=>BeginInstall();')
    (B/'ManagedClient.cs').write_text(cs,encoding='utf-8-sig')

if __name__=='__main__':
    panel()
    if '--panel-only' not in sys.argv:games()
    print('Prepared Client 2.3 / Central 1.2 quick website catalog.')
