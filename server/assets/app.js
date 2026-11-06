"use strict";

(() => {
  const el = id => document.getElementById(id);
  let token = "";
  let role = "viewer";
  let snapshot = null;
  let lastSuccess = 0;
  let busy = false;
  let gatewayWriting = false;
  let dbBusy = false;
  let dbSyncing = false;
  let dbSites = [];
  let dbEditing = null;
  let generation = 0;
  let controller = null;
  const activeControllers = new Set();
  let lastActivity = Date.now();

  function text(tag, value, className) {
    const item = document.createElement(tag);
    item.textContent = String(value ?? "");
    if (className) item.className = className;
    return item;
  }
  function message(id, value) {
    el(id).textContent = value || "";
    el(id).hidden = !value;
  }
  function stamp(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value || "—") : date.toLocaleString("pt-BR");
  }
  function badge(value, kind) { return text("span", value, `state-badge ${kind || ""}`); }
  function canWrite(kind) {
    if (!token || role !== "admin" || !snapshot || busy || dbBusy || dbSyncing || Date.now() - lastSuccess > 20000) return false;
    if (snapshot.mode === "demo") return true;
    const health = snapshot.health || {};
    return kind === "device" ? health.firewall === true && health.forwarding === true : health.dns === true;
  }
  function syncControls() {
    el("refresh").disabled = busy || dbBusy || !token;
    el("login-button").disabled = busy || dbBusy;
    el("add-domain").disabled = !canWrite("domain");
    el("new-domain").disabled = !canWrite("domain");
    el("ai-toggle").disabled = !canWrite("domain") || !snapshot?.policies?.ai_block;
    document.querySelectorAll("[data-write-kind]").forEach(button => {
      button.disabled = !canWrite(button.dataset.writeKind) || button.dataset.protected === "true";
    });
    const fresh = !!snapshot && Date.now() - lastSuccess <= 20000;
    el("fresh-dot").className = `status-dot ${fresh ? "fresh" : "stale"}`;
    const editable = canEditDB();
    for (const id of ["db-save", "db-domain", "db-category", "db-enabled", "db-notes", "db-import-text", "db-import-category", "db-import-button"]) el(id).disabled = !editable;
    for (const id of ["db-search-button", "db-export"]) el(id).disabled = !token || gatewayWriting || dbBusy;
    el("db-sync").disabled = !canWrite("domain");
    el("db-sync").textContent = dbSyncing ? "Aplicando lote…" : "Aplicar lista no gateway";
    document.querySelectorAll("[data-db-write]").forEach(button => { button.disabled = !editable; });
  }
  function canEditDB() { return !!token && role === "admin" && !gatewayWriting && !dbBusy && !dbSyncing; }
  function logout() {
    generation += 1;
    controller?.abort();
    activeControllers.forEach(item => item.abort()); activeControllers.clear();
    controller = null;
    token = "";
    role = "viewer";
    snapshot = null;
    lastSuccess = 0;
    busy = false;
    gatewayWriting = false;
    dbBusy = false; dbSyncing = false; dbSites = []; dbEditing = null;
    el("token").value = "";
    ["devices", "domains", "events", "audit", "ai-domains", "health", "db-sites"].forEach(id => el(id).replaceChildren());
    resetDBForm();
    el("db-search").value = ""; el("db-filter-category").value = ""; el("db-filter-enabled").value = ""; el("db-import-text").value = "";
    message("db-message", "");
    el("workspace").hidden = true;
    el("login").hidden = false;
    message("login-error", "");
    message("action-error", "");
    syncControls();
    el("token").focus();
  }
  async function api(path, body, expectSnapshot = true) {
    const requestController = new AbortController();
    controller = requestController;
    activeControllers.add(requestController);
    const timeout = setTimeout(() => requestController.abort(), 45000);
    try {
      const response = await fetch(path, {
        method: body ? "POST" : "GET", credentials: "omit", cache: "no-store",
        headers: { "Authorization": `Bearer ${token}`, "Accept": "application/json", ...(body ? {"Content-Type": "application/json"} : {}) },
        body: body ? JSON.stringify(body) : undefined, signal: requestController.signal
      });
      let result;
      try { result = await response.json(); } catch { throw new Error("O servidor retornou uma resposta inválida."); }
      if (!response.ok || result.ok !== true) {
        const error = new Error(result.error || "A operação não foi concluída.");
        error.status = response.status;
        throw error;
      }
      if (!result.data || !["admin", "viewer"].includes(result.role) || (expectSnapshot && !["demo", "gateway"].includes(result.data.mode))) throw new Error("Resposta incompatível com o painel.");
      return result;
    } finally { clearTimeout(timeout); activeControllers.delete(requestController); if (controller === requestController) controller = null; }
  }
  function emptyRow(body, columns, label) {
    const row = document.createElement("tr");
    const cell = text("td", label, "empty");
    cell.colSpan = columns;
    row.append(cell); body.append(row);
  }
  function actionButton(label, className, kind, callback, protectedAction = false) {
    const button = text("button", label, `button row-action ${className}`);
    button.type = "button";
    button.dataset.writeKind = kind;
    button.dataset.protected = String(protectedAction);
    button.addEventListener("click", callback);
    return button;
  }
  function render() {
    const data = snapshot;
    const metrics = data.metrics || {};
    el("metric-devices").textContent = metrics.observed_devices ?? (data.devices || []).length;
    el("metric-blocked").textContent = metrics.blocked_devices ?? 0;
    el("metric-queries").textContent = metrics.queries_window ?? (data.events || []).length;
    el("metric-dns-blocked").textContent = metrics.blocked_events_window ?? 0;
    el("role").textContent = role === "admin" ? "Administração" : "Somente consulta";
    const gateway = data.gateway || {};
    el("gateway-label").textContent = `${gateway.hostname || "Gateway"} · ${gateway.lab_cidr || "Rede configurada"}`;
    el("mode-banner").textContent = data.mode === "demo" ? "DEMONSTRAÇÃO — dados fictícios. Nenhuma regra é aplicada à rede." : "GATEWAY REAL — ações administrativas afetam a rede configurada.";
    el("mode-banner").className = `mode-banner ${data.mode === "gateway" ? "live" : ""}`;
    el("updated").textContent = `Atualizado em ${stamp(data.timestamp)} · consulta automática a cada 5 s`;
    el("health").replaceChildren();
    for (const [key, name] of [["firewall", "Firewall"], ["dns", "DNS / DHCP"], ["forwarding", "Encaminhamento"]]) {
      const item = document.createElement("div"); item.className = "health-item";
      item.append(text("strong", name), badge(data.health?.[key] === true ? "Ativo" : "Indisponível", data.health?.[key] === true ? "ok" : "off"));
      el("health").append(item);
    }
    const warnings = Array.isArray(data.warnings) ? data.warnings.slice(0, 10).join(" · ") : "";
    el("warnings").textContent = warnings; el("warnings").hidden = !warnings;
    el("devices").replaceChildren();
    const devices = Array.isArray(data.devices) ? data.devices : [];
    el("device-count").textContent = devices.length;
    for (const device of devices.slice(0, 1000)) {
      const row = document.createElement("tr");
      const name = document.createElement("td"); name.append(text("strong", device.name || "Sem nome"));
      if (device.protected) name.append(text("small", "Equipamento protegido"));
      const address = document.createElement("td"); address.append(text("strong", device.ip), text("small", device.mac || "MAC não observado"));
      const state = text("td", device.state || "Observada");
      const access = document.createElement("td"); access.append(badge(device.blocked ? "Suspensa" : "Permitida", device.blocked ? "off" : "ok"));
      const action = document.createElement("td");
      action.append(actionButton(device.protected ? "Protegida" : device.blocked ? "Restaurar" : "Suspender", device.blocked ? "success" : "danger", "device", () => mutate("set_device_block", {ip: device.ip, blocked: !device.blocked}, `${device.blocked ? "Restaurar" : "Suspender"} a internet de ${device.name || "máquina"} (${device.ip})?`, "device"), !!device.protected));
      row.append(name, address, state, access, action); el("devices").append(row);
    }
    if (!devices.length) emptyRow(el("devices"), 5, "Nenhuma máquina observada na amostra disponível.");
    const policy = data.policies?.ai_block;
    el("ai-state").textContent = policy ? policy.enabled ? "Ativo" : "Desativado" : "Indisponível";
    el("ai-state").className = `state-badge ${policy?.enabled ? "ok" : ""}`;
    el("ai-description").textContent = policy ? `${policy.services?.length || 0} serviços e ${policy.domain_count || 0} domínios no catálogo. Ativar aplica a lista ao laboratório inteiro.` : "O agente conectado não disponibiliza o perfil de IA.";
    el("ai-toggle").textContent = policy?.enabled ? "Desativar bloqueio de IA" : "Ativar bloqueio de IA";
    el("ai-domains").replaceChildren();
    for (const domain of (policy?.domains || []).slice(0, 1000)) el("ai-domains").append(text("li", domain));
    el("domains").replaceChildren();
    const domains = Array.isArray(data.domains) ? data.domains : [];
    el("domain-count").textContent = domains.length;
    for (const domain of domains.slice(0, 1000)) {
      const row = document.createElement("tr"); const source = domain.source === "ai_profile";
      const action = document.createElement("td");
      action.append(actionButton(source ? "Perfil IA" : "Remover", "quiet", "domain", () => mutate("remove_domain", {domain: domain.domain}, `Remover o bloqueio manual de ${domain.domain}? O domínio continuará bloqueado se também pertencer ao perfil IA ativo.`, "domain"), source));
      row.append(text("td", domain.domain), text("td", source ? "Perfil IA" : "Manual"), action); el("domains").append(row);
    }
    if (!domains.length) emptyRow(el("domains"), 3, "Nenhum domínio cadastrado.");
    el("audit").replaceChildren();
    for (const record of (data.audit || []).slice(0, 7)) {
      const item = document.createElement("li"); item.append(text("strong", record.action || "Ação administrativa"), text("p", `${record.target || ""} · ${record.outcome || ""}`), text("small", stamp(record.time))); el("audit").append(item);
    }
    if (!el("audit").children.length) el("audit").append(text("li", "Nenhum registro administrativo disponível."));
    el("events").replaceChildren();
    for (const event of (data.events || []).slice(0, 12)) {
      const row = document.createElement("tr"); row.append(text("td", stamp(event.time)), text("td", event.client_ip), text("td", event.domain), text("td", event.status || "Consulta")); el("events").append(row);
    }
    if (!el("events").children.length) emptyRow(el("events"), 4, "Nenhuma consulta DNS na amostra disponível.");
    syncControls();
  }
  async function refresh(login = false) {
    if (busy || dbBusy || dbSyncing || !token) return;
    busy = true; syncControls(); const current = generation;
    el("request-status").textContent = "Consultando gateway…";
    try {
      const result = await api("/api/snapshot");
      if (current !== generation) return;
      snapshot = result.data; role = result.role; lastSuccess = Date.now();
      el("workspace").hidden = false; el("login").hidden = true;
      message("login-error", ""); message("action-error", ""); render();
      el("request-status").textContent = "Dados recebidos com sucesso.";
    } catch (error) {
      if (current !== generation) return;
      lastSuccess = 0;
      if (error.status === 401) { logout(); message("login-error", "Token inválido ou acesso encerrado. Informe um token autorizado."); }
      else {
        const detail = error.name === "AbortError" ? "O servidor não respondeu a tempo. Confira o estado antes de repetir uma alteração." : error.message;
        message(login ? "login-error" : "action-error", detail);
        el("request-status").textContent = "Atualização indisponível. Ações de alteração desabilitadas.";
      }
    } finally { if (current === generation) { busy = false; syncControls(); } }
  }
  async function mutate(action, params, confirmation, kind) {
    if (!canWrite(kind)) { message("action-error", "Atualize os dados e use um perfil administrativo antes de alterar a rede."); return; }
    if (!window.confirm(confirmation + "\n\nA ação vale para a rede do gateway configurado. No modo demonstração ela é apenas simulada.")) return;
    busy = true; gatewayWriting = true; syncControls(); const current = generation;
    el("request-status").textContent = "Aplicando alteração…";
    try {
      const result = await api("/api/action", {action, params});
      if (current !== generation) return;
      snapshot = result.data; role = result.role; lastSuccess = Date.now(); render();
      message("action-error", ""); el("request-status").textContent = "Alteração concluída. Estado atualizado.";
    } catch (error) {
      if (current !== generation) return;
      lastSuccess = 0;
      if (error.status === 401) { logout(); message("login-error", "Acesso encerrado. Informe um token autorizado."); }
      else message("action-error", error.name === "AbortError" ? "Tempo esgotado. A alteração pode ter sido aplicada. Atualize o painel antes de tentar novamente." : error.message);
    } finally { if (current === generation) { busy = false; gatewayWriting = false; syncControls(); } }
  }
  function dbMessage(value, failed = false) {
    el("db-message").className = `message ${failed ? "error" : ""}`;
    message("db-message", value);
  }
  function dbPath() {
    const query = new URLSearchParams();
    const search = el("db-search").value.trim();
    if (search) query.set("q", search);
    if (el("db-filter-category").value) query.set("category", el("db-filter-category").value);
    if (el("db-filter-enabled").value) query.set("enabled", el("db-filter-enabled").value);
    return "/api/banlist" + (query.size ? "?" + query.toString() : "");
  }
  function resetDBForm() {
    dbEditing = null;
    el("db-form-title").textContent = "Novo registro";
    el("db-domain").value = ""; el("db-domain").readOnly = false;
    el("db-category").value = "Jogos"; el("db-enabled").checked = true; el("db-notes").value = "";
  }
  function renderDB(data) {
    dbSites = Array.isArray(data.sites) ? data.sites : [];
    const active = dbSites.filter(site => site.enabled && !site.deleted).length;
    el("db-summary").textContent = `${dbSites.length} registro(s) nesta consulta · ${active} ativo(s) · ${dbSites.length - active} inativo(s) ou excluído(s)` + (Number.isFinite(data.summary?.pending) ? ` · ${data.summary.pending} pendência(s) de aplicação` : "");
    el("db-sites").replaceChildren();
    for (const site of dbSites.slice(0, 1000)) {
      const row = document.createElement("tr");
      const name = document.createElement("td"); name.append(text("strong", site.domain), text("small", site.notes || `Revisão ${site.revision ?? "—"}`));
      const status = document.createElement("td"); status.append(badge(site.deleted ? "Excluído" : site.enabled ? "Ativo" : "Inativo", site.enabled && !site.deleted ? "ok" : "off"));
      const actions = document.createElement("td"); actions.className = "db-row-actions";
      const edit = text("button", "Editar", "button row-action quiet"); edit.type = "button"; edit.dataset.dbWrite = "true";
      edit.addEventListener("click", () => {
        if (!canEditDB()) return;
        dbEditing = site;
        el("db-form-title").textContent = "Editar registro";
        el("db-domain").value = site.domain; el("db-domain").readOnly = true;
        el("db-category").value = site.category === "Inteligência artificial" ? "IA" : site.category;
        if (!el("db-category").value) el("db-category").value = "Outros";
        el("db-enabled").checked = !!site.enabled; el("db-notes").value = site.notes || "";
        el("db-notes").focus();
      });
      const remove = text("button", "Excluir", "button row-action danger"); remove.type = "button"; remove.dataset.dbWrite = "true";
      remove.addEventListener("click", () => {
        if (!canEditDB() || !window.confirm(`Excluir ${site.domain} do banco gerenciado?\n\nEssa alteração é local. Para refletir a remoção no gateway, aplique a lista depois. Regras manuais e do perfil IA serão preservadas.`)) return;
        dbOperation("/api/banlist/delete", {domain: site.domain, expected_revision: site.revision}, "Registro excluído no banco. A rede ainda não foi alterada.");
      });
      actions.append(edit); if (!site.deleted) actions.append(remove);
      row.append(name, text("td", site.category), status, actions); el("db-sites").append(row);
    }
    if (!dbSites.length) emptyRow(el("db-sites"), 4, "Nenhum registro encontrado. Cadastre ou importe os domínios desejados.");
    if (dbSites.length > 1000) dbMessage("A tabela exibe os primeiros 1.000 registros. Use os filtros ou exporte o banco completo.");
    syncControls();
  }
  function handleDBError(error) {
    if (error.status === 401) { logout(); message("login-error", "Token inválido ou acesso encerrado."); }
    else dbMessage(error.name === "AbortError" ? "A consulta ao banco excedeu o tempo limite. Consulte o estado antes de repetir uma alteração." : error.message, true);
  }
  async function authenticateDB() {
    const current = generation; dbBusy = true; syncControls(); let connected = false;
    try {
      const result = await api("/api/banlist", undefined, false);
      if (current !== generation) return;
      role = result.role;
      el("role").textContent = role === "admin" ? "Administração" : "Somente consulta";
      el("workspace").hidden = false; el("login").hidden = true;
      el("mode-banner").textContent = "GATEWAY SEM DADOS — o banco local está disponível; aguarde a consulta da rede.";
      message("login-error", ""); renderDB(result.data); connected = true;
    } catch (error) {
      if (current !== generation) return;
      token = "";
      message("login-error", error.status === 401 ? "Token inválido. Informe um token autorizado." : error.message);
    } finally {
      if (current === generation) {
        dbBusy = false; syncControls();
        if (connected) { refresh(); setTimeout(() => pollSync(current, true), 1000); }
      }
    }
  }
  async function loadDB() {
    if (!token || dbBusy || gatewayWriting) { dbMessage("Aguarde a operação atual antes de consultar o banco."); return; }
    const current = generation; dbBusy = true; syncControls();
    try {
      const result = await api(dbPath(), undefined, false);
      if (current !== generation) return;
      role = result.role; renderDB(result.data);
    } catch (error) { if (current === generation) handleDBError(error); }
    finally { if (current === generation) { dbBusy = false; syncControls(); } }
  }
  async function dbOperation(path, body, success) {
    if (!canEditDB()) { dbMessage("Use um perfil administrativo e aguarde as operações em andamento.", true); return; }
    const current = generation; dbBusy = true; syncControls();
    try {
      const result = await api(path, body, false);
      if (current !== generation) return;
      role = result.role;
      const updated = await api(dbPath(), undefined, false);
      if (current !== generation) return;
      renderDB(updated.data); resetDBForm();
      const errors = Array.isArray(result.data.errors) ? result.data.errors.length : 0;
      dbMessage(success + (errors ? ` ${errors} item(ns) não foram importados; confira a lista.` : ""), errors > 0);
      if (path.endsWith("/import")) el("db-import-text").value = "";
    } catch (error) { if (current === generation) handleDBError(error); }
    finally { if (current === generation) { dbBusy = false; syncControls(); } }
  }
  async function startSync() {
    if (!canWrite("domain")) { dbMessage("Atualize os dados do gateway e use um perfil administrativo para aplicar a lista.", true); return; }
    if (!window.confirm("Aplicar um lote de até 20 alterações pendentes do banco no gateway?\n\nCada domínio pode reiniciar brevemente o DNS/DHCP. Uma falha pode deixar o lote parcialmente aplicado. Confira o resultado antes de repetir. Regras manuais e do perfil IA serão preservadas.\n\nSair do painel não cancela um lote já iniciado.")) return;
    const current = generation; dbBusy = true; dbSyncing = true; syncControls();
    try {
      const result = await api("/api/banlist/sync", {}, false);
      if (current !== generation) return;
      dbMessage("Lote autorizado. A aplicação ocorre em segundo plano; aguarde o resultado.");
      if (!result.data.running) finishSync(result.data.report || result.data);
      else setTimeout(() => pollSync(current), 3000);
    } catch (error) {
      if (current === generation) {
        if (error.status === 401 || error.status === 403) { dbSyncing = false; handleDBError(error); }
        else {
          dbSyncing = true;
          dbMessage("Não foi possível confirmar o início do lote. Consultando o estado do servidor antes de liberar novas alterações.", true);
          setTimeout(() => pollSync(current, true), 3000);
        }
      }
    }
    finally { if (current === generation) { dbBusy = false; syncControls(); } }
  }
  function finishSync(report) {
    dbSyncing = false;
    const applied = Array.isArray(report.applied) ? report.applied.length : Number(report.applied || 0);
    const errors = Array.isArray(report.errors) ? report.errors.length : 0;
    const pending = Number(report.pending || 0);
    dbMessage(`Lote concluído: ${applied} alteração(ões) aplicada(s), ${errors} falha(s) e ${pending} pendência(s).` + (pending ? " Consulte a lista e aplique outro lote quando desejar." : ""), errors > 0);
    if (report.snapshot && ["gateway", "demo"].includes(report.snapshot.mode)) { snapshot = report.snapshot; lastSuccess = Date.now(); render(); }
  }
  async function pollSync(current, initial = false) {
    if (current !== generation || !token) return;
    if (gatewayWriting || dbBusy) { setTimeout(() => pollSync(current, initial), 3000); return; }
    dbBusy = true; syncControls(); let again = false; let reload = false;
    try {
      const result = await api("/api/banlist/sync-status", undefined, false);
      if (current !== generation) return;
      dbSyncing = !!result.data.running;
      if (dbSyncing) { dbMessage("Aplicando lote no gateway. O banco está temporariamente bloqueado para edição."); again = true; }
      else if (!initial) {
        if (result.data.error) dbMessage(`O lote não foi concluído: ${result.data.error}. Consulte o gateway antes de repetir.`, true);
        else if (result.data.report) finishSync(result.data.report);
        reload = true;
      }
    } catch (error) {
      if (current === generation) {
        if (error.status === 401) handleDBError(error);
        else if (!initial || dbSyncing) { dbMessage("Não foi possível consultar o lote. O servidor pode continuar aplicando as alterações; aguarde nova consulta.", true); again = true; }
      }
    } finally {
      if (current === generation) {
        dbBusy = false; syncControls();
        if (again) setTimeout(() => pollSync(current), 3000);
        else if (reload) loadDB();
      }
    }
  }
  async function exportDB() {
    if (!token || gatewayWriting || dbBusy) return;
    const current = generation; dbBusy = true; syncControls();
    const exportController = new AbortController(); controller = exportController;
    activeControllers.add(exportController);
    const timeout = setTimeout(() => exportController.abort(), 20000);
    try {
      const response = await fetch("/api/banlist/export", {credentials: "omit", cache: "no-store", signal: exportController.signal, headers: {"Authorization": `Bearer ${token}`, "Accept": "text/csv"}});
      if (!response.ok) {
        let detail = {}; try { detail = await response.json(); } catch { /* Generic error below. */ }
        const error = new Error(detail.error || "Não foi possível exportar o banco."); error.status = response.status; throw error;
      }
      const blob = await response.blob();
      if (current !== generation) return;
      if (blob.size > 32 * 1024 * 1024) throw new Error("A exportação excedeu o limite de 32 MB do painel.");
      const url = URL.createObjectURL(blob); const link = document.createElement("a");
      link.href = url; link.download = "LabGuard-banco-sites.csv"; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      dbMessage("Exportação CSV solicitada. O arquivo inclui os registros do banco, sem token de acesso.");
    } catch (error) { if (current === generation) handleDBError(error); }
    finally { clearTimeout(timeout); activeControllers.delete(exportController); if (controller === exportController) controller = null; if (current === generation) { dbBusy = false; syncControls(); } }
  }
  el("db-filter").addEventListener("submit", event => { event.preventDefault(); loadDB(); });
  el("db-filter-category").addEventListener("change", loadDB);
  el("db-filter-enabled").addEventListener("change", loadDB);
  el("db-export").addEventListener("click", exportDB);
  el("db-sync").addEventListener("click", startSync);
  el("db-cancel").addEventListener("click", resetDBForm);
  el("db-form").addEventListener("submit", event => {
    event.preventDefault();
    const payload = {domain: el("db-domain").value.trim(), category: el("db-category").value, enabled: el("db-enabled").checked, notes: el("db-notes").value.trim()};
    if (!payload.domain) return;
    if (dbEditing) payload.expected_revision = dbEditing.revision;
    dbOperation("/api/banlist/upsert", payload, "Registro salvo no banco. A rede ainda não foi alterada.");
  });
  el("db-import-button").addEventListener("click", () => {
    const raw = el("db-import-text").value;
    const domains = raw.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    const payload = {domains, category: el("db-import-category").value};
    if (!domains.length || domains.length > 100 || new TextEncoder().encode(raw).length > 8192 || new TextEncoder().encode(JSON.stringify(payload)).length > 8192) { dbMessage("Importe entre 1 e 100 domínios, um por linha, em até 8 KB incluindo os dados da solicitação.", true); return; }
    dbOperation("/api/banlist/import", payload, "Lista importada para o banco. A rede ainda não foi alterada.");
  });
  el("login-button").addEventListener("click", () => {
    if (busy || dbBusy) return;
    const value = el("token").value.trim(); el("token").value = "";
    if (!value || value.length > 512) { message("login-error", "Informe um token de acesso válido."); return; }
    token = value; lastActivity = Date.now(); generation += 1; authenticateDB();
  });
  el("token").addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); el("login-button").click(); } });
  el("logout").addEventListener("click", logout);
  el("refresh").addEventListener("click", () => refresh());
  el("ai-toggle").addEventListener("click", () => {
    const enabled = !snapshot?.policies?.ai_block?.enabled;
    mutate("set_ai_block", {enabled}, `${enabled ? "Ativar" : "Desativar"} o catálogo de bloqueio de serviços de IA para todo o laboratório? O serviço DNS/DHCP será reiniciado brevemente. Bloqueios manuais serão preservados.`, "domain");
  });
  el("domain-form").addEventListener("submit", event => {
    event.preventDefault(); const domain = el("new-domain").value.trim();
    if (!domain) return;
    mutate("add_domain", {domain, category: "Outros"}, `Bloquear ${domain} e seus subdomínios no laboratório inteiro? O serviço DNS/DHCP será reiniciado brevemente.`, "domain");
  });
  window.addEventListener("pagehide", () => { token = ""; activeControllers.forEach(item => item.abort()); activeControllers.clear(); });
  ["pointerdown", "keydown"].forEach(name => document.addEventListener(name, () => { lastActivity = Date.now(); }, {passive: true}));
  setInterval(() => {
    if (token && Date.now() - lastActivity > 600000) {
      logout(); message("login-error", "A sessão foi encerrada após 10 minutos sem interação. Informe o token para entrar novamente.");
      return;
    }
    syncControls(); if (token && !busy && !dbBusy && !document.hidden) refresh();
  }, 5000);
  syncControls();
})();
