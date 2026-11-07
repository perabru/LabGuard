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
  let resourceBusy = false;
  let mapObjectURL = "";
  let mapSnapshotTime = "";
  let mapCacheState = "";
  const downloadObjectURLs = new Set();
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
  function supports(action) {
    if (!snapshot || snapshot.mode === "observation") return false;
    const capabilities = snapshot.capabilities || {};
    const name = {add_domain: "domain_filtering", remove_domain: "domain_filtering", set_ai_block: "ai_block", set_device_block: "device_internet_cut", set_address_block: "address_blocking"}[action];
    return !!name && capabilities[name] === true && (action !== "set_ai_block" || capabilities.domain_filtering === true);
  }
  function sourceRecent() {
    if (snapshot?.mode === "demo") return true;
    const identification = snapshot?.identification;
    if (!identification || identification.time_status !== "fresh" || identification.facts?.read_success === false || identification.facts?.collection_metadata_valid === false) return false;
    const collected = new Date(identification.timestamp).getTime();
    const age = Date.now() - collected;
    return Number.isFinite(age) && age >= 0 && age <= 20000;
  }
  function canWrite(action) {
    if (!token || role !== "admin" || !snapshot || busy || dbBusy || dbSyncing || Date.now() - lastSuccess > 20000) return false;
    if (!sourceRecent()) return false;
    if (!supports(action)) return false;
    if (snapshot.mode === "demo") return true;
    const health = snapshot.health || {};
    return ["set_device_block", "set_address_block"].includes(action) ? health.firewall === true && health.forwarding === true : health.dns === true;
  }
  function syncControls() {
    el("refresh").disabled = busy || dbBusy || !token;
    el("login-button").disabled = busy || dbBusy;
    el("add-domain").disabled = !canWrite("add_domain");
    el("new-domain").disabled = !canWrite("add_domain");
    el("ai-toggle").disabled = !canWrite("set_ai_block") || !snapshot?.policies?.ai_block;
    document.querySelectorAll("[data-write-kind]").forEach(button => {
      button.disabled = !canWrite(button.dataset.writeKind) || button.dataset.protected === "true" || button.dataset.unavailable === "true";
    });
    const responseRecent = !!snapshot && Date.now() - lastSuccess <= 20000;
    const fresh = responseRecent && sourceRecent();
    el("workspace").dataset.sampleState = fresh ? "fresh" : "stale";
    el("fresh-dot").className = `status-dot ${fresh ? "fresh" : "stale"}`;
    const editable = canEditDB();
    for (const id of ["db-save", "db-domain", "db-category", "db-enabled", "db-notes", "db-import-text", "db-import-category", "db-import-button"]) el(id).disabled = !editable;
    for (const id of ["db-search-button", "db-export"]) el(id).disabled = !token || gatewayWriting || dbBusy;
    el("db-sync").disabled = !canWrite("add_domain") || !canWrite("remove_domain");
    el("db-sync").textContent = dbSyncing ? "Aplicando lote…" : "Aplicar lista no equipamento";
    document.querySelectorAll("[data-db-write]").forEach(button => { button.disabled = !editable; });
    for (const id of ["map-load", "download-svg", "download-html", "download-csv", "download-pdf"]) el(id).disabled = !token || resourceBusy;
    el("map-load").textContent = resourceBusy ? "Consultando arquivo…" : mapObjectURL ? "Atualizar mapa" : "Carregar mapa";
    const sample = snapshot ? `Amostra do painel: ${stamp(snapshot.timestamp)}.` : "Nenhuma amostra carregada neste painel.";
    el("report-state").textContent = `${fresh ? "Dados recentes." : "Dados desatualizados ou indisponíveis no painel."} ${sample} Os arquivos usam o último estado armazenado no servidor.`;
    if (mapObjectURL && mapSnapshotTime !== snapshot?.timestamp) el("map-status").textContent = "O painel recebeu outra amostra. Atualize o mapa para consultar o estado armazenado no servidor.";
    if (mapObjectURL && (!fresh || mapCacheState === "stale")) el("map-status").textContent = "Mapa de uma amostra anterior; o estado atual da rede não está confirmado.";
    renderIdentification(responseRecent);
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
    resourceBusy = false; clearMap();
    downloadObjectURLs.forEach(url => URL.revokeObjectURL(url)); downloadObjectURLs.clear();
    el("token").value = "";
    ["devices", "domains", "events", "audit", "ai-domains", "health", "db-sites"].forEach(id => el(id).replaceChildren());
    resetDBForm();
    el("db-search").value = ""; el("db-filter-category").value = ""; el("db-filter-enabled").value = ""; el("db-import-text").value = "";
    message("db-message", "");
    message("report-message", "");
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
      if (!result.data || !["admin", "viewer"].includes(result.role) || (expectSnapshot && !["demo", "gateway", "observation", "equipment"].includes(result.data.mode))) throw new Error("Resposta incompatível com o painel.");
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
  function hasAddressRule(kind, address, device) {
    if (!address) return false;
    if (device[kind === "ip" ? "blocked_ip" : "blocked_mac"] === true) return true;
    return (Array.isArray(snapshot.address_blocks) ? snapshot.address_blocks : []).some(rule => rule.kind === kind && String(rule.address).toLowerCase() === String(address).toLowerCase());
  }
  function addressButton(device, kind, blocked) {
    const address = device[kind];
    const exists = hasAddressRule(kind, address, device);
    const label = `${blocked ? "Bloquear" : "Desbloquear"} ${kind.toUpperCase()}`;
    const button = actionButton(label, blocked ? "danger" : "quiet", "set_address_block", () => {
      if (!address || (blocked ? device.observed !== true || exists : !exists)) return;
      const scope = kind === "ip" ? "Este IP pode ser atribuído a outra máquina no futuro. A regra MAC permanece independente." : "A regra usa o endereço MAC informado pelo equipamento. Uma regra por IP pode continuar suspendendo o acesso.";
      mutate("set_address_block", {kind, address, blocked}, `${label} ${address}?\n\n${scope}\nUma regra por máquina também pode manter o acesso suspenso.`);
    }, !!device.protected);
    button.dataset.unavailable = String(!address || (blocked ? device.observed !== true || exists : !exists));
    button.title = device.protected ? "Equipamento protegido" : !address ? "Endereço não disponível" : blocked && device.observed !== true ? "Novos bloqueios exigem uma máquina observada na amostra" : `${label}: regra independente`;
    return button;
  }
  function wifiEvidence(device) {
    const supplied = value => typeof value === "string" && value.trim() ? value.trim() : "";
    const ssid = supplied(device.ssid) || supplied(device.wifi_ssid) || supplied(device.wifi?.ssid);
    const accessPoint = supplied(device.access_point) || supplied(device.ap) || supplied(device.wifi?.access_point);
    return `${ssid ? `SSID: ${ssid}` : "SSID desconhecido"} · ${accessPoint ? `AP: ${accessPoint}` : "AP desconhecido"}`;
  }
  function domainImpact() {
    return snapshot?.mode === "gateway" ? "O DNS/DHCP do gateway legado será reiniciado brevemente. Caches e conexões abertas podem continuar." : "A aplicação usa os recursos de filtragem do equipamento conectado. O resultado depende da configuração de DNS da rede; caches e conexões abertas podem continuar.";
  }
  function renderIdentification(responseRecent) {
    const result = snapshot?.identification;
    const supplied = result && typeof result === "object" ? result : {};
    const status = ["partial", "unavailable", "demo"].includes(supplied.status) ? supplied.status : "unavailable";
    const sourceAge = Date.now() - new Date(supplied.timestamp).getTime();
    const previous = !!snapshot && (!responseRecent || supplied.time_status === "stale" || Number.isFinite(sourceAge) && sourceAge > 20000);
    const notConfirmed = !!snapshot && !sourceRecent();
    const labels = {partial: "Amostra parcial", unavailable: "Identificação indisponível", demo: "Demonstração"};
    el("inventory-state").textContent = `${snapshot ? labels[status] : "Aguardando leitura"}${previous ? " · dados anteriores" : notConfirmed ? " · leitura não confirmada" : ""}`;
    el("inventory-state").className = `state-badge ${status === "unavailable" || previous || notConfirmed ? "off" : ""}`;
    el("inventory-summary").textContent = previous ? "Esta é a amostra anterior. A identificação atual da rede não foi confirmada; os registros continuam visíveis para consulta." : supplied.summary || "Consulte a fonte configurada para conhecer as evidências disponíveis. Uma lista vazia não comprova que não há equipamentos na rede.";
    el("inventory-source").textContent = `Fonte: ${supplied.source_label || "não confirmada"}`;
    const count = key => Number.isInteger(supplied.counts?.[key]) && supplied.counts[key] >= 0 ? supplied.counts[key] : 0;
    el("inventory-counts").textContent = `${count("local_devices")} endereço(s) local(is) informado(s) · ${count("observed_neighbors")} vizinho(s) com evidência · ${count("unique_ips")} IP(s) · ${count("known_macs")} MAC(s)`;
    el("inventory-time").textContent = supplied.timestamp ? `Coleta: ${stamp(supplied.timestamp)}` : "Horário da coleta não confirmado";
    el("inventory-next").textContent = previous || notConfirmed ? "Atualize a leitura e confira a fonte antes de tomar uma decisão. Nenhum resumo concede permissão de bloqueio." : supplied.next_action || "Confira o modo e a configuração da fonte antes de prosseguir.";
    el("inventory-gaps").replaceChildren();
    const gaps = Array.isArray(supplied.gaps) ? supplied.gaps.filter(value => typeof value === "string").slice(0, 12) : [];
    for (const gap of gaps) el("inventory-gaps").append(text("li", gap));
    if (!gaps.length) el("inventory-gaps").append(text("li", "A amostra não garante identificar todas as máquinas, seus usuários ou todo o tráfego."));
    el("refresh").textContent = snapshot?.mode === "observation" ? "Identificar minha rede" : "Atualizar";
  }
  function render() {
    const data = snapshot;
    const metrics = data.metrics || {};
    const capabilities = data.capabilities || {};
    el("metric-devices").textContent = data.identification?.counts?.devices ?? metrics.observed_devices ?? (data.devices || []).length;
    el("metric-blocked").textContent = data.mode === "observation" ? "—" : metrics.blocked_devices ?? 0;
    el("metric-queries").textContent = capabilities.dns_history === true ? metrics.queries_window ?? (data.events || []).length : "—";
    el("metric-dns-blocked").textContent = capabilities.dns_history === true ? metrics.blocked_events_window ?? 0 : "—";
    el("role").textContent = role === "admin" ? "Administração" : "Somente consulta";
    const gateway = data.gateway || {};
    el("gateway-label").textContent = `${gateway.hostname || (data.mode === "observation" ? "Observação local" : "Equipamento conectado")} · ${gateway.lab_cidr || "Escopo informado pela fonte"}`;
    const modes = {
      demo: "DEMONSTRAÇÃO — dados fictícios. Nenhuma regra é aplicada à rede.",
      observation: "OBSERVAÇÃO LOCAL — consulta parcial pela conexão deste computador. Este modo não bloqueia a rede nem mostra todo o tráfego.",
      equipment: "EQUIPAMENTO CONECTADO — dados e controles dependem do modelo, da configuração e das permissões informadas pela conexão.",
      gateway: "GATEWAY LEGADO — conexão opcional ao agente Linux. Ações administrativas afetam a rede configurada."
    };
    el("mode-banner").textContent = modes[data.mode];
    el("mode-banner").className = `mode-banner ${data.mode === "observation" ? "observation" : ["gateway", "equipment"].includes(data.mode) ? "live" : ""}`;
    const supported = Object.entries({inventory: "inventário", domain_filtering: "filtragem de sites", address_blocking: "regras por IP / MAC", device_internet_cut: "regras por máquina", ai_block: "bloqueio de IA", dns_history: "histórico DNS", port_control: "controle de portas"}).filter(([key]) => capabilities[key] === true).map(([, name]) => name);
    el("capability-summary").textContent = `Recursos informados pela fonte: ${supported.length ? supported.join(" · ") : "nenhum recurso confirmado"}. ${data.mode === "observation" ? "O banco de sites continua disponível para cadastro local." : "Os botões também exigem perfil administrativo, dados recentes e serviços ativos."}`;
    el("updated").textContent = `Atualizado em ${stamp(data.timestamp)} · consulta automática a cada 5 s`;
    el("health").replaceChildren();
    for (const [key, name, applicable] of [["firewall", "Firewall", capabilities.address_blocking === true || capabilities.device_internet_cut === true], ["dns", "DNS", capabilities.domain_filtering === true || capabilities.dns_history === true], ["forwarding", "Encaminhamento", capabilities.address_blocking === true || capabilities.device_internet_cut === true]]) {
      const item = document.createElement("div"); item.className = "health-item";
      item.append(text("strong", name), badge(!applicable ? "Sem recurso" : data.health?.[key] === true ? "Ativo" : "Indisponível", applicable && data.health?.[key] === true ? "ok" : applicable ? "off" : ""));
      el("health").append(item);
    }
    const warnings = Array.isArray(data.warnings) ? data.warnings.slice(0, 10).join(" · ") : "";
    el("warnings").textContent = warnings; el("warnings").hidden = !warnings;
    el("devices").replaceChildren();
    const devices = Array.isArray(data.devices) ? data.devices : [];
    el("device-count").textContent = `${devices.length} registro(s)`;
    el("address-rule-count").textContent = `Regras IP / MAC: ${Array.isArray(data.address_blocks) ? data.address_blocks.length : 0}`;
    for (const device of devices.slice(0, 1000)) {
      const row = document.createElement("tr");
      const name = document.createElement("td"); name.append(text("strong", device.name || "Sem nome"));
      if (device.protected) name.append(text("small", "Equipamento protegido"));
      const address = document.createElement("td"); address.append(text("strong", device.ip), text("small", device.mac || "MAC não observado"));
      const state = document.createElement("td"); state.append(text("strong", device.observed === false ? "Regra salva · sem observação atual" : device.state || "Observada"), text("small", wifiEvidence(device)));
      state.append(text("small", "Leitura atual não confirmada · presença não comprovada", "row-stale"));
      const access = document.createElement("td"); const knownAccess = data.mode !== "observation" && typeof device.blocked === "boolean";
      access.append(badge(!knownAccess ? "Não verificada" : device.blocked ? "Suspensa" : "Sem suspensão", !knownAccess ? "" : device.blocked ? "off" : "ok"));
      const causes = Array.isArray(device.blocked_by) ? device.blocked_by.map(value => ({device: "máquina", ip: "IP", mac: "MAC"})[value]).filter(Boolean) : [];
      if (causes.length) access.append(text("small", `Regras: ${causes.join(" + ")}`));
      const addressActions = document.createElement("td"); const addressGrid = document.createElement("div"); addressGrid.className = "address-actions";
      for (const kind of ["ip", "mac"]) for (const blocked of [true, false]) addressGrid.append(addressButton(device, kind, blocked));
      addressActions.append(addressGrid);
      const action = document.createElement("td");
      if (supports("set_device_block")) {
        const machineBlocked = causes.length ? causes.includes("máquina") : !!device.blocked && !hasAddressRule("ip", device.ip, device) && !hasAddressRule("mac", device.mac, device);
        const legacy = actionButton(device.protected ? "Protegida" : machineBlocked ? "Remover regra" : "Suspender máquina", machineBlocked ? "success" : "danger", "set_device_block", () => mutate("set_device_block", {ip: device.ip, blocked: !machineBlocked}, `${machineBlocked ? "Remover a regra por máquina" : "Suspender a internet"} de ${device.name || "máquina"} (${device.ip})? Regras independentes de IP e MAC serão preservadas.`), !!device.protected);
        legacy.dataset.unavailable = String(!device.ip || (!machineBlocked && device.observed === false)); action.append(legacy);
      } else {
        action.append(text("small", "Regra por máquina indisponível nesta conexão."));
      }
      row.append(name, address, state, access, addressActions, action); el("devices").append(row);
    }
    if (!devices.length) emptyRow(el("devices"), 6, "Nenhuma máquina observada nem regra de endereço disponível na amostra.");
    const policy = data.policies?.ai_block;
    el("ai-state").textContent = !supports("set_ai_block") ? "Sem suporte" : policy ? policy.enabled ? "Ativo" : "Desativado" : "Indisponível";
    el("ai-state").className = `state-badge ${supports("set_ai_block") && policy?.enabled ? "ok" : ""}`;
    el("ai-description").textContent = !supports("set_ai_block") ? "A fonte conectada não confirmou suporte ao bloqueio de IA. Você pode organizar domínios no banco local." : policy ? `${policy.services?.length || 0} serviços e ${policy.domain_count || 0} domínios no catálogo. A ativação aplica o perfil no equipamento configurado.` : "A fonte conectada não disponibiliza o perfil de IA.";
    el("ai-toggle").textContent = policy?.enabled ? "Desativar bloqueio de IA" : "Ativar bloqueio de IA";
    el("ai-domains").replaceChildren();
    for (const domain of (policy?.domains || []).slice(0, 1000)) el("ai-domains").append(text("li", domain));
    el("domains").replaceChildren();
    const domains = Array.isArray(data.domains) ? data.domains : [];
    el("domain-count").textContent = domains.length;
    for (const domain of domains.slice(0, 1000)) {
      const row = document.createElement("tr"); const source = domain.source === "ai_profile";
      const action = document.createElement("td");
      action.append(actionButton(source ? "Perfil IA" : "Remover", "quiet", "remove_domain", () => mutate("remove_domain", {domain: domain.domain}, `Remover o bloqueio manual de ${domain.domain}? O domínio continuará bloqueado se também pertencer ao perfil IA ativo. ${domainImpact()}`), source));
      row.append(text("td", domain.domain), text("td", source ? "Perfil IA" : "Manual"), action); el("domains").append(row);
    }
    if (!domains.length) emptyRow(el("domains"), 3, "Nenhum domínio cadastrado.");
    el("domain-impact").textContent = supports("add_domain") ? domainImpact() : "Esta fonte não confirmou filtragem de sites. Cadastros no banco local não alteram a rede.";
    el("audit").replaceChildren();
    for (const record of (data.audit || []).slice(0, 7)) {
      const item = document.createElement("li"); item.append(text("strong", record.action || "Ação administrativa"), text("p", `${record.target || ""} · ${record.outcome || ""}`), text("small", stamp(record.time))); el("audit").append(item);
    }
    if (!el("audit").children.length) el("audit").append(text("li", "Nenhum registro administrativo disponível."));
    el("events").replaceChildren();
    for (const event of (data.events || []).slice(0, 12)) {
      const row = document.createElement("tr"); row.append(text("td", stamp(event.time)), text("td", event.client_ip), text("td", event.domain), text("td", event.status || "Consulta")); el("events").append(row);
    }
    if (!el("events").children.length) emptyRow(el("events"), 4, capabilities.dns_history === true ? "Nenhuma consulta DNS na amostra disponível." : "A fonte conectada não disponibiliza histórico DNS.");
    syncControls();
  }
  async function refresh(login = false) {
    if (busy || dbBusy || dbSyncing || !token) return;
    busy = true; syncControls(); const current = generation;
    el("request-status").textContent = "Consultando a fonte configurada…";
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
  async function mutate(action, params, confirmation) {
    if (!canWrite(action)) { message("action-error", "A ação exige suporte confirmado da fonte, serviços ativos, dados recentes e perfil administrativo."); return; }
    if (!window.confirm(confirmation + (snapshot.mode === "demo" ? "\n\nModo demonstração: esta ação é apenas simulada." : "\n\nA ação será enviada ao equipamento configurado e pode afetar o acesso à rede."))) return;
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
        if (!canEditDB() || !window.confirm(`Excluir ${site.domain} do banco gerenciado?\n\nEssa alteração é local. Para refletir a remoção no equipamento, aplique a lista depois, quando houver suporte. Regras manuais e do perfil IA serão preservadas.`)) return;
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
      el("mode-banner").textContent = "FONTE SEM DADOS — o banco local está disponível; aguarde a consulta da conexão configurada.";
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
    if (!canWrite("add_domain") || !canWrite("remove_domain")) { dbMessage("A aplicação exige filtragem de sites confirmada pelo equipamento, DNS ativo, dados recentes e perfil administrativo.", true); return; }
    if (!window.confirm(`Aplicar um lote de até 20 alterações pendentes do banco no equipamento?\n\n${domainImpact()} Uma falha pode deixar o lote parcialmente aplicado. Confira o resultado antes de repetir. Regras manuais e do perfil IA serão preservadas.\n\nSair do painel não cancela um lote já iniciado.`)) return;
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
    if (report.snapshot && ["gateway", "demo", "equipment", "observation"].includes(report.snapshot.mode)) { snapshot = report.snapshot; lastSuccess = Date.now(); render(); }
  }
  async function pollSync(current, initial = false) {
    if (current !== generation || !token) return;
    if (gatewayWriting || dbBusy) { setTimeout(() => pollSync(current, initial), 3000); return; }
    dbBusy = true; syncControls(); let again = false; let reload = false;
    try {
      const result = await api("/api/banlist/sync-status", undefined, false);
      if (current !== generation) return;
      dbSyncing = !!result.data.running;
      if (dbSyncing) { dbMessage("Aplicando lote no equipamento. O banco está temporariamente bloqueado para edição."); again = true; }
      else if (!initial) {
        if (result.data.error) dbMessage(`O lote não foi concluído: ${result.data.error}. Consulte o equipamento antes de repetir.`, true);
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
  function clearMap() {
    if (mapObjectURL) URL.revokeObjectURL(mapObjectURL);
    mapObjectURL = ""; mapSnapshotTime = ""; mapCacheState = "";
    el("network-map").removeAttribute("src"); el("network-map").hidden = true;
    el("map-placeholder").hidden = false;
    el("map-status").textContent = "Mapa ainda não consultado.";
    el("address-rule-count").textContent = "Regras IP / MAC: —";
  }
  function reportMessage(value, failed = false) {
    el("report-message").className = `message ${failed ? "error" : ""}`;
    message("report-message", value);
  }
  async function resource(format, preview = false) {
    if (!token || resourceBusy) return;
    const formats = {
      svg: {path: "/api/network-map", type: "image/svg+xml", name: "LabGuard-mapa-rede.svg"},
      html: {path: "/api/report?format=html", type: "text/html", name: "LabGuard-relatorio.html"},
      csv: {path: "/api/report?format=csv", type: "text/csv", name: "LabGuard-relatorio.csv"},
      pdf: {path: "/api/report?format=pdf", type: "application/pdf", name: "LabGuard-relatorio.pdf"}
    };
    const target = formats[format]; if (!target) return;
    const current = generation; const requestController = new AbortController();
    activeControllers.add(requestController); resourceBusy = true; syncControls();
    const timeout = setTimeout(() => requestController.abort(), 20000);
    reportMessage(preview ? "Carregando o mapa lógico…" : "Preparando o arquivo da última amostra disponível…");
    try {
      const response = await fetch(target.path, {credentials: "omit", cache: "no-store", signal: requestController.signal, headers: {"Authorization": `Bearer ${token}`, "Accept": target.type}});
      if (!response.ok) {
        let detail = {}; try { detail = await response.json(); } catch { /* Use the generic error below. */ }
        const error = new Error(detail.error || "Arquivo indisponível. Atualize o painel para obter uma amostra da fonte configurada."); error.status = response.status; throw error;
      }
      if ((response.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase() !== target.type) throw new Error("O servidor retornou um formato de arquivo inesperado.");
      const blob = await response.blob(); if (current !== generation) return;
      if (blob.size > 8 * 1024 * 1024) throw new Error("O arquivo excedeu o limite de 8 MB do painel.");
      const state = response.headers.get("X-LabGuard-Snapshot-State");
      const stale = state !== "fresh";
      const notice = stale ? "Atenção: o servidor marcou a origem como desatualizada ou sem confirmação de atualização." : "O servidor marcou a amostra como recente.";
      const url = URL.createObjectURL(blob);
      if (preview) {
        const previous = mapObjectURL; mapObjectURL = url; mapSnapshotTime = snapshot?.timestamp ?? ""; mapCacheState = stale ? "stale" : "fresh";
        el("network-map").src = url; el("network-map").hidden = false; el("map-placeholder").hidden = true;
        if (previous) URL.revokeObjectURL(previous);
        el("map-status").textContent = `Mapa consultado em ${stamp(new Date().toISOString())}. ${notice}`;
        reportMessage(`Mapa lógico carregado. ${notice}`);
      } else {
        downloadObjectURLs.add(url);
        const link = document.createElement("a"); link.href = url; link.download = target.name; document.body.append(link); link.click(); link.remove();
        setTimeout(() => { URL.revokeObjectURL(url); downloadObjectURLs.delete(url); }, 1000);
        reportMessage(`Download ${format.toUpperCase()} solicitado. ${notice} O arquivo pode conter identificadores da rede; compartilhe somente com a equipe autorizada.`);
      }
    } catch (error) {
      if (current !== generation) return;
      if (error.status === 401) { logout(); message("login-error", "Acesso encerrado. Informe um token autorizado."); }
      else reportMessage(error.name === "AbortError" ? "O arquivo não foi recebido a tempo. Tente consultar novamente." : error.message, true);
    } finally { clearTimeout(timeout); activeControllers.delete(requestController); if (current === generation) { resourceBusy = false; syncControls(); } }
  }
  el("map-load").addEventListener("click", () => resource("svg", true));
  for (const format of ["svg", "html", "csv", "pdf"]) el(`download-${format}`).addEventListener("click", () => resource(format));
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
    payload.expected_revision = dbEditing ? dbEditing.revision : 0;
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
    mutate("set_ai_block", {enabled}, `${enabled ? "Ativar" : "Desativar"} o catálogo de bloqueio de serviços de IA no equipamento? ${domainImpact()} Bloqueios manuais serão preservados.`);
  });
  el("domain-form").addEventListener("submit", event => {
    event.preventDefault(); const domain = el("new-domain").value.trim();
    if (!domain) return;
    mutate("add_domain", {domain, category: "Outros"}, `Cadastrar o bloqueio de ${domain} no equipamento configurado? ${domainImpact()}`);
  });
  window.addEventListener("pagehide", () => { token = ""; activeControllers.forEach(item => item.abort()); activeControllers.clear(); clearMap(); downloadObjectURLs.forEach(url => URL.revokeObjectURL(url)); downloadObjectURLs.clear(); });
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
