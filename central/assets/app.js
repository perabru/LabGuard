"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const categoryNames = {jogos: "Jogos", roblox: "Roblox", minecraft: "Minecraft", adultos: "Adultos", apostas: "Apostas", ia: "Inteligência artificial", outros: "Outros"};
  const categoryOrder = Object.keys(categoryNames);
  const pageSize = 25;
  let snapshot = null;
  let csrf = "";
  let activeView = "sites";
  let currentPage = 1;
  let editOriginal = null;
  let confirmCallback = null;
  let enrollment = null;
  let pollTimer = null;
  let toastTimer = null;
  let stateRequest = null;
  let ruleFingerprint = "";
  let deviceFingerprint = "";
  let auditFingerprint = "";
  let authGeneration = 0;

  class ApiError extends Error {
    constructor(message, status) { super(message); this.status = status; }
  }

  function textNode(tag, text, className) {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function showError(id, message) {
    const element = $(id);
    element.textContent = message || "";
    element.hidden = !message;
  }

  function notify(message, isError = false) {
    clearTimeout(toastTimer);
    const toast = $("toast");
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.hidden = false;
    toastTimer = setTimeout(() => { toast.hidden = true; }, isError ? 7000 : 4500);
  }

  function formatDate(value, compact = false) {
    if (!value) return "Ainda não informado";
    const stamp = typeof value === "number" ? (value < 100000000000 ? value * 1000 : value) : value;
    const date = new Date(stamp);
    if (Number.isNaN(date.getTime())) return "Horário não informado";
    return new Intl.DateTimeFormat("pt-BR", compact
      ? {day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}
      : {day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit"}).format(date);
  }

  function number(value) { return Number.isFinite(Number(value)) ? Number(value).toLocaleString("pt-BR") : "—"; }

  async function api(path, body) {
    const options = {credentials: "same-origin", cache: "no-store", headers: {Accept: "application/json"}};
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      if (csrf) options.headers["X-CSRF-Token"] = csrf;
      options.body = JSON.stringify(body);
    }
    let response;
    try { response = await fetch(path, {...options, signal: AbortSignal.timeout(18000)}); }
    catch (error) { throw new ApiError("Não foi possível falar com a central. Confira se o LabGuard Central continua em execução e tente atualizar.", 0); }
    let result;
    try { result = await response.json(); }
    catch (error) { throw new ApiError("A central devolveu uma resposta inválida. Tente novamente.", response.status); }
    if (!response.ok || result.ok === false) {
      throw new ApiError(typeof result.error === "string" ? result.error : (typeof result.message === "string" ? result.message : "A operação não pôde ser concluída."), response.status);
    }
    return result;
  }

  function showLogin(message = "") {
    authGeneration += 1;
    clearTimeout(pollTimer);
    csrf = "";
    snapshot = null;
    enrollment = null;
    ruleFingerprint = "";
    deviceFingerprint = "";
    auditFingerprint = "";
    for (const dialog of document.querySelectorAll("dialog[open]")) dialog.close();
    $("loading-screen").hidden = true;
    $("app-shell").hidden = true;
    $("login-screen").hidden = false;
    $("password").value = "";
    showError("login-error", message);
    $("password").focus();
  }

  function showApp() {
    $("loading-screen").hidden = true;
    $("login-screen").hidden = true;
    $("app-shell").hidden = false;
    showError("connection-error", "");
  }

  function setView(name, focus = false) {
    const titles = {
      sites: ["Sites e regras", "Defina o que os computadores podem acessar."],
      devices: ["Computadores", "Acompanhe as estações conectadas à sua central."],
      help: ["Como usar", "Um caminho simples para administrar os acessos."]
    };
    if (!Object.hasOwn(titles, name)) return;
    activeView = name;
    for (const id of Object.keys(titles)) $("view-" + id).hidden = name !== id;
    $("page-title").textContent = titles[name][0];
    $("page-subtitle").textContent = titles[name][1];
    for (const button of document.querySelectorAll(".nav-link")) {
      const current = button.dataset.view === name;
      button.classList.toggle("active", current);
      if (current) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    if (focus) $("main").focus({preventScroll: true});
  }

  function categoryEnabled(category) {
    const item = snapshot?.categories?.find((entry) => entry.category === category);
    return item ? item.enabled !== false : true;
  }

  function ruleActive(rule) { return rule.enabled !== false && categoryEnabled(rule.category); }

  function renderCategories() {
    const oldFilter = $("category-filter").value;
    const oldEdit = $("rule-category").value;
    const categories = [...new Set([...categoryOrder, ...(snapshot?.categories || []).map((item) => item.category)])];
    $("category-filter").replaceChildren(new Option("Todas as categorias", ""));
    $("rule-category").replaceChildren();
    for (const category of categories) {
      const item = snapshot?.categories?.find((entry) => entry.category === category);
      const label = categoryNames[category] || category;
      $("category-filter").add(new Option(label + (item?.enabled === false ? " · pausada" : ""), category));
      $("rule-category").add(new Option(label + (item?.enabled === false ? " · pausada" : ""), category));
    }
    $("category-filter").value = categories.includes(oldFilter) ? oldFilter : "";
    $("rule-category").value = categories.includes(oldEdit) ? oldEdit : "outros";
  }

  function renderCategoryTools() {
    const selected = $("category-filter").value;
    const item = snapshot?.categories?.find((entry) => entry.category === selected);
    $("category-tools").hidden = !selected || !item;
    if (!item) return;
    const total = number(item.total);
    const label = categoryNames[selected] || selected;
    $("category-description").textContent = label + " · " + total + " cadastro(s) · " + (item.enabled ? "categoria ativa" : "categoria pausada");
    $("category-toggle").textContent = item.enabled ? "Pausar categoria" : "Ativar categoria";
  }

  function rowButton(label, action, domain, className, title) {
    const button = textNode("button", label, "row-button " + (className || ""));
    button.type = "button";
    button.dataset.action = action;
    button.dataset.domain = domain;
    if (title) { button.title = title; button.setAttribute("aria-label", title); }
    return button;
  }

  function renderRules() {
    if (!snapshot) return;
    const query = $("search").value.trim().toLocaleLowerCase("pt-BR");
    const category = $("category-filter").value;
    const action = $("action-filter").value;
    const rules = (snapshot.rules || []).filter((rule) => {
      if (query && !rule.domain.toLocaleLowerCase("pt-BR").includes(query)) return false;
      if (category && rule.category !== category) return false;
      if (action === "paused") return !ruleActive(rule);
      if (action === "block" && (rule.action !== "block" || !ruleActive(rule) || rule.overridden_by)) return false;
      if (action === "allow" && (!ruleActive(rule) || (rule.action !== "allow" && !rule.overridden_by))) return false;
      return true;
    }).sort((a, b) => a.domain.localeCompare(b.domain, "pt-BR"));
    const pages = Math.max(1, Math.ceil(rules.length / pageSize));
    currentPage = Math.max(1, Math.min(currentPage, pages));
    const start = (currentPage - 1) * pageSize;
    const fragment = document.createDocumentFragment();
    for (const rule of rules.slice(start, start + pageSize)) {
      const row = document.createElement("tr");
      const domainCell = document.createElement("td");
      domainCell.append(textNode("span", rule.domain, "domain-name"));
      if (rule.source === "manual" || rule.source === "tecnico") domainCell.append(textNode("span", "Cadastrado pela TI", "domain-detail"));
      const categoryCell = textNode("td", categoryNames[rule.category] || rule.category, "category-label");
      const statusCell = document.createElement("td");
      const enabled = ruleActive(rule);
      const allowed = rule.action === "allow";
      const inherited = enabled && rule.overridden_by;
      statusCell.append(textNode("span", inherited ? "Liberado por exceção" : (enabled ? (allowed ? "Liberado" : "Bloqueado") : "Pausado"), "badge " + (enabled ? ((allowed || inherited) ? "allowed" : "blocked") : "neutral")));
      if (inherited) statusCell.append(textNode("span", "Exceção: " + inherited, "row-subtitle"));
      else if (!enabled) statusCell.append(textNode("span", (allowed ? "Liberação" : "Bloqueio") + (categoryEnabled(rule.category) ? " desativado" : " · categoria pausada"), "row-subtitle"));
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "row-actions";
      if (inherited) actions.append(rowButton("Ver exceção", "parent", rule.domain, "toggle-allow", "Editar liberação de " + inherited));
      else actions.append(rowButton(allowed ? "Bloquear" : "Liberar", "toggle", rule.domain, allowed ? "toggle-block" : "toggle-allow", (allowed ? "Bloquear " : "Liberar ") + rule.domain));
      actions.append(rowButton("Editar", "edit", rule.domain, "", "Editar regra de " + rule.domain));
      actions.append(rowButton("×", "delete", rule.domain, "delete-button", "Excluir regra de " + rule.domain));
      actionCell.append(actions);
      row.append(domainCell, categoryCell, statusCell, actionCell);
      fragment.append(row);
    }
    $("rules-body").replaceChildren(fragment);
    $("rules-empty").hidden = rules.length !== 0;
    $("rules-total").textContent = rules.length ? (start + 1) + "–" + Math.min(start + pageSize, rules.length) + " de " + number(rules.length) + " domínios" : "0 domínios";
    $("page-number").textContent = currentPage + " / " + pages;
    $("previous-page").disabled = currentPage <= 1;
    $("next-page").disabled = currentPage >= pages;
    renderCategoryTools();
  }

  function renderDevices() {
    if (!snapshot) return;
    const labels = {online: ["Atualizado", "allowed"], offline: ["Sem contato", "neutral"], pending: ["Aguardando regras", "pending"], error: ["Requer atenção", "error-badge"], revoked: ["Vínculo revogado", "neutral"]};
    const fragment = document.createDocumentFragment();
    const devices = [...(snapshot.devices || [])].sort((a, b) => String(a.name).localeCompare(String(b.name), "pt-BR"));
    for (const device of devices) {
      const row = document.createElement("tr");
      const nameCell = document.createElement("td");
      nameCell.append(textNode("span", device.name || "Estação sem nome", "device-name"), textNode("div", "Cliente " + (device.client_version || "sem versão informada"), "device-version"));
      const statusCell = document.createElement("td");
      const status = labels[device.revoked ? "revoked" : device.status] || ["Aguardando contato", "neutral"];
      statusCell.append(textNode("span", status[0], "badge " + status[1]));
      if (device.error) statusCell.append(textNode("span", String(device.error), "row-subtitle"));
      const revisionCell = document.createElement("td");
      revisionCell.append(textNode("span", device.applied_revision == null ? "Ainda não aplicada" : "#" + number(device.applied_revision), "revision-value"));
      if (device.applied_revision !== snapshot.revision && !device.revoked) revisionCell.append(textNode("span", "Atual: #" + number(snapshot.revision), "row-subtitle"));
      const seenCell = textNode("td", formatDate(device.last_seen, true), "last-seen");
      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "row-actions";
      if (!device.revoked) {
        const button = textNode("button", "Revogar vínculo", "row-button");
        button.type = "button";
        button.dataset.device = device.device_id;
        button.setAttribute("aria-label", "Revogar vínculo de " + device.name);
        actions.append(button);
      } else actions.append(textNode("span", "Revogado", "row-subtitle"));
      actionCell.append(actions);
      row.append(nameCell, statusCell, revisionCell, seenCell, actionCell);
      fragment.append(row);
    }
    $("devices-body").replaceChildren(fragment);
    $("devices-empty").hidden = devices.length !== 0;
  }

  function renderAudit() {
    const titles = {rule_saved: "Regra salva", rule_deleted: "Regra excluída", category_changed: "Categoria alterada", enrollment_created: "Vínculo gerado", device_enrolled: "Computador vinculado", device_revoked: "Vínculo revogado"};
    const rows = (snapshot?.audit || []).slice(0, 20);
    const fragment = document.createDocumentFragment();
    for (const entry of rows) {
      const row = document.createElement("tr");
      let detail = String(entry.detail || "");
      if (entry.action === "rule_saved") detail = detail.replace(/ block$/, " · Bloquear").replace(/ allow$/, " · Liberar");
      if (entry.action === "category_changed") {
        const parts = detail.split(" ");
        detail = (categoryNames[parts[0]] || parts[0]) + " · " + (parts[1] === "enabled" ? "Ativada" : "Pausada");
      }
      row.append(textNode("td", formatDate(entry.time, true), "last-seen"), textNode("td", titles[entry.action] || "Alteração registrada"), textNode("td", detail, "audit-detail"));
      fragment.append(row);
    }
    $("audit-body").replaceChildren(fragment);
    $("audit-empty").hidden = rows.length !== 0;
  }

  function renderState(result) {
    snapshot = result;
    if (result.csrf) csrf = result.csrf;
    $("count-blocked").textContent = number(result.counts?.blocked);
    $("count-allowed").textContent = number(result.counts?.allowed);
    $("count-devices").textContent = number(result.counts?.devices);
    $("online-detail").textContent = number(result.counts?.online) + " com regras atualizadas";
    $("current-revision").textContent = "#" + number(result.revision);
    $("rule-budget").textContent = number(result.counts?.configured) + " de " + number(result.active_limit || 975) + " regras habilitadas. Os bloqueios cobertos por uma liberação permanecem cadastrados e voltam a valer se a exceção for retirada.";
    $("nav-device-count").textContent = number(result.counts?.devices);
    $("footer-revision").textContent = (result.version ? "Versão " + result.version + " · " : "") + "Revisão #" + number(result.revision);
    $("sync-interval").textContent = "Os clientes consultam a central a cada " + number(result.poll_seconds || 15) + " segundos. Sem contato há mais de 90 segundos: estação offline.";
    const nextRules = JSON.stringify([result.rules, result.categories]);
    if (nextRules !== ruleFingerprint) {
      ruleFingerprint = nextRules;
      renderCategories();
      renderRules();
    }
    const nextDevices = JSON.stringify([result.devices, result.revision]);
    if (nextDevices !== deviceFingerprint) { deviceFingerprint = nextDevices; renderDevices(); }
    const nextAudit = JSON.stringify(result.audit);
    if (nextAudit !== auditFingerprint) { auditFingerprint = nextAudit; renderAudit(); }
    $("refresh-state").textContent = "Atualizado às " + new Intl.DateTimeFormat("pt-BR", {hour: "2-digit", minute: "2-digit", second: "2-digit"}).format(new Date());
  }

  function schedulePoll() {
    clearTimeout(pollTimer);
    if (!csrf || $("app-shell").hidden) return;
    pollTimer = setTimeout(async () => {
      if (document.querySelector("dialog[open]") || document.hidden) { schedulePoll(); return; }
      await refreshState(false);
    }, 15000);
  }

  async function refreshState(showBusy = true) {
    if (stateRequest) return stateRequest;
    const generation = authGeneration;
    if (showBusy) { $("refresh").disabled = true; $("refresh-state").textContent = "Atualizando…"; }
    stateRequest = (async () => {
      try {
        const result = await api("/api/state");
        if (generation !== authGeneration) return;
        renderState(result);
        showError("connection-error", "");
      } catch (error) {
        if (generation !== authGeneration) return;
        if (error.status === 401) showLogin("Sua sessão terminou. Entre novamente para administrar a central.");
        else { showError("connection-error", error.message + " Os dados exibidos podem estar desatualizados."); $("refresh-state").textContent = "Atualização pendente"; }
      } finally {
        $("refresh").disabled = false;
        stateRequest = null;
        schedulePoll();
      }
    })();
    return stateRequest;
  }

  function setDialogBusy(dialog, busy) {
    dialog.dataset.busy = busy ? "true" : "false";
    for (const control of dialog.querySelectorAll("button,input,select")) control.disabled = busy;
  }

  function openRule(rule = null) {
    if (!snapshot) return;
    editOriginal = rule?.domain || null;
    $("rule-dialog-title").textContent = rule ? "Editar site" : "Adicionar site";
    $("rule-domain").value = rule?.domain || "";
    $("rule-category").value = rule?.category || "outros";
    $("rule-enabled").checked = rule?.enabled !== false;
    $("rule-form").elements.action.value = rule?.action || "block";
    updateInheritanceHint();
    showError("rule-error", "");
    setDialogBusy($("rule-dialog"), false);
    $("rule-dialog").showModal();
    $("rule-domain").focus();
  }

  function updateInheritanceHint() {
    const domain = $("rule-domain").value.trim().toLowerCase().replace(/\.$/, "");
    const allowedParent = (snapshot?.rules || []).find((rule) => rule.action === "allow" && ruleActive(rule) && rule.domain !== editOriginal && (domain === rule.domain || domain.endsWith("." + rule.domain)));
    $("rule-inheritance-hint").hidden = !allowedParent;
    $("rule-inheritance-hint").textContent = allowedParent ? "A liberação de " + allowedParent.domain + " também alcança este endereço. Um bloqueio cadastrado aqui só terá efeito depois que essa exceção for alterada ou retirada." : "";
  }

  function confirmAction(title, description, label, callback, danger = true) {
    confirmCallback = callback;
    $("confirm-title").textContent = title;
    $("confirm-description").textContent = description;
    $("confirm-action").textContent = label;
    $("confirm-action").className = "button " + (danger ? "danger" : "primary");
    showError("confirm-error", "");
    setDialogBusy($("confirm-dialog"), false);
    $("confirm-dialog").showModal();
  }

  async function performMutation(path, body, message) {
    await api(path, body);
    await refreshState(false);
    notify(message);
  }

  function openEnrollment() {
    enrollment = null;
    $("enrollment-result").hidden = true;
    $("generate-enrollment").textContent = "Gerar e baixar vínculo";
    showError("enrollment-error", "");
    setDialogBusy($("enrollment-dialog"), false);
    $("enrollment-dialog").showModal();
  }

  function downloadEnrollment() {
    if (!enrollment?.config) return;
    const blob = new Blob([JSON.stringify(enrollment.config, null, 2) + "\n"], {type: "application/json;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = typeof enrollment.filename === "string" && /^[a-zA-Z0-9_.-]+\.json$/.test(enrollment.filename) ? enrollment.filename : "LabGuard-Vinculo.json";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.currentTarget.querySelector("button[type=submit]");
    submit.disabled = true;
    showError("login-error", "");
    try {
      const result = await api("/api/login", {password: $("password").value});
      $("password").value = "";
      csrf = result.csrf || "";
      authGeneration += 1;
      showApp();
      await refreshState();
    } catch (error) { showError("login-error", error.message); $("password").focus(); }
    finally { submit.disabled = false; }
  });

  $("logout").addEventListener("click", async () => {
    $("logout").disabled = true;
    try { await api("/api/logout", {}); showLogin(); }
    catch (error) { if (error.status === 401) showLogin(); else notify("Não foi possível encerrar a sessão: " + error.message, true); }
    finally { $("logout").disabled = false; }
  });

  for (const button of document.querySelectorAll("[data-view]")) button.addEventListener("click", () => setView(button.dataset.view, true));
  $("refresh").addEventListener("click", () => refreshState());
  $("new-rule").addEventListener("click", () => openRule());
  $("rule-domain").addEventListener("input", updateInheritanceHint);
  for (const id of ["search", "category-filter", "action-filter"]) $(id).addEventListener(id === "search" ? "input" : "change", () => { currentPage = 1; renderRules(); });
  $("previous-page").addEventListener("click", () => { currentPage -= 1; renderRules(); });
  $("next-page").addEventListener("click", () => { currentPage += 1; renderRules(); });

  $("rules-body").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button || !snapshot) return;
    const rule = snapshot.rules.find((entry) => entry.domain === button.dataset.domain);
    if (!rule) return;
    if (button.dataset.action === "edit") { openRule(rule); return; }
    if (button.dataset.action === "parent") {
      const parent = snapshot.rules.find((entry) => entry.domain === rule.overridden_by);
      if (parent) openRule(parent);
      return;
    }
    if (button.dataset.action === "delete") {
      confirmAction("Excluir esta regra?", "O cadastro de “" + rule.domain + "” será removido. Um bloqueio de domínio superior ainda poderá se aplicar. Para criar uma exceção explícita, use Liberar.", "Excluir regra", () => performMutation("/api/rules/delete", {domain: rule.domain}, "Regra excluída. As estações receberão a nova revisão."));
      return;
    }
    button.disabled = true;
    try {
      const action = rule.action === "allow" ? "block" : "allow";
      await performMutation("/api/rules", {original: rule.domain, domain: rule.domain, category: rule.category, action, enabled: true}, "Regra de " + (action === "allow" ? "liberação" : "bloqueio") + " salva para " + rule.domain + ".");
    } catch (error) { if (error.status === 401) showLogin("Entre novamente para alterar a regra."); else notify(error.message, true); }
    finally { button.disabled = false; }
  });

  $("rule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const dialog = $("rule-dialog");
    const body = {domain: $("rule-domain").value.trim(), category: $("rule-category").value, action: event.currentTarget.elements.action.value, enabled: $("rule-enabled").checked};
    if (editOriginal) body.original = editOriginal;
    setDialogBusy(dialog, true);
    showError("rule-error", "");
    try {
      await performMutation("/api/rules", body, "Regra salva. Acompanhe o recebimento em Computadores.");
      dialog.close();
    } catch (error) { if (error.status === 401) showLogin("Entre novamente para salvar a regra."); else showError("rule-error", error.message); }
    finally { setDialogBusy(dialog, false); }
  });

  $("category-toggle").addEventListener("click", () => {
    const category = $("category-filter").value;
    const item = snapshot?.categories?.find((entry) => entry.category === category);
    if (!item) return;
    const enabled = !item.enabled;
    confirmAction(enabled ? "Ativar esta categoria?" : "Pausar esta categoria?", "As regras de bloqueio e liberação da categoria “" + (categoryNames[category] || category) + "” serão " + (enabled ? "reativadas" : "pausadas") + " nos computadores vinculados.", enabled ? "Ativar categoria" : "Pausar categoria", () => performMutation("/api/categories", {category, enabled}, "Categoria " + (enabled ? "ativada" : "pausada") + "."), !enabled);
  });

  $("confirm-action").addEventListener("click", async () => {
    if (!confirmCallback) return;
    const action = confirmCallback;
    const dialog = $("confirm-dialog");
    setDialogBusy(dialog, true);
    showError("confirm-error", "");
    try { await action(); dialog.close(); }
    catch (error) { if (error.status === 401) showLogin("Entre novamente para continuar."); else showError("confirm-error", error.message); }
    finally { setDialogBusy(dialog, false); }
  });

  $("devices-body").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-device]");
    if (!button) return;
    const device = snapshot?.devices?.find((entry) => entry.device_id === button.dataset.device);
    if (!device) return;
    confirmAction("Revogar vínculo da estação?", "“" + device.name + "” deixará de receber atualizações desta central. A última política recebida continua no computador. Para retirar a proteção, use a administração local do cliente.", "Revogar vínculo", () => performMutation("/api/devices/revoke", {device_id: device.device_id}, "Vínculo revogado."));
  });

  $("new-enrollment").addEventListener("click", openEnrollment);
  $("empty-enrollment").addEventListener("click", openEnrollment);
  $("download-enrollment").addEventListener("click", downloadEnrollment);
  $("generate-enrollment").addEventListener("click", async () => {
    const dialog = $("enrollment-dialog");
    setDialogBusy(dialog, true);
    showError("enrollment-error", "");
    try {
      enrollment = await api("/api/enrollment", {});
      $("enrollment-expiry").textContent = "Válido até " + formatDate(enrollment.expires_at) + ". Este arquivo cadastra um único computador.";
      $("enrollment-result").hidden = false;
      $("generate-enrollment").textContent = "Gerar outro vínculo";
      downloadEnrollment();
    } catch (error) { if (error.status === 401) showLogin("Entre novamente para vincular um computador."); else showError("enrollment-error", error.message); }
    finally { setDialogBusy(dialog, false); }
  });

  for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", () => { const dialog = $(button.dataset.close); if (dialog.dataset.busy !== "true") dialog.close(); });
  for (const dialog of document.querySelectorAll("dialog")) {
    dialog.addEventListener("cancel", (event) => { if (dialog.dataset.busy === "true") event.preventDefault(); });
    dialog.addEventListener("close", () => {
      if (dialog.id === "enrollment-dialog") enrollment = null;
      if (dialog.id === "confirm-dialog") confirmCallback = null;
      schedulePoll();
    });
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && csrf && !document.querySelector("dialog[open]")) refreshState(false); });

  (async () => {
    try {
      const session = await api("/api/session");
      if (!session.authenticated) { showLogin(); return; }
      csrf = session.csrf || "";
      showApp();
      await refreshState();
    } catch (error) { showLogin(error.status === 401 ? "" : error.message); }
  })();
})();
