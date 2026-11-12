  // Managed-client events and three explicitly scoped policies. Text-only rendering.
  let alertsFingerprint = "";
  let lastAlertId = 0;
  function renderManaged(result) {
    const rows = Array.isArray(result.alerts) ? result.alerts : [];
    const unread = Number(result.unread_alerts || 0);
    $("nav-alert-count").textContent = String(unread);
    $("alert-banner").hidden = unread === 0;
    $("alert-banner-text").textContent = unread + " aviso(s) não conferido(s). Consulte os computadores e o motivo abaixo.";
    const policy = result.managed_policy || {};
    $("managed-policy-revision").textContent = "Política de proteção #" + number(policy.revision) + " · Clientes Jogos 2.2. A lista Sites e regras continua destinada ao Cliente 1.x.";
    if (!document.querySelector("#managed-policy-form :focus")) {
      for (const key of ["cleanup_enabled", "close_games", "block_youtube"]) $("managed-" + key).checked = policy[key] === true;
    }
    const fp = JSON.stringify(rows);
    if (fp !== alertsFingerprint) {
      alertsFingerprint = fp;
      const fragment = document.createDocumentFragment();
      for (const entry of rows) {
        const tr = document.createElement("tr");
        const detail = document.createElement("td");
        detail.append(textNode("strong", entry.title || "Aviso do cliente"));
        if (entry.process) detail.append(textNode("div", entry.process, "row-subtitle"));
        tr.append(textNode("td", formatDate(entry.time, true), "last-seen"), textNode("td", entry.name || "Estação"), detail, textNode("td", entry.seen ? "Conferido" : "Novo", entry.seen ? "" : "blocked-text"));
        fragment.append(tr);
      }
      $("alerts-body").replaceChildren(fragment);
      $("alerts-empty").hidden = rows.length !== 0;
      $("ack-alerts").disabled = rows.length === 0 || unread === 0;
      const latest = rows[0];
      if (latest && latest.id > lastAlertId && !latest.seen) {
        if (lastAlertId > 0 && "Notification" in window && Notification.permission === "granted") {
          const note = new Notification("LabGuard · " + latest.name, {body: latest.title + (latest.process ? ": " + latest.process : ""), tag: "labguard-alert"});
          note.onclick = () => { window.focus(); setView("alerts", true); note.close(); };
        }
        lastAlertId = latest.id;
      }
    }
  }
  $("ack-alerts").addEventListener("click", async () => {
    const first = snapshot?.alerts?.[0];
    if (!first) return;
    try { await api("/api/alerts/ack", {through: first.id}); await refreshState(); }
    catch(error) { showError("connection-error", error.message); }
  });
  $("enable-alert-notifications").addEventListener("click", async () => {
    if (!("Notification" in window)) { $("notification-state").textContent = "Este navegador não oferece notificações. Os avisos continuam no painel."; return; }
    const value = await Notification.requestPermission();
    $("notification-state").textContent = value === "granted" ? "Notificações autorizadas neste navegador. Mantenha o painel aberto e autenticado." : "Avisos mantidos no painel; notificações do navegador não autorizadas.";
  });
  $("managed-policy-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!snapshot?.managed_policy) return;
    const body = {expected_revision: snapshot.managed_policy.revision};
    for (const key of ["cleanup_enabled", "close_games", "block_youtube"]) body[key] = $("managed-" + key).checked;
    if (!window.confirm("Aplicar estas três opções a todos os clientes Jogos 2.2 vinculados? A reativação da limpeza pode remover jogos e saves permanentemente.")) return;
    $("save-managed-policy").disabled = true;
    try { await api("/api/managed-policy", body); await refreshState(); $("managed-policy-result").textContent = "Política enviada. Confira a confirmação de cada estação em Computadores."; }
    catch(error) { $("managed-policy-result").textContent = error.message; }
    finally { $("save-managed-policy").disabled = false; }
  });
