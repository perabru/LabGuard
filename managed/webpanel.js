  // Only the fixed quick-site catalog. No wildcard for the whole internet.
  let webFingerprint = "";
  function renderWebSites(result) {
    const rows = Array.isArray(result.web_catalog) ? result.web_catalog : [];
    const policy = result.web_policy || {};
    const fp = JSON.stringify([rows, result.managed_policy?.block_youtube]);
    const devices = (result.devices || []).filter(d => d.managed && !d.revoked);
    const confirmed = devices.filter(d => d.web_confirmed).length;
    $("web-status-line").textContent = "Lista #" + number(policy.revision) + " · " + confirmed + " de " + devices.length + " clientes gerenciados confirmaram esta lista. Confira cada estação em Computadores.";
    if (fp === webFingerprint) return;
    webFingerprint = fp;
    const fragment = document.createDocumentFragment();
    for (const row of rows) {
      const tr = document.createElement("tr"); tr.dataset.webId = row.id;
      const name = document.createElement("td"); name.append(textNode("strong", row.label));
      if (row.note) name.append(textNode("div", row.note, "row-subtitle"));
      const address = textNode("td", row.domains.length ? row.domains.join(", ") : "Informe o endereço", "web-domain");
      const state = textNode("td", !row.domains.length ? "Endereço pendente" : row.blocked ? "Bloqueio solicitado" : "Sem bloqueio nesta lista", "web-request-state");
      const actions = document.createElement("td");
      const toggle = document.createElement("button"); toggle.className = "button secondary compact";
      toggle.textContent = row.blocked ? "Liberar" : "Bloquear"; toggle.disabled = !row.domains.length;
      toggle.addEventListener("click", () => changeWebSite(row, !row.blocked));
      const edit = document.createElement("button"); edit.className = "button secondary compact"; edit.textContent = "Editar endereço";
      edit.addEventListener("click", () => editWebSite(row));
      actions.append(toggle, document.createTextNode(" "), edit); tr.append(name, address, state, actions); fragment.append(tr);
    }
    const yt = document.createElement("tr"); yt.dataset.webId = "youtube";
    const ytActions = document.createElement("td"); const ytButton = document.createElement("button");
    ytButton.className = "button secondary compact"; ytButton.textContent = result.managed_policy?.block_youtube ? "Liberar" : "Bloquear";
    ytButton.addEventListener("click", async () => {
      try { const p = snapshot.managed_policy; await api("/api/managed-policy", {expected_revision:p.revision, cleanup_enabled:p.cleanup_enabled, close_games:p.close_games, block_youtube:!p.block_youtube}); await refreshState(); $("web-result").textContent = "YouTube atualizado. Reabra o navegador na estação para conferir."; }
      catch (error) { $("web-result").textContent = error.message; }
    });
    ytActions.append(ytButton);
    yt.append(textNode("td", "YouTube"), textNode("td", "youtube.com e endereços relacionados"), textNode("td", result.managed_policy?.block_youtube ? "Bloqueio solicitado" : "Sem bloqueio nesta política"), ytActions); fragment.append(yt);
    $("web-sites-body").replaceChildren(fragment);
  }
  async function changeWebSite(row, blocked, addresses = row.domains) {
    try {
      await api("/api/web-sites/change", {expected_revision:snapshot.web_policy.revision, id:row.id, domains:addresses, blocked});
      await refreshState(); $("web-result").textContent = row.label + ": alteração enviada. Confira Sites na linha de cada computador; reabra os navegadores.";
      return true;
    } catch (error) { $("web-result").textContent = error.message; return false; }
  }
  function editWebSite(row) {
    $("web-edit-id").value = row.id; $("web-edit-label").textContent = row.label;
    $("web-edit-domains").value = row.domains.join("\n"); $("web-edit-blocked").checked = row.blocked || !row.domains.length;
    $("web-edit-error").textContent = ""; $("web-edit-dialog").showModal();
  }
  $("web-edit-cancel").addEventListener("click", () => $("web-edit-dialog").close());
  $("web-edit-form").addEventListener("submit", async event => {
    event.preventDefault(); const row = snapshot.web_catalog.find(r => r.id === $("web-edit-id").value); if (!row) return;
    const values = $("web-edit-domains").value.split(/[\n,;]+/).map(v => v.trim()).filter(Boolean);
    $("web-edit-save").disabled = true;
    try { await api("/api/web-sites/change", {expected_revision:snapshot.web_policy.revision, id:row.id, domains:values, blocked:$("web-edit-blocked").checked}); $("web-edit-dialog").close(); await refreshState(); $("web-result").textContent = "Endereço salvo; confira a confirmação dos clientes."; }
    catch (error) { $("web-edit-error").textContent = error.message; }
    finally { $("web-edit-save").disabled = false; }
  });
  $("web-block-all").addEventListener("click", async () => {
    if (!snapshot?.web_policy) return;
    if (!window.confirm("Bloquear todos os sites com endereço cadastrado nesta lista e o YouTube, em todos os clientes Jogos 2.3 vinculados?\n\nIsso não corta a internet inteira nem ativa a remoção de jogos. Itens sem endereço continuarão pendentes.")) return;
    $("web-block-all").disabled = true;
    try {
      const reply = await api("/api/web-sites/block-all", {expected_revision:snapshot.web_policy.revision});
      await refreshState(); $("web-result").textContent = "Bloqueios enviados. Confira a aplicação em Computadores." + (reply.pending_names?.length ? " Endereço ainda pendente: " + reply.pending_names.join(", ") + "." : "");
    } catch (error) { $("web-result").textContent = error.message; }
    finally { $("web-block-all").disabled = false; }
  });
