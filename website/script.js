"use strict";

(() => {
  const body = document.body;
  const themeButton = document.querySelector("#theme-switch");
  const themeIcon = themeButton?.querySelector("use");
  function setTheme(dark) {
    body.classList.toggle("theme-dark", dark);
    themeButton?.setAttribute("aria-pressed", String(dark));
    themeButton?.setAttribute("aria-label", dark ? "Ativar tema claro" : "Ativar tema escuro");
    themeIcon?.setAttribute("href", dark ? "#i-moon" : "#i-sun");
  }
  let savedTheme = null;
  try { savedTheme = localStorage.getItem("labguard-promo-theme"); } catch { /* Theme is optional. */ }
  setTheme(savedTheme === "dark");
  themeButton?.addEventListener("click", () => {
    const dark = !body.classList.contains("theme-dark");
    setTheme(dark);
    try { localStorage.setItem("labguard-promo-theme", dark ? "dark" : "light"); } catch { /* Local storage may be disabled. */ }
  });

  const menuButton = document.querySelector(".menu-toggle");
  const menu = document.querySelector("#main-nav");
  function closeMenu() {
    menu?.classList.remove("is-open");
    menuButton?.setAttribute("aria-expanded", "false");
    menuButton?.setAttribute("aria-label", "Abrir menu");
  }
  menuButton?.addEventListener("click", () => {
    const expanded = menuButton.getAttribute("aria-expanded") !== "true";
    menu?.classList.toggle("is-open", expanded);
    menuButton.setAttribute("aria-expanded", String(expanded));
    menuButton.setAttribute("aria-label", expanded ? "Fechar menu" : "Abrir menu");
  });
  menu?.querySelectorAll("a").forEach(link => link.addEventListener("click", closeMenu));
  document.addEventListener("keydown", event => { if (event.key === "Escape") closeMenu(); });

  const machines = [...document.querySelectorAll(".machine-card[data-machine]")];
  const onlineCount = document.querySelector("#demo-online-count");
  const feedback = document.querySelector("#demo-feedback");
  const aiButton = document.querySelector("#ai-toggle");
  const aiStatus = document.querySelector("#demo-ai-status");
  const aiServices = document.querySelector("#ai-service-list");
  function setMachine(card, blocked, announce = true) {
    card.classList.toggle("is-blocked", blocked);
    const button = card.querySelector(".machine-toggle");
    button.setAttribute("aria-pressed", String(blocked));
    button.textContent = blocked ? "Restaurar internet" : "Suspender internet";
    card.querySelector(".machine-state").textContent = blocked ? "Suspensa" : "Permitida";
    onlineCount.textContent = String(machines.filter(machine => !machine.classList.contains("is-blocked")).length + 1).padStart(2, "0");
    if (announce) feedback.textContent = `Simulação: internet ${blocked ? "suspensa" : "restaurada"} em ${card.querySelector("h5").textContent}. Sua rede não foi alterada.`;
  }
  machines.forEach(card => card.querySelector(".machine-toggle").addEventListener("click", () => setMachine(card, !card.classList.contains("is-blocked"))));
  function setAI(enabled, announce = true) {
    aiButton.setAttribute("aria-checked", String(enabled));
    aiStatus.textContent = enabled ? "Ativado" : "Desativado";
    aiServices.classList.toggle("is-blocked", enabled);
    if (announce) feedback.textContent = `Simulação: perfil de domínios de IA ${enabled ? "ativado" : "desativado"}. Nenhum bloqueio real foi aplicado.`;
  }
  aiButton?.addEventListener("click", () => setAI(aiButton.getAttribute("aria-checked") !== "true"));
  document.querySelector("#demo-reset")?.addEventListener("click", () => {
    machines.forEach(card => setMachine(card, card.dataset.machine === "3", false));
    setAI(false, false);
    feedback.textContent = "Demonstração reiniciada. Todos os dados e controles são fictícios.";
  });

  // Public release metadata only: no user, school or network data are sent.
  // A missing release leaves an honest link to GitHub's release page.
  const releaseStatus = document.querySelector("#release-status");
  const controller = new AbortController();
  const releaseTimeout = window.setTimeout(() => controller.abort(), 6500);
  fetch("https://api.github.com/repos/perabru/LabGuard/releases/latest", {
    signal: controller.signal,
    headers: { "Accept": "application/vnd.github+json" }
  }).then(response => {
    if (!response.ok) throw new Error("Release unavailable");
    return response.json();
  }).then(release => {
    const version = /^v2\.(\d+)\.(\d+)$/.exec(String(release.tag_name || ""));
    if (!version || Number(version[1]) === 0 && Number(version[2]) < 1) throw new Error("Versão com ajuda de identificação ainda em publicação");
    const assets = Array.isArray(release.assets) ? release.assets : [];
    document.querySelectorAll("[data-release-asset]").forEach(link => {
      const asset = assets.find(item => item.name === link.dataset.releaseAsset);
      if (asset && typeof asset.browser_download_url === "string" && asset.browser_download_url.startsWith("https://github.com/perabru/LabGuard/releases/download/")) {
        link.href = asset.browser_download_url;
        link.textContent = link.dataset.downloadLabel;
      }
    });
    const setup = assets.find(asset => asset.name === "LabGuard-Setup.exe") || null;
    if (setup && typeof setup.browser_download_url === "string" && setup.browser_download_url.startsWith("https://github.com/perabru/LabGuard/releases/download/")) {
      document.querySelectorAll(".download-link").forEach(link => {
        link.href = setup.browser_download_url;
      });
      const size = Number(setup.size);
      releaseStatus.textContent = `${String(release.tag_name || "Versão disponível").slice(0, 40)} · Instalador Windows${Number.isFinite(size) && size > 0 ? ` · ${(size / 1048576).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} MB` : ""} · Consulte o guia antes de configurar a rede.`;
    } else {
      releaseStatus.textContent = "Os arquivos disponíveis estão na página de versões do GitHub. Confira o instalador e as instruções antes de baixar.";
    }
  }).catch(() => {
    releaseStatus.textContent = "Consulte a página de versões no GitHub para verificar a disponibilidade do instalador. O código-fonte também está disponível no repositório.";
  }).finally(() => window.clearTimeout(releaseTimeout));
})();
