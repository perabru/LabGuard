"use strict";
(() => {
  const body=document.body, themeButton=document.querySelector("#theme-switch"), themeIcon=themeButton?.querySelector("use");
  function setTheme(dark){body.classList.toggle("theme-dark",dark);themeButton?.setAttribute("aria-pressed",String(dark));themeButton?.setAttribute("aria-label",dark?"Ativar tema claro":"Ativar tema escuro");themeIcon?.setAttribute("href",dark?"#i-moon":"#i-sun");}
  let savedTheme=null;try{savedTheme=localStorage.getItem("labguard-promo-theme");}catch{}
  setTheme(savedTheme==="dark");themeButton?.addEventListener("click",()=>{const dark=!body.classList.contains("theme-dark");setTheme(dark);try{localStorage.setItem("labguard-promo-theme",dark?"dark":"light");}catch{}});
  const menuButton=document.querySelector(".menu-toggle"),menu=document.querySelector("#main-nav");
  function closeMenu(){menu?.classList.remove("is-open");menuButton?.setAttribute("aria-expanded","false");menuButton?.setAttribute("aria-label","Abrir menu");}
  menuButton?.addEventListener("click",()=>{const expanded=menuButton.getAttribute("aria-expanded")!=="true";menu?.classList.toggle("is-open",expanded);menuButton.setAttribute("aria-expanded",String(expanded));menuButton.setAttribute("aria-label",expanded?"Fechar menu":"Abrir menu");});
  menu?.querySelectorAll("a").forEach(link=>link.addEventListener("click",closeMenu));document.addEventListener("keydown",event=>{if(event.key==="Escape")closeMenu();});
  const machines=[...document.querySelectorAll(".machine-card[data-machine]")],onlineCount=document.querySelector("#demo-online-count"),feedback=document.querySelector("#demo-feedback"),aiButton=document.querySelector("#ai-toggle"),aiStatus=document.querySelector("#demo-ai-status"),aiServices=document.querySelector("#ai-service-list");
  function setMachine(card,blocked,announce=true){card.classList.toggle("is-blocked",blocked);const button=card.querySelector(".machine-toggle");button.setAttribute("aria-pressed",String(blocked));button.textContent=blocked?"Restaurar internet":"Suspender internet";card.querySelector(".machine-state").textContent=blocked?"Suspensa":"Permitida";onlineCount.textContent=String(machines.filter(machine=>!machine.classList.contains("is-blocked")).length+1).padStart(2,"0");if(announce)feedback.textContent=`Simulação: internet ${blocked?"suspensa":"restaurada"} em ${card.querySelector("h5").textContent}. Sua rede não foi alterada.`;}
  machines.forEach(card=>card.querySelector(".machine-toggle").addEventListener("click",()=>setMachine(card,!card.classList.contains("is-blocked"))));
  function setAI(enabled,announce=true){aiButton.setAttribute("aria-checked",String(enabled));aiStatus.textContent=enabled?"Ativado":"Desativado";aiServices.classList.toggle("is-blocked",enabled);if(announce)feedback.textContent=`Simulação: perfil de domínios de IA ${enabled?"ativado":"desativado"}. Nenhum bloqueio real foi aplicado.`;}
  aiButton?.addEventListener("click",()=>setAI(aiButton.getAttribute("aria-checked")!=="true"));document.querySelector("#demo-reset")?.addEventListener("click",()=>{machines.forEach(card=>setMachine(card,card.dataset.machine==="3",false));setAI(false,false);feedback.textContent="Demonstração reiniciada. Todos os dados e controles são fictícios.";});
  // Automatic local client is independent of the DNS edition. Never resolve it from /latest.
  const gamesUrl="downloads/", gamesRelease="https://github.com/perabru/LabGuard/releases/download/automatico-v2.4.0/";
  if(menu&&!menu.querySelector('[data-games-nav]')){const link=document.createElement("a");link.href=gamesUrl;link.textContent="Qual arquivo baixar?";link.dataset.gamesNav="true";link.addEventListener("click",closeMenu);menu.appendChild(link);}
  const heroButtons=document.querySelector(".hero-buttons");if(heroButtons&&!document.querySelector("#games-hero-link")){const link=document.createElement("a");link.id="games-hero-link";link.className="button button-primary";link.href=gamesUrl;link.textContent="Cliente automático 2.4 + guia rápido";heroButtons.appendChild(link);}
  const heroCopy=document.querySelector(".hero-copy");
  if(heroCopy&&!document.querySelector("#automatic-client-notice")){const notice=document.createElement("p");notice.id="automatic-client-notice";notice.className="hero-note";notice.textContent="Novo cliente automático 2.4: proteção local sem configurar DNS ou vínculo. Central opcional para avisos. Consulte os downloads separados.";heroCopy.appendChild(notice);}
  const section=document.querySelector("#download .container")||document.querySelector("#download");
  if(section){
    let card=document.querySelector("#games-download-card");
    if(!card){card=document.createElement("article");card.id="games-download-card";card.className="feature-card feature-blue";section.prepend(card);}
    const title=document.createElement("h3");title.textContent="LabGuard Automático 2.4 — estação do aluno";
    const text=document.createElement("p");text.textContent="Abra o cliente, autorize o administrador e confirme. Instalação, bloqueios locais, monitor e limpeza são ativados em sequência. Não precisa de vínculo para proteger a estação. A Central 1.2 é opcional para avisos e controle remoto. Remoções podem apagar jogos e saves permanentemente.";
    const links=document.createElement("div");links.className="hero-buttons";
    const exe=document.createElement("a");exe.className="button button-primary";exe.href=gamesRelease+"LabGuard-Jogos.exe";exe.textContent="Baixar cliente automático 2.4";
    const guide=document.createElement("a");guide.className="button button-plain";guide.href=gamesRelease+"LabGuard_Guia_Rapido_2.4.pdf";guide.textContent="Guia rápido PDF";
    const choose=document.createElement("a");choose.className="button button-plain";choose.href=gamesUrl;choose.textContent="Central, pacote completo e outros arquivos";
    links.append(exe,guide,choose);card.replaceChildren(title,text,links);
  }
  // Only network-specific controls are populated from the network release metadata.
  const releaseStatus=document.querySelector("#release-status"),controller=new AbortController();const timeout=window.setTimeout(()=>controller.abort(),6500);
  fetch("https://api.github.com/repos/perabru/LabGuard/releases/latest",{signal:controller.signal,headers:{"Accept":"application/vnd.github+json"}}).then(response=>{if(!response.ok)throw new Error("Release unavailable");return response.json();}).then(release=>{
    const version=/^v2\.(\d+)\.(\d+)$/.exec(String(release.tag_name||""));if(!version||Number(version[1])<3)throw new Error("Versão de rede indisponível");const assets=Array.isArray(release.assets)?release.assets:[];
    document.querySelectorAll("[data-release-asset]").forEach(link=>{const asset=assets.find(item=>item.name===link.dataset.releaseAsset);if(asset&&typeof asset.browser_download_url==="string"&&asset.browser_download_url.startsWith("https://github.com/perabru/LabGuard/releases/download/")){link.href=asset.browser_download_url;link.textContent=link.dataset.downloadLabel;}});
    const setup=assets.find(asset=>asset.name==="LabGuard-Setup.exe")||null;
    if(setup&&typeof setup.browser_download_url==="string"&&setup.browser_download_url.startsWith("https://github.com/perabru/LabGuard/releases/download/")){document.querySelectorAll(".download-link").forEach(link=>{link.href=setup.browser_download_url;});const size=Number(setup.size);if(releaseStatus)releaseStatus.textContent=`${String(release.tag_name||"Versão disponível").slice(0,40)} · Instalador de rede Windows${Number.isFinite(size)&&size>0?` · ${(size/1048576).toLocaleString("pt-BR",{maximumFractionDigits:1})} MB`:""} · Independente do cliente automático. Consulte o guia antes de configurar DNS.`;}else if(releaseStatus){releaseStatus.textContent="Consulte os arquivos da edição de rede na página de versões do GitHub.";}
  }).catch(()=>{if(releaseStatus)releaseStatus.textContent="Consulte a página de versões para verificar o instalador de rede. Cliente automático e Central têm downloads separados acima.";}).finally(()=>window.clearTimeout(timeout));
})();
