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
  // Product choices and links are rendered in HTML, including without JavaScript.
})();
