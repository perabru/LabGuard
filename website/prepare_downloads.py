"""Build static download navigation without altering the separate network edition guides."""
from pathlib import Path
W=Path(__file__).resolve().parent
p=W/'index.html'
s=p.read_text(encoding='utf-8')
if 'id="managed-downloads-ready"' not in s:
    s=s.replace('LabGuard 2.4.4: controle os sites pelo PC do técnico, sem cliente instalado nos alunos. Guia de DNS para Vivo e switch Mercusys, downloads e testes.', 'LabGuard: escolha o arquivo certo. Central no PC administrador, Cliente nos alunos, filtro DNS separado, desinstalador e guias.')
    s=s.replace('<a href="#recursos">Recursos</a>', '<a href="downloads/">Qual arquivo baixar?</a><a href="#recursos">Recursos de rede</a>',1)
    s=s.replace('Encontre os sites na lista do técnico e use Bloquear ou Liberar sem perder o cadastro. O LabGuard filtra o DNS dos computadores do laboratório, sem instalar cliente nas estações. Configure o DNS e confira o resultado no PC do aluno.', 'Para fechar jogos e receber avisos, use a Central no administrador e o Cliente em cada PC dos alunos. Para filtrar domínios por DNS, existe uma edição de rede separada. Escolha os arquivos pelo que cada um faz, não pelo número da versão.')
    s=s.replace('href="#download"><svg class="icon"><use href="#i-download"/></svg> Ver downloads', 'href="downloads/"><svg class="icon"><use href="#i-download"/></svg> Qual arquivo baixar?')
    s=s.replace('> Edição de rede 2.4.4 <span>•</span> Instalação no PC da TI', '> Central 1.2 + Cliente 2.3 <span>•</span> Rede 2.4.4 é outra edição')
    s=s.replace('Interface real do aplicativo · dados de demonstração', 'Interface da edição de rede 2.4 · dados de demonstração')
    start=s.index('    <section class="section download-section" id="download">')
    end=s.index('    <section class="section" id="manual">',start)
    s=s[:start]+'''    <section class="section download-section" id="download"><div class="container" id="managed-downloads-ready">
      <div class="section-heading"><div><span class="section-kicker">COMECE AQUI · CADA ARQUIVO TEM UMA FUNÇÃO</span><h2>Administrador e aluno.<br>Dois programas diferentes.</h2></div><p>Para jogos, avisos e Sites rápidos, use a Central 1.2 junto do Cliente 2.3. A edição de rede 2.4.4 não substitui esse par.</p></div>
      <div class="platform-grid">
        <article class="platform-card"><span class="platform-kicker">01 · NO PC ADMINISTRADOR</span><h3>Central 1.2</h3><p><strong>LabGuardTecnico.exe</strong><br>Mostra computadores e avisos, cria vínculos e envia regras. É o painel da TI, não o programa do aluno.</p><a class="platform-download" href="https://github.com/perabru/LabGuard/releases/download/gerenciado-v2.3.0/LabGuardTecnico.exe">Baixar painel do administrador</a><p>Atualize com <strong>Instalar / reparar</strong>.</p></article>
        <article class="platform-card"><span class="platform-kicker">02 · EM CADA PC DOS ALUNOS</span><h3>Cliente 2.3</h3><p><strong>LabGuard-Jogos.exe</strong><br>Aplica as regras no Windows, fecha jogos reconhecidos e envia avisos à Central. A instalação exige a conta administrativa.</p><a class="platform-download" href="https://github.com/perabru/LabGuard/releases/download/gerenciado-v2.3.0/LabGuard-Jogos.exe">Baixar cliente dos alunos</a><p>Já vinculado? <strong>Atualizar e manter vínculo</strong>.</p></article>
        <article class="platform-card"><span class="platform-kicker">ALTERNATIVA · OS DOIS ARQUIVOS</span><h3>Pacote completo ZIP</h3><p><strong>LabGuard-Gerenciado-Windows.zip</strong><br>Reúne os dois EXEs, instruções e verificações. Extraia antes de executar. Não é outro programa nem instala tudo sozinho.</p><a class="platform-download" href="https://github.com/perabru/LabGuard/releases/download/gerenciado-v2.3.0/LabGuard-Gerenciado-Windows.zip">Baixar pacote completo</a><a class="platform-guide" href="downloads/#guia">Ver o guia rápido →</a></article>
      </div>
      <p class="platform-note"><strong>Não confunda:</strong> LabGuard-Setup.exe é o filtro DNS de rede. LabGuard-Desinstalador.exe serve para retirar o produto. Source code é código-fonte, não um instalador pronto. A limpeza de jogos pode excluir saves permanentemente; teste uma estação com backup.</p>
      <div class="hero-buttons"><a class="button button-primary" href="downloads/">Comparar todos os arquivos e suas funções →</a><a class="button button-plain" href="downloads/#outros">Filtro de rede, Linux, servidores e desinstalador</a></div>
    </div></section>

'''+s[end:]
    s=s.replace('<div class="manual-grid">','<div class="manual-grid"><article class="platform-card"><span class="platform-kicker">CENTRAL + CLIENTE · USO GERENCIADO</span><h3>Guia dos dois executáveis</h3><p>Instale a Central no administrador, vincule cada cliente e confira Sites rápidos, Bloquear tudo e os avisos.</p><a class="platform-download" href="downloads/#guia">Instalar ou atualizar o par atual</a><a class="platform-secondary" href="https://github.com/perabru/LabGuard/blob/main/managed/README.md">Ler instruções completas</a></article>',1)
    s=s.replace('COMECE AQUI · SEM CLIENTE','EDIÇÃO DE REDE · DNS SEM CLIENTE')
    s=s.replace('<h3>Guia do técnico</h3>','<h3>Guia do filtro DNS</h3>')
    s=s.replace('<p>A edição de rede 2.4.4 funciona com o LabGuard no PC da TI.', '<p><strong>Para jogos e avisos gerenciados, sim:</strong> instale Central 1.2 no administrador e Cliente 2.3 em cada estação. <a href="downloads/">Escolher os arquivos</a>.</p><p>Já a edição de rede 2.4.4 funciona com o LabGuard no PC da TI.')
    s=s.replace('>VIVO + SWITCH SIMPLES</span>','>EDIÇÃO DE REDE · VIVO + SWITCH SIMPLES</span>')
    p.write_text(s,encoding='utf-8')
p=W/'script.js';s=p.read_text(encoding='utf-8')
a=s.find('  const gamesUrl=');b=s.find('  const releaseStatus=',a)
if a>=0 and b>a:
    s=s[:a]+'  // Product-specific downloads are static and explained in downloads/.\n'+s[b:]
    p.write_text(s,encoding='utf-8')
p=W/'jogos/index.html';s=p.read_text(encoding='utf-8')
if 'id="managed-edition-notice"' not in s:
    marker='<main id="conteudo">'
    if marker not in s:raise RuntimeError('Games page main not found')
    s=s.replace(marker,marker+'<section id="managed-edition-notice" class="notice wide"><strong>Esta página documenta o cliente local 2.1.</strong><p>Para o cliente atual com avisos na Central, Sites rápidos e Bloquear tudo, use <strong>Cliente 2.3 + Central 1.2</strong>. Os arquivos abaixo são da edição local anterior.</p><a class="button primary" href="../downloads/">Escolher os downloads atuais</a></section>',1)
    p.write_text(s,encoding='utf-8')
print('Static download choices and product roles prepared.')
