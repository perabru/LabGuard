"""Three-page quick-start PDF generated from the actual automatic-installer workflow."""
from pathlib import Path
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
R=Path(__file__).resolve().parent;OUT=R/'dist';OUT.mkdir(exist_ok=True)
P=colors.HexColor('#6135B3');INK=colors.HexColor('#252039');MUTED=colors.HexColor('#625D73');LINE=colors.HexColor('#DFD9EB')
s=getSampleStyleSheet()
s.add(ParagraphStyle(name='LGTitle',fontName='Helvetica-Bold',fontSize=29,leading=32,textColor=INK,spaceAfter=13))
s.add(ParagraphStyle(name='LGH',fontName='Helvetica-Bold',fontSize=17,leading=21,textColor=INK,spaceBefore=15,spaceAfter=9))
s.add(ParagraphStyle(name='LGB',fontName='Helvetica',fontSize=10.5,leading=15,textColor=INK,spaceAfter=8))
s.add(ParagraphStyle(name='LGSmall',fontName='Helvetica',fontSize=9,leading=13,textColor=MUTED,spaceAfter=6))
s.add(ParagraphStyle(name='LGKicker',fontName='Helvetica-Bold',fontSize=9,leading=12,textColor=P,spaceAfter=12))
s.add(ParagraphStyle(name='LGStep',fontName='Helvetica-Bold',fontSize=12,leading=16,textColor=P,spaceAfter=5))
def p(text,style='LGB'):return Paragraph(text,s[style])
def box(title,text,bg='#F0EAF9'):
    t=Table([[p(title,'LGStep')],[p(text)]],colWidths=[489]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor(bg)),('BOX',(0,0),(-1,-1),.5,LINE),('LEFTPADDING',(0,0),(-1,-1),14),('RIGHTPADDING',(0,0),(-1,-1),14),('TOPPADDING',(0,0),(-1,0),12),('BOTTOMPADDING',(0,-1),(-1,-1),8)]));return t
story=[]
def step(n,title,text):story.extend([p(f'{n}. {title}','LGStep'),p(text),Spacer(1,5)])
def footer(canvas,doc):
    w,h=A4;canvas.setStrokeColor(LINE);canvas.line(44,43,w-44,43);canvas.setFont('Helvetica',8);canvas.setFillColor(MUTED);canvas.drawString(44,29,'LabGuard | Cliente automático 2.4 + Central 1.2');canvas.drawRightString(w-44,29,f'Guia rápido  /  {doc.page} de 3')
story += [p('GUIA RÁPIDO  /  WINDOWS 64 BITS','LGKicker'),p('Abra. Confirme.<br/>O LabGuard ativa o restante.','LGTitle'),p('Cliente automático 2.4','LGStep'),p('Proteção local sem preencher IP, sem arquivo de vínculo e sem precisar deixar o painel aberto.'),Spacer(1,6),box('Use este arquivo no computador do aluno','<b>LabGuard-Jogos.exe</b><br/>Ele instala ou atualiza a proteção local. Não é o painel do administrador e não é o desinstalador.'),Spacer(1,18)]
step('1','Abra o executável','Salve o arquivo em <b>Downloads</b>, dê dois cliques e autorize a conta administrativa no pedido do Windows. Não execute de dentro do ZIP: extraia primeiro.')
step('2','Confirme a ativação','Leia o aviso e clique em <b>Sim</b>. Depois disso, a instalação, a configuração inicial, o início das rotinas e a conferência acontecem automaticamente. Não é necessário selecionar um JSON.')
step('3','Confira o resultado e feche','A tela deve informar <b>Proteção local confirmada</b>. Se mostrar pendências, leia o registro antes de sair. Fechar a janela não desliga as tarefas. No próximo login, permanece apenas o ícone identificado na bandeja.')
story += [box('Atenção: remoção permanente','Jogos reconhecidos, saves e mundos das pastas abrangidas podem ser excluídos. Faça backup antes. Use somente nas estações administradas pela instituição. Mantenha os alunos em contas padrão.','#FFF3CE'),Spacer(1,14),p('Na atualização de uma estação já vinculada, o vínculo e a política da Central são preservados. Se a proteção estiver pausada pelo administrador, retome no painel.','LGSmall'),PageBreak()]
story += [p('02  /  O QUE FICA LIGADO','LGKicker'),p('Proteção sem<br/>configuração adicional.','LGTitle')]
rows=[[p('<b>Rotina</b>'),p('<b>Funcionamento</b>')]]
for a,b in [('Fechar jogos','Monitor de processos conhecidos, com intervalo nominal de <b>2 segundos</b>.'),('Limpar instalações','Primeira solicitação na instalação; repetição de <b>5 minutos</b>. Uma operação longa não é sobreposta por outra.'),('Bloquear sites','<b>YouTube, Termo, Friv, Poki e Chess.com</b> ficam configurados localmente para Chrome, Edge e Firefox.'),('Iniciar com o Windows','Tarefas administrativas automáticas. O painel do aluno não precisa ficar aberto.'),('Preservar ferramentas','Roblox Studio, Minecraft Education e ferramentas educacionais reconhecidas não são alvos padrão.')]:rows.append([p(a),p(b)])
t=Table(rows,colWidths=[148,341],hAlign='LEFT');t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#EDE7F7')),('LINEBELOW',(0,0),(-1,-1),.5,LINE),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),10)]));story += [t,p('Teste na conta do aluno','LGH')]
step('1','Reabra o navegador','Feche e abra o navegador após instalar. Teste um site da lista e um site de aula que deve continuar permitido. Uma aba já carregada pode não refletir a mudança imediatamente.')
step('2','Confira os estados','Use <b>Opções avançadas</b> para consultar monitor e registros. A pasta <b>%ProgramData%\\LabGuardJogos2</b> contém <b>install-status.json</b>, <b>guard-status.json</b>, <b>guard.log</b> e <b>remocoes.log</b>.')
story += [box('Limites importantes','<b>Joguester:</b> endereço ainda pendente; informe o domínio real no painel. “Poke” foi interpretado como Poki.<br/><b>Bloquear tudo:</b> bloqueia os sites cadastrados na lista rápida, não toda a internet.<br/>Jogos desconhecidos, renomeados e portáteis podem exigir aprovação de uma pasta exclusiva. ISO não é apagada apenas pela extensão.','#EDF4FE'),Spacer(1,10),p('A confirmação verifica processos, tarefas e gravação das regras, não todo acesso possível. Outros navegadores, proxies e políticas externas podem interferir. Capturas ficam desligadas; não há envio de telas ou histórico de navegação.','LGSmall'),PageBreak()]
story += [p('03  /  PAINEL DO ADMINISTRADOR - OPCIONAL','LGKicker'),p('Conecte para receber avisos<br/>e mudar as regras.','LGTitle')]
step('1','Prepare a Central','No PC administrador, abra <b>LabGuardTecnico.exe</b>. Na primeira instalação, informe IP real/reservado, rede autorizada e senha. Para atualizar uma Central antiga, use <b>Instalar / reparar</b>. A Central 1.2 existente já é compatível.')
step('2','Gere e importe o vínculo','No painel local <b>http://127.0.0.1:8787/</b>, vá a <b>Computadores → Vincular computador</b>. O JSON vale por uma hora e para uma estação. No cliente, abra a administração pelo ícone e escolha <b>Conectar ao painel (opcional)</b>.')
step('3','Confira contato, regras e avisos','Verifique a estação e as confirmações em <b>Computadores</b>. Use <b>Sites rápidos → Bloquear tudo</b> e <b>Avisos e proteção</b>. O contato ocorre em torno de 15 segundos; mantenha o painel aberto/autenticado para notificações do navegador.')
story += [box('Sem conexão, a proteção local continua','Para receber novas regras e avisos, mantenha o PC administrador ligado e acessível por <b>HTTPS/TCP 8788</b>. Não exponha essa porta na internet. Se não houver contato, confira IP, rede autorizada, firewall e relógios.'),p('Não confunda os downloads','LGH')]
rows=[[p('<b>Arquivo</b>','LGSmall'),p('<b>Uso</b>','LGSmall')]]
for a,b in [('LabGuard-Jogos.exe','Proteção local em cada PC dos alunos.'),('LabGuardTecnico.exe','Central e avisos no administrador.'),('Pacote ZIP','Os dois EXEs e este guia; extraia antes de usar.'),('LabGuard-Setup.exe','Edição de rede/DNS, independente deste cliente.'),('LabGuard-Desinstalador.exe','Retirar o produto. Não usar para atualizar.')]:rows.append([p(a,'LGSmall'),p(b,'LGSmall')])
t=Table(rows,colWidths=[192,297]);t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,-1),.4,LINE),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),3)]));story += [t,Spacer(1,12),p('<b>Atualização automática:</b> execute o novo cliente em Downloads. Ele pausa novas limpezas e aguarda a operação atual antes de substituir a instalação. Se não conseguir concluir, mostra a pendência; não force o encerramento do Windows Installer.','LGSmall'),p('EXEs sem certificado comercial: confira a origem e o SHA-256. Não desative antivírus ou UAC. Testes em Windows descartável não substituem o teste em uma estação real do laboratório.','LGSmall')]
doc=SimpleDocTemplate(str(OUT/'LabGuard_Guia_Rapido_2.4.pdf'),pagesize=A4,rightMargin=53,leftMargin=53,topMargin=43,bottomMargin=57,title='LabGuard 2.4 - Guia rápido de instalação automática',author='LabGuard - Bruno Michel Pera')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
print(OUT/'LabGuard_Guia_Rapido_2.4.pdf')
