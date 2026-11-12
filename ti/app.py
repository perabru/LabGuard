"""Extend, never replace, the original LabGuard network interface."""
from __future__ import annotations
import queue
from threading import Thread
import tkinter as tk
from tkinter import messagebox,ttk
import webbrowser
from labguard.simple_gui import App as NetworkApp
from labguard.ui import ActionButton, RoundCard, BG, PANEL, TEXT, MUTED, PURPLE, BLUE
from ti import bridge

QUICK_SITES = (('term.ooo','Jogos'),('friv.com','Jogos'),('friv.com.br','Jogos'),
               ('poki.com','Jogos'),('chess.com','Jogos'),('youtube.com','Outros'),
               ('youtu.be','Outros'),('youtube-nocookie.com','Outros'),('youtubekids.com','Outros'))

def append_quick_sites(transport,database):
    """Use the original mutation and persistence path; never replace the rule bank."""
    from labguard.site_controls import apply_site_change
    added=[];errors=[];warnings=[]
    for domain,category in QUICK_SITES:
        try:
            result=apply_site_change(transport,database,domain=domain,category=category,blocked=True)
            if result.get('warning'):warnings.append(domain+': '+result['warning'])
            added.append(domain)
        except Exception as error:
            errors.append(domain+': '+str(error))
            break
    return {'snapshot':transport.request('snapshot'),'added':added,'errors':errors,'warnings':warnings}

class App(NetworkApp):
    def _build(self):
        super()._build()
        self.title('LabGuard TI | Filtro de rede + clientes e avisos')
        nav=self._nav['home'].master
        nav.columnconfigure(4,weight=1)
        button=ActionButton(nav,text='Clientes e avisos',height=42,command=lambda:self.show_page('central'))
        button.grid(row=0,column=4,sticky='ew',padx=(7,0));self._nav['central']=button
        frame=tk.Frame(self._pages['home'].master,bg=BG);frame.grid(row=0,column=0,sticky='nsew')
        frame.columnconfigure(0,weight=1);self._pages['central']=frame
        self._ti_status=tk.StringVar(value='Central: use Conferir conexão para consultar o serviço local.')
        self._ti_port=tk.StringVar(value='8787');self._ti_results=queue.Queue();self._ti_check_busy=False
        frame.rowconfigure(0,weight=1)
        canvas=tk.Canvas(frame,bg=BG,highlightthickness=0)
        canvas.grid(row=0,column=0,sticky='nsew')
        scrollbar=ttk.Scrollbar(frame,orient='vertical',command=canvas.yview)
        scrollbar.grid(row=0,column=1,sticky='ns');canvas.configure(yscrollcommand=scrollbar.set)
        body=tk.Frame(canvas,bg=BG,padx=4,pady=10);body.columnconfigure(0,weight=1)
        item=canvas.create_window(0,0,window=body,anchor='nw')
        body.bind('<Configure>',lambda _:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(item,width=e.width))
        self.bind('<MouseWheel>',lambda e:canvas.yview_scroll(-1 if e.delta>0 else 1,'units') if self._page=='central' else None,add='+')
        self.bind('<Button-4>',lambda _:canvas.yview_scroll(-1,'units') if self._page=='central' else None,add='+')
        self.bind('<Button-5>',lambda _:canvas.yview_scroll(1,'units') if self._page=='central' else None,add='+')
        self._ti_canvas=canvas
        self._label(body,'O filtro continua aqui. A Central acrescenta.',fg=TEXT,font=(self.font_family,20,'bold')).grid(row=0,column=0,sticky='w',pady=(0,8))
        self._label(body,'Início, Dispositivos, Sites, Atividade, mapa, relatórios e opções avançadas mantêm o funcionamento original.',wraplength=970).grid(row=1,column=0,sticky='ew',pady=(0,16))
        network=RoundCard(body,padding=18);network.grid(row=2,column=0,sticky='ew',pady=(0,14))
        self._label(network.body,'1. Filtro de rede / DNS',bg=PANEL,fg=PURPLE,font=(self.font_family,14,'bold')).pack(anchor='w')
        self._label(network.body,'Continua filtrando os computadores que usam o DNS deste PC. Os bancos e as regras anteriores não são substituídos pela Central.',bg=PANEL,wraplength=940).pack(anchor='w',pady=(7,12))
        row=tk.Frame(network.body,bg=PANEL);row.pack(fill='x')
        ActionButton(row,text='Abrir filtro original',command=lambda:self.show_page('home'),height=38).pack(side='left')
        ActionButton(row,text='Sites e bloqueios DNS',command=lambda:self.show_page('sites'),height=38).pack(side='left',padx=8)
        self._ti_quick_button=ActionButton(row,text='Bloquear lista rápida no DNS',command=self._ti_block_quick,height=38)
        self._ti_quick_button.pack(side='left')
        self._label(network.body,'Lista rápida: Termo, Friv, Poki, Chess.com e YouTube. Acrescenta regras; não bloqueia toda a internet. Joguester exige o domínio correto.',bg=PANEL,wraplength=940,font=(self.font_family,9)).pack(anchor='w',pady=(10,0))
        central=RoundCard(body,padding=18);central.grid(row=3,column=0,sticky='ew',pady=(0,14))
        self._label(central.body,'2. Central de clientes e avisos',bg=PANEL,fg=BLUE,font=(self.font_family,14,'bold')).pack(anchor='w')
        self._label(central.body,'Abre o painel existente para jogos, YouTube, Sites rápidos e alertas. A Central tem suas próprias confirmações e não desliga o filtro DNS.',bg=PANEL,wraplength=940).pack(anchor='w',pady=(7,10))
        self._label(central.body,textvariable=self._ti_status,bg=PANEL,fg=TEXT,wraplength=940).pack(anchor='w',pady=(0,8))
        row=tk.Frame(central.body,bg=PANEL);row.pack(fill='x')
        self._label(row,'Porta local:',bg=PANEL).pack(side='left')
        tk.Entry(row,textvariable=self._ti_port,width=7).pack(side='left',padx=(7,12))
        ActionButton(row,text='Abrir Central existente',command=self._ti_open,height=38).pack(side='left')
        ActionButton(row,text='Conferir conexão',command=self._ti_probe,height=38).pack(side='left',padx=8)
        ActionButton(row,text='Instalar / reparar Central',command=self._ti_install,height=38).pack(side='left')
        self._label(central.body,'Já usa Central 1.2? Abra a existente: não precisa recriar vínculos ou senha. Instalar/reparar abre o instalador administrativo incluído no pacote.',bg=PANEL,wraplength=940,font=(self.font_family,9)).pack(anchor='w',pady=(10,0))
        self._label(body,'As duas camadas são complementares. Liberar um site em uma delas não remove o bloqueio da outra. Mantenha o PC do DNS ligado e teste na conta do aluno.',fg=MUTED,wraplength=970).grid(row=4,column=0,sticky='ew')
        self.show_page('home')
        self.after(200,self._ti_drain)

    def _ti_get_port(self):
        try:
            port=int(self._ti_port.get());bridge.panel_url(port);return port
        except (ValueError,TypeError):
            messagebox.showerror('Porta da Central','Informe a porta local correta; padrão 8787.',parent=self);return None

    def _ti_probe(self):
        port=self._ti_get_port()
        if port is None or self._ti_check_busy:return
        self._ti_check_busy=True;self._ti_status.set('Conferindo apenas o serviço local da Central…')
        def work():self._ti_results.put(('health',bridge.health(port)))
        Thread(target=work,daemon=True).start()

    def _ti_drain(self):
        if self._closed:return
        try:
            while True:
                _,result=self._ti_results.get_nowait();self._ti_check_busy=False
                self._ti_status.set(('Central '+result['version']+' respondeu. Entre no painel para conferir os clientes.') if result['ready'] else 'Central sem resposta nesta porta. O filtro de rede é independente e continua no estado anterior.')
        except queue.Empty:pass
        self.after(200,self._ti_drain)

    def _ti_open(self):
        port=self._ti_get_port()
        if port is not None:webbrowser.open(bridge.panel_url(port),new=2);self._ti_probe()

    def _ti_install(self):
        if not messagebox.askyesno('Central complementar','Abrir o instalador da Central 1.2?\n\nSeu filtro DNS e suas regras não serão substituídos. Na Central existente, use Instalar / reparar somente para atualizar ou corrigir essa Central.',parent=self):return
        try:bridge.start_central_setup();self._ti_status.set('Instalador da Central aberto. Conclua a etapa administrativa e confira a conexão.')
        except OSError as error:messagebox.showerror('Central',str(error),parent=self)

    def _ti_block_quick(self):
        if not self._mutation_allowed(('dns',),capability='domain_filtering'):return False
        if not self._confirm('Acrescentar bloqueios DNS','Acrescentar Termo, Friv, Poki, Chess.com e YouTube ao filtro de rede atual?\n\nNenhuma regra anterior será apagada. Isso não altera a política da Central nem corta toda a internet. Estações precisam usar este DNS.'):return False
        if not self._mutation_allowed(('dns',),capability='domain_filtering'):return False
        try:path=self._banlist_path()
        except Exception as error:self.status.set(str(error));return False
        transport=self.transport
        def work():
            from labguard.banlist import BanlistDatabase
            db=BanlistDatabase(path)
            try:return append_quick_sites(transport,db)
            finally:db.close()
        def done(result):
            self._apply_snapshot(result['snapshot'])
            self.status.set('%d regra(s) confirmada(s) nesta solicitação. Regras anteriores mantidas.' % len(result['added']))
            if result['errors'] or result['warnings']:messagebox.showwarning('Confira as pendências','\n'.join(result['errors']+result['warnings']),parent=self)
            else:messagebox.showinfo('Lista acrescentada','Bloqueios acrescentados ao filtro DNS. Reabra o navegador e teste em uma estação.\n\nA Central mantém suas próprias políticas.',parent=self)
        return self._run_job(work,label='Acrescentando lista ao filtro DNS',on_success=done,alert=True)
