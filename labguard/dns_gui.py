"""Three-step setup for Vivo and unmanaged switches, without fake router access."""
from __future__ import annotations
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox
from .ui import ActionButton, RoundCard, BG, PANEL, TEXT, MUTED, PURPLE, BLUE
from .local_dns import validate_config, DNSError, CHECK_DOMAIN


def suggest_dns_settings(snapshot):
    if snapshot.get('mode') == 'demo':return '', ''
    for row in snapshot.get('interfaces', []):
        raw = row.get('ipv4', '')
        if not isinstance(raw, str) or '/' not in raw:continue
        try:
            value = ipaddress.IPv4Interface(raw)
            validate_config(str(value.ip), str(value.network))
            return str(value.ip), str(value.network)
        except (ValueError, DNSError):continue
    return '', ''


def dns_instructions(ip, *, token='consulte o código no painel ativo'):
    address = str(ipaddress.IPv4Address(ip))
    return (
        '1. Mantenha este computador com IP reservado/fixo e o LabGuard aberto.\n'
        '2. No DHCP/LAN do Vivo, se o modelo permitir, anuncie '+address+' como DNS do laboratório. '
        'Se essa opção estiver bloqueada, configure esse DNS nas estações de teste ou por política da TI. '
        'O switch Mercusys não precisa de configuração. Não use um DNS público como alternativa: ele pode contornar a lista.\n'
        '3. Autorize UDP e TCP 53 no firewall deste PC somente para a rede informada. O LabGuard não cria essa regra sozinho.\n'
        '4. Em OUTRO computador, execute:\n'
        'nslookup -type=TXT '+CHECK_DOMAIN+' '+address+'\n'
        'Depois de configurar o DNS, teste também SEM informar o servidor:\n'
        'nslookup -type=TXT '+CHECK_DOMAIN+'\n'
        'Código esperado: '+token+'\n'
        '5. Em Sites, cadastre um domínio ou abra Banco de sites e aplique a lista. '
        'Confira o resultado em Atividade. Consultas recebidas não garantem cobertura de toda a rede.\n'
        'Ao parar o filtro ou desligar este PC, restaure o DNS anterior nos clientes. '
        'VPN, DoH, cache e DNS IPv6 alternativo exigem política complementar da TI.'
    )



def dns_network_choices(snapshot):
    """Offer observed interfaces only; demo data must never prefill a real listener."""
    if snapshot.get('mode') == 'demo':return {}
    choices = {}
    for row in snapshot.get('interfaces', []):
        raw = row.get('ipv4', '')
        if not isinstance(raw, str) or '/' not in raw:continue
        try:
            value = ipaddress.IPv4Interface(raw)
            host, network = str(value.ip), str(value.network)
            validate_config(host, network)
        except (ValueError, DNSError):continue
        choices[str(row.get('name') or 'Conexão')+' · '+host+' · '+network] = (host, network)
    return choices


def effective_dns_service(snapshot, entered_ip):
    service = snapshot.get('dns_service', {})
    active = snapshot.get('source_type') == 'local_dns' and service.get('service_running') is True
    # Instructions always refer to the running endpoint, not unsaved form edits.
    address = service.get('listen', '') if active else entered_ip
    try:address = str(ipaddress.IPv4Address(address))
    except (ValueError, TypeError):address = ''
    return active, address, service


class DNSSetupWindow(tk.Toplevel):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner; self._poll_id = None; self._closed = False
        self.protocol('WM_DELETE_WINDOW', self.close); self.configure(bg=BG)
        self.title('LabGuard | Configurar e testar'); self.geometry('880x700'); self.minsize(820,650); self.transient(owner)
        self.columnconfigure(0, weight=1); self.rowconfigure(2, weight=1)
        self._label(self, 'Vamos colocar o filtro para funcionar', size=21, color=TEXT).grid(row=0,column=0,sticky='ew',padx=22,pady=(18,6))
        self._label(self, 'Siga as três etapas. Vivo e switch simples não precisam de integração para este modo.').grid(row=1,column=0,sticky='ew',padx=22,pady=(0,12))
        self.steps = ttk.Notebook(self); self.steps.grid(row=2,column=0,sticky='nsew',padx=22)
        pages = []
        for title in ('1. Ligar filtro', '2. Usar nos computadores', '3. Testar'):
            page = tk.Frame(self.steps,bg=PANEL,padx=18,pady=15);page.columnconfigure(0,weight=1)
            self.steps.add(page,text=title);pages.append(page)
        setup, clients, tests = pages
        host, network = suggest_dns_settings(owner.snapshot)
        service = owner.snapshot.get('dns_service', {})
        self.host=tk.StringVar(value=service.get('listen',host)); self.network=tk.StringVar(value=service.get('network',network)); self.upstream=tk.StringVar(value=service.get('upstream','1.1.1.1'))
        self._label(setup,'Escolha a conexão do laboratório',size=14,color=TEXT).grid(row=0,column=0,sticky='ew')
        self._choices=dns_network_choices(owner.snapshot); self.connection=tk.StringVar()
        current=next((label for label,values in self._choices.items() if values==(self.host.get(),self.network.get())), '')
        self.connection.set(current)
        self.connection_box=ttk.Combobox(setup,textvariable=self.connection,values=list(self._choices),state='readonly')
        self.connection_box.grid(row=1,column=0,sticky='ew',pady=(10,5));self.connection_box.bind('<<ComboboxSelected>>',self._choose_connection)
        self.endpoint=tk.StringVar();self._label(setup,textvariable=self.endpoint,color=PURPLE).grid(row=2,column=0,sticky='ew',pady=(0,8))
        self.advanced_button=ActionButton(setup,text='Ajustar IP / DNS',command=self._toggle_advanced,height=34)
        self.advanced_button.grid(row=3,column=0,sticky='w')
        self.advanced=tk.Frame(setup,bg=PANEL);self.advanced.columnconfigure(1,weight=1)
        self.advanced.grid(row=4,column=0,sticky='ew',pady=7);self.advanced.grid_remove()
        for n,(label,var) in enumerate((('IP deste PC',self.host),('Rede autorizada (CIDR)',self.network),('DNS de saída',self.upstream))):
            self._label(self.advanced,label).grid(row=n,column=0,sticky='w',pady=3,padx=(0,10))
            ttk.Entry(self.advanced,textvariable=var).grid(row=n,column=1,sticky='ew',pady=3)
        self._label(self.advanced,'DNS na porta 53, UDP e TCP. Escolha um IP fixo/reservado deste PC.').grid(row=3,column=0,columnspan=2,sticky='ew',pady=(4,0))
        if not self._choices and not service.get('listen'):self.advanced.grid()
        self.authorize=tk.BooleanVar(value=False)
        self.autostart=tk.BooleanVar(value=(owner._preferences.get('local_dns') or {}).get('start_on_open') is True)
        for row,text,var in ((5,'Autorizo ligar o filtro neste PC para a rede escolhida',self.authorize),
                (6,'Ligar este filtro ao abrir o LabGuard',self.autostart)):
            tk.Checkbutton(setup,text=text,variable=var,bg=PANEL,fg=TEXT,anchor='w',selectcolor=PANEL).grid(row=row,column=0,sticky='ew',pady=2)
        actions=tk.Frame(setup,bg=PANEL);actions.grid(row=7,column=0,sticky='ew',pady=(12,0))
        self.start_button=ActionButton(actions,text='Iniciar filtro DNS',command=self.start,style='Accent.TButton');self.start_button.pack(side='left')
        ActionButton(actions,text='Salvar início automático',command=self.save_startup).pack(side='left',padx=8)
        self._label(clients,'Use este DNS nos computadores',size=15,color=TEXT).grid(row=0,column=0,sticky='ew')
        self.client_ip=tk.StringVar();self._label(clients,textvariable=self.client_ip,size=23,color=PURPLE).grid(row=1,column=0,sticky='ew',pady=12)
        self._label(clients,'No Vivo, configure esse IP como DNS do DHCP/LAN, se o modelo permitir. Caso não permita, configure o DNS nas estações ou por política da TI. Vale para cabo e Wi-Fi que alcancem este PC.').grid(row=2,column=0,sticky='ew')
        self._label(clients,'Comece em uma estação. Guarde o DNS anterior para restaurar. Não informe um DNS público alternativo: ele pode contornar o filtro.').grid(row=3,column=0,sticky='ew',pady=10)
        bar=tk.Frame(clients,bg=PANEL);bar.grid(row=4,column=0,sticky='ew',pady=(0,8))
        ActionButton(bar,text='Copiar IP',command=self.copy_ip,style='Accent.TButton').pack(side='left')
        ActionButton(bar,text='Ver instruções completas',command=self._toggle_instructions).pack(side='left',padx=8)
        self.instructions_shell=tk.Frame(clients,bg=PANEL);self.instructions_shell.columnconfigure(0,weight=1);self.instructions_shell.rowconfigure(0,weight=1)
        self.instructions_shell.grid(row=5,column=0,sticky='nsew');self.instructions_shell.grid_remove();clients.rowconfigure(5,weight=1)
        self.instructions=tk.Text(self.instructions_shell,height=6,wrap='word',bg=BG,fg=TEXT,font=(owner.font_family,10),padx=10,pady=10,relief='flat')
        self.instructions.grid(row=0,column=0,sticky='nsew');bar=ttk.Scrollbar(self.instructions_shell,command=self.instructions.yview);bar.grid(row=0,column=1,sticky='ns');self.instructions.configure(yscrollcommand=bar.set)
        ActionButton(clients,text='Continuar para teste',command=lambda:self.steps.select(2)).grid(row=6,column=0,sticky='w',pady=(12,0))
        self._label(tests,'Confira o funcionamento',size=15,color=TEXT).grid(row=0,column=0,sticky='ew')
        self._label(tests,'Primeiro, confira as duas portas do filtro neste PC. Depois, teste em outro computador.').grid(row=1,column=0,sticky='ew',pady=(8,12))
        self.verify_button=ActionButton(tests,text='Verificar neste PC',command=self.verify,style='Accent.TButton');self.verify_button.grid(row=2,column=0,sticky='w')
        self.test_result=tk.StringVar(value='Este teste local não confirma o DNS das estações.');self._label(tests,textvariable=self.test_result,color=PURPLE).grid(row=3,column=0,sticky='ew',pady=(10,18))
        self._label(tests,'Em outro computador, abra o terminal e execute:',color=TEXT).grid(row=4,column=0,sticky='ew')
        self._label(tests,'nslookup -type=TXT '+CHECK_DOMAIN,color=TEXT,size=12).grid(row=5,column=0,sticky='ew',pady=8)
        self.token=tk.StringVar();self._label(tests,textvariable=self.token).grid(row=6,column=0,sticky='ew')
        bar=tk.Frame(tests,bg=PANEL);bar.grid(row=7,column=0,sticky='ew',pady=12)
        ActionButton(bar,text='Copiar comando',command=self.copy_test).pack(side='left')
        ActionButton(bar,text='Abrir ajuda',command=owner._open_diagnostics).pack(side='left',padx=8)
        self._label(tests,'Se o código coincidir, essa estação alcançou este filtro. Confira Sites e Atividade. VPN, DNS seguro do navegador e DNS IPv6 alternativo exigem uma política complementar.').grid(row=8,column=0,sticky='ew')
        self.state=tk.StringVar();self._label(self,textvariable=self.state,color=PURPLE).grid(row=3,column=0,sticky='ew',padx=22,pady=(12,6))
        self._label(self,'Mantenha este PC ligado. Antes de parar o filtro, restaure o DNS dos clientes.').grid(row=4,column=0,sticky='ew',padx=22,pady=(0,14))
        self.refresh()

    def _label(self,parent,text='',size=10,color=MUTED,**kw):
        label=tk.Label(parent,text=text,bg=parent.cget('bg'),fg=color,font=(self.owner.font_family,size),anchor='w',justify='left',**kw)
        label.bind('<Configure>',lambda e:label.configure(wraplength=max(180,e.width-4)))
        return label

    def _choose_connection(self, _event=None):
        values=self._choices.get(self.connection.get())
        if values:self.host.set(values[0]);self.network.set(values[1]);self.refresh()

    def _toggle_advanced(self):
        if self.advanced.winfo_manager():self.advanced.grid_remove()
        else:self.advanced.grid()

    def _toggle_instructions(self):
        if self.instructions_shell.winfo_manager():self.instructions_shell.grid_remove()
        else:self.instructions_shell.grid()
        self.refresh()

    def refresh(self):
        active,address,service=effective_dns_service(self.owner.snapshot,self.host.get().strip())
        self.endpoint.set('Filtro em '+address if address else 'Não encontramos uma conexão válida. Informe o IP e a rede em Ajustar IP / DNS.')
        self.client_ip.set(address or 'Informe o IP na etapa 1')
        token=service.get('check_token','aparece após iniciar o filtro')
        self.token.set('Código esperado: '+token)
        try:text=dns_instructions(address,token=token)
        except ValueError:text='Informe o IP real deste computador na etapa 1. O IP do roteador não é o IP do servidor DNS.'
        self.instructions.configure(state='normal');self.instructions.delete('1.0','end');self.instructions.insert('1.0',text);self.instructions.configure(state='disabled')
        self.start_button.configure(state='disabled' if active or self.owner._busy else 'normal')
        self.verify_button.configure(state='normal' if active and not self.owner._busy and getattr(self.owner.transport,'kind','')=='local_dns' else 'disabled')
        self.connection_box.configure(state='disabled' if active else 'readonly')
        self.state.set(('Filtro ativo neste PC · '+str(service.get('received_clients',0))+' IP(s) com consultas. Teste cada estação.') if active else 'Etapa 1: escolha a rede e inicie o filtro.')

    def start(self):
        self.owner._cancel_saved_startup()
        if self.owner._busy:return
        if not self.authorize.get():self.state.set('Marque a autorização para abrir o serviço DNS local.');return
        try:validate_config(self.host.get().strip(),self.network.get().strip(),self.upstream.get().strip())
        except DNSError:self.state.set('Confira o IP deste PC, a rede privada e o DNS de saída.');return
        settings={'host':self.host.get().strip(),'lab_cidr':self.network.get().strip(),'upstream':self.upstream.get().strip(),'manage_rules':True}
        self.owner._demo_requested=False;self.owner.password_var.set('');self.owner.manage_var.set(False)
        if self.owner._start_transport('local_dns',settings,authorized=True,remember_options={'dns_start_on_open':self.autostart.get() is True}):
            self.state.set('Iniciando filtro. Aguarde o resultado…');self.start_button.configure(state='disabled')
            self._poll_id=self.after(250,self._poll_start)

    def _poll_start(self):
        if self._closed:return
        if self.owner._busy:self._poll_id=self.after(250,self._poll_start);return
        self._poll_id=None;self.refresh()
        if self.owner.snapshot.get('source_type')=='local_dns':self.steps.select(1)
        else:self.state.set(self.owner.status.get())

    def verify(self):
        transport=self.owner.transport
        if self._closed or getattr(transport,'kind','')!='local_dns':
            self.state.set('Inicie o filtro na etapa 1 antes de testar.');return False
        def current():return not self._closed and self.owner.transport is transport
        def complete(result):
            if not current():return
            self.refresh()
            if result.get('ok') is True:
                self.test_result.set('Tudo certo neste PC: UDP e TCP responderam com o código correto. Agora teste uma estação.')
            else:
                self.test_result.set('Teste local incompleto. Confira o IP, o filtro e a permissão UDP/TCP 53 no firewall deste PC.')
            self.owner.status.set('Teste do DNS local concluído. A cobertura das estações precisa ser conferida separadamente.')
        def failed(_error):
            if not current():return
            self.refresh();self.test_result.set('Não foi possível testar. Volte à etapa 1 e confira se o filtro está ativo.')
            self.owner.status.set('Teste local não confirmado. Confira a configuração do filtro.')
        started=self.owner._run_job(transport.verify_dns,label='Testando o filtro neste PC',on_success=complete,on_error=failed)
        if started:self.verify_button.configure(state='disabled');self.test_result.set('Testando UDP e TCP…')
        return started

    def close(self):
        self._closed=True
        if self._poll_id is not None:
            try:self.after_cancel(self._poll_id)
            except tk.TclError:pass
        self.destroy()

    def save_startup(self):
        active,_address,service=effective_dns_service(self.owner.snapshot,self.host.get().strip())
        if not active or getattr(self.owner.transport,'kind','')!='local_dns':
            self.state.set('Inicie o filtro com sucesso antes de salvar o início automático.');return
        self.owner._remember_local_dns({'host':service.get('listen'),'lab_cidr':service.get('network'),'upstream':service.get('upstream')},self.autostart.get() is True)
        self.state.set(self.owner._startup_message)

    def copy_ip(self):
        _active,address,_service=effective_dns_service(self.owner.snapshot,self.host.get().strip())
        if not address:self.state.set('Informe o IP na etapa 1 antes de copiar.');return
        self.clipboard_clear();self.clipboard_append(address);self.state.set('IP copiado. Configure uma estação e siga para Testar.')

    def copy_test(self):
        self.clipboard_clear();self.clipboard_append('nslookup -type=TXT '+CHECK_DOMAIN)
        self.state.set('Comando copiado. Execute em OUTRO computador e compare o código esperado.')

    def copy(self):
        self.refresh();self.clipboard_clear();self.clipboard_append(self.instructions.get('1.0','end').strip());self.state.set('Passo a passo copiado.')
