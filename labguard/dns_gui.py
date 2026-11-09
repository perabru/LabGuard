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


class DNSSetupWindow(tk.Toplevel):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner; self._poll_id=None; self._closed=False; self.protocol('WM_DELETE_WINDOW',self.close); self.configure(bg=BG); self.title('LabGuard | Vivo e switch simples')
        self.geometry('930x770'); self.minsize(820,650); self.transient(owner)
        self.columnconfigure(0, weight=1); self.rowconfigure(4, weight=1)
        self._label(self, 'Bloquear sites sem MikroTik', size=21, color=TEXT).grid(row=0,column=0,sticky='ew',padx=22,pady=(18,6))
        self._label(self, 'Vivo + switch Mercusys não gerenciável: o filtro funciona neste PC. Os clientes precisam usar este DNS.').grid(row=1,column=0,sticky='ew',padx=22,pady=(0,12))
        card = RoundCard(self,padding=16);card.grid(row=2,column=0,sticky='ew',padx=22)
        body=card.body;body.columnconfigure(1,weight=1)
        host, network = suggest_dns_settings(owner.snapshot)
        service=owner.snapshot.get('dns_service', {})
        self.host=tk.StringVar(value=service.get('listen',host)); self.network=tk.StringVar(value=service.get('network',network)); self.upstream=tk.StringVar(value=service.get('upstream','1.1.1.1'))
        for n,(label,var) in enumerate((('IP deste computador',self.host),('Rede autorizada (CIDR)',self.network),('DNS de saída',self.upstream))):
            self._label(body,label).grid(row=n,column=0,sticky='w',pady=4,padx=(0,10))
            ttk.Entry(body,textvariable=var).grid(row=n,column=1,sticky='ew',pady=4)
        self._label(body,'A porta é 53, em UDP e TCP. O DNS de saída recebe somente consultas que não estão bloqueadas.').grid(row=3,column=0,columnspan=2,sticky='ew',pady=6)
        self.authorize=tk.BooleanVar(value=False)
        tk.Checkbutton(body,text='Autorizar iniciar o DNS local para esta rede, carregando apenas regras já aplicadas',variable=self.authorize,bg=PANEL,fg=TEXT,anchor='w').grid(row=4,column=0,columnspan=2,sticky='ew')
        self.autostart=tk.BooleanVar(value=(owner._preferences.get('local_dns') or {}).get('start_on_open') is True)
        tk.Checkbutton(body,text='Iniciar este filtro automaticamente ao abrir o LabGuard',variable=self.autostart,bg=PANEL,fg=TEXT,anchor='w').grid(row=5,column=0,columnspan=2,sticky='ew')
        actions=tk.Frame(self,bg=BG);actions.grid(row=3,column=0,sticky='ew',padx=22,pady=10)
        self.start_button=ActionButton(actions,text='Iniciar filtro DNS',command=self.start,style='Accent.TButton');self.start_button.pack(side='left')
        ActionButton(actions,text='Atualizar instruções',command=self.refresh).pack(side='left',padx=8)
        ActionButton(actions,text='Copiar passo a passo',command=self.copy).pack(side='left')
        ActionButton(actions,text='Salvar início',command=self.save_startup).pack(side='left',padx=8)
        shell=tk.Frame(self,bg=BG);shell.grid(row=4,column=0,sticky='nsew',padx=22);shell.columnconfigure(0,weight=1);shell.rowconfigure(0,weight=1)
        self.instructions=tk.Text(shell,wrap='word',bg=PANEL,fg=TEXT,font=(owner.font_family,10),padx=13,pady=12,relief='flat')
        self.instructions.grid(row=0,column=0,sticky='nsew')
        bar=ttk.Scrollbar(shell,command=self.instructions.yview);bar.grid(row=0,column=1,sticky='ns');self.instructions.configure(yscrollcommand=bar.set)
        self.state=tk.StringVar();self._label(self,textvariable=self.state,color=PURPLE).grid(row=5,column=0,sticky='ew',padx=22,pady=12)
        self._label(self,'Este modo não corta internet por IP/MAC, não controla portas do switch e não remove programas.').grid(row=6,column=0,sticky='ew',padx=22,pady=(0,12))
        self.refresh()

    def _label(self,parent,text='',size=10,color=MUTED,**kw):
        label=tk.Label(parent,text=text,bg=parent.cget('bg'),fg=color,font=(self.owner.font_family,size),anchor='w',justify='left',**kw)
        label.bind('<Configure>',lambda e:label.configure(wraplength=max(200,e.width-4)))
        return label

    def refresh(self):
        service=self.owner.snapshot.get('dns_service',{})
        active=self.owner.snapshot.get('source_type')=='local_dns' and service.get('service_running') is True
        try:text=dns_instructions(self.host.get().strip(),token=service.get('check_token','aparece após iniciar o filtro'))
        except ValueError:text='Informe o IP real deste computador para gerar as instruções. O endereço do roteador Vivo não é o IP do servidor DNS.'
        self.instructions.configure(state='normal');self.instructions.delete('1.0','end');self.instructions.insert('1.0',text);self.instructions.configure(state='disabled')
        self.start_button.configure(state='disabled' if active or self.owner._busy else 'normal')
        self.state.set(('DNS local ativo · '+str(service.get('received_clients',0))+' IP(s) enviaram consultas. Confira cada estação; não há cobertura total confirmada.') if active else 'Aguardando ativação. Nenhuma configuração de roteador, estação ou firewall foi alterada.')

    def start(self):
        self.owner._cancel_saved_startup()
        if self.owner._busy:return
        if not self.authorize.get():self.state.set('Marque a autorização para abrir o serviço DNS local.');return
        try:validate_config(self.host.get().strip(),self.network.get().strip(),self.upstream.get().strip())
        except DNSError:self.state.set('Confira o IP deste PC, a rede privada e o DNS de saída.');return
        settings={'host':self.host.get().strip(),'lab_cidr':self.network.get().strip(),'upstream':self.upstream.get().strip(),'manage_rules':True}
        self.owner._demo_requested = False
        self.owner.password_var.set(''); self.owner.manage_var.set(False)
        if self.owner._start_transport('local_dns',settings,authorized=True,remember_options={'dns_start_on_open':self.autostart.get() is True}):
            self.state.set('Iniciando filtro. Aguarde o resultado…');self.start_button.configure(state='disabled')
            self._poll_id=self.after(250,self._poll_start)

    def _poll_start(self):
        if self._closed:return
        if self.owner._busy:self._poll_id=self.after(250,self._poll_start);return
        self._poll_id=None;self.refresh()
        if self.owner.snapshot.get('source_type') != 'local_dns':self.state.set(self.owner.status.get())

    def close(self):
        self._closed=True
        if self._poll_id is not None:
            try:self.after_cancel(self._poll_id)
            except tk.TclError:pass
        self.destroy()

    def save_startup(self):
        service=self.owner.snapshot.get('dns_service',{})
        if (self.owner.snapshot.get('source_type') != 'local_dns' or service.get('service_running') is not True
                or getattr(self.owner.transport,'kind','') != 'local_dns'):
            self.state.set('Inicie o filtro com sucesso antes de salvar o início automático.');return
        self.owner._remember_local_dns({'host':service.get('listen'),'lab_cidr':service.get('network'),'upstream':service.get('upstream')},self.autostart.get() is True)
        self.state.set(self.owner._startup_message)

    def copy(self):
        self.refresh();self.clipboard_clear();self.clipboard_append(self.instructions.get('1.0','end').strip());self.state.set('Passo a passo copiado; revise com a TI antes de mudar o DNS dos clientes.')
