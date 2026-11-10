"""Three-step setup for Vivo and unmanaged switches, without fake router access."""
from __future__ import annotations
import ipaddress
import tkinter as tk
import webbrowser
from tkinter import ttk, messagebox
from .ui import ActionButton, RoundCard, BG, PANEL, TEXT, MUTED, PURPLE, BLUE
from .local_dns import validate_config, DNSError, CHECK_DOMAIN


FAMILY_RESOLVER = '1.1.1.3'
DEFAULT_RESOLVER = '1.1.1.1'
NETWORK_TOOLS_GUIDE = 'https://perabru.github.io/LabGuard/tecnico/dns-ipv6.html'


def initial_resolver(service, saved):
    upstream = service.get('upstream') or saved.get('upstream') or DEFAULT_RESOLVER
    if upstream == FAMILY_RESOLVER:
        return True, saved.get('custom_upstream') or DEFAULT_RESOLVER
    return False, upstream


def suggest_dns_settings(snapshot):
    return next(iter(dns_network_choices(snapshot).values()), ('', ''))


def diagnostic_commands(address, port=53):
    """Return Windows commands with a literal endpoint and an absolute DNS name."""
    address = str(ipaddress.IPv4Address(address))
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Porta DNS inválida')
    question = '-type=TXT ' + CHECK_DOMAIN + '.'
    port_option = '' if port == 53 else f'-port={port} '
    return f'nslookup {port_option}{question} {address}', f'nslookup {question}'


def dns_instructions(ip, *, token='consulte o código no painel ativo', commands=None):
    address = str(ipaddress.IPv4Address(ip))
    if commands is None:
        commands = diagnostic_commands(address)
    support = (
        'Diagnóstico manual opcional no CMD da estação. Compare o texto TXT dos dois resultados '
        f'com o código atual {token}.\nTeste direto no filtro: {commands[0]}\n'
        f'Teste do DNS padrão da estação: {commands[1]}\n'
        if commands else 'Os comandos de diagnóstico ficam disponíveis após ligar o filtro.\n'
    )
    return (
        'Abra Administrar estações para verificar ou configurar o DNS de máquinas com gestão remota habilitada.\n'
        'Mantenha o PC do filtro ligado, com IP reservado ou fixo. Autorize UDP e TCP 53 no firewall '
        'somente para a rede do laboratório.\n'
        'Se usar distribuição pelo DHCP/LAN do Vivo, anuncie '+address+' como DNS quando o modelo permitir. '
        'Para configurar manualmente nas estações, guarde o DNS anterior. Um DNS alternativo pode contornar a lista.\n'
        + support +
        'Em Sites, aplique os domínios desejados. Em Atividade, confira domínio, origem e horário '
        'da consulta. Antes de parar o filtro, restaure o DNS anterior nos clientes.'
    )


CMD_RESULTS = {
    'Os dois testes retornam o código atual':
        'Essa estação recebeu o código da sessão diretamente e pelo DNS padrão. Teste um domínio permitido e um bloqueado no aplicativo usado em aula.',
    'Domínio inexistente no teste padrão (NXDOMAIN)':
        'Se o direto respondeu com o código atual, confira Servidor e Address no teste padrão. Um endereço fe80:: indica um resolvedor IPv6. Revise os DNS do adaptador ativo com a TI e repita o teste padrão.',
    'Domínio inexistente no teste direto (NXDOMAIN)':
        'Copie novamente o teste direto. Confira o IP após o nome terminado em ponto e se o filtro está ativo nesse endereço. Em Atividade, confira domínio, IP de origem e horário.',
    'Tempo esgotado no teste direto':
        'Confira se o filtro está ligado e acessível a partir da estação. Revise a sub-rede autorizada, isolamento de Wi-Fi ou VLAN e a entrada UDP/TCP 53 no firewall do PC do filtro.',
    'Código TXT diferente':
        'O código muda quando o filtro reinicia. Compare com o código da sessão atual e execute os dois testes novamente. Se apenas o padrão divergir, confira os DNS da estação.',
}


def dns_network_choices(snapshot):
    """Offer observed interfaces only; demo data must never prefill a real listener."""
    mode = snapshot.get('mode', 'observation')
    if mode != 'observation' and not (mode == 'equipment' and snapshot.get('source_type') == 'local_dns'):
        return {}
    choices = {}
    for row in snapshot.get('interfaces', []):
        if not isinstance(row, dict):
            continue
        raw = row.get('ipv4', '')
        if not isinstance(raw, str):
            continue
        if '/' not in raw:
            prefix = row.get('prefixlen')
            if type(prefix) is not int or not 0 <= prefix <= 32:
                continue
            raw = f'{raw}/{prefix}'
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
        saved = owner._preferences.get('local_dns') or {}
        family, custom = initial_resolver(service, saved)
        self.host = tk.StringVar(value=service.get('listen', host))
        self.network = tk.StringVar(value=service.get('network', network))
        self.upstream = tk.StringVar(value=custom)
        self.family_mode = tk.BooleanVar(value=family)
        self._advanced_window = None
        self._label(setup,'Escolha a conexão do laboratório',size=14,color=TEXT).grid(row=0,column=0,sticky='ew')
        self._choices=dns_network_choices(owner.snapshot); self.connection=tk.StringVar()
        current=next((label for label,values in self._choices.items() if values==(self.host.get(),self.network.get())), '')
        self.connection.set(current)
        self.connection_box=ttk.Combobox(setup,textvariable=self.connection,values=list(self._choices),state='readonly')
        self.connection_box.grid(row=1,column=0,sticky='ew',pady=(10,5));self.connection_box.bind('<<ComboboxSelected>>',self._choose_connection)
        self.endpoint=tk.StringVar();self._label(setup,textvariable=self.endpoint,color=PURPLE).grid(row=2,column=0,sticky='ew',pady=(0,8))
        self.advanced_button=ActionButton(setup,text='Ajustar IP / DNS',command=self._toggle_advanced,height=34)
        self.advanced_button.grid(row=3,column=0,sticky='w')
        self.family_check = tk.Checkbutton(setup, text='Filtrar conteúdo adulto e malware com Cloudflare Families',
                                         variable=self.family_mode, bg=PANEL, fg=TEXT, anchor='w', selectcolor=PANEL)
        self.family_check.grid(row=4, column=0, sticky='ew', pady=(8,0))
        self._label(setup, 'Essa opção encaminha consultas permitidas à Cloudflare (1.1.1.3). Se a escola usa nomes internos ou Active Directory, mantenha o DNS interno da TI em Ajustar IP / DNS.').grid(row=5, column=0, sticky='ew', pady=(2,6))
        self.authorize=tk.BooleanVar(value=False)
        self.autostart=tk.BooleanVar(value=(owner._preferences.get('local_dns') or {}).get('start_on_open') is True)
        for row,text,var in ((6,'Autorizo ligar o filtro neste PC para a rede escolhida',self.authorize),
                (7,'Ligar este filtro ao abrir o LabGuard',self.autostart)):
            tk.Checkbutton(setup,text=text,variable=var,bg=PANEL,fg=TEXT,anchor='w',selectcolor=PANEL).grid(row=row,column=0,sticky='ew',pady=2)
        actions = tk.Frame(setup, bg=PANEL)
        actions.grid(row=8, column=0, sticky='ew', pady=(12,0))
        self.protect_button = ActionButton(actions, text='Proteger laboratório', command=self.protect, style='Accent.TButton')
        self.protect_button.pack(side='left')
        self.start_button = ActionButton(actions, text='Iniciar filtro DNS', command=self.start)
        self.start_button.pack(side='left', padx=8)
        ActionButton(actions, text='Salvar início automático', command=self.save_startup).pack(side='left')
        self.protection_report = tk.StringVar(value='Proteger laboratório aplica a lista escolar de jogos e sites adultos ao filtro local.')
        self._label(setup, textvariable=self.protection_report, color=PURPLE).grid(row=9, column=0, sticky='ew', pady=(8,0))
        self._label(clients,'Use este DNS nos computadores',size=15,color=TEXT).grid(row=0,column=0,sticky='ew')
        self.client_ip=tk.StringVar();self._label(clients,textvariable=self.client_ip,size=23,color=PURPLE).grid(row=1,column=0,sticky='ew',pady=12)
        self._label(clients, 'Sem cliente instalado: configure o DNS na estação. O guia inclui uma ferramenta para ajustar o DNS IPv4 e desabilitar IPv6 no adaptador escolhido, com restauração. A administração remota é opcional e exige um canal já preparado.').grid(row=2,column=0,sticky='ew')
        client_actions = tk.Frame(clients, bg=PANEL)
        client_actions.grid(row=3, column=0, sticky='ew', pady=10)
        ActionButton(client_actions, text='Guia e ferramenta IPv6', command=self._open_network_tool_guide, style='Accent.TButton').pack(side='left')
        self.manage_clients_button = ActionButton(client_actions, text='Administrar estações', command=self._open_stations)
        self.manage_clients_button.pack(side='left', padx=8)
        bar = tk.Frame(clients, bg=PANEL)
        bar.grid(row=4, column=0, sticky='ew', pady=(0,8))
        ActionButton(bar, text='Copiar IP', command=self.copy_ip).pack(side='left')
        ActionButton(bar, text='Ver instruções completas', command=self._toggle_instructions).pack(side='left', padx=8)
        self.instructions_shell=tk.Frame(clients,bg=PANEL);self.instructions_shell.columnconfigure(0,weight=1);self.instructions_shell.rowconfigure(0,weight=1)
        self.instructions_shell.grid(row=5,column=0,sticky='nsew');self.instructions_shell.grid_remove();clients.rowconfigure(5,weight=1)
        self.instructions=tk.Text(self.instructions_shell,height=6,wrap='word',bg=BG,fg=TEXT,font=(owner.font_family,10),padx=10,pady=10,relief='flat')
        self.instructions.grid(row=0,column=0,sticky='nsew');bar=ttk.Scrollbar(self.instructions_shell,command=self.instructions.yview);bar.grid(row=0,column=1,sticky='ns');self.instructions.configure(yscrollcommand=bar.set)
        ActionButton(clients,text='Continuar para teste',command=lambda:self.steps.select(2)).grid(row=6,column=0,sticky='w',pady=(12,0))
        self._label(tests, 'Testar uma estação pelo painel', size=15, color=TEXT).grid(row=0, column=0, sticky='ew')
        self._label(tests, 'Escolha a estação para comparar a resposta do filtro com a do DNS configurado na máquina.').grid(row=1, column=0, sticky='ew', pady=(8,10))
        self.manage_tests_button = ActionButton(tests, text='Administrar estações', command=self._open_stations, style='Accent.TButton')
        self.manage_tests_button.grid(row=2, column=0, sticky='w')
        self.token = tk.StringVar()
        self._label(tests, textvariable=self.token, color=PURPLE).grid(row=3, column=0, sticky='ew', pady=(8,16))
        self._label(tests, 'Filtro neste computador', size=12, color=TEXT).grid(row=4, column=0, sticky='ew')
        self.verify_button = ActionButton(tests, text='Verificar neste PC', command=self.verify)
        self.verify_button.grid(row=5, column=0, sticky='w', pady=(6,4))
        self.test_result = tk.StringVar(value='O teste local confere as respostas UDP e TCP do filtro.')
        self._label(tests, textvariable=self.test_result).grid(row=6, column=0, sticky='ew', pady=4)
        support = tk.Frame(tests, bg=PANEL)
        support.grid(row=7, column=0, sticky='ew', pady=(12,0))
        ActionButton(support, text='Diagnóstico manual', command=self._open_manual_tests).pack(side='left')
        ActionButton(support, text='Abrir ajuda', command=owner._open_diagnostics).pack(side='left', padx=8)
        self._manual_window = None
        self.direct_command = tk.StringVar()
        self.default_command = tk.StringVar()
        self.state=tk.StringVar();self._label(self,textvariable=self.state,color=PURPLE).grid(row=3,column=0,sticky='ew',padx=22,pady=(12,6))
        self._label(self,'Mantenha este PC ligado. Antes de parar o filtro, restaure o DNS dos clientes.').grid(row=4,column=0,sticky='ew',padx=22,pady=(0,14))
        self.refresh()

    def _label(self,parent,text='',size=10,color=MUTED,**kw):
        label=tk.Label(parent,text=text,bg=parent.cget('bg'),fg=color,font=(self.owner.font_family,size),anchor='w',justify='left',**kw)
        label.bind('<Configure>',lambda e:label.configure(wraplength=max(180,e.width-4)))
        return label

    def _open_stations(self):
        from .station_dns_gui import open_station_dns
        return open_station_dns(self)

    def _open_network_tool_guide(self):
        try:
            opened = webbrowser.open(NETWORK_TOOLS_GUIDE)
        except Exception:
            opened = False
        if not opened:
            self.state.set('Abra no navegador: ' + NETWORK_TOOLS_GUIDE)
        return opened

    def _station_commands(self):
        snapshot = self.owner.snapshot
        active, address, service = effective_dns_service(snapshot, '')
        if (not active or not address or getattr(self.owner.transport, 'kind', '') != 'local_dns'
                or getattr(self.owner, '_snapshot_stale', False) or not service.get('check_token')):
            return ()
        try:
            return diagnostic_commands(address, service.get('port', 53))
        except ValueError:
            return ()

    def _open_manual_tests(self):
        if self._manual_window is not None and self._manual_window.winfo_exists():
            self._manual_window.lift()
            return
        window = tk.Toplevel(self)
        self._manual_window = window
        window.transient(self)
        window.title('LabGuard | Diagnóstico manual')
        window.configure(bg=PANEL)
        window.geometry('730x480')
        window.minsize(650, 450)
        window.columnconfigure(0, weight=1)
        self._label(window, 'Diagnóstico manual da estação', size=15, color=TEXT).grid(row=0, column=0, sticky='ew', padx=16, pady=(12,6))
        self._label(window, 'Para suporte presencial, execute cada comando no CMD da mesma estação e compare os resultados.').grid(row=1, column=0, sticky='ew', padx=16)
        self._command_buttons = []
        for row, (title, variable, direct) in enumerate((
                ('Copiar teste direto', self.direct_command, True),
                ('Copiar teste padrão', self.default_command, False)), start=2):
            line = tk.Frame(window, bg=PANEL)
            line.grid(row=row, column=0, sticky='ew', padx=16, pady=(8,0))
            line.columnconfigure(0, weight=1)
            ttk.Entry(line, textvariable=variable, state='readonly').grid(row=0, column=0, sticky='ew')
            button = ActionButton(line, text=title, command=lambda value=direct:self.copy_test(value))
            button.grid(row=0, column=1, padx=(8,0))
            self._command_buttons.append(button)
        self._label(window, textvariable=self.token, color=PURPLE).grid(row=4, column=0, sticky='ew', padx=16, pady=(10,12))
        self._label(window, 'Resultado do CMD', size=12, color=TEXT).grid(row=5, column=0, sticky='ew', padx=16)
        result = ttk.Combobox(window, state='readonly', values=list(CMD_RESULTS))
        result.grid(row=6, column=0, sticky='ew', padx=16, pady=6)
        result.current(1)
        guidance = tk.StringVar(window, value=CMD_RESULTS[result.get()])
        result.bind('<<ComboboxSelected>>', lambda _event:guidance.set(CMD_RESULTS[result.get()]))
        self._label(window, textvariable=guidance).grid(row=7, column=0, sticky='ew', padx=16, pady=4)
        self.refresh()

    def _choose_connection(self, _event=None):
        values=self._choices.get(self.connection.get())
        if values:self.host.set(values[0]);self.network.set(values[1]);self.refresh()

    def _toggle_advanced(self):
        if self._advanced_window is not None and self._advanced_window.winfo_exists():
            self._advanced_window.lift()
            return
        active, _, _ = effective_dns_service(self.owner.snapshot, '')
        panel = tk.Toplevel(self)
        self._advanced_window = panel
        panel.transient(self)
        panel.title('LabGuard | Ajustar IP e DNS')
        panel.configure(bg=PANEL, padx=16, pady=12)
        panel.columnconfigure(1, weight=1)
        for row, (label, variable) in enumerate((('IP deste PC', self.host), ('Rede autorizada (CIDR)', self.network),
                                                ('DNS personalizado', self.upstream))):
            self._label(panel, label).grid(row=row, column=0, sticky='w', padx=(0,10), pady=4)
            field = ttk.Entry(panel, textvariable=variable, width=26, state='readonly' if active else 'normal')
            field.grid(row=row, column=1, sticky='ew', pady=4)
        self._label(panel, 'Escolha um IP reservado para o filtro. O DNS personalizado é usado quando Cloudflare Families está desmarcado.').grid(row=3, column=0, columnspan=2, sticky='ew', pady=8)
        ActionButton(panel, text='Concluir', command=lambda:(panel.destroy(), self.refresh())).grid(row=4,column=0,columnspan=2,sticky='e')

    def _toggle_instructions(self):
        if self.instructions_shell.winfo_manager():self.instructions_shell.grid_remove()
        else:self.instructions_shell.grid()
        self.refresh()

    def refresh(self):
        self._owner_state = (id(self.owner.snapshot), self.owner._busy, getattr(self.owner, '_snapshot_stale', False))
        active,address,service=effective_dns_service(self.owner.snapshot,self.host.get().strip())
        choices = dns_network_choices(self.owner.snapshot)
        if choices != self._choices:
            self._choices = choices
            self.connection_box.configure(values=list(choices))
        if not active and not self.host.get().strip() and not self.network.get().strip() and choices:
            label = next(iter(choices)); host, network = choices[label]
            self.host.set(host); self.network.set(network); self.connection.set(label)
            active,address,service=effective_dns_service(self.owner.snapshot,host)
        self.endpoint.set('Filtro em '+address if address else 'Não encontramos uma conexão válida. Informe o IP e a rede em Ajustar IP / DNS.')
        self.client_ip.set(address or 'Informe o IP na etapa 1')
        commands = self._station_commands()
        token = service.get('check_token') if commands else None
        self.token.set('Código da sessão atual: '+token if token else 'Ligue o filtro e atualize a leitura para obter o código desta sessão.')
        self.direct_command.set(commands[0] if commands else '')
        self.default_command.set(commands[1] if commands else '')
        enabled = 'normal' if commands else 'disabled'
        self.manage_clients_button.configure(state=enabled)
        self.manage_tests_button.configure(state=enabled)
        if self._manual_window is not None and self._manual_window.winfo_exists():
            for button in self._command_buttons:
                button.configure(state=enabled)
        try:text=dns_instructions(address, token=token, commands=commands)
        except ValueError:text='Informe o IP real deste computador na etapa 1. O IP do roteador não é o IP do servidor DNS.'
        self.instructions.configure(state='normal');self.instructions.delete('1.0','end');self.instructions.insert('1.0',text);self.instructions.configure(state='disabled')
        if active and service.get('upstream'):
            self.family_mode.set(service['upstream'] == FAMILY_RESOLVER)
            if not self.family_mode.get():
                self.upstream.set(service['upstream'])
        self.family_check.configure(state='disabled' if active or self.owner._busy else 'normal')
        real_source = self.owner.snapshot.get('mode') != 'demo'
        ready = real_source and not self.owner._busy and (not active or bool(commands))
        self.protect_button.configure(state='normal' if ready else 'disabled')
        self.start_button.configure(state='disabled' if active or self.owner._busy else 'normal')
        self.verify_button.configure(state='normal' if active and not self.owner._busy and getattr(self.owner.transport,'kind','')=='local_dns' else 'disabled')
        self.connection_box.configure(state='disabled' if active else 'readonly')
        if active:
            self.state.set(f"Filtro ativo neste PC · {service.get('received_clients', 0)} IP(s) com consultas · "
                           f"{service.get('local_diagnostic_queries', 0)} consulta(s) de autoteste local.")
        else:
            self.state.set('Escolha a rede e inicie o filtro na etapa 1.')

    def sync_owner(self):
        """Follow completed reads/errors without polling or overwriting form edits."""
        if self._closed:return
        state = (id(self.owner.snapshot), self.owner._busy, getattr(self.owner, '_snapshot_stale', False))
        if state != self.__dict__.get('_owner_state'):
            self._owner_state = state
            self.refresh()

    def protect(self):
        if self.owner.snapshot.get('mode') == 'demo':
            self.state.set('Escolha Observar esta rede em Opções avançadas para proteger o laboratório real.')
            return False
        active, _, _ = effective_dns_service(self.owner.snapshot, '')
        if active:
            return self.owner._apply_school_protection()
        return self.start(protect=True)

    def start(self, *, protect=False):
        self.owner._cancel_saved_startup()
        if self.owner._busy:
            return False
        if not self.authorize.get():
            self.state.set('Marque a autorização para abrir o serviço DNS local.')
            return False
        host = self.host.get().strip()
        network = self.network.get().strip()
        custom = self.upstream.get().strip()
        resolver = FAMILY_RESOLVER if self.family_mode.get() else custom
        try:
            validate_config(host, network, custom)
            validate_config(host, network, resolver)
        except DNSError:
            self.state.set('Confira o IP deste PC, a rede privada e o DNS personalizado em Ajustar IP / DNS.')
            return False
        if protect and not self.owner._confirm_school_protection(host):
            return False
        settings = {'host': host, 'lab_cidr': network, 'upstream': resolver, 'manage_rules': True}
        options = {'dns_start_on_open': self.autostart.get() is True, 'apply_school_policy': protect}
        if self.family_mode.get():
            options['custom_upstream'] = custom
        self.owner._demo_requested = False
        self.owner.password_var.set('')
        self.owner.manage_var.set(False)
        if self.owner._start_transport('local_dns', settings, authorized=True, remember_options=options):
            self.state.set('Iniciando filtro. Aguarde o resultado…')
            self.start_button.configure(state='disabled')
            self._poll_id = self.after(250, self._poll_start)
            return True
        return False

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
                self.test_result.set('Tudo certo neste PC. UDP e TCP responderam com o código correto. Use Administrar estações para testar uma máquina.')
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
        settings = {'host':service.get('listen'), 'lab_cidr':service.get('network'), 'upstream':service.get('upstream')}
        if settings['upstream'] == FAMILY_RESOLVER:
            settings['custom_upstream'] = self.upstream.get().strip()
        self.owner._remember_local_dns(settings, self.autostart.get() is True)
        self.state.set(self.owner._startup_message)

    def copy_ip(self):
        _active,address,_service=effective_dns_service(self.owner.snapshot,self.host.get().strip())
        if not address:self.state.set('Informe o IP na etapa 1 antes de copiar.');return
        self.clipboard_clear();self.clipboard_append(address);self.state.set('IP copiado. Configure uma estação e siga para Testar.')

    def copy_test(self, direct=True):
        commands = self._station_commands()
        if not commands:
            self.refresh()
            self.state.set('Ligue o filtro e atualize a leitura para copiar o comando da sessão atual.')
            return
        self.clipboard_clear()
        self.clipboard_append(commands[0] if direct else commands[1])
        self.state.set('Comando copiado para o diagnóstico manual da estação.')

    def copy(self):
        self.refresh();self.clipboard_clear();self.clipboard_append(self.instructions.get('1.0','end').strip());self.state.set('Passo a passo copiado.')
