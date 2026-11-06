"""Administração remota por recursos nativos previamente habilitados no endpoint."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import queue
from time import monotonic
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .ui import ActionButton, RoundCard, BG, PANEL, TEXT, MUTED, PURPLE

SESSION_IDLE_SECONDS = 600
INVENTORY_VALID_SECONDS = 60
MONITOR_SECONDS = 15
WARNING_INTERVAL_SECONDS = 300


def package_removable(package, protected=False):
    """Somente decisões explícitas do catálogo habilitam uma remoção."""
    return not protected and isinstance(package, dict) and package.get("can_uninstall") is True


def warning_categories(events, domains, target_ip, processes=()):
    """Consultas DNS são sinais de política, nunca prova de uma visita."""
    found = {"games"} if any(isinstance(p, dict) and (p.get("game_id") or p.get("game")) and p.get("is_launcher") is not True for p in processes) else set()
    rules = []
    for row in domains:
        if not isinstance(row, dict):
            continue
        category = str(row.get("category", "")).strip().casefold()
        kind = "games" if category in {"jogo", "jogos", "games"} else (
            "adult" if category in {"adulto", "adultos", "conteúdo adulto", "conteudo adulto", "pornografia"} else None)
        domain = str(row.get("domain", "")).strip().lower().rstrip(".")
        if kind and domain:
            rules.append((domain, kind))
    for event in events:
        if not isinstance(event, dict) or event.get("client_ip") != target_ip:
            continue
        domain = str(event.get("domain", "")).lower().rstrip(".")
        for suffix, kind in rules:
            if domain == suffix or domain.endswith("." + suffix):
                found.add(kind)
    return found


class RemoteWindow(tk.Toplevel):
    """Nenhum cliente residente, configuração remota automática ou senha persistida."""
    def __init__(self, parent, target_ip, protected=False, events_callback=None,
                 domains_callback=None, session_factory=None):
        target_ip = str(ipaddress.ip_address(target_ip))
        super().__init__(parent)
        self.transient(parent)
        self.title(f"LabGuard | Administração remota — {target_ip}")
        self.geometry("1120x820")
        self.minsize(920, 690)
        self.configure(bg=BG)
        self.target_ip = target_ip
        self.protected = bool(protected)
        self.events_callback = events_callback or (lambda: [])
        self.domains_callback = domains_callback or (lambda: [])
        self.session_factory = session_factory
        self.session = None
        self.snapshot = {}
        self._packages = {}
        self._busy = False
        self._closed = False
        self._generation = 0
        self._stale = True
        self._last_snapshot = 0.0
        self._last_activity = monotonic()
        self._last_warning = {}
        self._seen_dns = set()
        self._pending_warnings = set()
        self._log_rows = []
        self._results = queue.Queue()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="labguard-remoto")
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind("<KeyPress>", self._activity, add="+")
        self.bind("<ButtonPress>", self._activity, add="+")
        self.after(80, self._drain)
        self.after(5000, self._check_idle)
        self.after(MONITOR_SECONDS * 1000, self._monitor_tick)

    def _label(self, parent, text="", **kwargs):
        widget = tk.Label(parent, text=text, bg=kwargs.pop("bg", PANEL),
                          fg=kwargs.pop("fg", MUTED), anchor="w", justify="left", **kwargs)
        widget.bind("<Configure>", lambda event: widget.configure(wraplength=max(160, event.width - 4)))
        return widget

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        title = tk.Frame(self, bg=BG)
        title.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 12))
        self._label(title, "ADMINISTRAÇÃO REMOTA · SEM AGENTE", bg=BG, fg=PURPLE,
                    font=("Arial", 8, "bold")).pack(fill="x")
        self._label(title, f"Computador {self.target_ip}", bg=BG, fg=TEXT,
                    font=("Arial", 20, "bold")).pack(fill="x", pady=(4, 6))
        self._label(title, "Usa o gerenciamento nativo já autorizado no computador. O programa não habilita WinRM/SSH nem instala cliente nos alunos.", bg=BG).pack(fill="x")
        form = RoundCard(self, padding=15)
        form.grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 12))
        body = form.body
        body.grid_columnconfigure(0, weight=1)
        self.connection_fields = fields_body = tk.Frame(body, bg=PANEL)
        fields_body.grid(row=0, column=0, sticky="ew")
        self._fields_hidden = False
        for column in (1, 3):
            fields_body.grid_columnconfigure(column, weight=1)
        self.protocol_var = tk.StringVar(value="Windows · WinRM HTTPS")
        self.port_var = tk.StringVar(value="5986")
        self.user_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.ca_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.known_hosts_var = tk.StringVar()
        self.target_var = tk.StringVar(value=self.target_ip)
        fields = [("Acesso", self.protocol_var, "Porta", self.port_var),
                  ("Usuário administrativo", self.user_var, "Senha da sessão", self.password_var),
                  ("Autoridade certificadora HTTPS", self.ca_var, "Chave SSH", self.key_var),
                  ("known_hosts SSH", self.known_hosts_var, "Destino fixo", self.target_var)]
        for row, (left, left_var, right, right_var) in enumerate(fields):
            for column, label, variable in ((0, left, left_var), (2, right, right_var)):
                self._label(fields_body, label).grid(row=row, column=column, sticky="w", padx=(10 if column else 0, 8), pady=4)
                if row == 0 and column == 0:
                    entry = ttk.Combobox(fields_body, textvariable=variable, state="readonly",
                                         values=["Windows · WinRM HTTPS", "Linux · SSH"])
                    entry.bind("<<ComboboxSelected>>", self._protocol_changed)
                else:
                    entry = ttk.Entry(fields_body, textvariable=variable,
                                      show="*" if variable is self.password_var else "",
                                      state="readonly" if row == 3 and column == 2 else "normal")
                entry.grid(row=row, column=column+1, sticky="ew", pady=4)
        commands = tk.Frame(body, bg=PANEL)
        commands.grid(row=1, column=0, sticky="ew", pady=(10, 2))
        self.connect_button = ActionButton(commands, text="Conectar e consultar", style="Accent.TButton", command=self._connect)
        self.connect_button.pack(side="left")
        self.refresh_button = ActionButton(commands, text="Atualizar", command=self._refresh, state="disabled")
        self.refresh_button.pack(side="left", padx=8)
        self.disconnect_button = ActionButton(commands, text="Desconectar", command=self._disconnect, state="disabled")
        self.disconnect_button.pack(side="left")
        ActionButton(commands, text="Selecionar CA", command=lambda: self._pick(self.ca_var)).pack(side="right")
        ActionButton(commands, text="Selecionar chave", command=lambda: self._pick(self.key_var)).pack(side="right", padx=8)

        notebook = ttk.Notebook(self)
        self.notebook = notebook
        notebook.grid(row=2, column=0, sticky="nsew", padx=22)
        games = tk.Frame(notebook, bg=BG)
        warnings = tk.Frame(notebook, bg=BG)
        notebook.add(games, text="Jogos e programas")
        notebook.add(warnings, text="Avisos e monitoramento")
        self._build_inventory(self._scroll_panel(games, 445), games)
        self._build_warnings(self._scroll_panel(warnings, 345))
        self.status = tk.StringVar(value="Nenhum computador conectado. As consultas e remoções exigem acesso administrativo previamente configurado.")
        self._label(self, textvariable=self.status, bg=BG).grid(row=3, column=0, sticky="ew", padx=22, pady=(12, 16))

    def _scroll_panel(self, parent, minheight):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns", padx=(7, 0))
        canvas.configure(yscrollcommand=scroll.set)
        inner = tk.Frame(canvas, bg=BG)
        item = canvas.create_window(0, 0, window=inner, anchor="nw")
        def fit(_event=None):
            canvas.itemconfigure(item, width=max(canvas.winfo_width(), 1),
                height=max(canvas.winfo_height(), inner.winfo_reqheight(), minheight))
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", fit)
        canvas.bind("<Configure>", fit)
        return inner

    def _build_inventory(self, parent, actions_parent=None):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)
        self._label(parent, "Processos reconhecidos no catálogo", bg=BG, fg=TEXT,
                    font=("Arial", 11, "bold")).grid(row=0, column=0, sticky="ew", pady=(12, 5))
        self.process_table = self._table(parent, ("name", "game"), ("Processo", "Jogo reconhecido"), row=1, height=3)
        self._label(parent, "Pacotes reconhecidos no catálogo", bg=BG, fg=TEXT,
                    font=("Arial", 11, "bold")).grid(row=2, column=0, sticky="ew", pady=(12, 5))
        self.package_table = self._table(parent, ("name", "version", "removal", "reason"),
            ("Programa", "Método reconhecido", "Remoção suportada", "Condição / motivo"), row=3, height=5)
        self.package_table.bind("<<TreeviewSelect>>", self._selection)
        bar = tk.Frame(actions_parent or parent, bg=BG)
        bar.grid(row=1 if actions_parent else 4, column=0, sticky="ew", pady=(10, 0))
        self.remove_button = ActionButton(bar, text="Desinstalar selecionado", style="Danger.TButton",
                                         command=self._uninstall, state="disabled")
        self.remove_button.pack(side="left")
        self._label(bar, "Computador protegido: remoções indisponíveis." if self.protected else
            "Sem remoção automática. Cada pacote exige seleção, suporte explícito e confirmação.", bg=BG).pack(side="left", fill="x", expand=True, padx=12)

    def _build_warnings(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(4, weight=1)
        self._label(parent, "Avisos ao usuário conectado", bg=BG, fg=TEXT,
                    font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="ew", pady=(15, 5))
        self._label(parent, "Windows: mensagem via msg.exe para sessão ativa. Linux: aviso via wall em terminais conectados; popup gráfico não é garantido. Uma consulta DNS não comprova uma visita.", bg=BG).grid(row=1, column=0, sticky="ew", pady=(0, 10))
        bar = tk.Frame(parent, bg=BG)
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        self.game_warning_button = ActionButton(bar, text="Enviar aviso sobre jogos", command=lambda: self._send_warning("games"), state="disabled")
        self.game_warning_button.pack(side="left")
        self.adult_warning_button = ActionButton(bar, text="Enviar aviso de política adulta", command=lambda: self._send_warning("adult"), state="disabled")
        self.adult_warning_button.pack(side="left", padx=8)
        self.monitor_var = tk.BooleanVar(value=False)
        tk.Checkbutton(parent, text="Monitorar e avisar enquanto esta janela estiver aberta", variable=self.monitor_var,
            command=self._monitor_changed, bg=BG, fg=TEXT, activebackground=BG,
            selectcolor=PANEL, anchor="w").grid(row=3, column=0, sticky="ew", pady=(0, 9))
        self.log = tk.Text(parent, height=8, bg=PANEL, fg=MUTED, relief="flat", wrap="word",
                           state="disabled", padx=12, pady=10)
        self.log.grid(row=4, column=0, sticky="nsew")
        self._label(parent, "Verificação a cada 15 s; no máximo um aviso de cada tipo a cada 5 min. A sessão expira após 10 min sem interação. Não há serviço residente no aluno.", bg=BG).grid(row=5, column=0, sticky="ew", pady=(10, 0))

    def _table(self, parent, columns, titles, row, height):
        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=row, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse", height=height)
        for column, title in zip(columns, titles):
            tree.heading(column, text=title, anchor="w")
            tree.column(column, width=160 if column != "reason" else 300, minwidth=90, anchor="w")
        tree.grid(row=0, column=0, sticky="nsew")
        vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        return tree

    def _protocol_changed(self, _event=None):
        self.port_var.set("5986" if self.protocol_var.get().startswith("Windows") else "22")
        self.password_var.set("")

    def _pick(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:
            variable.set(path)

    def _activity(self, _event=None):
        self._last_activity = monotonic()

    def _connect(self):
        if self._busy:
            return
        if self.__dict__.get("_fields_hidden", False):
            self.connection_fields.grid()
            self._fields_hidden = False
            self.connect_button.configure(text="Conectar e consultar")
            return
        try:
            port = int(self.port_var.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.status.set("Informe uma porta entre 1 e 65535. O Windows exige HTTPS na porta 5986.")
            return
        settings = {"host": self.target_ip, "port": port,
            "user": self.user_var.get().strip(), "password": self.password_var.get(),
            "ca_file": self.ca_var.get().strip(), "key_path": self.key_var.get().strip(),
            "known_hosts": self.known_hosts_var.get().strip()}
        protocol = "windows" if self.protocol_var.get().startswith("Windows") else "linux"
        self._generation += 1
        def connect():
            factory = self.session_factory
            if factory is None:
                from .remote import create_session
                factory = create_session
            session = factory(platform=protocol, **settings)
            try:
                return session, session.inspect()
            except Exception:
                self._close_session(session)
                raise
        def connected(value):
            old = self.session
            self.session, snapshot = value
            self._close_session(old)
            self.password_var.set("")
            self.connection_fields.grid_remove()
            self._fields_hidden = True
            self.connect_button.configure(text="Alterar acesso")
            self._show(snapshot)
        self._run(connect, connected, "Consultando computador autorizado")

    def _run(self, function, callback, label):
        if self._busy or self._closed:
            return False
        self._busy = True
        self._controls()
        generation = self._generation
        def work():
            try:
                result = function()
                if self._closed or generation != self._generation:
                    if isinstance(result, tuple):
                        self._close_session(result[0])
                    return
                self._results.put((generation, True, result, callback))
            except Exception as error:
                self._results.put((generation, False, str(error), callback))
        self.status.set(label + "…")
        self._executor.submit(work)
        return True

    def _drain(self):
        if self._closed:
            return
        try:
            while True:
                generation, ok, result, callback = self._results.get_nowait()
                if generation != self._generation:
                    if ok and isinstance(result, tuple):
                        self._close_session(result[0])
                    continue
                self._busy = False
                if ok:
                    callback(result)
                else:
                    self._stale = True
                    self.password_var.set("")
                    self.status.set("Operação não concluída. Atualize a consulta antes de agir: " + result)
                    self._append_log("Falha de operação; inventário sem confirmação.")
                self._controls()
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _show(self, snapshot):
        self.snapshot = snapshot
        self._stale = False
        self._last_snapshot = monotonic()
        self._packages = {}
        for tree in (self.process_table, self.package_table):
            children = tree.get_children()
            if children:
                tree.delete(*children)
        for index, process in enumerate(snapshot.get("processes", [])):
            self.process_table.insert("", "end", iid=f"proc:{index}", values=(process.get("name", ""), str(process.get("game", "")) + (" (inicializador)" if process.get("is_launcher") is True else "")))
        for index, package in enumerate(snapshot.get("games", [])):
            key = f"pkg:{index}"
            self._packages[key] = package
            removable = package_removable(package, self.protected)
            self.package_table.insert("", "end", iid=key, values=(package.get("name", ""), package.get("method", ""),
                "Sim" if removable else "Não", "Computador protegido" if self.protected else package.get("reason", "")))
        for warning in snapshot.get("warnings", []):
            self._append_log(str(warning))
        self.status.set(f"Inventário pontual de {self.target_ip} atualizado. Consulta limitada ao catálogo de jogos; detalhes na aba de avisos.")
        self._controls()

    def _fresh(self):
        return bool(self.session and not self._busy and not self._stale and monotonic() - self._last_snapshot <= INVENTORY_VALID_SECONDS)

    def _controls(self):
        fresh = self._fresh()
        self.connect_button.configure(state="disabled" if self._busy else "normal")
        self.refresh_button.configure(state="normal" if self.session and not self._busy else "disabled")
        self.disconnect_button.configure(state="normal" if self.session else "disabled")
        notify = self.snapshot.get("capabilities", {}).get("notify") is True
        for button in (self.game_warning_button, self.adult_warning_button):
            button.configure(state="normal" if fresh and notify else "disabled")
        self._selection()

    def _selection(self, _event=None):
        selected = self.package_table.selection()
        package = self._packages.get(selected[0]) if selected else None
        allowed = self._fresh() and self.snapshot.get("capabilities", {}).get("uninstall") is True and package_removable(package, self.protected)
        self.remove_button.configure(state="normal" if allowed else "disabled")

    def _refresh(self, monitor=False):
        if self.session and not self._busy:
            session = self.session
            def shown(snapshot):
                self._show(snapshot)
                if monitor and self.monitor_var.get():
                    self._monitor_signals()
            self._run(session.inspect, shown, "Atualizando inventário remoto")

    def _uninstall(self):
        selected = self.package_table.selection()
        package = self._packages.get(selected[0]) if selected else None
        if not self._fresh() or self.snapshot.get("capabilities", {}).get("uninstall") is not True or not package_removable(package, self.protected):
            self.status.set("Remoção recusada. Confirme inventário recente, pacote suportado e destino não protegido.")
            return
        install_id = package.get("install_id")
        if not install_id:
            self.status.set("O catálogo não forneceu um identificador de instalação removível.")
            return
        session = self.session
        def previewed(preview):
            if not isinstance(preview, dict) or not self._fresh() or self.protected or preview.get("host") != self.target_ip or not preview.get("token"):
                self.status.set("Prévia de remoção inválida ou sessão sem confirmação. Consulte novamente o computador.")
                return
            game = preview.get("game", {})
            name = str(game.get("name", package.get("name", "Programa")))
            if not messagebox.askyesno("Confirmar desinstalação",
                f"Desinstalar {name} do computador {preview['host']}?\n\n"
                f"Pacote: {game.get('install_id', install_id)}\n"
                f"Método: {game.get('method', 'catálogo reconhecido')}\n\n"
                "Esta ação remove o programa selecionado. " + str(preview.get("data_notice", "")) +
                "\n\nA autorização da prévia é válida por até 60 segundos. Nenhuma remoção automática está habilitada.",
                parent=self, default="no", icon="warning"):
                return
            if not self._fresh() or self.protected or self.session is not session:
                self.status.set("A sessão expirou durante a confirmação. Atualize antes de tentar novamente.")
                return
            token = preview["token"]
            def uninstall():
                result = session.uninstall(token)
                return result, session.inspect()
            def done(value):
                result, snapshot = value
                self._show(snapshot)
                self._append_log(f"Remoção de {name} em {self.target_ip}: " + str(result.get("message", "Solicitação concluída; confira o inventário."))[:500])
            self._run(uninstall, done, "Solicitando desinstalação do pacote confirmado")
        self._run(lambda: session.preview_uninstall(install_id), previewed, "Conferindo prévia de desinstalação")

    def _send_warning(self, kind, automatic=False):
        if kind not in {"games", "adult"} or not self._fresh() or self.snapshot.get("capabilities", {}).get("notify") is not True:
            return False
        now = monotonic()
        if now - self._last_warning.get(kind, -WARNING_INTERVAL_SECONDS) < WARNING_INTERVAL_SECONDS:
            self.status.set("Aguarde o intervalo de cinco minutos antes de repetir este tipo de aviso.")
            return False
        session = self.session
        def sent(result):
            sent_ok = isinstance(result, dict) and result.get("sent") is True
            message = str(result.get("message", "Aviso solicitado ao mecanismo nativo."))[:500] if isinstance(result, dict) else "Resposta de aviso sem confirmação."
            self._append_log(("Aviso solicitado: " if sent_ok else "Aviso não confirmado: ") + message)
            self.status.set(message + " A confirmação de envio não comprova leitura pelo usuário.")
        self._last_warning[kind] = now
        return self._run(lambda: session.notify(kind=kind), sent, "Enviando aviso de política")

    def _monitor_changed(self):
        self._activity()
        self._pending_warnings.clear()
        if self.monitor_var.get() and not self.session:
            self.monitor_var.set(False)
            self.status.set("Conecte o computador antes de habilitar o monitoramento de avisos.")
            return
        if self.monitor_var.get():
            try:
                self._seen_dns = {self._event_key(row) for row in self.events_callback() if isinstance(row, dict)}
            except Exception:
                self._seen_dns = set()
        self._append_log("Monitoramento com avisos ativado nesta janela; consultas DNS anteriores não serão reapresentadas." if self.monitor_var.get() else "Monitoramento com avisos desativado.")

    @staticmethod
    def _event_key(event):
        return str(event.get("time", "")), str(event.get("client_ip", "")), str(event.get("domain", ""))

    def _monitor_signals(self):
        try:
            events = [row for row in self.events_callback() if isinstance(row, dict)]
            new_events = [row for row in events if self._event_key(row) not in self._seen_dns]
            self._seen_dns = {self._event_key(row) for row in events}
            kinds = warning_categories(new_events, self.domains_callback(), self.target_ip,
                                       self.snapshot.get("processes", []))
        except Exception:
            self.status.set("Não foi possível consultar as regras DNS para o monitoramento desta janela.")
            return
        self._pending_warnings.update(kinds)
        for kind in ("games", "adult"):
            if kind not in self._pending_warnings:
                continue
            if monotonic() - self._last_warning.get(kind, -WARNING_INTERVAL_SECONDS) < WARNING_INTERVAL_SECONDS:
                self._pending_warnings.discard(kind)
            elif self._send_warning(kind, automatic=True):
                self._pending_warnings.discard(kind)
                break

    def _monitor_tick(self):
        if self._closed:
            return
        if self.monitor_var.get() and self.session and not self._busy:
            self._refresh(monitor=True)
        self.after(MONITOR_SECONDS * 1000, self._monitor_tick)

    def _append_log(self, message):
        self._log_rows.append(str(message))
        self._log_rows = self._log_rows[-40:]
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", "\n".join(self._log_rows))
        self.log.configure(state="disabled")
        self.log.see("end")

    def _check_idle(self):
        if self._closed:
            return
        if self.session and monotonic() - self._last_activity >= SESSION_IDLE_SECONDS:
            self._disconnect(expired=True)
        self._controls()
        self.after(5000, self._check_idle)

    @staticmethod
    def _close_session(session):
        close = getattr(session, "close", None)
        if callable(close):
            close()

    def _disconnect(self, expired=False):
        self._generation += 1
        old, self.session = self.session, None
        self._close_session(old)
        self._busy = False
        self._stale = True
        self.password_var.set("")
        self.connection_fields.grid()
        self._fields_hidden = False
        self.connect_button.configure(text="Conectar e consultar")
        self.monitor_var.set(False)
        self._seen_dns.clear()
        self._pending_warnings.clear()
        self._controls()
        self.status.set("Sessão encerrada por inatividade; reconecte para agir." if expired else "Sessão remota desconectada. Credenciais removidas da interface.")

    def close(self):
        if self._closed:
            return
        self._disconnect()
        self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()
