"""Administração DNS de uma estação a partir do PC que mantém o filtro."""
from concurrent.futures import ThreadPoolExecutor
from time import monotonic
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

from .station_policy import StationScope, station_target_from_snapshot
from .station_connectivity import check_winrm_port
from .school_policy import sample_blocked_domain
from .remote import RemoteError, create_session
from .ui import ActionButton, BG, PANEL, TEXT, MUTED, PURPLE


WINDOWS = "Windows · WinRM HTTPS"
LINUX = "Linux · SSH"
PROBE_LABELS = {
    "ok": "Código desta sessão confirmado", "different": "Outro código TXT",
    "nxdomain": "Domínio inexistente", "timeout": "Tempo esgotado",
    "failed": "Consulta falhou", "unavailable": "Recurso indisponível",
}


def _active_service(owner, transport):
    if (owner._closed or owner.transport is not transport
            or getattr(transport, "kind", None) != "local_dns"
            or owner.snapshot.get("source_type") != "local_dns"):
        raise RemoteError("Inicie o filtro DNS local para administrar uma estação.")
    service = owner.snapshot.get("dns_service", {})
    if (not owner._management_authorized or service.get("service_running") is not True
            or not service.get("check_token")):
        raise RemoteError("Confira a autorização e o estado do filtro na etapa Ligar filtro.")
    if (owner._snapshot_stale or monotonic() - owner._last_snapshot_monotonic > 60):
        raise RemoteError("Atualize a leitura do filtro antes de acessar uma estação.")
    return service


def station_target(owner, transport, entered_ip, *, for_change=False):
    _active_service(owner, transport)
    return station_target_from_snapshot(owner.snapshot, entered_ip, for_change=for_change)


def open_station_dns(wizard):
    try:
        _active_service(wizard.owner, wizard.owner.transport)
    except RemoteError as error:
        wizard.state.set(str(error))
        return None
    window = getattr(wizard, "_station_dns_window", None)
    if window is not None and window.winfo_exists():
        window.lift()
        window.focus_set()
        return window
    wizard._station_dns_window = StationDNSWindow(wizard)
    return wizard._station_dns_window


class StationDNSWindow(tk.Toplevel):
    def __init__(self, wizard):
        super().__init__(wizard)
        self.owner = wizard.owner
        self.transport = self.owner.transport
        self._font_family = getattr(self.owner, "font_family", None) or tkfont.nametofont("TkDefaultFont").actual("family")
        self._session = self._api = self._bound = self._preview = self._future = None
        self._closed = False
        self._last_used = monotonic()
        self._poll_id = None
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="labguard-estacao")
        self.title("LabGuard | Estações do laboratório")
        self.configure(bg=BG)
        self.geometry("845x695")
        self.minsize(700, 575)
        self.transient(wizard)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind("<Destroy>", self._destroy_event, add="+")
        self._build()
        self._buttons()
        self._poll_id = self.after(150, self._tick)

    def _label(self, parent, text="", *, variable=None, title=False):
        return tk.Label(parent, text=text, textvariable=variable, bg=parent.cget("bg"),
                        fg=TEXT if title else MUTED, anchor="w", justify="left",
                        wraplength=635, font=(self._font_family, 12 if title else 10, "bold" if title else "normal"))

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        heading = self._label(self, "Estações do laboratório", title=True)
        heading.configure(font=(self._font_family, 18, "bold"), fg=PURPLE)
        heading.grid(row=0, column=0, sticky="ew", padx=18, pady=10)
        canvas = tk.Canvas(self, bg=BG, highlightthickness=0, borderwidth=0)
        scroll = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.grid(row=1, column=0, sticky="nsew", padx=(18, 2))
        scroll.grid(row=1, column=1, sticky="ns")
        body = tk.Frame(canvas, bg=BG)
        item = canvas.create_window(0, 0, window=body, anchor="nw")
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(item, width=e.width))
        form = tk.Frame(body, bg=PANEL, padx=14, pady=12)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        self.target = tk.StringVar()
        self.platform = tk.StringVar(value=WINDOWS)
        self.user = tk.StringVar()
        self.secret = tk.StringVar()
        self.ca = tk.StringVar()
        self.key = tk.StringVar()
        self.known = tk.StringVar()
        self._label(form, "IPv4 da estação").grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.targets = ttk.Combobox(form, textvariable=self.target, postcommand=self._load_targets)
        self.targets.grid(row=0, column=1, sticky="ew", pady=3)
        self._label(form, "Acesso").grid(row=1, column=0, sticky="w")
        self.mode = ttk.Combobox(form, textvariable=self.platform, state="readonly", values=(WINDOWS, LINUX))
        self.mode.grid(row=1, column=1, sticky="ew", pady=3)
        self.mode.bind("<<ComboboxSelected>>", lambda _: self._protocol_changed())
        self.port_row = tk.Frame(form, bg=PANEL)
        self.port_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        self.port_button = ActionButton(self.port_row, text="Verificar porta", command=self.check_port)
        self.port_button.pack(side="left", padx=(0, 10))
        self.port_status = tk.StringVar(value="Teste TCP 5986 a partir deste PC, sem usar a conta da estação.")
        port_label = self._label(self.port_row, variable=self.port_status)
        port_label.configure(wraplength=450)
        port_label.pack(side="left", fill="x", expand=True)
        self._label(form, "Conta administrativa").grid(row=3, column=0, sticky="w")
        self.username = ttk.Entry(form, textvariable=self.user)
        self.username.grid(row=3, column=1, sticky="ew", pady=3)
        self.windows = tk.Frame(form, bg=PANEL)
        self.linux = tk.Frame(form, bg=PANEL)
        for panel in (self.windows, self.linux):
            panel.columnconfigure(1, weight=1)
            panel.grid(row=4, column=0, columnspan=2, sticky="ew")
        self._label(self.windows, "Senha da sessão").grid(row=0, column=0, sticky="w", padx=(0, 15))
        self.password = ttk.Entry(self.windows, textvariable=self.secret, show="*")
        self.password.grid(row=0, column=1, columnspan=2, sticky="ew", pady=3)
        self._file_field(self.windows, 1, "CA HTTPS (opcional)", self.ca)
        self._file_field(self.linux, 0, "Chave SSH (opcional)", self.key)
        self._file_field(self.linux, 1, "known_hosts (opcional)", self.known)
        self.linux.grid_remove()
        self.explanation = tk.StringVar()
        self._label(form, variable=self.explanation).grid(row=5, column=0, columnspan=2, sticky="ew", pady=7)
        self._protocol_changed()
        actions = tk.Frame(form, bg=PANEL)
        actions.grid(row=6, column=0, columnspan=2, sticky="ew")
        self.test_button = ActionButton(actions, text="Testar estação", command=self.test, style="Accent.TButton")
        self.test_button.pack(side="left")
        self.change_button = ActionButton(actions, text="Trocar estação", command=self.disconnect)
        self.change_button.pack(side="left", padx=6)
        results = tk.Frame(body, bg=PANEL, padx=14, pady=10)
        results.pack(fill="x", pady=9)
        self.direct = tk.StringVar(value="Aguardando teste")
        self.default = tk.StringVar(value="Aguardando teste")
        self.blocked = tk.StringVar(value="Aguardando teste")
        for row, (label, var) in enumerate((("Direto ao filtro", self.direct), ("DNS padrão da estação", self.default),
                                            ("Domínio aplicado", self.blocked))):
            self._label(results, label).grid(row=row, column=0, sticky="w", padx=(0, 14), pady=4)
            self._label(results, variable=var, title=True).grid(row=row, column=1, sticky="w")
        controls = tk.Frame(body, bg=PANEL, padx=14, pady=10)
        controls.pack(fill="x")
        self.detail = tk.StringVar(value="No Windows, prepare a alteração para conferir o adaptador e a configuração anterior.")
        self._label(controls, variable=self.detail).pack(fill="x", pady=(0, 7))
        bar = tk.Frame(controls, bg=PANEL)
        bar.pack(anchor="w")
        self.preview_button = ActionButton(bar, text="Preparar alteração", command=self.preview)
        self.apply_button = ActionButton(bar, text="Aplicar DNS", command=self.apply, style="Purple.TButton")
        self.restore_button = ActionButton(bar, text="Restaurar DNS", command=self.restore)
        for button in (self.preview_button, self.apply_button, self.restore_button):
            button.pack(side="left", padx=(0, 6))
        self.status = tk.StringVar(value="Escolha uma estação do inventário ou digite seu IPv4 autorizado.")
        self._label(self, variable=self.status).grid(row=2, column=0, sticky="ew", padx=18, pady=10)
        self.target.trace_add("write", lambda *_: self._reset_results())

    def _file_field(self, panel, row, label, var):
        self._label(panel, label).grid(row=row, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(panel, textvariable=var).grid(row=row, column=1, sticky="ew", pady=3)
        def pick():
            filename = filedialog.askopenfilename(parent=self, title=label)
            if filename:
                var.set(filename)
        ttk.Button(panel, text="Escolher", command=pick).grid(row=row, column=2, padx=(5, 0))

    def _protocol_changed(self):
        windows = self.platform.get() == WINDOWS
        (self.windows if windows else self.linux).grid()
        (self.linux if windows else self.windows).grid_remove()
        if windows:
            self.port_row.grid()
        else:
            self.port_row.grid_remove()
        self.secret.set("")
        self.explanation.set("Use a conta da TI autorizada na estação. A senha é limpa a cada tentativa de conexão."
                             if windows else "Teste por SSH usando chave, servidor conhecido e Python 3 na estação Linux.")
        if hasattr(self, "status"):
            self._reset_results()
            self._buttons()

    def _reset_results(self):
        self.secret.set("")
        self.port_status.set("Teste TCP 5986 a partir deste PC, sem usar a conta da estação.")
        self.direct.set("Aguardando teste")
        self.default.set("Aguardando teste")
        self.blocked.set("Aguardando teste")
        self.detail.set("Teste a estação antes de preparar uma alteração de DNS.")
        self.status.set("Escolha a estação e faça o teste.")

    def _load_targets(self):
        try:
            _active_service(self.owner, self.transport)
            addresses = StationScope(self.owner.snapshot).inventory()
        except RemoteError as error:
            addresses = []
            self.status.set(str(error))
        self.targets.configure(values=addresses)

    def _buttons(self):
        busy = self._future is not None
        connecting = self._session is None
        editable = connecting and not busy
        self.targets.configure(state="normal" if editable else "disabled")
        self.mode.configure(state="readonly" if editable else "disabled")
        self.username.configure(state="normal" if editable else "disabled")
        for panel in (self.windows, self.linux):
            for child in panel.winfo_children():
                if isinstance(child, (ttk.Entry, ttk.Button)):
                    child.configure(state="normal" if editable else "disabled")
        ready = not connecting and not busy and self.platform.get() == WINDOWS
        for button, enabled in ((self.port_button, editable and self.platform.get() == WINDOWS),
                                (self.test_button, not busy), (self.change_button, not connecting and not busy),
                                (self.preview_button, ready), (self.restore_button, ready),
                                (self.apply_button, ready and bool(self._preview))):
            button.configure(state="normal" if enabled else "disabled")

    def _target(self, for_change=False):
        target = station_target(self.owner, self.transport, self.target.get(), for_change=for_change)
        if self._bound is not None and self._bound != target:
            raise RemoteError("Mudou a identidade do alvo ou do filtro. Use Trocar estação e teste novamente.")
        return target

    def _session_args(self):
        return dict(platform="windows" if self.platform.get() == WINDOWS else "linux",
                    user=self.user.get().strip(), password=self.secret.get(), ca_file=self.ca.get().strip(),
                    key_path=self.key.get().strip(), known_hosts=self.known.get().strip())

    def _start(self, action, operation, callback, *, for_change=False, port_only=False):
        if self._closed or self._future is not None:
            return
        try:
            target = self._target(for_change)
        except RemoteError as error:
            self.status.set(str(error))
            return
        session, api = self._session, self._api
        credentials = None
        if session is None and not port_only:
            if self.platform.get() == WINDOWS:
                if not self.user.get().strip():
                    self.status.set("Informe a conta administrativa da estação ou use Verificar porta sem credenciais.")
                    self.username.focus_set()
                    return
                if not self.secret.get():
                    self.status.set("Digite a senha da conta administrativa para esta tentativa ou use Verificar porta.")
                    self.password.focus_set()
                    return
            credentials = self._session_args()
            self.secret.set("")
        def run():
            from .station_dns import StationDNS
            opened = None
            try:
                if self._closed or station_target(self.owner, self.transport, target.address, for_change=for_change) != target:
                    raise RemoteError("A conexão mudou. Atualize o filtro e repita o teste.")
                if port_only:
                    return None, None, operation(target.address)
                active_session = session
                active_api = api
                if active_session is None:
                    opened = create_session(host=target.address, **credentials)
                    active_session = opened
                    active_api = StationDNS(opened, listen=target.listen, network=target.network, token=target.token)
                result = operation(active_api)
                return active_session, active_api, result
            except BaseException:
                if opened is not None:
                    opened.close()
                raise
            finally:
                if credentials is not None:
                    credentials.clear()
        self._last_used = monotonic()
        self._pending_target = target
        self._callback = callback
        self._future = self._worker.submit(run)
        self.status.set(action + "…")
        self._buttons()
        return True

    def check_port(self):
        if self.platform.get() == WINDOWS and self._session is None:
            if self._start("Verificando a porta TCP 5986", check_winrm_port, self._show_port, port_only=True):
                self.port_status.set("Verificando a porta TCP 5986…")

    def _show_port(self, result):
        self.port_status.set(result["message"])
        self.status.set("Preencha a conta e a senha e clique em Testar estação." if result["ok"]
                        else "Confira a orientação ao lado de Verificar porta e repita esse teste.")

    def test(self):
        self._preview = None
        def probe(api):
            state = self.transport.request("snapshot")
            station = station_target_from_snapshot(state, api.target)
            if station != self._pending_target or station.token != api.token:
                raise RemoteError("Mudou a sessão do filtro. Teste a estação com a leitura atual.")
            domain = sample_blocked_domain(state)
            if domain:
                return api.test(blocked_domain=domain, read_evidence=lambda: self.transport.request("snapshot"))
            return api.test()

        if self._start("Testando a partir da estação", probe, self._show_test):
            self.direct.set("Consulta em andamento")
            self.default.set("Consulta em andamento")
            self.blocked.set("Consulta em andamento")

    def _show_test(self, result):
        self.direct.set(PROBE_LABELS.get(result.get("direct"), "Sem confirmação"))
        self.default.set(PROBE_LABELS.get(result.get("default"), "Sem confirmação"))
        domain = result.get("blocked_domain")
        if domain:
            if result.get("block_confirmed") is True:
                report = "Bloqueio confirmado pelo filtro"
            else:
                report = {"nxdomain": "Domínio inexistente, sem confirmação pelo filtro", "resolved": "Resolveu",
                          "timeout": "Tempo esgotado"}.get(result.get("block_result"), "Resultado inconclusivo")
            self.blocked.set(f"{domain} · {report}")
        else:
            self.blocked.set("Cadastre ou aplique um domínio em Sites para testá-lo.")
        self.status.set(result.get("message", "Teste concluído."))

    def preview(self):
        self._preview = None
        self._start("Lendo adaptador e DNS da estação", lambda api: api.preview(), self._show_preview, for_change=True)

    def _show_preview(self, result):
        self._preview = result
        self.detail.set(result["message"])
        self.status.set("Confira a prévia antes de aplicar.")

    def apply(self):
        preview = self._preview
        if not preview or not messagebox.askyesno("Aplicar DNS", preview["message"] + "\n\nAplicar nesta estação?",
                                                  parent=self, default="no"):
            return
        self._preview = None
        self._start("Aplicando e conferindo o DNS", lambda api: api.apply(preview["id"]), self._show_change, for_change=True)

    def restore(self):
        if not self._bound:
            return
        text = "Restaurar a configuração de DNS salva para a estação " + self._bound.address + "?"
        if messagebox.askyesno("Restaurar DNS", text, parent=self, default="no"):
            self._preview = None
            self._start("Restaurando o DNS da estação", lambda api: api.restore(), self._show_change, for_change=True)

    def _show_change(self, result):
        self._preview = None
        self.detail.set(result["message"])
        self.direct.set("Repita o teste para consultar o estado atual")
        self.default.set("Repita o teste para consultar o estado atual")
        self.blocked.set("Repita o teste para consultar o estado atual")
        self.status.set(result["message"])

    def _finish(self):
        future, self._future = self._future, None
        returned = None
        try:
            returned, api, result = future.result()
            if self._target() != self._pending_target:
                raise RemoteError("O alvo ou a sessão do filtro mudou. Confira o estado antes de repetir a operação.")
            if returned is not None:
                self._session, self._api, self._bound = returned, api, self._pending_target
            self._callback(result)
        except Exception as error:
            if returned is not None and returned is not self._session:
                returned.close()
            if self._callback == self._show_port:
                self.port_status.set("Verificação da porta sem resultado.")
            else:
                self._preview = None
                self.direct.set("Sem confirmação")
                self.default.set("Sem confirmação")
                self.blocked.set("Sem confirmação")
                self.detail.set("O teste remoto não entregou resultados de DNS." if self._session is None else
                                "Confira o estado da estação antes de repetir uma alteração.")
            self.status.set(str(error) if isinstance(error, RemoteError) else
                            "A operação falhou. Confira o acesso administrativo e teste novamente.")
        self._last_used = monotonic()
        self._buttons()

    def _tick(self):
        if self._closed:
            return
        if self._future is not None and self._future.done():
            self._finish()
        elif self._session is not None and self._future is None and monotonic() - self._last_used > 600:
            self.disconnect()
            self.status.set("Sessão encerrada por inatividade.")
        self._poll_id = self.after(150, self._tick)

    def disconnect(self):
        if self._future is not None:
            return
        if self._session is not None:
            self._session.close()
        self._session = self._api = self._bound = self._preview = None
        self._reset_results()
        self._buttons()

    def _destroy_event(self, event):
        if event.widget is self:
            self._cleanup()

    def _cleanup(self):
        if self._closed:
            return
        self._closed = True
        if self._poll_id is not None:
            self.after_cancel(self._poll_id)
        future, existing = self._future, self._session
        def release(completed):
            try:
                session, _, _ = completed.result()
            except Exception:
                session = existing
            if session is not None:
                session.close()
        if future is not None:
            future.add_done_callback(release)
        elif existing is not None:
            existing.close()
        self._worker.shutdown(wait=False, cancel_futures=True)

    def close(self):
        if self._future is not None:
            self.status.set("Aguarde a operação desta estação antes de fechar.")
            return
        self._cleanup()
        self.destroy()
