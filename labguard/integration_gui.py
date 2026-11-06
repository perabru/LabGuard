"""Central de integrações diretas. As chamadas remotas ficam fora do thread Tk."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import queue
import shutil
from time import monotonic
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .integrations import IntegrationManager, IntegrationError
from .ui import ActionButton

BG = "#F5F3FC"
PANEL = "#FFFFFF"
TEXT = "#21183F"
MUTED = "#736B87"
AMBER = "#8A610D"
PURPLE = "#6C42D9"
BLUE = "#3478F6"
DEEP = "#29184F"
SESSION_IDLE_SECONDS = 600
INVENTORY_VALID_SECONDS = 60


def inventory_rows(snapshot):
    """Preserva os tipos para que uma máquina nunca seja tratada como porta."""
    rows = []
    for index, port in enumerate(snapshot.get("ports", [])):
        macs = port.get("macs", [])
        rows.append((f"port:{index}", "port", port, (
            "Porta", port.get("name", ""), ", ".join(macs) if isinstance(macs, list) else str(macs),
            port.get("status", ""), port.get("description", ""))))
    for index, device in enumerate(snapshot.get("devices", [])):
        rows.append((f"device:{index}", "device", device, (
            "Máquina", device.get("name") or device.get("hostname") or device.get("ip", ""),
            device.get("ip") or device.get("address") or "", device.get("state") or device.get("status") or "Observada",
            device.get("mac", ""))))
    return rows


def capability_text(capabilities):
    names = [("inventory", "inventário"), ("port_control", "controle de portas"),
             ("domain_filtering", "bloqueio de domínios"),
             ("device_internet_cut", "corte de internet por máquina")]
    available = [label for key, label in names if capabilities.get(key)]
    return ", ".join(available) if available else "consulte as notas do perfil"


class IntegrationWindow(tk.Toplevel):
    """Credenciais somente em memória. Não aceita chaves SSH automaticamente."""
    def __init__(self, parent, manager=None):
        super().__init__(parent)
        self.title("LabGuard | Roteadores e switches")
        self.geometry("1100x780")
        self.minsize(900, 650)
        self.configure(bg=BG)
        self.manager = manager or IntegrationManager()
        self.session = None
        self.snapshot = {}
        self._row_data = {}
        self._detail_windows = []
        self._profiles = {}
        self._busy = False
        self._closed = False
        self._generation = 0
        self._stale = True
        self._last_snapshot = 0.0
        self._last_activity = monotonic()
        self._results = queue.Queue()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="labguard-integracao")
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        self._reload_profiles()
        self.bind("<KeyPress>", self._record_activity, add="+")
        self.bind("<ButtonPress>", self._record_activity, add="+")
        self.after(80, self._drain)
        self.after(5000, self._check_idle)

    def _label(self, parent, text, **kwargs):
        color = kwargs.pop("fg", MUTED)
        background = kwargs.pop("bg", None)
        if background is None:
            try:
                background = parent.cget("bg")
            except tk.TclError:
                background = BG
        label = tk.Label(parent, text=text, bg=background, fg=color, justify="left", anchor="w", **kwargs)
        label.bind("<Configure>", lambda event: label.configure(wraplength=max(200, event.width - 6)))
        return label

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        top = tk.Frame(self, bg=DEEP, padx=20, pady=16)
        top.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 15))
        self._label(top, "EQUIPAMENTOS & CONEXÕES", font=("Arial", 8, "bold"), fg="#D8C9F5").pack(fill="x", pady=(0, 5))
        self._label(top, "Integrações diretas", font=("Arial", 20, "bold"), fg="#FFFFFF").pack(fill="x")
        self._label(top, "Conecte, consulte e controle as portas autorizadas. Os recursos dependem do modelo e firmware.", fg="#E5DDF7").pack(fill="x", pady=(7, 0))
        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, sticky="nsew", padx=20)
        device_shell = tk.Frame(notebook, bg=BG)
        profiles_shell = tk.Frame(notebook, bg=BG)
        notebook.add(device_shell, text="Equipamento e inventário")
        notebook.add(profiles_shell, text="Adicionar adaptadores")
        self._build_device(self._scroll_panel(device_shell, minheight=505))
        self._build_profiles(self._scroll_panel(profiles_shell))
        self.status = tk.StringVar(value="Escolha um perfil e confira suas capacidades antes de conectar.")
        footer = self._label(self, "")
        footer.configure(textvariable=self.status)
        footer.grid(row=2, column=0, sticky="ew", padx=20, pady=15)

    def _scroll_panel(self, parent, minheight=None):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        canvas = tk.Canvas(parent, bg=BG, borderwidth=0, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns", padx=(8, 0))
        canvas.configure(yscrollcommand=scroll.set)
        inner = tk.Frame(canvas, bg=BG)
        item = canvas.create_window(0, 0, window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        def resize(event):
            settings = {"width": event.width}
            if minheight:
                settings["height"] = max(minheight, event.height)
            canvas.itemconfigure(item, **settings)
        canvas.bind("<Configure>", resize)
        return inner

    def _build_device(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(4, weight=1)
        form = tk.Frame(parent, bg=PANEL, padx=16, pady=10, highlightbackground="#E4DDF3", highlightthickness=1)
        form.grid(row=0, column=0, sticky="ew", pady=(15, 10))
        for column in (1, 3):
            form.grid_columnconfigure(column, weight=1)
        self.profile_var = tk.StringVar()
        tk.Label(form, text="Fabricante / perfil", bg=PANEL, fg=MUTED).grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.profile_combo = ttk.Combobox(form, textvariable=self.profile_var, state="readonly")
        self.profile_combo.grid(row=0, column=1, columnspan=3, sticky="ew", pady=4)
        self.profile_combo.bind("<<ComboboxSelected>>", self._profile_selected)
        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="admin")
        self.key_var = tk.StringVar()
        self.known_hosts_var = tk.StringVar()
        self.allowed_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.ca_var = tk.StringVar()
        fields = [("IP / host", self.host_var, "Porta", self.port_var),
                  ("Usuário", self.user_var, "Senha HTTPS (sessão)", self.password_var),
                  ("Chave SSH", self.key_var, "known_hosts", self.known_hosts_var),
                  ("Portas de acesso autorizadas", self.allowed_var, "Certificado CA HTTPS", self.ca_var)]
        for row, (left, left_var, right, right_var) in enumerate(fields, start=1):
            for col, label, variable in ((0, left, left_var), (2, right, right_var)):
                tk.Label(form, text=label, bg=PANEL, fg=MUTED).grid(row=row, column=col, sticky="w", padx=(12 if col else 0, 8), pady=4)
                entry = ttk.Entry(form, textvariable=variable, show="*" if variable is self.password_var else "")
                entry.grid(row=row, column=col+1, sticky="ew", pady=4)
        self.profile_notes = tk.StringVar()
        notes = self._label(parent, "")
        notes.configure(textvariable=self.profile_notes)
        notes.grid(row=1, column=0, sticky="ew", pady=(0, 9))
        buttons = ttk.Frame(parent)
        buttons.grid(row=2, column=0, sticky="ew", pady=(0, 9))
        self.connect_button = ActionButton(buttons, text="Conectar e consultar", style="Accent.TButton", command=self._connect)
        self.connect_button.pack(side="left")
        self.refresh_button = ActionButton(buttons, text="Atualizar inventário", command=self._refresh, state="disabled")
        self.refresh_button.pack(side="left", padx=7)
        self.off_button = ActionButton(buttons, text="Desativar porta", style="Danger.TButton", command=lambda: self._set_port(False), state="disabled")
        self.off_button.pack(side="left", padx=7)
        self.on_button = ActionButton(buttons, text="Ativar porta", command=lambda: self._set_port(True), state="disabled")
        self.on_button.pack(side="left")
        self.raw_button = ActionButton(buttons, text="Ver saída de consulta", command=self._show_raw, state="disabled")
        self.raw_button.pack(side="right")
        self.active_summary = tk.StringVar(value="Nenhum equipamento conectado. As consultas não alteram a configuração.")
        summary_bar = tk.Frame(parent, bg=BG)
        summary_bar.grid(row=3, column=0, sticky="ew", pady=(0, 9))
        summary_bar.grid_columnconfigure(0, weight=1)
        summary = self._label(summary_bar, "")
        summary.configure(textvariable=self.active_summary, fg=PURPLE)
        summary.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.disconnect_button = ActionButton(summary_bar, text="Desconectar", command=self._disconnect, state="disabled")
        self.disconnect_button.grid(row=0, column=1)
        table_frame = ttk.Frame(parent)
        table_frame.grid(row=4, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        self.table = ttk.Treeview(table_frame, columns=("kind", "name", "address", "state", "info"), show="headings", selectmode="browse")
        for key, title, width in [("kind", "Tipo", 85), ("name", "Porta / máquina", 180), ("address", "IP / MACs", 220), ("state", "Estado", 130), ("info", "Informação", 260)]:
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=70)
        self.table.grid(row=0, column=0, sticky="nsew")
        vs = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        hs = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        self.table.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.table.bind("<<TreeviewSelect>>", self._selection)
        self._label(parent, "Desativar uma porta interrompe toda a rede nela, inclusive recursos locais. Autorize somente portas de computadores; exclua uplinks, trunks e gerenciamento.").grid(row=5, column=0, sticky="ew", pady=(10, 0))
        self.session_notice = tk.StringVar(value="Sessão protegida: desconexão após 10 minutos sem interação. Consultas antigas não autorizam cortes.")
        notice = self._label(parent, "")
        notice.configure(textvariable=self.session_notice)
        notice.grid(row=6, column=0, sticky="ew", pady=(7, 0))

    def _build_profiles(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        self._label(parent, "Adicione uma nova marca", font=("Arial", 16, "bold"), fg=TEXT).grid(
            row=0, column=0, sticky="ew", pady=(20, 5))
        self._label(parent, "Importe um perfil revisado ou baixe com endereço e código de integridade. Os recursos disponíveis sempre aparecem antes da conexão.").grid(
            row=1, column=0, sticky="ew", pady=(0, 15))
        local = tk.Frame(parent, bg=PANEL, padx=18, pady=16,
                         highlightbackground="#E4DDF3", highlightthickness=1)
        local.grid(row=2, column=0, sticky="ew", pady=(0, 13))
        local.grid_columnconfigure(0, weight=1)
        self._label(local, "01  Arquivo no computador", font=("Arial", 11, "bold"), fg=PURPLE).grid(
            row=0, column=0, sticky="ew")
        self._label(local, "Selecione JSON ou ZIP com um perfil declarativo.").grid(
            row=1, column=0, sticky="ew", pady=(5, 0))
        ActionButton(local, text="Escolher arquivo", command=self._install_profile).grid(
            row=0, column=1, rowspan=2, padx=(20, 0))
        download = tk.Frame(parent, bg=PANEL, padx=18, pady=16,
                            highlightbackground="#E4DDF3", highlightthickness=1)
        download.grid(row=3, column=0, sticky="ew", pady=(0, 13))
        download.grid_columnconfigure(1, weight=1)
        self._label(download, "02  Download verificado", font=("Arial", 11, "bold"), fg=PURPLE).grid(
            row=0, column=0, columnspan=2, sticky="ew", pady=(0, 9))
        self.url_var = tk.StringVar()
        self.sha_var = tk.StringVar()
        for row, title, variable in [(1, "URL HTTPS do perfil", self.url_var), (2, "SHA-256 esperado", self.sha_var)]:
            tk.Label(download, text=title, bg=PANEL, fg=MUTED).grid(
                row=row, column=0, sticky="w", padx=(0, 15), pady=5)
            ttk.Entry(download, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=5)
        ActionButton(download, text="Baixar e instalar perfil", style="Accent.TButton", command=self._download_profile).grid(
            row=3, column=1, sticky="e", pady=(12, 0))
        self._label(parent, "Use uma fonte confiável. Os perfis não executam instaladores nem código Python; o SHA-256 verifica se o arquivo foi alterado.").grid(
            row=4, column=0, sticky="ew", pady=(0, 12))
        ssh_info = "OpenSSH pronto para conexões neste computador." if shutil.which("ssh") else "OpenSSH não encontrado. Consulte o guia para habilitar o cliente no Windows ou Linux."
        self._label(parent, ssh_info, fg=PURPLE).grid(row=5, column=0, sticky="ew", pady=(0, 9))
        self._label(parent, "Equipamento da Embratel? Cadastre o fabricante e o modelo reais fornecidos pela operadora.").grid(
            row=6, column=0, sticky="ew", pady=(0, 12))
        ActionButton(parent, text="Abrir guia de integrações", command=self._open_manual).grid(row=7, column=0, sticky="w")

    def _reload_profiles(self, selected_id=None):
        profiles = self.manager.list_profiles()
        self._profiles = {f"{p.get('vendor', '')} | {p.get('name', p['id'])} [{p['id']}]": p for p in profiles}
        self.profile_combo.configure(values=list(self._profiles))
        chosen = next((name for name, profile in self._profiles.items() if profile["id"] == selected_id), None)
        if chosen:
            self.profile_var.set(chosen)
        elif self.profile_var.get() not in self._profiles:
            self.profile_var.set(next(iter(self._profiles), ""))
        self._profile_selected()

    def _profile_selected(self, _event=None):
        if self.session and not self._busy:
            self._disconnect("Perfil alterado. Conecte novamente para confirmar o equipamento de destino.")
        profile = self._profiles.get(self.profile_var.get(), {})
        transport = profile.get("transport", "ssh")
        self.port_var.set("443" if "https" in transport.lower() else "22")
        notes = profile.get("notes", "")
        if isinstance(notes, list):
            notes = " ".join(map(str, notes))
        self.profile_notes.set(f"{profile.get('description', '')}\nRecursos: {capability_text(profile.get('capabilities', {}))}. {notes}")

    def _run(self, function, callback, label):
        if self._busy or self._closed:
            return False
        self._busy = True
        self._last_activity = monotonic()
        generation = self._generation
        self.profile_combo.configure(state="disabled")
        self.status.set(label + "…")
        for button in (self.connect_button, self.refresh_button, self.off_button, self.on_button, self.disconnect_button):
            button.configure(state="disabled")
        def work():
            try:
                result = function()
                if self._closed or generation != self._generation:
                    if isinstance(result, tuple) and result and callable(getattr(result[0], "close", None)):
                        result[0].close()
                else:
                    self._results.put((generation, True, result, callback))
            except Exception as exc:
                if not self._closed and generation == self._generation:
                    self._results.put((generation, False, str(exc), callback))
        self._executor.submit(work)
        return True

    def _drain(self):
        if self._closed:
            return
        try:
            while True:
                generation, ok, result, callback = self._results.get_nowait()
                if generation != self._generation:
                    if ok and isinstance(result, tuple) and result and callable(getattr(result[0], "close", None)):
                        result[0].close()
                    continue
                self._busy = False
                self.profile_combo.configure(state="readonly")
                self.connect_button.configure(state="normal")
                self.refresh_button.configure(state="normal" if self.session else "disabled")
                if ok:
                    callback(result)
                else:
                    self._stale = True
                    self.active_summary.set("CONEXÃO NÃO CONFIRMADA | Dados anteriores somente para consulta. Atualize o inventário antes de controlar portas.")
                    self.status.set("Operação não concluída: " + result)
                    messagebox.showerror("Integração", result, parent=self)
                self._selection()
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _connect(self):
        if self._busy:
            return
        profile = self._profiles.get(self.profile_var.get())
        if not profile:
            return
        settings = dict(host=self.host_var.get().strip(), port=self.port_var.get().strip(),
                        user=self.user_var.get().strip(), key_path=self.key_var.get().strip(),
                        known_hosts=self.known_hosts_var.get().strip(),
                        allowed_access_ports=self.allowed_var.get().strip(),
                        password=self.password_var.get(), ca_file=self.ca_var.get().strip())
        self._disconnect()
        self.password_var.set("")
        def connect():
            session = self.manager.connect(profile["id"], **settings)
            try:
                return session, session.snapshot()
            except Exception:
                if callable(getattr(session, "close", None)):
                    session.close()
                raise
        def connected(value):
            self.session, snapshot = value
            self._show(snapshot)
        self._run(connect, connected, "Conectando e consultando equipamento")

    def _refresh(self):
        if self.session:
            session = self.session
            self._run(session.snapshot, self._show, "Atualizando inventário")

    def _show(self, snapshot):
        self._stale = False
        self._last_snapshot = monotonic()
        self.snapshot = snapshot
        self._row_data = {}
        children = self.table.get_children()
        if children:
            self.table.delete(*children)
        for iid, kind, record, values in inventory_rows(snapshot):
            self.table.insert("", "end", iid=iid, values=values)
            self._row_data[iid] = (kind, record)
        target = getattr(self.session, "host", "")
        target_text = f" | Equipamento: {target}" if isinstance(target, str) and target else ""
        self.active_summary.set(f"{snapshot.get('vendor', '')} | {snapshot.get('adapter', '')}{target_text} | Recursos: {capability_text(snapshot.get('capabilities', {}))}")
        warnings = " | ".join(map(str, snapshot.get("warnings", [])))
        operation = snapshot.get("operation", {})
        message = operation.get("message", "Inventário atualizado. Nenhuma ação de configuração nesta consulta.")
        if operation and not operation.get("verified"):
            message += " Confira o estado no equipamento antes de repetir."
        self.status.set(message + (" | " + warnings if warnings else ""))
        self.raw_button.configure(state="normal" if snapshot.get("raw_summary") else "disabled")
        self._selection()

    def _show_raw(self):
        output = self.snapshot.get("raw_summary")
        if not output:
            return
        if not isinstance(output, str):
            import json
            output = json.dumps(output, ensure_ascii=False, indent=2)
        dialog = tk.Toplevel(self)
        self._detail_windows.append(dialog)
        dialog.title("LabGuard | Saída das consultas de inventário")
        dialog.geometry("900x550")
        dialog.configure(bg=BG)
        dialog.transient(self)
        from tkinter.scrolledtext import ScrolledText
        text = ScrolledText(dialog, wrap="none", bg=PANEL, fg=TEXT, insertbackground=TEXT)
        text.pack(fill="both", expand=True, padx=12, pady=12)
        text.insert("1.0", output[:32768])
        text.configure(state="disabled")

    def _selection(self, _event=None):
        selection = self.table.selection()
        kind, port = self._row_data.get(selection[0], (None, {})) if selection else (None, {})
        allowed = (not self._busy and self._inventory_fresh() and kind == "port" and self.snapshot.get("capabilities", {}).get("port_control")
                   and port.get("controllable", port.get("eligible", True)))
        state = "normal" if allowed else "disabled"
        self.off_button.configure(state=state)
        self.on_button.configure(state=state)
        self.disconnect_button.configure(state="normal" if self.session and not self._busy else "disabled")

    def _set_port(self, enabled):
        if self._busy or not self.session:
            return
        selection = self.table.selection()
        kind, port = self._row_data.get(selection[0], (None, {})) if selection else (None, {})
        if kind != "port" or not self.snapshot.get("capabilities", {}).get("port_control") or not port.get("controllable", port.get("eligible", True)):
            return
        if not self._inventory_fresh():
            self.status.set("Atualize o inventário: a consulta está antiga ou a conexão não foi confirmada.")
            return
        name = str(port.get("name", ""))
        session = self.session
        target = getattr(session, "host", "equipamento conectado")
        verb = "Ativar" if enabled else "Desativar"
        if not messagebox.askyesno(f"{verb} porta", f"{verb} a porta {name} em {target}?\n\nDesativar corta toda a conectividade dos equipamentos nessa porta, incluindo a rede local. Não use em uplinks, trunks ou gerenciamento.\n\nA ação só é aceita para as portas autorizadas na conexão atual.", parent=self, icon="warning", default="no"):
            return
        self._run(lambda: session.set_port_enabled(name, enabled), self._show, f"Alterando porta {name}")

    def _install_profile(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(parent=self, title="Perfil declarativo de fabricante", filetypes=[("JSON ou ZIP", "*.json *.zip"), ("Todos", "*.*")])
        if path:
            self._run(lambda: self.manager.install_profile(path), self._installed, "Validando e instalando perfil")

    def _download_profile(self):
        if self._busy:
            return
        url, sha256 = self.url_var.get().strip(), self.sha_var.get().strip()
        if not url or not sha256:
            messagebox.showinfo("Informe os dados", "Preencha a URL HTTPS e o SHA-256 esperado, obtidos de uma fonte confiável.", parent=self)
            return
        self._run(lambda: self.manager.download_profile(url, sha256), self._installed, "Baixando e verificando perfil")

    def _installed(self, profile):
        self._reload_profiles(profile.get("id"))
        self.status.set(f"Perfil instalado: {profile.get('vendor', '')} | {profile.get('name', profile.get('id', ''))}. Revise as capacidades e o modelo antes de conectar.")

    def _open_manual(self):
        import webbrowser
        path = Path(__file__).resolve().parents[1] / "docs" / "INTEGRACOES.md"
        if path.is_file():
            webbrowser.open(path.as_uri())

    def _record_activity(self, _event=None):
        self._last_activity = monotonic()

    def _inventory_fresh(self):
        return bool(self.session and not self._stale and monotonic() - self._last_snapshot <= INVENTORY_VALID_SECONDS)

    def _check_idle(self):
        if self._closed:
            return
        if self.session:
            remaining = SESSION_IDLE_SECONDS - (monotonic() - self._last_activity)
            if remaining <= 0 and not self._busy:
                self._disconnect("Sessão encerrada por inatividade. Conecte novamente ao equipamento.")
            else:
                minutes = max(0, int(remaining + 59) // 60)
                self.session_notice.set(f"Sessão administrativa: desconexão em até {minutes} min sem interação. Atualize consultas com mais de 60 s antes de controlar portas.")
                self._selection()
        self.after(5000, self._check_idle)

    def _disconnect(self, reason="Sessão desconectada. Conecte novamente para consultar ou controlar o equipamento."):
        self._generation += 1
        session, self.session = self.session, None
        if session and callable(getattr(session, "close", None)):
            session.close()
        self.password_var.set("")
        self._stale = True
        self._last_snapshot = 0.0
        self.snapshot = {}
        self._row_data = {}
        for dialog in self._detail_windows:
            try:
                dialog.destroy()
            except tk.TclError:
                pass
        self._detail_windows = []
        children = self.table.get_children()
        if children:
            self.table.delete(*children)
        self.raw_button.configure(state="disabled")
        self.refresh_button.configure(state="disabled")
        self.off_button.configure(state="disabled")
        self.on_button.configure(state="disabled")
        self.disconnect_button.configure(state="disabled")
        self.active_summary.set("Nenhum equipamento conectado.")
        self.session_notice.set("Sessão encerrada. Credenciais da conexão não são salvas em disco.")
        self.status.set(reason)

    def close(self):
        self._closed = True
        self._disconnect()
        while not self._results.empty():
            try:
                _, ok, result, _ = self._results.get_nowait()
                if ok and isinstance(result, tuple) and result and callable(getattr(result[0], "close", None)):
                    result[0].close()
            except queue.Empty:
                break
        self._executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()
