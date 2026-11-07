"""LabGuard 2: observação imediata e controle explícito por API compatível."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import tempfile
from time import monotonic
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

from .demo import normalize_domain, normalize_mac
from .ui import (ActionButton, RoundCard, IconBadge, BG, PANEL, TEXT, MUTED,
                 PURPLE, BLUE, GREEN, RED, AMBER, BORDER)

FRESH_SECONDS = 20
CAPABILITY_NAMES = {
    "inventory": "Ver dispositivos", "domain_filtering": "Bloquear sites",
    "device_internet_cut": "Suspender internet", "address_blocking": "Controlar IP e MAC",
    "ai_block": "Perfil global de IA", "dns_history": "Consultar atividade DNS"}
PROFILE_KINDS = {
    "Observar esta rede (qualquer roteador)": "observation",
    "Controlar MikroTik via HTTPS": "routeros",
    "Outros equipamentos": "integration",
    "Gateway SSH existente (opcional)": "legacy"}


class PolicyBankSelection:
    """Referencia bancos locais sem copiar cadastros nem mudar vínculos de rede."""
    _FILENAME = re.compile(r"(?:policy2|[0-9a-f]{24}|equipment-[0-9a-f]{24})\.sqlite3\Z")
    _TARGET = re.compile(r"[0-9a-f]{64}\Z")

    def __init__(self, directory):
        self.directory = Path(directory)
        self.state_path = self.directory / "policy_state_v2.json"
        self.active = "policy2.sqlite3"
        self.real_target = None
        self.targets = {}
        self.warning = ""
        self._invalid_state = self._dirty = False
        try:
            if self.state_path.is_symlink():raise ValueError("Referência simbólica")
            if not self.state_path.exists():return
            with self.state_path.open("rb") as source:raw = source.read(65537)
            if len(raw) > 65536:raise ValueError("Referência grande")
            state = json.loads(raw)
            active, target, targets = state["active_bank"], state["real_target"], state["targets"]
            if state.get("version") != 1 or not isinstance(targets, dict) or len(targets) > 200:raise ValueError()
            if not isinstance(active, str) or not self._FILENAME.fullmatch(active):raise ValueError()
            if any(not isinstance(k, str) or not self._TARGET.fullmatch(k) or not isinstance(v, str) or not self._FILENAME.fullmatch(v) for k, v in targets.items()):raise ValueError()
            if target is not None and (not isinstance(target, str) or targets.get(target) != active):raise ValueError()
            if target is None and (targets or active != "policy2.sqlite3"):raise ValueError()
            self.active, self.real_target, self.targets = active, target, targets
        except (OSError, ValueError, TypeError, KeyError):
            self._invalid_state = True
            self.warning = "Referência local do banco indisponível; novos destinos usarão bancos separados. Nenhum cadastro foi apagado."

    def _save(self):
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if any(path.is_symlink() for path in (self.directory, *self.directory.parents)) or self.state_path.is_symlink():
            raise OSError("A referência do banco não pode usar links simbólicos.")
        if os.name != "nt" and self.directory.stat().st_mode & 0o077:
            raise OSError("Use uma pasta privada para o banco de sites (permissão 0700).")
        descriptor, temporary = tempfile.mkstemp(prefix="policy-state-", suffix=".tmp", dir=self.directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump({"version": 1, "active_bank": self.active, "real_target": self.real_target, "targets": self.targets}, target, sort_keys=True)
                target.flush(); os.fsync(target.fileno())
            os.replace(temporary, self.state_path)
            self._dirty = False
        finally:
            try:Path(temporary).unlink()
            except FileNotFoundError:pass

    def path_for(self, snapshot, transport):
        mode = snapshot.get("mode", "observation")
        host, port = str(getattr(transport, "host", "")), str(getattr(transport, "port", ""))
        legacy_identity = "|".join((mode, host, port))
        legacy_name = hashlib.sha256(legacy_identity.encode()).hexdigest()[:24] + ".sqlite3"
        if mode == "demo":return self.directory / legacy_name
        if mode in {"gateway", "equipment"}:
            identity = "|".join((mode, host.casefold().rstrip("."), port))
            target = hashlib.sha256(identity.encode()).hexdigest()
            filename = self.targets.get(target)
            if filename is None:
                if mode == "gateway":filename = legacy_name
                elif self.real_target is None and not self._invalid_state:filename = self.active
                else:filename = "equipment-" + target[:24] + ".sqlite3"
            if self.real_target != target or self.active != filename or self.targets.get(target) != filename:
                self.active, self.real_target = filename, target
                self.targets[target] = filename; self._dirty = True
        if self._dirty:self._save()
        return self.directory / self.active


def snapshot_capabilities(snapshot):
    """Ausência de capacidade em equipamento real nunca significa autorização."""
    if snapshot.get("mode") == "observation":
        return {name: name == "inventory" for name in CAPABILITY_NAMES}
    value = snapshot.get("capabilities", snapshot.get("caps"))
    if isinstance(value, dict):
        return {name: value.get(name) is True for name in CAPABILITY_NAMES}
    legacy = snapshot.get("mode") in {"demo", "gateway"}
    return {name: legacy for name in CAPABILITY_NAMES}


def summarize_inventory(snapshot):
    from .inventory import summarize_inventory as summarize
    return summarize(snapshot, max_age_seconds=FRESH_SECONDS)


def source_collection_current(snapshot):
    if snapshot.get("mode") == "demo":return True
    from .inventory import collection_recency
    evidence = summarize_inventory(snapshot)
    facts = evidence.get("facts", {})
    return (collection_recency(snapshot, max_age_seconds=FRESH_SECONDS)["fresh"] is True
            and facts.get("read_success") is not False and facts.get("collection_metadata_valid") is not False)


def inventory_presentation(snapshot, *, stale=False, busy=False):
    """Resume apenas a exibição; nenhuma capacidade ou permissão é produzida."""
    evidence = summarize_inventory(snapshot)
    prior = bool(snapshot.get("timestamp") or evidence["facts"]["has_evidence"])
    if snapshot.get("mode") == "demo":
        state, kind = "Demonstração · dados fictícios", "demo"
    elif stale and prior:
        state, kind = "Dados desatualizados", "stale"
    elif busy and not prior:
        state, kind = "Identificando a rede…", "busy"
    elif evidence["status"] == "unavailable":
        state, kind = "Leitura indisponível", "unavailable"
    elif not evidence["fresh"]:
        state, kind = "Dados desatualizados", "stale"
    elif busy:
        state, kind = "Consultando · leitura anterior", "busy"
    else:
        state, kind = evidence["status_label"], "partial"
    next_action = ("A consulta atual não confirmou estes dados. Identifique a rede novamente antes de agir."
                   if kind == "stale" else evidence["next_action"])
    return {"evidence": evidence, "state": state, "kind": kind, "next_action": next_action}


def conflicted_device_ips(snapshot):
    identities, conflicts = {}, set()
    rows = snapshot.get("devices", [])
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):continue
        try:address = str(ipaddress.IPv4Address(row.get("ip", "")))
        except (ValueError, TypeError, ipaddress.AddressValueError):continue
        if row.get("identity_conflict") is True:conflicts.add(address)
        try:mac = normalize_mac(row.get("mac", ""))
        except ValueError:continue
        identities.setdefault(address, set()).add(mac)
    conflicts.update(address for address, macs in identities.items() if len(macs) > 1)
    return conflicts


def mutation_reason(snapshot, *, capability=None, required_health=(), stale=False,
                    age=0, busy=False, authorized=True):
    if busy:
        return "Aguarde a operação em andamento."
    if snapshot.get("mode") == "observation":
        return "Modelo/API necessários para bloquear. A observação local é somente consulta."
    if snapshot.get("mode") not in {"demo", "gateway", "equipment"}:
        return "Conecte um roteador compatível antes de alterar a rede."
    if stale or age > FRESH_SECONDS:
        return "Atualize a leitura antes de alterar a rede."
    if not source_collection_current(snapshot):
        return "O horário ou o resultado da coleta na fonte não foi confirmado. Atualize antes de alterar a rede."
    if snapshot.get("mode") != "demo" and not authorized:
        return "Reconecte com a opção Autorizar alterações habilitada para controlar o roteador."
    if capability and not snapshot_capabilities(snapshot).get(capability):
        return "Este modelo ou perfil não oferece esta operação. Consulte os recursos disponíveis em Início."
    health = snapshot.get("health", {})
    if any(health.get(name) is not True for name in required_health):
        return "O serviço necessário não foi confirmado nesta leitura. Atualize e confira o equipamento."
    return None


def device_blocked_here(snapshot, device):
    """A liberação de IP nunca é apresentada como liberação de outro escopo."""
    if not device:return False
    if snapshot.get("mode") == "equipment":
        if type(device.get("blocked_ip")) is bool:return device["blocked_ip"]
        scopes = device.get("blocked_by", [])
        if isinstance(scopes, dict):return scopes.get("ip") is True
        if isinstance(scopes, (list, tuple)) and "ip" in scopes:return True
        return any(row.get("kind") == "ip" and row.get("address") == device.get("ip")
                   for row in snapshot.get("address_blocks", []) if isinstance(row, dict))
    if "blocked_by" in device:
        scopes = device["blocked_by"]
        return scopes.get("device") is True if isinstance(scopes, dict) else "device" in scopes if isinstance(scopes, (list, tuple)) else False
    return bool(device.get("blocked"))


def create_transport(kind="observation", **settings):
    # Import tardio: descoberta e API são implementações independentes da interface.
    from .controller import create_transport as factory
    return factory(kind=kind, **settings)


class App(tk.Tk):
    def __init__(self, transport=None):
        super().__init__()
        self.title("LabGuard | Sua rede, mais simples")
        self.geometry("1240x820")
        self.minsize(1000, 700)
        self.configure(bg=BG)
        self.transport = transport
        self.snapshot = {"mode": "observation", "devices": [], "events": [], "domains": []}
        self._management_authorized = transport is not None
        self._snapshot_stale = True
        self._last_snapshot_monotonic = 0.0
        self._generation = 0
        self._busy = self._closed = False
        self._results = queue.Queue()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="labguard-controle")
        self._pages, self._nav, self._device_rows = {}, {}, {}
        self._domain_rows = {}
        self._snapshot_source = None
        self._map_windows = []
        self._last_error = ""
        self._diagnostics_window = None
        self._banks = PolicyBankSelection(Path.home()/".labguard"/"banlists")
        self._style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._drain_id = self.after(70, self._drain)
        self._initial_id = self.after(100, self.refresh if transport is not None else self._observe)
        self._tick_id = self.after(5000, self._tick)

    def _style(self):
        installed = set(tkfont.families(self))
        self.font_family = next((f for f in ("Segoe UI", "DejaVu Sans", "Liberation Sans", "Arial", "Helvetica") if f in installed),
                                tkfont.nametofont("TkDefaultFont").actual("family"))
        tkfont.nametofont("TkDefaultFont").configure(family=self.font_family, size=10)
        self.option_add("*Font", (self.font_family, 10))
        style = ttk.Style(self); style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, padding=8, bordercolor=BORDER)
        style.configure("Compact.TEntry", padding=5)
        style.configure("TCombobox", fieldbackground=PANEL, foreground=TEXT, padding=7, arrowcolor=PURPLE)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", TEXT)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=35, font=(self.font_family, 9), borderwidth=0)
        style.configure("Treeview.Heading", background="#EDE7FA", foreground=PURPLE,
                        font=(self.font_family, 9, "bold"), padding=(10, 11), relief="flat")
        style.map("Treeview", background=[("selected", "#DED0FA")], foreground=[("selected", TEXT)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#EDE7FA", padding=(15, 10))
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", PURPLE)])

    def _label(self, parent, text="", **kwargs):
        label = tk.Label(parent, text=text, bg=kwargs.pop("bg", BG), fg=kwargs.pop("fg", MUTED),
                         anchor="w", justify="left", **kwargs)
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(120, e.width - 3)))
        return label

    def _build(self):
        self.columnconfigure(0, weight=1); self.rowconfigure(3, weight=1)
        header = tk.Frame(self, bg=PANEL, padx=23, pady=15)
        header.grid(row=0, column=0, sticky="ew")
        IconBadge(header, kind="shield", color=PURPLE, tint="#EEE7FD", size=40).pack(side="left", padx=(0, 10))
        brand = tk.Frame(header, bg=PANEL); brand.pack(side="left")
        self._label(brand, "LabGuard", bg=PANEL, fg=TEXT, font=(self.font_family, 19, "bold")).pack(anchor="w")
        self._label(brand, "CONTROLE ESCOLAR · 2.1", bg=PANEL, font=(self.font_family, 7, "bold")).pack(anchor="w")
        ActionButton(header, text="Outros equipamentos", command=self._open_integrations, height=38).pack(side="right")
        ActionButton(header, text="Mapa e relatórios", command=self._open_network_map, style="Yellow.TButton", height=38).pack(side="right", padx=9)
        nav = tk.Frame(self, bg=BG, padx=23, pady=12); nav.grid(row=1, column=0, sticky="ew")
        for col, (key, name) in enumerate((("home", "Início"), ("devices", "Dispositivos"), ("sites", "Sites"), ("activity", "Atividade"))):
            nav.columnconfigure(col, weight=1)
            button = ActionButton(nav, text=name, height=42, command=lambda k=key: self.show_page(k))
            button.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 7, 0))
            self._nav[key] = button
        self.mode_text = tk.StringVar(value="OBSERVAÇÃO LOCAL · identificando os dados disponíveis")
        mode_shell = tk.Frame(self, bg=BG)
        mode_shell.grid(row=2, column=0, sticky="ew", padx=23, pady=(0, 12))
        mode_shell.columnconfigure(0, weight=1)
        self.mode_banner = self._label(mode_shell, textvariable=self.mode_text, bg="#E8F0FF", fg="#2456A3", padx=15, pady=10)
        self.mode_banner.grid(row=0, column=0, sticky="ew")
        ActionButton(mode_shell, text="Não identificou? Ver passo a passo", command=self._open_diagnostics, height=38).grid(row=0, column=1, padx=(9, 0))
        content = tk.Frame(self, bg=BG); content.grid(row=3, column=0, sticky="nsew", padx=23)
        content.columnconfigure(0, weight=1); content.rowconfigure(0, weight=1)
        for key in self._nav:
            frame = tk.Frame(content, bg=BG); frame.grid(row=0, column=0, sticky="nsew")
            self._pages[key] = frame
        self._build_home(self._scroll_page(self._pages["home"]))
        self._build_devices(self._pages["devices"])
        self._build_sites(self._pages["sites"])
        self._build_activity(self._pages["activity"])
        footer = tk.Frame(self, bg=BG); footer.grid(row=4, column=0, sticky="ew", padx=23, pady=(12, 14))
        self.status = tk.StringVar(value="Lendo a rede local em segundo plano. Nenhuma regra será alterada.")
        self._label(footer, textvariable=self.status, font=(self.font_family, 8)).pack(side="left", fill="x", expand=True)
        self.refresh_button = ActionButton(footer, text="Atualizar", command=self.refresh, height=35)
        self.refresh_button.pack(side="right")
        self.error_help_button = ActionButton(footer, text="Ver passo a passo", command=self._open_diagnostics, height=35)
        self.show_page("home")

    def _scroll_page(self, parent):
        parent.columnconfigure(0, weight=1); parent.rowconfigure(0, weight=1)
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        bar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview); bar.grid(row=0, column=1, sticky="ns")
        canvas.configure(yscrollcommand=bar.set)
        self.home_canvas = canvas
        def wheel(event):
            if self.__dict__.get("_page") == "home":
                canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")
        self.bind("<MouseWheel>", wheel, add="+")
        self.bind("<Button-4>", lambda _: canvas.yview_scroll(-1, "units") if self.__dict__.get("_page") == "home" else None, add="+")
        self.bind("<Button-5>", lambda _: canvas.yview_scroll(1, "units") if self.__dict__.get("_page") == "home" else None, add="+")
        self.bind("<Next>", lambda _: canvas.yview_scroll(1, "pages") if self.__dict__.get("_page") == "home" else None, add="+")
        self.bind("<Prior>", lambda _: canvas.yview_scroll(-1, "pages") if self.__dict__.get("_page") == "home" else None, add="+")
        body = tk.Frame(canvas, bg=BG); item = canvas.create_window(0, 0, window=body, anchor="nw")
        body.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(item, width=e.width))
        return body

    def _build_home(self, parent):
        parent.columnconfigure(0, weight=3, uniform="home"); parent.columnconfigure(1, weight=2, uniform="home")
        self._label(parent, "Identifique a sua rede", fg=TEXT, font=(self.font_family, 21, "bold")).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(3, 4))
        self._label(parent, "Comece pela leitura local. Veja o que foi encontrado e qual é o próximo passo.").grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 17))
        action_card = RoundCard(parent, padding=19); action_card.grid(row=2, column=0, sticky="new", padx=(0, 15))
        self._label(action_card.body, "Leia a LAN deste computador", bg=PANEL, fg=TEXT, font=(self.font_family, 13, "bold")).pack(fill="x")
        self.identification_hint = tk.StringVar(value="Consulta interfaces, rota e vizinhos conhecidos. A cobertura é parcial e não concede controle do roteador.")
        self._label(action_card.body, textvariable=self.identification_hint, bg=PANEL).pack(fill="x", pady=(9, 16))
        self.identify_button = ActionButton(action_card.body, text="Identificar minha rede", command=self.refresh, style="Accent.TButton")
        self.identify_button.pack(anchor="w")
        ActionButton(action_card.body, text="Ver dispositivos", command=lambda:self.show_page("devices"), height=36).pack(anchor="w", pady=(9, 0))
        self.admin_panel = setup = RoundCard(parent, padding=19)
        setup.grid(row=4, column=0, columnspan=2, sticky="new", pady=(12, 0)); setup.grid_remove()
        body = setup.body
        self._label(body, "Acesso ao equipamento", bg=PANEL, fg=TEXT, font=(self.font_family, 12, "bold")).pack(fill="x")
        self.profile_var = tk.StringVar(value=next(iter(PROFILE_KINDS)))
        combo = ttk.Combobox(body, textvariable=self.profile_var, values=list(PROFILE_KINDS), state="readonly")
        combo.pack(fill="x", pady=(12, 8)); combo.bind("<<ComboboxSelected>>", self._profile_changed)
        self.profile_hint = tk.StringVar()
        self._label(body, textvariable=self.profile_hint, bg=PANEL).pack(fill="x", pady=(0, 11))
        self.host_var, self.port_var = tk.StringVar(), tk.StringVar(value="443")
        self.user_var, self.password_var = tk.StringVar(), tk.StringVar()
        self.ca_var, self.key_var, self.known_hosts_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.fields_frame = tk.Frame(body, bg=PANEL); self.fields_frame.columnconfigure(1, weight=1)
        self._field_widgets = {}
        fields = [("host", "Endereço do roteador", self.host_var), ("port", "Porta", self.port_var),
            ("user", "Usuário", self.user_var), ("password", "Senha da sessão", self.password_var),
            ("ca", "Certificado CA (opcional)", self.ca_var), ("key", "Chave privada SSH", self.key_var),
            ("known", "known_hosts SSH", self.known_hosts_var)]
        for row, (name, title, variable) in enumerate(fields):
            label = self._label(self.fields_frame, title, bg=PANEL)
            label.grid(row=row, column=0, sticky="w", padx=(0, 10), pady=4)
            entry = ttk.Entry(self.fields_frame, textvariable=variable, style="Compact.TEntry", show="*" if name == "password" else "")
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            widgets = [label, entry]
            if name in {"ca", "key", "known"}:
                pick = ttk.Button(self.fields_frame, text="...", width=3, command=lambda v=variable: self._pick(v))
                pick.grid(row=row, column=2, padx=(5, 0)); widgets.append(pick)
            self._field_widgets[name] = widgets
        self.advanced_button = ActionButton(body, text="Configuração avançada", command=self._toggle_advanced, height=34)
        self.advanced_frame = tk.Frame(body, bg=PANEL); self.advanced_frame.columnconfigure(1, weight=1)
        self.wan_var = tk.StringVar(value="WAN"); self.cidr_var = tk.StringVar()
        self.protected_ips_var = tk.StringVar(); self.protected_macs_var = tk.StringVar()
        for row, (label, variable) in enumerate((("Lista de interfaces WAN", self.wan_var), ("Rede do laboratório", self.cidr_var), ("IPs protegidos (vírgula)", self.protected_ips_var), ("MACs protegidos (vírgula)", self.protected_macs_var))):
            self._label(self.advanced_frame, label, bg=PANEL).grid(row=row, column=0, sticky="w", padx=(0, 9), pady=4)
            ttk.Entry(self.advanced_frame, textvariable=variable, style="Compact.TEntry").grid(row=row, column=1, sticky="ew", pady=4)
        self.manage_var = tk.BooleanVar(value=False)
        self.consent_row = tk.Frame(body, bg=PANEL)
        tk.Checkbutton(self.consent_row, text="Autorizar alterações neste roteador", variable=self.manage_var,
                       bg=PANEL, activebackground=PANEL, fg=TEXT, anchor="w", selectcolor=PANEL).pack(fill="x")
        self._label(self.consent_row, "Permite aplicar bloqueios usando a API. Desmarcado: somente consulta. A senha fica apenas nesta sessão.", bg=PANEL, font=(self.font_family, 8)).pack(fill="x", pady=(2, 5))
        self.connect_bar = tk.Frame(body, bg=PANEL); self.connect_bar.pack(fill="x", pady=(8, 0))
        self.connect_button = ActionButton(self.connect_bar, text="Identificar minha rede", command=self._connect, style="Accent.TButton")
        self.connect_button.pack(side="left")
        self.disconnect_button = ActionButton(self.connect_bar, text="Desconectar", command=self._observe)
        self.disconnect_button.pack(side="left", padx=7)
        tools = tk.Frame(parent, bg=BG); tools.grid(row=2, column=1, sticky="new")
        current = RoundCard(tools, padding=18); current.pack(fill="x", pady=(0, 13))
        self._label(current.body, "O que foi identificado", bg=PANEL, fg=TEXT, font=(self.font_family, 13, "bold")).pack(fill="x")
        self.collection_state = tk.StringVar(value="Aguardando consulta")
        self.collection_state_label = self._label(current.body, textvariable=self.collection_state, bg=PANEL, fg=PURPLE, font=(self.font_family, 10, "bold"))
        self.collection_state_label.pack(fill="x", pady=(10, 5))
        self.network_text = tk.StringVar(value="Fonte: observação local")
        self._label(current.body, textvariable=self.network_text, bg=PANEL).pack(fill="x", pady=(0, 7))
        self.count_text = tk.StringVar(value="Aguardando observações")
        self._label(current.body, textvariable=self.count_text, bg=PANEL).pack(fill="x")
        self.local_network_text = tk.StringVar(value="Segmento local ainda não informado.")
        self._label(current.body, textvariable=self.local_network_text, bg=PANEL).pack(fill="x", pady=(7, 10))
        self._label(current.body, "A amostra é parcial. Registros de DHCP/ARP não confirmam presença atual.", bg=PANEL, font=(self.font_family, 8)).pack(fill="x")
        self._label(current.body, "PRÓXIMO PASSO", bg=PANEL, fg=PURPLE, font=(self.font_family, 8, "bold")).pack(fill="x", pady=(13, 5))
        self.next_action_text = tk.StringVar(value="Identifique a rede ou abra o passo a passo de ajuda.")
        self._label(current.body, textvariable=self.next_action_text, bg=PANEL, fg=TEXT).pack(fill="x")
        self.details_panel = tk.Frame(parent, bg=BG)
        self.details_panel.grid(row=5, column=0, columnspan=2, sticky="new", pady=(12, 0)); self.details_panel.grid_remove()
        self.capability_labels = {}
        capabilities = RoundCard(self.details_panel, padding=18); capabilities.pack(fill="x")
        self._label(capabilities.body, "RECURSOS DESTA CONEXÃO", bg=PANEL, fg=PURPLE, font=(self.font_family, 8, "bold")).pack(fill="x", pady=(0, 10))
        for key, name in CAPABILITY_NAMES.items():
            label = self._label(capabilities.body, name + " · aguardando", bg=PANEL)
            label.pack(fill="x", pady=5); self.capability_labels[key] = label
        self.connection_note = tk.StringVar(value="Modelo/API necessários para bloquear.")
        self._label(self.details_panel, textvariable=self.connection_note).pack(fill="x", pady=12)
        panels = tk.Frame(action_card.body, bg=PANEL); panels.pack(fill="x", pady=(12, 0))
        self.admin_toggle_button = ActionButton(panels, text="Acesso ao equipamento", command=self._toggle_admin, height=37)
        self.admin_toggle_button.pack(side="left")
        self.details_toggle_button = ActionButton(panels, text="Detalhes e recursos", command=self._toggle_details, height=37)
        self.details_toggle_button.pack(side="left", padx=8)
        more = tk.Frame(parent, bg=BG); more.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(15, 10))
        ActionButton(more, text="Abrir demonstração", command=self._switch_demo, height=36).pack(side="left")
        ActionButton(more, text="Manual do usuário", command=self._open_manual, height=36).pack(side="left", padx=8)
        self._profile_changed()

    def _table(self, parent, columns, titles):
        parent.columnconfigure(0, weight=1); parent.rowconfigure(0, weight=1)
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        for key, title in zip(columns, titles):
            tree.heading(key, text=title, anchor="w"); tree.column(key, width=155, minwidth=95, anchor="w")
        tree.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(parent, orient="vertical", command=tree.yview); vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview); horizontal.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        return tree

    def _build_devices(self, parent):
        parent.columnconfigure(0, weight=1); parent.rowconfigure(3, weight=1)
        self._label(parent, "Dispositivos da sua rede", fg=TEXT, font=(self.font_family, 20, "bold")).grid(row=0, column=0, sticky="ew")
        self.devices_note = tk.StringVar(value="A observação local usa somente os dados disponíveis neste computador; não confirma todas as máquinas da rede.")
        self._label(parent, textvariable=self.devices_note).grid(row=1, column=0, sticky="ew", pady=(6, 14))
        bar = tk.Frame(parent, bg=BG); bar.grid(row=2, column=0, sticky="ew", pady=(0, 11))
        self._label(bar, "Buscar").pack(side="left", padx=(0, 8))
        self.device_search = tk.StringVar(); self.device_search.trace_add("write", lambda *_: self._render_devices())
        ttk.Entry(bar, textvariable=self.device_search, width=23).pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.block_button = ActionButton(bar, text="Suspender internet", command=lambda: self._set_block(True), style="Danger.TButton", height=38)
        self.block_button.pack(side="left")
        self.unblock_button = ActionButton(bar, text="Restaurar internet", command=lambda: self._set_block(False), height=38)
        self.unblock_button.pack(side="left", padx=7)
        ActionButton(bar, text="Programas e avisos", command=self._open_remote, height=38).pack(side="left")
        frame = tk.Frame(parent, bg=BG); frame.grid(row=3, column=0, sticky="nsew")
        self.devices_table = self._table(frame, ("name", "ip", "mac", "state", "blocked", "protected"),
            ("Dispositivo", "IP", "MAC", "Evidência", "Internet", "Protegido"))
        self.devices_table.bind("<<TreeviewSelect>>", lambda _: self._refresh_mutation_controls())
        self.device_selection_text = tk.StringVar(value="Selecione um dispositivo. IP e MAC não identificam uma pessoa.")
        self._label(parent, textvariable=self.device_selection_text).grid(row=4, column=0, sticky="ew", pady=(11, 0))

    def _build_sites(self, parent):
        parent.columnconfigure(0, weight=1); parent.rowconfigure(4, weight=1)
        self._label(parent, "Sites e política de IA", fg=TEXT, font=(self.font_family, 20, "bold")).grid(row=0, column=0, sticky="ew")
        self.site_note = tk.StringVar(value="Organize uma lista local. Aplicar exige um roteador compatível conectado.")
        self._label(parent, textvariable=self.site_note).grid(row=1, column=0, sticky="ew", pady=(5, 13))
        card = RoundCard(parent, padding=16); card.grid(row=2, column=0, sticky="ew", pady=(0, 13))
        card.body.columnconfigure(0, weight=1)
        self._label(card.body, "Sua lista de bloqueios", bg=PANEL, fg=TEXT, font=(self.font_family, 12, "bold")).grid(row=0, column=0, sticky="ew")
        self._label(card.body, "Crie, importe e revise cadastros mesmo sem controle do roteador. O banco só altera a rede ao aplicar.", bg=PANEL).grid(row=1, column=0, sticky="ew", pady=(5, 8))
        actions = tk.Frame(card.body, bg=PANEL); actions.grid(row=2, column=0, sticky="ew")
        ActionButton(actions, text="Banco de sites", command=self._open_banlist, style="Purple.TButton", height=37).pack(side="left")
        ActionButton(actions, text="Adicionar catálogo de IA ao banco", command=self._seed_ai_catalog, height=37).pack(side="left", padx=8)
        self.ai_button = ActionButton(actions, text="Perfil global de IA", command=self._toggle_ai, height=37)
        self.ai_button.pack(side="left")
        bar = tk.Frame(parent, bg=BG); bar.grid(row=3, column=0, sticky="ew", pady=(0, 11))
        self._label(bar, "Domínio").pack(side="left", padx=(0, 8))
        self.domain_var = tk.StringVar(); self.category_var = tk.StringVar(value="Jogos")
        ttk.Entry(bar, textvariable=self.domain_var).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Combobox(bar, textvariable=self.category_var, values=["Jogos", "Inteligência artificial", "Adultos", "Outros"], state="readonly", width=18).pack(side="left", padx=(0, 8))
        self.domain_add_button = ActionButton(bar, text="Bloquear domínio", command=self._add_domain, style="Accent.TButton", height=38)
        self.domain_add_button.pack(side="left")
        self.domain_remove_button = ActionButton(bar, text="Remover", command=self._remove_domain, height=38)
        self.domain_remove_button.pack(side="left", padx=(7, 0))
        frame = tk.Frame(parent, bg=BG); frame.grid(row=4, column=0, sticky="nsew")
        self.domains_table = self._table(frame, ("domain", "category", "source"), ("Domínio aplicado", "Categoria", "Origem"))
        self._label(parent, "O filtro cobre os domínios cadastrados. Não identifica toda IA nem revela o conteúdo de páginas HTTPS.").grid(row=5, column=0, sticky="ew", pady=(11, 0))

    def _build_activity(self, parent):
        parent.columnconfigure(0, weight=1); parent.rowconfigure(2, weight=1)
        self._label(parent, "Atividade disponível", fg=TEXT, font=(self.font_family, 20, "bold")).grid(row=0, column=0, sticky="ew")
        self.activity_note = tk.StringVar(value="A rede local não fornece histórico de navegação. Consultas DNS só aparecem quando a fonte as disponibiliza.")
        self._label(parent, textvariable=self.activity_note).grid(row=1, column=0, sticky="ew", pady=(5, 13))
        book = ttk.Notebook(parent); book.grid(row=2, column=0, sticky="nsew")
        tables = [("Consultas DNS", ("time", "ip", "domain", "status"), ("Horário", "IP", "Domínio solicitado", "Resultado"), "dns_table"),
            ("Ações", ("time", "action", "target", "outcome"), ("Horário", "Ação", "Alvo", "Resultado"), "audit_table"),
            ("Conexões", ("source", "dest", "proto", "port", "state"), ("Origem", "Destino", "Protocolo", "Porta", "Estado"), "connections_table")]
        for name, columns, titles, attribute in tables:
            tab = tk.Frame(book, bg=BG); book.add(tab, text=name); setattr(self, attribute, self._table(tab, columns, titles))

    def show_page(self, name):
        self._pages[name].tkraise(); self._page = name
        for key, button in self._nav.items():
            button.configure(face=PURPLE if key == name else "#EEE8FA", fg="white" if key == name else PURPLE)

    def _profile_changed(self, _event=None):
        kind = PROFILE_KINDS[self.profile_var.get()]
        self.password_var.set(""); self.manage_var.set(False)
        self.fields_frame.pack_forget(); self.advanced_button.pack_forget()
        self.advanced_frame.pack_forget(); self.consent_row.pack_forget()
        hints = {"observation": "Funciona na rede atual, sem senha de roteador. Mostra vizinhos conhecidos e a rota padrão; não bloqueia a internet.",
            "routeros": "Controle direto de MikroTik com API REST HTTPS já habilitada. Certificado validado; nenhuma configuração é ativada automaticamente.",
            "integration": "Consulte os perfis disponíveis para TP-Link, Cisco, OpenWrt e outros. Recursos variam por modelo e firmware.",
            "legacy": "Opção avançada para quem já possui um gateway LabGuard por SSH. Não é necessário instalar um para observar a rede."}
        self.profile_hint.set(hints[kind])
        if kind in {"routeros", "legacy"}:
            self.port_var.set("443" if kind == "routeros" else "22")
            self.fields_frame.pack(fill="x", before=self.connect_bar, pady=(0, 8))
            visible = {"host", "port", "user", "password", "ca"} if kind == "routeros" else {"host", "port", "user", "key", "known"}
            for name, widgets in self._field_widgets.items():
                for widget in widgets: widget.grid() if name in visible else widget.grid_remove()
            if kind == "routeros":self.advanced_button.pack(anchor="w", before=self.connect_bar, pady=(0, 8))
            self.consent_row.pack(fill="x", before=self.connect_bar)
        self.connect_button.configure(text="Identificar minha rede" if kind == "observation" else "Ver equipamentos" if kind == "integration" else "Conectar")

    def _toggle_home_panel(self, panel, button, label):
        if panel.winfo_manager():
            panel.grid_remove(); button.configure(text=label)
        else:
            panel.grid(); button.configure(text="Fechar " + label.lower())
            self.update_idletasks()
            bounds = self.home_canvas.bbox("all")
            if bounds:self.home_canvas.yview_moveto(max(0, panel.winfo_y()-8)/max(1, bounds[3]))

    def _toggle_admin(self):
        self._toggle_home_panel(self.admin_panel, self.admin_toggle_button, "Acesso ao equipamento")

    def _toggle_details(self):
        self._toggle_home_panel(self.details_panel, self.details_toggle_button, "Detalhes e recursos")

    def _toggle_advanced(self):
        if self.advanced_frame.winfo_manager():self.advanced_frame.pack_forget()
        else:self.advanced_frame.pack(fill="x", before=self.consent_row, pady=(0, 9))

    def _pick(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:variable.set(path)

    def _connect(self):
        kind = PROFILE_KINDS[self.profile_var.get()]
        if kind == "integration":return self._open_integrations()
        if kind == "observation":return self._observe()
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:raise ValueError
        except ValueError:
            self.status.set("Informe uma porta válida, de 1 a 65535."); return False
        settings = {"host": self.host_var.get().strip(), "port": port, "user": self.user_var.get().strip(),
            "password": self.password_var.get(), "ca_file": self.ca_var.get().strip(),
            "key_path": self.key_var.get().strip(), "known_hosts": self.known_hosts_var.get().strip(),
            "manage_rules": self.manage_var.get(), "wan_interface_list": self.wan_var.get().strip() or "WAN",
            "lab_cidr": self.cidr_var.get().strip(),
            "protected_ips": [x.strip() for x in self.protected_ips_var.get().split(",") if x.strip()] or None,
            "protected_macs": [x.strip() for x in self.protected_macs_var.get().split(",") if x.strip()] or None}
        return self._start_transport(kind, settings, authorized=bool(settings["manage_rules"]))

    def _observe(self):
        self.password_var.set(""); self.manage_var.set(False)
        return self._start_transport("observation", {}, authorized=False)

    def _switch_demo(self):
        self.password_var.set(""); self.manage_var.set(False)
        return self._start_transport("demo", {}, authorized=True)

    def _start_transport(self, kind, settings, *, authorized=False):
        if self._busy:return False
        def connect():
            transport = create_transport(kind, **settings)
            try:return transport, transport.request("snapshot")
            except Exception:
                self._close_transport(transport); raise
        def connected(value):
            old = self.transport; self.transport, snapshot = value
            self._close_transport(old); self._management_authorized = authorized
            self.password_var.set("")
            for window in self._map_windows:
                try:window.close()
                except tk.TclError:pass
            self._map_windows.clear(); self._apply_snapshot(snapshot)
        return self._run_job(connect, label="Lendo a rede local" if kind == "observation" else "Conectando perfil", on_success=connected, alert=kind not in {"observation", "demo"})

    def _run_job(self, function, *, label, on_success=None, alert=False):
        if self._busy or self._closed:return False
        self._busy = True; self.status.set(label + "…"); self._refresh_mutation_controls()
        self.refresh_button.configure(state="disabled")
        generation = self._generation
        def work():
            try:
                value = function()
                if self._closed or generation != self._generation:
                    if isinstance(value, tuple):self._close_transport(value[0])
                    return
                self._results.put((generation, True, value, on_success, alert))
                if (self._closed or generation != self._generation) and isinstance(value, tuple):
                    self._close_transport(value[0])
            except Exception as error:self._results.put((generation, False, str(error), None, alert))
        self._executor.submit(work); return True

    def _drain(self):
        if self._closed:return
        try:
            while True:
                generation, ok, value, callback, alert = self._results.get_nowait()
                if generation != self._generation:
                    if ok and isinstance(value, tuple):self._close_transport(value[0])
                    continue
                self._busy = False; self.refresh_button.configure(state="normal")
                if ok:(callback or self._apply_snapshot)(value)
                else:
                    self._snapshot_stale = True; self.password_var.set("")
                    from .diagnostics import classify_connection_error, safe_error_message
                    self._last_error = classify_connection_error(value) or "connection_error"
                    self.error_help_button.pack(side="right", padx=(0, 8), before=self.refresh_button)
                    safe_message = safe_error_message(self._last_error)
                    self.status.set(safe_message)
                    self._render_home()
                    self._notify_diagnostics()
                    if alert:messagebox.showerror("Operação não confirmada", safe_message, parent=self)
                self._refresh_mutation_controls()
        except queue.Empty:pass
        self._drain_id = self.after(70, self._drain)

    def refresh(self):
        if self.transport is None:return self._observe()
        transport = self.transport
        return self._run_job(lambda: transport.request("snapshot"), label="Atualizando dados")

    def _tick(self):
        if self._closed:return
        self._refresh_mutation_controls(); self._render_home()
        if not self._busy and monotonic() - self._last_snapshot_monotonic > 15:self.refresh()
        self._tick_id = self.after(5000, self._tick)

    def _snapshot_identity(self, snapshot):
        return (snapshot.get("mode"), str(getattr(self.transport, "kind", "")),
                str(getattr(self.transport, "host", "")), str(getattr(self.transport, "port", "")))

    def _apply_snapshot(self, snapshot):
        if not isinstance(snapshot, dict) or snapshot.get("mode") not in {"demo", "gateway", "equipment", "observation"}:
            self._snapshot_stale = True; self.status.set("Resposta não reconhecida. Dados anteriores mantidos.")
            self._render_home(); self._refresh_mutation_controls(); return False
        identity = self._snapshot_identity(snapshot)
        old_evidence = summarize_inventory(self.snapshot)
        source_current = source_collection_current(snapshot)
        if (snapshot.get("mode") != "demo" and not source_current and
                self.__dict__.get("_snapshot_source") == identity and old_evidence["facts"]["has_evidence"]):
            self._snapshot_stale = True; self._last_error = "connection_error"
            self.status.set("A nova coleta não foi confirmada. Dados anteriores mantidos como desatualizados; nenhuma ação será repetida.")
            self.error_help_button.pack(side="right", padx=(0, 8), before=self.refresh_button)
            self._render_home(); self._refresh_mutation_controls(); self._notify_diagnostics()
            return False
        self.snapshot = snapshot
        self._snapshot_source = identity
        self._snapshot_stale = not source_current
        self._last_snapshot_monotonic = monotonic()
        self._last_error = ""
        self.error_help_button.pack_forget()
        bank_warning = ""
        try:self._banks.path_for(snapshot, self.transport)
        except OSError:bank_warning = " A referência do banco não pôde ser salva; confira a pasta privada antes de preparar a lista."
        self._render_home(); self._render_devices(); self._render_sites(); self._render_activity()
        self._refresh_mutation_controls()
        prefix = "Dados recebidos sem coleta recente confirmada: " if self._snapshot_stale else "Leitura recebida: "
        self.status.set(prefix + self._time(snapshot.get("timestamp")) + ". Consulte a fonte e a cobertura antes de agir." + bank_warning + (" " + self._banks.warning if self._banks.warning else ""))
        self._notify_diagnostics()
        return True

    def _notify_diagnostics(self):
        window = self.__dict__.get("_diagnostics_window")
        if window is not None:
            try:
                if window.winfo_exists():window.refresh_plan()
            except tk.TclError:pass

    def _open_diagnostics(self):
        window = self.__dict__.get("_diagnostics_window")
        if window is not None:
            try:
                if window.winfo_exists():window.refresh_plan(); window.lift(); return window
            except tk.TclError:pass
        self._diagnostics_window = DiagnosticWindow(self)
        return self._diagnostics_window

    def _diagnostic_retry_available(self):
        from .transport import SSHTransport
        return self.transport is not None and self.snapshot.get("mode") in {"observation", "equipment", "demo"} and getattr(self.transport, "kind", "") != "legacy" and not isinstance(self.transport, SSHTransport)

    def _diagnostic_refresh(self):
        if self.transport is None:
            self.status.set("Ainda não há uma conexão para consultar. Escolha Observação ou um equipamento em Início.")
            return False
        if not self._diagnostic_retry_available():
            self.status.set("A consulta do perfil SSH legado pode reconciliar políticas; siga o fluxo avançado ou escolha Observação em Início. O assistente não troca o perfil.")
            return False
        transport = self.transport
        return self._run_job(lambda: transport.request("snapshot"), label="Conferindo a identificação pela conexão atual")

    @staticmethod
    def _time(value):
        try:return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().strftime("%d/%m %H:%M:%S")
        except (ValueError, TypeError):return str(value or "horário não informado")

    def _render_home(self):
        view = inventory_presentation(self.snapshot, stale=self._snapshot_stale, busy=self._busy)
        evidence = view["evidence"]; counts = evidence["counts"]
        mode = self.snapshot.get("mode", "observation"); stale = view["kind"] == "stale" or self._snapshot_stale
        labels = {"observation": "OBSERVAÇÃO LOCAL · somente consulta", "equipment": "ROTEADOR CONECTADO · recursos conforme a API",
                  "gateway": "GATEWAY SSH EXISTENTE · perfil avançado", "demo": "DEMONSTRAÇÃO · dados fictícios · nenhuma alteração real"}
        self.mode_text.set(labels.get(mode, "Aguardando conexão") + (" · dados desatualizados" if stale else ""))
        self.mode_banner.configure(bg="#FFF2C4" if mode == "demo" or stale else "#E8F0FF", fg="#77560D" if mode == "demo" or stale else "#2456A3")
        gateway = self.snapshot.get("gateway", {}); local = self.snapshot.get("local", {})
        self.collection_state.set(view["state"])
        self.collection_state_label.configure(fg=RED if view["kind"] in {"stale", "unavailable"} else PURPLE)
        self.network_text.set("Fonte: " + evidence["source_label"])
        records = self.snapshot.get("devices", [])
        self.count_text.set(f"{len(records)} registro(s) recebido(s) · {counts['unique_ips']} endereço(s) distinto(s)\n"
                            f"{counts['observed_neighbors']} vizinho(s) registrado(s) · {counts['known_macs']} MAC(s) conhecido(s)")
        try:
            network = ipaddress.ip_network(gateway.get("lab_cidr", ""), strict=False)
            segment = "Segmento informado: " + str(network)
        except (ValueError, TypeError):segment = "Segmento local não informado."
        self.local_network_text.set(segment + f"\n{counts['local_interfaces']} interface(s) local(is) · {counts['local_devices']} IP(s) deste computador")
        self.next_action_text.set(view["next_action"])
        button_labels = {"observation": "Identificar minha rede", "equipment": "Atualizar leitura da API", "gateway": "Atualizar perfil avançado", "demo": "Atualizar demonstração"}
        self.identify_button.configure(text=button_labels.get(mode, "Identificar minha rede"), state="disabled" if self._busy else "normal")
        hints = {"observation": "Consulta interfaces, rota e vizinhos conhecidos. A cobertura é parcial e não concede controle do roteador.",
                 "equipment": "Relê o inventário disponível na API conectada. Confirme a fonte e o horário antes de agir.",
                 "gateway": "Perfil avançado existente. A consulta pode reconciliar políticas configuradas; confira os detalhes.",
                 "demo": "Treinamento com dados fictícios. Use Acesso ao equipamento para escolher a Observação da rede real."}
        self.identification_hint.set(hints.get(mode, hints["observation"]))
        caps = snapshot_capabilities(self.snapshot)
        for key, label in self.capability_labels.items():
            enabled = caps[key]
            label.configure(text=CAPABILITY_NAMES[key] + (" · disponível" if enabled else " · não fornecido"), fg=GREEN if enabled else MUTED)
        note = "Modelo/API necessários para bloquear. A conexão comum ao Wi-Fi ou cabo não concede acesso administrativo ao roteador."
        if mode in {"equipment", "gateway"}:note = "Recursos confirmados por este perfil. " + ("Alterações autorizadas nesta sessão." if self._management_authorized else "Sessão somente de consulta; autorize alterações ao reconectar.")
        elif mode == "demo":note = "Treinamento com dados fictícios. Volte à observação para consultar a sua rede real."
        methods = evidence["facts"].get("source_methods", [])
        self.connection_note.set(note + "\n\n" + "\n".join(evidence["gaps"][:5]) +
            ("\n\nMétodos confirmados: " + ", ".join(methods) if methods else "") +
            "\n\nHorário da fonte: " + self._time(evidence["timestamp"]))
        if not self.host_var.get():
            detected = gateway.get("ip") or gateway.get("gateway_ip") or local.get("default_gateway")
            if detected:self.host_var.set(str(detected))

    @staticmethod
    def _fill(tree, rows):
        selected = tree.selection(); children = tree.get_children()
        if children:tree.delete(*children)
        for key, values in rows:tree.insert("", "end", iid=str(key), values=values)
        for key in selected:
            if tree.exists(key):tree.selection_set(key)

    def _render_devices(self):
        term = self.device_search.get().strip().casefold(); self._device_rows = {}
        rows, occurrences = [], {}
        conflicts = conflicted_device_ips(self.snapshot)
        for index, device in enumerate(self.snapshot.get("devices", [])):
            if not isinstance(device, dict):continue
            if term and term not in " ".join(str(device.get(k, "")) for k in ("name", "ip", "mac", "state")).casefold():continue
            key = str(device.get("ip", "")) + "|" + str(device.get("mac", ""))
            if key == "|":key = "device:" + str(index)
            duplicate = occurrences.get(key, 0); occurrences[key] = duplicate + 1
            if duplicate:key += "|record:" + str(duplicate)
            self._device_rows[key] = device
            uncertain = device.get("identity_conflict") is True or device.get("ip") in conflicts
            state = "Identidade incerta · MACs conflitantes" if uncertain else device.get("state") or "Registro da fonte"
            if str(state).strip().casefold() in {"online", "conectado", "ativo"}:state = "Registro da fonte · presença não confirmada"
            rows.append((key, (device.get("name") or "Sem nome", device.get("ip", ""), device.get("mac", ""),
                state, "Suspensa" if device.get("blocked") else "Sem suspensão informada", "Sim" if device.get("protected") else "Não")))
        self._fill(self.devices_table, rows)
        self.devices_note.set("Dispositivos observados; uma entrada antiga não comprova presença atual. " +
            ("Modelo/API necessários para bloquear." if self.snapshot.get("mode") == "observation" else
             "Esta tela controla a regra de IP. MAC e outros bloqueios são independentes; revise o mapa." if self.snapshot.get("mode") == "equipment" else
             "Selecione o alvo e confira as capacidades antes de agir."))

    def _render_sites(self):
        rows, self._domain_rows, occurrences = [], {}, {}
        for index, row in enumerate(self.snapshot.get("domains", [])):
            if not isinstance(row, dict):continue
            key = str(row.get("domain") or "domain:" + str(index))
            duplicate = occurrences.get(key, 0); occurrences[key] = duplicate + 1
            if duplicate:key += "|record:" + str(duplicate)
            self._domain_rows[key] = row
            rows.append((key, (row.get("domain", ""), row.get("category", ""), row.get("source", "Manual"))))
        self._fill(self.domains_table, rows)
        self.site_note.set("Bloqueios enviados a esta conexão. Caches e conexões já abertas podem continuar." if snapshot_capabilities(self.snapshot)["domain_filtering"] else
            "Este perfil não fornece bloqueio de sites. Você pode organizar o Banco de sites local e conectar um roteador compatível depois.")
        policy = self.snapshot.get("policies", {}).get("ai_block", {})
        if not isinstance(policy, dict):policy = {}
        self.ai_button.configure(text="Desativar perfil de IA" if policy.get("enabled") else "Ativar perfil de IA")

    def _render_activity(self):
        caps = snapshot_capabilities(self.snapshot)
        self.activity_note.set("Amostra recente de consultas DNS. Solicitações em segundo plano não comprovam visitas nem o conteúdo de páginas." if caps["dns_history"] else
            "Esta conexão não fornece consultas DNS. O programa não vê páginas HTTPS nem o histórico de navegação dos outros computadores.")
        self._fill(self.dns_table, [(i, (self._time(row.get("time")), row.get("client_ip", ""), row.get("domain", ""), row.get("status", "Consulta"))) for i, row in enumerate(self.snapshot.get("events", [])) if isinstance(row, dict)] if caps["dns_history"] else [])
        self._fill(self.audit_table, [(i, (self._time(row.get("time")), row.get("action", ""), row.get("target", ""), row.get("outcome", ""))) for i, row in enumerate(self.snapshot.get("audit", [])) if isinstance(row, dict)])
        self._fill(self.connections_table, [(i, (row.get("source", ""), row.get("dest", ""), row.get("proto", ""), row.get("port", ""), row.get("state", ""))) for i, row in enumerate(self.snapshot.get("connections", [])) if isinstance(row, dict)])

    def _selected_device(self):
        selected = self.devices_table.selection()
        return self._device_rows.get(selected[0]) if selected else None

    def _device_identity_uncertain(self, device):
        return bool(device and (device.get("identity_conflict") is True or device.get("ip") in conflicted_device_ips(self.snapshot)))

    def _mutation_allowed(self, required_health=(), notify=True, capability=None):
        if capability is None:
            capability = "domain_filtering" if "dns" in required_health else "address_blocking" if "firewall" in required_health else None
        reason = mutation_reason(self.snapshot, capability=capability, required_health=required_health,
            stale=self._snapshot_stale, age=monotonic()-self._last_snapshot_monotonic,
            busy=self._busy, authorized=self._management_authorized)
        if reason and notify:self.status.set(reason)
        return reason is None

    def _refresh_mutation_controls(self):
        dns = self._mutation_allowed(("dns",), notify=False, capability="domain_filtering")
        for button in (self.domain_add_button, self.domain_remove_button):button.configure(state="normal" if dns else "disabled")
        ai = self._mutation_allowed(("dns",), notify=False, capability="ai_block")
        self.ai_button.configure(state="normal" if ai else "disabled")
        device = self._selected_device(); protected = not device or device.get("protected") or self._device_identity_uncertain(device)
        equipment = self.snapshot.get("mode") == "equipment"
        capability = "address_blocking" if equipment else "device_internet_cut"
        allowed = self._mutation_allowed(("firewall", "forwarding"), notify=False, capability=capability) and not protected
        own_block = device_blocked_here(self.snapshot, device)
        self.block_button.configure(text="Bloquear IP" if equipment else "Suspender internet", state="normal" if allowed and not own_block and device.get("observed") is not False else "disabled")
        self.unblock_button.configure(text="Desbloquear IP" if equipment else "Restaurar internet", state="normal" if allowed and own_block else "disabled")
        self.device_selection_text.set("Selecione um dispositivo. IP e MAC não identificam uma pessoa." if not device else
            f"{device.get('name') or 'Sem nome'} · {device.get('ip', '')} · {device.get('mac', '')}" +
            (" · IP bloqueado" if equipment and own_block else " · IP sem regra" if equipment else "") +
            (" · MAC bloqueado" if equipment and device.get("blocked_mac") else "") +
            (" · identidade incerta: ações desabilitadas" if self._device_identity_uncertain(device) else "") +
            (" · protegido" if device.get("protected") else ""))
        self.connect_button.configure(state="disabled" if self._busy else "normal")
        if "identify_button" in self.__dict__:self.identify_button.configure(state="disabled" if self._busy else "normal")
        self.disconnect_button.configure(state="normal" if not self._busy and self.snapshot.get("mode") in {"equipment", "gateway", "demo"} else "disabled")

    def _confirm(self, title, message):
        return self.snapshot.get("mode") == "demo" or messagebox.askyesno(title, message, parent=self, default="no", icon="warning")

    def _set_block(self, blocked):
        equipment = self.snapshot.get("mode") == "equipment"
        capability = "address_blocking" if equipment else "device_internet_cut"
        if not self._mutation_allowed(("firewall", "forwarding"), capability=capability):return False
        device = self._selected_device()
        if not device or device.get("protected") or (blocked and device.get("observed") is False):return False
        if self._device_identity_uncertain(device):
            self.status.set("Identidade incerta: confira o IP e os MACs na fonte autorizada antes de agir."); return False
        try:
            if ipaddress.ip_address(str(device.get("ip", ""))).version != 4:raise ValueError
        except ValueError:
            self.status.set("Selecione um dispositivo com endereço IPv4 válido."); return False
        verb = ("Bloquear" if blocked else "Desbloquear") if equipment else ("Suspender" if blocked else "Restaurar")
        title = verb + (" IP" if equipment else " internet")
        message = (f"{verb} somente o IP {device['ip']} ({device.get('name') or 'dispositivo'})?\n\nRegras de MAC e outras políticas permanecem. Liberar o IP não garante acesso se outro escopo bloquear." if equipment else
            f"{verb} a internet de {device.get('name') or 'dispositivo'} ({device.get('ip')})?\n\nOutras regras por IP/MAC podem continuar.")
        if not self._confirm(title, message + "\nO programa não desliga o aparelho nem o rádio Wi-Fi."):return False
        if not self._mutation_allowed(("firewall", "forwarding"), capability=capability):return False
        transport = self.transport
        return self._run_job(lambda: transport.request("set_address_block", kind="ip", address=device["ip"], blocked=blocked) if equipment else
            transport.request("set_device_block", ip=device["ip"], blocked=blocked), label=title, alert=True)

    def _add_domain(self):
        if not self._mutation_allowed(("dns",), capability="domain_filtering"):return False
        try:domain = normalize_domain(self.domain_var.get())
        except ValueError as error:self.status.set(str(error)); return False
        if not self._confirm("Bloquear domínio", f"Bloquear {domain} e seus subdomínios usando este roteador?\n\nO efeito depende do DNS e do caminho da rede. Conexões já abertas podem continuar."):return False
        if not self._mutation_allowed(("dns",), capability="domain_filtering"):return False
        transport = self.transport; category = self.category_var.get()
        def done(snapshot):self.domain_var.set(""); self._apply_snapshot(snapshot)
        return self._run_job(lambda: transport.request("add_domain", domain=domain, category=category), label="Aplicando bloqueio", on_success=done, alert=True)

    def _remove_domain(self):
        if not self._mutation_allowed(("dns",), capability="domain_filtering"):return False
        selected = self.domains_table.selection()
        if not selected:return False
        row = self.__dict__.get("_domain_rows", {}).get(selected[0]) or next((row for row in self.snapshot.get("domains", []) if isinstance(row, dict) and row.get("domain") == selected[0]), None)
        if not row:return False
        if row.get("source") == "external":self.status.set("Regra externa: revise-a no equipamento pelo fluxo que a criou."); return False
        if row.get("source") == "ai_profile":self.status.set("Esse domínio pertence ao perfil global de IA. Use o controle do perfil."); return False
        domain = row.get("domain", "")
        if not self._confirm("Remover bloqueio", f"Remover a regra de {domain}? Outras políticas podem manter o domínio bloqueado."):return False
        if not self._mutation_allowed(("dns",), capability="domain_filtering"):return False
        transport = self.transport
        return self._run_job(lambda: transport.request("remove_domain", domain=domain), label="Removendo regra", alert=True)

    def _toggle_ai(self):
        if not self._mutation_allowed(("dns",), capability="ai_block"):return False
        policy = self.snapshot.get("policies", {}).get("ai_block", {})
        if not isinstance(policy, dict):return False
        if type(policy.get("enabled")) is not bool:return False
        enabled = not policy["enabled"]
        if not self._confirm("Perfil de IA", ("Ativar" if enabled else "Desativar") + " o perfil de domínios de IA? Ele não identifica toda IA integrada ou local."):return False
        if not self._mutation_allowed(("dns",), capability="ai_block"):return False
        transport = self.transport
        return self._run_job(lambda: transport.request("set_ai_block", enabled=enabled), label="Atualizando perfil de IA", alert=True)

    def _banlist_path(self):
        return self._banks.path_for(self.snapshot, self.transport)

    def _open_banlist(self):
        from .banlist_gui import BanlistWindow
        from .banlist import BanlistError
        transport = self.transport
        allowed = lambda:self.transport is transport and self._mutation_allowed(("dns",), capability="domain_filtering")
        try:
            path = self._banlist_path()
            for child in self.winfo_children():
                if isinstance(child, BanlistWindow) and not child._closed and child.db.path == path:
                    child.transport = transport; child.can_sync_callback = allowed
                    child.refresh(); child.lift(); return child
            return BanlistWindow(self, transport, path, can_sync_callback=allowed)
        except (BanlistError, OSError) as error:messagebox.showerror("Banco de sites", str(error), parent=self)

    def _seed_ai_catalog(self):
        from .banlist import BanlistDatabase, BanlistError
        from .controller import seed_ai_catalog
        try:
            database = BanlistDatabase(self._banlist_path())
            try:result = seed_ai_catalog(database)
            finally:database.close()
            self.status.set("Catálogo de IA adicionado ao banco local. Revise e use Aplicar quando houver controle compatível. Nenhuma regra foi enviada à rede.")
            return self._open_banlist()
        except (BanlistError, OSError, ValueError) as error:messagebox.showerror("Catálogo de IA", str(error), parent=self)

    def _open_network_map(self):
        from .network_map_gui import NetworkMapWindow
        callback = self._set_address_block if snapshot_capabilities(self.snapshot)["address_blocking"] and self._management_authorized else None
        window = NetworkMapWindow(self, snapshot_callback=lambda: self.snapshot, action_callback=callback)
        self._map_windows.append(window); return window

    def _set_address_block(self, kind, address, blocked):
        from .network_map_gui import valid_address
        if type(blocked) is not bool or not valid_address(kind, address):return False
        if not self._mutation_allowed(("firewall", "forwarding"), capability="address_blocking"):return False
        if any(str(row.get(kind, "")).lower() == str(address).lower() and self._device_identity_uncertain(row)
               for row in self.snapshot.get("devices", []) if isinstance(row, dict)):
            self.status.set("Identidade incerta: nenhuma regra desse alvo será alterada até a conferência."); return False
        if any(row.get("protected") and str(row.get(kind, "")).lower() == str(address).lower() for row in self.snapshot.get("devices", [])):return False
        verb = "Bloquear" if blocked else "Desbloquear"
        if not self._confirm(verb + " " + kind.upper(), f"{verb} {kind.upper()} {address}?\n\nA regra é independente dos outros bloqueios. Ela não desassocia o rádio Wi-Fi."):return False
        if not self._mutation_allowed(("firewall", "forwarding"), capability="address_blocking"):return False
        transport = self.transport
        return self._run_job(lambda: transport.request("set_address_block", kind=kind, address=address, blocked=blocked), label=verb + " endereço", alert=True)

    def _open_remote(self):
        from .remote_gui import RemoteWindow
        device = self._selected_device()
        if not device:self.status.set("Selecione um dispositivo com IP real."); return None
        if self.snapshot.get("mode") == "demo":self.status.set("Os IPs da demonstração são fictícios. Volte à observação para selecionar um computador real."); return None
        if self._device_identity_uncertain(device):self.status.set("Confira a identidade conflitante do dispositivo antes de abrir a administração remota."); return None
        if self._snapshot_stale or monotonic()-self._last_snapshot_monotonic > 60:self.status.set("Atualize a observação antes de escolher o computador."); return None
        try:ipaddress.ip_address(str(device.get("ip", "")))
        except ValueError:self.status.set("O dispositivo selecionado não tem um IP válido."); return None
        return RemoteWindow(self, device["ip"], protected=bool(device.get("protected")),
            events_callback=lambda:self.snapshot.get("events", []), domains_callback=lambda:self.snapshot.get("domains", []))

    def _open_integrations(self):
        from .integration_gui import IntegrationWindow
        return IntegrationWindow(self)

    def _open_manual(self):
        import webbrowser
        docs = Path(__file__).resolve().parents[1]/"docs"
        for name in ("MANUAL_DO_USUARIO_V2.html", "Manual_LabGuard_2.pdf", "COMECE_AQUI.md",
                     "MANUAL_DO_USUARIO.html", "MANUAL_DO_USUARIO.md"):
            path = docs/name
            if path.is_file():webbrowser.open(path.as_uri()); return
        messagebox.showinfo("Manual", "Consulte a documentação da mesma versão do programa.", parent=self)

    @staticmethod
    def _close_transport(transport):
        close = getattr(transport, "close", None)
        if callable(close):
            try:close()
            except Exception:pass

    def close(self):
        if self._closed:return
        self._closed = True; self._generation += 1; self.password_var.set("")
        for identifier in (self._drain_id, self._initial_id, self._tick_id):
            try:self.after_cancel(identifier)
            except tk.TclError:pass
        try:
            while True:
                _, ok, value, _, _ = self._results.get_nowait()
                if ok and isinstance(value, tuple):self._close_transport(value[0])
        except queue.Empty:pass
        for child in list(self.winfo_children()):
            if isinstance(child, tk.Toplevel):
                close = getattr(child, "close", None)
                try:close() if callable(close) else child.destroy()
                except tk.TclError:pass
        self._close_transport(self.transport); self._executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


class DiagnosticWindow(tk.Toplevel):
    """Passo a passo de leitura: sem comandos remotos, descoberta extra ou mutação."""
    def __init__(self, parent):
        import platform
        from .diagnostics import CASE_LABELS
        super().__init__(parent)
        self.owner = parent; self._closed = False
        self.plan = {"steps": [], "facts": {}}; self.index = 0
        self.title("LabGuard | Ajuda para identificar a rede")
        self.geometry("900x680"); self.minsize(760, 560); self.configure(bg=BG)
        self.transient(parent); self.protocol("WM_DELETE_WINDOW", self.close)
        self.columnconfigure(0, weight=1); self.rowconfigure(4, weight=1)
        self.case_var = tk.StringVar(value="Verificações sugeridas")
        system = platform.system(); self.system_var = tk.StringVar(value=system if system in {"Windows", "Linux"} else "Outro")
        self._case_ids = {label: key for key, label in CASE_LABELS.items()}
        self._label(self, "Ajuda para identificar a rede", fg=TEXT, font=(parent.font_family, 20, "bold")).grid(row=0, column=0, sticky="ew", padx=22, pady=(19, 5))
        self._label(self, "Siga as verificações que correspondem ao seu caso. O assistente não executa comandos nem altera configurações.").grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 12))
        choices = tk.Frame(self, bg=BG); choices.grid(row=2, column=0, sticky="ew", padx=22)
        choices.columnconfigure(1, weight=1)
        self._label(choices, "Quero conferir").grid(row=0, column=0, padx=(0, 9))
        cases = ttk.Combobox(choices, textvariable=self.case_var, values=["Verificações sugeridas", *CASE_LABELS.values()], state="readonly")
        cases.grid(row=0, column=1, sticky="ew"); cases.bind("<<ComboboxSelected>>", lambda _: self.refresh_plan(preserve=False))
        ttk.Combobox(choices, textvariable=self.system_var, values=["Windows", "Linux", "Outro"], state="readonly", width=10).grid(row=0, column=2, padx=(10, 0))
        self.system_var.trace_add("write", lambda *_: self.refresh_plan(preserve=False))
        self.context = tk.StringVar(); self.progress = tk.StringVar()
        line = tk.Frame(self, bg=BG); line.grid(row=3, column=0, sticky="ew", padx=22, pady=(11, 9))
        self._label(line, textvariable=self.context, fg=PURPLE).pack(side="left", fill="x", expand=True)
        self._label(line, textvariable=self.progress, fg=TEXT).pack(side="right")
        shell = RoundCard(self, padding=14); shell.grid(row=4, column=0, sticky="nsew", padx=22)
        shell.body.columnconfigure(0, weight=1); shell.body.rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(shell.body, bg=PANEL, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(shell.body, orient="vertical", command=self.canvas.yview)
        scrollbar.grid(row=0, column=1, sticky="ns"); self.canvas.configure(yscrollcommand=scrollbar.set)
        self.body = tk.Frame(self.canvas, bg=PANEL)
        item = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self.body.bind("<Configure>", lambda _: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(item, width=e.width))
        self.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"), add="+")
        self.bind("<Button-4>", lambda _: self.canvas.yview_scroll(-1, "units"), add="+")
        self.bind("<Button-5>", lambda _: self.canvas.yview_scroll(1, "units"), add="+")
        self.bind("<Next>", lambda _: self.canvas.yview_scroll(1, "pages"), add="+")
        self.bind("<Prior>", lambda _: self.canvas.yview_scroll(-1, "pages"), add="+")
        controls = tk.Frame(self, bg=BG); controls.grid(row=5, column=0, sticky="ew", padx=22, pady=(12, 7))
        self.back_button = ActionButton(controls, text="Voltar", command=self._back, height=37); self.back_button.pack(side="left")
        self.next_button = ActionButton(controls, text="Avançar", command=self._next, style="Purple.TButton", height=37); self.next_button.pack(side="left", padx=7)
        self.retry_button = ActionButton(controls, text="Atualizar consulta", command=self._refresh_query, style="Accent.TButton", height=37); self.retry_button.pack(side="left")
        self.copy_button = ActionButton(controls, text="Copiar comandos", command=self._copy_commands, height=37); self.copy_button.pack(side="left", padx=7)
        ActionButton(controls, text="Fechar", command=self.close, height=37).pack(side="right")
        self.feedback = tk.StringVar(value="Nenhuma consulta foi iniciada pelo assistente.")
        self._label(self, textvariable=self.feedback, font=(parent.font_family, 8)).grid(row=6, column=0, sticky="ew", padx=22, pady=(0, 16))
        self.refresh_plan()

    def _label(self, parent, text="", **kwargs):
        label = tk.Label(parent, text=text, bg=kwargs.pop("bg", BG), fg=kwargs.pop("fg", MUTED), anchor="w", justify="left", **kwargs)
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(120, e.width-4)))
        return label

    def refresh_plan(self, preserve=True):
        from .diagnostics import build_diagnostic_plan
        if self._closed:return
        previous = self.plan["steps"][self.index]["id"] if self.plan["steps"] else None
        self.plan = build_diagnostic_plan(self.owner.snapshot, self.owner.__dict__.get("_last_error", ""),
            system=self.system_var.get(), case=self._case_ids.get(self.case_var.get()))
        ids = [step["id"] for step in self.plan["steps"]]
        self.index = ids.index(previous) if preserve and previous in ids else 0
        facts = self.plan["facts"]
        mode = {"demo": "DEMONSTRAÇÃO · dados fictícios", "observation": "Observação local", "equipment": "Equipamento", "gateway": "SSH legado", "unknown": "Modo não confirmado"}[facts["mode"]]
        self.context.set(f"{mode} · {facts['observed_neighbors']} vizinho(s) · {facts['known_macs']} MAC(s) conhecido(s)")
        self.retry_button.configure(state="normal" if self.owner._diagnostic_retry_available() and not self.owner._busy else "disabled")
        if facts["mode"] == "gateway":self.feedback.set("Consulta desabilitada no SSH legado: essa rotina pode reconciliar políticas existentes. O assistente não troca o modo.")
        self._show_step()

    def _show_step(self):
        for widget in self.body.winfo_children():widget.destroy()
        step = self.plan["steps"][self.index]
        self.progress.set(f"Passo {self.index+1} de {len(self.plan['steps'])}")
        self._label(self.body, step["title"], bg=PANEL, fg=PURPLE, font=(self.owner.font_family, 14, "bold")).pack(fill="x", pady=(1, 13))
        for number, instruction in enumerate(step["instructions"], 1):
            self._label(self.body, f"{number}. {instruction}", bg=PANEL, fg=TEXT).pack(fill="x", pady=(0, 13))
        if step["commands"]:
            self._label(self.body, "Comandos de consulta · execução manual", bg=PANEL, fg=PURPLE, font=(self.owner.font_family, 9, "bold")).pack(fill="x", pady=(3, 6))
            commands = tk.Text(self.body, height=len(step["commands"])+1, bg="#F1EDF9", fg=TEXT, font=("Courier", 10), relief="flat", wrap="word", padx=11, pady=8)
            commands.insert("1.0", "\n".join(step["commands"])); commands.configure(state="disabled"); commands.pack(fill="x")
        self.back_button.configure(state="normal" if self.index else "disabled")
        self.next_button.configure(state="normal" if self.index < len(self.plan["steps"])-1 else "disabled")
        self.copy_button.configure(state="normal" if step["commands"] else "disabled")
        self.canvas.yview_moveto(0)

    def _back(self):
        if self.index:self.index -= 1; self._show_step()

    def _next(self):
        if self.index < len(self.plan["steps"])-1:self.index += 1; self._show_step()

    def _copy_commands(self):
        commands = self.plan["steps"][self.index]["commands"]
        if commands:
            self.clipboard_clear(); self.clipboard_append("\n".join(commands))
            self.feedback.set("Comandos copiados. O assistente não os executou.")

    def _refresh_query(self):
        if self.owner._diagnostic_refresh():
            self.retry_button.configure(state="disabled")
            self.feedback.set("Consulta solicitada na conexão atual. Nenhuma ação de bloqueio será repetida.")
        else:self.feedback.set("A consulta não foi iniciada. Aguarde a operação atual ou confira o modo em Início.")

    def close(self):
        if self._closed:return
        self._closed = True
        if self.owner.__dict__.get("_diagnostics_window") is self:self.owner._diagnostics_window = None
        self.destroy()
