"""Interface desktop do LabGuard. Rede e SSH nunca executam no thread do Tk."""
from __future__ import annotations

import csv
import hashlib
from collections import Counter
from time import monotonic
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import queue
import tkinter as tk
from tkinter import font as tkfont
from tkinter import filedialog, messagebox, ttk

from .demo import DemoTransport
from .transport import SSHTransport, TransportError


from .ui import (ActionButton, RoundCard, IconBadge, BG, PANEL, CARD, TEXT,
                 MUTED, PURPLE, BLUE, GREEN, AMBER, RED, SIDEBAR, BORDER)


def csv_safe(value):
    """Impede que nomes recebidos da rede sejam fórmulas em planilhas."""
    text = str(value if value is not None else "")
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def dashboard_summary(snapshot):
    """Resume apenas a amostra recebida; não cria séries nem visitas fictícias."""
    events = [row for row in snapshot.get("events", []) if isinstance(row, dict)]
    devices = [row for row in snapshot.get("devices", []) if isinstance(row, dict)]
    names = {row.get("ip"): row.get("name") or "Sem nome" for row in devices}
    domains = Counter(str(row.get("domain", "")).lower().rstrip(".") for row in events if row.get("domain"))
    clients = Counter(str(row.get("client_ip", "")) for row in events if row.get("client_ip"))
    return {
        "domains": sorted(domains.items(), key=lambda row: (-row[1], row[0]))[:5],
        "clients": [(ip, names.get(ip, "Sem nome"), count) for ip, count in sorted(clients.items(), key=lambda row: (-row[1], row[0]))[:5]],
        "events": events[:5],
        "audit": [row for row in snapshot.get("audit", []) if isinstance(row, dict)][:4],
        "queries": len(events),
        "blocked_queries": sum(row.get("status") == "Bloqueio DNS confirmado" for row in events),
        "protected": sum(bool(row.get("protected")) for row in devices),
    }


class App(tk.Tk):
    def __init__(self, transport=None):
        super().__init__()
        self.title("LabGuard | Controle de rede do laboratório")
        self.geometry("1280x820")
        self.minsize(1024, 700)
        self.configure(bg=BG)
        self.transport = transport or DemoTransport()
        self.snapshot = {}
        self._snapshot_stale = True
        self._last_snapshot_monotonic = 0.0
        self._generation = 0
        self._busy = False
        self._closed = False
        self._results = queue.Queue()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="labguard-ssh")
        self._shown_events = []
        self._pages = {}
        self._nav_buttons = {}
        self._page = "overview"
        self._style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(60, self._drain)
        self.after(100, self.refresh)
        self.after(5000, self._auto_refresh)

    def _style(self):
        installed = set(tkfont.families(self))
        self.font_family = next((name for name in (
            "Segoe UI", "DejaVu Sans", "Liberation Sans", "Arial", "Helvetica")
            if name in installed), tkfont.nametofont("TkDefaultFont").actual("family"))
        tkfont.nametofont("TkDefaultFont").configure(family=self.font_family, size=10)
        self.option_add("*Font", (self.font_family, 10))
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=9)
        style.configure("TCombobox", fieldbackground=PANEL, foreground=TEXT,
                        background=CARD, arrowcolor=PURPLE, padding=8, bordercolor=BORDER)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL)],
                  foreground=[("readonly", TEXT)], selectbackground=[("readonly", PANEL)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CARD, foreground=MUTED, padding=(18, 11), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", PURPLE)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        borderwidth=0, rowheight=39, font=(self.font_family, 10),
                        lightcolor=BORDER, darkcolor=BORDER)
        style.configure("Overview.Treeview", rowheight=29, font=(self.font_family, 9))
        style.configure("Overview.Treeview.Heading", font=(self.font_family, 8, "bold"), padding=(8, 9))
        style.configure("Treeview.Heading", background="#EDE7FA", foreground="#5C467D",
                        font=(self.font_family, 9, "bold"), padding=(12, 13), relief="flat")
        style.map("Treeview", background=[("selected", "#DED0FA")],
                  foreground=[("selected", "#39215F")])
        style.map("Treeview.Heading", background=[("active", "#E1D5F7")])
        style.configure("Vertical.TScrollbar", background="#D4C7EB", troughcolor=BG,
                        bordercolor=BG, arrowcolor=PURPLE)
        style.configure("Horizontal.TScrollbar", background="#D4C7EB", troughcolor=BG,
                        bordercolor=BG, arrowcolor=PURPLE)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        sidebar = tk.Frame(self, bg=SIDEBAR, width=218)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        brand = tk.Frame(sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=22, pady=(25, 28))
        IconBadge(brand, kind="shield", color=AMBER, tint="#453064", size=42).pack(side="left", padx=(0, 10))
        words = tk.Frame(brand, bg=SIDEBAR)
        words.pack(side="left")
        tk.Label(words, text="LabGuard", font=(self.font_family, 19, "bold"),
                 bg=SIDEBAR, fg="white", anchor="w").pack(fill="x")
        tk.Label(words, text="CONTROLE ESCOLAR", bg=SIDEBAR, fg="#BDA7DF",
                 font=(self.font_family, 7, "bold"), anchor="w").pack(fill="x", pady=(3, 0))
        tk.Label(sidebar, text="SEU LABORATÓRIO", bg=SIDEBAR, fg="#A48BC6",
                 font=(self.font_family, 8, "bold"), anchor="w").pack(fill="x", padx=26, pady=(0, 8))
        pages = [("overview", "Visão geral"), ("devices", "Máquinas"),
                 ("domains", "Sites e IA"), ("dns", "Histórico DNS"),
                 ("connections", "Conexões por IP"), ("audit", "Auditoria"),
                 ("connection", "Conectar e ajuda")]
        self._nav_labels = dict(pages)
        for name, label in pages:
            button = ActionButton(sidebar, text=label, style="Nav.TButton",
                                  height=43, font=(self.font_family, 9),
                                  command=lambda n=name: self.show_page(n))
            button.pack(fill="x", padx=13, pady=3)
            self._nav_buttons[name] = button
        tk.Frame(sidebar, bg="#4B3566", height=1).pack(fill="x", padx=24, pady=(16, 14))
        ActionButton(sidebar, text="Roteadores e switches", style="Yellow.TButton",
                     font=(self.font_family, 9, "bold"), command=self._open_integrations).pack(
                         fill="x", padx=15, pady=0)
        ActionButton(sidebar, text="Banco de sites", style="Nav.TButton", height=39,
                     command=self._open_banlist).pack(fill="x", padx=15, pady=(5, 0))
        ActionButton(sidebar, text="Mapa e relatórios", style="Nav.TButton", height=39,
                     command=self._open_network_map).pack(fill="x", padx=15, pady=(4, 0))
        tk.Label(sidebar, text="LabGuard 1.4 · Administração", bg=SIDEBAR, fg="#BCA7D9",
                 justify="left", anchor="w", font=(self.font_family, 8)).pack(
                     side="bottom", padx=24, pady=14, fill="x")

        main = tk.Frame(self, bg=BG)
        main.grid(row=0, column=1, sticky="nsew", padx=26, pady=23)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)
        header = tk.Frame(main, bg=BG)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        title_box = tk.Frame(header, bg=BG)
        title_box.pack(side="left")
        tk.Label(title_box, text="ADMINISTRAÇÃO DO LABORATÓRIO", bg=BG, fg=PURPLE,
                 font=(self.font_family, 8, "bold"), anchor="w").pack(fill="x", pady=(0, 4))
        self.page_title = tk.Label(title_box, text="Visão geral", bg=BG, fg=TEXT,
                                  font=(self.font_family, 24, "bold"), anchor="w")
        self.page_title.pack(fill="x")
        self.refresh_button = ActionButton(header, text="Atualizar", style="Purple.TButton", command=self.refresh)
        self.refresh_button.pack(side="right", pady=(8, 0))
        self.mode_banner = tk.Label(main, text="DEMONSTRAÇÃO | dados fictícios | nenhum bloqueio real",
                                   bg="#FFF2C4", fg="#77560D", anchor="w", padx=16, pady=11,
                                   font=(self.font_family, 9, "bold"))
        self.mode_banner.grid(row=1, column=0, sticky="ew", pady=(0, 18))
        self.content = tk.Frame(main, bg=BG)
        self.content.grid(row=2, column=0, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)
        for name, _ in pages:
            frame = ttk.Frame(self.content)
            frame.grid(row=0, column=0, sticky="nsew")
            self._pages[name] = frame
        self._build_overview(self._scrollable_page(self._pages["overview"]))
        self._build_devices(self._pages["devices"])
        self._build_dns(self._pages["dns"])
        self._build_domains(self._pages["domains"])
        self._build_connections(self._pages["connections"])
        self._build_audit(self._pages["audit"])
        self._build_connection(self._scrollable_page(self._pages["connection"]))
        footer = tk.Frame(main, bg=BG)
        footer.grid(row=3, column=0, sticky="ew", pady=(13, 0))
        self.status = tk.StringVar(value="Carregando demonstração…")
        self._responsive_wrap(tk.Label(footer, textvariable=self.status, bg=BG, fg=MUTED,
            anchor="w", font=(self.font_family, 8), wraplength=900, justify="left")).pack(fill="x")
        self.show_page("overview")

    def _open_integrations(self):
        from .integration_gui import IntegrationWindow
        IntegrationWindow(self)

    def _open_banlist(self):
        from .banlist_gui import BanlistWindow
        from .banlist import BanlistError
        transport = self.transport
        identity = "|".join((self.snapshot.get("mode", "demo"),
                             str(getattr(transport, "host", "")), str(getattr(transport, "port", ""))))
        filename = hashlib.sha256(identity.encode()).hexdigest()[:24] + ".sqlite3"
        path = Path.home() / ".labguard" / "banlists" / filename
        try:
            BanlistWindow(self, transport, path,
                can_sync_callback=lambda: self.transport is transport and self._mutation_allowed(("dns",)))
        except (BanlistError, OSError) as error:
            messagebox.showerror("Banco de sites", str(error), parent=self)

    def _open_remote(self):
        from .remote_gui import RemoteWindow
        device = self._selected_device()
        if not device:
            messagebox.showinfo("Selecione uma máquina", "Selecione uma linha na tabela de máquinas.", parent=self)
            return
        if self.snapshot.get("mode") == "demo":
            messagebox.showinfo("Demonstração", "Os IPs desta demonstração são fictícios. Conecte o gateway real para selecionar um computador do laboratório.", parent=self)
            return
        if not self._mutation_allowed():
            return
        RemoteWindow(self, device["ip"], protected=bool(device.get("protected")),
                     events_callback=lambda: self.snapshot.get("events", []),
                     domains_callback=lambda: self.snapshot.get("domains", []))

    def _open_network_map(self):
        from .network_map_gui import NetworkMapWindow
        NetworkMapWindow(self, snapshot_callback=lambda: self.snapshot,
                         action_callback=self._set_address_block)

    def _set_address_block(self, kind, address, blocked):
        from .network_map_gui import valid_address
        if kind not in ("ip", "mac") or type(blocked) is not bool or not valid_address(kind, address):
            self.status.set("Endereço de rede inválido.")
            return
        if not self._mutation_allowed(("firewall", "forwarding")):
            return
        address = address.lower()
        if any(row.get("protected") and str(row.get(kind, "")).lower() == address
               for row in self.snapshot.get("devices", [])):
            self.status.set("Endereço administrativo protegido.")
            return
        verb = "Bloquear" if blocked else "Desbloquear"
        if not self._live_confirmation(f"{verb} {kind.upper()}",
            f"{verb} a internet pelo {kind.upper()} {address}?\n\nA regra é independente dos demais bloqueios. Liberar este endereço pode manter a máquina bloqueada por outro escopo. A ação não desassocia o aparelho do Wi-Fi."):
            return
        if not self._mutation_allowed(("firewall", "forwarding")):
            return
        transport = self.transport
        self._run_job(lambda: transport.request("set_address_block", kind=kind, address=address, blocked=blocked),
                      label=f"{verb} {kind.upper()} {address}", alert=True)

    def show_page(self, name):
        self._page = name
        self._pages[name].tkraise()
        for key, button in self._nav_buttons.items():
            button.configure(face="#4B2F76" if key == name else SIDEBAR,
                             fg="white" if key == name else "#D5CAE9")
        self.page_title.configure(text=self._nav_labels[name])

    def _hint(self, parent, text, row=0):
        label = ttk.Label(parent, text=text, style="Muted.TLabel", wraplength=870,
                          justify="left")
        label.grid(row=row, column=0, sticky="ew", pady=(0, 15))
        self._responsive_wrap(label)
        return label

    @staticmethod
    def _responsive_wrap(label, padding=0):
        label.bind("<Configure>", lambda event: label.configure(
            wraplength=max(120, event.width - padding)), add="+")
        return label

    def _scrollable_page(self, parent):
        """Mantém orientações e formulários acessíveis em telas de 700 px."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(9, 0))
        inner = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))
        return inner

    def _table(self, parent, columns, row, widths=None):
        container = ttk.Frame(parent)
        container.grid(row=row, column=0, sticky="nsew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        keys = [c[0] for c in columns]
        table = ttk.Treeview(container, columns=keys, show="headings", selectmode="browse")
        for index, (key, label) in enumerate(columns):
            table.heading(key, text=label, anchor="w")
            table.column(key, width=(widths or {}).get(key, 135), minwidth=80, anchor="w")
        table.grid(row=0, column=0, sticky="nsew")
        vs = ttk.Scrollbar(container, orient="vertical", command=table.yview)
        hs = ttk.Scrollbar(container, orient="horizontal", command=table.xview)
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        table.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        table.tag_configure("blocked", foreground=RED)
        table.tag_configure("protected", foreground=GREEN)
        return table

    def _build_overview(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        self.overview_caption = tk.StringVar(value="Aguardando a primeira leitura do laboratório.")
        heading = tk.Frame(parent, bg=BG)
        heading.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        heading.grid_columnconfigure(0, weight=1)
        tk.Label(heading, text="PAINEL OPERACIONAL", bg=BG, fg=PURPLE,
                 font=(self.font_family, 8, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        self._responsive_wrap(tk.Label(heading, textvariable=self.overview_caption,
            bg=BG, fg=MUTED, font=(self.font_family, 9), anchor="w", justify="left")).grid(
                row=1, column=0, sticky="ew", pady=(4, 0))
        ActionButton(heading, text="Conectar gateway", style="Purple.TButton", height=39,
                     command=lambda: self.show_page("connection")).grid(row=0, column=1, rowspan=2, padx=(12, 0))

        cards = tk.Frame(parent, bg=BG)
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        self.metric_labels = {}
        self.metric_details = {}
        metrics = [("observed_devices", "Máquinas observadas", BLUE, "computer", "#E7F0FF", "DHCP e vizinhos de rede"),
                   ("blocked_devices", "Internet suspensa", RED, "shield", "#FDEBF0", "Política por máquina"),
                   ("queries_window", "Consultas DNS", PURPLE, "activity", "#EFE8FD", "Amostra recente"),
                   ("blocked_events_window", "Bloqueios DNS", "#936500", "dns", "#FFF3C7", "Respostas confirmadas")]
        for col, (key, title, color, kind, tint, detail) in enumerate(metrics):
            cards.grid_columnconfigure(col, weight=1, uniform="metrics")
            card = RoundCard(cards, padding=15, radius=16)
            card.grid(row=0, column=col, sticky="nsew", padx=(0, 10 if col < 3 else 0))
            top = tk.Frame(card.body, bg=PANEL)
            top.pack(fill="x")
            self._responsive_wrap(tk.Label(top, text=title, bg=PANEL, fg=MUTED,
                font=(self.font_family, 8, "bold"), anchor="w", justify="left", wraplength=120)).pack(side="left", fill="x", expand=True)
            IconBadge(top, kind=kind, color=color, tint=tint, size=29).pack(side="right", padx=(4, 0))
            value = tk.Label(card.body, text="-", bg=PANEL, fg=TEXT,
                             font=(self.font_family, 25, "bold"), anchor="w")
            value.pack(fill="x", pady=(4, 0))
            caption = tk.Label(card.body, text=detail, bg=PANEL, fg=MUTED,
                               font=(self.font_family, 8), anchor="w", justify="left", wraplength=155)
            self._responsive_wrap(caption).pack(fill="x", pady=(2, 0))
            self.metric_labels[key] = value
            self.metric_details[key] = caption

        service = RoundCard(parent, padding=16, radius=16)
        service.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        service.body.grid_columnconfigure(0, weight=1)
        service_top = tk.Frame(service.body, bg=PANEL)
        service_top.grid(row=0, column=0, sticky="ew")
        tk.Label(service_top, text="Estado da operação", bg=PANEL, fg=TEXT,
                 font=(self.font_family, 11, "bold"), anchor="w").pack(side="left")
        self.overview_state = tk.Label(service_top, text="Aguardando dados", bg=CARD, fg=MUTED,
                 padx=10, pady=4, font=(self.font_family, 8, "bold"))
        self.overview_state.pack(side="right")
        self.gateway_summary = tk.StringVar(value="Gateway não conectado.")
        self._responsive_wrap(tk.Label(service.body, textvariable=self.gateway_summary,
            bg=PANEL, fg=MUTED, justify="left", anchor="w", font=(self.font_family, 8))).grid(
                row=1, column=0, sticky="ew", pady=(5, 11))
        health_row = tk.Frame(service.body, bg=PANEL)
        health_row.grid(row=2, column=0, sticky="ew")
        self.health_labels = {}
        for col, (key, title) in enumerate((("firewall", "Firewall"), ("dns", "DNS / DHCP"),
                                          ("forwarding", "Encaminhamento"), ("ai", "Perfil de IA"))):
            health_row.grid_columnconfigure(col, weight=1, uniform="health")
            cell = tk.Frame(health_row, bg="#F8F7FC", padx=11, pady=8)
            cell.grid(row=0, column=col, sticky="nsew", padx=(0, 8 if col < 3 else 0))
            tk.Label(cell, text=title, bg="#F8F7FC", fg=MUTED,
                     font=(self.font_family, 8), anchor="w").pack(fill="x")
            label = tk.Label(cell, text="Sem leitura", bg="#F8F7FC", fg=MUTED,
                             font=(self.font_family, 9, "bold"), anchor="w")
            label.pack(fill="x", pady=(3, 0))
            self.health_labels[key] = label

        sample = tk.Frame(parent, bg=BG)
        sample.grid(row=3, column=0, sticky="ew", pady=(0, 14))
        for col in (0, 1):
            sample.grid_columnconfigure(col, weight=1, uniform="sample")
        domain_card = RoundCard(sample, padding=16, radius=16)
        domain_card.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        client_card = RoundCard(sample, padding=16, radius=16)
        client_card.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self._overview_heading(domain_card.body, "Domínios mais solicitados", "Contagem na amostra recente; não equivale a visitas.")
        self.top_domains_table = self._overview_table(domain_card.body,
            [("domain", "Domínio", 210), ("count", "Consultas", 75)], height=5)
        self.top_domains_table.bind("<Double-1>", self._overview_domain)
        self._overview_heading(client_card.body, "Atividade por máquina", "Ordenação pelas consultas DNS da mesma amostra.")
        self.top_clients_table = self._overview_table(client_card.body,
            [("name", "Máquina", 105), ("ip", "IP", 135), ("count", "Consultas", 75)], height=5)
        self.top_clients_table.bind("<Double-1>", self._overview_client)

        recent = RoundCard(parent, padding=16, radius=16)
        recent.grid(row=4, column=0, sticky="ew", pady=(0, 14))
        self._overview_heading(recent.body, "Solicitações recentes", "Últimos registros disponíveis no gateway.")
        self.overview_events_table = self._overview_table(recent.body,
            [("time", "Horário", 90), ("ip", "IP solicitante", 135), ("domain", "Domínio", 260),
             ("status", "Resultado observado", 195)], height=4)

        bottom = tk.Frame(parent, bg=BG)
        bottom.grid(row=5, column=0, sticky="ew", pady=(0, 14))
        bottom.grid_columnconfigure(0, weight=3)
        bottom.grid_columnconfigure(1, weight=2)
        audit = RoundCard(bottom, padding=16, radius=16)
        audit.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        alerts = RoundCard(bottom, padding=16, radius=16)
        alerts.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self._overview_heading(audit.body, "Últimas ações", "Auditoria administrativa recebida do gateway.")
        self.overview_audit_table = self._overview_table(audit.body,
            [("time", "Horário", 80), ("action", "Ação", 170), ("target", "Alvo", 180)], height=4)
        self._overview_heading(alerts.body, "Pontos de atenção", "Avisos de operação e contexto da leitura.")
        self.overview_warnings = tk.StringVar(value="Aguardando dados.")
        self._responsive_wrap(tk.Label(alerts.body, textvariable=self.overview_warnings,
            bg=PANEL, fg=MUTED, anchor="nw", justify="left", font=(self.font_family, 9))).pack(fill="both", expand=True)

        actions = tk.Frame(parent, bg=BG)
        actions.grid(row=6, column=0, sticky="ew", pady=(0, 10))
        for label, command, style in (("Máquinas", lambda: self.show_page("devices"), "Accent.TButton"),
                                      ("Sites e IA", lambda: self.show_page("domains"), "Purple.TButton"),
                                      ("Histórico DNS", lambda: self.show_page("dns"), "TButton"),
                                      ("Equipamentos", self._open_integrations, "Yellow.TButton")):
            ActionButton(actions, text=label, command=command, style=style, height=40).pack(side="left", padx=(0, 8))

    def _overview_heading(self, parent, title, subtitle):
        tk.Label(parent, text=title, bg=PANEL, fg=TEXT, font=(self.font_family, 11, "bold"), anchor="w").pack(fill="x")
        self._responsive_wrap(tk.Label(parent, text=subtitle, bg=PANEL, fg=MUTED,
            font=(self.font_family, 8), anchor="w", justify="left")).pack(fill="x", pady=(4, 10))

    def _overview_table(self, parent, columns, height=5):
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill="both", expand=True)
        frame.grid_columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height,
                            selectmode="browse", style="Overview.Treeview")
        for key, title, width in columns:
            tree.heading(key, text=title, anchor="w")
            tree.column(key, width=width, minwidth=55 if key == "count" else 75, anchor="w", stretch=key != "count")
        tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        scroll.grid(row=1, column=0, sticky="ew")
        tree.configure(xscrollcommand=scroll.set)
        tree.tag_configure("blocked", foreground=RED)
        tree.tag_configure("muted", foreground=MUTED)
        return tree

    def _render_overview(self):
        data = self.snapshot
        summary = dashboard_summary(data)
        demo = data.get("mode") == "demo"
        stamp = self._time(data.get("timestamp", ""))
        self.overview_caption.set(f"{'Cenário de demonstração' if demo else 'Última leitura do gateway'} | {stamp} | {summary['queries']} consultas na amostra")
        gateway = data.get("gateway", {})
        self.gateway_summary.set(f"{gateway.get('hostname', 'Gateway')} | {gateway.get('lab_cidr', '-')} | LAN {gateway.get('lan_interface', '-')} > WAN {gateway.get('wan_interface', '-')}")
        health = data.get("health", {})
        healthy = all(health.get(key) is True for key in ("firewall", "dns", "forwarding"))
        stale = self.__dict__.get("_snapshot_stale", False)
        title, fg, bg = ("Demonstração", "#77560D", "#FFF2C4") if demo else (
            ("Leitura desatualizada", "#77560D", "#FFF2C4") if stale else
            (("Serviços operacionais", GREEN, "#DDF3E9") if healthy else ("Verifique os serviços", RED, "#FCE9EF")))
        self.overview_state.configure(text=title, fg=fg, bg=bg)
        for key in ("firewall", "dns", "forwarding"):
            active = health.get(key) is True
            text = "Ativo" if active else "Indisponível"
            if stale and not demo:
                text = "Sem confirmação"
            self.health_labels[key].configure(text=text, fg=MUTED if stale and not demo else (GREEN if active else RED))
        policy = data.get("policies", {}).get("ai_block", {})
        enabled = policy.get("enabled") is True
        self.health_labels["ai"].configure(text="Ativado" if enabled else "Desativado", fg=PURPLE if enabled else MUTED)
        self.metric_details["observed_devices"].configure(text=f"{summary['protected']} endereço(s) protegido(s)")
        self.metric_details["queries_window"].configure(text="Amostra recente disponível")
        self._fill_tree(self.top_domains_table, [(domain, (domain, count), ()) for domain, count in summary["domains"]])
        self._fill_tree(self.top_clients_table, [(ip, (name, ip, count), ()) for ip, name, count in summary["clients"]])
        self._fill_tree(self.overview_events_table, [(i, (self._time(e.get("time", "")).split(" ")[-1], e.get("client_ip", ""),
            e.get("domain", ""), e.get("status", "Consulta")), ("blocked",) if e.get("status") == "Bloqueio DNS confirmado" else ())
            for i, e in enumerate(summary["events"])])
        self._fill_tree(self.overview_audit_table, [(i, (self._time(e.get("time", "")).split(" ")[-1], e.get("action", ""), e.get("target", "")), ())
            for i, e in enumerate(summary["audit"])])
        warnings = [str(x) for x in data.get("warnings", [])]
        if demo:
            warnings = ["Dados fictícios. Os controles desta sessão não alteram a rede."]
        elif stale:
            warnings.insert(0, "Atualize a leitura antes de aplicar alterações na rede.")
        self.overview_warnings.set("\n\n".join(warnings[:3]) if warnings else "Nenhum aviso informado pelo gateway nesta leitura.")
        if not summary["domains"]:
            self._fill_tree(self.top_domains_table, [("empty", ("Sem consultas nesta amostra", "-"), ("muted",))])
        if not summary["clients"]:
            self._fill_tree(self.top_clients_table, [("empty", ("Sem atividade na amostra", "", "-"), ("muted",))])

    def _overview_domain(self, _event=None):
        selection = self.top_domains_table.selection()
        if selection and selection[0] != "empty":
            self.dns_ip.set("Todas")
            self.dns_search.set(selection[0])
            self._render_dns()
            self.show_page("dns")

    def _overview_client(self, _event=None):
        selection = self.top_clients_table.selection()
        if selection and selection[0] != "empty":
            self.dns_ip.set(selection[0])
            self.dns_search.set("")
            self._render_dns()
            self.show_page("dns")

    def _build_devices(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)
        self._hint(parent, "Selecione uma máquina para suspender sua internet ou consultar os domínios solicitados. Equipamentos protegidos não podem ser suspensos.")
        bar = ttk.Frame(parent)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 13))
        ActionButton(bar, text="Ver consultas DNS", command=self._device_dns).pack(side="left")
        self.block_button = ActionButton(bar, text="Suspender internet", style="Danger.TButton",
                                       command=lambda: self._set_block(True))
        self.block_button.pack(side="left", padx=8)
        self.unblock_button = ActionButton(bar, text="Restaurar internet", command=lambda: self._set_block(False))
        self.unblock_button.pack(side="left")
        programs = ttk.Frame(parent)
        programs.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        ActionButton(programs, text="Programas e avisos", style="Purple.TButton", command=self._open_remote).pack(side="left")
        self.devices_table = self._table(parent, [("name", "Máquina"), ("ip", "IP"),
            ("mac", "MAC"), ("state", "Evidência de presença"), ("access", "Internet"),
            ("queries", "Consultas"), ("protected", "Protegida")], 2,
            {"name": 140, "mac": 160, "state": 170, "queries": 90, "protected": 90})
        self.devices_table.bind("<<TreeviewSelect>>", self._device_selection)
        self.device_note = tk.StringVar(value="Nenhuma máquina selecionada.")
        self._responsive_wrap(ttk.Label(parent, textvariable=self.device_note, style="Muted.TLabel", wraplength=850)).grid(
            row=4, column=0, sticky="ew", pady=(12, 0))
        self._device_selection()

    def _build_dns(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)
        self._hint(parent, "Domínios solicitados por cada IP, inclusive serviços em segundo plano. A amostra é limitada aos registros disponíveis no gateway.")
        bar = ttk.Frame(parent)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 13))
        ttk.Label(bar, text="Máquina / IP").pack(side="left", padx=(0, 8))
        self.dns_ip = tk.StringVar(value="Todas")
        self.dns_ip_combo = ttk.Combobox(bar, textvariable=self.dns_ip, values=["Todas"], width=19, state="readonly")
        self.dns_ip_combo.pack(side="left")
        self.dns_ip_combo.bind("<<ComboboxSelected>>", lambda _: self._render_dns())
        ttk.Label(bar, text="Buscar domínio").pack(side="left", padx=(17, 8))
        self.dns_search = tk.StringVar()
        self.dns_search.trace_add("write", lambda *_: self._render_dns())
        ttk.Entry(bar, textvariable=self.dns_search, width=23).pack(side="left")
        ActionButton(bar, text="Exportar CSV", command=self._export_dns).pack(side="right")
        self.dns_table = self._table(parent, [("time", "Horário"), ("ip", "IP solicitante"),
            ("domain", "Domínio"), ("type", "Tipo"), ("status", "Resultado observado")], 2,
            {"time": 175, "domain": 265, "type": 80, "status": 205})
        self.dns_count = tk.StringVar(value="0 registros exibidos")
        ttk.Label(parent, textvariable=self.dns_count, style="Muted.TLabel").grid(
            row=3, column=0, sticky="w", pady=(12, 0))

    def _build_domains(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(4, weight=1)
        self._hint(parent, "Lista global do laboratório. Informe apenas o domínio: exemplo.com. Os subdomínios também serão incluídos no bloqueio DNS.")
        ai_surface = RoundCard(parent, padding=18)
        ai_surface.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        ai_card = ai_surface.body
        ai_card.grid_columnconfigure(0, weight=1)
        tk.Label(ai_card, text="Bloquear serviços de IA", bg=PANEL, fg=TEXT,
                 anchor="w", font=(self.font_family, 13, "bold")).grid(row=0, column=0, sticky="ew")
        self.ai_state_text = tk.StringVar(value="Carregando perfil de IA…")
        self.ai_state_label = tk.Label(ai_card, textvariable=self.ai_state_text, bg=PANEL,
                                      fg=MUTED, anchor="w", justify="left")
        self._responsive_wrap(self.ai_state_label).grid(row=1, column=0, sticky="ew", pady=(5, 0))
        self.ai_toggle_button = ActionButton(ai_card, text="Ativar bloqueio de IA",
                                          style="Accent.TButton", state="disabled",
                                          command=self._toggle_ai_block)
        self.ai_toggle_button.grid(row=0, column=1, rowspan=2, padx=(12, 0))
        self.ai_catalog_button = ActionButton(ai_card, text="Ver serviços incluídos",
                                           state="disabled", command=self._show_ai_catalog)
        self.ai_catalog_button.grid(row=2, column=0, sticky="w", pady=(10, 0))
        self._responsive_wrap(tk.Label(ai_card,
            text="Bloqueia os domínios cadastrados. IA integrada em outros sites ou local precisa de controles adicionais.",
            bg=PANEL, fg=MUTED, anchor="w", justify="left", wraplength=850)).grid(
                row=3, column=0, columnspan=2, sticky="ew", pady=(9, 0))
        bar = ttk.Frame(parent)
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        self.domain_input = tk.StringVar()
        self.category_input = tk.StringVar(value="Jogos")
        ttk.Entry(bar, textvariable=self.domain_input, width=32).pack(side="left")
        ttk.Combobox(bar, textvariable=self.category_input, values=["Jogos", "Inteligência artificial", "Redes sociais", "Outros"],
                     width=16).pack(side="left", padx=8)
        self.domain_add_button = ActionButton(bar, text="Adicionar domínio", style="Accent.TButton", command=self._add_domain)
        self.domain_add_button.pack(side="left")
        actions = ttk.Frame(parent)
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        self.domain_import_button = ActionButton(actions, text="Importar lista .txt", command=self._import_domains)
        self.domain_import_button.pack(side="left")
        self.domain_remove_button = ActionButton(actions, text="Remover selecionado", command=self._remove_domain)
        self.domain_remove_button.pack(side="left", padx=8)
        self.domains_table = self._table(parent, [("domain", "Domínio bloqueado"),
            ("category", "Categoria"), ("source", "Origem"), ("created", "Adicionado em")], 4,
            {"domain": 280, "category": 180, "source": 140, "created": 180})
        self._responsive_wrap(ttk.Label(parent, text="Mudanças aplicam-se a novas resoluções DNS. O serviço DNS/DHCP é reiniciado brevemente para reler as regras.",
                  style="Muted.TLabel", wraplength=870)).grid(row=5, column=0, sticky="ew", pady=(12, 0))

    def _build_connections(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        self._hint(parent, "Conexões observadas no gateway. Destinos por IP podem hospedar muitos sites; esta tabela não revela URLs completas ou conteúdo HTTPS.")
        self.connections_table = self._table(parent, [("source", "IP da máquina"),
            ("dest", "IP de destino"), ("proto", "Protocolo"), ("port", "Porta de destino"),
            ("state", "Estado")], 1, {"source": 185, "dest": 185, "state": 210})

    def _build_audit(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        self._hint(parent, "Registro das ações administrativas disponibilizado pelo gateway. A auditoria de demonstração também é fictícia.")
        self.audit_table = self._table(parent, [("time", "Horário"), ("action", "Ação"),
            ("target", "Alvo"), ("outcome", "Resultado")], 1,
            {"time": 190, "action": 220, "target": 230, "outcome": 200})

    def _build_connection(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        self._hint(parent, "Conecte a interface ao gateway Linux do laboratório. A autenticação usa uma chave SSH; senhas e chaves privadas não são copiadas para o programa.")
        form_surface = RoundCard(parent, padding=20)
        form_surface.grid(row=1, column=0, sticky="ew")
        form = form_surface.body
        form.grid_columnconfigure(1, weight=1)
        self.host_var = tk.StringVar(value="192.168.50.1")
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="labguard")
        self.key_var = tk.StringVar()
        self.known_hosts_var = tk.StringVar()
        fields = [("Endereço do gateway", self.host_var), ("Porta SSH", self.port_var),
                  ("Usuário SSH", self.user_var), ("Arquivo da chave privada", self.key_var),
                  ("known_hosts (opcional)", self.known_hosts_var)]
        for row, (label, var) in enumerate(fields):
            tk.Label(form, text=label, bg=PANEL, fg=MUTED, anchor="w").grid(
                row=row, column=0, sticky="w", padx=(0, 18), pady=6)
            ttk.Entry(form, textvariable=var).grid(row=row, column=1, sticky="ew", pady=6)
            if row in (3, 4):
                ActionButton(form, text="Selecionar", command=lambda v=var: self._pick_file(v)).grid(
                    row=row, column=2, padx=(9, 0))
        actions = ttk.Frame(parent)
        actions.grid(row=2, column=0, sticky="ew", pady=(15, 19))
        ActionButton(actions, text="Conectar ao gateway", style="Accent.TButton", command=self._connect).pack(side="left")
        ActionButton(actions, text="Abrir demonstração", command=self._switch_demo).pack(side="left", padx=9)
        help_surface = RoundCard(parent, padding=19)
        help_surface.grid(row=3, column=0, sticky="ew")
        help_box = help_surface.body
        tk.Label(help_box, text="Antes da primeira conexão", bg=PANEL, fg=TEXT,
                 font=(self.font_family, 13, "bold"), anchor="w").pack(fill="x", pady=(0, 8))
        help_text = (
            "1. Instale o gateway Linux com duas interfaces, entre o roteador e o switch do laboratório.\n"
            "2. Configure a rede, os IPs protegidos e a chave administrativa conforme o manual.\n"
            "3. Verifique a impressão digital SSH no console do gateway e cadastre-a no known_hosts.\n"
            "4. Se a chave tiver senha, carregue-a no ssh-agent. O programa usa o OpenSSH do sistema.\n\n"
            "A chave do servidor é verificada rigorosamente. Uma falha de conexão mantém o modo anterior e exibe o erro.\n"
            "Esta conexão administra o gateway. Para equipamentos compatíveis, abra Roteadores / switches e confira os recursos do adaptador.")
        self._responsive_wrap(tk.Label(help_box, text=help_text, bg=PANEL, fg=MUTED, justify="left", anchor="w",
                 wraplength=850, font=(self.font_family, 10))).pack(fill="x")
        ActionButton(parent, text="Abrir manual do usuário", command=self._open_manual).grid(
            row=4, column=0, sticky="w", pady=(14, 0))

    def _pick_file(self, variable):
        selected = filedialog.askopenfilename(parent=self, title="Selecionar arquivo")
        if selected:
            variable.set(selected)

    def _open_manual(self):
        import webbrowser
        root = Path(__file__).resolve().parents[1]
        candidates = [root / "docs" / "MANUAL_DO_USUARIO.html", root / "docs" / "Manual_LabGuard_1.4.pdf",
                      root / "docs" / "INSTALACAO.md", root / "README.md"]
        path = next((p for p in candidates if p.is_file()), None)
        if path:
            webbrowser.open(path.as_uri())
        else:
            messagebox.showinfo("Manual", "Consulte o README e a pasta docs do pacote LabGuard.", parent=self)

    def _run_job(self, function, *, label, on_success=None, alert=False):
        if self._busy or self._closed:
            self.status.set("Aguarde a operação em andamento antes de iniciar outra ação.")
            return False
        self._busy = True
        self._refresh_mutation_controls()
        generation = self._generation
        self.status.set(label + "…")
        self.refresh_button.configure(state="disabled")
        def work():
            try:
                result = function()
                self._results.put((generation, True, result, on_success, alert, label))
            except Exception as exc:
                self._results.put((generation, False, str(exc), None, alert, label))
        self._executor.submit(work)
        return True

    def _drain(self):
        if self._closed:
            return
        try:
            while True:
                generation, ok, value, callback, alert, label = self._results.get_nowait()
                if generation != self._generation:
                    continue
                self._busy = False
                self.refresh_button.configure(state="normal")
                if ok:
                    if callback:
                        callback(value)
                    else:
                        self._apply_snapshot(value)
                else:
                    mode = "demonstração" if self.snapshot.get("mode", "demo") == "demo" else "gateway"
                    if mode == "gateway":
                        self._snapshot_stale = True
                        self._refresh_mutation_controls()
                        if "overview_caption" in self.__dict__:
                            self._render_overview()
                        self.mode_banner.configure(
                            text="GATEWAY SEM ATUALIZAÇÃO | conexão não confirmada | dados anteriores",
                            bg="#FFF2C4", fg="#77560D")
                    self.status.set(f"Falha: {value}  |  Modo {mode}; dados anteriores mantidos.")
                    if alert:
                        messagebox.showerror("Operação não concluída", value, parent=self)
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def refresh(self):
        transport = self.transport
        self._run_job(lambda: transport.request("snapshot"), label="Atualizando dados")

    def _auto_refresh(self):
        if self._closed:
            return
        self._refresh_mutation_controls()
        if not self._busy:
            self.refresh()
        self.after(5000, self._auto_refresh)

    def _connect(self):
        if self._busy:
            self.status.set("Aguarde a operação atual para conectar ao gateway.")
            return
        try:
            port = int(self.port_var.get().strip())
            transport = SSHTransport(host=self.host_var.get().strip(), port=port,
                user=self.user_var.get().strip(), key_path=self.key_var.get().strip(),
                known_hosts=self.known_hosts_var.get().strip() or None)
        except (ValueError, TransportError) as exc:
            messagebox.showerror("Configuração inválida", str(exc), parent=self)
            return
        self._generation += 1
        def connected(snapshot):
            if snapshot.get("mode") != "gateway":
                messagebox.showerror("Resposta inválida", "O destino SSH não retornou um gateway real.", parent=self)
                self.status.set("Conexão não ativada; modo anterior mantido.")
                return
            close_previous = getattr(self.transport, "close", None)
            if callable(close_previous):
                close_previous()
            self.transport = transport
            self._apply_snapshot(snapshot)
            self.show_page("overview")
        self._run_job(lambda: transport.request("snapshot"), label="Conectando ao gateway",
                      on_success=connected, alert=True)

    def _switch_demo(self):
        if self._busy:
            self.status.set("Aguarde a operação atual para trocar de modo.")
            return
        self._generation += 1
        close_previous = getattr(self.transport, "close", None)
        if callable(close_previous):
            close_previous()
        self.transport = DemoTransport()
        self.snapshot = {}
        self.mode_banner.configure(text="DEMONSTRAÇÃO | dados fictícios | nenhum bloqueio real", bg="#FFF2C4", fg="#77560D")
        self.refresh()

    @staticmethod
    def _fill_tree(tree, rows):
        selection = tree.selection()
        scroll = tree.yview()
        children = tree.get_children()
        if children:
            tree.delete(*children)
        for iid, values, tags in rows:
            tree.insert("", "end", iid=str(iid), values=values, tags=tags)
        for iid in selection:
            if tree.exists(iid):
                tree.selection_set(iid)
        if scroll:
            tree.yview_moveto(scroll[0])

    def _apply_snapshot(self, data):
        if not isinstance(data, dict) or data.get("mode") not in ("demo", "gateway"):
            self._snapshot_stale = True
            self._refresh_mutation_controls()
            self.status.set("O gateway retornou uma resposta inválida. Dados anteriores mantidos.")
            return
        self.snapshot = data
        self._snapshot_stale = False
        self._last_snapshot_monotonic = monotonic()
        demo = data["mode"] == "demo"
        ready = all(data.get("health", {}).get(key) is True for key in ("firewall", "dns", "forwarding"))
        self.mode_banner.configure(
            text="DEMONSTRAÇÃO | dados fictícios | nenhum bloqueio real" if demo else (
                "GATEWAY CONECTADO | serviços confirmados nesta leitura" if ready else
                "GATEWAY CONECTADO | verifique os serviços indisponíveis antes de alterar a rede"),
            bg="#FFF2C4" if demo or not ready else "#DDF3E9", fg="#77560D" if demo or not ready else GREEN)
        for key, label in self.metric_labels.items():
            label.configure(text=str(data.get("metrics", {}).get(key, 0)))
        gateway = data.get("gateway", {})
        health = data.get("health", {})
        state = lambda key: "ativo" if health.get(key) else "indisponível"
        self.gateway_summary.set(
            f"{gateway.get('hostname', 'Gateway')}  |  Rede {gateway.get('lab_cidr', '-')}\n"
            f"LAN: {gateway.get('lan_interface', '-')}   >   WAN: {gateway.get('wan_interface', '-')}\n"
            f"Firewall: {state('firewall')}   |   DNS: {state('dns')}   |   Encaminhamento: {state('forwarding')}\n"
            f"IPv6: {gateway.get('ipv6_policy', 'consulte o gateway')}")
        self._fill_tree(self.devices_table, [(d["ip"], (
            d.get("name") or "Sem nome", d["ip"], d.get("mac") or "-", d.get("state", "Observada"),
            "Suspensa" if d.get("blocked") else "Permitida", d.get("dns_queries", 0),
            "Sim" if d.get("protected") else "Não"),
            ("protected",) if d.get("protected") else (("blocked",) if d.get("blocked") else ()))
            for d in data.get("devices", [])])
        self._render_overview()
        self._device_selection()
        ips = sorted({d["ip"] for d in data.get("devices", [])} |
                     {e.get("client_ip", "") for e in data.get("events", [])} - {""})
        self.dns_ip_combo.configure(values=["Todas"] + ips)
        if self.dns_ip.get() not in ["Todas"] + ips:
            self.dns_ip.set("Todas")
        self._render_dns()
        self._render_ai_policy()
        self._fill_tree(self.domains_table, [(d["domain"], (
            d["domain"], d.get("category", "Outros"),
            "Perfil IA" if d.get("source") == "ai_profile" else "Manual",
            self._time(d.get("created_at", ""))), ())
            for d in data.get("domains", [])])
        self._fill_tree(self.connections_table, [(i, (c.get("source_ip", ""),
            c.get("destination_ip", ""), c.get("protocol", ""), c.get("port", ""), c.get("state", "")), ())
            for i, c in enumerate(data.get("connections", []))])
        self._fill_tree(self.audit_table, [(i, (self._time(a.get("time", "")), a.get("action", ""),
            a.get("target", ""), a.get("outcome", "")), ()) for i, a in enumerate(data.get("audit", []))])
        warnings = data.get("warnings", [])
        stamp = self._time(data.get("timestamp", ""))
        self._refresh_mutation_controls()
        self.status.set(f"Atualizado: {stamp}  |  Atualização automática a cada 5 s" +
                        ("  |  " + " | ".join(map(str, warnings)) if warnings else ""))

    @staticmethod
    def _time(value):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().strftime("%d/%m/%Y %H:%M:%S")
        except (ValueError, TypeError):
            return str(value or "-")

    def _selected_device(self):
        selection = self.devices_table.selection()
        if not selection:
            return None
        return next((d for d in self.snapshot.get("devices", []) if d.get("ip") == selection[0]), None)

    def _device_selection(self, _event=None):
        device = self._selected_device()
        protected = not device or device.get("protected")
        permitted = self._mutation_allowed(("firewall", "forwarding"), notify=False)
        self.block_button.configure(state="disabled" if not permitted or protected or device.get("blocked") else "normal")
        legacy = bool(device and ("device" in device.get("blocked_by", []) if "blocked_by" in device else device.get("blocked")))
        self.unblock_button.configure(state="disabled" if not permitted or protected or not legacy else "normal")
        self.device_note.set("Nenhuma máquina selecionada." if not device else
            f"{device.get('name') or 'Sem nome'} | {device['ip']} | Última evidência: {self._time(device.get('last_seen', ''))}" +
            (" | Equipamento protegido" if device.get("protected") else "") +
            (" | Escopos: " + ", ".join(device["blocked_by"]) + ". IP/MAC: use Mapa e relatórios." if device.get("blocked_by") else ""))

    def _device_dns(self):
        device = self._selected_device()
        if not device:
            messagebox.showinfo("Selecione uma máquina", "Selecione uma linha na tabela de máquinas.", parent=self)
            return
        self.dns_ip.set(device["ip"])
        self.dns_search.set("")
        self._render_dns()
        self.show_page("dns")

    def _render_dns(self):
        selected_ip = self.dns_ip.get()
        term = self.dns_search.get().strip().lower()
        self._shown_events = [e for e in self.snapshot.get("events", [])
            if (selected_ip == "Todas" or e.get("client_ip") == selected_ip)
            and term in e.get("domain", "").lower()]
        self._fill_tree(self.dns_table, [(i, (self._time(e.get("time", "")), e.get("client_ip", ""),
            e.get("domain", ""), e.get("query_type", ""), e.get("status", "Consulta")),
            ("blocked",) if "bloqueio" in e.get("status", "").lower() else ())
            for i, e in enumerate(self._shown_events)])
        self.dns_count.set(f"{len(self._shown_events)} registros exibidos | amostra recente, não histórico completo de navegação")

    def _mutation_allowed(self, required_health=(), notify=True):
        """Recusa alterações com leitura antiga ou serviço necessário sem confirmação."""
        data = self.snapshot
        reason = None
        if self.__dict__.get("_busy", False):
            reason = "Aguarde a operação em andamento antes de alterar a rede."
        elif self.__dict__.get("_session_locked", False):
            reason = "A sessão administrativa está bloqueada. Reconecte antes de alterar a rede."
        elif data.get("mode") == "demo":
            return True
        elif data.get("mode") != "gateway":
            reason = "Conecte e atualize o gateway antes de aplicar alterações."
        elif self.__dict__.get("_snapshot_stale", True) or monotonic() - self.__dict__.get("_last_snapshot_monotonic", 0.0) > 20:
            reason = "A leitura do gateway está desatualizada. Atualize e confirme a conexão antes de aplicar alterações."
        else:
            missing = [name for name in required_health if data.get("health", {}).get(name) is not True]
            if missing:
                names = {"firewall": "firewall", "dns": "DNS/DHCP", "forwarding": "encaminhamento"}
                reason = "Serviço sem confirmação: " + ", ".join(names.get(name, name) for name in missing) + ". Verifique o gateway antes de alterar a rede."
        if reason and notify:
            self.status.set(reason)
        return reason is None

    def _refresh_mutation_controls(self):
        allowed = self._mutation_allowed(("dns",), notify=False)
        for name in ("domain_add_button", "domain_import_button", "domain_remove_button"):
            widget = self.__dict__.get(name)
            if widget is not None:
                widget.configure(state="normal" if allowed else "disabled")
        if "ai_toggle_button" in self.__dict__:
            policy = self._ai_policy()
            self.ai_toggle_button.configure(state="normal" if allowed and policy is not None else "disabled")
        if all(key in self.__dict__ for key in ("devices_table", "block_button", "unblock_button")):
            self._device_selection()

    def _live_confirmation(self, title, text):
        if not self._mutation_allowed():
            return False
        if self.snapshot.get("mode") == "demo":
            return True
        return messagebox.askyesno(title, text, parent=self, icon="warning", default="no")

    def _set_block(self, blocked):
        if not self._mutation_allowed(("firewall", "forwarding")):
            return
        device = self._selected_device()
        if not device or device.get("protected"):
            return
        verb = "Suspender" if blocked else "Restaurar"
        if not self._live_confirmation(f"{verb} internet", f"{verb} a internet de {device.get('name') or 'máquina'} ({device['ip']})?\n\nA ação altera o bloqueio legado de máquina. Regras independentes de IP ou MAC permanecem; consulte Mapa e relatórios."):
            return
        transport = self.transport
        self._run_job(lambda: transport.request("set_device_block", ip=device["ip"], blocked=blocked),
                      label=f"{verb} internet de {device['ip']}", alert=True)

    def _add_domain(self):
        if not self._mutation_allowed(("dns",)):
            return
        domain = self.domain_input.get().strip()
        category = self.category_input.get().strip() or "Outros"
        if not domain:
            messagebox.showinfo("Informe o domínio", "Exemplo: jogos.exemplo.com", parent=self)
            return
        if not self._live_confirmation("Adicionar bloqueio DNS", f"Bloquear {domain} e seus subdomínios em todo o laboratório?\n\nO serviço DNS/DHCP será reiniciado brevemente. Caches e conexões existentes podem continuar."):
            return
        transport = self.transport
        def done(snapshot):
            self.domain_input.set("")
            self._apply_snapshot(snapshot)
        self._run_job(lambda: transport.request("add_domain", domain=domain, category=category),
                      label="Adicionando domínio", on_success=done, alert=True)

    def _ai_policy(self):
        policies = self.snapshot.get("policies", {})
        policy = policies.get("ai_block") if isinstance(policies, dict) else None
        if not isinstance(policy, dict) or type(policy.get("enabled")) is not bool:
            return None
        return policy

    def _render_ai_policy(self):
        policy = self._ai_policy()
        if policy is None:
            self.ai_state_text.set("Atualize o agente do gateway para usar o perfil de IA.")
            self.ai_state_label.configure(fg=MUTED)
            self.ai_toggle_button.configure(state="disabled", text="Perfil indisponível")
            self.ai_catalog_button.configure(state="disabled")
            return
        enabled = policy["enabled"]
        count = len(policy.get("domains", []))
        services = len(policy.get("services", []))
        self.ai_state_text.set(f"{'Ativo' if enabled else 'Desativado'} | {services} serviços, {count} domínios no perfil")
        self.ai_state_label.configure(fg=GREEN if enabled else MUTED)
        self.ai_toggle_button.configure(state="normal",
            text="Desativar bloqueio de IA" if enabled else "Ativar bloqueio de IA")
        self.ai_catalog_button.configure(state="normal")

    def _toggle_ai_block(self):
        if not self._mutation_allowed(("dns",)):
            return
        if self._busy:
            self.status.set("Aguarde a operação em andamento antes de alterar o perfil de IA.")
            return
        policy = self._ai_policy()
        if policy is None:
            self.status.set("Atualize o agente do gateway para usar o perfil de IA.")
            return
        enabled = not policy["enabled"]
        verb = "Ativar" if enabled else "Desativar"
        count = len(policy.get("domains", []))
        message = (f"{verb} o perfil de bloqueio de IA em todo o laboratório?\n\n"
            f"O perfil contém {count} domínios dos serviços listados em 'Ver serviços incluídos'. "
            "Ele não identifica automaticamente toda IA da internet. Regras manuais permanecem cadastradas.\n\n"
            "O serviço DNS/DHCP será reiniciado uma vez. Caches e conexões existentes podem continuar.")
        if not self._live_confirmation(f"{verb} bloqueio de IA", message):
            return
        transport = self.transport
        self._run_job(lambda: transport.request("set_ai_block", enabled=enabled),
                      label=f"{verb} perfil de IA", alert=True)

    def _show_ai_catalog(self):
        policy = self._ai_policy()
        if policy is None:
            return
        dialog = tk.Toplevel(self)
        dialog.title("LabGuard | Serviços de IA incluídos")
        dialog.geometry("710x510")
        dialog.minsize(480, 330)
        dialog.configure(bg=BG)
        dialog.transient(self)
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)
        self._responsive_wrap(tk.Label(dialog,
            text="Perfil global de IA: os domínios abaixo e seus subdomínios. Para incluir outros serviços, adicione seus domínios na lista manual.",
            bg=BG, fg=TEXT, wraplength=660, justify="left", anchor="w")).grid(
                row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=16)
        body = tk.Text(dialog, bg=PANEL, fg=TEXT, relief="flat", padx=14, pady=12,
                       wrap="word", font=(self.font_family, 10))
        body.grid(row=1, column=0, sticky="nsew", padx=(18, 0))
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=body.yview)
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 18))
        body.configure(yscrollcommand=scrollbar.set)
        for service in policy.get("services", []):
            body.insert("end", f"{service.get('name', 'Serviço')}\n")
            for domain in service.get("domains", []):
                body.insert("end", f"  {domain}\n")
            body.insert("end", "\n")
        body.configure(state="disabled")
        ActionButton(dialog, text="Fechar", command=dialog.destroy).grid(
            row=2, column=0, columnspan=2, sticky="e", padx=18, pady=14)

    def _remove_domain(self):
        if not self._mutation_allowed(("dns",)):
            return
        selection = self.domains_table.selection()
        if not selection:
            messagebox.showinfo("Selecione um domínio", "Selecione o domínio que deseja remover da lista.", parent=self)
            return
        domain = selection[0]
        row = next((d for d in self.snapshot.get("domains", []) if d.get("domain") == domain), {})
        if row.get("source") == "ai_profile":
            messagebox.showinfo("Domínio do perfil de IA",
                "Este domínio pertence ao perfil de IA. Desative o perfil para retirar suas regras. "
                "Você pode adicionar os domínios que deseja manter na lista manual.", parent=self)
            return
        policy = self._ai_policy()
        overlap = bool(policy and policy["enabled"] and domain in policy.get("domains", []))
        note = "\n\nEste domínio continuará bloqueado pelo perfil de IA ativo." if overlap else ""
        if not self._live_confirmation("Remover bloqueio DNS", f"Remover a regra manual de {domain}?{note}\n\nO serviço DNS/DHCP será reiniciado brevemente."):
            return
        transport = self.transport
        self._run_job(lambda: transport.request("remove_domain", domain=domain), label="Removendo domínio", alert=True)

    def _import_domains(self):
        if not self._mutation_allowed(("dns",)):
            return
        if self._busy:
            self.status.set("Aguarde a operação atual antes de importar.")
            return
        path = filedialog.askopenfilename(parent=self, title="Lista de domínios - um por linha",
                                          filetypes=[("Texto", "*.txt"), ("Todos", "*.*")])
        if not path:
            return
        try:
            if Path(path).stat().st_size > 128 * 1024:
                raise ValueError("A lista deve ter até 128 KB e 100 domínios por importação.")
            lines = [line.strip() for line in Path(path).read_text(encoding="utf-8-sig").splitlines()
                     if line.strip() and not line.lstrip().startswith("#")]
            domains = list(dict.fromkeys(lines))
            if not domains or len(domains) > 100:
                raise ValueError("Importe entre 1 e 100 domínios por vez, um domínio por linha.")
        except (OSError, UnicodeError, ValueError) as exc:
            messagebox.showerror("Lista inválida", str(exc), parent=self)
            return
        if not self._live_confirmation("Importar bloqueios", f"Adicionar {len(domains)} domínios em todo o laboratório?\n\nCada domínio será aplicado separadamente, com reinício breve do DNS/DHCP. Se houver falha, os anteriores continuam adicionados."):
            return
        transport = self.transport
        category = self.category_input.get().strip() or "Outros"
        def import_list():
            snapshot = None
            completed = 0
            for domain in domains:
                try:
                    snapshot = transport.request("add_domain", domain=domain, category=category)
                    completed += 1
                except Exception as exc:
                    raise TransportError(f"Importação interrompida em {domain}: {exc}. {completed} item(ns) anterior(es) já aplicado(s); atualize o painel.") from exc
            return snapshot
        self._run_job(import_list, label=f"Importando {len(domains)} domínios", alert=True)

    def _export_dns(self):
        events = list(self._shown_events)
        if not events:
            messagebox.showinfo("Sem registros", "Não há registros no filtro atual para exportar.", parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, title="Exportar amostra DNS",
            initialfile="LabGuard_consultas_DNS.csv", defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as output:
                writer = csv.writer(output, delimiter=";")
                writer.writerow(["Modo", "Horário", "IP solicitante", "Domínio", "Tipo", "Resultado observado"])
                for event in events:
                    writer.writerow([csv_safe(v) for v in [self.snapshot.get("mode", ""),
                        event.get("time", ""), event.get("client_ip", ""), event.get("domain", ""),
                        event.get("query_type", ""), event.get("status", "")]])
            self.status.set(f"Exportados {len(events)} registros para {path}")
        except OSError as exc:
            messagebox.showerror("Não foi possível exportar", str(exc), parent=self)

    def close(self):
        self._closed = True
        self._generation += 1
        close_transport = getattr(self.transport, "close", None)
        if callable(close_transport):
            close_transport()
        for window in self.winfo_children():
            close_window = getattr(window, "close", None)
            if isinstance(window, tk.Toplevel) and callable(close_window):
                close_window()
        self._executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def main():
    App().mainloop()

