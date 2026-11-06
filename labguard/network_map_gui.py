"""Mapa lógico do inventário já observado; nenhuma descoberta de rede é executada."""
from __future__ import annotations

import ipaddress
import json
import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .controller import snapshot_capabilities
from .ui import (ActionButton, RoundCard, BG, PANEL, CARD, TEXT, MUTED,
                 PURPLE, BLUE, AMBER, GREEN, RED, BORDER, rounded)

MAP_LIMIT = 200
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z", re.I)


def observed_devices(snapshot, query=""):
    """Filtra o inventário sem confundir concessão DHCP com presença confirmada."""
    query = str(query).strip().casefold()
    devices = [dict(d) for d in snapshot.get("devices", []) if isinstance(d, dict)]
    # Persisted rules remain removable even after a DHCP lease disappears.
    for rule in snapshot.get("address_blocks", []):
        if not isinstance(rule, dict) or rule.get("kind") not in ("ip", "mac"):
            continue
        kind, address = rule["kind"], str(rule.get("address", ""))
        if address and not any(str(d.get(kind, "")).lower() == address.lower() for d in devices):
            devices.append({kind: address, "name": "Regra salva", "observed": False,
                            "blocked": True, "state": "Sem observação recente"})
    return [d for d in devices if not query or query in " ".join(str(d.get(k, ""))
            for k in ("name", "hostname", "ip", "mac", "state")).casefold()]


def valid_address(kind, value):
    if kind == "mac":
        return bool(MAC_RE.fullmatch(str(value)))
    if kind == "ip":
        try:
            return ipaddress.ip_address(str(value)).version == 4
        except ValueError:
            return False
    return False


def address_is_blocked(snapshot, device, kind):
    address = str(device.get(kind, "")).lower()
    if "address_blocks" in snapshot:
        return any(isinstance(row, dict) and row.get("kind") == kind
                   and str(row.get("address", "")).lower() == address
                   for row in snapshot.get("address_blocks", []))
    scopes = device.get("blocked_by", [])
    if isinstance(scopes, dict):
        return bool(scopes.get(kind))
    return isinstance(scopes, (list, tuple)) and kind in scopes


def block_description(snapshot, device):
    if snapshot.get("mode") == "observation":
        return "Bloqueio não verificado"
    scopes = [kind.upper() for kind in ("ip", "mac") if address_is_blocked(snapshot, device, kind)]
    if scopes:
        return "Bloqueio: " + " + ".join(scopes)
    if device.get("blocked"):
        return "Bloqueio registrado; origem não informada"
    if snapshot.get("mode") == "observation":
        return "Bloqueio não verificado"
    if snapshot.get("mode") == "equipment":
        return "Sem bloqueio informado pela fonte"
    return "Sem bloqueio por endereço"


class NetworkMapWindow(tk.Toplevel):
    def __init__(self, parent, snapshot_callback=None, action_callback=None):
        super().__init__(parent)
        self.parent = parent
        self.snapshot_callback = snapshot_callback or (lambda: getattr(parent, "snapshot", {}))
        self.action_callback = action_callback
        self.snapshot = {}
        self._selected_key = None
        self._devices_by_key = {}
        self._signature = None
        self._after_id = None
        self._closed = False
        self._source_error = False
        self.title("LabGuard · Mapa da rede")
        self.configure(bg=BG)
        self.geometry("1280x900")
        self.minsize(1000, 740)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.search = tk.StringVar()
        self.banner = tk.StringVar(value="Aguardando o inventário do painel…")
        self.summary = tk.StringVar()
        self.status = tk.StringVar(value="Selecione uma máquina no mapa ou na tabela.")
        self._build()
        self.search.trace_add("write", lambda *_: self.refresh(force=True))
        self._tick()

    def _label(self, parent, text=None, **kwargs):
        options = {"bg": parent.cget("bg"), "fg": TEXT, "anchor": "w", "font": ("Arial", 10)}
        options.update(kwargs)
        return tk.Label(parent, text=text, **options)

    def _build(self):
        outer = tk.Frame(self, bg=BG, padx=22, pady=18)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text="Mapa da rede", bg=BG, fg=TEXT,
                 font=("Arial", 24, "bold"), anchor="w").pack(fill="x")
        self.source_subtitle = tk.Label(outer, text="Inventário observado · relações lógicas · controle conforme a fonte",
                                        bg=BG, fg=MUTED, font=("Arial", 11), anchor="w")
        self.source_subtitle.pack(fill="x", pady=(4, 12))
        self.mode_label = tk.Label(outer, textvariable=self.banner, bg="#FFF5CF", fg="#705514",
                                   font=("Arial", 10, "bold"), anchor="w", padx=14, pady=10)
        self.mode_label.pack(fill="x")
        self.summary_label = tk.Label(outer, textvariable=self.summary, bg=BG, fg=MUTED,
                                      font=("Arial", 10), anchor="w", justify="left", wraplength=1180)
        self.summary_label.pack(fill="x", pady=(10, 9))
        bar = tk.Frame(outer, bg=BG)
        bar.pack(fill="x", pady=(0, 12))
        tk.Label(bar, text="Buscar", bg=BG, fg=TEXT, font=("Arial", 10, "bold")).pack(side="left", padx=(0, 8))
        self.search_entry = ttk.Entry(bar, textvariable=self.search, width=25)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 12), ipady=5)
        for text, fmt, style in (("Salvar mapa SVG", "svg", "Purple.TButton"),
                                 ("Relatório HTML", "html", "TButton"),
                                 ("CSV", "csv", "TButton"), ("PDF", "pdf", "Yellow.TButton")):
            ActionButton(bar, text=text, style=style, height=38,
                         command=lambda f=fmt: self._export(f)).pack(side="left", padx=(0, 6))
        body = tk.Frame(outer, bg=BG)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.book = ttk.Notebook(body)
        self.book.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        map_frame = tk.Frame(self.book, bg=PANEL)
        table_frame = tk.Frame(self.book, bg=PANEL)
        self.book.add(map_frame, text="  Mapa lógico  ")
        self.book.add(table_frame, text="  Inventário completo  ")
        map_frame.rowconfigure(0, weight=1)
        map_frame.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(map_frame, bg=PANEL, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        ybar = ttk.Scrollbar(map_frame, orient="vertical", command=self.canvas.yview)
        ybar.grid(row=0, column=1, sticky="ns")
        xbar = ttk.Scrollbar(map_frame, orient="horizontal", command=self.canvas.xview)
        xbar.grid(row=1, column=0, sticky="ew")
        self.canvas.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.canvas.bind("<Configure>", lambda _: self._draw_map())
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"))
        self.canvas.bind("<Button-4>", lambda _: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind("<Button-5>", lambda _: self.canvas.yview_scroll(1, "units"))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        columns = ("name", "ip", "mac", "evidence", "blocked", "protected")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        for col, label, width in zip(columns, ("Máquina", "IP", "MAC", "Evidência", "Bloqueio", "Protegida"),
                                     (125, 128, 145, 140, 110, 78)):
            self.table.heading(col, text=label)
            self.table.column(col, width=width, minwidth=70, stretch=False)
        self.table.grid(row=0, column=0, sticky="nsew")
        table_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        table_y.grid(row=0, column=1, sticky="ns")
        self.table.configure(yscrollcommand=table_y.set)
        table_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        table_scroll.grid(row=1, column=0, sticky="ew")
        self.table.configure(xscrollcommand=table_scroll.set)
        self.table.bind("<<TreeviewSelect>>", self._table_selection)
        # Keep all controls reachable on 1024×740 displays without forcing a tall window.
        side_frame = tk.Frame(body, bg=BG, width=300, height=400)
        side_frame.grid(row=0, column=1, sticky="nsew")
        side_frame.grid_propagate(False)
        side_frame.rowconfigure(0, weight=1)
        side_frame.columnconfigure(0, weight=1)
        self.side_canvas = tk.Canvas(side_frame, bg=BG, highlightthickness=0, width=284)
        self.side_canvas.grid(row=0, column=0, sticky="nsew")
        side_scroll = ttk.Scrollbar(side_frame, orient="vertical", command=self.side_canvas.yview)
        side_scroll.grid(row=0, column=1, sticky="ns")
        self.side_canvas.configure(yscrollcommand=side_scroll.set)
        side = RoundCard(self.side_canvas, padding=18, width=284)
        side_id = self.side_canvas.create_window(0, 0, anchor="nw", window=side, width=284)
        self.side_canvas.bind("<Configure>", lambda event: self.side_canvas.itemconfigure(side_id, width=event.width))
        side.bind("<Configure>", lambda _: self.side_canvas.configure(scrollregion=self.side_canvas.bbox("all")), add="+")
        self._label(side.body, "EQUIPAMENTO SELECIONADO", font=("Arial", 9, "bold")).pack(fill="x")
        self.selected_title = tk.Label(side.body, text="Escolha uma máquina", bg=PANEL, fg=TEXT,
                                       font=("Arial", 16, "bold"), wraplength=255, justify="left", anchor="w")
        self.selected_title.pack(fill="x", pady=(12, 8))
        self.details = tk.StringVar(value="Os cartões representam evidências de DHCP e vizinhança. Não confirmam conexão neste instante.")
        tk.Label(side.body, textvariable=self.details, bg=PANEL, fg=MUTED, font=("Arial", 10),
                 wraplength=255, justify="left", anchor="nw").pack(fill="x", pady=(0, 14))
        self.action_buttons = {}
        for kind in ("ip", "mac"):
            row = tk.Frame(side.body, bg=PANEL)
            row.pack(fill="x", pady=(0, 7))
            for blocked, verb, style in ((True, "Bloquear", "Danger.TButton"), (False, "Desbloquear", "TButton")):
                button = ActionButton(row, text=f"{verb} {kind.upper()}", style=style, height=39,
                                      state="disabled", command=lambda k=kind, b=blocked: self._act(k, b))
                button.pack(fill="x", pady=(0, 5))
                self.action_buttons[(kind, blocked)] = button
        tk.Label(side.body, text="IP e MAC têm regras independentes. Liberar um endereço não remove o bloqueio do outro.",
                 bg=PANEL, fg=MUTED, font=("Arial", 9), wraplength=255, justify="left", anchor="w").pack(fill="x", pady=(7, 12))
        tk.Label(side.body, text="LINHAS TRACEJADAS", bg=PANEL, fg=BLUE,
                 font=("Arial", 9, "bold"), anchor="w").pack(fill="x")
        tk.Label(side.body, text="Relações lógicas inferidas na LAN. Portas e cabos físicos não foram descobertos. SSID e AP não informados sem evidência da fonte.",
                 bg=PANEL, fg=MUTED, font=("Arial", 9), wraplength=255, justify="left", anchor="w").pack(fill="x", pady=(5, 0))
        self.status_label = tk.Label(outer, textvariable=self.status, bg=BG, fg=MUTED, font=("Arial", 9),
                                     anchor="w", wraplength=1160, justify="left")
        self.status_label.pack(fill="x", pady=(10, 0))
        outer.bind("<Configure>", lambda event: self._wrap_labels(event.width))

    def _wrap_labels(self, width):
        self.summary_label.configure(wraplength=max(100, width-44))
        self.status_label.configure(wraplength=max(100, width-44))

    def _stale(self):
        return bool(self._source_error or self.snapshot.get("_stale") or self.snapshot.get("stale")
                    or getattr(self.parent, "_snapshot_stale", False))

    def refresh(self, force=False):
        try:
            value = self.snapshot_callback()
            if not isinstance(value, dict):
                raise ValueError("Inventário indisponível")
            self.snapshot = value
            self._source_error = False
        except Exception:
            self._source_error = True
        signature = json.dumps([self.snapshot, self.search.get(), self._stale()], sort_keys=True, default=str)
        if force or signature != self._signature:
            self._signature = signature
            self._render()
        else:
            self._update_selection()

    def _tick(self):
        if not self._closed:
            self.refresh()
            self._after_id = self.after(1000, self._tick)

    def _render(self):
        demo = self.snapshot.get("mode") == "demo"
        mode = self.snapshot.get("mode")
        self.source_subtitle.configure(text="Observação parcial do sistema local · relações lógicas inferidas" if mode == "observation" else
                                       "Inventário do roteador · LAN / Wi-Fi conforme a fonte" if mode == "equipment" else
                                       "Inventário observado · LAN / Wi-Fi pelo gateway · controle por endereço")
        self.banner.set("DEMONSTRAÇÃO · dados fictícios · nenhuma alteração na rede real" if demo else
                        "Observação parcial local · bloqueios indisponíveis" + (" · leitura antiga" if self._stale() else "") if mode == "observation" else
                        "DADOS DESATUALIZADOS · ações suspensas; atualize o painel principal" if self._stale() else
                        "ROTEADOR · inventário informado; controle por endereço indisponível" if mode == "equipment" and not snapshot_capabilities(self.snapshot)["address_blocking"] else
                        "ROTEADOR · inventário informado; presença atual não confirmada" if mode == "equipment" else
                        "GATEWAY · inventário observado; presença atual não confirmada")
        self.mode_label.configure(bg="#FFF5CF" if demo else "#FCE9EF" if self._stale() else "#E7F0FF",
                                  fg="#705514" if demo else RED if self._stale() else BLUE)
        all_devices = observed_devices(self.snapshot)
        devices = observed_devices(self.snapshot, self.search.get())
        self.summary.set(f"{sum(d.get('observed', True) is not False for d in all_devices)} máquinas observadas   ·   {sum(d.get('observed') is False for d in all_devices)} registros sem evidência recente   ·   "
                         f"{len(devices)} no filtro   ·   mapa até {MAP_LIMIT} cartões; inventário exportado até 10.000 registros")
        self._devices_by_key = {f"{d.get('ip', '')}|{d.get('mac', '')}": d for d in devices}
        self.table.delete(*self.table.get_children())
        for key, d in self._devices_by_key.items():
            self.table.insert("", "end", iid=key, values=(d.get("name") or d.get("hostname") or "Sem nome",
                              d.get("ip", "—"), d.get("mac", "—"), d.get("state") or "Observada",
                              block_description(self.snapshot, d), "Sim" if d.get("protected") else "Não"))
        # Preserve selection by stable addresses rather than its former filtered row index.
        if self._selected_key not in self._devices_by_key:
            self._selected_key = None
        self._draw_map()
        self._update_selection()

    def _draw_map(self):
        c = self.canvas
        c.delete("all")
        width = max(720, c.winfo_width())
        gateway = self.snapshot.get("gateway", {})
        center = width / 2
        rounded(c, center-175, 18, center+175, 86, 16, fill=PURPLE, outline="")
        mode = self.snapshot.get("mode")
        source_label = "FONTE LOCAL" if mode == "observation" else "ROTEADOR" if mode == "equipment" else "GATEWAY"
        source_name = gateway.get("hostname") or ("Observação local" if mode == "observation" else "Roteador não informado" if mode == "equipment" else "Gateway não informado")
        c.create_text(center, 39, text=source_label, fill="#D9CCFF", font=("Arial", 9, "bold"))
        c.create_text(center, 64, text=str(source_name)[:42],
                      fill="white", font=("Arial", 12, "bold"))
        c.create_line(center, 86, center, 116, fill=BLUE, width=2, dash=(5, 4))
        rounded(c, center-180, 116, center+180, 171, 14, fill="#E7F0FF", outline="")
        c.create_text(center, 135, text=f"{'SEGMENTO' if mode == 'observation' else 'REDE LAN'}  ·  {gateway.get('lab_cidr') or 'segmento não informado'}",
                      fill=BLUE, font=("Arial", 11, "bold"))
        c.create_text(center, 154, text="Segmento observado · relações inferidas" if mode == "observation" else "LAN / Wi-Fi · relações inferidas", fill=MUTED, font=("Arial", 9))
        devices = list(self._devices_by_key.items())[:MAP_LIMIT]
        columns = 3
        gap, margin = 16, 22
        card_width = (width - margin*2 - gap*(columns-1)) / columns
        for i, (key, d) in enumerate(devices):
            row, col = divmod(i, columns)
            x, y = margin + col*(card_width+gap), 212 + row*160
            cx = x + card_width/2
            c.create_line(center, 171, center, y-18, cx, y-18, cx, y, fill="#BDCCE9", dash=(4, 4), width=1)
        for i, (key, d) in enumerate(devices):
            row, col = divmod(i, columns)
            x, y = margin + col*(card_width+gap), 212 + row*160
            selected = key == self._selected_key
            tag = "device_" + str(i)
            rounded(c, x, y, x+card_width, y+142, 16, fill=CARD if selected else "#EEEEF1" if d.get("observed") is False else "#F8F6FD",
                    outline=PURPLE if selected else BORDER, width=2 if selected else 1, tags=tag)
            name = str(d.get("name") or d.get("hostname") or "Sem nome")
            c.create_text(x+13, y+21, text=name[:24], anchor="w", fill=TEXT, font=("Arial", 11, "bold"), tags=tag)
            c.create_text(x+13, y+46, text=f"IP  {d.get('ip') or '—'}", anchor="w", fill=BLUE, font=("Arial", 10), tags=tag)
            c.create_text(x+13, y+66, text=f"MAC  {d.get('mac') or '—'}", anchor="w", fill=MUTED, font=("Arial", 9), tags=tag)
            status = "PROTEGIDA" if d.get("protected") else block_description(self.snapshot, d)
            c.create_text(x+13, y+92, text=status[:36], anchor="w", fill=PURPLE if d.get("protected") else MUTED if mode == "observation" else RED if d.get("blocked") or "IP" in status or "MAC" in status else GREEN,
                          font=("Arial", 9, "bold"), tags=tag)
            c.create_text(x+13, y+117, text=("Regra salva / sem evidência recente" if d.get("observed") is False else str(d.get("state") or "Observada"))[:37], anchor="w", fill=MUTED, font=("Arial", 9), tags=tag)
            c.tag_bind(tag, "<Button-1>", lambda _, k=key: self._select(k))
            c.tag_bind(tag, "<Enter>", lambda _: c.configure(cursor="hand2"))
            c.tag_bind(tag, "<Leave>", lambda _: c.configure(cursor=""))
        height = 235 + ((len(devices)+2)//3)*160
        if not devices:
            c.create_text(center, 248, text="Nenhuma máquina observada neste filtro.", fill=MUTED, font=("Arial", 12))
        if len(self._devices_by_key) > MAP_LIMIT:
            c.create_text(center, height-12, text="Mapa limitado a 200 cartões. Use a busca ou a tabela para os demais.", fill=MUTED, font=("Arial", 9))
        c.configure(scrollregion=(0, 0, width, max(320, height)))

    def _select(self, key):
        self._selected_key = key if key in self._devices_by_key else None
        if self._selected_key is not None:
            self.table.selection_set(self._selected_key)
            self.table.see(self._selected_key)
        self._draw_map()
        self._update_selection()

    def _table_selection(self, _event=None):
        selection = self.table.selection()
        if selection:
            self._selected_key = selection[0]
            self._draw_map()
            self._update_selection()

    def _selected(self):
        return self._devices_by_key.get(self._selected_key)

    @staticmethod
    def _wireless_details(device):
        parts = []
        connection = device.get("connection_type")
        if connection in ("wifi", "wired"):
            parts.append("Conexão: " + ("Wi-Fi" if connection == "wifi" else "Cabo"))
        for key, label in (("ssid", "SSID"), ("ap", "AP")):
            if device.get(key):
                parts.append(f"{label}: {device[key]}")
        if not parts:
            parts.append("Cabo/Wi-Fi, SSID e AP: não informados")
        return "\n".join(parts) + "\n\n"

    def _allowed(self, device):
        if not snapshot_capabilities(self.snapshot)["address_blocking"]:
            return False
        if not device or device.get("protected") or not callable(self.action_callback):
            return False
        if getattr(self.parent, "_busy", False) or getattr(self.parent, "_session_locked", False):
            return False
        return self.snapshot.get("mode") == "demo" or not self._stale()

    def _update_selection(self):
        d = self._selected()
        if d:
            self.selected_title.configure(text=d.get("name") or d.get("hostname") or "Sem nome")
            self.details.set(f"IP  {d.get('ip') or 'Não informado'}\nMAC  {d.get('mac') or 'Não informado'}\n\n"
                             f"Evidência: {d.get('state') or 'Observada'}\nÚltimo registro: {d.get('last_seen') or 'Não informado'}\n\n"
                             f"{block_description(self.snapshot, d)}\n" + self._wireless_details(d) + ("Equipamento protegido: ações indisponíveis." if d.get("protected") else "Presença atual não confirmada."))
        else:
            self.selected_title.configure(text="Escolha uma máquina")
            self.details.set("Selecione um cartão ou uma linha. O inventário pode conter concessões antigas; o estado exibido é a evidência fornecida pela fonte.")
        for (kind, blocked), button in self.action_buttons.items():
            enabled = self._allowed(d) and valid_address(kind, d.get(kind)) and address_is_blocked(self.snapshot, d, kind) != blocked and (not blocked or d.get("observed") is not False)
            button.configure(state="normal" if enabled else "disabled")

    def _act(self, kind, blocked):
        # Re-read local state immediately; parent also confirms and validates before worker dispatch.
        self.refresh()
        d = self._selected()
        if (not self._allowed(d) or not valid_address(kind, d.get(kind))
                or address_is_blocked(self.snapshot, d, kind) == blocked or (blocked and d.get("observed") is False)):
            self.status.set("Ação indisponível: confira seleção, proteção e atualização do painel.")
            return
        try:
            self.action_callback(kind, d[kind], blocked)
            self.status.set(f"Solicitação encaminhada ao painel: {'bloquear' if blocked else 'desbloquear'} {kind.upper()} {d[kind]}.")
        except Exception as exc:
            messagebox.showerror("Controle por endereço", str(exc), parent=self)
        self.refresh(force=True)

    def _export(self, fmt):
        self.refresh()
        if not self.snapshot:
            self.status.set("Não há inventário disponível para exportar.")
            return
        path = filedialog.asksaveasfilename(parent=self, title="Exportar inventário completo", defaultextension="."+fmt,
                                           initialfile="LabGuard-mapa.svg" if fmt == "svg" else "LabGuard-relatorio."+fmt,
                                           filetypes=[(fmt.upper(), "*."+fmt)])
        if not path:
            return
        try:
            from .reports import export_report, network_map_svg
            source = dict(self.snapshot, _stale=self._stale())
            if fmt == "svg":
                export_report(source, path, "svg")
            else:
                export_report(source, path, fmt)
            limit_note = "Mapa com até 200 nós." if fmt == "svg" else "Inventário com até 10.000 registros; PDF resume até 12 nós no desenho." if fmt == "pdf" else "Inventário com até 10.000 registros."
            self.status.set(f"Exportação salva: {Path(path).name}. {limit_note} A busca não limita a exportação.")
        except Exception as exc:
            messagebox.showerror("Exportar relatório", str(exc), parent=self)

    def close(self):
        self._closed = True
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.destroy()
