"""Gerenciamento local da política de sites; aplicação explícita no gateway."""
from __future__ import annotations

from pathlib import Path
from threading import Event
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .banlist import BanlistDatabase, BanlistError, CATEGORIES
from .ui import ActionButton, BG, TEXT, MUTED, PURPLE


class BanlistWindow(tk.Toplevel):
    def __init__(self, parent, transport, db_path, can_sync_callback=None):
        super().__init__(parent)
        self.transient(parent)
        self.owner, self.transport = parent, transport
        self.can_sync_callback = can_sync_callback or (lambda: True)
        try:
            self.db = BanlistDatabase(db_path)
        except Exception:
            self.destroy()
            raise
        self._closed, self._syncing = False, False
        self._cancel_sync = Event()
        self._selected = None
        self._rows = {}
        self.title("LabGuard | Banco de sites banidos")
        self.geometry("1080x760")
        self.minsize(920, 650)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        header = tk.Frame(self, bg=BG)
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 12))
        tk.Label(header, text="Banco de sites banidos", bg=BG, fg=TEXT,
                 font=(parent.font_family, 22, "bold")).pack(anchor="w")
        tk.Label(header, text="Organize a lista e aplique as mudanças quando estiver pronta.",
                 bg=BG, fg=MUTED).pack(anchor="w", pady=(5, 0))
        self.stats = tk.StringVar()
        tk.Label(self, textvariable=self.stats, bg="#EDE6FC", fg=PURPLE,
                 padx=14, pady=11, anchor="w").grid(row=1, column=0, sticky="ew", padx=24)
        filters = ttk.Frame(self)
        filters.grid(row=2, column=0, sticky="ew", padx=24, pady=12)
        self.search = tk.StringVar()
        self.filter_category = tk.StringVar(value="Todas")
        self.filter_state = tk.StringVar(value="Todos")
        ttk.Entry(filters, textvariable=self.search, width=28).pack(side="left", padx=(0, 8))
        ttk.Combobox(filters, textvariable=self.filter_category, values=("Todas",) + CATEGORIES,
                     state="readonly", width=23).pack(side="left", padx=(0, 8))
        ttk.Combobox(filters, textvariable=self.filter_state, values=("Todos", "Ativos", "Inativos"),
                     state="readonly", width=10).pack(side="left", padx=(0, 8))
        ActionButton(filters, text="Buscar", command=self.refresh).pack(side="left")
        self.book = ttk.Notebook(self)
        self.book.grid(row=3, column=0, sticky="nsew", padx=24)
        listing, history = ttk.Frame(self.book), ttk.Frame(self.book)
        self.book.add(listing, text="Sites cadastrados")
        self.book.add(history, text="Histórico do banco")
        self.table = self._table(listing, ("domain", "category", "enabled", "notes"),
                                 ("Domínio e subdomínios", "Categoria", "Ativo", "Observação"))
        self.table.bind("<<TreeviewSelect>>", self._select)
        self.audit_table = self._table(history, ("time", "action", "domain", "outcome"),
                                      ("Data UTC", "Ação", "Domínio", "Resultado"))
        form = ttk.Frame(self)
        form.grid(row=4, column=0, sticky="ew", padx=24, pady=(12, 0))
        form.columnconfigure(0, weight=2)
        form.columnconfigure(1, weight=1)
        form.columnconfigure(2, weight=3)
        self.domain, self.category, self.notes = tk.StringVar(), tk.StringVar(value="Jogos"), tk.StringVar()
        self.enabled = tk.BooleanVar(value=True)
        for col, label in enumerate(("Domínio, sem https://", "Categoria", "Observação")):
            ttk.Label(form, text=label).grid(row=0, column=col, sticky="w", padx=(0, 8))
        self.domain_entry = ttk.Entry(form, textvariable=self.domain)
        self.domain_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        ttk.Combobox(form, textvariable=self.category, values=CATEGORIES, state="readonly").grid(
            row=1, column=1, sticky="ew", padx=(0, 8))
        ttk.Entry(form, textvariable=self.notes).grid(row=1, column=2, sticky="ew")
        ttk.Checkbutton(form, text="Bloqueio ativo", variable=self.enabled).grid(row=2, column=0, sticky="w", pady=8)
        controls = ttk.Frame(self)
        controls.grid(row=5, column=0, sticky="ew", padx=24, pady=(0, 8))
        self.buttons = []
        for text, command, style in (("Novo", self._new, "TButton"), ("Salvar", self._save, "Purple.TButton"),
                                     ("Excluir", self._delete, "Danger.TButton"),
                                     ("Importar TXT", self._import, "TButton"), ("Exportar CSV", self._export, "TButton")):
            button = ActionButton(controls, text=text, command=command, style=style)
            button.pack(side="left", padx=(0, 6))
            self.buttons.append(button)
        self.apply_button = ActionButton(controls, text="Aplicar ao gateway", style="Yellow.TButton", command=self._sync)
        self.apply_button.pack(side="right")
        self.buttons.append(self.apply_button)
        self.status = tk.StringVar(value="Salvar e excluir alteram o banco. A rede muda somente ao aplicar a lista.")
        tk.Label(self, textvariable=self.status, bg=BG, fg=MUTED, anchor="w", justify="left",
                 wraplength=990).grid(row=6, column=0, sticky="ew", padx=24, pady=(0, 18))
        self.refresh()

    @staticmethod
    def _table(parent, columns, headings):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse", height=6)
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
            tree.column(column, width=190 if column != "enabled" else 65, minwidth=65)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(parent, command=tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        return tree

    def refresh(self):
        if self._closed or self._syncing:
            return
        try:
            state = {"Todos": None, "Ativos": True, "Inativos": False}[self.filter_state.get()]
            category = "" if self.filter_category.get() == "Todas" else self.filter_category.get()
            rows = self.db.list_sites(query=self.search.get(), category=category, enabled=state)
            self._rows = {row["domain"]: row for row in rows}
            self.table.delete(*self.table.get_children())
            for row in rows:
                self.table.insert("", "end", iid=row["domain"], values=(row["domain"], row["category"],
                    "Sim" if row["enabled"] else "Não", row["notes"]))
            summary = self.db.summary()
            self.stats.set(f'{summary["total"]} cadastrados     •     {summary["enabled"]} ativos     •     '
                           f'{summary["pending"]} pendentes     •     {summary["owned_rules"]} regras próprias aplicadas'
                           + ("     |     DEMONSTRAÇÃO: nenhuma alteração real" if self.owner.snapshot.get("mode") == "demo" else ""))
            self.audit_table.delete(*self.audit_table.get_children())
            for index, row in enumerate(self.db.audit()):
                self.audit_table.insert("", "end", iid=str(index), values=(row.get("time", row.get("created_at", "")),
                    row.get("action", ""), row.get("domain", ""), row.get("outcome", "")))
        except (BanlistError, OSError) as error:
            messagebox.showerror("Banco de sites", str(error), parent=self)

    def _select(self, _event=None):
        if self._syncing:
            return
        selection = self.table.selection()
        row = self._rows.get(selection[0]) if selection else None
        if row:
            self._selected = row
            self.domain.set(row["domain"])
            self.domain_entry.configure(state="readonly")
            self.category.set(row["category"])
            self.notes.set(row["notes"])
            self.enabled.set(row["enabled"])

    def _new(self):
        self._selected = None
        self.table.selection_remove(*self.table.selection())
        self.domain_entry.configure(state="normal")
        self.domain.set("")
        self.notes.set("")
        self.enabled.set(True)
        self.domain_entry.focus_set()

    def _save(self):
        if self._syncing:
            return
        try:
            self.db.upsert(self.domain.get(), self.category.get(), self.enabled.get(), self.notes.get(),
                           expected_revision=self._selected["revision"] if self._selected else 0)
            self._new()
            self.refresh()
            self.status.set("Cadastro salvo. Use Aplicar ao gateway para atualizar os bloqueios.")
        except BanlistError as error:
            messagebox.showerror("Cadastro inválido", str(error), parent=self)

    def _delete(self):
        if self._syncing or not self._selected:
            return
        row = self._selected
        if not messagebox.askyesno("Excluir cadastro", f'Excluir {row["domain"]} do banco?\nA regra própria será removida da rede na próxima aplicação.', parent=self, default="no"):
            return
        try:
            self.db.delete(row["domain"], expected_revision=row["revision"])
            self._new()
            self.refresh()
        except BanlistError as error:
            messagebox.showerror("Banco de sites", str(error), parent=self)

    def _import(self):
        if self._syncing:
            return
        name = filedialog.askopenfilename(parent=self, title="Um domínio por linha", filetypes=[("Lista TXT", "*.txt")])
        if not name:
            return
        try:
            with Path(name).open("rb") as source:
                data = source.read(128 * 1024 + 1)
            if len(data) > 128 * 1024:
                raise BanlistError("A lista deve ter até 128 KB e 1.000 domínios.")
            domains = [line.strip() for line in data.decode("utf-8-sig").splitlines()
                       if line.strip() and not line.lstrip().startswith("#")]
            result = self.db.import_domains(domains, self.category.get())
            self.refresh()
            self.status.set(f'Importação: {len(result["added"])} novos; {len(result["existing"])} existentes; {len(result["errors"])} inválidos. Aplique ao gateway para alterar a rede.')
        except (BanlistError, OSError, UnicodeError) as error:
            messagebox.showerror("Importação", str(error), parent=self)

    def _export(self):
        if self._syncing:
            return
        name = filedialog.asksaveasfilename(parent=self, defaultextension=".csv", initialfile="sites-banidos.csv", filetypes=[("CSV", "*.csv")])
        if name:
            try:
                Path(name).write_text(self.db.export_csv(), encoding="utf-8-sig", newline="")
                self.status.set("Lista completa exportada em CSV.")
            except (BanlistError, OSError) as error:
                messagebox.showerror("Exportação", str(error), parent=self)

    def _sync(self):
        if self._syncing or not self.can_sync_callback():
            self.status.set("Atualize a conexão com o gateway original antes de aplicar a lista.")
            return
        if not messagebox.askyesno("Aplicar banco de sites", "Aplicar até 20 alterações de bloqueio ao gateway atual?\nRegras manuais e regras de IA existentes serão preservadas.\nSe houver mais mudanças, aplique um novo lote após revisar o resultado.", parent=self, default="no"):
            return
        if self._closed or not self.can_sync_callback():
            self.status.set("A conexão mudou ou expirou durante a confirmação. Atualize o gateway antes de aplicar.")
            return
        self._cancel_sync.clear()
        self._syncing = True
        for button in self.buttons:
            button.configure(state="disabled")
        self.status.set("Aplicando lista. Aguarde o resultado antes de repetir a operação…")

        def finished(report):
            if report.get("snapshot"):
                self.owner._apply_snapshot(report["snapshot"])
            elif report.get("errors"):
                self.owner._snapshot_stale = True
                self.owner._refresh_mutation_controls()
            if self._closed:
                return
            self._syncing = False
            for button in self.buttons:
                button.configure(state="normal")
            self.refresh()
            self.status.set(f'{len(report["applied"])} alterações confirmadas; {report["pending"]} pendentes; {len(report["errors"])} resultados sem confirmação.'
                            + (" Atualize e revise o gateway antes de repetir." if report["errors"] else ""))

        # Use the parent's serialized network worker: its refresh/connect/mutation
        # controls remain paused throughout the complete batch.
        def work():
            try:
                return self.db.sync(self.transport, limit=20, cancel_event=self._cancel_sync)
            except Exception as error:
                try:
                    pending = self.db.summary()["pending"]
                except Exception:
                    pending = "não confirmado"
                return {"snapshot": None, "applied": [], "pending": pending,
                        "errors": [{"message": str(error)}], "failure": str(error)}

        original = finished
        def report_finished(report):
            original(report)
            if report.get("failure") and not self._closed:
                self.status.set(report["failure"])
        if not self.owner._run_job(work, label="Aplicando banco de sites", on_success=report_finished):
            self._syncing = False
            for button in self.buttons:
                button.configure(state="normal")

    def close(self):
        self._cancel_sync.set()
        self._closed = True
        self.db.close()
        self.destroy()
