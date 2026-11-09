"""Serve the desktop's selected source through the existing local web panel."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser

from .preferences import PreferenceStore, _windows_private
from .server import Application, ASSET_TYPES, LocalHTTPServer, ServerError, asset_directory
from .ui import BG, TEXT, MUTED, PURPLE, ActionButton


class DesktopSource:
    """Closing this view revokes its requests while the desktop retains its transport."""

    def __init__(self, transport, current, writable):
        self.transport = transport
        self.kind = transport.kind
        self.host = transport.host
        self.port = transport.port
        self.current = current
        self.writable = writable
        self.revoked = threading.Event()

    def available(self):
        return not self.revoked.is_set() and self.current()

    def station_source_current(self):
        return self.available() and self.writable() and self.kind == 'local_dns'

    def request(self, action, **params):
        if not self.available():
            raise ServerError('O painel foi encerrado ou a conexão mudou.')
        if action != 'snapshot' and not self.writable():
            raise ServerError('Atualize a fonte e confira a autorização no desktop.')
        return self.transport.request(action, **params)

    def close(self):
        self.revoked.set()


class _DesktopApplication(Application):
    """Also recheck desktop authority for writes to its shared local bank."""

    def edit_banlist(self, operation, payload):
        if not self.transport.available() or not self.transport.writable():
            raise ServerError('O desktop precisa de uma conexão autorizada para esta alteração.')
        return super().edit_banlist(operation, payload)


class _DesktopHTTPServer(LocalHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class DesktopWebSession:
    def __init__(self, transport, snapshot, *, current, writable, authorized, bank_path, directory=None):
        if getattr(transport, 'kind', '') not in {'local_dns', 'observation', 'demo'}:
            raise ServerError('Abra o painel com o filtro DNS local, observação ou demonstração.')
        if not current():
            raise ServerError('A fonte mudou. Atualize a conexão antes de abrir o painel.')
        if any(not (asset_directory() / name).is_file() for name, _ in ASSET_TYPES.values()):
            raise ServerError('Os arquivos do painel web estão ausentes. Atualize a instalação do LabGuard.')
        controller = {'kind': transport.kind, 'manage_rules': authorized is True}
        if transport.kind == 'local_dns':
            service = snapshot.get('dns_service', {})
            if snapshot.get('source_type') != 'local_dns' or service.get('service_running') is not True:
                raise ServerError('Ligue o filtro DNS e aguarde a leitura antes de abrir o painel.')
            controller.update(host=service['listen'], lab_cidr=service['network'], port=service['port'],
                              upstream=service['upstream'])

        bank_path = Path(bank_path)
        root = Path(directory) if directory is not None else Path.home() / '.labguard' / 'desktop-web'
        identity = '|'.join((transport.kind, str(transport.host), str(transport.port), str(bank_path)))
        scope = root / hashlib.sha256(identity.encode()).hexdigest()[:24]
        for folder in (root, scope, scope / 'data', bank_path.parent):
            PreferenceStore(folder)._directory(create=True)

        self.role = 'admin' if authorized is True and transport.kind != 'observation' else 'viewer'
        self.token = secrets.token_urlsafe(32)
        unused_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        token_hashes = dict.fromkeys(('viewer', 'admin'), unused_hash)
        token_hashes[self.role] = hashlib.sha256(self.token.encode('ascii')).hexdigest()
        config = SimpleNamespace(directory=scope, port=0, controller=controller, demo=transport.kind == 'demo',
                                 token_hashes=token_hashes, controller_password='')
        self.source = DesktopSource(transport, current, lambda: self.role == 'admin' and writable())
        self.app = _DesktopApplication(config, self.source, logging_enabled=False, banlist_path=bank_path)
        self.server = None
        try:
            if os.name == 'nt':
                _windows_private(self.app.banlist.path, directory=False)
            self.server = _DesktopHTTPServer(self.app, port=0)
            self.url = f'http://127.0.0.1:{self.server.server_port}/'
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.1},
                                           name='LabGuard-Web', daemon=True)
            self.thread.start()
        except BaseException:
            if self.server is not None:
                self.server.server_close()
            self.app.close()
            raise
        self.closed = threading.Event()
        self.stopped = threading.Event()

    def install_station_ca(self, path):
        if not self.source.station_source_current():
            raise ServerError('Abra o painel com o filtro DNS autorizado antes de instalar a CA.')
        with Path(path).open('rb') as stream:
            data = stream.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError('Escolha um arquivo de certificados de até 256 KiB.')
        text = data.decode('ascii')
        pattern = r'(?:\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+'
        if not re.fullmatch(pattern, text):
            raise ValueError('Escolha um arquivo PEM contendo apenas certificados públicos.')
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=text)
        directory = self.app.config.directory
        descriptor, filename = tempfile.mkstemp(dir=directory, prefix='station-ca-', suffix='.tmp')
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                if os.name == 'nt':
                    _windows_private(Path(filename), directory=False)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(filename, directory / 'station-ca.pem')
        finally:
            Path(filename).unlink(missing_ok=True)

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        self.source.close()
        self.token = ''
        self.app.config.token_hashes = {'viewer': '', 'admin': ''}
        self.app.cancel_sync.set()

        def stop():
            try:
                self.server.shutdown()
                self.server.server_close()
                self.app.close()
            finally:
                self.stopped.set()

        threading.Thread(target=stop, name='LabGuard-Web-Encerramento', daemon=False).start()


class DesktopWebWindow(tk.Toplevel):
    def __init__(self, owner, session):
        super().__init__(owner)
        self.owner = owner
        self.session = session
        self.title('LabGuard | Painel web')
        self.transient(owner)
        self.configure(bg=BG, padx=18, pady=16)
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.columnconfigure(0, weight=1)
        self._label('Painel web local', 16, PURPLE).grid(row=0, column=0, sticky='ew')
        access = 'Administração' if session.role == 'admin' else 'Somente consulta'
        self._label(f'{access} · {session.url}', 11, TEXT).grid(row=1, column=0, sticky='ew', pady=(6,12))
        self._label('Cole a chave na tela de acesso do navegador. A sessão fica disponível enquanto esta janela estiver aberta.', 10, MUTED).grid(row=2, column=0, sticky='ew')
        actions = tk.Frame(self, bg=BG)
        actions.grid(row=3, column=0, sticky='ew', pady=(14,0))
        ActionButton(actions, text='Copiar chave e abrir', command=self.copy_and_open, style='Accent.TButton').pack(side='left')
        ActionButton(actions, text='Abrir navegador', command=self.open_browser).pack(side='left', padx=6)
        ActionButton(actions, text='Encerrar painel', command=self.close).pack(side='left')

        if session.role == 'admin' and session.source.kind == 'local_dns':
            ActionButton(self, text='Selecionar CA do WinRM', command=self.choose_ca, height=34).grid(row=4, column=0, sticky='w', pady=(10,0))

    def choose_ca(self):
        filename = filedialog.askopenfilename(parent=self, title='Selecione a CA usada pelo WinRM da escola',
                                              filetypes=[('Certificados públicos', '*.pem *.crt *.cer'), ('Todos', '*')])
        if not filename:
            return
        try:
            self.session.install_station_ca(filename)
        except (OSError, ValueError, ServerError) as error:
            messagebox.showerror('CA do WinRM', f'Não foi possível instalar a CA. {error}', parent=self)
            return
        messagebox.showinfo('CA do WinRM', 'A CA ficará disponível nas próximas conexões deste perfil.', parent=self)

    def _label(self, text, size, color):
        return tk.Label(self, text=text, fg=color, bg=BG, font=(self.owner.font_family, size),
                        justify='left', anchor='w', wraplength=410)

    def copy_and_open(self):
        if not self.session.source.available():
            self.close()
            return
        self.clipboard_clear()
        self.clipboard_append(self.session.token)
        self.open_browser()

    def open_browser(self):
        try:
            opened = webbrowser.open(self.session.url)
        except Exception:
            opened = False
        if not opened:
            messagebox.showinfo('Painel web', f'Abra {self.session.url} no navegador deste PC.', parent=self)

    def close(self):
        self.session.close()
        self.owner._desktop_web_window = None
        self.destroy()


def open_desktop_web(owner):
    window = owner.__dict__.get('_desktop_web_window')
    if window is not None and window.winfo_exists():
        window.lift()
        return window
    source = owner.transport
    if owner._busy or source is None:
        owner.status.set('Aguarde a leitura da conexão para abrir o painel web.')
        return None
    try:
        session = DesktopWebSession(
            source, owner.snapshot, bank_path=owner._banlist_path(),
            current=lambda: not owner._closed and owner.transport is source,
            authorized=owner._management_authorized is True,
            writable=lambda: owner._management_authorized is True and
                owner._mutation_allowed(('dns',), notify=False, capability='domain_filtering'),
        )
        try:
            window = DesktopWebWindow(owner, session)
        except BaseException:
            session.close()
            raise
        owner._desktop_web_window = window
        return window
    except (OSError, RuntimeError, ValueError) as error:
        messagebox.showerror('Painel web', str(error), parent=owner)
        return None
