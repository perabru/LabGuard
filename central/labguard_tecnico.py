#!/usr/bin/env python3
"""LabGuard Central: instalador Windows e inicialização do painel do técnico."""
from __future__ import annotations

import argparse
import base64
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET

CENTRAL_VERSION = "1.0.0"
TASK = "LabGuardCentral"
FIREWALL = "LabGuardCentral-Clientes-TLS"
MARKER = "instalacao-central.json"
EXE = "LabGuardTecnico.exe"
INSTANCE_FILE = "central-instancia.json"

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))


def windows_helpers():
    from labguard_cliente import (_lc_system, _lc_run, _lc_secure_chain,
                                 _lc_no_links, client_directory, require_client_admin)
    return _lc_system, _lc_run, _lc_secure_chain, _lc_no_links, client_directory, require_client_admin


def installation_directory():
    if os.name != "nt":
        return Path.home() / ".labguard-central"
    return windows_helpers()[4]().parent / "LabGuardCentral"


def require_admin():
    if os.name != "nt":
        raise RuntimeError("A instalação automática usa o Windows 10/11 de 64 bits.")
    windows_helpers()[5]()


def private_directory(path):
    """Cria a pasta com ACL administrativa desde o primeiro instante."""
    from ctypes import wintypes
    class SA(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                    ("inherit", wintypes.BOOL)]
    descriptor = ctypes.c_void_p()
    sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;OW)"
    if not ctypes.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError()
    try:
        attrs = SA(ctypes.sizeof(SA), descriptor, False)
        if not ctypes.windll.kernel32.CreateDirectoryW(str(path), ctypes.byref(attrs)):
            raise ctypes.WinError()
    finally:
        ctypes.windll.kernel32.LocalFree(descriptor)


def read_config(directory):
    from labguard_central import read_config as checked_config
    return checked_config(directory)


def _ps(script):
    system, run, *_ = windows_helpers()
    # Estes scripts administrativos contêm somente a tarefa e a regra locais,
    # nunca a senha do painel ou credenciais dos vínculos.
    wrapped = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try {\n" + script +
               "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
    encoded = base64.b64encode(wrapped.encode("utf-16-le")).decode("ascii")
    result = run([system() / "WindowsPowerShell/v1.0/powershell.exe", "-NoProfile",
                  "-NonInteractive", "-EncodedCommand", encoded], timeout=60, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8-sig", errors="replace").strip()
        detail = " ".join(detail.split())[-1800:] or "sem diagnóstico adicional"
        raise RuntimeError(f"A administração do Windows falhou (código {result.returncode}): {detail}")
    return result


def _ps_literal(text):
    return "'" + str(text).replace("'", "''") + "'"


def _task_details():
    # COM distinguishes a missing task from access or service errors and emits
    # UTF-8 regardless of the language of this Windows installation.
    result = _ps(r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$service=New-Object -ComObject Schedule.Service
$service.Connect()
try { $task=$service.GetFolder('\').GetTask('LabGuardCentral') }
catch {
 $errorObject=$_.Exception
 while ($null -ne $errorObject) {
  if ($errorObject.HResult -eq -2147024894) { 'null'; exit 0 }
  $errorObject=$errorObject.InnerException
 }
 throw
}
@{xml=[string]$task.Xml;state=[int]$task.State} | ConvertTo-Json -Compress
""")
    try:
        data = json.loads(result.stdout.decode("utf-8-sig"))
        if data is not None and (not isinstance(data, dict) or set(data) != {"xml", "state"}
                                or type(data["state"]) is not int or not isinstance(data["xml"], str)):
            raise ValueError()
        return data
    except (ValueError, UnicodeError):
        raise RuntimeError("Não foi possível conferir a tarefa existente do Windows.") from None


def task_snapshot():
    details = _task_details()
    try:
        return None if details is None else ET.fromstring(details["xml"])
    except ET.ParseError:
        raise RuntimeError("Não foi possível conferir a tarefa existente do Windows.") from None


def owned_task(directory):
    tree = task_snapshot()
    if tree is None:
        return False
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    action_container = tree.find("t:Actions", ns)
    actions = tree.findall("t:Actions/t:Exec", ns)
    principal = tree.find("t:Principals/t:Principal/t:UserId", ns)
    if (action_container is None or len(action_container) != 1 or len(actions) != 1
            or tree.findtext("t:RegistrationInfo/t:Author", "", ns) != "LabGuard Central"
            or principal is None or (principal.text or "").upper() not in {"S-1-5-18", "SYSTEM", "NT AUTHORITY\\SYSTEM"}
            or os.path.normcase(actions[0].findtext("t:Command", "", ns)) != os.path.normcase(str(directory / EXE))
            or actions[0].findtext("t:Arguments", "", ns) != "run"
            or os.path.normcase(actions[0].findtext("t:WorkingDirectory", "", ns)) != os.path.normcase(str(directory))):
        raise RuntimeError("Já existe uma tarefa LabGuardCentral que não pertence a esta instalação.")
    return True


def _stop_owned_task(directory):
    # Refuse a foreign task, but an absent task is not proof that an earlier
    # onefile child has stopped. Its protected instance marker still identifies it.
    owned_task(directory)
    # The onefile bootloader and the actual Python server are separate Windows
    # processes. Ending only the scheduled parent can leave its child serving.
    # Ask the exact running instance to close both listeners and exit itself.
    config = read_config(directory)
    deadline = time.monotonic() + 45
    requested = None
    details = None
    instance = None
    while time.monotonic() < deadline:
        details = _task_details()
        inactive = details is None or details["state"] not in {2, 4}
        if inactive and _listeners_closed(config):
            return
        instance = _lifecycle_record(Path(directory) / INSTANCE_FILE)
        if instance is not None and instance != requested:
            _request_instance_stop(directory, instance)
            requested = instance
        time.sleep(.3)
    diagnosis = {"task_state": None if details is None else details["state"],
                 "instance_present": instance is not None,
                 "request_written": requested is not None,
                 "listeners": _listener_states(config)}
    raise RuntimeError("A Central ainda não confirmou o encerramento da tarefa e das duas portas. "
                       "A instalação foi preservada; confira a instância antes de atualizar ou remover a inicialização. "
                       "Diagnóstico: " + json.dumps(diagnosis, ensure_ascii=True, separators=(",", ":")))


def _lifecycle_record(path):
    """Read only a small, regular local record inside the protected directory."""
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 2048):
        raise RuntimeError("O registro da instância da Central não é um arquivo local válido.")
    try:
        if os.name == "nt":
            windows_helpers()[2](path)
        elif stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("Restrinja o registro da instância ao proprietário.")
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None  # Its owner may have completed shutdown between the reads.
    except OSError as error:
        # GetNamedSecurityInfo can report Win32 ERROR_FILE_NOT_FOUND while an
        # owner removes its marker. Never hide permission or other ACL failures.
        if (getattr(error, "winerror", None) == 2 or error.errno == 2) and not path.exists():
            return None
        raise
    except (ValueError, UnicodeError):
        raise RuntimeError("Registro da instância inválido.") from None
    if (not isinstance(data, dict) or set(data) != {"instance", "pid"}
            or not isinstance(data["instance"], str) or not re.fullmatch(r"[a-f0-9]{32}", data["instance"])
            or type(data["pid"]) is not int or data["pid"] <= 0):
        raise RuntimeError("Registro da instância inválido.")
    return data


def _write_lifecycle_record(path, record):
    from labguard_cliente import _atomic_json
    # Refuse links, malformed records and permissive existing files before replace.
    _lifecycle_record(path)
    _atomic_json(Path(path), record)


def _stop_request_path(directory, instance):
    nonce = instance.get("instance") if isinstance(instance, dict) else None
    if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise RuntimeError("Identificação de instância inválida.")
    return Path(directory) / ("parar-central-" + nonce + ".json")


def _request_instance_stop(directory, instance):
    # A delayed request for A has a different filename from a request for B.
    # It therefore cannot overwrite a new instance's stop request after a restart.
    _write_lifecycle_record(_stop_request_path(directory, instance), instance)


def _instance_stop_requested(directory, instance):
    return _lifecycle_record(_stop_request_path(directory, instance)) == instance


def _remove_instance_records(directory, instance):
    for path in (Path(directory) / INSTANCE_FILE, _stop_request_path(directory, instance)):
        if _lifecycle_record(path) == instance:
            path.unlink(missing_ok=True)


def _listener_states(config):
    states = {}
    for name, address, port in (("panel", "127.0.0.1", config["panel_port"]),
                                ("agents", config["server_host"], config["agent_port"])):
        started = time.monotonic()
        try:
            # Windows retries a refused local SYN before reporting ECONNREFUSED
            # (about two seconds). Short repeated probes only observe a timeout.
            # CPython issue85480 documents the operating-system behavior.
            with socket.create_connection((address, port), timeout=3):
                result = {"state": "open"}
        except OSError as error:
            result = {"state": "closed" if isinstance(error, ConnectionRefusedError) else "unknown",
                      "error": type(error).__name__, "errno": error.errno,
                      "winerror": getattr(error, "winerror", None)}
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        states[name] = result
    return states


def _listeners_closed(config):
    # A failed HTTP response is insufficient evidence: both TCP listeners must
    # explicitly refuse connections. A timeout is still an uncertain result.
    return all(result["state"] == "closed" for result in _listener_states(config).values())


def _firewall_owned_script(directory):
    return (f"$rule=Get-NetFirewallRule -Name '{FIREWALL}' -ErrorAction SilentlyContinue; "
            "if($null -ne $rule){ "
            "$application=$rule | Get-NetFirewallApplicationFilter; "
            f"if($rule.Description -ne 'LabGuardCentral/1' -or $application.Program -ine {_ps_literal(directory / EXE)})"
            "{ throw ('A regra de firewall existente pertence a outra configuração; confira sua origem. ' + "
            "'Descrição=' + [string]$rule.Description + '; Programa=' + [string]$application.Program) }; "
            "$rule | Remove-NetFirewallRule }; ")


def _task_xml(directory):
    ns = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    ET.register_namespace("", ns)
    def child(parent, name, text=None, **attrs):
        value = ET.SubElement(parent, "{" + ns + "}" + name, attrs)
        value.text = text
        return value
    root = ET.Element("{" + ns + "}Task", version="1.4")
    info = child(root, "RegistrationInfo")
    child(info, "Author", "LabGuard Central")
    child(info, "Description", "Central de regras do laboratório, administrada pela equipe de TI.")
    trigger = child(child(root, "Triggers"), "BootTrigger")
    child(trigger, "Enabled", "true")
    child(trigger, "Delay", "PT15S")
    principal = child(child(root, "Principals"), "Principal", id="System")
    child(principal, "UserId", "S-1-5-18")
    child(principal, "RunLevel", "HighestAvailable")
    settings = child(root, "Settings")
    for name, value in (("MultipleInstancesPolicy", "IgnoreNew"),
                        ("DisallowStartIfOnBatteries", "false"), ("StopIfGoingOnBatteries", "false"),
                        ("StartWhenAvailable", "true"), ("Enabled", "true"),
                        ("Hidden", "false"), ("ExecutionTimeLimit", "PT0S")):
        child(settings, name, value)
    restart = child(settings, "RestartOnFailure")
    child(restart, "Interval", "PT1M")
    child(restart, "Count", "3")
    action = child(child(root, "Actions", Context="System"), "Exec")
    child(action, "Command", str(directory / EXE))
    child(action, "Arguments", "run")
    child(action, "WorkingDirectory", str(directory))
    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def _marker(directory):
    path = directory / MARKER
    if not path.is_file():
        raise RuntimeError("Esta pasta não contém uma instalação identificada da central.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("application") != TASK:
        raise RuntimeError("A pasta pertence a outro aplicativo.")
    return data


def install(password=None, server_host=None, allowed_cidr=None):
    require_admin()
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Use LabGuardTecnico.exe para instalar no Windows. O fonte pode executar init/run para desenvolvimento.")
    from labguard_central import initialize
    directory = installation_directory()
    system, run, secure, no_links, *_ = windows_helpers()
    secure(directory.parent)
    existed = directory.exists()
    if existed:
        secure(directory)
        _marker(directory)
    else:
        private_directory(directory)
        (directory / MARKER).write_text(json.dumps({"application": TASK, "version": CENTRAL_VERSION}), encoding="utf-8")
    task_exists = owned_task(directory)
    if (directory / "config.json").exists():
        _stop_owned_task(directory)
    elif task_exists:
        raise RuntimeError("Existe uma tarefa da Central sem configuração. Confira a instalação antes de repará-la.")
    if not (directory / "config.json").exists():
        if not password or not server_host or not allowed_cidr:
            raise RuntimeError("Defina a senha, o IP do técnico e a rede do laboratório.")
        initialize(directory, password, server_host, allowed_cidr)
    config = read_config(directory)
    source, target = Path(sys.executable).resolve(), directory / EXE
    if source != target.resolve():
        if target.exists():
            no_links(target)
        staged = directory / "central-novo.exe"
        if staged.exists():
            no_links(staged)
            staged.unlink()
        with source.open("rb") as incoming, staged.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        for attempt in range(40):
            try:
                os.replace(staged, target)
                break
            except PermissionError:
                if attempt == 39:
                    raise RuntimeError("Feche a outra janela da central antes de atualizar.") from None
                time.sleep(.25)
    secure(target)
    task_file = directory / "inicializacao.xml"
    task_file.write_bytes(_task_xml(directory))
    run([system() / "schtasks.exe", "/Create", "/TN", TASK, "/XML", task_file, "/F"])
    address = str(ipaddress.IPv4Address(config["server_host"]))
    cidr = str(ipaddress.IPv4Network(config["allowed_cidr"]))
    port = int(config["agent_port"])
    # Only this application's rule is managed; no global firewall changes.
    _ps("$ErrorActionPreference='Stop'; " + _firewall_owned_script(directory) +
        f"New-NetFirewallRule -Name '{FIREWALL}' -DisplayName 'LabGuard Central - clientes TLS' "
        "-Group 'LabGuard Central' -Description 'LabGuardCentral/1' "
        f"-Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} "
        f"-LocalAddress '{address}' -RemoteAddress '{cidr}' -Profile Any -Program {_ps_literal(target)} | Out-Null")
    start()
    return {"ok": True, "version": CENTRAL_VERSION, "panel_url": panel_url(directory)}


def start():
    require_admin()
    directory = installation_directory()
    windows_helpers()[2](directory)
    _marker(directory)
    if not owned_task(directory):
        raise RuntimeError("Clique em Instalar / reparar para registrar a inicialização.")
    system, run, *_ = windows_helpers()
    run([system() / "schtasks.exe", "/Run", "/TN", TASK])


def stop(*, unregister=False):
    require_admin()
    directory = installation_directory()
    windows_helpers()[2](directory)
    _marker(directory)
    system, run, *_ = windows_helpers()
    _stop_owned_task(directory)
    if unregister and owned_task(directory):
        run([system() / "schtasks.exe", "/Delete", "/TN", TASK, "/F"])
    if unregister:
        _ps("$ErrorActionPreference='Stop'; " + _firewall_owned_script(directory))


def panel_url(directory):
    port = int(read_config(directory).get("panel_port", 8787))
    return f"http://127.0.0.1:{port}/"


def is_ready(directory):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(panel_url(directory) + "healthz", timeout=1) as response:
            result = json.load(response)
        return result.get("ok") is True and result.get("app") == TASK
    except (OSError, ValueError):
        return False


def run_servers(directory):
    from labguard_central import build_servers
    if os.name == "nt":
        require_admin()
        windows_helpers()[2](Path(directory))
    panel, agents = build_servers(directory)
    instance = {"instance": secrets.token_hex(16), "pid": os.getpid()}
    stopping = threading.Event()
    threads = [threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .3}, daemon=True)
               for server in (panel, agents)]
    def request_stop(*_):
        stopping.set()
    started = []
    try:
        # Publication happens only after acquiring BOTH bound sockets. Old stop
        # requests remain harmless because each process has a fresh nonce.
        _write_lifecycle_record(Path(directory) / INSTANCE_FILE, instance)
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, request_stop)
        for server, thread in zip((panel, agents), threads):
            thread.start()
            started.append((server, thread))
        while not stopping.wait(.5):
            if _instance_stop_requested(directory, instance):
                stopping.set()
                break
            if not all(thread.is_alive() for thread in threads):
                raise RuntimeError("Um dos serviços da central encerrou inesperadamente.")
    finally:
        try:
            for server, thread in started:
                server.shutdown()
            # Keep both sockets bound while removing our marker. Because another
            # process can publish only after both binds, it cannot replace the
            # marker during our compare/unlink. Never remove another nonce.
            _remove_instance_records(directory, instance)
        finally:
            for server in (panel, agents):
                server.server_close()
            for _server, thread in started:
                thread.join(timeout=5)
    return 0


def local_addresses():
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
        return sorted(a for a in addresses if ipaddress.ip_address(a).is_private
                      and not ipaddress.ip_address(a).is_loopback
                      and not ipaddress.ip_address(a).is_link_local)
    except OSError:
        return []


def show_ui():
    require_admin()
    import tkinter as tk
    from tkinter import ttk, messagebox
    from concurrent.futures import ThreadPoolExecutor
    root = tk.Tk()
    root.title("LabGuard Central | Técnico do laboratório")
    root.geometry("660x590")
    root.minsize(620, 560)
    root.configure(bg="#f6f5fb")
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", font=("Segoe UI", 11), padding=(12, 9))
    style.configure("TEntry", font=("Segoe UI", 11), padding=8)
    header = tk.Frame(root, bg="#50318d", padx=24, pady=20)
    header.pack(fill="x")
    tk.Label(header, text="LabGuard Central", bg="#50318d", fg="white", font=("Segoe UI", 23, "bold")).pack(anchor="w")
    tk.Label(header, text="Controle os sites de todos os computadores vinculados.", bg="#50318d", fg="#eee7ff", font=("Segoe UI", 11)).pack(anchor="w", pady=(6, 0))
    body = tk.Frame(root, bg="#f6f5fb", padx=24, pady=20)
    body.pack(fill="both", expand=True)
    directory = installation_directory()
    configured = (directory / "config.json").is_file()
    config = read_config(directory) if configured else {}
    addresses = local_addresses()
    host = tk.StringVar(value=config.get("server_host", addresses[0] if addresses else ""))
    cidr = tk.StringVar(value=config.get("allowed_cidr", ""))
    password, confirm = tk.StringVar(), tk.StringVar()
    def field(label, var, secret=False):
        tk.Label(body, text=label, bg="#f6f5fb", fg="#252337", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 4))
        widget = ttk.Entry(body, textvariable=var, show="•" if secret else "")
        widget.pack(fill="x")
        return widget
    if configured:
        tk.Label(body, text="Central configurada", bg="#f6f5fb", fg="#252337", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(body, text=f"IP do técnico: {host.get()}\nRede dos alunos: {cidr.get()}\nPainel: {panel_url(directory)}",
                 bg="#f6f5fb", fg="#555268", font=("Segoe UI", 12), justify="left").pack(anchor="w", pady=12)
    else:
        field("IPv4 deste computador na rede do laboratório", host)
        field("Rede autorizada (CIDR; exemplo: 192.168.15.0/24)", cidr)
        field("Crie a senha do painel (mínimo de 12 caracteres)", password, True)
        field("Confirme a senha", confirm, True)
    status = tk.StringVar(value="Use um IP reservado no roteador para que os alunos encontrem a central.")
    tk.Label(body, textvariable=status, bg="#f6f5fb", fg="#555268", font=("Segoe UI", 10), wraplength=600,
             justify="left").pack(fill="x", pady=14)
    buttons = tk.Frame(body, bg="#f6f5fb")
    buttons.pack(fill="x", pady=6)
    executor = ThreadPoolExecutor(max_workers=1)
    busy = False
    controls = []
    def submit(action, description, open_after=False):
        nonlocal busy
        if busy:
            return
        busy = True
        for button in controls:
            button.configure(state="disabled")
        status.set(description)
        future = executor.submit(action)
        def done():
            nonlocal busy
            if not future.done():
                root.after(150, done)
                return
            busy = False
            for button in controls:
                button.configure(state="normal")
            try:
                future.result()
                if open_after:
                    status.set("Aguardando a central iniciar…")
                    await_ready(0)
                else:
                    status.set("Operação concluída.")
            except Exception as error:
                status.set(str(error))
                messagebox.showerror("LabGuard Central", str(error), parent=root)
        root.after(150, done)
    def await_ready(attempt):
        if is_ready(directory):
            status.set("Central ativa. Entre no painel com a senha definida pela TI.")
            webbrowser.open(panel_url(directory))
        elif attempt < 40:
            root.after(500, lambda: await_ready(attempt + 1))
        else:
            status.set("A central não respondeu. Confira o IP, as portas e o arquivo central-erro.log na pasta de instalação.")
    def setup():
        if not configured:
            if password.get() != confirm.get():
                return messagebox.showerror("Senha", "As senhas não coincidem.", parent=root)
            if len(password.get()) < 12:
                return messagebox.showerror("Senha", "Use pelo menos 12 caracteres.", parent=root)
        args = (password.get(), host.get().strip(), cidr.get().strip())
        submit(lambda: install(*args), "Instalando a central e sua inicialização automática…", True)
    def add_button(text, command):
        button = ttk.Button(buttons, text=text, command=command)
        button.pack(side="left", padx=(0, 8), pady=3)
        controls.append(button)
    add_button("Instalar / reparar" if configured else "Instalar e abrir painel", setup)
    if configured:
        add_button("Abrir painel", lambda: submit(start, "Iniciando a central…", True))
        add_button("Parar central", lambda: submit(stop, "Parando a central…"))
        def remove_startup():
            if messagebox.askyesno("Remover inicialização", "Parar a central e remover sua inicialização automática?\nOs cadastros serão preservados. Os clientes manterão a última política recebida.", parent=root):
                submit(lambda: stop(unregister=True), "Removendo a inicialização…")
        ttk.Button(body, text="Remover inicialização automática", command=remove_startup).pack(anchor="w", pady=12)
    def close():
        if busy:
            return
        executor.shutdown(wait=False)
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    root.mainloop()
    return 0


def self_test():
    from labguard_central import assets_directory
    assets = assets_directory()
    for filename in ("index.html", "app.css", "app.js"):
        if not (assets / filename).is_file():
            raise RuntimeError("Recurso ausente: " + filename)
    from cryptography import x509
    return {"ok": True, "version": CENTRAL_VERSION, "app": TASK, "assets": 3}


def main(argv=None):
    parser = argparse.ArgumentParser(description="LabGuard Central para o técnico do laboratório")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    sub = parser.add_subparsers(dest="command")
    init = sub.add_parser("init", help="Preparar a central em código-fonte")
    init.add_argument("--directory", type=Path, required=True)
    init.add_argument("--host", required=True)
    init.add_argument("--network", required=True)
    run = sub.add_parser("run", help="Executar os serviços da central")
    run.add_argument("--directory", type=Path)
    sub.add_parser("start", help="Iniciar a tarefa Windows")
    sub.add_parser("stop", help="Parar a tarefa Windows")
    sub.add_parser("remove-startup", help="Remover a inicialização Windows e preservar os dados")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = self_test()
            if args.output:
                with args.output.open("x", encoding="utf-8") as out:
                    json.dump(result, out)
            if sys.stdout is not None:
                print(json.dumps(result))
            return 0
        if args.command == "init":
            import getpass
            from labguard_central import initialize
            password = getpass.getpass("Senha do painel (12+ caracteres): ")
            if password != getpass.getpass("Confirme a senha: "):
                raise ValueError("As senhas não coincidem.")
            initialize(args.directory, password, args.host, args.network)
            print("Central configurada. Execute run --directory com a mesma pasta.")
            return 0
        if args.command == "run":
            return run_servers(args.directory or installation_directory())
        if args.command == "start":
            start()
            return 0
        if args.command in {"stop", "remove-startup"}:
            stop(unregister=args.command == "remove-startup")
            return 0
        return show_ui()
    except Exception as error:
        if sys.stderr is not None:
            print("LabGuard Central: " + str(error), file=sys.stderr)
        if args.command == "run":
            try:
                directory = args.directory or installation_directory()
                (directory / "central-erro.log").write_text(time.strftime("%Y-%m-%d %H:%M:%S ") + type(error).__name__ + ": " + str(error) + "\n", encoding="utf-8")
            except OSError:
                pass
        elif not args.command and not args.self_test:
            from tkinter import messagebox
            messagebox.showerror("LabGuard Central", str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
