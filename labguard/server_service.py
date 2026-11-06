"""Integração nativa com SCM, sem wrappers ou serviços externos baixados."""
from __future__ import annotations

import os
import threading

SERVICE_NAME = "LabGuardServer"


def run_service(directory, *, demo=False):
    if os.name != "nt":
        raise ValueError("--service é exclusivo do Service Control Manager do Windows.")
    import ctypes
    from ctypes import wintypes as w
    from .server import build_server

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    service_main_type = ctypes.WINFUNCTYPE(None, w.DWORD, ctypes.POINTER(w.LPWSTR))
    handler_type = ctypes.WINFUNCTYPE(w.DWORD, w.DWORD, w.DWORD, w.LPVOID, w.LPVOID)

    class Status(ctypes.Structure):
        _fields_ = [("service_type", w.DWORD), ("state", w.DWORD), ("controls", w.DWORD),
                    ("win32_error", w.DWORD), ("specific_error", w.DWORD),
                    ("checkpoint", w.DWORD), ("wait_hint", w.DWORD)]

    class TableEntry(ctypes.Structure):
        _fields_ = [("name", w.LPWSTR), ("main", service_main_type)]

    advapi.RegisterServiceCtrlHandlerExW.argtypes = [w.LPCWSTR, handler_type, w.LPVOID]
    advapi.RegisterServiceCtrlHandlerExW.restype = w.HANDLE
    advapi.SetServiceStatus.argtypes = [w.HANDLE, ctypes.POINTER(Status)]
    advapi.SetServiceStatus.restype = w.BOOL
    advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(TableEntry)]
    advapi.StartServiceCtrlDispatcherW.restype = w.BOOL
    state = {"handle": None, "server": None, "error": 0}
    status_lock = threading.Lock()

    def report(value, error=0):
        with status_lock:
            status = Status(0x10, value, 0x1 | 0x4 if value == 4 else 0,
                            error, 0, 1 if value in (2, 3) else 0, 60000 if value in (2, 3) else 0)
            if state["handle"]:
                advapi.SetServiceStatus(state["handle"], ctypes.byref(status))

    @handler_type
    def handler(control, _event, _data, _context):
        if control in (1, 5):  # STOP / SHUTDOWN
            report(3)
            server = state["server"]
            if server:
                threading.Thread(target=server.shutdown, daemon=True).start()
        elif control == 4:  # INTERROGATE
            pass
        return 0

    @service_main_type
    def service_main(_argc, _argv):
        state["handle"] = advapi.RegisterServiceCtrlHandlerExW(SERVICE_NAME, handler, None)
        if not state["handle"]:
            state["error"] = ctypes.get_last_error() or 1
            return
        report(2)
        try:
            server = build_server(directory, demo=demo)
            state["server"] = server
            server.application.audit("service", "system", "started_demo" if demo else "started")
            report(4)
            server.serve_forever(poll_interval=0.25)
        except Exception:
            # Não vaza dados de configuração no SCM nem no console.
            state["error"] = 1066
        finally:
            if state["server"]:
                state["server"].server_close()
                state["server"].application.close()
            report(1, state["error"])

    table = (TableEntry * 2)()
    table[0].name = SERVICE_NAME
    table[0].main = service_main
    table[1].name = None
    table[1].main = service_main_type()
    if not advapi.StartServiceCtrlDispatcherW(table):
        code = ctypes.get_last_error()
        if code == 1063:
            raise ValueError("Inicie este modo pelo serviço LabGuardServer instalado; para console, omita --service.")
        raise OSError(code, "Não foi possível conectar ao Service Control Manager.")
    return 0 if not state["error"] else 1
