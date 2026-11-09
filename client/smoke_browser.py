"""Exercise ordinary browser navigation against a CI-owned HTTP service on loopback."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, ProxyHandler, Request


class ProbePages(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.add(self.path)
        body = b"<html><head><title>LabGuard CI</title></head><body>LabGuard CI</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def browser_binary(product, relative_path):
    for variable in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(variable):
            path = Path(os.environ[variable]) / relative_path
            if path.is_file():
                return path
    raise RuntimeError(f"{product} ausente da imagem do runner.")


def driver_binary(product, filename, env_name):
    from_env = Path(os.environ.get(env_name, ".")) / filename
    alternatives = (from_env, Path(os.environ["SystemDrive"] + "/SeleniumWebDrivers") / (product + "Driver") / filename)
    for path in alternatives:
        if path.is_file():
            return str(path)
    found = shutil.which(filename)
    if found:
        return found
    raise RuntimeError(f"{filename} ausente da imagem do runner.")


class DriverFailure(RuntimeError):
    def __init__(self, body):
        self.code = body.get("error", "webdriver")
        self.net_errors = re.findall(r"\bERR_[A-Z0-9_]+", body.get("message", ""))
        # Session failures occur before navigation. The first line is sufficient
        # to diagnose runner browser/driver mismatch without dumping a stack.
        brief = body.get("message", "").splitlines()
        super().__init__(f"{self.code}: " + (brief[0][:220] if brief else ""))


@contextmanager
def browser_session(product, binary, driver, options_key, browser_name):
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"], ignore_cleanup_errors=True) as profile:
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        root = f"http://127.0.0.1:{port}"
        opener = build_opener(ProxyHandler({}))

        def request(method, path, payload=None):
            data = json.dumps(payload).encode() if payload is not None else None
            req = Request(root + path, data=data, headers={"Content-Type": "application/json; charset=utf-8"}, method=method)
            try:
                with opener.open(req, timeout=55) as response:
                    return json.load(response).get("value")
            except HTTPError as error:
                raise DriverFailure(json.loads(error.read()).get("value", {})) from None

        proc = subprocess.Popen([driver, f"--port={port}"], cwd=profile, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=dict(os.environ, MSEDGEDRIVER_TELEMETRY_OPTOUT="1"))
        sid = None
        try:
            limit = time.monotonic() + 15
            while time.monotonic() < limit and proc.poll() is None:
                try:
                    if request("GET", "/status")["ready"]:
                        break
                except URLError:
                    time.sleep(.1)
            else:
                raise RuntimeError(f"{product}: o driver nativo não iniciou.")
            args = ["--headless=new", "--disable-gpu", "--disable-extensions", "--disable-sync",
                    "--disable-background-networking", "--no-first-run", "--no-default-browser-check",
                    "--no-proxy-server", "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable",
                    "--host-resolver-rules=MAP *.labguard.test 127.0.0.1", "--user-data-dir=" + profile]
            session = request("POST", "/session", {"capabilities": {"alwaysMatch": {
                "browserName": browser_name, options_key: {"binary": str(binary), "args": args},
                "timeouts": {"pageLoad": 20000, "script": 10000}
            }}})
            sid = session["sessionId"]
            version = session.get("capabilities", {}).get("browserVersion", "?")
            print(f"{product} {version}: sessão WebDriver iniciada.", flush=True)
            yield lambda method, path, payload=None: request(method, "/session/" + sid + path, payload)
        finally:
            try:
                if sid and proc.poll() is None:
                    request("DELETE", "/session/" + sid)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


_DIAGNOSTIC = """
const t = (document.body ? document.body.innerText : '').slice(0, 12000);
return {title: document.title.slice(0, 90), host: location.hostname,
        protocol: location.protocol, marker: t.trim() === 'LabGuard CI',
        errors: Array.from(new Set(t.match(/ERR_[A-Z0-9_]+/g) || [])).slice(0, 5)};
"""


def navigate(server, product, call, hostname, expected):
    unique = "/s-" + secrets.token_hex(12)
    url = f"http://{hostname}:{server.server_port}{unique}"
    failures = []
    try:
        call("POST", "/url", {"url": url})
    except DriverFailure as err:
        failures = err.net_errors or [err.code]
    meta = call("POST", "/execute/sync", {"script": _DIAGNOSTIC, "args": []})
    reached = unique in server.paths
    summary = (f"{product} {hostname}: esperado={expected}, chegou_ao_servidor={reached}, "
               f"título={meta['title']!r}, destino={meta['protocol']}//{meta['host']}, "
               f"erros={failures + meta['errors']}")
    print(summary, flush=True)
    if reached != expected or (expected and (not meta["marker"] or failures)) or (not expected and meta["marker"]):
        raise RuntimeError(f"Navegação do {product} divergiu da política para {hostname}.")
    errors = set(failures + meta["errors"])
    if not expected and any(e.startswith("ERR_") and e != "ERR_BLOCKED_BY_ADMINISTRATOR" for e in errors):
        raise RuntimeError(f"{product}: erro de rede inesperado ao testar o site bloqueado.")


def main():
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("RUNNER_OS") != "Windows":
        raise SystemExit("Este ensaio é exclusivo do Windows hospedado pelo GitHub.")
    parser = argparse.ArgumentParser()
    parser.add_argument("state", choices=("protegido", "permitidos", "restaurado"))
    state = parser.parse_args().state
    apps = (
        ("Chrome", "Google/Chrome/Application/chrome.exe", "chromedriver.exe", "CHROMEWEBDRIVER", "goog:chromeOptions", "chrome"),
        ("Edge", "Microsoft/Edge/Application/msedge.exe", "msedgedriver.exe", "EDGEWEBDRIVER", "ms:edgeOptions", "MicrosoftEdge"),
    )
    with ThreadingHTTPServer(("127.0.0.1", 0), ProbePages) as server:
        server.paths = set()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for product, relative_path, driver_name, env, opts, browser_name in apps:
                executable = browser_binary(product, relative_path)
                driver = driver_binary(product, driver_name, env)
                with browser_session(product, executable, driver, opts, browser_name) as call:
                    navigate(server, product, call, "aula.labguard.test", expected=True)
                    navigate(server, product, call, "sub.jogo.labguard.test", expected=state == "restaurado")
                    if state == "permitidos":
                        navigate(server, product, call, "fora.labguard.test", expected=False)
                        navigate(server, product, call, "aula.labguard.test", expected=True)
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
