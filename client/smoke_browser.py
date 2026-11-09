"""Check actual Chromium browser navigation with the CI runner's own local HTTP server."""
import argparse
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading


class ProbePages(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.add(self.path)
        body = b"<html><body>LabGuard CI</body></html>"
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


def navigate(server, product, executable, hostname, expected):
    # Test a subdomain not mapped in hosts. A controlled launcher maps both names
    # to loopback even before uninstall; a policy rejection precedes resolution.
    unique = "/s-" + secrets.token_hex(12)
    url = f"http://{hostname}:{server.server_port}{unique}"
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"], ignore_cleanup_errors=True) as profile:
        args = [
            str(executable), "--headless=new", "--disable-gpu", "--disable-extensions",
            "--disable-background-networking", "--disable-sync", "--no-first-run",
            "--no-default-browser-check", "--no-proxy-server",
            "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable",
            "--host-resolver-rules=MAP *.labguard.test 127.0.0.1",
            "--user-data-dir=" + profile, "--dump-dom", url,
        ]
        result = subprocess.run(args, cwd=profile, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=45, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{product} terminou com código {result.returncode}.")
    reached = unique in server.paths
    if reached != expected:
        raise RuntimeError(f"{product}: acesso a {hostname} esperado={expected}, observado={reached}.")
    if expected and b"LabGuard CI" not in result.stdout:
        raise RuntimeError(f"{product} não renderizou a página de teste.")
    outcome = "página local carregada" if reached else "acesso não chegou ao servidor local"
    if not reached and b"ERR_BLOCKED_BY_ADMINISTRATOR" in result.stdout:
        outcome += " (ERR_BLOCKED_BY_ADMINISTRATOR)"
    print(f"{product}: {hostname} - {outcome}")


def main():
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("RUNNER_OS") != "Windows":
        raise SystemExit("Este ensaio é exclusivo do Windows hospedado pelo GitHub.")
    parser = argparse.ArgumentParser()
    parser.add_argument("state", choices=("protegido", "permitidos", "restaurado"))
    state = parser.parse_args().state
    apps = {
        "Chrome": Path("Google/Chrome/Application/chrome.exe"),
        "Edge": Path("Microsoft/Edge/Application/msedge.exe"),
    }
    with ThreadingHTTPServer(("127.0.0.1", 0), ProbePages) as server:
        server.paths = set()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for product, relative_path in apps.items():
                executable = browser_binary(product, relative_path)
                navigate(server, product, executable, "aula.labguard.test", expected=True)
                navigate(server, product, executable, "sub.jogo.labguard.test", expected=state == "restaurado")
                if state == "permitidos":
                    navigate(server, product, executable, "fora.labguard.test", expected=False)
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
