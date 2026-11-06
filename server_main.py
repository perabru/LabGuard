"""LabGuard Server: administração local sem Tk, para Windows e Linux."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading


def self_test(output=None):
    try:
        from labguard import __version__
        from labguard.server import ASSET_TYPES, asset_directory, validate_action
        from labguard.demo import DemoTransport
        from labguard.integrations import IntegrationManager
        assets = asset_directory()
        for name, _mime in ASSET_TYPES.values():
            if not (assets / name).is_file() or (assets / name).stat().st_size == 0:
                raise RuntimeError("Recurso do painel de servidor ausente: " + name)
        validate_action("set_ai_block", {"enabled": True})
        snapshot = DemoTransport().request("snapshot")
        result = {"ok": True, "version": __version__, "service": "LabGuard Server", "bind_host": "127.0.0.1",
                  "assets": len(ASSET_TYPES), "roles": ["viewer", "admin"],
                  "catalog_services": len(snapshot["policies"]["ai_block"]["services"]),
                  "integration_profiles": len(IntegrationManager(profile_dir=assets / "__none__").list_profiles())}
        code = 0
    except Exception as error:
        result, code = {"ok": False, "error": str(error)}, 1
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    if sys.stdout is not None:
        print(text)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description="LabGuard Server - administração local do gateway")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output")
    commands = parser.add_subparsers(dest="command")
    initialize = commands.add_parser("init", help="Criar configuração e credenciais locais")
    initialize.add_argument("--directory", required=True, type=Path)
    run = commands.add_parser("run", help="Executar servidor no loopback")
    run.add_argument("--directory", required=True, type=Path)
    run.add_argument("--demo", action="store_true", help="Dados fictícios, sem acesso à rede do laboratório")
    run.add_argument("--service", action="store_true", help="Conectar ao Service Control Manager do Windows")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test(args.output)
    if not args.command:
        parser.error("Use init, run ou --self-test.")
    from labguard.server import ServerError, build_server, initialize as make_config
    try:
        if os.name != "nt":
            os.umask(0o077)
        if args.command == "init":
            result = make_config(args.directory)
            if sys.stdout is not None:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.service:
            from labguard.server_service import run_service
            return run_service(args.directory, demo=args.demo)
        server = build_server(args.directory, demo=args.demo)
        server.application.audit("service", "system", "started_demo" if args.demo else "started")
        def stop(*_args):
            threading.Thread(target=server.shutdown, daemon=True).start()
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, stop)
        if sys.stdout is not None:
            print(f"LabGuard Server em http://127.0.0.1:{server.server_port}/ - " + ("DEMONSTRAÇÃO" if args.demo else "gateway configurado"), flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            server.application.audit("service", "system", "stopped")
            server.application.close()
        return 0
    except (ServerError, OSError, ValueError) as error:
        if sys.stderr is not None:
            print(f"LabGuard Server: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
