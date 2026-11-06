"""Inicia o painel ou valida os recursos de um pacote Windows sem abrir rede."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile


def self_test(output: str | None = None) -> int:
    """Verifica os dados empacotados sem iniciar Tk nem comandos de rede."""
    try:
        from labguard import __version__
        from labguard.demo import DemoTransport
        from labguard.integrations import IntegrationManager
        from labguard.banlist import BanlistDatabase
        from labguard.remote import PROCESS_CATALOGUE
        with tempfile.TemporaryDirectory(prefix="labguard-selftest-") as temporary:
            database = BanlistDatabase(Path(temporary) / "data" / "banlist.sqlite3")
            database.upsert("selftest.example", "Jogos")
            if database.summary()["enabled"] != 1:
                raise RuntimeError("Banco de sites indisponível.")
            database.close()
        if getattr(sys, "frozen", False):
            from winrm.protocol import Protocol  # noqa: F401 - dependency load, no connection
            from reportlab.platypus import SimpleDocTemplate  # noqa: F401
        snapshot = DemoTransport().request("snapshot")
        if getattr(sys, "frozen", False):
            from labguard.reports import export_report
            with tempfile.TemporaryDirectory(prefix="labguard-reports-selftest-") as temporary:
                for format in ("svg", "html", "csv", "pdf"):
                    report = Path(temporary) / ("report." + format)
                    export_report(snapshot, report, format)
                    if report.stat().st_size < 100:
                        raise RuntimeError("Relatórios empacotados indisponíveis.")
        # Diretório não criado: não lê perfis privados do operador neste teste.
        profiles = IntegrationManager(profile_dir=Path(__file__).parent / "__selftest_no_profiles__").list_profiles()
        policy = snapshot["policies"]["ai_block"]
        if not policy["services"] or not profiles or snapshot["mode"] != "demo":
            raise RuntimeError("Recursos internos do pacote incompletos.")
        payload = {"ok": True, "version": __version__, "catalog_services": len(policy["services"]),
                   "catalog_domains": policy["domain_count"], "integration_profiles": len(profiles),
                   "banlist_database": "sqlite3", "remote_process_signatures": len(PROCESS_CATALOGUE),
                   "reports": ["svg", "html", "csv", "pdf"]}
        code = 0
    except Exception as error:
        payload, code = {"ok": False, "error": str(error)}, 1
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    if sys.stdout is not None:
        print(text)
    return code


def run() -> int:
    parser = argparse.ArgumentParser(description="LabGuard - controle do laboratório escolar")
    parser.add_argument("--self-test", action="store_true", help="Validar recursos do pacote sem abrir a interface")
    parser.add_argument("--output", help="Gravar resultado do autoteste em JSON")
    args = parser.parse_args()
    if args.self_test:
        return self_test(args.output)
    from labguard.gui import main
    main()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
