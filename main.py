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
        from labguard.controller import create_transport
        from labguard.discovery import LocalObservationTransport
        from labguard.direct_routeros import DirectRouterOSTransport
        from labguard.diagnostics import build_diagnostic_plan
        from labguard.local_dns import DNSFilter, CHECK_DOMAIN
        from dnslib import DNSRecord, RCODE
        dns_check = DNSFilter('127.0.0.1', '127.0.0.0/8', port=53535, rules={'blocked.example':'Jogos'})
        try:
            wire = dns_check.resolve(DNSRecord.question('blocked.example').pack(), '127.0.0.1')
            if DNSRecord.parse(wire).header.rcode != RCODE.NXDOMAIN:raise RuntimeError('Filtro DNS ausente.')
        finally:dns_check.close()
        from labguard.inventory import summarize_inventory
        from labguard.preferences import default_preferences, normalize_preferences
        from labguard.credential_store import CredentialStore  # import only: no vault access
        from labguard.updater import version_tuple
        if normalize_preferences(default_preferences()) != default_preferences():
            raise RuntimeError("Preferências internas incompatíveis.")
        if version_tuple(__version__) <= (0, 0, 0):
            raise RuntimeError("Versão do atualizador incompatível.")
        update_helper = Path(__file__).parent / "labguard" / "update_helpers" / "apply_windows.ps1"
        if not update_helper.is_file() or update_helper.stat().st_size < 100:
            raise RuntimeError("Assistente de atualização ausente do pacote.")
        inventory_check = summarize_inventory({"mode": "observation", "interfaces": [], "devices": [],
            "discovery": {"read_success": False, "interfaces_read": False, "routes_read": False, "neighbors_read": False}})
        if inventory_check["status"] != "unavailable" or inventory_check["facts"]["coverage_complete"] is not False:
            raise RuntimeError("Resumo de identificação indisponível ou incompatível.")
        identification = build_diagnostic_plan({"mode": "observation", "interfaces": [], "devices": [], "gateway": {}}, system="Windows")
        if len(identification["steps"]) < 3 or "no_gateway" not in identification["cases"]:
            raise RuntimeError("Ajuda de identificação indisponível no pacote.")
        with tempfile.TemporaryDirectory(prefix="labguard-selftest-") as temporary:
            database = BanlistDatabase(Path(temporary) / "data" / "banlist.sqlite3")
            database.upsert("selftest.example", "Jogos")
            if database.summary()["enabled"] != 1:
                raise RuntimeError("Banco de sites indisponível.")
            database.close()
        if getattr(sys, "frozen", False):
            from winrm.protocol import Protocol  # noqa: F401 - dependency load, no connection
            from reportlab.platypus import SimpleDocTemplate  # noqa: F401
        snapshot = create_transport("demo").request("snapshot")
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
                   "reports": ["svg", "html", "csv", "pdf"],
                   "identification_help_steps": len(identification["steps"]),
                   "inventory_summary_check": "ok",
                   "local_dns_check": "ok", "preferences_check": "ok", "update_helper_check": "ok",
                   "credential_storage": "windows-vault-optional",
                   "startup_mode": "observation", "controller_modes": ["observation", "local_dns", "routeros", "legacy", "demo"]}
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
    parser.add_argument("--dns-self-test", action="store_true", help="Testar DNS por UDP e TCP somente no loopback")
    parser.add_argument("--demo", action="store_true", help="Abrir demonstração explícita com dados fictícios")
    parser.add_argument("--no-updates", action="store_true", help="Desativar consultas de atualização nesta execução")
    parser.add_argument("--legacy-ui", action="store_true", help="Abrir a interface avançada do gateway existente")
    parser.add_argument("--output", help="Gravar resultado do autoteste em JSON")
    args = parser.parse_args()
    if args.dns_self_test:
        from labguard.local_dns import smoke_test
        from labguard import __version__
        try:result=smoke_test();result['version']=__version__;code=0
        except Exception:result={'ok':False,'error':'Teste DNS local não concluiu.'};code=1
        if args.output:Path(args.output).write_text(json.dumps(result)+'\n',encoding='utf-8')
        if sys.stdout is not None:print(json.dumps(result))
        return code
    if args.self_test:
        return self_test(args.output)
    if args.legacy_ui:
        from labguard.gui import main
        main()
    else:
        from labguard.simple_gui import App
        from labguard.controller import create_transport
        app = App(transport=create_transport("demo") if args.demo else None,
                  updates_enabled=not args.no_updates and not args.demo)
        app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
