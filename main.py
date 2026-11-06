"""Inicia o painel ou valida os recursos de um pacote Windows sem abrir rede."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def self_test(output: str | None = None) -> int:
    """Verifica os dados empacotados sem iniciar Tk nem comandos de rede."""
    try:
        from labguard import __version__
        from labguard.demo import DemoTransport
        from labguard.integrations import IntegrationManager
        snapshot = DemoTransport().request("snapshot")
        # Diretório não criado: não lê perfis privados do operador neste teste.
        profiles = IntegrationManager(profile_dir=Path(__file__).parent / "__selftest_no_profiles__").list_profiles()
        policy = snapshot["policies"]["ai_block"]
        if not policy["services"] or not profiles or snapshot["mode"] != "demo":
            raise RuntimeError("Recursos internos do pacote incompletos.")
        payload = {"ok": True, "version": __version__, "catalog_services": len(policy["services"]),
                   "catalog_domains": policy["domain_count"], "integration_profiles": len(profiles)}
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
