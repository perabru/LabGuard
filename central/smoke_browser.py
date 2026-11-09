"""Validação do painel real no Microsoft Edge da VM Windows de compilação.

Não grava senha, arquivo de vínculo, rastreamento de rede ou perfil do navegador
nos artefatos. As duas imagens mostram apenas o painel já autenticado, com os
diálogos fechados. As regras temporárias são retiradas também quando há falha.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from urllib.parse import urlsplit


def _edge_executable():
    candidates = []
    for variable in ("ProgramFiles(x86)", "PROGRAMFILES(X86)", "ProgramFiles", "PROGRAMFILES", "LOCALAPPDATA"):
        directory = os.environ.get(variable)
        if directory:
            candidates.append(Path(directory) / "Microsoft" / "Edge" / "Application" / "msedge.exe")
    candidates.extend((Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                       Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("O Microsoft Edge não foi encontrado na VM de validação do Windows.")


def smoke_ui(panel_url, password, output_directory):
    """Exercita o painel já em execução; devolve somente resultados sem segredos."""
    from playwright.sync_api import expect, sync_playwright

    parts = urlsplit(panel_url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.username or parts.password:
        raise RuntimeError("A validação do painel exige o endereço HTTP local da Central.")
    origin = parts.scheme + "://" + parts.netloc
    panel_url = origin + "/"
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    domain = "labguard-ui-check-" + secrets.token_hex(6) + ".invalid"
    page_errors = []
    completed = []
    baseline_rules = None
    rules_restored = False
    csrf = ""
    failure = None
    cleanup_failure = None

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(_edge_executable()), headless=True,
            args=["--no-first-run", "--no-default-browser-check"],
        )
        context = browser.new_context(viewport={"width": 1440, "height": 1080},
                                      accept_downloads=True, locale="pt-BR")
        page = context.new_page()
        page.set_default_timeout(20000)
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        try:
            page.goto(panel_url, wait_until="domcontentloaded")
            expect(page.locator("#login-screen")).to_be_visible()
            page.locator("#password").fill(password)
            page.locator("#login-form button[type=submit]").click()
            expect(page.locator("#app-shell")).to_be_visible()
            expect(page.locator("#rules-body tr").first).to_be_visible()
            expect(page.locator("#password")).to_have_value("")
            state_response = context.request.get(origin + "/api/state")
            if not state_response.ok:
                raise RuntimeError("O painel não confirmou a sessão após entrar.")
            initial = state_response.json()
            csrf = initial["csrf"]
            baseline_rules = initial["rules"]
            if any(rule["domain"] == domain for rule in baseline_rules):
                raise RuntimeError("O domínio reservado ao teste já estava cadastrado.")
            completed.append("login")

            # Paginação sobre o catálogo real, sem inserir dados de demonstração.
            if len(initial["rules"]) > 25:
                expect(page.locator("#rules-body tr")).to_have_count(25)
                page.locator("#next-page").click()
                expect(page.locator("#page-number")).to_have_text(re.compile(r"^2 / "))
                page.locator("#previous-page").click()
                expect(page.locator("#page-number")).to_have_text(re.compile(r"^1 / "))
                completed.append("pagination")

            page.locator("#category-filter").select_option("jogos")
            expect(page.locator("#category-tools")).to_be_visible()
            page.wait_for_function("""() => [...document.querySelectorAll('#rules-body .category-label')]
                .length > 0 && [...document.querySelectorAll('#rules-body .category-label')]
                .every(item => item.textContent === 'Jogos')""")
            page.locator("#category-filter").select_option("")
            completed.append("category_filter")

            page.locator("#new-rule").click()
            expect(page.locator("#rule-dialog")).to_be_visible()
            page.locator("#rule-domain").fill(domain)
            page.locator("#rule-category").select_option("outros")
            page.locator("#rule-form input[value=block]").check()
            page.locator("#save-rule").click()
            expect(page.locator("#rule-dialog")).not_to_be_visible()
            page.locator("#search").fill(domain)
            expect(page.locator("#rules-body tr")).to_have_count(1)
            expect(page.locator("#rules-body .domain-name")).to_have_text(domain)
            expect(page.locator("#rules-body .badge")).to_have_text("Bloqueado")
            completed.append("add_block")

            page.locator("#rules-body button[data-action=toggle]").click()
            expect(page.locator("#rules-body .badge")).to_have_text("Liberado")
            page.locator("#action-filter").select_option("allow")
            expect(page.locator("#rules-body tr")).to_have_count(1)
            page.locator("#action-filter").select_option("block")
            expect(page.locator("#rules-empty")).to_be_visible()
            page.locator("#action-filter").select_option("")
            expect(page.locator("#rules-body .badge")).to_have_text("Liberado")
            completed.append("allow_and_filter")

            page.locator("#rules-body button[data-action=toggle]").click()
            expect(page.locator("#rules-body .badge")).to_have_text("Bloqueado")
            completed.append("block_again")

            page.locator("#rules-body button[data-action=edit]").click()
            expect(page.locator("#rule-dialog")).to_be_visible()
            page.locator("#rule-enabled").uncheck()
            page.locator("#save-rule").click()
            expect(page.locator("#rule-dialog")).not_to_be_visible()
            expect(page.locator("#rules-body .badge")).to_have_text("Pausado")
            completed.append("edit_pause")

            page.locator("#rules-body button[data-action=delete]").click()
            expect(page.locator("#confirm-dialog")).to_be_visible()
            page.locator("#confirm-action").click()
            expect(page.locator("#confirm-dialog")).not_to_be_visible()
            expect(page.locator("#rules-empty")).to_be_visible()
            completed.append("delete")

            page.locator("#search").fill("")
            page.locator(".audit-panel > summary").click()
            expect(page.locator("#audit-body tr").first).to_be_visible()
            page.locator(".audit-panel > summary").click()
            completed.append("history")

            page.locator(".nav-link[data-view=devices]").click()
            expect(page.locator("#view-devices")).to_be_visible()
            page.locator("#new-enrollment").click()
            expect(page.locator("#enrollment-dialog")).to_be_visible()
            with page.expect_download() as download_info:
                page.locator("#generate-enrollment").click()
            download = download_info.value
            with tempfile.TemporaryDirectory(prefix="labguard-ui-link-") as temporary:
                saved = Path(temporary) / "vinculo.json"
                download.save_as(saved)
                config = json.loads(saved.read_text(encoding="utf-8"))
                if (set(config) != {"format", "server_url", "ca_pem", "enrollment_token"}
                        or config["format"] != "labguard-central-v1"
                        or not config["server_url"].startswith("https://")
                        or "BEGIN CERTIFICATE" not in config["ca_pem"]
                        or len(config["enrollment_token"]) < 32):
                    raise RuntimeError("O arquivo baixado não contém o vínculo individual esperado.")
                saved.unlink()
            download.delete()
            del config
            expect(page.locator("#enrollment-result")).to_be_visible()
            page.locator("#enrollment-dialog button[data-close]").first.click()
            expect(page.locator("#enrollment-dialog")).not_to_be_visible()
            completed.append("devices_and_enrollment_download")

            page.locator(".nav-link[data-view=help]").click()
            expect(page.locator("#view-help")).to_be_visible()
            expect(page.locator("#view-help")).to_contain_text("Técnico → Importar vínculo")
            page.locator(".nav-link[data-view=sites]").click()
            page.locator("#category-filter").select_option("jogos")
            expect(page.locator("#rules-body tr").first).to_be_visible()
            expect(page.locator("dialog[open]")).to_have_count(0)
            expect(page.locator("#password")).to_have_value("")
            page.screenshot(path=str(output / "painel-desktop.png"), full_page=False)

            page.set_viewport_size({"width": 390, "height": 844})
            page.wait_for_function("window.innerWidth === 390")
            for view in ("sites", "devices", "help"):
                page.locator(f'.nav-link[data-view="{view}"]').click()
                expect(page.locator("#view-" + view)).to_be_visible()
                width = page.evaluate("({viewport: window.innerWidth, content: document.documentElement.scrollWidth})")
                if width["content"] > width["viewport"]:
                    raise RuntimeError("O painel transbordou a largura de 390 px na seção " + view + ".")
            page.locator('.nav-link[data-view="sites"]').click()
            page.screenshot(path=str(output / "painel-mobile.png"), full_page=False)
            completed.append("desktop_mobile_390_no_overflow")

            if page_errors:
                raise RuntimeError("Erros de JavaScript: " + "; ".join(page_errors))

            final_response = context.request.get(origin + "/api/state")
            if not final_response.ok or final_response.json()["rules"] != baseline_rules:
                raise RuntimeError("A lista de regras não voltou ao estado anterior após o teste do painel.")
            rules_restored = True
            page.locator("#logout").click()
            expect(page.locator("#login-screen")).to_be_visible()
            completed.append("logout")
        except Exception as error:
            failure = str(error).replace(password, "<senha omitida>")
        finally:
            # Se a UI falhou durante CRUD, a sessão de teste limpa somente seu
            # domínio único. Nenhum cadastro anterior é removido ou regravado.
            if baseline_rules is not None and csrf and not rules_restored:
                try:
                    state_response = context.request.get(origin + "/api/state")
                    if state_response.status == 401:
                        login_response = context.request.post(origin + "/api/login", data={"password": password},
                            headers={"Origin": origin})
                        if not login_response.ok:
                            raise RuntimeError("A sessão de limpeza do painel não pôde ser aberta.")
                        csrf = login_response.json()["csrf"]
                        state_response = context.request.get(origin + "/api/state")
                    if not state_response.ok:
                        raise RuntimeError("A central não respondeu à verificação de limpeza.")
                    current = state_response.json()
                    if any(rule["domain"] == domain for rule in current["rules"]):
                        response = context.request.post(origin + "/api/rules/delete", data={"domain": domain},
                            headers={"Origin": origin, "X-CSRF-Token": csrf})
                        if not response.ok:
                            raise RuntimeError("A regra temporária da interface não pôde ser retirada.")
                        current_response = context.request.get(origin + "/api/state")
                        if not current_response.ok:
                            raise RuntimeError("A limpeza da regra não pôde ser conferida.")
                        current = current_response.json()
                    if current["rules"] != baseline_rules:
                        raise RuntimeError("As regras ficaram diferentes da lista inicial.")
                except Exception:
                    cleanup_failure = "Falha ao conferir a limpeza da regra temporária do painel."
            context.close()
            browser.close()
    if failure or cleanup_failure:
        raise RuntimeError("Validação do painel: " + (failure or "") + (" " + cleanup_failure if cleanup_failure else "")) from None
    return {"ok": True, "checks": completed, "screenshots": ["painel-desktop.png", "painel-mobile.png"], "javascript_errors": 0}
