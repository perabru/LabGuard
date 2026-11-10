"""Teste de integração real em uma VM Windows descartável do GitHub Actions.

Instala os dois EXEs, aplica uma regra, libera e exclui o mesmo domínio,
confere o registro real do Windows e a confirmação enviada pela estação.
"""
from __future__ import annotations
import argparse
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'client'))
from labguard_cliente import client_directory
import labguard_tecnico as launcher


def wait_for(check, label, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Tempo esgotado: ' + label)


def entries(key):
    import winreg
    result = set()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            for i in range(winreg.QueryInfoKey(handle)[1]):
                result.add(winreg.EnumValue(handle, i)[1])
    except FileNotFoundError:
        pass
    return result


def main():
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Este teste instala proteção; use apenas a VM Windows descartável do CI.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--central', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    args = parser.parse_args()
    central_exe, client_exe = args.central.resolve(), args.client.resolve()
    central_dir, client_dir = launcher.installation_directory(), client_directory()
    if central_dir.exists() or client_dir.exists():
        raise RuntimeError('O teste requer uma VM sem instalação anterior.')
    addresses = launcher.local_addresses()
    if not addresses:
        raise RuntimeError('A VM não informou um endereço privado para testar TLS.')
    host = addresses[0]
    network = str(ipaddress.ip_network(host + '/32'))
    password = secrets.token_urlsafe(24)
    temp = Path(tempfile.mkdtemp(prefix='labguard-central-ci-'))
    installed_client = False
    cookie = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookie))
    csrf = None
    def api(path, body=None):
        headers = {'Origin': 'http://127.0.0.1:8787'}
        data = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            if csrf:
                headers['X-CSRF-Token'] = csrf
            data = json.dumps(body).encode()
        request = urllib.request.Request('http://127.0.0.1:8787' + path, data=data, headers=headers)
        with opener.open(request, timeout=10) as response:
            return json.load(response)
    def client(*arguments):
        output = temp / (secrets.token_hex(8) + '.json')
        process = subprocess.run([str(client_exe), *arguments, '--saida', str(output)], timeout=120)
        if process.returncode:
            if output.exists():
                print(output.read_text(encoding='utf-8'))
            raise RuntimeError('O cliente recusou: ' + arguments[0])
        return json.loads(output.read_text(encoding='utf-8'))
    def acknowledged(revision):
        devices = api('/api/state')['devices']
        return any(row['applied_revision'] == revision and row['status'] == 'online' for row in devices)
    try:
        with patch.object(sys, 'frozen', True, create=True), patch.object(sys, 'executable', str(central_exe)):
            launcher.install(password, host, network)
        wait_for(lambda: launcher.is_ready(central_dir), 'inicialização da central', 60)
        from central.smoke_browser import smoke_ui
        smoke_ui(launcher.panel_url(central_dir), password, Path('build/central/qa').resolve())
        csrf = api('/api/login', {'password': password})['csrf']
        link = api('/api/enrollment', {})['config']
        pairing = temp / 'vinculo.json'
        pairing.write_text(json.dumps(link), encoding='utf-8')
        policy = temp / 'politica.json'
        policy.write_text(json.dumps({'mode': 'bloqueados', 'catalog_enabled': False, 'domains': [],
                                     'allowed_domains': [], 'games': [], 'remove_roblox': False,
                                     'remove_games': []}), encoding='utf-8')
        client('instalar', '--politica', str(policy), '--sim')
        installed_client = True
        client('parear', '--vinculo', str(pairing), '--sim')
        domain = 'labguard-central-check.invalid'
        block_key = r'SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
        allow_key = r'SOFTWARE\Policies\Microsoft\Edge\URLAllowlist'
        for action in ('block', 'allow'):
            rule = {'domain': domain, 'category': 'outros', 'action': action, 'enabled': True}
            if action == 'allow':
                rule['original'] = domain
            change = api('/api/rules', rule)
            wait_for(lambda: acknowledged(change['revision']), 'confirmação da regra ' + action)
            if action == 'block':
                assert domain in entries(block_key), 'Bloqueio ausente no registro Windows'
            else:
                assert domain in entries(allow_key), 'Liberação ausente no registro Windows'
                assert domain not in entries(block_key), 'Bloqueio não removido após liberar'
                hosts = Path(os.environ['SystemRoot']) / 'System32/drivers/etc/hosts'
                assert domain not in hosts.read_text(errors='replace'), 'Hosts não liberou o domínio'
        change = api('/api/rules/delete', {'domain': domain})
        wait_for(lambda: acknowledged(change['revision']), 'confirmação da exclusão')
        assert domain not in entries(allow_key) | entries(block_key), 'Exclusão não removeu regras'
        # Reapply a block and stop the central to verify the station keeps enforcing it.
        change = api('/api/rules', {'domain': domain, 'category': 'outros', 'action': 'block', 'enabled': True})
        wait_for(lambda: acknowledged(change['revision']), 'confirmação antes do modo offline')
        launcher.stop()
        wait_for(lambda: not launcher.is_ready(central_dir), 'central realmente desligada para testar modo offline', 20)
        time.sleep(20)
        assert domain in entries(block_key), 'A regra foi perdida quando a central parou'
        client('desvincular', '--sim')
        wait_for(lambda: domain not in entries(block_key), 'restauração da política local após desvincular')
        print('PASSOU: instalação Windows, TLS, vínculo, bloquear, liberar, excluir, confirmação e política offline.', flush=True)
    finally:
        cleanup_errors = []
        try:
            if installed_client:
                client('remover', '--sim')
        except Exception as error:
            cleanup_errors.append('cliente: ' + type(error).__name__ + ': ' + str(error).replace(password, '<senha omitida>')[:1800])
        central_stage = 'parar e desregistrar'
        try:
            if central_dir.exists():
                print('Limpeza: parando e desregistrando a Central.', flush=True)
                launcher.stop(unregister=True)
                # Directory did not exist before this test, and is owned by this CI run.
                central_stage = 'aguardar o encerramento HTTP'
                print('Limpeza: aguardando o encerramento HTTP da Central.', flush=True)
                wait_for(lambda: not launcher.is_ready(central_dir), 'encerramento da central', 20)
                central_stage = 'remover a pasta criada pelo teste'
                for attempt in range(20):
                    try:
                        shutil.rmtree(central_dir)
                        break
                    except PermissionError:
                        if attempt == 19:
                            raise
                        time.sleep(.5)
        except Exception as error:
            cleanup_errors.append('central/' + central_stage + ': ' + type(error).__name__ + ': ' + str(error).replace(password, '<senha omitida>')[:1800])
        try:
            shutil.rmtree(temp)
        except Exception as error:
            cleanup_errors.append('temporários: ' + type(error).__name__ + ': ' + str(error).replace(password, '<senha omitida>')[:1800])
        if cleanup_errors:
            raise RuntimeError('Limpeza da VM não foi concluída: ' + ', '.join(cleanup_errors))


if __name__ == '__main__':
    main()
