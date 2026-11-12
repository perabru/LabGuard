"""LabGuard Windows uninstaller. No installed program or registry command is executed."""
from __future__ import annotations
import base64
import ctypes
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

VERSION = '1.0.0'
APP_DIRS = ('LabGuard', 'LabGuardJogos', 'LabGuardJogos2', 'LabGuardCliente', 'LabGuardCentral', 'LabGuardServer')
EXES = {'labguard.exe', 'labguard-jogos.exe', 'labguardcliente.exe', 'labguardtecnico.exe', 'labguardserver.exe'}
TASKS = {'LabGuard-RemoverJogos', 'LabGuard-Jogos2-Limpeza', 'LabGuard-Jogos2-Monitor', 'LabGuardCliente', 'LabGuardCentral'}
RUN_NAMES = {'LabGuard', 'LabGuardJogos2', 'LabGuardCliente', 'LabGuardCentral', 'LabGuardServer'}
UNINSTALL_IDS = {'{84474208-6606-4F7A-A421-EDC4FF33948C}_is1', 'LabGuardJogos2', 'LabGuardCliente', 'LabGuardCentral', 'LabGuardServer'}
BROWSER_KEYS = {
    r'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist': ('Edge', 'block'),
    r'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist': ('Chrome', 'block'),
    r'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block': ('Firefox', 'block'),
}


def resource(name: str) -> Path:
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)) / 'resources' / name


def read_json(path: Path, limit: int = 4 * 1024 * 1024):
    no_links(path)
    if path.stat().st_size > limit:
        raise ValueError('Arquivo de estado excedeu o limite: ' + str(path))
    return json.loads(path.read_text(encoding='utf-8-sig'))


def no_links(path: Path):
    """Do not traverse junctions, symlinks or other reparse points."""
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Link/junction recusado: ' + str(item))


def within(path: str, root: str) -> bool:
    import ntpath
    try:
        a, b = ntpath.normcase(ntpath.abspath(path)), ntpath.normcase(ntpath.abspath(root))
        return a == b or a.startswith(b.rstrip('\\') + '\\')
    except (ValueError, TypeError):
        return False


def safe_delete(path: Path, root: Path):
    """Only a previously approved root; no recursive OS delete following links."""
    if not (path == root or root in path.parents) or len(root.parts) < 3:
        raise ValueError('Caminho fora da instalacao aprovada.')
    no_links(path)
    if not path.exists():
        return
    if path.is_dir():
        for child in list(path.iterdir()):
            safe_delete(child, root)
        no_links(path)
        path.rmdir()
    else:
        if path == Path(sys.executable).resolve():
            raise ValueError('Execute o desinstalador fora da pasta do LabGuard.')
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        path.unlink()


def strip_youtube_hosts(data: bytes) -> bytes:
    if len(data) > 16 * 1024 * 1024 or b'\x00' in data:
        raise ValueError('Hosts em formato/tamanho nao suportado; preservado.')
    start, end = b'# BEGIN LABGUARD JOGOS YOUTUBE', b'# END LABGUARD JOGOS YOUTUBE'
    lines = data.splitlines(keepends=True)
    a = [i for i, x in enumerate(lines) if x.rstrip(b'\r\n') == start]
    b = [i for i, x in enumerate(lines) if x.rstrip(b'\r\n') == end]
    if not a and not b:
        return data
    if len(a) != 1 or len(b) != 1 or a[0] >= b[0]:
        raise ValueError('Marcadores YouTube inconsistentes. Hosts preservado.')
    # Refuse a modified block containing content other than YouTube deny entries.
    hosts = {'youtube.com','www.youtube.com','m.youtube.com','music.youtube.com','studio.youtube.com','gaming.youtube.com','kids.youtube.com','youtu.be','www.youtu.be','youtube-nocookie.com','www.youtube-nocookie.com','youtubekids.com','www.youtubekids.com','youtubeeducation.com','www.youtubeeducation.com','youtubei.googleapis.com','youtube.googleapis.com'}
    for line in lines[a[0]+1:b[0]]:
        fields = line.decode('ascii').strip().split()
        if fields and (len(fields) != 2 or fields[0] not in ('0.0.0.0', '::1') or fields[1] not in hosts):
            raise ValueError('Bloco YouTube alterado por outra politica; revisao necessaria.')
    return b''.join(lines[:a[0]] + lines[b[0]+1:])


def atomic_bytes(path: Path, expected: bytes, desired: bytes):
    no_links(path)
    if expected == desired:
        return
    fd, temp_name = tempfile.mkstemp(prefix='lgu-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(desired)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != expected:
            raise RuntimeError('Arquivo alterado durante a operacao; tente novamente.')
        if os.name == 'nt':
            from ctypes import wintypes as w
            api = ctypes.WinDLL('kernel32', use_last_error=True)
            api.ReplaceFileW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD, w.LPVOID, w.LPVOID]
            api.ReplaceFileW.restype = w.BOOL
            if not api.ReplaceFileW(str(path), temp_name, None, 0, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(temp_name, path)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def known_folder(number: int) -> Path:
    buf = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.shell32.SHGetFolderPathW(None, number, None, 0, buf):
        raise OSError('Pasta do Windows indisponivel.')
    return Path(buf.value)


def system_dir() -> Path:
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf)):
        raise ctypes.WinError()
    return Path(buf.value)


def run_ps(script: str, payload=None, timeout=90):
    wrapper = "$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$LGU=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:LGU_DATA)));& ([scriptblock]::Create([Console]::In.ReadToEnd()))"
    env = dict(os.environ)
    env['LGU_DATA'] = base64.b64encode(json.dumps(payload or {}, ensure_ascii=True).encode()).decode()
    env['PSModulePath'] = str(system_dir() / 'WindowsPowerShell/v1.0/Modules')
    env['PATH'] = str(system_dir()) + ';' + str(system_dir().parent)
    command = [str(system_dir() / 'WindowsPowerShell/v1.0/powershell.exe'), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(wrapper.encode('utf-16-le')).decode()]
    completed = subprocess.run(command, input=script, capture_output=True, text=True, encoding='utf-8', errors='replace', env=env, cwd=system_dir(), creationflags=0x08000000, timeout=timeout)
    if completed.returncode:
        raise RuntimeError((completed.stderr or completed.stdout).strip()[-1600:])
    output = completed.stdout.strip().lstrip('\ufeff')
    return json.loads(output) if output else None


def operations(mode, payload=None, timeout=90):
    return run_ps(resource('operations.ps1').read_text(encoding='utf-8-sig'), dict(payload or {}, mode=mode), timeout)


def profile_paths():
    import winreg as reg
    output = []
    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') as base:
        for index in range(reg.QueryInfoKey(base)[0]):
            sid = reg.EnumKey(base, index)
            if not re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+|S-1-12-1-(?:\d+-){3}\d+', sid):
                continue
            with reg.OpenKey(base, sid) as key:
                folder = Path(os.path.expandvars(reg.QueryValueEx(key, 'ProfileImagePath')[0]))
            try:
                no_links(folder)
                if folder.is_dir():
                    output.append({'sid': sid, 'path': str(folder)})
            except OSError:
                continue
    return output


class Cleaner:
    def __init__(self, emit=None):
        self.emit = emit or (lambda text: None)
        self.warnings = []
        self.roots = []
        self.held = set()
        self.report = []
        self.snapshot = {}
        self.profiles = []
        self.report_path = None

    def log(self, text, warning=False):
        line = dt.datetime.now().strftime('%H:%M:%S') + (' [PENDENTE] ' if warning else ' ') + text
        self.report.append(line)
        if warning:
            self.warnings.append(text)
        self.emit(line)

    def attempt(self, label, fn, hold=None):
        try:
            result = fn()
            self.log(label)
            return result
        except Exception as error:
            self.log(label + ': ' + str(error), True)
            if hold:
                self.held.add(str(hold).casefold())
            return None

    def add_root(self, path: Path, kind: str, markers=()):
        try:
            if not path.exists():
                return
            no_links(path)
            if not path.is_dir() or len(path.parts) < 3:
                return
            if markers and not any((path / marker).is_file() for marker in markers):
                self.log('Pasta sem identificacao suficiente, preservada: ' + str(path), True)
                return
            if not any(x['path'].casefold() == str(path).casefold() for x in self.roots):
                self.roots.append({'path': str(path), 'kind': kind})
        except Exception as error:
            self.log(str(error), True)

    def scan(self):
        self.roots = []
        self.profiles = profile_paths()
        program = known_folder(38)
        bases = [program]
        try:
            alternate = known_folder(42)
            if alternate not in bases:
                bases.append(alternate)
        except OSError:
            pass
        markers = {'LabGuard': ('LabGuard.exe','unins000.dat'), 'LabGuardJogos': ('LabGuardCore.ps1','LabGuard_Remover_Jogos.bat'), 'LabGuardJogos2': ('LabGuard-Jogos.exe','config.json'), 'LabGuardCliente': ('instalacao.json','LabGuardCliente.exe','LabGuardCliente.py'), 'LabGuardCentral': ('instalacao-central.json','LabGuardTecnico.exe'), 'LabGuardServer': ('LabGuardServer.exe','config.json')}
        for base in bases:
            for name in APP_DIRS:
                self.add_root(base/name, 'programa', markers[name])
        for name in APP_DIRS:
            self.add_root(known_folder(35)/name, 'dados')
        for profile in self.profiles:
            home = Path(profile['path'])
            self.add_root(home/'AppData/Local/Programs/LabGuard','programa',markers['LabGuard'])
            for suffix in ('AppData/Roaming/LabGuard','AppData/Local/LabGuard','AppData/Local/LabGuardJogos2','.labguard'):
                self.add_root(home/suffix,'dados')
        self.snapshot = operations('Inventory', {'roots': self.roots})
        # Registered custom install directories are accepted only with a LabGuard executable marker.
        for service in self.snapshot.get('services', []):
            m = re.match(r'^"([^"]+LabGuardServer\.exe)"(?:\s|$)', service['PathName'], re.I)
            if m:
                self.add_root(Path(m[1]).parent, 'programa', ('LabGuardServer.exe',))
                config = re.search(r'--directory\s+"([^"]+)"', service['PathName'], re.I)
                if config and Path(config[1]).name.casefold() in ('labguardserver','labguard-server'):
                    self.add_root(Path(config[1]), 'dados', ('config.json',))
        self.log('Conferencia: %d pasta(s), %d tarefa(s), %d servico(s) LabGuard.' % (len(self.roots),len(self.snapshot.get('tasks',[])),len(self.snapshot.get('services',[]))))
        for entry in self.roots:
            self.log('  ' + entry['path'])
        return self.snapshot

    def restore_client(self):
        import _vendor_labguard_cliente as old
        for entry in self.roots:
            path = Path(entry['path'])
            if path.name.casefold() != 'labguardcliente':
                continue
            state_path = path/'estado.json'
            if not state_path.exists():
                self.log('Cliente sem estado.json; politicas externas nao serao apagadas por suposicao.', True)
                self.held.add(str(path).casefold())
                continue
            def restore():
                # Reuse audited restoration code, never an installed executable.
                old._lc_secure_chain(path)
                old._lc_guard_file(state_path)
                state = read_json(state_path)
                if not isinstance(state,dict):
                    raise ValueError('Estado do cliente invalido.')
                persist = lambda: old._atomic_json(state_path,state)
                browser = old.undo_sites(state, checkpoint=persist)
                hosts = old.undo_system_sites(state, checkpoint=persist)
                if not browser.get('ok') or not hosts.get('ok'):
                    raise RuntimeError('Restauracao do cliente incompleta; estado preservado para nova tentativa.')
            self.attempt('Restaurar politicas do Cliente 1.x',restore,path)

    def restore_youtube(self):
        import _vendor_labguard_cliente as old
        for entry in self.roots:
            path = Path(entry['path'])
            if path.name.casefold() != 'labguardjogos2':
                continue
            owned = path/'youtube-owned-rules.json'
            if not owned.exists():
                continue
            def restore():
                old._lc_secure_chain(path)
                old._lc_guard_file(owned)
                records = read_json(owned)
                if isinstance(records,dict):
                    records = [records]
                if not isinstance(records,list) or len(records)>100:
                    raise ValueError('Registro YouTube invalido.')
                state = {'sites':{}}
                for row in records:
                    if row is None:
                        continue
                    if not isinstance(row,dict) or row.get('Key') not in BROWSER_KEYS or not re.fullmatch(r'[1-9][0-9]{0,2}|1000',str(row.get('Name',''))) or not isinstance(row.get('Value'),str):
                        raise ValueError('Regra YouTube fora do escopo permitido.')
                    browser, group = BROWSER_KEYS[row['Key']]
                    scope = state['sites'].setdefault(browser,{}).setdefault(group,{'owned':{}})
                    scope['owned'][str(row['Name'])] = row['Value']
                result = old.undo_sites(state,checkpoint=lambda:None)
                if not result.get('ok'):
                    raise RuntimeError('Uma politica de navegador nao pode ser restaurada.')
                old._atomic_json(owned,[])
            self.attempt('Retirar regras YouTube pertencentes ao LabGuard',restore,path)
        def restore_hosts():
            path = system_dir()/'drivers/etc/hosts'
            if not path.exists():
                return
            no_links(path)
            original=path.read_bytes()
            atomic_bytes(path,original,strip_youtube_hosts(original))
        # Preserve recovery data if even one host operation fails.
        before=len(self.warnings)
        self.attempt('Retirar bloco YouTube do hosts, preservando as demais entradas',restore_hosts)
        if len(self.warnings)>before:
            for entry in self.roots:
                if Path(entry['path']).name.casefold()=='labguardjogos2':
                    self.held.add(entry['path'].casefold())

    def restore_dns(self):
        script = resource('restore-network.ps1').read_text(encoding='utf-8-sig')
        # Dot-source defines only the shipped original functions; no default diagnostic runs.
        encoded=base64.b64encode(script.encode()).decode()
        code=". ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'))));$out=@();$base='HKLM:\\SOFTWARE\\LabGuard\\NetworkDNS';if(Test-Path -LiteralPath $base){foreach($key in @(Get-ChildItem -LiteralPath $base)){try{$rec=Read-LabGuardBackup $key.PSChildName;if($null -eq $rec){continue};$a=@(Get-NetAdapter -IncludeHidden|Where-Object {([guid]$_.InterfaceGuid).ToString() -ieq $rec.InterfaceGuid});if($a.Count -ne 1){throw 'Adaptador da copia nao encontrado.'};$r=Invoke-LabGuardDnsTool -Modo Restaurar -InterfaceIndex $a[0].ifIndex -ConfirmarAlteracao 6>$null;$out+=@{ok=[bool]$r.Ok;message=[string]$r.Message}}catch{$out+=@{ok=$false;message=$_.Exception.Message}}}};ConvertTo-Json -InputObject @($out) -Depth 5"
        results=self.attempt('Conferir backups DNS/IPv6 da ferramenta de rede',lambda:run_ps(code,timeout=180))
        for result in results or []:
            self.log('DNS/IPv6: '+result.get('message','restaurado'),not result.get('ok'))
        import winreg as reg
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE,r'SOFTWARE\LabGuard\StationDNS') as key:
                raw=reg.QueryValueEx(key,'Pending')[0]
        except FileNotFoundError:
            return
        def station():
            saved=json.loads(raw)
            before=saved['before']
            ipaddress.IPv4Address(before['target']);ipaddress.IPv4Address(saved['listen'])
            for family in ('ipv4','ipv6'):
                family_state=before[family]
                if family_state['mode'] not in ('auto','static') or len(family_state['servers'])>12:
                    raise ValueError('Copia de DNS invalida.')
                for value in family_state['servers']:
                    ipaddress.ip_address(value)
            payload={'action':'restore','target':before['target'],'listen':saved['listen'],'token':'LabGuard-0000000000000000'}
            source=resource('restore-station.ps1').read_text(encoding='utf-8-sig')
            source=source.replace('__PARAMS__',base64.b64encode(json.dumps(payload).encode()).decode())
            result=run_ps(source,timeout=120)
            if not result.get('ok'):
                raise RuntimeError(result.get('message','DNS nao restaurado.'))
        self.attempt('Restaurar DNS configurado pelo painel da estacao',station)

    def stop_config(self):
        import _vendor_labguard_cliente as old
        for entry in self.roots:
            path=Path(entry['path'])
            name=path.name.casefold()
            if name not in ('labguardjogos2','labguardjogos','labguardcliente'):
                continue
            def pause():
                old._lc_secure_chain(path)
                if name=='labguardjogos2' and (path/'config.json').exists():
                    old._lc_guard_file(path/'config.json')
                    config=read_json(path/'config.json')
                    if not isinstance(config,dict):
                        raise ValueError('Configuracao invalida.')
                    for prop in ('Enabled','AutoCloseGames','Screenshots','BlockYouTube'):
                        config[prop]=False
                    old._atomic_json(path/'config.json',config)
                elif name=='labguardcliente':
                    no_links(path/'parar.flag');(path/'parar.flag').write_text('DESINSTALACAO',encoding='ascii')
                elif name=='labguardjogos':
                    no_links(path/'PAUSADO');(path/'PAUSADO').touch()
            self.attempt('Solicitar parada: '+path.name,pause)

    def remove(self):
        self.scan()
        if any(within(str(Path(sys.executable).resolve()),r['path']) for r in self.roots):
            raise RuntimeError('Mova o desinstalador para Downloads antes de executar.')
        self.stop_config()
        result=self.attempt('Parar e remover tarefas, servicos e processos identificados',lambda:operations('Stop',{'roots':self.roots},180))
        for item in result or []:
            self.log(item['message'],not item['ok'])
        self.restore_client()
        self.restore_youtube()
        self.restore_dns()
        result=self.attempt('Remover somente regras locais de firewall do LabGuard',lambda:operations('Firewall',{'roots':self.roots}))
        for item in result or []:
            self.log(item['message'],not item['ok'])
        # Clean loaded and offline profile Run/uninstall keys before deleting their files.
        result=self.attempt('Limpar inicializacao e cadastros das instalacoes',lambda:operations('Registry',{'roots':self.roots,'profiles':self.profiles},180))
        for item in result or []:
            self.log(item['message'],not item['ok'])
        result=self.attempt('Limpar atalhos do LabGuard',lambda:operations('Shortcuts',{'roots':self.roots,'profiles':self.profiles},120))
        for item in result or []:
            self.log(item['message'],not item['ok'])
        self.attempt('Remover credenciais LabGuard do usuario administrativo atual',lambda:operations('Credentials'))
        for entry in sorted(self.roots,key=lambda r:len(r['path']),reverse=True):
            path=Path(entry['path'])
            if str(path).casefold() in self.held:
                self.log('Dados de recuperacao preservados por pendencia: '+str(path),True)
                # Stop executables even when a recovery journal has to remain.
                for name in ('LabGuard-Jogos.exe','LabGuardCliente.exe','LabGuardCliente.py','LabGuardCore.ps1','LabGuard_Remover_Jogos.bat'):
                    target=path/name
                    if target.exists():
                        self.attempt('Remover binario: '+str(target),lambda p=target,r=path:safe_delete(p,r))
                continue
            self.attempt('Remover pasta: '+str(path),lambda p=path:safe_delete(p,p))
        self.attempt('Atualizar cache DNS',lambda:run_ps('Clear-DnsClientCache -ErrorAction Stop; @{ok=$true}|ConvertTo-Json'))
        final=operations('Inventory',{'roots':self.roots})
        if final.get('tasks') or final.get('services') or final.get('processes'):
            self.log('Ainda ha componentes registrados/em execucao. Consulte os itens abaixo e reinicie o Windows antes de repetir.',True)
            for key in ('tasks','services','processes'):
                for item in final.get(key,[]):
                    self.log('Restante: '+str(item.get('TaskName',item.get('Name','componente'))),True)
        remaining=[r['path'] for r in self.roots if Path(r['path']).exists()]
        if remaining:
            self.log('Pastas restantes: '+'; '.join(remaining),True)
        self.log('Nao foram reinstalados jogos ou recuperados saves anteriormente apagados.')
        self.log('Nao foram alterados roteadores, outros computadores, WinRM/SSH ou politicas externas.')
        self.log('Credenciais de outras contas Windows, quando existentes, precisam ser removidas no cofre de cada conta.')
        self.save_report()
        return not self.warnings

    def save_report(self):
        # The report intentionally survives. It contains no passwords or captured screens.
        folder=known_folder(28)/'LabGuard-Desinstalador-Relatorios'
        no_links(folder);folder.mkdir(parents=True,exist_ok=True)
        self.report_path=folder/('remocao-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S')+'.txt')
        self.report_path.write_text('LabGuard Desinstalador '+VERSION+'\n\n'+'\n'.join(self.report)+'\n',encoding='utf-8')


def self_test():
    import hashlib
    import hmac
    import _vendor_labguard_cliente as old
    baseline=b'# escola\r\n127.0.0.1 localhost\r\n192.168.1.3 intranet.escola\r\n'
    block=b'# BEGIN LABGUARD JOGOS YOUTUBE\r\n0.0.0.0 www.youtube.com\r\n::1 www.youtube.com\r\n# END LABGUARD JOGOS YOUTUBE\r\n'
    assert strip_youtube_hosts(baseline+block)==baseline
    assert strip_youtube_hosts(baseline)==baseline
    try: strip_youtube_hosts(baseline+block.replace(b'www.youtube.com',b'intranet.escola'))
    except ValueError: pass
    else: raise AssertionError('Modified hosts block accepted')
    secret='a1'*24
    covered,_,_,_=old._hosts_block(baseline,secret,{'roblox.com'})
    restored,_,_,_=old._hosts_block(covered,secret,set())
    assert restored==baseline
    try: old._hosts_block(covered.replace(b'roblox.com',b'example.com'),secret,set())
    except old._HostsIssue: pass
    else: raise AssertionError('Unauthenticated client hosts block accepted')
    assert within(r'C:\Program Files\LabGuard\app.exe',r'C:\Program Files\LabGuard')
    assert not within(r'C:\Program Files\LabGuardExtra\app.exe',r'C:\Program Files\LabGuard')
    with tempfile.TemporaryDirectory(prefix='lgu-check-') as tmp:
        root=Path(tmp)/'LabGuard';root.mkdir();(root/'item.txt').write_text('fixture')
        safe_delete(root,root);assert not root.exists()
        keep=Path(tmp)/'aula.txt';keep.write_text('must stay')
        root.mkdir()
        try: safe_delete(keep,root)
        except ValueError: pass
        else: raise AssertionError('Out-of-scope deletion accepted')
        assert keep.read_text()=='must stay'
    return 'PASS: hosts YouTube; HMAC do cliente; preservacao da intranet; escopo de caminhos; remocao de arquivos sinteticos.'


class Window(tk.Tk):
    def __init__(self, smoke=False):
        super().__init__()
        self.title('LabGuard | Desinstalador completo')
        self.geometry('860x650');self.minsize(710,530)
        self.configure(bg='#f5f4fa')
        self.queue=queue.Queue();self.busy=False;self.cleaner=Cleaner(self.queue.put)
        style=ttk.Style(self);style.theme_use('clam')
        style.configure('TButton',font=('Segoe UI',10),padding=9)
        top=tk.Frame(self,bg='#31204e',padx=25,pady=22);top.pack(fill='x')
        tk.Label(top,text='LabGuard  /  Desinstalador',bg='#31204e',fg='white',font=('Segoe UI',22,'bold')).pack(anchor='w')
        tk.Label(top,text='Remove as edicoes Windows conhecidas deste computador.',bg='#31204e',fg='#ddd3ed',font=('Segoe UI',11)).pack(anchor='w',pady=(8,0))
        body=tk.Frame(self,bg='#f5f4fa',padx=24,pady=16);body.pack(fill='both',expand=True)
        text='Tarefas, monitor, cliente, painel, servidor, arquivos, configuracoes e capturas.\nRestaura as regras proprias de sites e usa backups do DNS/IPv6 quando disponiveis.\nNao reinstala jogos apagados e nao remove regras de outros administradores.'
        tk.Label(body,text=text,justify='left',anchor='w',bg='#f5f4fa',fg='#30283d',font=('Segoe UI',10),wraplength=790).pack(fill='x')
        bar=tk.Frame(body,bg='#f5f4fa');bar.pack(fill='x',pady=15)
        self.scan_button=ttk.Button(bar,text='1. Conferir instalacoes',command=lambda:self.begin(False));self.scan_button.pack(side='left')
        self.remove_button=ttk.Button(bar,text='2. Desinstalar tudo do LabGuard',command=self.confirm);self.remove_button.pack(side='left',padx=10)
        self.report_button=ttk.Button(bar,text='Ver relatorio',command=self.open_report);self.report_button.pack(side='right')
        self.status=tk.StringVar(value='Pronto. Nenhuma alteracao feita ao abrir esta janela.')
        tk.Label(body,textvariable=self.status,bg='#f5f4fa',fg='#583198',font=('Segoe UI',11,'bold'),anchor='w').pack(fill='x')
        self.progress=ttk.Progressbar(body,mode='indeterminate');self.progress.pack(fill='x',pady=8)
        frame=tk.Frame(body);frame.pack(fill='both',expand=True)
        self.output=tk.Text(frame,wrap='word',font=('Consolas',10),bg='white',fg='#242132',state='disabled')
        scroll=ttk.Scrollbar(frame,command=self.output.yview);self.output.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');self.output.pack(fill='both',expand=True)
        tk.Label(body,text='Execute em cada PC. No PC servidor de DNS, restaure primeiro os clientes dependentes.\nUm relatorio local e eventuais backups com falha de restauracao serao preservados.',bg='#f5f4fa',fg='#62596d',justify='left',font=('Segoe UI',9)).pack(fill='x',pady=(12,0))
        self.after(100,self.poll);self.protocol('WM_DELETE_WINDOW',self.close)
        if smoke:self.after(1600,self.destroy)

    def confirm(self):
        if messagebox.askyesno('Confirmar remocao','Remover todas as instalacoes Windows identificadas do LabGuard neste PC?\n\nInclui configuracoes, bancos de sites, registros e capturas. A protecao sera interrompida.\n\nOutros computadores nao serao alterados. Um relatorio e dados necessarios para corrigir restauracoes pendentes serao preservados.',default='no'):
            self.begin(True)

    def begin(self,remove):
        if self.busy:return
        self.busy=True;self.scan_button.configure(state='disabled');self.remove_button.configure(state='disabled');self.progress.start(12)
        self.status.set('Desinstalando...' if remove else 'Conferindo instalacoes...')
        self.cleaner=Cleaner(self.queue.put)
        def work():
            try:
                ok=self.cleaner.remove() if remove else (self.cleaner.scan() is not None)
                self.queue.put(('done',remove,ok))
            except Exception as error:
                self.cleaner.log(str(error),True)
                try:self.cleaner.save_report()
                except Exception:pass
                self.queue.put(('done',remove,False))
        threading.Thread(target=work,daemon=False).start()

    def poll(self):
        while True:
            try:item=self.queue.get_nowait()
            except queue.Empty:break
            if isinstance(item,tuple):
                _,removed,ok=item;self.busy=False;self.progress.stop();self.scan_button.configure(state='normal');self.remove_button.configure(state='normal')
                self.status.set(('Remocao concluida.' if ok else 'Remocao com pendencias. Veja o relatorio.') if removed else 'Conferencia concluida. Revise os itens acima.')
                if self.cleaner.report_path:self.append('Relatorio: '+str(self.cleaner.report_path))
            else:self.append(item)
        self.after(100,self.poll)

    def append(self,text):
        self.output.configure(state='normal');self.output.insert('end',text+'\n');self.output.see('end');self.output.configure(state='disabled')

    def open_report(self):
        if self.cleaner.report_path:os.startfile(self.cleaner.report_path)
        else:messagebox.showinfo('Relatorio','O relatorio sera criado depois da remocao.')

    def close(self):
        if self.busy:messagebox.showinfo('Em execucao','A operacao esta em execucao. A janela podera ser fechada quando terminar.')
        else:self.destroy()


def main():
    if '--self-test' in sys.argv:
        result=self_test()
        if sys.stdout:print(result)
        if '--result' in sys.argv:
            Path(sys.argv[sys.argv.index('--result')+1]).write_text(result,encoding='utf-8')
        return 0
    if os.name!='nt':raise RuntimeError('Este desinstalador e para Windows 10/11 x64.')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        messagebox.showerror('Autorizacao necessaria','Clique com o botao direito e execute como administrador. O UAC precisa ser autorizado.')
        return 1
    Window(smoke='--ui-smoke' in sys.argv).mainloop()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
