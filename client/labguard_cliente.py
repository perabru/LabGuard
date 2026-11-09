#!/usr/bin/env python3
"""LabGuard Cliente para Windows 10/11 x64. Abra como administrador para instalar.
O cliente usa políticas locais e uma tarefa identificada da escola. Execute
com --help para administração por linha de comando. Requer Python 3.10+ ao
usar o fonte. O executável oficial inclui o interpretador.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager

import contextlib
import hashlib
import hmac
import ntpath
import secrets
import shutil
import stat
import xml.etree.ElementTree as ET

CLIENT_VERSION = "1.0.0"

# Catálogo inicial editável pela TI. Jogos e adultos incluem as regras do painel.
STARTER_DOMAINS = (
    "roblox.com", "rbxcdn.com", "poki.com", "crazygames.com", "friv.com",
    "y8.com", "miniclip.com", "now.gg", "fortnite.com", "minecraft.net",
    "store.steampowered.com", "playvalorant.com", "leagueoflegends.com",
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
    "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com",
    "copilot.microsoft.com", "perplexity.ai", "chat.deepseek.com",
)


def default_policy():
    return {"mode": "bloqueados", "domains": list(STARTER_DOMAINS),
            "allowed_domains": [], "games": list(GAME_IDS),
            "remove_roblox": True, "remove_games": []}


def _domain_names(values):
    if not isinstance(values, list) or len(values) > 350:
        raise ValueError("Informe uma lista com até 350 domínios.")
    names = set()
    for value in values:
        if not isinstance(value, str) or len(value) > 254:
            raise ValueError("Domínio inválido.")
        name = value.strip().lower().removeprefix("*.").removesuffix(".")
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Confira a grafia do domínio.") from None
        parts = name.split(".")
        if (len(name) > 253 or len(parts) < 2 or parts[-1].isdigit()
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in parts)
                or name.endswith((".localhost", ".arpa"))):
            raise ValueError("Digite domínios completos, como roblox.com, sem protocolo ou caminho.")
        names.add(name)
    return sorted(names)


def _id_list(values, available):
    if not isinstance(values, list) or any(not isinstance(g, str) or g not in available for g in values):
        raise ValueError("A política contém um jogo fora do catálogo.")
    return sorted(set(values))


def validate_policy(raw):
    if not isinstance(raw, dict) or set(raw) - set(default_policy()):
        raise ValueError("O arquivo de política tem formato ou campos desconhecidos.")
    policy = default_policy()
    policy["remove_roblox"] = False  # Arquivos parciais não autorizam desinstalação.
    policy.update(raw)
    if policy["mode"] not in ("bloqueados", "permitidos"):
        raise ValueError("Escolha o modo bloqueados ou permitidos.")
    for key in ("domains", "allowed_domains"):
        policy[key] = _domain_names(policy[key])
    if policy["mode"] == "permitidos":
        if not policy["allowed_domains"]:
            raise ValueError("Informe ao menos um domínio permitido antes de ativar o modo de aula.")
        for a in policy["allowed_domains"]:
            if any(a == b or a.endswith("." + b) or b.endswith("." + a) for b in policy["domains"]):
                raise ValueError("Revise os domínios que aparecem simultaneamente nas listas de bloqueio e permissão.")
    policy["games"] = _id_list(policy["games"], GAME_IDS)
    policy["remove_games"] = _id_list(policy["remove_games"], ("minecraft",))
    if type(policy["remove_roblox"]) is not bool:
        raise ValueError("remove_roblox deve ser true ou false.")
    if policy["remove_roblox"] and "roblox" not in policy["games"]:
        raise ValueError("Para remover o Roblox, marque também o bloqueio do Roblox.")
    if set(policy["remove_games"]) - set(policy["games"]):
        raise ValueError("Somente um jogo marcado para bloqueio pode ser removido.")
    return policy


def _json_read(path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Arquivo de configuração ou de estado excedeu o limite.")
    with path.open(encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("Arquivo JSON inválido.")
    return data


def _atomic_json(path, data):
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix="lg-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(6):
            try:
                os.replace(name, path)
                return
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(.12)
    finally:
        Path(name).unlink(missing_ok=True)


def read_policy():
    return validate_policy(_json_read(client_directory() / "politica.json"))


@contextmanager
def _operation_lock(directory, timeout=45):
    import msvcrt
    with (directory / "operacao.lock").open("a+b") as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"L")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Outra operação do LabGuard Cliente ainda está em andamento.") from None
                time.sleep(.2)
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _health_time(stamp):
    try:
        age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(stamp)).total_seconds()
        return 0 <= age <= 180
    except (TypeError, ValueError):
        return False


def _layer(name, func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
        if not isinstance(result, dict) or type(result.get("ok")) is not bool:
            raise ValueError()
        return result
    except Exception as err:
        return {"ok": False, "errors": [f"{name}: {type(err).__name__}. Consulte as permissões e a política."]}


# Ciclo de vida da instalação Windows. Uma tarefa nomeada inicia o cliente no boot.


_LC_NAME = 'LabGuardCliente'
_LC_AUTH = 'LabGuard Cliente escolar'
_LC_RECORD = 'instalacao.json'
_LC_SID_SYSTEM = 'S-1-5-18'
_LC_SID_ADMINS = 'S-1-5-32-544'
_LC_TRUSTED = {_LC_SID_SYSTEM, _LC_SID_ADMINS,
               'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
_LC_KNOWN = {_LC_RECORD, 'politica.json', 'estado.json', 'status.json', 'operacao.lock',
             'parar.flag', 'tarefa.xml', 'LabGuardCliente.exe', 'LabGuardCliente.py'}
_LC_RUN_KEY = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'


def _lc_windows():
    if os.name != 'nt' or sys.maxsize <= 2**32:
        raise RuntimeError('Use o Windows de 64 bits com o cliente EXE ou Python de 64 bits instalado para todos os usuários.')


def require_client_admin():
    _lc_windows()
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('Abra a instalação ou o console da TI como administrador do Windows.')


def client_directory():
    _lc_windows()
    buf = ctypes.create_unicode_buffer(32768)
    # CSIDL_PROGRAM_FILES: shell known folder, not the process environment.
    if ctypes.windll.shell32.SHGetFolderPathW(None, 38, None, 0, buf) or not buf.value:
        raise RuntimeError('O Windows não informou a pasta Arquivos de Programas.')
    return Path(buf.value) / _LC_NAME


def _lc_system():
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf)):
        raise ctypes.WinError()
    return Path(buf.value)


def _lc_run(args, *, timeout=45, check=True, binary_input=None):
    system = _lc_system()
    env = dict(os.environ)
    env['PSModulePath'] = str(system / 'WindowsPowerShell' / 'v1.0' / 'Modules')
    env['PATH'] = os.pathsep.join((str(system), str(system.parent)))
    result = subprocess.run([str(a) for a in args], input=binary_input or b'', capture_output=True,
                            cwd=system, env=env, timeout=timeout, creationflags=0x08000000)
    if check and result.returncode:
        raise RuntimeError(f'O Windows recusou {Path(args[0]).name} (código {result.returncode}).')
    return result


def _lc_is_link(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise RuntimeError('A instalação encontrou um ponto de nova análise. Use uma pasta local protegida.')
    return info


def _lc_no_links(path):
    for item in (path, *path.parents):
        _lc_is_link(item)


def _lc_sid(pointer):
    from ctypes import wintypes
    text = ctypes.c_wchar_p()
    adv = ctypes.windll.advapi32
    if not adv.ConvertSidToStringSidW(ctypes.c_void_p(pointer), ctypes.byref(text)):
        raise ctypes.WinError()
    try:
        return text.value
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _lc_acl(path, *, drive_root=False):
    """Recusa ACLs que permitem escrita por outros usuários, inclusive no runtime de origem."""
    import struct
    adv = ctypes.windll.advapi32
    dacl, owner, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = adv.GetNamedSecurityInfoW(ctypes.c_wchar_p(str(path)), 1, 5, ctypes.byref(owner), None,
                                      ctypes.byref(dacl), None, ctypes.byref(sd))
    if error:
        raise OSError(error, 'Não foi possível conferir as permissões da instalação.')
    try:
        if not dacl.value or not owner.value:
            raise RuntimeError('Pasta sem controle de acesso confiável.')
        owner_sid = _lc_sid(owner.value)
        owner_restricted = False
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        # In the volume root ordinary users may create new folders, but must not be
        # entitled to replace Program Files. Below it all applicable write rights matter.
        write = 0x500d0040 if drive_root else 0x500d0156
        for index in range(count):
            ace = ctypes.c_void_p()
            if not adv.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError()
            kind, flags, size, mask = struct.unpack('<BBHI', ctypes.string_at(ace.value, 8))
            if flags & 8 or kind not in (0, 5, 9, 11):
                continue  # inherit-only or non-allow ACE
            if kind != 0:
                if mask & write:
                    raise RuntimeError('Permissão de escrita condicional não suportada na instalação.')
                continue
            trustee = _lc_sid(ace.value + 8)
            if trustee == 'S-1-3-4':
                owner_restricted = True
            if mask & write and trustee not in _LC_TRUSTED:
                raise RuntimeError(f'Pasta ou arquivo permite escrita sem elevação: {path.name}. Use o instalador em um local protegido.')
        if owner_sid not in _LC_TRUSTED and not owner_restricted:
            raise RuntimeError(f'Proprietário de arquivo fora da administração do sistema: {path.name}. Prefira a edição EXE.')
    finally:
        ctypes.windll.kernel32.LocalFree(sd)


def _lc_secure_chain(path):
    _lc_no_links(path)
    for item in (path, *path.parents):
        _lc_acl(item, drive_root=item == Path(item.anchor))


def _lc_make_directory(path):
    from ctypes import wintypes
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [('nLength', wintypes.DWORD), ('descriptor', ctypes.c_void_p),
                    ('inherit', wintypes.BOOL)]
    sd = ctypes.c_void_p()
    desc = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;OICI;GR;;;OW)'
    adv = ctypes.windll.advapi32
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(desc, 1, ctypes.byref(sd), None):
        raise ctypes.WinError()
    try:
        attrs = SecurityAttributes(ctypes.sizeof(SecurityAttributes), sd, False)
        if not ctypes.windll.kernel32.CreateDirectoryW(str(path), ctypes.byref(attrs)):
            raise ctypes.WinError()
    finally:
        ctypes.windll.kernel32.LocalFree(sd)


@contextlib.contextmanager
def _lc_deployment_lock():
    k = ctypes.windll.kernel32
    k.CreateMutexW.restype = ctypes.c_void_p
    h = k.CreateMutexW(None, False, r'Global\LabGuardCliente-Instalacao-1')
    if not h:
        raise ctypes.WinError()
    handle = ctypes.c_void_p(h)
    try:
        if k.WaitForSingleObject(handle, 10000) not in (0, 0x80):
            raise RuntimeError('Outra operação de instalação ou remoção está em andamento.')
        try:
            yield
        finally:
            k.ReleaseMutex(handle)
    finally:
        k.CloseHandle(handle)


def _lc_guard_file(path):
    info = _lc_is_link(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError(f'Arquivo de instalação inválido ou com vínculo adicional: {path.name}.')
    _lc_acl(path)


def _lc_runtime(directory):
    frozen = bool(getattr(sys, 'frozen', False))
    if frozen:
        return {'mode':'exe', 'copy':'LabGuardCliente.exe',
                'command':str(directory/'LabGuardCliente.exe'), 'user_command':str(directory/'LabGuardCliente.exe')}
    executable = Path(os.path.abspath(sys.executable))
    pf = directory.parent
    if (executable.name.lower() != 'python.exe' or not executable.is_relative_to(pf)
            or Path(sys.base_prefix) != executable.parent or sys.prefix != sys.base_prefix):
        raise RuntimeError('O agente de sistema exige Python de 64 bits instalado para todos em Arquivos de Programas. Outra opção é usar o LabGuardCliente.exe.')
    home = executable.parent
    _lc_secure_chain(home)
    if any(home.glob('*._pth')) or any((x/'pyvenv.cfg').exists() for x in (home,home.parent)):
        raise RuntimeError('Use uma instalação padrão do Python, sem ambiente virtual ou arquivo ._pth.')
    # -I -S excludes site-packages, user site, environment and the script/current
    # directory from sys.path. Validate all files that can supply the core runtime.
    for name in ('python.exe','pythonw.exe','Lib','DLLs'):
        if not (home/name).exists():
            raise RuntimeError('A instalação para todos os usuários do Python está incompleta.')
    for item in home.iterdir():
        if item.suffix.lower() in ('.zip','.dll','.pyd','.exe') or item.name in ('Lib','DLLs'):
            _lc_is_link(item)
            _lc_acl(item)
    for branch in (home/'Lib', home/'DLLs'):
        for base, dirs, files in os.walk(branch):
            if Path(base) == home/'Lib':
                dirs[:] = [name for name in dirs if name.lower() != 'site-packages']
            for name in dirs + files:
                item = Path(base)/name
                _lc_is_link(item)
                _lc_acl(item)
    return {'mode':'py', 'copy':'LabGuardCliente.py', 'command':str(executable),
            'user_command':str(home/'pythonw.exe')}


def _lc_arguments(directory, record, action):
    return subprocess.list2cmdline((['-I','-S','-B',str(directory/'LabGuardCliente.py')]
                                   if record['mode']=='py' else []) + [action])


def _lc_run_string(directory, record):
    result = subprocess.list2cmdline([record['user_command']]) + ' ' + _lc_arguments(directory,record,'usuario')
    if len(result) > 260:
        raise RuntimeError('O caminho instalado excede o limite de inicialização por usuário do Windows.')
    return result


def _lc_user_start(command=None, *, remove=False):
    import winreg
    access = winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY
    if command:
        access |= winreg.KEY_SET_VALUE
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _LC_RUN_KEY, 0, access) as key:
        try:
            value, kind = winreg.QueryValueEx(key,_LC_NAME)
        except FileNotFoundError:
            value, kind = None, None
        if command is not None:
            if value is not None and (kind != winreg.REG_SZ or value != command):
                raise RuntimeError('Já existe uma entrada de inicialização com o nome LabGuardCliente e outro comando.')
            if remove and value is not None:
                winreg.DeleteValue(key,_LC_NAME)
            elif not remove and value is None:
                winreg.SetValueEx(key,_LC_NAME,0,winreg.REG_SZ,command)
        return value


_LC_QUERY_TASK = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$s=New-Object -ComObject Schedule.Service
$s.Connect()
try { $t=$s.GetFolder('\').GetTask('LabGuardCliente') }
catch {
 $e=$_.Exception; while ($null -ne $e) {if ($e.HResult -eq -2147024894){ 'null'; exit 0 }; $e=$e.InnerException}; throw
}
@{xml=[string]$t.Xml;state=[int]$t.State} | ConvertTo-Json -Compress
"""


def _lc_task():
    ps = _lc_system()/'WindowsPowerShell'/'v1.0'/'powershell.exe'
    result = _lc_run([ps,'-NoProfile','-NoLogo','-NonInteractive','-Command',_LC_QUERY_TASK])
    return json.loads(result.stdout.decode('utf-8-sig'))


def _lc_owned_task(task,directory,record):
    if task is None:
        return
    ns = {'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    root = ET.fromstring(task['xml'])
    action = root.find('t:Actions/t:Exec',ns)
    principal = root.findtext('t:Principals/t:Principal/t:UserId','',ns)
    if (record is None or root.findtext('t:RegistrationInfo/t:Author','',ns) != _LC_AUTH
            or principal.upper() not in ('SYSTEM','NT AUTHORITY\\SYSTEM',_LC_SID_SYSTEM)
            or action is None or len(root.find('t:Actions',ns)) != 1
            or Path(action.findtext('t:Command','',ns)) != Path(record['command'])
            or action.findtext('t:Arguments','',ns) != _lc_arguments(directory,record,'worker')
            or Path(action.findtext('t:WorkingDirectory','',ns)) != directory):
        raise RuntimeError('Já existe outra tarefa com o nome LabGuardCliente. A TI deve conferir sua origem.')


def _lc_task_xml(directory,record):
    task = ET.Element('Task', {'version':'1.2','xmlns':'http://schemas.microsoft.com/windows/2004/02/mit/task'})
    def node(parent, tag, value=None, **attrs):
        child = ET.SubElement(parent,tag,attrs)
        if value is not None:
            child.text=value
        return child
    reg=node(task,'RegistrationInfo');node(reg,'Author',_LC_AUTH)
    node(reg,'Description','Aplica as políticas locais de sites e jogos do laboratório. Administração pela TI.')
    trigger=node(node(task,'Triggers'),'BootTrigger');node(trigger,'Enabled','true')
    pr=node(node(task,'Principals'),'Principal',id='SchoolSystem')
    node(pr,'UserId',_LC_SID_SYSTEM);node(pr,'RunLevel','HighestAvailable')
    settings=node(task,'Settings')
    for key,value in [('MultipleInstancesPolicy','IgnoreNew'),('DisallowStartIfOnBatteries','false'),
                      ('StopIfGoingOnBatteries','false'),('StartWhenAvailable','true'),
                      ('Enabled','true'),('Hidden','false'),('ExecutionTimeLimit','PT0S')]:
        node(settings,key,value)
    restart=node(settings,'RestartOnFailure');node(restart,'Interval','PT1M');node(restart,'Count','3')
    act=node(node(task,'Actions',Context='SchoolSystem'),'Exec')
    node(act,'Command',record['command']);node(act,'Arguments',_lc_arguments(directory,record,'worker'))
    node(act,'WorkingDirectory',str(directory))
    return ET.tostring(task,encoding='utf-16',xml_declaration=True)


def _lc_schtasks(*args):
    return _lc_run([_lc_system()/'schtasks.exe',*args])


def _lc_sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def _lc_load(directory):
    _lc_secure_chain(directory)
    for name in _LC_KNOWN:
        target = directory/name
        if os.path.lexists(target):
            _lc_guard_file(target)
    record_path = directory/_LC_RECORD
    if not record_path.exists() or record_path.stat().st_size > 8192:
        raise RuntimeError('Esta pasta já existe sem o registro de instalação do cliente. A TI deve conferir a pasta.')
    record = json.loads(record_path.read_text(encoding='utf-8'))
    if (record.get('owner') != 'LabGuardCliente/1' or record.get('mode') not in ('exe','py')
            or record.get('copy') != ('LabGuardCliente.exe' if record['mode']=='exe' else 'LabGuardCliente.py')):
        raise RuntimeError('Registro de instalação incompatível.')
    exe,user = Path(record['command']),Path(record['user_command'])
    if record['mode']=='exe':
        valid=exe==user==directory/'LabGuardCliente.exe'
    else:
        valid=(exe.name.lower()=='python.exe' and exe.is_relative_to(directory.parent)
               and user==exe.with_name('pythonw.exe'))
    if not valid:
        raise RuntimeError('O caminho do programa instalado é inválido.')
    return record


def _lc_executable_source():
    return Path(os.path.abspath(sys.executable if getattr(sys,'frozen',False) else __file__))


def install_client(initialize):
    require_client_admin()
    with _lc_deployment_lock():
        directory=client_directory()
        if ctypes.windll.kernel32.GetDriveTypeW(str(directory.anchor)) != 3:
            raise RuntimeError('Use um volume local fixo para instalar o cliente.')
        _lc_secure_chain(directory.parent)
        fresh=not os.path.lexists(directory)
        task=_lc_task()
        run=_lc_user_start()
        if fresh and (task is not None or run is not None):
            raise RuntimeError('Já existe uma inicialização LabGuardCliente sem registro local da instalação.')
        candidate=_lc_runtime(directory)
        src=_lc_executable_source()
        digest=_lc_sha(src)
        if not fresh:
            existing=_lc_load(directory)
            if any(existing[k]!=candidate[k] for k in candidate) or existing['sha256']!=digest:
                raise RuntimeError('Há outra versão instalada. Remova-a pela TI antes de trocar o programa.')
            copy=directory/existing['copy']
            if _lc_sha(copy)!=digest:
                raise RuntimeError('O programa instalado mudou. Confira a instalação antes de continuar.')
            _lc_owned_task(task,directory,existing)
        record=dict(candidate,owner='LabGuardCliente/1',sha256=digest)
        run_command=_lc_run_string(directory,record)
        if run is not None and run!=run_command:
            raise RuntimeError('A entrada de inicialização pertence a outro programa.')
        created_task=created_run=False
        if fresh:
            _lc_make_directory(directory)
        try:
            if fresh:
                dest=directory/record['copy']
                with src.open('rb') as anchor, dest.open('xb') as output:
                    shutil.copyfileobj(anchor,output)
                if _lc_sha(dest)!=digest:
                    raise RuntimeError('O programa de origem mudou durante a cópia.')
                (directory/_LC_RECORD).write_text(json.dumps(record,ensure_ascii=False),encoding='utf8')
                _lc_load(directory)
            initialize(directory)
            (directory/'parar.flag').unlink(missing_ok=True)
            if task is None:
                xml=directory/'tarefa.xml'
                xml.write_bytes(_lc_task_xml(directory,record))
                try:
                    _lc_schtasks('/Create','/TN',_LC_NAME,'/XML',xml)
                    created_task=True
                finally:
                    xml.unlink(missing_ok=True)
            if run is None:
                _lc_user_start(run_command)
                created_run=True
            _lc_schtasks('/Run','/TN',_LC_NAME)
        except Exception:
            if created_task:
                _lc_schtasks('/Delete','/F','/TN',_LC_NAME)
            if created_run:
                _lc_user_start(run_command,remove=True)
            if fresh:
                for name in _LC_KNOWN:
                    (directory/name).unlink(missing_ok=True)
                directory.rmdir()
            raise
        return {'ok':True,'installed':True,'task':_LC_NAME,'directory':str(directory),
                'message':'Inicialização solicitada. Consulte o status para confirmar os controles aplicados.'}


def client_runtime_guard():
    require_client_admin()
    directory=client_directory()
    record=_lc_load(directory)
    if _lc_executable_source()!=directory/record['copy']:
        raise RuntimeError('O modo worker pertence à cópia instalada pela TI.')
    who=_lc_run([_lc_system()/'whoami.exe','/user','/fo','csv','/nh']).stdout
    if b'"S-1-5-18"' not in who:
        raise RuntimeError('A tarefa do Windows deve executar o worker como SYSTEM.')
    return directory


def client_task_status():
    directory=client_directory()
    if not os.path.lexists(directory):
        return {'installed':False,'running':False,'directory':str(directory)}
    record=_lc_load(directory)
    task=_lc_task()
    _lc_owned_task(task,directory,record)
    return {'installed':True,'running':bool(task and task['state']==4),
            'task_registered':task is not None,'user_start':_lc_user_start()==_lc_run_string(directory,record),
            'directory':str(directory)}


def uninstall_client(undo):
    require_client_admin()
    with _lc_deployment_lock():
        directory=client_directory()
        if not os.path.lexists(directory):
            if _lc_task() is not None or _lc_user_start() is not None:
                raise RuntimeError('Há uma inicialização com esse nome sem registro de instalação. Confira na TI.')
            return {'ok':True,'installed':False}
        record=_lc_load(directory)
        if record['mode']=='exe' and _lc_executable_source()==directory/record['copy']:
            raise RuntimeError('Feche a cópia instalada e use Remover na cópia baixada do cliente.')
        task=_lc_task()
        _lc_owned_task(task,directory,record)
        run_command=_lc_run_string(directory,record)
        _lc_user_start(run_command,remove=True)
        (directory/'parar.flag').write_text('TI',encoding='ascii')
        if task:
            if task['state'] in (2,4):
                until=time.monotonic()+6
                while time.monotonic()<until and (_lc_task() or {}).get('state') in (2,4):
                    time.sleep(.35)
                if (_lc_task() or {}).get('state') in (2,4):
                    _lc_schtasks('/End','/TN',_LC_NAME)
                until=time.monotonic()+12
                while (_lc_task() or {}).get('state') in (2,4):
                    if time.monotonic()>=until:
                        raise RuntimeError('A tarefa ainda está parando. Repita a remoção quando ela encerrar.')
                    time.sleep(.5)
            _lc_schtasks('/Delete','/F','/TN',_LC_NAME)
        undo(directory)
        # Remove only our named artifacts; keep record until all other deletions succeed.
        for name in sorted(_LC_KNOWN-{_LC_RECORD}):
            item=directory/name
            if os.path.lexists(item):
                _lc_guard_file(item)
                item.unlink()
        leftovers=[p.name for p in directory.iterdir() if p.name!=_LC_RECORD]
        (directory/_LC_RECORD).unlink()
        if not leftovers:
            directory.rmdir()
        return {'ok':True,'installed':False,'files_preserved':len(leftovers),
                'message':'Tarefa e inicialização removidas; as políticas gerenciadas foram restauradas.'}


# Mandatory Windows browser policies. Browser URL filters also match subdomains.
# https://learn.microsoft.com/deployedge/microsoft-edge-policies/urlblocklist
# https://support.google.com/chrome/a/answer/9942583
# https://firefox-admin-docs.mozilla.org/reference/policies/websitefilter/
_BROWSER_POLICIES = {
    "Edge": (r"SOFTWARE\Policies\Microsoft\Edge", "URLBlocklist", "URLAllowlist"),
    "Chrome": (r"SOFTWARE\Policies\Google\Chrome", "URLBlocklist", "URLAllowlist"),
    "Firefox": (r"SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter", "Block", "Exceptions"),
}
_BROWSER_LIMIT = 1000


def _site_domains(values):
    import ipaddress
    import re

    if not isinstance(values, (list, tuple)):
        raise ValueError("A lista de domínios de navegação é inválida.")
    cleaned = set()
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 254:
            raise ValueError("Informe nomes de domínio, sem caminhos ou curingas.")
        host = value.strip().rstrip(".").lower()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Nome de domínio inválido.") from None
        if (len(host) > 253 or "." not in host or
                not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in host.split(".")) or host.rsplit(".", 1)[-1].isdigit()):
            raise ValueError("Use um domínio completo, como exemplo.org.br.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            cleaned.add(host)
        else:
            raise ValueError("A política de navegação requer um domínio, não um IP.")
    if len(cleaned) > _BROWSER_LIMIT:
        raise ValueError("O navegador aceita até 1000 entradas por lista.")
    return sorted(cleaned)


class _BrowserRegistry:
    def __init__(self):
        import winreg
        self.reg = winreg
        self.string_type = winreg.REG_SZ

    def _open(self, path, write=False):
        r = self.reg
        access = r.KEY_READ | r.KEY_WOW64_64KEY
        if write:
            access |= r.KEY_SET_VALUE
        return r.OpenKey(r.HKEY_LOCAL_MACHINE, path, 0, access)

    def inspect(self, path):
        try:
            key = self._open(path)
        except FileNotFoundError:
            return False, {}
        with key:
            count = self.reg.QueryInfoKey(key)[1]
            items = {}
            for i in range(count):
                name, value, kind = self.reg.EnumValue(key, i)
                items[name] = (value, kind)
            return True, items

    def add_if_free(self, path, slot, text):
        r = self.reg
        with r.CreateKeyEx(r.HKEY_LOCAL_MACHINE, path, 0,
                           r.KEY_READ | r.KEY_SET_VALUE | r.KEY_WOW64_64KEY) as key:
            try:
                r.QueryValueEx(key, slot)
            except FileNotFoundError:
                r.SetValueEx(key, slot, 0, r.REG_SZ, text)
                return
            raise OSError("A lista do navegador mudou durante a aplicação. Tente novamente.")

    def replace_if_same(self, path, slot, expected, new):
        with self._open(path, write=True) as key:
            if self.reg.QueryValueEx(key, slot) != (expected, self.string_type):
                raise OSError("A lista do Firefox mudou durante a atualização.")
            self.reg.SetValueEx(key, slot, 0, self.string_type, new)

    def remove_if_same(self, path, slot, expected):
        try:
            with self._open(path, write=True) as key:
                if self.reg.QueryValueEx(key, slot) == (expected, self.string_type):
                    self.reg.DeleteValue(key, slot)
        except FileNotFoundError:
            pass

    def remove_if_empty(self, path):
        try:
            with self._open(path) as key:
                subkeys, values, _ = self.reg.QueryInfoKey(key)
            if not subkeys and not values:
                self.reg.DeleteKeyEx(self.reg.HKEY_LOCAL_MACHINE, path, self.reg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            pass


def _valid_browser_slot(slot):
    return (isinstance(slot, str) and slot.isascii() and slot.isdecimal()
            and len(slot) <= 4 and 1 <= int(slot) <= _BROWSER_LIMIT and str(int(slot)) == slot)


def _reconcile_browser_list(registry, path, desired, records, checkpoint, *, firefox=False):
    """Journal before writes. Only revert a value that still equals our saved value."""
    exists, current = registry.inspect(path)
    if not desired and not records:
        return {"entries": 0, "external": len(current), "extra": len(current)}
    owned = records.setdefault("owned", {})
    if not isinstance(owned, dict) or any(not _valid_browser_slot(k) or not isinstance(v, str)
                                          for k, v in owned.items()):
        raise ValueError("Registro de propriedade das regras de navegação inválido.")
    pending = records.get("replacement")
    if pending is not None:
        if not isinstance(pending, list) or len(pending) != 2 or not all(isinstance(v, str) for v in pending):
            raise ValueError("Registro de atualização de navegação inválido.")
        if current.get("1") == (pending[1], registry.string_type):
            owned["1"] = pending[1]
        del records["replacement"]
        checkpoint()
    inactive = []
    for slot, previous in list(owned.items()):
        if current.get(slot) != (previous, registry.string_type):
            # A GPO or another administrator changed the policy, or an interrupted
            # write left only a journal record. Never overwrite a replaced value.
            del owned[slot]
        elif previous not in desired:
            inactive.append(slot)
    checkpoint()
    available = set(str(i) for i in range(1, _BROWSER_LIMIT + 1))
    external = {k: v for k, v in current.items() if k not in owned}
    existing = {value for key, (value, kind) in current.items()
                if _valid_browser_slot(key) and kind == registry.string_type}
    missing = [value for value in desired if value not in existing]
    free = sorted(available - current.keys(), key=int)
    if desired and len(current) - len(inactive) + len(missing) > _BROWSER_LIMIT:
        raise ValueError("A lista do navegador excederia 1000 entradas. Revise as políticas existentes.")
    if firefox and desired and external and (next(iter(current), "1") != "1" or
            any(not _valid_browser_slot(k) or v[1] != registry.string_type for k, v in external.items())):
        raise ValueError("A lista existente do Firefox tem formato incompatível. Revise a política institucional.")

    # Preserve key 1 in a nonempty Firefox list: its Windows parser requires the
    # first enumerated value to be named "1". Never change an unrelated value.
    if firefox and "1" in inactive and (desired or external):
        if missing:
            replacement = missing.pop(0)
        elif desired:
            replacement = desired[0]
        else:
            replacement = next((value for value, kind in external.values()
                                if kind == registry.string_type and isinstance(value, str)), None)
        if replacement is None:
            raise ValueError("A TI deve revisar o formato da lista de políticas do Firefox.")
        old_value = owned["1"]
        # Replace in place (delete/recreate would also move the first index).
        records["replacement"] = [old_value, replacement]
        checkpoint()
        registry.replace_if_same(path, "1", old_value, replacement)
        owned["1"] = replacement
        del records["replacement"]
        checkpoint()
        current["1"] = (replacement, registry.string_type)
        if not desired:
            # On removal, the remaining institutional filter needs this first
            # slot as a duplicate of an existing external rule.
            del owned["1"]
            checkpoint()
        inactive.remove("1")

    def remove(slot):
        registry.remove_if_same(path, slot, owned[slot])
        del owned[slot]
        checkpoint()

    # Keep still-protective old rules until additions are accepted when possible.
    while len(free) < len(missing):
        if not inactive:
            raise ValueError("Não há posições livres na lista do navegador.")
        reuse = inactive.pop()
        remove(reuse)
        free.append(reuse)
    if missing and not exists:
        records["created"] = True
        checkpoint()
    for slot, value in zip(free, missing):
        owned[slot] = value
        checkpoint()
        registry.add_if_free(path, slot, value)
    for slot in inactive:
        remove(slot)
    if not owned and records.get("created"):
        registry.remove_if_empty(path)
        records.pop("created", None)
        checkpoint()
    _, observed = registry.inspect(path)
    rules = {value for key, (value, kind) in observed.items()
             if _valid_browser_slot(key) and kind == registry.string_type}
    if firefox and desired and next(iter(observed), None) != "1":
        raise ValueError("O Firefox exige que a primeira entrada seja 1. Confira a lista no Registro.")
    if any(value not in rules for value in desired):
        raise OSError("O Windows não confirmou todas as entradas da política de navegação.")
    extra = sum(1 for value, kind in external.values() if kind != registry.string_type or value not in desired)
    return {"entries": len(desired), "external": len(external), "extra": extra}


def _browser_patterns(browser, domains):
    if browser == "Firefox":
        return [f"*://*.{domain}/*" for domain in domains]
    return list(domains)


def _browser_policy_run(policy, state, checkpoint, registry, removing=False):
    mode = policy.get("mode", "bloqueados")
    if mode not in ("bloqueados", "permitidos"):
        raise ValueError("Modo de proteção de sites inválido.")
    strict = mode == "permitidos" and not removing
    domains = [] if removing else _site_domains(policy.get("domains", []))
    allowed = _site_domains(policy.get("allowed_domains", [])) if strict else []
    if strict and not allowed:
        raise ValueError("Cadastre ao menos um domínio escolar antes de usar somente permitidos.")
    saved = state.setdefault("sites", {})
    result = {"ok": True, "mode": mode, "browsers": {}, "warnings": []}
    for browser, (base, block_key, allow_key) in _BROWSER_POLICIES.items():
        if removing and browser not in saved:
            continue
        pair = saved.setdefault(browser, {})
        block = ["<all_urls>" if browser == "Firefox" else "*"] if strict else _browser_patterns(browser, domains)
        allow = _browser_patterns(browser, allowed)
        lists = {"block": (block_key, block), "allow": (allow_key, allow)}
        report = {}
        try:
            # On entering strict mode, install permitted learning sites before *
            # takes effect. Leave strict mode by removing * before its exceptions.
            for name in (("allow", "block") if strict else ("block", "allow")):
                key, entries = lists[name]
                scope = pair.setdefault(name, {})
                report[name] = _reconcile_browser_list(registry, base + "\\" + key, entries,
                                                       scope, checkpoint, firefox=browser == "Firefox")
                if not scope.get("owned") and not scope.get("created"):
                    pair.pop(name, None)
            report["ok"] = True
            if report["allow"]["extra"] and not removing:
                result["warnings"].append(browser + ": há exceções externas. Confira a política efetiva no navegador.")
                if strict:
                    report["ok"] = False
                    report["error"] = "Há permissões externas além da lista escolar. Revise as exceções na TI."
                    result["ok"] = False
        except (OSError, ValueError) as exc:
            report.update(ok=False, error=str(exc))
            result["ok"] = False
        result["browsers"][browser] = report
        if not pair:
            saved.pop(browser, None)
    checkpoint()
    return result


def sync_sites(policy, state, *, checkpoint):
    return _browser_policy_run(policy, state, checkpoint, _BrowserRegistry())


def undo_sites(state, *, checkpoint):
    return _browser_policy_run({}, state, checkpoint, _BrowserRegistry(), removing=True)


# Managed system resolver entries. Windows hosts supports exact names, not wildcards.


_HOSTS_LIMIT = 16 * 1024 * 1024
_HOSTS_BOM = b"\xef\xbb\xbf"
_HOSTS_PREFIX = b"# LabGuard Cliente / hosts / "
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ROBLOX_ENDPOINTS = ("api", "apis", "assetdelivery", "auth", "clientsettings",
                     "clientsettingscdn", "gamejoin", "games", "setup", "setup-cfly", "users")


class _HostsIssue(Exception):
    """Fixed operator-facing messages for incomplete ownership or conflicts."""


def _hosts_names(policy):
    names = set()
    for domain in policy["domains"]:
        labels = domain.split(".")
        if (len(labels) < 2 or len(domain) > 253
                or not all(_HOST_LABEL.fullmatch(label) for label in labels)):
            raise _HostsIssue("Domínio inválido para o resolvedor local.")
        names.add(domain)
        if not domain.startswith("www.") and len(domain) <= 249:
            names.add("www." + domain)
        if domain == "roblox.com":
            names.update(label + ".roblox.com" for label in _ROBLOX_ENDPOINTS)
    return names


def _hosts_block(data, secret, requested):
    if len(data) > _HOSTS_LIMIT or b"\x00" in data:
        raise _HostsIssue("O hosts tem tamanho ou codificação incompatível. A TI deve revisá-lo.")
    key = bytes.fromhex(secret)
    ident = hashlib.sha256(key).hexdigest()[:16].encode()
    begin = _HOSTS_PREFIX + b"inicio " + ident + b" "
    end = _HOSTS_PREFIX + b"fim " + ident
    bom = _HOSTS_BOM if data.startswith(_HOSTS_BOM) else b""
    lines = data[len(bom):].splitlines(keepends=True)
    markers = [i for i, line in enumerate(lines) if line.startswith(_HOSTS_PREFIX)]
    had_block = bool(markers)
    if had_block:
        if (len(markers) != 2 or not lines[markers[0]].startswith(begin)
                or lines[markers[1]].rstrip(b"\r\n") != end):
            raise _HostsIssue("O hosts contém marcadores conflitantes. Revise o arquivo antes de continuar.")
        a, b = markers
        digest = lines[a].rstrip(b"\r\n")[len(begin):]
        payload = b"".join(lines[a + 1:b])
        if not hmac.compare_digest(hmac.new(key, payload, hashlib.sha256).hexdigest().encode(), digest):
            raise _HostsIssue("O trecho gerenciado do hosts foi editado. Revise-o para preservar as alterações.")
        del lines[a:b + 1]

    conflicts = set()
    for line in lines:
        fields = line.split(b"#", 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            ip = ipaddress.ip_address(fields[0].decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            continue
        if ip.is_unspecified or ip.is_loopback:
            continue
        for value in fields[1:]:
            label = value.rstrip(b".").lower()
            if label.isascii() and label.decode() in requested:
                conflicts.add(label.decode())
    active = sorted(requested - conflicts)
    rest = b"".join(lines)
    if not active:
        return bom + rest, len(active), len(conflicts), had_block
    newline = b"\n" if b"\n" in rest and b"\r\n" not in rest else b"\r\n"
    payload = b"".join(ip + b" " + name.encode("ascii") + newline
                       for name in active for ip in (b"0.0.0.0", b"::"))
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest().encode()
    return bom + begin + signature + newline + payload + end + newline + rest, len(active), len(conflicts), had_block


def _hosts_location():
    import winreg
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    buf = ctypes.create_unicode_buffer(32768)
    size = kernel.GetSystemDirectoryW(buf, len(buf))
    if not 0 < size < len(buf):
        raise ctypes.WinError(ctypes.get_last_error())
    system = Path(buf.value)
    parent = system / "drivers" / "etc"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as key:
        try:
            raw, _ = winreg.QueryValueEx(key, "DataBasePath")
        except FileNotFoundError:
            raw = str(parent)
    # Never write via a custom registry path, environment-controlled temp directory or junction.
    pattern = re.compile(r"^(?:%systemroot%|%windir%|\\systemroot)(?=\\)", re.I)
    resolved = pattern.sub(lambda _: str(system.parent), str(raw))
    if os.path.normcase(os.path.normpath(resolved)) != os.path.normcase(str(parent)):
        raise _HostsIssue("O Windows usa um diretório hosts personalizado. Revise-o pela gestão da escola.")
    for directory in (parent, parent.parent, system, system.parent):
        if directory.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise _HostsIssue("O diretório de hosts é um redirecionamento. A edição foi interrompida.")
    return kernel, parent / "hosts", system


@contextlib.contextmanager
def _hosts_read_locked(kernel, path):
    import msvcrt
    from ctypes import wintypes as wt
    open_file = kernel.CreateFileW
    open_file.argtypes = (wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE)
    open_file.restype = wt.HANDLE
    # Allow readers and rename-based replacement, refuse concurrent in-place writers.
    handle = open_file(str(path), 0x80000000, 1 | 4, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        code = ctypes.get_last_error()
        if code == 2:
            yield None
            return
        raise ctypes.WinError(code)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(wt.HANDLE(handle))
        raise
    with os.fdopen(fd, "rb") as src:
        info = os.fstat(src.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise _HostsIssue("O hosts é um vínculo ou arquivo especial. A edição foi interrompida.")
        data = src.read(_HOSTS_LIMIT + 1)
        if len(data) > _HOSTS_LIMIT:
            raise _HostsIssue("O hosts excede o limite de edição. Revise-o antes de prosseguir.")
        yield data


def _hosts_sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _hosts_apply_file(kernel, path, backup, old, new, remove_empty):
    from ctypes import wintypes as wt
    if remove_empty:
        os.rename(path, backup)
        return
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(prefix="labguard-cliente-", suffix=".tmp", dir=path.parent,
                                         delete=False) as out:
            tmp = Path(out.name)
            out.write(new)
            out.flush()
            os.fsync(out.fileno())
        if old is None:
            os.rename(tmp, path)  # On Windows, an existing destination is never replaced.
        else:
            replace = kernel.ReplaceFileW
            replace.argtypes = (wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, wt.LPVOID, wt.LPVOID)
            replace.restype = wt.BOOL
            if not replace(str(path), str(tmp), str(backup), 0, None, None):
                code = ctypes.get_last_error()
                # ReplaceFile may leave the original under the backup name on selected errors.
                if not path.exists() and backup.exists():
                    os.rename(backup, path)
                raise ctypes.WinError(code)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def _manage_hosts(policy, state, checkpoint, removing):
    out = {"ok": False, "changed": False, "blocked_names": 0, "conflicts": 0, "errors": []}
    try:
        record = state.get("system_hosts")
        if record is None and removing:
            out["ok"] = True
            return out
        kernel, path, system = _hosts_location()
        requested = set() if removing else _hosts_names(policy)
        if record is None:
            record = {"secret": secrets.token_hex(24), "created": False}
            state["system_hosts"] = record
            checkpoint()
        if not isinstance(record, dict) or not re.fullmatch(r"[a-f0-9]{48}", str(record.get("secret", ""))):
            raise _HostsIssue("O registro de propriedade do hosts está inválido. Revise a instalação.")
        secret = record["secret"]
        ident = hashlib.sha256(bytes.fromhex(secret)).hexdigest()[:16]
        backup = path.with_name("hosts.labguard-" + ident + ".bak")
        if backup.exists():
            with _hosts_read_locked(kernel, backup) as saved:
                if not path.exists():
                    os.rename(backup, path)
                elif saved is None or _hosts_sha(saved) != record.get("before"):
                    raise _HostsIssue("Edição simultânea do hosts. A cópia hosts.labguard-*.bak foi preservada para a TI.")
                else:
                    backup.unlink()
        with _hosts_read_locked(kernel, path) as data:
            desired, count, conflicts, owned = _hosts_block(data or b"", secret, requested)
            out.update(blocked_names=count, conflicts=conflicts)
            erase = removing and owned and record.get("created") and not desired
            if desired != (data or b"") or erase:
                if data is None:
                    record["created"] = True
                record["before"] = _hosts_sha(data)
                checkpoint()  # Durable ownership and expected original before a host replacement.
                _hosts_apply_file(kernel, path, backup, data, desired, erase)
                out["changed"] = True
        if backup.exists():
            with _hosts_read_locked(kernel, backup) as saved:
                if saved is None or _hosts_sha(saved) != record.get("before"):
                    if not path.exists():
                        os.rename(backup, path)
                    raise _HostsIssue("O hosts foi alterado durante a atualização. Confira o arquivo e a cópia hosts.labguard-*.bak.")
                backup.unlink()
        if out["changed"]:
            command = [str(system / "ipconfig.exe"), "/flushdns"]
            result = subprocess.run(command, cwd=system, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=12, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                out["errors"].append("O hosts foi atualizado. O Windows não confirmou a limpeza do cache DNS.")
        if conflicts:
            out["errors"].append("Há nomes com endereço próprio no hosts da escola. Revise os conflitos na configuração local.")
        if removing:
            del state["system_hosts"]
            checkpoint()
        out["ok"] = not out["errors"]
    except _HostsIssue as e:
        out["errors"].append(str(e))
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        code = getattr(e, "winerror", None)
        out["errors"].append("O Windows não confirmou o hosts. Confira permissões, bloqueios de edição e o estado local."
                             + (f" Código {code}." if isinstance(code, int) else ""))
    return out


def sync_system_sites(policy, state, *, checkpoint):
    return _manage_hosts(policy, state, checkpoint, False)


def undo_system_sites(state, *, checkpoint):
    return _manage_hosts({}, state, checkpoint, True)


# Bloqueio local de jogos e desinstalação de pacotes de identidade conhecida.
# Processos são examinados por nome e localização/família. Não lemos argumentos,
# documentos, históricos ou processos do aluno fora do catálogo abaixo.

GAME_IDS = ('roblox', 'minecraft', 'fortnite', 'valorant', 'league', 'cs2', 'genshin')
_GAME_IMAGES = {
    'robloxplayerbeta.exe': 'roblox', 'robloxplayer.exe': 'roblox',
    'robloxgameclient.exe': 'roblox', 'windows10universal.exe': 'roblox',
    'minecraft.windows.exe': 'minecraft', 'fortniteclient-win64-shipping.exe': 'fortnite',
    'valorant-win64-shipping.exe': 'valorant', 'league of legends.exe': 'league',
    'cs2.exe': 'cs2', 'genshinimpact.exe': 'genshin',
}
_ROBLOX_FAMILIES = {'robloxcorporation.roblox_55nm5eh3cm0pr',
                    'robloxcorporation.robloxgdk_55nm5eh3cm0pr'}
_GAME_IMAGE_SUFFIX = {
    'fortnite': r'\fortnitegame\binaries\win64\fortniteclient-win64-shipping.exe',
    'valorant': r'\shootergame\binaries\win64\valorant-win64-shipping.exe',
    'league': r'\league of legends\game\league of legends.exe',
    'cs2': r'\game\bin\win64\cs2.exe',
    'genshin': r'\genshin impact game\genshinimpact.exe',
}


def _game_from_image(image_path, package_family=''):
    """O nome genérico Windows10Universal e o Java nunca identificam um jogo por si só."""
    path = ntpath.normpath(image_path).casefold()
    name = ntpath.basename(path)
    game = _GAME_IMAGES.get(name)
    family = package_family.casefold()
    if game == 'roblox':
        if family in _ROBLOX_FAMILIES:
            return game
        if name != 'windows10universal.exe' and re.search(r'\\(?:roblox|bloxstrap|fishstrap)\\versions\\version-[0-9a-f]{8,64}\\[^\\]+$', path):
            return game
    elif game == 'minecraft':
        if family == 'microsoft.minecraftuwp_8wekyb3d8bbwe':
            return game
    elif game and path.endswith(_GAME_IMAGE_SUFFIX[game]):
        return game
    return None


def _game_kernel():
    from ctypes import wintypes as w
    k = ctypes.WinDLL('kernel32', use_last_error=True)

    class ProcessEntry(ctypes.Structure):
        _fields_ = [('dwSize', w.DWORD), ('cntUsage', w.DWORD), ('pid', w.DWORD),
                    ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', w.DWORD),
                    ('cntThreads', w.DWORD), ('parentPid', w.DWORD),
                    ('pcPriClassBase', w.LONG), ('dwFlags', w.DWORD),
                    ('image', w.WCHAR * 260)]

    def bind(name, result, *arguments):
        fn = getattr(k, name)
        fn.restype = result
        fn.argtypes = list(arguments)

    bind('CreateToolhelp32Snapshot', w.HANDLE, w.DWORD, w.DWORD)
    bind('Process32FirstW', w.BOOL, w.HANDLE, ctypes.POINTER(ProcessEntry))
    bind('Process32NextW', w.BOOL, w.HANDLE, ctypes.POINTER(ProcessEntry))
    bind('OpenProcess', w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
    bind('ProcessIdToSessionId', w.BOOL, w.DWORD, ctypes.POINTER(w.DWORD))
    bind('QueryFullProcessImageNameW', w.BOOL, w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
    bind('GetPackageFamilyName', w.LONG, w.HANDLE, ctypes.POINTER(w.UINT), w.LPWSTR)
    bind('TerminateProcess', w.BOOL, w.HANDLE, w.UINT)
    bind('CloseHandle', w.BOOL, w.HANDLE)
    return k, ProcessEntry


def _game_check_process(k, pid, selected):
    """Pin the process once, then verify the live executable before termination."""
    from ctypes import wintypes as w
    handle = k.OpenProcess(0x1000 | 0x0001, False, pid)  # query limited + terminate
    if not handle:
        return 'gone' if ctypes.get_last_error() in (87, 1168) else 'failed'
    try:
        sid = w.DWORD()
        if not k.ProcessIdToSessionId(pid, ctypes.byref(sid)):
            return 'failed'
        if sid.value == 0:
            return 'skip'
        image = ctypes.create_unicode_buffer(32768)
        n = w.DWORD(len(image))
        if not k.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(n)):
            return 'failed'
        family = ctypes.create_unicode_buffer(256)
        n_family = w.UINT(len(family))
        if k.GetPackageFamilyName(handle, ctypes.byref(n_family), family) != 0:
            family.value = ''
        game = _game_from_image(image.value, family.value)
        if game not in selected:
            return 'skip'
        return 'stopped' if k.TerminateProcess(handle, 1) else 'failed'
    finally:
        k.CloseHandle(handle)


def _enforce_game_processes(selected):
    if not selected:
        return {'ok': True, 'stopped': 0, 'failures': 0}
    k, Entry = _game_kernel()
    snapshot = k.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError('O inventário de processos está indisponível.')
    stopped = failures = 0
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(entry)
        more = k.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            if _GAME_IMAGES.get(entry.image.casefold()) in selected:
                result = _game_check_process(k, entry.pid, selected)
                stopped += int(result == 'stopped')
                failures += int(result == 'failed')
            more = k.Process32NextW(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            failures += 1
    finally:
        k.CloseHandle(snapshot)
    return {'ok': failures == 0, 'stopped': stopped, 'failures': failures}


def _games_system_windows():
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    buffer = ctypes.create_unicode_buffer(32768)
    length = k.GetSystemWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError('Diretório do Windows indisponível.')
    return buffer.value


def _games_ps(script, timeout):
    """Execute only built-in, fixed source with the system PowerShell and modules."""
    import base64
    win = _games_system_windows()
    system = os.path.join(win, 'System32')
    exe_dir = os.path.join(system, 'WindowsPowerShell', 'v1.0')
    exe = os.path.join(exe_dir, 'powershell.exe')
    if ctypes.sizeof(ctypes.c_void_p) == 4 and os.path.isdir(os.path.join(win, 'Sysnative')):
        exe = os.path.join(win, 'Sysnative', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    env = dict(os.environ)
    env['PSModulePath'] = os.path.join(exe_dir, 'Modules')
    env['PATH'] = os.pathsep.join((system, win, exe_dir))
    source = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " \
             "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n" + script
    data = base64.b64encode(source.encode('utf-16le')).decode('ascii')
    try:
        result = subprocess.run([exe, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', data],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                creationflags=subprocess.CREATE_NO_WINDOW, cwd=system, env=env,
                                check=False, timeout=timeout)
        if result.returncode or len(result.stdout) > 8192:
            raise ValueError('resultado inválido')
        response = json.loads(result.stdout.decode('utf-8-sig'))
        if not isinstance(response, dict) or type(response.get('ok')) is not bool:
            raise ValueError('resultado inválido')
        return response
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {'ok': False, 'status': 'sem_confirmacao'}


_GAME_STORE_SCRIPT = r"""
$ids = @()
__CATALOG__
$removed = 0; $remaining = 0; $failed = 0
foreach ($spec in $ids) {
    try {
        function Get-Parents {
            $packs = @(Get-AppxPackage -AllUsers -Name $spec.Name -PackageTypeFilter Bundle)
            if ($packs.Count -eq 0) { $packs = @(Get-AppxPackage -AllUsers -Name $spec.Name -PackageTypeFilter Main) }
            $packs
        }
        $parents = @(Get-Parents)
        foreach ($pkg in $parents) {
            if ($pkg.Name -ine $spec.Name -or $pkg.PackageFamilyName -ine ($spec.Name+'_'+$spec.Id) -or
                $pkg.Publisher -ine $spec.Publisher -or $pkg.PublisherId -cne $spec.Id -or
                $pkg.SignatureKind -ne 'Store' -or $pkg.IsFramework -or $pkg.IsResourcePackage) {
                $failed++; continue
            }
            try {
                Remove-AppxPackage -AllUsers -Package $pkg.PackageFullName -ErrorAction Stop
                $removed++
            } catch { $failed++ }
        }
        $remaining += @(Get-Parents).Count
    } catch { $failed++ }
}
@{ok=($remaining -eq 0 -and $failed -eq 0); removed=$removed; remaining=$remaining; failures=$failed} | ConvertTo-Json -Compress
"""
_ROBLOX_STORE_IDS = (
    ('ROBLOXCORPORATION.ROBLOX', '55nm5eh3cm0pr', 'CN=6FEF9772-62F8-4C8B-8DE0-70F628846515'),
    ('ROBLOXCorporation.RobloxGDK', '55nm5eh3cm0pr', 'CN=6FEF9772-62F8-4C8B-8DE0-70F628846515'),
)
_MINECRAFT_STORE_ID = ('Microsoft.MinecraftUWP', '8wekyb3d8bbwe',
                       'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US')


def _game_store_script(policy):
    catalog = list(_ROBLOX_STORE_IDS) if policy.get('remove_roblox', True) else []
    if 'minecraft' in policy.get('remove_games', ()):
        catalog.append(_MINECRAFT_STORE_ID)
    # Only constant package identities are interpolated, never a configuration value.
    if not catalog:
        return None
    create = "\n".join("$ids += @{Name='%s'; Id='%s'; Publisher='%s'}" % entry for entry in catalog)
    return _GAME_STORE_SCRIPT.replace('__CATALOG__', create)


def enforce_games(policy, *, maintenance=True):
    selected = set(GAME_IDS).intersection(policy.get('games', GAME_IDS))
    try:
        processes = _enforce_game_processes(selected)
    except (OSError, AttributeError):
        processes = {'ok': False, 'status': 'inventario_indisponivel'}
    report = {'ok': processes['ok'], 'processes': processes}
    script = _game_store_script(policy) if maintenance else None
    if script:
        try:
            report['store'] = _games_ps(script, 150)
        except (OSError, AttributeError):
            report['store'] = {'ok': False, 'status': 'powershell_indisponivel'}
        report['ok'] = report['ok'] and report['store']['ok']
    return report

# Classic Player lives in each Windows profile. This script must be launched
# ONLY through the non-elevated user entry point, never from the SYSTEM worker.
_GAME_CLASSIC_SCRIPT = r"""
function Report($status, $ok) { @{ok=$ok; status=$status} | ConvertTo-Json -Compress }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $id.User.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20') -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    Report 'aguarda_usuario_sem_elevacao' $false; return
}
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\roblox-player'
if (!(Test-Path -LiteralPath $key)) { Report 'sem_registro_player_neste_usuario' $true; return }
$entry = Get-ItemProperty -LiteralPath $key
if ($entry.Publisher -ine 'Roblox Corporation' -or $entry.DisplayName -notmatch '^Roblox Player(?: for .+)?$') {
    Report 'identidade_do_registro_incompativel' $false; return
}
# Read a narrow format only. Shell verbs, interpreter invocations and additional
# registry-supplied switches never become commands.
$pattern = '^(?:"(?<exe>[^"]+\.exe)"|(?<exe>[A-Z]:\\[^"]+?\.exe))\s+-uninstall(?:\s+-silent)?\s*$'
if ([string]$entry.UninstallString -notmatch $pattern) { Report 'revisar_desinstalador' $false; return }
$exe = $Matches['exe']
$base = [Environment]::GetFolderPath('LocalApplicationData')
$profile = [Environment]::GetFolderPath('UserProfile')
$expected = [IO.Path]::Combine($base, 'Roblox\Versions\')
if ($exe -notmatch '^[A-Z]:\\' -or $exe.Contains('/') -or
    !$base.StartsWith($profile.TrimEnd('\')+'\', [StringComparison]::OrdinalIgnoreCase) -or
    ![string]::Equals([IO.Path]::GetFullPath($exe), $exe, [StringComparison]::OrdinalIgnoreCase) -or
    !$exe.StartsWith($expected, [StringComparison]::OrdinalIgnoreCase) -or
    $exe.Substring($expected.Length) -notmatch '^version-[a-f0-9]{8,64}\\RobloxPlayer(Installer|Launcher)\.exe$') {
    Report 'caminho_do_player_incompativel' $false; return
}
# Disallow links/junctions at every part of the selected local path.
$cursor = $exe
while (![string]::IsNullOrEmpty($cursor)) {
    $item = Get-Item -LiteralPath $cursor -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Report 'caminho_redirecionado' $false; return
    }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
}
$guard = [IO.File]::Open($exe,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
    $sign = Get-AuthenticodeSignature -LiteralPath $exe
    if ($sign.Status -ne 'Valid' -or !$sign.SignerCertificate -or
        $sign.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ine 'Roblox Corporation') {
        Report 'assinatura_do_player_nao_confirmada' $false; return
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $exe; $info.Arguments = '-uninstall'
    $info.WorkingDirectory = [IO.Path]::GetDirectoryName($exe)
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $worker = [Diagnostics.Process]::Start($info)
} finally { $guard.Dispose() }
try {
    if (!$worker.WaitForExit(60000)) { Report 'desinstalacao_pendente' $false; return }
    if ($worker.ExitCode -ne 0) { Report 'desinstalacao_falhou' $false; return }
} finally { $worker.Dispose() }
$deadline = [DateTime]::UtcNow.AddSeconds(15)
# The official bootstrapper may re-launch from its temp directory. Recheck both
# the exact registration and the player executable before declaring success.
$player = [IO.Path]::Combine([IO.Path]::GetDirectoryName($exe), 'RobloxPlayerBeta.exe')
do {
    if (!(Test-Path -LiteralPath $key) -and !(Test-Path -LiteralPath $player)) {
        Report 'roblox_player_removido' $true; return
    }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $deadline)
Report 'desinstalacao_sem_confirmacao' $false
"""


def remove_roblox_for_current_user(policy):
    if policy.get('remove_roblox', True) is not True:
        return {'ok': True, 'status': 'desativado'}
    if os.name != 'nt':
        return {'ok': False, 'status': 'somente_windows'}
    if ctypes.windll.shell32.IsUserAnAdmin():
        return {'ok': False, 'status': 'aguarda_usuario_sem_elevacao'}
    try:
        return _games_ps(_GAME_CLASSIC_SCRIPT, 105)
    except (OSError, AttributeError):
        return {'ok': False, 'status': 'powershell_indisponivel'}


# Administrative window. It is opened only by the interactive entry point.
def show_client_ui():
    import json
    import tkinter as tk
    from concurrent.futures import ThreadPoolExecutor
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("LabGuard Cliente | Administração da estação")
    root.geometry("800x650")
    root.minsize(660, 520)
    bg, purple, blue, ink, muted = "#f5f4fa", "#50318d", "#254f9d", "#202739", "#4d576d"
    root.configure(bg=bg)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("LG.TFrame", background=bg)
    style.configure("Card.TFrame", background="white")
    style.configure("LG.TButton", font=("Segoe UI", 10), padding=(12, 7))
    style.configure("Apply.LG.TButton", foreground="white", background=blue,
                    font=("Segoe UI", 10, "bold"), borderwidth=0)
    style.map("Apply.LG.TButton", background=[("disabled", "#858b9d"), ("active", purple)])
    style.configure("LG.TRadiobutton", background="white", font=("Segoe UI", 10))
    style.configure("LG.TCheckbutton", background="white", font=("Segoe UI", 10))
    style.configure("LG.TNotebook", background=bg, borderwidth=0)
    style.configure("LG.TNotebook.Tab", padding=(15, 7), font=("Segoe UI", 10))

    def label(parent, text, *, heading=False, variable=None, wrap=585):
        return tk.Label(parent, text=text, textvariable=variable, background="white",
                        foreground=ink if heading else muted, anchor="w", justify="left",
                        wraplength=wrap, font=("Segoe UI", 12 if heading else 10,
                                               "bold" if heading else "normal"))

    head = tk.Frame(root, bg=purple, padx=20, pady=12)
    head.pack(fill="x")
    tk.Label(head, text="LabGuard Cliente", bg=purple, fg="white",
             font=("Segoe UI", 19, "bold")).pack(anchor="w")
    root_body = ttk.Frame(root, style="LG.TFrame", padding=(16, 12, 16, 10))
    root_body.pack(fill="both", expand=True)
    root_body.columnconfigure(0, weight=1)
    root_body.rowconfigure(0, weight=1)
    tabs = ttk.Notebook(root_body, style="LG.TNotebook")
    tabs.grid(row=0, column=0, sticky="nsew")
    home, sites, games = [ttk.Frame(tabs, style="Card.TFrame", padding=14) for _ in range(3)]
    for panel, name in ((home, "Estação"), (sites, "Sites"), (games, "Jogos")):
        tabs.add(panel, text=name)
        panel.columnconfigure(0, weight=1)

    agent_state = tk.StringVar(value="Lendo a estação…")
    agent_time = tk.StringVar()
    feedback = tk.StringVar()
    label(home, "", heading=True, variable=agent_state).grid(row=0, column=0, sticky="w")
    label(home, "", variable=agent_time).grid(row=1, column=0, sticky="w", pady=(4, 10))
    label(home, "O cliente inicia com o Windows. A proteção funciona em segundo plano. "
                "A TI pode consultá-la no Agendador de Tarefas ou nesta janela.").grid(
                    row=2, column=0, sticky="w", pady=(0, 10))
    label(home, "Use as abas Sites e Jogos para escolher a política desta estação.").grid(
                    row=3, column=0, sticky="w", pady=(0, 10))
    controls = ttk.Frame(home, style="Card.TFrame")
    controls.grid(row=4, column=0, sticky="w")
    refresh = ttk.Button(controls, text="Atualizar estado", style="LG.TButton")
    details = ttk.Button(controls, text="Detalhes técnicos", style="LG.TButton")
    remove = ttk.Button(controls, text="Desinstalar cliente", style="LG.TButton")
    for button in (refresh, details, remove):
        button.pack(side="left", padx=(0, 5))

    mode = tk.StringVar(value="bloqueados")
    label(sites, "Política dos navegadores", heading=True).grid(row=0, column=0, sticky="w")
    options = ttk.Frame(sites, style="Card.TFrame")
    options.grid(row=1, column=0, sticky="w", pady=(3, 4))
    for value, name in (("bloqueados", "Bloquear os listados"), ("permitidos", "Permitir só os listados")):
        ttk.Radiobutton(options, text=name, variable=mode, value=value,
                        style="LG.TRadiobutton").pack(side="left", padx=(0, 11))
    label(sites, "O modo de permitidos restringe a navegação no Edge, Chrome e Firefox compatíveis. "
                 "Inclua também os domínios usados no login e nos materiais das aulas.").grid(
                    row=2, column=0, sticky="w", pady=(0, 6))

    def domain_box(row, title):
        label(sites, title).grid(row=row, column=0, sticky="w")
        part = ttk.Frame(sites, style="Card.TFrame")
        part.grid(row=row+1, column=0, sticky="nsew", pady=(2, 6))
        part.columnconfigure(0, weight=1)
        part.rowconfigure(0, weight=1)
        field = tk.Text(part, height=3, wrap="none", font=("Consolas", 10),
                        relief="solid", borderwidth=1, padx=5, pady=3, undo=True)
        field.grid(row=0, column=0, sticky="nsew")
        bar = ttk.Scrollbar(part, command=field.yview)
        bar.grid(row=0, column=1, sticky="ns")
        field.configure(yscrollcommand=bar.set)
        sites.rowconfigure(row+1, weight=1)
        return field

    deny = domain_box(3, "Domínios bloqueados • um por linha")
    allow = domain_box(5, "Domínios permitidos no modo restrito • um por linha")

    label(games, "Jogos com execução bloqueada", heading=True).grid(row=0, column=0, sticky="w")
    label(games, "O cliente procura processos conhecidos dos jogos marcados e encerra a execução "
                 "quando os identifica.").grid(row=1, column=0, sticky="w", pady=(3, 8))
    check_grid = ttk.Frame(games, style="Card.TFrame")
    check_grid.grid(row=2, column=0, sticky="w")
    names = {"roblox": "Roblox", "minecraft": "Minecraft", "fortnite": "Fortnite",
             "valorant": "VALORANT", "league": "League of Legends", "cs2": "Counter-Strike 2",
             "genshin": "Genshin Impact"}
    game_flags = {}
    for i, (game, name) in enumerate(names.items()):
        value = tk.BooleanVar()
        game_flags[game] = value
        ttk.Checkbutton(check_grid, text=name, variable=value, style="LG.TCheckbutton").grid(
            row=i//3, column=i%3, sticky="w", padx=(0, 16), pady=1)
    remove_roblox = tk.BooleanVar()
    ttk.Checkbutton(games, text="Desinstalar o Roblox identificado", variable=remove_roblox,
                    style="LG.TCheckbutton").grid(row=3, column=0, sticky="w", pady=(12, 3))
    label(games, "A cópia da Microsoft Store pode ser removida para todas as contas. "
                 "A versão clássica compatível é tratada na entrada do aluno no Windows. "
                 "A desinstalação pode remover dados locais do aplicativo.").grid(row=4, column=0, sticky="w")

    remove_minecraft = tk.BooleanVar()
    ttk.Checkbutton(games, text="Desinstalar também o Minecraft para Windows (Microsoft Store)",
                    variable=remove_minecraft, style="LG.TCheckbutton").grid(row=5, column=0, sticky="w", pady=(9, 2))
    label(games, "Essa opção pode apagar mundos salvos localmente. Faça o backup dos mundos antes de ativá-la.").grid(
        row=6, column=0, sticky="w")
    def couple_removal(game, removal):
        def game_changed(*_):
            if not game.get() and removal.get():
                removal.set(False)
        def removal_changed(*_):
            if removal.get() and not game.get():
                game.set(True)
        game.trace_add("write", game_changed)
        removal.trace_add("write", removal_changed)
    couple_removal(game_flags["roblox"], remove_roblox)
    couple_removal(game_flags["minecraft"], remove_minecraft)

    foot = ttk.Frame(root_body, style="LG.TFrame")
    foot.grid(row=1, column=0, sticky="ew", pady=(9, 0))
    foot.columnconfigure(0, weight=1)
    message = tk.Label(foot, textvariable=feedback, anchor="w", justify="left", bg=bg, fg=muted,
                       wraplength=465, font=("Segoe UI", 9))
    message.grid(row=0, column=0, sticky="ew", padx=(0, 8))
    apply_button = ttk.Button(foot, text="Instalar proteção", style="Apply.LG.TButton")
    apply_button.grid(row=0, column=1, sticky="e")
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="labguard-admin")
    job = None
    policy = {}
    snapshot = {}
    initialized = False
    installed = False
    editable = False
    try:
        require_client_admin()
        admin = True
    except Exception:
        admin = False

    def buttons():
        ready = initialized and job is None
        for button, active in ((refresh, job is None), (details, ready and bool(snapshot)),
                               (remove, ready and installed and admin),
                               (apply_button, ready and editable and admin)):
            button.state(["!disabled" if active else "disabled"])
        apply_button.configure(text="Salvar política" if installed else "Instalar proteção")

    def fill(data):
        nonlocal policy
        policy = dict(data)
        mode.set(data["mode"])
        for area, key in ((deny, "domains"), (allow, "allowed_domains")):
            area.delete("1.0", "end")
            area.insert("1.0", "\n".join(data.get(key, [])))
        for key, flag in game_flags.items():
            flag.set(key in data["games"])
        remove_roblox.set(data["remove_roblox"])
        remove_minecraft.set("minecraft" in data.get("remove_games", []))

    def load_state():
        try:
            value = get_client_status()
        except (ValueError, OSError, RuntimeError) as error:
            if not (client_directory() / "instalacao.json").is_file():
                raise
            return {"installed": True, "ok": False, "situacao": "falha na leitura do estado"}, True, None, str(error)
        present = bool(value.get("installed"))
        data, issue = None, None
        try:
            data = (value.get("policy") or read_policy()) if present else default_policy()
        except Exception as error:
            issue = str(error)
        return value, present, data, issue

    def display(result, replace_form, note=""):
        nonlocal initialized, snapshot, installed, editable
        value, present, data, issue = result
        replace_form = replace_form or not initialized or installed != present
        initialized, installed, snapshot = True, present, value
        editable = data is not None
        if replace_form and data is not None:
            fill(data)
        worker = value.get("worker") or {}
        if not isinstance(worker, dict):
            worker = {}
        if not installed:
            agent_state.set("Cliente ainda não instalado")
            agent_time.set("Escolha a política e clique em Instalar proteção.")
        else:
            summary = str(value.get("situacao") or "cliente instalado")
            agent_state.set(summary[:1].upper() + summary[1:])
            stamp = worker.get("checked_at")
            agent_time.set("Último registro (UTC)   " + str(stamp) if stamp else
                           "Abra Detalhes técnicos para consultar o estado da proteção.")
        feedback.set(issue or ("Abra este programa como administrador para alterar a proteção."
                              if not admin else note))
        buttons()

    def submit(text, operation, callback):
        nonlocal job
        if job is not None:
            return
        feedback.set(text)
        job = executor.submit(operation)
        buttons()
        def poll():
            nonlocal job
            if not job.done():
                root.after(100, poll)
                return
            finished, job = job, None
            try:
                callback(finished.result())
            except Exception as error:
                feedback.set(str(error) or "Falha ao concluir a operação.")
                messagebox.showerror("LabGuard Cliente", feedback.get(), parent=root)
            buttons()
        root.after(100, poll)

    def apply():
        try:
            edited = dict(policy)
            for area, key in ((deny, "domains"), (allow, "allowed_domains")):
                edited[key] = [line.strip() for line in area.get("1.0", "end").splitlines() if line.strip()]
            edited.update(mode=mode.get(), games=[k for k, v in game_flags.items() if v.get()],
                          remove_roblox=remove_roblox.get(),
                          remove_games=["minecraft"] if remove_minecraft.get() else [])
            checked = validate_policy(edited)
        except Exception as error:
            messagebox.showerror("Confira a política", str(error), parent=root)
            return
        description = ("Salvar esta política no computador?" if installed else
                       "Instalar o LabGuard Cliente neste computador e iniciar a proteção a cada inicialização?")
        if checked["mode"] == "permitidos":
            description += "\n\nO modo restrito permite apenas os domínios listados nos navegadores gerenciados."
        if checked["remove_roblox"] or checked.get("remove_games"):
            description += "\n\nA remoção dos jogos configurados pode apagar dados locais. Desinstalar o cliente depois não recupera esses dados."
        if checked.get("remove_games"):
            description += "\n\nMinecraft para Windows será desinstalado e mundos locais podem ser perdidos. Confirme que a TI possui o backup."
        if not messagebox.askyesno("Confirmar proteção", description, parent=root, default="no"):
            return
        updating = installed
        def work():
            if updating:
                save_client_policy(checked)
            else:
                perform_install(checked)
            return load_state()
        submit("Salvando a política…" if updating else "Instalando a proteção…", work,
               lambda value: display(value, True, "Política salva. Atualize o estado para acompanhar a verificação."))

    def uninstall():
        if not messagebox.askyesno("Desinstalar cliente",
            "Remover a proteção e as configurações aplicadas pelo LabGuard nesta estação? "
            "Jogos já desinstalados continuarão removidos.", parent=root, default="no"):
            return
        def work():
            perform_uninstall()
            return load_state()
        submit("Removendo a proteção…", work, lambda value: display(value, True, "Cliente desinstalado."))

    def detail_window():
        win = tk.Toplevel(root)
        win.title("LabGuard Cliente | Detalhes técnicos")
        win.geometry("680x430")
        box = tk.Text(win, wrap="word", padx=10, pady=8, font=("Consolas", 10))
        scroll = ttk.Scrollbar(win, command=box.yview)
        scroll.pack(side="right", fill="y")
        box.pack(fill="both", expand=True)
        box.configure(yscrollcommand=scroll.set)
        box.insert("1.0", json.dumps(snapshot, indent=2, ensure_ascii=False))
        box.configure(state="disabled")

    refresh.configure(command=lambda: submit("Consultando a estação…", load_state, lambda x: display(x, False)))
    details.configure(command=detail_window)
    remove.configure(command=uninstall)
    apply_button.configure(command=apply)
    def close():
        if job is not None:
            feedback.set("Aguarde a operação terminar antes de fechar a janela.")
            return
        executor.shutdown(wait=False)
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    tabs.select(home)
    submit("Consultando a estação…", load_state, lambda result: display(result, True))
    root.mainloop()
    return 0


def perform_install(policy):
    require_client_admin()
    accepted = validate_policy(policy)
    def initialize(directory):
        with _operation_lock(directory):
            config, journal = directory / "politica.json", directory / "estado.json"
            if config.exists() or journal.exists():
                if not (config.is_file() and journal.is_file()):
                    raise RuntimeError("Instalação incompleta. Confira o estado e remova antes de instalar novamente.")
                if validate_policy(_json_read(config)) != accepted:
                    raise RuntimeError("Já existe uma política. Edite-a na interface da TI ou use o comando politica.")
                _json_read(journal)  # Nunca substitua o registro de propriedade de uma instalação ativa.
                return
            _atomic_json(config, accepted)
            _atomic_json(journal, {})
    return install_client(initialize)


def save_client_policy(policy):
    require_client_admin()
    accepted = validate_policy(policy)
    directory = client_directory()
    if not (directory / "instalacao.json").is_file():
        raise RuntimeError("Instale o cliente antes de salvar a política.")
    _lc_load(directory)
    with _operation_lock(directory):
        if (directory / "parar.flag").exists():
            raise RuntimeError("A remoção do cliente está em andamento. Conclua essa operação primeiro.")
        _atomic_json(directory / "politica.json", accepted)


def perform_uninstall():
    require_client_admin()
    def undo(directory):
        with _operation_lock(directory):
            state = _json_read(directory / "estado.json")
            persist = lambda: _atomic_json(directory / "estado.json", state)
            web = _layer("Navegadores", undo_sites, state, checkpoint=persist)
            dns = _layer("Nomes do Windows", undo_system_sites, state, checkpoint=persist)
            if not (web["ok"] and dns["ok"]):
                _atomic_json(directory / "status.json", {"ok":False, "checked_at":_utc_now(),
                             "sites":web, "system_sites":dns, "situacao":"restauracao_pendente"})
                raise RuntimeError("Restauração pendente. Consulte o status e repita a remoção pela TI.")
    return uninstall_client(undo)


def get_client_status():
    directory = client_directory()
    if not (directory / "instalacao.json").is_file():
        return {"installed":False, "ok":False, "version":CLIENT_VERSION, "situacao":"ausente"}
    report = {"installed":True, "ok":False, "version":CLIENT_VERSION}
    report["task"] = client_task_status()
    policy_path, status_path = directory / "politica.json", directory / "status.json"
    if status_path.is_file():
        report["worker"] = _json_read(status_path)
    if policy_path.is_file():
        report["policy"] = read_policy()
    worker = report.get("worker", {})
    fresh = _health_time(worker.get("checked_at"))
    pending = (directory / "parar.flag").exists()
    same = worker.get("policy_revision") == _policy_revision(report.get("policy", {}))
    task = report["task"]
    startup_ok = task.get("running") and task.get("user_start") and task.get("task_registered")
    report["ok"] = bool(worker.get("ok") and fresh and same and not pending and startup_ok)
    if pending:
        report["situacao"] = "remoção em andamento ou pendente"
    elif not startup_ok and worker:
        report["situacao"] = "inicialização incompleta; confira a tarefa e a entrada de logon"
    elif not worker:
        report["situacao"] = "aguardando primeira verificação"
    elif not fresh:
        report["situacao"] = "verificação desatualizada; confira a tarefa LabGuardCliente"
    elif not same:
        report["situacao"] = "aguardando aplicação da política salva"
    else:
        report["situacao"] = "regras locais conferidas" if report["ok"] else "verificação com pendências"
    return report


def _policy_revision(policy):
    import hashlib
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest()


def run_client_worker():
    client_runtime_guard()
    directory = client_directory()
    stop = directory / "parar.flag"
    last_sites = last_store = float("-inf")
    revision = None
    sites, system_sites, store_result = {}, {}, None
    while not stop.exists():
        try:
            with _operation_lock(directory):
                if stop.exists():
                    break
                policy = read_policy()
                key = _policy_revision(policy)
                now = time.monotonic()
                if revision != key or now - last_sites >= 60:
                    state = _json_read(directory / "estado.json")
                    persist = lambda: _atomic_json(directory / "estado.json", state)
                    sites = _layer("Navegadores", sync_sites, policy, state, checkpoint=persist)
                    system_sites = _layer("Nomes do Windows", sync_system_sites, policy, state, checkpoint=persist)
                    last_sites = now
                if stop.exists():
                    break
                maintain = revision != key or now - last_store >= 600
                games = _layer("Jogos", enforce_games, policy, maintenance=maintain)
                if maintain:
                    last_store, store_result = now, games.get("store")
                elif store_result is not None:
                    games["store"] = store_result
                    games["ok"] = games["ok"] and store_result.get("ok") is True
                revision = key
                report = {"version": CLIENT_VERSION, "policy_revision":key, "checked_at":_utc_now(),
                          "ok":all(item.get("ok") is True for item in (sites, system_sites, games)),
                          "sites":sites, "system_sites":system_sites, "games":games}
                _atomic_json(directory / "status.json", report)
        except Exception as err:
            revision = None
            _atomic_json(directory / "status.json", {"ok":False, "checked_at":_utc_now(),
                         "erro":"A configuração ou o estado não pôde ser processado.",
                         "tipo":type(err).__name__})
        for _ in range(15):
            if stop.exists():
                return 0
            time.sleep(1)
    return 0


def _emit_result(data, args):
    output = json.dumps(data, ensure_ascii=False, indent=2)
    destination = getattr(args, "saida", None)
    if destination:
        with Path(destination).open("x", encoding="utf-8") as stream:
            stream.write(output + "\n")
    if sys.stdout is not None:
        print(output)


def _ensure_interactive_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    # Windows presents the normal UAC confirmation only for an interactive launch.
    source = Path(__file__).resolve()
    if not getattr(sys, "frozen", False):
        _lc_runtime(client_directory())  # Não elevar um Python gravável pelo aluno.
    argv = [] if getattr(sys, "frozen", False) else ["-I", "-S", "-B", str(source)]
    params = subprocess.list2cmdline(argv)
    from ctypes import wintypes
    launch = ctypes.windll.shell32.ShellExecuteW
    launch.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                       wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int)
    launch.restype = ctypes.c_void_p
    result = launch(None, "runas", str(Path(sys.executable).resolve()), params, None, 1)
    if not result or result <= 32:
        ctypes.windll.user32.MessageBoxW(None, "O Windows requer a autorização da TI para administrar este cliente.",
                                        "LabGuard Cliente", 0x30)
    return False


def _parse_cli(argv):
    parser = argparse.ArgumentParser(prog="LabGuardCliente", description="Cliente de proteção local da escola.")
    ops = parser.add_subparsers(dest="action")
    for name in ("instalar", "politica", "remover", "status", "verificar", "worker", "usuario"):
        p = ops.add_parser(name)
        if name in ("instalar", "remover", "politica"):
            p.add_argument("--sim", action="store_true", help="confirmar a operação administrativa")
        if name in ("instalar", "politica"):
            p.add_argument("--politica", type=Path, required=name=="politica", help="arquivo JSON da política")
        if name in ("status", "verificar", "instalar", "politica", "remover", "usuario"):
            p.add_argument("--json", action="store_true", help="exibir resultado em JSON")
            p.add_argument("--saida", help="registrar resultado em um arquivo novo")
    return parser.parse_args(argv)


def main_client(argv=None):
    args = _parse_cli(sys.argv[1:] if argv is None else argv)
    try:
        if os.name != "nt":
            raise RuntimeError("O LabGuard Cliente 1.0 requer Windows 10/11 x64.")
        if not args.action:
            if _ensure_interactive_admin():
                return show_client_ui() or 0
            return 0
        if args.action == "worker":
            return run_client_worker()
        if args.action == "usuario":
            directory = client_directory()
            if (directory / "parar.flag").exists():
                return 0
            result = remove_roblox_for_current_user(read_policy())
        elif args.action in ("status","verificar"):
            result = get_client_status()
        else:
            if not args.sim:
                raise ValueError("Leia a política e adicione --sim para confirmar, ou abra a interface da TI.")
            if args.action == "remover":
                result = perform_uninstall()
            else:
                policy = validate_policy(_json_read(args.politica)) if args.politica else validate_policy(default_policy())
                if args.action == "instalar":
                    result = perform_install(policy)
                else:
                    save_client_policy(policy)
                    result = {"ok":True, "situacao":"política salva; aguarde a verificação do cliente"}
        _emit_result(result, args)
        if args.action in ("verificar","usuario") and not result.get("ok"):
            return 2
        return 0
    except Exception as err:
        problem = {"ok":False, "erro":str(err) or type(err).__name__}
        try:
            _emit_result(problem, args)
        except OSError:
            if sys.stderr:
                print(problem["erro"], file=sys.stderr)
        if not args.action and os.name == "nt":
            ctypes.windll.user32.MessageBoxW(None, problem["erro"], "LabGuard Cliente", 0x10)
        return 1


if __name__ == "__main__":
    raise SystemExit(main_client())
