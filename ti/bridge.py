"""Restricted bridge to the existing Central. No credentials or policy are copied."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

CENTRAL_SHA256 = '4693103f63e9265342f77689a160e35dcb52fffdfdc45e8ecd36e0d786f16e88'

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise OSError('Redirecionamento da Central recusado.')

def panel_url(port=8787):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Informe uma porta local entre 1024 e 65535.')
    return 'http://127.0.0.1:%d/' % port

def health(port=8787):
    try:
        opener=build_opener(ProxyHandler({}),NoRedirect())
        with opener.open(panel_url(port)+'healthz',timeout=1.5) as response:
            raw=response.read(4097)
            if len(raw)>4096: raise ValueError()
            value=json.loads(raw)
        if value.get('ok') is True and value.get('app')=='LabGuardCentral':
            return {'ready':True,'version':str(value.get('version',''))[:24]}
    except (OSError,ValueError,TypeError):
        pass
    return {'ready':False,'version':''}

def payload():
    root=Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parents[1]))
    path=root/'ti/payload/LabGuardTecnico.exe'
    if not path.is_file() or path.stat().st_size>80*1024*1024:
        raise OSError('O componente Central está ausente. Reinstale o pacote TI sem apagar os dados.')
    for p in (path,*path.parents):
        info=p.lstat()
        if p.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
            raise OSError('Link/redirecionamento no componente Central recusado.')
    if hashlib.sha256(path.read_bytes()).hexdigest()!=CENTRAL_SHA256:
        raise OSError('A integridade da Central não foi confirmada. O componente não foi executado.')
    return path

def start_central_setup():
    if os.name!='nt':raise OSError('O instalador da Central deste pacote é para Windows.')
    import ctypes
    from ctypes import wintypes
    path=payload()
    shell=ctypes.WinDLL('shell32',use_last_error=True)
    shell.ShellExecuteW.argtypes=[wintypes.HWND,wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.LPCWSTR,ctypes.c_int]
    shell.ShellExecuteW.restype=ctypes.c_ssize_t
    result=shell.ShellExecuteW(None,'runas',str(path),None,str(path.parent),1)
    if result<=32:raise OSError('A abertura administrativa da Central não foi autorizada ou não pôde ser concluída.')
    return True
