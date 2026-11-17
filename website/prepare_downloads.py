"""Validate publishable static pages without changing their content or product versions.

Older deploys rewrote the homepage to stale client releases. Product choices now live
in the tracked HTML and work with JavaScript disabled. This check blocks a missing
local page/anchor or a downgrade in the current download entry points.
"""
from __future__ import annotations
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import sys

ROOT = Path(__file__).resolve().parent
CURRENT = {
    'ti': ('2.4.6', 'ti-v2.4.6', 'LabGuard-TI-Setup.exe'),
    'automatic': ('2.5.1', 'automatico-v2.5.1', 'LabGuard-Jogos.exe'),
    'central': ('1.2.1', 'automatico-v2.5.1', 'LabGuardTecnico.exe'),
}

class Page(HTMLParser):
    def __init__(self, path: Path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.feed(path.read_text(encoding='utf-8'))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        if attrs.get('name') and tag == 'a':
            self.ids.add(attrs['name'])
        for name in ('href', 'src'):
            if attrs.get(name):
                self.links.append(attrs[name])


def validate() -> list[str]:
    pages = {p.resolve(): Page(p) for p in ROOT.rglob('*.html')}
    errors = []
    for path, page in pages.items():
        for raw in page.links:
            link = urlsplit(raw)
            if link.scheme or link.netloc:
                continue
            if not link.path:
                target = path
            elif link.path.startswith('/'):
                target = ROOT / unquote(link.path.lstrip('/'))
            else:
                target = path.parent / unquote(link.path)
            target = target.resolve()
            if target.is_dir():
                target /= 'index.html'
            if not target.is_relative_to(ROOT):
                errors.append(f'{path.relative_to(ROOT)}: link fora do site: {raw}')
            elif not target.is_file():
                errors.append(f'{path.relative_to(ROOT)}: destino ausente: {raw}')
            elif link.fragment and target in pages and unquote(link.fragment) not in pages[target].ids:
                errors.append(f'{path.relative_to(ROOT)}: âncora ausente: {raw}')
    for rel in ('index.html', 'downloads/index.html'):
        source = (ROOT/rel).read_text(encoding='utf-8')
        for version, tag, asset in CURRENT.values():
            expected = f'https://github.com/perabru/LabGuard/releases/download/{tag}/{asset}'
            if expected not in source:
                errors.append(f'{rel}: download atual ausente: {asset} {version}')
        for stale in ('automatico-v2.4.0/', 'gerenciado-v2.3.0/', 'CLIENTE 2.4', 'Cliente 2.3'):
            if stale in source:
                errors.append(f'{rel}: versão obsoleta na escolha atual: {stale}')
        if 'manual-atual/' not in source:
            errors.append(f'{rel}: manual atual ausente')
    script = (ROOT/'script.js').read_text(encoding='utf-8')
    if 'releases/latest' in script:
        errors.append('script.js: não resolva produtos diferentes pela release global latest')
    if 'managed-downloads-ready' not in (ROOT/'index.html').read_text(encoding='utf-8'):
        errors.append('index.html: downloads estáticos ausentes')
    return errors

if __name__ == '__main__':
    issues = validate()
    if issues:
        print('\n'.join(issues), file=sys.stderr)
        raise SystemExit(1)
    print('Site validado: links locais, âncoras e downloads atuais consistentes; nenhum arquivo foi reescrito.')
