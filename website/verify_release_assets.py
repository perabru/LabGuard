"""Gate publication until every GitHub release download linked by the site exists.

Only GitHub metadata is requested. Credentials come from the runner environment and
are never included in URLs, arguments or output. No executable is downloaded/run.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent

class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls = set()
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key == 'href' and value:
                self.urls.add(value)


def release_assets(root: Path) -> dict[tuple[str, str, str], set[str]]:
    required = defaultdict(set)
    for path in root.rglob('*.html'):
        links = Links()
        links.feed(path.read_text(encoding='utf-8'))
        for raw in links.urls:
            url = urlsplit(raw)
            parts = url.path.strip('/').split('/')
            if (url.scheme == 'https' and url.netloc == 'github.com'
                and len(parts) == 6 and parts[2:4] == ['releases', 'download']):
                owner, repo, _, _, tag, asset = map(unquote, parts)
                required[(owner, repo, tag)].add(asset)
    return dict(required)


def request_release(owner: str, repo: str, tag: str) -> dict | None:
    url = 'https://api.github.com/repos/{}/{}/releases/tags/{}'.format(
        quote(owner, safe=''), quote(repo, safe=''), quote(tag, safe=''))
    headers = {'Accept': 'application/vnd.github+json',
               'X-GitHub-Api-Version': '2022-11-28',
               'User-Agent': 'LabGuard-Pages-release-check'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        with urlopen(Request(url, headers=headers), timeout=8) as response:
            return json.load(response)
    except HTTPError as exc:
        if exc.code in (400, 401, 422):
            raise RuntimeError(f'API GitHub recusou a consulta (HTTP {exc.code}).') from None
        # Includes not-yet-published releases, transient server/rate-limit errors.
        return None
    except (URLError, TimeoutError, OSError, ValueError):
        return None


def missing_assets(required, fetch=request_release) -> list[str]:
    missing = []
    for (owner, repo, tag), names in sorted(required.items()):
        release = fetch(owner, repo, tag)
        if not isinstance(release, dict) or release.get('draft'):
            missing.extend(f'{owner}/{repo}@{tag}/{name}' for name in sorted(names))
            continue
        uploaded = {asset.get('name') for asset in release.get('assets', [])
                    if isinstance(asset, dict) and asset.get('state') == 'uploaded'
                    and isinstance(asset.get('size'), int) and asset['size'] > 0}
        missing.extend(f'{owner}/{repo}@{tag}/{name}' for name in sorted(names-uploaded))
    return missing


def wait_for_assets(required, wait_seconds: int, *, fetch=request_release,
                    clock=time.monotonic, sleep=time.sleep, emit=print) -> bool:
    deadline = clock() + wait_seconds
    while True:
        missing = missing_assets(required, fetch)
        if not missing:
            emit(f'Downloads confirmados: {sum(map(len, required.values()))} arquivos em {len(required)} releases.')
            return True
        remaining = deadline - clock()
        emit(f'Aguardando {len(missing)} arquivo(s) de release: ' + ', '.join(missing))
        if remaining <= 0:
            emit('Publicação cancelada: há downloads ainda indisponíveis. O site publicado anteriormente permanece ativo.')
            return False
        sleep(min(30, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait-seconds', type=int, default=0,
                        help='Prazo de espera por releases/arquivos pendentes (máximo 1200).')
    args = parser.parse_args()
    if not 0 <= args.wait_seconds <= 1200:
        parser.error('--wait-seconds deve estar entre 0 e 1200.')
    required = release_assets(ROOT)
    if not required:
        parser.error('Nenhum download de release encontrado; confira as páginas antes de publicar.')
    try:
        return 0 if wait_for_assets(required, args.wait_seconds) else 1
    except RuntimeError as exc:
        print(str(exc))
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
