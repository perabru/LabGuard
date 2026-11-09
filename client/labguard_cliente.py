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
import csv
import hashlib
import hmac
import io
import ntpath
import secrets
import shutil
import sqlite3
import stat
import xml.etree.ElementTree as ET

CLIENT_VERSION = "1.1.0"
CLIENT_CATALOG_VERSION = "2026.11.09.1"

def default_policy():
    return {"mode": "bloqueados", "domains": [], "catalog_enabled": True,
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
    if type(policy["catalog_enabled"]) is not bool:
        raise ValueError("catalog_enabled deve ser true ou false.")
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
    payload = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if path.is_file() and path.stat().st_size == len(payload) and path.read_bytes() == payload:
        return
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix="lg-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
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


# Domínios verificados, acompanhados da categoria e da origem. O banco da estação
# preserva alterações da TI nas próximas versões deste catálogo.
CLIENT_CATALOG_NOTICE = """Fontes do LabGuard Cliente • revisão de 9 de novembro de 2026

v2fly:<arquivo> indica https://github.com/v2fly/domain-list-community/blob/e8d7a10a15bf662c927a40a3aa680bae86379608/data/<arquivo>. Fontes HTTPS identificam documentação ou páginas oficiais consultadas. Os registros contêm nomes de rede; não foram reproduzidos os textos das páginas.
A categoria minecraft evita os sufixos compartilhados minecraft.net, minecraft-services.net, minecrafteduservices.com, xboxlive.com, playfabapi.com e Microsoft/Azure/MakeCode. Contém hosts específicos de download Java e redes de servidores públicos, lojas e mods. O recorte foi confrontado com os serviços documentados do Minecraft Education; outras categorias ou políticas da instituição podem interferir. A lista não bloqueia mundos offline nem endereços por IP.
https://edusupport.minecraft.net/hc/en-us/articles/360047118992-FAQ-IT-Admin-Guide
Seleção offline por origem, sem varredura de disponibilidade. Jogos com acesso por IP, plataformas de uso misto e novos domínios podem exigir revisão. As categorias de jogos abrangem portais, lojas e infraestrutura. Aplicar roblox também pode afetar Roblox Studio; políticas DNS e de remoção de pacotes são distintas.

## Fontes das categorias de apostas e conteúdo adulto

Retrato local consultado em 9 de novembro de 2026. O catálogo guarda domínios e categorias, sem consultar os sites listados, coletar histórico ou avaliar a disponibilidade atual.

| Origem | Domínios | Seleção usada |
|---|---:|---|
| [Secretaria de Prêmios e Apostas do Ministério da Fazenda](https://www.gov.br/fazenda/pt-br/composicao/orgaos/secretaria-de-premios-e-apostas/transparencia-ativa-processos-de-autorizacao-de-apostas-de-quota-fixa/planilha-de-autorizacoes-1.csv/view) | 183 | Apenas nomes completos do campo DOMÍNIOS, com sufixo .bet.br, na planilha publicada em 14/09/2026. As células “a definir” foram ignoradas. A presença na lista histórica identifica o setor e não certifica situação legal ou operacional atual. |
| [Sinfonietta/hostfiles](https://github.com/Sinfonietta/hostfiles/blob/46f3097d7bcfc9eea323fe365074dfd771d0d17c/gambling-hosts) | 117 | Subconjunto de domínios da lista gambling-hosts, incluindo operadores conhecidos e variantes presentes na lista original. Revisão `46f3097d7bcfc9eea323fe365074dfd771d0d17c`. Licença MIT. |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/blob/e8d7a10a15bf662c927a40a3aa680bae86379608/data/category-porn) | 220 | Nomes explicitamente presentes em category-porn ou em listas por ela incluídas, com prioridade a nomes reconhecidos, domínios brasileiros e famílias de sites. Revisão `e8d7a10a15bf662c927a40a3aa680bae86379608`. Licença MIT. |

A fonte governamental identifica seu conteúdo como [CC BY-ND 3.0](https://creativecommons.org/licenses/by-nd/3.0/). Foram extraídos apenas os endereços factuais publicados, sem modificar sua grafia e sem redistribuir a planilha, o texto ou as informações de empresas.

As inclusões consultadas no catálogo adulto foram bongacams, brazzers, camwhores, clips4sale, digitalplayground, metart, mindgeek-porn, mydirtyhobby, nudevista, nutaku, pornhub, pornpros, realitykings, redtube, spankbang, theporndude, tube8, vixengroup, xhamster, xnxx, xvideos, youjizz, youporn. A seleção verifica nomes exatos contra as listas originais. Não expande nomes por suposição, não testa acesso a nenhum destino e não atribui classificação a páginas individuais.

### Licenças dos conjuntos MIT

**Sinfonietta/hostfiles** — [licença na revisão utilizada](https://github.com/Sinfonietta/hostfiles/blob/46f3097d7bcfc9eea323fe365074dfd771d0d17c/LICENSE).

```text
The MIT License (MIT)

Copyright (c) 2016 Sinfonietta

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**v2fly/domain-list-community** — [licença na revisão utilizada](https://github.com/v2fly/domain-list-community/blob/e8d7a10a15bf662c927a40a3aa680bae86379608/LICENSE).

```text
MIT License

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
"""

CLIENT_CATALOG_ROWS = (
    ('4tube.com', 'adultos', 'v2fly/domain-list-community'),
    ('8teenxxx.com', 'adultos', 'v2fly/domain-list-community'),
    ('acasadasbrasileirinhas.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('adultfriendfinder.com', 'adultos', 'v2fly/domain-list-community'),
    ('allpornsites.net', 'adultos', 'v2fly/domain-list-community'),
    ('babes.com', 'adultos', 'v2fly/domain-list-community'),
    ('bangbros.com', 'adultos', 'v2fly/domain-list-community'),
    ('bcicdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('bcrncdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('bcvcdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('beeg.com', 'adultos', 'v2fly/domain-list-community'),
    ('bgicdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('blacked.com', 'adultos', 'v2fly/domain-list-community'),
    ('blackedraw.com', 'adultos', 'v2fly/domain-list-community'),
    ('bongacams.com', 'adultos', 'v2fly/domain-list-community'),
    ('brazzer.com', 'adultos', 'v2fly/domain-list-community'),
    ('brazzers.com', 'adultos', 'v2fly/domain-list-community'),
    ('brazzers.xxx', 'adultos', 'v2fly/domain-list-community'),
    ('brazzersnetwork.com', 'adultos', 'v2fly/domain-list-community'),
    ('c4slive.com', 'adultos', 'v2fly/domain-list-community'),
    ('cam4.com', 'adultos', 'v2fly/domain-list-community'),
    ('camsoda.com', 'adultos', 'v2fly/domain-list-community'),
    ('camwhores.tv', 'adultos', 'v2fly/domain-list-community'),
    ('camwhores.video', 'adultos', 'v2fly/domain-list-community'),
    ('chaturbate.com', 'adultos', 'v2fly/domain-list-community'),
    ('chinesexxxporn.net', 'adultos', 'v2fly/domain-list-community'),
    ('clips4sale.com', 'adultos', 'v2fly/domain-list-community'),
    ('coliriodemacho.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('collector.xhamster.com', 'adultos', 'v2fly/domain-list-community'),
    ('deeper.com', 'adultos', 'v2fly/domain-list-community'),
    ('digitalplayground.com', 'adultos', 'v2fly/domain-list-community'),
    ('digitalplaygroundnetwork.com', 'adultos', 'v2fly/domain-list-community'),
    ('drtuber.com', 'adultos', 'v2fly/domain-list-community'),
    ('eporner.com', 'adultos', 'v2fly/domain-list-community'),
    ('erome.com', 'adultos', 'v2fly/domain-list-community'),
    ('exporntoons.net', 'adultos', 'v2fly/domain-list-community'),
    ('extremetube.com', 'adultos', 'v2fly/domain-list-community'),
    ('fapello.com', 'adultos', 'v2fly/domain-list-community'),
    ('filmesporno.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('filmesporno.net.br', 'adultos', 'v2fly/domain-list-community'),
    ('freeporn.com', 'adultos', 'v2fly/domain-list-community'),
    ('freepornhdonlinegay.com', 'adultos', 'v2fly/domain-list-community'),
    ('freexh.blog', 'adultos', 'v2fly/domain-list-community'),
    ('freexh.live', 'adultos', 'v2fly/domain-list-community'),
    ('freshporno.net', 'adultos', 'v2fly/domain-list-community'),
    ('gaytube.com', 'adultos', 'v2fly/domain-list-community'),
    ('geilegratisporno.com', 'adultos', 'v2fly/domain-list-community'),
    ('gelbooru.com', 'adultos', 'v2fly/domain-list-community'),
    ('hclips.com', 'adultos', 'v2fly/domain-list-community'),
    ('hdgaytube.xxx', 'adultos', 'v2fly/domain-list-community'),
    ('hdporn92.com', 'adultos', 'v2fly/domain-list-community'),
    ('heavy-r.com', 'adultos', 'v2fly/domain-list-community'),
    ('hotmovies.com', 'adultos', 'v2fly/domain-list-community'),
    ('hqporner.com', 'adultos', 'v2fly/domain-list-community'),
    ('incesto.blog.br', 'adultos', 'v2fly/domain-list-community'),
    ('javlibrary.com', 'adultos', 'v2fly/domain-list-community'),
    ('jizzbunker.com', 'adultos', 'v2fly/domain-list-community'),
    ('keezmovies.com', 'adultos', 'v2fly/domain-list-community'),
    ('kink.com', 'adultos', 'v2fly/domain-list-community'),
    ('letsdoeit.com', 'adultos', 'v2fly/domain-list-community'),
    ('livehdcams.com', 'adultos', 'v2fly/domain-list-community'),
    ('livejasmin.com', 'adultos', 'v2fly/domain-list-community'),
    ('livexxx.me', 'adultos', 'v2fly/domain-list-community'),
    ('machosaonatural.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('manyvids.com', 'adultos', 'v2fly/domain-list-community'),
    ('matureporner.com', 'adultos', 'v2fly/domain-list-community'),
    ('mdhcdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('megaporno.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('men.com', 'adultos', 'v2fly/domain-list-community'),
    ('metart.com', 'adultos', 'v2fly/domain-list-community'),
    ('metartnetwork.com', 'adultos', 'v2fly/domain-list-community'),
    ('metcams.com', 'adultos', 'v2fly/domain-list-community'),
    ('milfy.com', 'adultos', 'v2fly/domain-list-community'),
    ('mobileporngames.com', 'adultos', 'v2fly/domain-list-community'),
    ('mofos.com', 'adultos', 'v2fly/domain-list-community'),
    ('moozporn.com', 'adultos', 'v2fly/domain-list-community'),
    ('motherless.com', 'adultos', 'v2fly/domain-list-community'),
    ('mundomais.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('mydirtyhobby.com', 'adultos', 'v2fly/domain-list-community'),
    ('myfreecams.com', 'adultos', 'v2fly/domain-list-community'),
    ('mypornhere.com', 'adultos', 'v2fly/domain-list-community'),
    ('naiadsystems.com', 'adultos', 'v2fly/domain-list-community'),
    ('netxh.blog', 'adultos', 'v2fly/domain-list-community'),
    ('nhentai.net', 'adultos', 'v2fly/domain-list-community'),
    ('nsimg.net', 'adultos', 'v2fly/domain-list-community'),
    ('nudevista.com', 'adultos', 'v2fly/domain-list-community'),
    ('nudevista.es', 'adultos', 'v2fly/domain-list-community'),
    ('nudevista.net', 'adultos', 'v2fly/domain-list-community'),
    ('nudevista.vip', 'adultos', 'v2fly/domain-list-community'),
    ('nutaku.com', 'adultos', 'v2fly/domain-list-community'),
    ('nutaku.net', 'adultos', 'v2fly/domain-list-community'),
    ('ohpornocasero.com', 'adultos', 'v2fly/domain-list-community'),
    ('phncdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('phprcdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('porn.com', 'adultos', 'v2fly/domain-list-community'),
    ('porn300.com', 'adultos', 'v2fly/domain-list-community'),
    ('porndig.com', 'adultos', 'v2fly/domain-list-community'),
    ('porndude2.com', 'adultos', 'v2fly/domain-list-community'),
    ('porndudecasting.com', 'adultos', 'v2fly/domain-list-community'),
    ('porngub.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornhd.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornhub-deutsch.net', 'adultos', 'v2fly/domain-list-community'),
    ('pornhub.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornhub.org', 'adultos', 'v2fly/domain-list-community'),
    ('pornhubapparel.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornhubpremium.com', 'adultos', 'v2fly/domain-list-community'),
    ('porniq.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornktube.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornmd.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornobom.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('pornobrasil.blog.br', 'adultos', 'v2fly/domain-list-community'),
    ('pornocaserotube.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornogratis.vlog.br', 'adultos', 'v2fly/domain-list-community'),
    ('pornoid.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornone.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornotube.blog.br', 'adultos', 'v2fly/domain-list-community'),
    ('pornpair.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornpros.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornprosnetwork.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornsites.com', 'adultos', 'v2fly/domain-list-community'),
    ('porntrex.com', 'adultos', 'v2fly/domain-list-community'),
    ('pornwebmasters.com', 'adultos', 'v2fly/domain-list-community'),
    ('pussyporntubes.com', 'adultos', 'v2fly/domain-list-community'),
    ('rdtcdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('realgfporn.com', 'adultos', 'v2fly/domain-list-community'),
    ('realitykings.com', 'adultos', 'v2fly/domain-list-community'),
    ('redtube.com', 'adultos', 'v2fly/domain-list-community'),
    ('redtube.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('redtubepremium.com', 'adultos', 'v2fly/domain-list-community'),
    ('rk.com', 'adultos', 'v2fly/domain-list-community'),
    ('sb-cd.com', 'adultos', 'v2fly/domain-list-community'),
    ('seancody.com', 'adultos', 'v2fly/domain-list-community'),
    ('sex.com', 'adultos', 'v2fly/domain-list-community'),
    ('sexu.com', 'adultos', 'v2fly/domain-list-community'),
    ('sexvid.xxx', 'adultos', 'v2fly/domain-list-community'),
    ('shemaleporn.fun', 'adultos', 'v2fly/domain-list-community'),
    ('shemalepornonly.com', 'adultos', 'v2fly/domain-list-community'),
    ('slayed.com', 'adultos', 'v2fly/domain-list-community'),
    ('spankbang.com', 'adultos', 'v2fly/domain-list-community'),
    ('spankbang.party', 'adultos', 'v2fly/domain-list-community'),
    ('stripchat.com', 'adultos', 'v2fly/domain-list-community'),
    ('sunporno.com', 'adultos', 'v2fly/domain-list-community'),
    ('swingerpornfun.com', 'adultos', 'v2fly/domain-list-community'),
    ('thepornbet.com', 'adultos', 'v2fly/domain-list-community'),
    ('theporndude.cc', 'adultos', 'v2fly/domain-list-community'),
    ('theporndude.com', 'adultos', 'v2fly/domain-list-community'),
    ('theporndude.vip', 'adultos', 'v2fly/domain-list-community'),
    ('thumbzilla.com', 'adultos', 'v2fly/domain-list-community'),
    ('tnaflix.com', 'adultos', 'v2fly/domain-list-community'),
    ('tube8.com', 'adultos', 'v2fly/domain-list-community'),
    ('tube8.fr', 'adultos', 'v2fly/domain-list-community'),
    ('tufos.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('tushy.com', 'adultos', 'v2fly/domain-list-community'),
    ('tushyraw.com', 'adultos', 'v2fly/domain-list-community'),
    ('twistys.com', 'adultos', 'v2fly/domain-list-community'),
    ('txxx.com', 'adultos', 'v2fly/domain-list-community'),
    ('venezporn.com', 'adultos', 'v2fly/domain-list-community'),
    ('videos4sale.com', 'adultos', 'v2fly/domain-list-community'),
    ('videosdepornografia.blog.br', 'adultos', 'v2fly/domain-list-community'),
    ('videosdesexo.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('videosporno.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('vixen.com', 'adultos', 'v2fly/domain-list-community'),
    ('vixengroup.com', 'adultos', 'v2fly/domain-list-community'),
    ('voyeurhit.com', 'adultos', 'v2fly/domain-list-community'),
    ('webcams.tv', 'adultos', 'v2fly/domain-list-community'),
    ('whynotbi.com', 'adultos', 'v2fly/domain-list-community'),
    ('xdporner.com', 'adultos', 'v2fly/domain-list-community'),
    ('xfantazy.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster.desi', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster.xxx', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster18.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster18.desi', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster19.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster2.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhamster3.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhamsterlive.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhapp.live', 'adultos', 'v2fly/domain-list-community'),
    ('xhcdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhnews.live', 'adultos', 'v2fly/domain-list-community'),
    ('xhpingcdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('xhreal5.com', 'adultos', 'v2fly/domain-list-community'),
    ('xnxx-cdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('xnxx-tv.net', 'adultos', 'v2fly/domain-list-community'),
    ('xnxx.com', 'adultos', 'v2fly/domain-list-community'),
    ('xnxx.net', 'adultos', 'v2fly/domain-list-community'),
    ('xnxx.tv', 'adultos', 'v2fly/domain-list-community'),
    ('xnxx3.com', 'adultos', 'v2fly/domain-list-community'),
    ('xozilla.com', 'adultos', 'v2fly/domain-list-community'),
    ('xpornplease.com', 'adultos', 'v2fly/domain-list-community'),
    ('xtapes.to', 'adultos', 'v2fly/domain-list-community'),
    ('xv-ru.com', 'adultos', 'v2fly/domain-list-community'),
    ('xvideo.vlog.br', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos-ar.com', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos-cdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos-india.com', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos.com', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos.red', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos.tv.br', 'adultos', 'v2fly/domain-list-community'),
    ('xvideos5.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('xvideosnovinha.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('xvideosnovinhas.com', 'adultos', 'v2fly/domain-list-community'),
    ('xvideosup.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('xvideosx.com.br', 'adultos', 'v2fly/domain-list-community'),
    ('xxx-porn-fuck.com', 'adultos', 'v2fly/domain-list-community'),
    ('xxx-porn-tube.com', 'adultos', 'v2fly/domain-list-community'),
    ('xxxbunker.com', 'adultos', 'v2fly/domain-list-community'),
    ('xxxpornozinho.blog.br', 'adultos', 'v2fly/domain-list-community'),
    ('xxxsexocasero.com', 'adultos', 'v2fly/domain-list-community'),
    ('xxxstreams.org', 'adultos', 'v2fly/domain-list-community'),
    ('xxxvideo.blog.br', 'adultos', 'v2fly/domain-list-community'),
    ('xxxvideo.vip', 'adultos', 'v2fly/domain-list-community'),
    ('yjcontentdelivery.com', 'adultos', 'v2fly/domain-list-community'),
    ('yopornshop.com', 'adultos', 'v2fly/domain-list-community'),
    ('youjizz.com', 'adultos', 'v2fly/domain-list-community'),
    ('youporn.com', 'adultos', 'v2fly/domain-list-community'),
    ('youporngay.com', 'adultos', 'v2fly/domain-list-community'),
    ('youpornpremium.com', 'adultos', 'v2fly/domain-list-community'),
    ('youpornru.com', 'adultos', 'v2fly/domain-list-community'),
    ('ypncdn.com', 'adultos', 'v2fly/domain-list-community'),
    ('10bet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('12bet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('1pra1.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('1xbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('1xbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('22bet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('22betpartners.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('4play.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('4win.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('55w.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('5g.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('666casino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('6r.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('6z.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('7games.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('7k.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('9d.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('9f.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('a247.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('afun.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ai.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('alfa.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('americanfootballbetting.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('aposta.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('aposta1.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('apostaganha.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('apostamax.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('apostatudo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('apostou.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('arena-bet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('arenaplus.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('artemisbet10.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('aviao.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('b1bet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bacanaplay.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bandbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bateu.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bau.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bestbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bestbettoday.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet-at-home.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet-at-home.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet33.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet365.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bet365.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet365.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet4.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bet7days.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet90.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bet9ja.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betadria.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betaki.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betano.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betano.bg', 'apostas', 'Sinfonietta/hostfiles'),
    ('betano.cz', 'apostas', 'Sinfonietta/hostfiles'),
    ('betano.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('betano.pt', 'apostas', 'Sinfonietta/hostfiles'),
    ('betao.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betapp.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betboo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betboom.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betboro.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betbra.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betbuffalos.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betcaixa.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betclic.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betclic.pl', 'apostas', 'Sinfonietta/hostfiles'),
    ('betclic.pt', 'apostas', 'Sinfonietta/hostfiles'),
    ('betcopa.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betcris.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betcris.pl', 'apostas', 'Sinfonietta/hostfiles'),
    ('betdaq.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betdasorte.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betdna.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betespecial.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betesporte.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betextratime.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betfair.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betfair.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betfalcons.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betfast.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betfinal.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betfred.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betfusion.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betgo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betgorillas.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betika.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betinternet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betmclean.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betmgm.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betmotion.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betn1.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betnacional.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betonline.ag', 'apostas', 'Sinfonietta/hostfiles'),
    ('betorca.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betoto.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betou.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betpack.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betpix365.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betplay.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betpontobet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betroyal.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betsafe.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betsafe.lt', 'apostas', 'Sinfonietta/hostfiles'),
    ('betsson.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betsson.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betsul.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bettripledraw.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betvictor.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betvip.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betwarrior.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('betway.bg', 'apostas', 'Sinfonietta/hostfiles'),
    ('betway.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('betway.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('betway.pt', 'apostas', 'Sinfonietta/hostfiles'),
    ('big.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bingo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bingoplus.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('blaze.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bolsadeaposta.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('br4.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bra.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('brasil.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('brasildasorte.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bravo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('brazino777.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('brbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('brx.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bullsbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('bwin.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('bwin.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('bwin.pt', 'apostas', 'Sinfonietta/hostfiles'),
    ('bz.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('campobet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('casadeapostas.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('casinoeuro.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('casinoheroes.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('casinopop.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('cassino.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('cbesportes.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('centrebet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('cgg.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('circlebet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('cmdbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('contorabet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('crownbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('dafabet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('daftarbetplace88.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('diegocasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('donald.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('donosdabola.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('doxxbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('drbingo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('eccobet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('energia.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('energybet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('esporte365.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('esportiva.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('esportivavip.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('esportsbetting.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('estorilsolcasinos.pt', 'apostas', 'Sinfonietta/hostfiles'),
    ('estrelabet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('f12.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('fanbit.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('fastbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('faz1.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('fazo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('fikacasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('fogo777.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('free.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('fullbetter.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('fulltbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('fybet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('galera.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ganhei.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('geralbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ginga.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('goldebet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('goliathcasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('h2.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('hiper.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ice.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ijogo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('interwetten.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('interwetten.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('jackpotcity.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('jogajunto.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('jogalimpo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('jogao.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('jogodeouro.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('jogoonline.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('jogos.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('jojobet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('jonbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('kbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('kingpanda.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('kto.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('lancedesorte.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('lider.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('lotogreen.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('lottoland.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('lottu.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('louisvillecasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('lsbet690.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('luck.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('luckycasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('luva.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('magicjackpot.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('marathonbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('marsbet200.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('matchbook.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('maxima.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('mcgames.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('megabet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('megaposta.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('meridianbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('mgm.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('milhao.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('mmabet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('mobocasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('montecarlos.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('multi.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('naijabet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('netbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('nossa.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('novibet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('novibet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('obabet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('oleybet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ona.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('p9.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('pagol.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('papigames.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('parimatch.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('pin.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('pinnacle.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('pitaco.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('pix.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('play.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('playuzu.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('pointcasino.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('pokerstars.bg', 'apostas', 'Sinfonietta/hostfiles'),
    ('pokerstars.cz', 'apostas', 'Sinfonietta/hostfiles'),
    ('pokerstars.eu', 'apostas', 'Sinfonietta/hostfiles'),
    ('pq777.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('qg.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('r7.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('rdp.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('realdealbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('reals.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('receba.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('reidopitaco.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('rico.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('rivalo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('rivalo.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('rubet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('scandibet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('seguro.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('seu.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('skinbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('sortenabet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('sorteonline.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('sportingbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('sportingbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('sportingbet.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('sportsbet.io', 'apostas', 'Sinfonietta/hostfiles'),
    ('sporty.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('sssbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('stake.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('stake.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('start.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('statusbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('super.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('superbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('suprema.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('tiger.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('tipico.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('tipico.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('tivo.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('tradicional.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('tropino.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('ultra.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('unibet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('up.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vaidebet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vbet.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vbet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('vbet.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('vera.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('versus.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vert.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vivaro.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vivasorte.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('vupi.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('williamhill.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('winamax.de', 'apostas', 'Sinfonietta/hostfiles'),
    ('wjcasino.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('xbetcaixa.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('xx.bet.br', 'apostas', 'SPA/MF (2026-09-14)'),
    ('yabet.com', 'apostas', 'Sinfonietta/hostfiles'),
    ('aistudio.google.com', 'ia', 'v2fly:google-deepmind'),
    ('anthropic.com', 'ia', 'v2fly:anthropic'),
    ('chat.com', 'ia', 'v2fly:openai'),
    ('chatgpt.com', 'ia', 'v2fly:openai'),
    ('clau.de', 'ia', 'v2fly:anthropic'),
    ('claude.ai', 'ia', 'v2fly:anthropic'),
    ('claude.app', 'ia', 'v2fly:anthropic'),
    ('claude.com', 'ia', 'v2fly:anthropic'),
    ('claude.new', 'ia', 'v2fly:anthropic'),
    ('claudeusercontent.com', 'ia', 'v2fly:anthropic'),
    ('copilot.cloud.microsoft', 'ia', 'v2fly:category-ai-!cn'),
    ('copilot.com', 'ia', 'v2fly:category-ai-!cn'),
    ('copilot.microsoft.com', 'ia', 'v2fly:category-ai-!cn'),
    ('duck.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('gemini.google', 'ia', 'v2fly:google-deepmind'),
    ('gemini.google.com', 'ia', 'v2fly:google-deepmind'),
    ('gemini.gstatic.com', 'ia', 'v2fly:google-deepmind'),
    ('generativelanguage.googleapis.com', 'ia', 'v2fly:google-deepmind'),
    ('githubcopilot.com', 'ia', 'v2fly:github-copilot'),
    ('grok.com', 'ia', 'v2fly:xai'),
    ('grok.x.com', 'ia', 'v2fly:xai'),
    ('jasper.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('kimi.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('meta.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('midjourney.com', 'ia', 'v2fly:category-ai-!cn'),
    ('mistral.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('moonshot.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('notebooklm.google.com', 'ia', 'v2fly:google-deepmind'),
    ('oaistatic.com', 'ia', 'v2fly:openai'),
    ('oaiusercontent.com', 'ia', 'v2fly:openai'),
    ('openai.com', 'ia', 'v2fly:openai'),
    ('openrouter.ai', 'ia', 'v2fly:category-ai-!cn'),
    ('perplexity.ai', 'ia', 'v2fly:perplexity'),
    ('perplexity.com', 'ia', 'v2fly:perplexity'),
    ('poe.com', 'ia', 'v2fly:poe'),
    ('poecdn.net', 'ia', 'v2fly:poe'),
    ('pplx.ai', 'ia', 'v2fly:perplexity'),
    ('sora.com', 'ia', 'v2fly:openai'),
    ('x.ai', 'ia', 'v2fly:xai'),
    ('2k.com', 'jogos', 'v2fly:2kgames'),
    ('2kgames.com', 'jogos', 'v2fly:2kgames'),
    ('2ksports.com', 'jogos', 'v2fly:2kgames'),
    ('acesofthunder.net', 'jogos', 'v2fly:gaijin'),
    ('activematter.game', 'jogos', 'v2fly:gaijin'),
    ('activision.com', 'jogos', 'v2fly:activision'),
    ('activisionblizzard.com', 'jogos', 'v2fly:activision-blizzard'),
    ('addictinggames.com', 'jogos', 'https://addictinggames.com/'),
    ('arcraiders.com', 'jogos', 'v2fly:embark'),
    ('arma3.com', 'jogos', 'v2fly:bohemia'),
    ('armaplatform.com', 'jogos', 'v2fly:bohemia'),
    ('armorgames.com', 'jogos', 'https://armorgames.com/'),
    ('awayoutgame.com', 'jogos', 'v2fly:ea'),
    ('battle.net', 'jogos', 'v2fly:blizzard'),
    ('battlebreakers.com', 'jogos', 'v2fly:epicgames'),
    ('battlefieldbadcompany2.com', 'jogos', 'v2fly:ea'),
    ('battlefront2.com', 'jogos', 'v2fly:ea'),
    ('battlefrontii.com', 'jogos', 'v2fly:ea'),
    ('bejeweledstars.com', 'jogos', 'v2fly:ea'),
    ('blizzard.com', 'jogos', 'v2fly:blizzard'),
    ('boombeach.com', 'jogos', 'v2fly:supercell'),
    ('brawlstars.com', 'jogos', 'v2fly:supercell'),
    ('brawlstarsgame.com', 'jogos', 'v2fly:supercell'),
    ('callofduty.com', 'jogos', 'v2fly:activision'),
    ('callofdutyleague.com', 'jogos', 'v2fly:activision'),
    ('callofdutymobile.com', 'jogos', 'v2fly:activision'),
    ('candycrush.com', 'jogos', 'v2fly:activision-blizzard'),
    ('capitalgames.com', 'jogos', 'v2fly:ea'),
    ('clashofclans.com', 'jogos', 'v2fly:supercell'),
    ('clashroyale.com', 'jogos', 'v2fly:supercell'),
    ('clashroyaleapp.com', 'jogos', 'v2fly:supercell'),
    ('clickjogos.com.br', 'jogos', 'https://clickjogos.com.br/'),
    ('crashbandicoot.com', 'jogos', 'v2fly:activision'),
    ('crazygames.com', 'jogos', 'https://crazygames.com/'),
    ('crossout.net', 'jogos', 'v2fly:gaijin'),
    ('crsed.net', 'jogos', 'v2fly:gaijin'),
    ('crysis.jp', 'jogos', 'v2fly:ea'),
    ('cubicodyssey.game', 'jogos', 'v2fly:gaijin'),
    ('cyberpunk.net', 'jogos', 'v2fly:cdprojekt'),
    ('dayz.com', 'jogos', 'v2fly:bohemia'),
    ('demonware.net', 'jogos', 'v2fly:activision'),
    ('diablo.com', 'jogos', 'v2fly:blizzard'),
    ('diablo3.com', 'jogos', 'v2fly:blizzard'),
    ('diablo4.com', 'jogos', 'v2fly:blizzard'),
    ('diabloimmortal.com', 'jogos', 'v2fly:blizzard'),
    ('diep.io', 'jogos', 'https://diep.io/'),
    ('dota2.com', 'jogos', 'v2fly:steam'),
    ('ea.com', 'jogos', 'v2fly:ea'),
    ('eaaccess.com', 'jogos', 'v2fly:ea'),
    ('eamobile.com', 'jogos', 'v2fly:ea'),
    ('eaplay.com', 'jogos', 'v2fly:ea'),
    ('easports.com', 'jogos', 'v2fly:ea'),
    ('eastore.com', 'jogos', 'v2fly:origin'),
    ('electronicarts.com', 'jogos', 'v2fly:ea'),
    ('embark.games', 'jogos', 'v2fly:embark'),
    ('enlisted.net', 'jogos', 'v2fly:gaijin'),
    ('epicgames.com', 'jogos', 'v2fly:epicgames'),
    ('epicgamescdn.com', 'jogos', 'v2fly:epicgames'),
    ('faceit-cdn.net', 'jogos', 'v2fly:faceit'),
    ('faceit.com', 'jogos', 'v2fly:faceit'),
    ('fanatical.com', 'jogos', 'v2fly:category-games-!cn'),
    ('fortnite.com', 'jogos', 'v2fly:epicgames'),
    ('friv.com', 'jogos', 'https://friv.com/'),
    ('gaijin.net', 'jogos', 'v2fly:gaijin'),
    ('gamebanana.com', 'jogos', 'v2fly:category-games-!cn'),
    ('gamesplanet.com', 'jogos', 'v2fly:gamesplanet'),
    ('garena.com', 'jogos', 'v2fly:garena'),
    ('garena.live', 'jogos', 'v2fly:garena'),
    ('garenanow.com', 'jogos', 'v2fly:garena'),
    ('garticphone.com', 'jogos', 'https://garticphone.com/'),
    ('genshinimpact.com', 'jogos', 'v2fly:hoyoverse'),
    ('gog-services.com', 'jogos', 'v2fly:gog'),
    ('gog-statics.com', 'jogos', 'v2fly:gog'),
    ('gog.com', 'jogos', 'v2fly:gog'),
    ('gogalaxy.com', 'jogos', 'v2fly:gog'),
    ('gpstatic.com', 'jogos', 'v2fly:gamesplanet'),
    ('hayday.com', 'jogos', 'v2fly:supercell'),
    ('haydaygame.com', 'jogos', 'v2fly:supercell'),
    ('heroesofdragonage.com', 'jogos', 'v2fly:ea'),
    ('heroesofthestorm.com', 'jogos', 'v2fly:blizzard'),
    ('honkaiimpact3.com', 'jogos', 'v2fly:hoyoverse'),
    ('honkaistarrail.com', 'jogos', 'v2fly:hoyoverse'),
    ('hoyolab.com', 'jogos', 'v2fly:hoyoverse'),
    ('hoyoverse.com', 'jogos', 'v2fly:hoyoverse'),
    ('itch.io', 'jogos', 'v2fly:itchio'),
    ('itch.zone', 'jogos', 'v2fly:itchio'),
    ('jogos360.com.br', 'jogos', 'https://jogos360.com.br/'),
    ('joinsquad.com', 'jogos', 'v2fly:category-games-!cn'),
    ('king.com', 'jogos', 'v2fly:activision-blizzard'),
    ('kizi.com', 'jogos', 'https://kizi.com/'),
    ('konami.com', 'jogos', 'v2fly:konami'),
    ('konami.net', 'jogos', 'v2fly:konami'),
    ('konamionline.com', 'jogos', 'v2fly:konami'),
    ('kongregate.com', 'jogos', 'https://kongregate.com/'),
    ('krunker.io', 'jogos', 'https://krunker.io/'),
    ('lagged.com', 'jogos', 'https://lagged.com/'),
    ('leagueoflegends.com', 'jogos', 'v2fly:riot'),
    ('lolesports.com', 'jogos', 'v2fly:riot'),
    ('lolstatic.com', 'jogos', 'v2fly:riot'),
    ('lolusercontent.com', 'jogos', 'v2fly:riot'),
    ('masteroforion.com', 'jogos', 'v2fly:wargaming'),
    ('miniclip.com', 'jogos', 'https://miniclip.com/'),
    ('modernwarships.com', 'jogos', 'v2fly:gaijin'),
    ('nexon.com', 'jogos', 'v2fly:nexon'),
    ('nexon.net', 'jogos', 'v2fly:nexon'),
    ('nexoncdn.co.kr', 'jogos', 'v2fly:nexon'),
    ('nexongames.co.kr', 'jogos', 'v2fly:nexon'),
    ('nintendo.com', 'jogos', 'v2fly:nintendo'),
    ('nintendo.net', 'jogos', 'v2fly:nintendo'),
    ('nintendonetwork.net', 'jogos', 'v2fly:nintendo'),
    ('nintendostore.com', 'jogos', 'v2fly:nintendo'),
    ('nintendoswitch.com', 'jogos', 'v2fly:nintendo'),
    ('now.gg', 'jogos', 'https://now.gg/'),
    ('noxygames.com', 'jogos', 'v2fly:category-games-!cn'),
    ('origin.com', 'jogos', 'v2fly:origin'),
    ('playapex.com', 'jogos', 'v2fly:ea'),
    ('playartifact.com', 'jogos', 'v2fly:steam'),
    ('playbattlegrounds.com', 'jogos', 'v2fly:pubg'),
    ('playgwent.com', 'jogos', 'v2fly:cdprojekt'),
    ('playhearthstone.com', 'jogos', 'v2fly:blizzard'),
    ('playoverwatch.com', 'jogos', 'v2fly:blizzard'),
    ('playstation.com', 'jogos', 'v2fly:playstation'),
    ('playstation.net', 'jogos', 'v2fly:playstation'),
    ('playstationnetwork.com', 'jogos', 'v2fly:playstation'),
    ('playvalorant.com', 'jogos', 'v2fly:riot'),
    ('playwarcraft3.com', 'jogos', 'v2fly:blizzard'),
    ('pogo.com', 'jogos', 'v2fly:ea'),
    ('pogobeta.com', 'jogos', 'v2fly:ea'),
    ('pokemon.com', 'jogos', 'v2fly:nintendo'),
    ('poki.com', 'jogos', 'https://poki.com/'),
    ('popcap.com', 'jogos', 'v2fly:ea'),
    ('pubg.com', 'jogos', 'v2fly:pubg'),
    ('pvp.net', 'jogos', 'v2fly:riot'),
    ('reachthefinals.com', 'jogos', 'v2fly:embark'),
    ('riotcdn.net', 'jogos', 'v2fly:riot'),
    ('riotgames.com', 'jogos', 'v2fly:riot'),
    ('riotgames.net', 'jogos', 'v2fly:riot'),
    ('roborecall.com', 'jogos', 'v2fly:epicgames'),
    ('rockstargames.com', 'jogos', 'v2fly:rockstar'),
    ('rockstarnorth.com', 'jogos', 'v2fly:rockstar'),
    ('rsg.sc', 'jogos', 'v2fly:rockstar'),
    ('rstatic.net', 'jogos', 'v2fly:riot'),
    ('s.team', 'jogos', 'v2fly:steam'),
    ('sekirothegame.com', 'jogos', 'v2fly:activision'),
    ('shadowcomplex.com', 'jogos', 'v2fly:epicgames'),
    ('shellshock.io', 'jogos', 'https://shellshock.io/'),
    ('sierragames.com', 'jogos', 'v2fly:activision'),
    ('silicagame.com', 'jogos', 'v2fly:bohemia'),
    ('skylanders.com', 'jogos', 'v2fly:activision'),
    ('speedrun.com', 'jogos', 'v2fly:category-games-!cn'),
    ('spyrothedragon.com', 'jogos', 'v2fly:activision'),
    ('squadbusters.com', 'jogos', 'v2fly:supercell'),
    ('star-conflict.com', 'jogos', 'v2fly:gaijin'),
    ('starcraft.com', 'jogos', 'v2fly:blizzard'),
    ('starcraft2.com', 'jogos', 'v2fly:blizzard'),
    ('steam-api.com', 'jogos', 'v2fly:steam'),
    ('steam-chat.com', 'jogos', 'v2fly:steam'),
    ('steam.tv', 'jogos', 'v2fly:steam'),
    ('steamcommunity.com', 'jogos', 'v2fly:steam'),
    ('steamconnecttest.com', 'jogos', 'v2fly:steam'),
    ('steamcontent.com', 'jogos', 'v2fly:steam'),
    ('steamdb.info', 'jogos', 'v2fly:category-games-!cn'),
    ('steamdeck.com', 'jogos', 'v2fly:steam'),
    ('steamgames.com', 'jogos', 'v2fly:steam'),
    ('steampeek.hu', 'jogos', 'v2fly:category-games-!cn'),
    ('steampowered.com', 'jogos', 'v2fly:steam'),
    ('steamserver.net', 'jogos', 'v2fly:steam'),
    ('steamstatic.com', 'jogos', 'v2fly:steam'),
    ('steamusercontent.com', 'jogos', 'v2fly:steam'),
    ('stumbleguys.com', 'jogos', 'https://stumbleguys.com/'),
    ('supercell.com', 'jogos', 'v2fly:supercell'),
    ('supercell.net', 'jogos', 'v2fly:supercell'),
    ('supercellgames.com', 'jogos', 'v2fly:supercell'),
    ('supercellid.com', 'jogos', 'v2fly:supercell'),
    ('supercellstore.com', 'jogos', 'v2fly:supercell'),
    ('take2games.com', 'jogos', 'v2fly:take-two'),
    ('thewitcher.com', 'jogos', 'v2fly:cdprojekt'),
    ('tonyhawkthegame.com', 'jogos', 'v2fly:activision'),
    ('ubi.com', 'jogos', 'v2fly:ubisoft'),
    ('ubisoft.com', 'jogos', 'v2fly:ubisoft'),
    ('ubisoftconnect.com', 'jogos', 'v2fly:ubisoft'),
    ('underlords.com', 'jogos', 'v2fly:steam'),
    ('unrealtournament.com', 'jogos', 'v2fly:epicgames'),
    ('uplay.com', 'jogos', 'v2fly:ubisoft'),
    ('vigorgame.com', 'jogos', 'v2fly:bohemia'),
    ('vrchat.cloud', 'jogos', 'v2fly:vrchat'),
    ('vrchat.com', 'jogos', 'v2fly:vrchat'),
    ('vrchat.net', 'jogos', 'v2fly:vrchat'),
    ('wargaming.net', 'jogos', 'v2fly:wargaming'),
    ('warnerbrosgames.com', 'jogos', 'v2fly:wbgames'),
    ('warthunder.com', 'jogos', 'v2fly:gaijin'),
    ('wbagora.com', 'jogos', 'v2fly:wbgames'),
    ('wbgames.com', 'jogos', 'v2fly:wbgames'),
    ('worldoftanks.com', 'jogos', 'v2fly:wargaming'),
    ('worldoftanks.eu', 'jogos', 'v2fly:wargaming'),
    ('worldofwarcraft.com', 'jogos', 'v2fly:blizzard'),
    ('worldofwarplanes.com', 'jogos', 'v2fly:wargaming'),
    ('worldofwarships.asia', 'jogos', 'v2fly:wargaming'),
    ('worldofwarships.com', 'jogos', 'v2fly:wargaming'),
    ('worldseriesofwarzone.com', 'jogos', 'v2fly:activision'),
    ('wotblitz.com', 'jogos', 'v2fly:wargaming'),
    ('wowsblitz.com', 'jogos', 'v2fly:wargaming'),
    ('wtmobile.com', 'jogos', 'v2fly:gaijin'),
    ('y8.com', 'jogos', 'https://y8.com/'),
    ('ylands.com', 'jogos', 'v2fly:bohemia'),
    ('yugioh-card.com', 'jogos', 'v2fly:konami'),
    ('zenlesszonezero.com', 'jogos', 'v2fly:hoyoverse'),
    ('zynga.com', 'jogos', 'v2fly:zynga'),
    ('zyngapoker.com', 'jogos', 'v2fly:zynga'),
    ('chunkbase.com', 'minecraft', 'v2fly:category-games-!cn'),
    ('cubecraft.net', 'minecraft', 'https://help.cubecraft.net/en/article/how-do-i-join-cubecraft-java-edition-15kob0/'),
    ('fabricmc.net', 'minecraft', 'v2fly:category-games-!cn'),
    ('hypixel.net', 'minecraft', 'https://support.hypixel.net/hc/en-us/articles/360019495360-How-to-Join-the-Hypixel-Server'),
    ('launchermeta.mojang.com', 'minecraft', 'https://minecraft.wiki/w/Version_manifest.json'),
    ('libraries.minecraft.net', 'minecraft', 'https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Game_files'),
    ('mc.hypixel.net', 'minecraft', 'https://support.hypixel.net/hc/en-us/articles/360019495360-How-to-Join-the-Hypixel-Server'),
    ('minecraftforge.net', 'minecraft', 'v2fly:category-games-!cn'),
    ('minecraftservices.com', 'minecraft', 'v2fly:mojang'),
    ('minecraftshop.com', 'minecraft', 'v2fly:mojang'),
    ('namemc.com', 'minecraft', 'v2fly:category-games-!cn'),
    ('neoforged.net', 'minecraft', 'v2fly:category-games-!cn'),
    ('optifine.net', 'minecraft', 'v2fly:category-games-!cn'),
    ('papermc.io', 'minecraft', 'v2fly:category-games-!cn'),
    ('piston-data.mojang.com', 'minecraft', 'https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Game_files'),
    ('piston-meta.mojang.com', 'minecraft', 'https://piston-meta.mojang.com/mc/game/version_manifest_v2.json'),
    ('planetminecraft.com', 'minecraft', 'v2fly:category-games-!cn'),
    ('play.cubecraft.net', 'minecraft', 'https://help.cubecraft.net/en/article/how-do-i-join-cubecraft-java-edition-15kob0/'),
    ('prismlauncher.org', 'minecraft', 'v2fly:category-games-!cn'),
    ('quiltmc.org', 'minecraft', 'v2fly:category-games-!cn'),
    ('resources.download.minecraft.net', 'minecraft', 'https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Game_files'),
    ('spigotmc.org', 'minecraft', 'v2fly:category-games-!cn'),
    ('www.minecraft.net', 'minecraft', 'https://www.minecraft.net/en-us/download'),
    ('api.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('assetgame.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('captcha.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('chat.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('chatsite.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('clientsettings.api.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('js.rbxcdn.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('rblx.co', 'roblox', 'v2fly:roblox'),
    ('rblx.com', 'roblox', 'v2fly:roblox'),
    ('rblx.org', 'roblox', 'v2fly:roblox'),
    ('rbx.com', 'roblox', 'v2fly:roblox'),
    ('rbxcdn.com', 'roblox', 'v2fly:roblox'),
    ('rbxinfra.net', 'roblox', 'v2fly:roblox'),
    ('rbxlabs.com', 'roblox', 'v2fly:roblox'),
    ('rbxtrk.com', 'roblox', 'v2fly:roblox'),
    ('roblox-api.arkoselabs.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('roblox.ca', 'roblox', 'v2fly:roblox'),
    ('roblox.cl', 'roblox', 'v2fly:roblox'),
    ('roblox.co.jp', 'roblox', 'v2fly:roblox'),
    ('roblox.co.uk', 'roblox', 'v2fly:roblox'),
    ('roblox.com', 'roblox', 'v2fly:roblox'),
    ('roblox.de', 'roblox', 'v2fly:roblox'),
    ('roblox.eu', 'roblox', 'v2fly:roblox'),
    ('roblox.fr', 'roblox', 'v2fly:roblox'),
    ('roblox.it', 'roblox', 'v2fly:roblox'),
    ('roblox.jp', 'roblox', 'v2fly:roblox'),
    ('roblox.kr', 'roblox', 'v2fly:roblox'),
    ('roblox.mx', 'roblox', 'v2fly:roblox'),
    ('roblox.net', 'roblox', 'v2fly:roblox'),
    ('roblox.org', 'roblox', 'v2fly:roblox'),
    ('roblox.pt', 'roblox', 'v2fly:roblox'),
    ('roblox.tv', 'roblox', 'v2fly:roblox'),
    ('roblox.uk', 'roblox', 'v2fly:roblox'),
    ('roblox.us', 'roblox', 'v2fly:roblox'),
    ('robloxlabs.com', 'roblox', 'v2fly:roblox'),
    ('setup.rbxcdn.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('setup.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('static.rbxcdn.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('versioncompatibility.api.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
    ('www.roblox.com', 'roblox', 'https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks'),
)


# Banco SQLite local. Escritas da TI são transacionais; os leitores abrem a base
# em modo somente leitura. O chamador mantém a pasta privada à escrita de alunos.

CATALOG_CATEGORIES = ('jogos', 'roblox', 'minecraft', 'adultos', 'apostas', 'ia', 'outros')
CATALOG_ACTIVE_LIMIT = 975
_CATALOG_STORED_LIMIT = 10000
CATALOG_CSV_LIMIT = 2 * 1024 * 1024
_CATALOG_APP_ID = 0x4C474354  # LGCT
_CATALOG_SCHEMA = 1


def _catalog_domain(domain):
    return _domain_names([domain])[0]


def _catalog_category(value):
    if isinstance(value, str):
        value = value.strip().lower()
    if value not in CATALOG_CATEGORIES:
        raise ValueError('Categoria inválida. Use ' + ', '.join(CATALOG_CATEGORIES) + '.')
    return value


def _catalog_switch(value):
    if type(value) is not bool:
        raise ValueError('Informe se o item está ativo.')
    return int(value)


def _catalog_extras(values):
    if isinstance(values, (str, bytes)):
        raise ValueError('Informe uma lista de domínios da política.')
    return {_catalog_domain(domain) for domain in values}


def _catalog_limit(active):
    if len(active) > CATALOG_ACTIVE_LIMIT:
        raise ValueError(f'O limite é de {CATALOG_ACTIVE_LIMIT} domínios ativos, incluindo a política da TI. '
                         'Desative entradas ou categorias antes de continuar.')


class ClientCatalog:
    def __init__(self, path, *, seed_rows=None, seed_version=None):
        self.path = Path(path)
        self.seed_rows = CLIENT_CATALOG_ROWS if seed_rows is None else seed_rows
        self.seed_version = str(CLIENT_CATALOG_VERSION if seed_version is None else seed_version)
        self.notice = globals().get('CLIENT_CATALOG_NOTICE', '')
        if not isinstance(self.notice, str) or len(self.notice) > 512_000:
            raise ValueError('Aviso de licença ou proveniência inválido.')
        if not self.seed_version or len(self.seed_version) > 80:
            raise ValueError('Versão do catálogo inválida.')

    def _check_path(self):
        folder = self.path.parent.lstat()
        if not stat.S_ISDIR(folder.st_mode) or getattr(folder, 'st_file_attributes', 0) & 0x400:
            raise ValueError('A pasta do banco de sites precisa ser um diretório local válido.')
        for suffix in ('', '-journal', '-wal', '-shm'):
            try:
                info = self.path.with_name(self.path.name + suffix).lstat()
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or getattr(info, 'st_file_attributes', 0) & 0x400):
                raise ValueError('O banco de sites possui um vínculo ou um arquivo especial.')

    @contextmanager
    def _open(self, *, write=False, create=False):
        self._check_path()
        mode = 'rwc' if create else ('rw' if write else 'ro')
        uri = self.path.absolute().as_uri() + '?mode=' + mode
        db = sqlite3.connect(uri, uri=True, timeout=8, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            schema = db.execute('PRAGMA user_version').fetchone()[0]
            app = db.execute('PRAGMA application_id').fetchone()[0]
            if schema != _CATALOG_SCHEMA or app != _CATALOG_APP_ID:
                empty = create and schema == app == 0 and not db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone()
                if not empty:
                    raise ValueError('Banco de sites incompatível. Preserve o arquivo e confira a versão do cliente.')
                self._create(db)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _create(db):
        db.execute('CREATE TABLE catalog_meta (id INTEGER PRIMARY KEY CHECK(id=1), '
                   'revision INTEGER NOT NULL, seed_version TEXT NOT NULL)')
        db.execute("INSERT INTO catalog_meta VALUES (1, 0, '')")
        db.execute('CREATE TABLE categories (category TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)))')
        db.executemany('INSERT INTO categories VALUES (?,1)', ((name,) for name in CATALOG_CATEGORIES))
        db.execute('CREATE TABLE domains (domain TEXT PRIMARY KEY, category TEXT NOT NULL REFERENCES categories(category), '
                   'source TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), '
                   'shipped INTEGER NOT NULL CHECK(shipped IN (0,1)), touched INTEGER NOT NULL CHECK(touched IN (0,1)), '
                   'deleted INTEGER NOT NULL CHECK(deleted IN (0,1)))')
        db.execute('CREATE INDEX idx_catalog_category ON domains(category,deleted,enabled,domain)')
        db.execute(f'PRAGMA application_id={_CATALOG_APP_ID}')
        db.execute(f'PRAGMA user_version={_CATALOG_SCHEMA}')

    @staticmethod
    def _revision(db):
        return db.execute('SELECT revision FROM catalog_meta WHERE id=1').fetchone()[0]

    @staticmethod
    def _advance(db):
        db.execute('UPDATE catalog_meta SET revision=revision+1 WHERE id=1')

    @staticmethod
    def _visible(db, domain):
        return db.execute('SELECT * FROM domains WHERE domain=? AND deleted=0', (domain,)).fetchone()

    @staticmethod
    def _active(db, extra):
        active = set(extra)
        active.update(row[0] for row in db.execute(
            'SELECT d.domain FROM domains d JOIN categories c USING(category) '
            'WHERE d.deleted=0 AND d.enabled=1 AND c.enabled=1'))
        _catalog_limit(active)
        return active

    @staticmethod
    def _size(db):
        if db.execute('SELECT COUNT(*) FROM domains').fetchone()[0] > _CATALOG_STORED_LIMIT:
            raise ValueError(f'O banco comporta até {_CATALOG_STORED_LIMIT} registros locais.')

    def ensure(self, *, extra_domains=()):
        """Seed offline once per dataset version; retain edits, switches and deleted built-ins."""
        extra = _catalog_extras(extra_domains)
        def current(db):
            return db.execute('SELECT seed_version FROM catalog_meta WHERE id=1').fetchone()[0] == self.seed_version
        def notice_current(db):
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_notices'").fetchone():
                return False
            row = db.execute("SELECT content FROM catalog_notices WHERE key='distribuicao'").fetchone()
            return bool(row and row[0] == self.notice)
        if self.path.exists() and self.path.stat().st_size:
            # Another installer may have created the DB file before committing its first schema.
            try:
                with self._open() as db:
                    if current(db) and notice_current(db):
                        if extra:
                            self._active(db, extra)
                        return self._revision(db)
            except ValueError:
                pass
        with self._open(write=True, create=True) as db:
            if not notice_current(db):
                db.execute('CREATE TABLE IF NOT EXISTS catalog_notices(key TEXT PRIMARY KEY,content TEXT NOT NULL)')
                db.execute("INSERT INTO catalog_notices(key,content) VALUES('distribuicao',?) "
                           "ON CONFLICT(key) DO UPDATE SET content=excluded.content", (self.notice,))
            if current(db):
                if extra:
                    self._active(db, extra)
                return self._revision(db)
            db.execute('CREATE TEMP TABLE incoming(domain TEXT PRIMARY KEY, category TEXT, source TEXT)')
            for domain, category, source in self.seed_rows:
                domain, category = _catalog_domain(domain), _catalog_category(category)
                if not isinstance(source, str) or not source or len(source) > 2048 or not source.isprintable():
                    raise ValueError('Fonte inválida na lista distribuída.')
                if db.execute('SELECT 1 FROM incoming WHERE domain=?', (domain,)).fetchone():
                    raise ValueError(f'O domínio {domain} está repetido na lista distribuída.')
                db.execute('INSERT INTO incoming VALUES (?,?,?)', (domain, category, source))
            # Removed seed records disappear unless the TI has customized them.
            db.execute('DELETE FROM domains WHERE shipped=1 AND touched=0 AND domain NOT IN (SELECT domain FROM incoming)')
            db.execute('UPDATE domains SET shipped=0 WHERE shipped=1 AND domain NOT IN (SELECT domain FROM incoming)')
            db.execute('INSERT INTO domains(domain,category,source,enabled,shipped,touched,deleted) '
                       'SELECT domain,category,source,1,1,0,0 FROM incoming WHERE 1 '
                       'ON CONFLICT(domain) DO UPDATE SET shipped=1, '
                       'category=CASE WHEN touched=0 THEN excluded.category ELSE domains.category END, '
                       'source=CASE WHEN touched=0 THEN excluded.source ELSE domains.source END')
            self._size(db)
            self._active(db, extra)
            db.execute('UPDATE catalog_meta SET seed_version=?,revision=revision+1 WHERE id=1', (self.seed_version,))
            return self._revision(db)

    def revision(self):
        with self._open() as db:
            return self._revision(db)

    def notices(self):
        with self._open() as db:
            return dict(db.execute('SELECT key,content FROM catalog_notices'))

    def effective_snapshot(self, extra_domains=()):
        """Returns (revision, sorted effective domains) from one committed snapshot."""
        extra = _catalog_extras(extra_domains)
        with self._open() as db:
            return self._revision(db), sorted(self._active(db, extra))

    def effective(self, extra_domains=()):
        return self.effective_snapshot(extra_domains)[1]

    def categories(self):
        with self._open() as db:
            rows = db.execute('SELECT c.category,c.enabled,COUNT(d.domain) AS total, '
                              'COALESCE(SUM(d.enabled*c.enabled),0) AS active FROM categories c '
                              'LEFT JOIN domains d ON d.category=c.category AND d.deleted=0 GROUP BY c.category,c.enabled')
            summaries = {r['category']: dict(r, enabled=bool(r['enabled'])) for r in rows}
            return [summaries[name] for name in CATALOG_CATEGORIES]

    def search(self, query='', category=None, *, limit=100, offset=0):
        if not isinstance(query, str) or len(query) > 255:
            raise ValueError('Pesquisa de domínio inválida.')
        if type(limit) is not int or not 1 <= limit <= 1000 or type(offset) is not int or offset < 0:
            raise ValueError('Intervalo de consulta inválido.')
        terms, params = ['d.deleted=0'], []
        if query.strip():
            terms.append('instr(d.domain,?)>0')
            params.append(query.strip().lower())
        if category is not None:
            terms.append('d.category=?')
            params.append(_catalog_category(category))
        with self._open() as db:
            rows = db.execute('SELECT d.domain,d.category,d.source,d.enabled,d.touched,d.shipped, '
                              '(d.enabled AND c.enabled) AS effective FROM domains d JOIN categories c USING(category) '
                              'WHERE ' + ' AND '.join(terms) + ' ORDER BY d.domain LIMIT ? OFFSET ?', (*params, limit, offset))
            return [dict(row, enabled=bool(row['enabled']), effective=bool(row['effective']),
                         touched=bool(row['touched']), shipped=bool(row['shipped'])) for row in rows]

    @staticmethod
    def _forget(db, domain):
        row = ClientCatalog._visible(db, domain)
        if row is None:
            raise ValueError('Este domínio já foi removido ou não está cadastrado.')
        if row['shipped']:
            db.execute('UPDATE domains SET deleted=1,touched=1 WHERE domain=?', (domain,))
        else:
            db.execute('DELETE FROM domains WHERE domain=?', (domain,))

    @staticmethod
    def _save(db, domain, category, enabled, origin):
        db.execute('INSERT INTO domains(domain,category,source,enabled,shipped,touched,deleted) VALUES(?,?,?,?,0,1,0) '
                   'ON CONFLICT(domain) DO UPDATE SET category=excluded.category,enabled=excluded.enabled, '
                   'touched=1,deleted=0', (domain, category, origin, enabled))

    def put(self, domain, category, enabled=True, *, original=None, extra_domains=()):
        domain, category, enabled = _catalog_domain(domain), _catalog_category(category), _catalog_switch(enabled)
        original = _catalog_domain(original) if original is not None else None
        extra = _catalog_extras(extra_domains)
        with self._open(write=True) as db:
            target = self._visible(db, domain)
            if target and original != domain:
                raise ValueError('Domínio já cadastrado. Selecione a entrada para editá-la.')
            if original is not None:
                if original != domain:
                    self._forget(db, original)
                elif target is None:
                    raise ValueError('A entrada original foi removida.')
                elif target['category'] == category and target['enabled'] == enabled:
                    return self._revision(db)
            self._save(db, domain, category, enabled, 'TI')
            self._size(db)
            self._active(db, extra)
            self._advance(db)
            return self._revision(db)

    def delete(self, domain, *, extra_domains=()):
        domain = _catalog_domain(domain)
        extra = _catalog_extras(extra_domains)
        with self._open(write=True) as db:
            self._forget(db, domain)
            self._active(db, extra)
            self._advance(db)
            return self._revision(db)

    def set_category(self, category, enabled, *, extra_domains=()):
        category, enabled = _catalog_category(category), _catalog_switch(enabled)
        extra = _catalog_extras(extra_domains)
        with self._open(write=True) as db:
            changed = db.execute('UPDATE categories SET enabled=? WHERE category=? AND enabled!=?',
                                 (enabled, category, enabled)).rowcount
            if changed:
                self._active(db, extra)
                self._advance(db)
            return self._revision(db)

    @staticmethod
    def _parse_csv(text):
        if not isinstance(text, str) or len(text) > CATALOG_CSV_LIMIT or len(text.encode('utf8')) > CATALOG_CSV_LIMIT:
            raise ValueError('O CSV deve ser UTF-8 com no máximo 2 MiB.')
        text = text.removeprefix('\ufeff')
        first_line = text.partition('\n')[0]
        csv_file = csv.reader(io.StringIO(text, newline=''), delimiter=';' if ';' in first_line else ',', strict=True)
        try:
            header = next(csv_file, [])
            if tuple(v.strip().lower() for v in header) not in (('dominio','categoria','ativo'), ('domain','category','enabled')):
                raise ValueError('O cabeçalho do CSV deve ser dominio,categoria,ativo.')
            rows = {}
            for values in csv_file:
                if not values:
                    continue
                line = csv_file.line_num
                if len(values) != 3:
                    raise ValueError(f'Linha {line} do CSV com número incorreto de colunas.')
                try:
                    domain = _catalog_domain(values[0])
                    category = _catalog_category(values[1])
                    switch = values[2].strip().lower()
                    if switch not in ('1','0','sim','não','nao','true','false'):
                        raise ValueError('Use 1 ou 0 na coluna ativo.')
                except ValueError as error:
                    raise ValueError(f'Linha {line} do CSV. {error}') from None
                if domain in rows:
                    raise ValueError(f'Linha {line} do CSV. O domínio {domain} está repetido.')
                rows[domain] = (category, int(switch in ('1','sim','true')))
                if len(rows) > _CATALOG_STORED_LIMIT:
                    raise ValueError(f'O CSV excede {_CATALOG_STORED_LIMIT} registros.')
        except csv.Error:
            raise ValueError('Estrutura inválida no arquivo CSV.') from None
        if not rows:
            raise ValueError('O CSV não contém domínios.')
        return rows

    def _plan(self, db, rows, extra):
        current = {r['domain']:(r['category'],r['enabled']) for r in db.execute(
            'SELECT domain,category,enabled FROM domains WHERE deleted=0')}
        enabled = {r[0] for r in db.execute('SELECT category FROM categories WHERE enabled=1')}
        added = sum(domain not in current for domain in rows)
        changed = {k:v for k,v in rows.items() if current.get(k) != v}
        current.update(changed)
        all_keys = {r[0] for r in db.execute('SELECT domain FROM domains')}
        if len(all_keys.union(rows)) > _CATALOG_STORED_LIMIT:
            raise ValueError(f'O banco comporta até {_CATALOG_STORED_LIMIT} registros locais.')
        active = extra | {domain for domain,(category,on) in current.items() if on and category in enabled}
        _catalog_limit(active)
        return {'revision': self._revision(db), 'added': added, 'updated':len(changed)-added,
                'unchanged':len(rows)-len(changed), 'total':len(rows), 'active':len(active)}, changed

    def preview_import(self, csv_text, *, extra_domains=()):
        rows, extra = self._parse_csv(csv_text), _catalog_extras(extra_domains)
        with self._open() as db:
            return self._plan(db, rows, extra)[0]

    def import_csv(self, csv_text, *, expected_revision, extra_domains=()):
        rows, extra = self._parse_csv(csv_text), _catalog_extras(extra_domains)
        with self._open(write=True) as db:
            if type(expected_revision) is not int or self._revision(db) != expected_revision:
                raise ValueError('O banco mudou desde a prévia. Confira a importação novamente.')
            summary, changed = self._plan(db, rows, extra)
            for domain,(category,on) in changed.items():
                self._save(db, domain, category, on, 'CSV')
            if changed:
                self._size(db)
                self._advance(db)
                summary['revision'] = self._revision(db)
            return summary

    def export_csv(self):
        stream = io.StringIO(newline='')
        writer = csv.writer(stream, lineterminator='\r\n')
        writer.writerow(('dominio','categoria','ativo'))
        with self._open() as db:
            rows = db.execute('SELECT domain,category,enabled FROM domains WHERE deleted=0 ORDER BY domain')
            writer.writerows(tuple(r) for r in rows)
        return stream.getvalue()


# Ciclo de vida da instalação Windows. Uma tarefa nomeada inicia o cliente no boot.


_LC_NAME = 'LabGuardCliente'
_LC_AUTH = 'LabGuard Cliente escolar'
_LC_RECORD = 'instalacao.json'
_LC_SID_SYSTEM = 'S-1-5-18'
_LC_SID_ADMINS = 'S-1-5-32-544'
_LC_TRUSTED = {_LC_SID_SYSTEM, _LC_SID_ADMINS,
               'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
_LC_DB_SIDECARS = {'banco.sqlite3-journal', 'banco.sqlite3-wal', 'banco.sqlite3-shm'}
_LC_PREVIOUS = 'cliente.anterior'
_LC_STAGE = 'cliente.preparado'
_LC_RECORD_STAGE = 'instalacao.tmp'
_LC_KNOWN = _LC_DB_SIDECARS | {_LC_PREVIOUS, _LC_STAGE, _LC_RECORD_STAGE, 'banco.sqlite3', _LC_RECORD, 'politica.json', 'estado.json', 'status.json', 'operacao.lock',
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
            try:
                _lc_guard_file(target)
            except FileNotFoundError:
                # SQLite can delete a transient sidecar as a concurrent transaction ends.
                if name not in _LC_DB_SIDECARS:
                    raise
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


def _lc_write_record(directory, record):
    staged=directory/_LC_RECORD_STAGE
    with staged.open('wb') as f:
        f.write(json.dumps(record,ensure_ascii=False).encode('utf8'))
        f.flush()
        os.fsync(f.fileno())
    os.replace(staged, directory/_LC_RECORD)


def _lc_stop_task(directory, task):
    (directory/'parar.flag').write_text('TI',encoding='ascii')
    if not task or task['state'] not in (2,4):
        return
    deadline=time.monotonic()+6
    while time.monotonic()<deadline and (_lc_task() or {}).get('state') in (2,4):
        time.sleep(.35)
    if (_lc_task() or {}).get('state') in (2,4):
        _lc_schtasks('/End','/TN',_LC_NAME)
    deadline=time.monotonic()+12
    while (_lc_task() or {}).get('state') in (2,4):
        if time.monotonic()>=deadline:
            raise RuntimeError('A tarefa ainda está parando. Repita a operação quando ela encerrar.')
        time.sleep(.5)


def _lc_copy_staged(source, target, digest):
    with source.open('rb') as incoming, target.open('wb') as outgoing:
        shutil.copyfileobj(incoming,outgoing)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    if _lc_sha(target)!=digest:
        raise RuntimeError('A cópia não corresponde ao programa de origem. Confira o instalador.')


def _lc_recover_copy(directory, record):
    # A previous upgrade may have lost power between replacing the executable
    # and atomically committing its manifest. Only restore the recorded digest.
    live=directory/record['copy']
    backup=directory/_LC_PREVIOUS
    if _lc_sha(live)==record['sha256']:
        return
    if ((directory/'parar.flag').is_file() and backup.is_file()
            and _lc_sha(backup)==record['sha256']):
        os.replace(backup,live)
        return
    raise RuntimeError('O programa instalado mudou. Confira a integridade antes de continuar.')


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
        existing=None
        if not fresh:
            existing=_lc_load(directory)
            if any(existing[k]!=candidate[k] for k in candidate):
                raise RuntimeError('O formato ou o Python da instalação é diferente. Use o mesmo formato para preservar a política.')
            _lc_owned_task(task,directory,existing)
            _lc_recover_copy(directory,existing)
        upgrading=bool(existing and existing['sha256']!=digest)
        record=dict(candidate,owner='LabGuardCliente/1',sha256=digest,version=CLIENT_VERSION)
        run_command=_lc_run_string(directory,record)
        if run is not None and run!=run_command:
            raise RuntimeError('A entrada de inicialização pertence a outro programa.')
        created_task=created_run=replaced=enabled_task=False
        old_task_stopped=False
        dest=directory/record['copy']
        backup=directory/_LC_PREVIOUS
        stage=directory/_LC_STAGE
        if fresh:
            _lc_make_directory(directory)
        try:
            if fresh:
                _lc_copy_staged(src,dest,digest)
                _lc_write_record(directory,record)
                _lc_load(directory)
            elif upgrading:
                _lc_copy_staged(src,stage,digest)
                _lc_stop_task(directory,task)
                old_task_stopped=True
                _lc_copy_staged(dest,backup,existing['sha256'])
                os.replace(stage,dest)
                replaced=True
                _lc_write_record(directory,record)
            initialize(directory)
            if existing and not upgrading and existing.get('version') != CLIENT_VERSION:
                _lc_write_record(directory,record)
            (directory/'parar.flag').unlink(missing_ok=True)
            if task is None:
                xml=directory/'tarefa.xml'
                xml.write_bytes(_lc_task_xml(directory,record))
                try:
                    _lc_schtasks('/Create','/TN',_LC_NAME,'/XML',xml)
                    created_task=True
                finally:
                    xml.unlink(missing_ok=True)
            elif task['state']==1:
                # An explicit Instalar/Ativar restores an owned task disabled by TI.
                _lc_schtasks('/Change','/TN',_LC_NAME,'/ENABLE')
                enabled_task=True
            if run is None:
                _lc_user_start(run_command)
                created_run=True
            _lc_schtasks('/Run','/TN',_LC_NAME)
        except Exception:
            if enabled_task:
                _lc_schtasks('/Change','/TN',_LC_NAME,'/DISABLE')
            if created_task:
                _lc_schtasks('/Delete','/F','/TN',_LC_NAME)
            if created_run:
                _lc_user_start(run_command,remove=True)
            if upgrading:
                if replaced:
                    if _lc_sha(backup)!=existing['sha256']:
                        raise RuntimeError('A atualização parou. Confira o backup do programa antes de continuar.')
                    os.replace(backup,dest)
                    _lc_write_record(directory,existing)
                if old_task_stopped:
                    (directory/'parar.flag').unlink(missing_ok=True)
                    if task is not None and task['state']!=1:
                        _lc_schtasks('/Run','/TN',_LC_NAME)
            if fresh:
                for name in _LC_KNOWN:
                    (directory/name).unlink(missing_ok=True)
                directory.rmdir()
            raise
        else:
            backup.unlink(missing_ok=True)
        finally:
            stage.unlink(missing_ok=True)
        return {'ok':True,'installed':True,'updated':upgrading,'task':_LC_NAME,'directory':str(directory),
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
            'installed_version':record.get('version'),'update_available':record.get('version')!=CLIENT_VERSION,
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
        _lc_stop_task(directory, task)
        if task:
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
    desired_set = set(desired)
    for slot, previous in list(owned.items()):
        if current.get(slot) != (previous, registry.string_type):
            # A GPO or another administrator changed the policy, or an interrupted
            # write left only a journal record. Never overwrite a replaced value.
            del owned[slot]
        elif previous not in desired_set:
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
    additions = list(zip(free, missing))
    for offset in range(0, len(additions), 32):
        batch = additions[offset:offset+32]
        owned.update(batch)
        checkpoint()  # Durable reservations precede every registry write in the batch.
        for slot, value in batch:
            registry.add_if_free(path, slot, value)
    for offset in range(0, len(inactive), 32):
        for slot in inactive[offset:offset+32]:
            remove(slot)
        checkpoint()
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
    if policy.get("mode") == "permitidos":
        allowed = policy.get("allowed_domains", [])
        names = {name for name in names if not any(name == domain or name.endswith("." + domain) for domain in allowed)}
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


# Snapshot is read outside the GUI thread, using the same catalog as the worker.
def _admin_bank_snapshot(installed, admin):
    if not installed:
        rows = [{"domain": d, "category": cat, "source": origin, "enabled": True, "effective": True}
                for d, cat, origin in CLIENT_CATALOG_ROWS]
        counts = {cat: sum(row["category"] == cat for row in rows) for cat in CATALOG_CATEGORIES}
        return rows, [{"category": cat, "enabled": True, "total": count, "active": count}
                      for cat, count in counts.items()]
    if not admin:
        return [], []
    catalog = get_site_bank()
    for attempt in range(2):
        revision = catalog.revision()
        groups = catalog.categories()
        rows = []
        for offset in range(0, sum(group["total"] for group in groups), 500):
            rows.extend(catalog.search(limit=500, offset=offset))
        if revision == catalog.revision():
            return rows, groups
    raise RuntimeError("O catálogo foi alterado durante a leitura. Atualize o estado.")


def _admin_bank_tab(parent, root, submit, read_state, display, *, can_edit, is_installed):
    import pathlib
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    labels = {"jogos": "Jogos", "roblox": "Roblox", "minecraft": "Minecraft",
              "adultos": "Adultos", "apostas": "Apostas", "ia": "IA", "outros": "Outros"}
    reverse = {label: key for key, label in labels.items()}
    all_groups = "Todas"
    search, category, summary = tk.StringVar(), tk.StringVar(value=all_groups), tk.StringVar()
    rows, groups, shown = [], {}, {}
    page = 0
    per_page = 80
    parent.columnconfigure(0, weight=1)
    parent.rowconfigure(2, weight=1)
    title = tk.Label(parent, textvariable=summary, bg="white", fg="#50318d",
                     font=("Segoe UI", 10, "bold"), anchor="w", justify="left", wraplength=575)
    title.grid(row=0, column=0, sticky="ew", pady=(0, 7))
    filters = ttk.Frame(parent, style="Card.TFrame")
    filters.grid(row=1, column=0, sticky="ew", pady=(0, 5))
    filters.columnconfigure(1, weight=1)
    ttk.Label(filters, text="Buscar", background="white").grid(row=0, column=0, padx=(0, 5))
    ttk.Entry(filters, textvariable=search).grid(row=0, column=1, sticky="ew")
    ttk.Label(filters, text="Categoria", background="white").grid(row=0, column=2, padx=(9, 5))
    ttk.Combobox(filters, textvariable=category, values=[all_groups, *labels.values()], state="readonly",
                 width=12).grid(row=0, column=3)
    frame = ttk.Frame(parent, style="Card.TFrame")
    frame.grid(row=2, column=0, sticky="nsew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    tree = ttk.Treeview(frame, columns=("domain", "cat", "state"), show="headings",
                        selectmode="browse", height=5)
    for field, name, width in (("domain", "Domínio", 220), ("cat", "Categoria", 110),
                                ("state", "Bloqueio no banco", 135)):
        tree.heading(field, text=name)
        tree.column(field, width=width, minwidth=65, stretch=(field == "domain"))
    tree.grid(row=0, column=0, sticky="nsew")
    scroll = ttk.Scrollbar(frame, command=tree.yview)
    scroll.grid(row=0, column=1, sticky="ns")
    tree.configure(yscrollcommand=scroll.set)
    tools = ttk.Frame(parent, style="Card.TFrame")
    tools.grid(row=3, column=0, sticky="ew", pady=(5, 0))
    page_info = tk.StringVar()
    page_bar = ttk.Frame(parent, style="Card.TFrame")
    page_bar.grid(row=4, column=0, sticky="ew", pady=(4, 0))
    def button(bar, text, cb):
        w = ttk.Button(bar, text=text, command=cb)
        w.pack(side="left", padx=(0, 4))
        return w
    def selected():
        selection = tree.selection()
        return shown.get(selection[0]) if selection else None
    def mutator(action, *args, **kwargs):
        def operation():
            bank_change(action, *args, **kwargs)
            return read_state()
        submit("Atualizando o banco de sites…", operation,
               lambda result: display(result, False, "Banco salvo. O cliente confere as novas regras no próximo ciclo."))

    def entry_dialog(edit):
        original = selected() if edit else {}
        if not can_edit() or original is None:
            return
        dialog = tk.Toplevel(root)
        dialog.title("Editar domínio" if edit else "Novo domínio")
        dialog.transient(root)
        dialog.resizable(False, False)
        body = ttk.Frame(dialog, style="Card.TFrame", padding=14)
        body.pack()
        domain = tk.StringVar(value=original.get("domain", ""))
        cat = tk.StringVar(value=labels.get(original.get("category"), category.get() if category.get() != all_groups else "Outros"))
        active = tk.BooleanVar(value=original.get("enabled", True))
        ttk.Label(body, text="Domínio", background="white").grid(row=0, column=0, sticky="w", pady=4)
        entry = ttk.Entry(body, textvariable=domain, width=32)
        entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(body, text="Categoria", background="white").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Combobox(body, values=list(labels.values()), textvariable=cat, state="readonly").grid(row=1,column=1,sticky="ew")
        ttk.Checkbutton(body, text="Ativo para bloqueio", variable=active,
                        style="LG.TCheckbutton").grid(row=2, column=1, sticky="w", pady=4)
        def save():
            name = domain.get().strip()
            if not name:
                entry.focus_set()
                return
            values = name, reverse[cat.get()], bool(active.get())
            dialog.destroy()
            mutator("put", *values, original=original.get("domain"))
        ttk.Button(body,text="Salvar domínio",command=save).grid(row=3,column=1,sticky="e",pady=(8,0))
        entry.focus_set()
        dialog.grab_set()

    def delete():
        row = selected()
        if can_edit() and row and messagebox.askyesno("Excluir do banco", f"Excluir {row['domain']} deste banco?", parent=root, default="no"):
            mutator("delete", row["domain"])

    def toggle_category():
        code = reverse.get(category.get())
        if not can_edit() or not code or code not in groups:
            return
        active = not groups[code]["enabled"]
        verb = "Ativar" if active else "Pausar"
        if messagebox.askyesno("Alterar categoria", f"{verb} a categoria {labels[code]} nesta estação? "
                    "A escolha individual de cada domínio será mantida.", parent=root, default="no"):
            mutator("set_category", code, active)

    def import_csv():
        if not can_edit():
            return
        filename = filedialog.askopenfilename(parent=root, title="Importar CSV · dominio, categoria, ativo",
                                             filetypes=[("Arquivo CSV", "*.csv"), ("Todos", "*.*")])
        if not filename:
            return
        def preview():
            with open(filename, "rb") as f:
                raw = f.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("O arquivo CSV ultrapassa 2 MiB.")
            data = raw.decode("utf-8-sig")
            return data, bank_preview_import(data)
        def confirm(result):
            data, info = result
            prompt = (f"Novos: {info['added']}\nAtualizados: {info['updated']}\n"
                      f"Sem alteração: {info['unchanged']}\n\nImportar esse arquivo para o banco da estação?")
            if messagebox.askyesno("Revisar importação", prompt, parent=root, default="no"):
                mutator("import_csv", data, expected_revision=info["revision"])
        submit("Verificando o CSV…", preview, confirm)

    def export_csv():
        if not can_edit():
            return
        filename = filedialog.asksaveasfilename(parent=root, title="Exportar para um arquivo novo",
                       defaultextension=".csv", initialfile="labguard-sites.csv", filetypes=[("Arquivo CSV","*.csv")])
        if not filename:
            return
        def export():
            data = get_site_bank().export_csv()
            try:
                with pathlib.Path(filename).open("x", encoding="utf-8-sig", newline="") as out:
                    out.write(data)
            except FileExistsError:
                raise ValueError("Escolha um nome de arquivo novo para exportar o banco.") from None
        submit("Exportando o banco…", export, lambda _: messagebox.showinfo("Banco de sites", "Arquivo CSV exportado.", parent=root))

    new = button(tools, "Novo", lambda: entry_dialog(False))
    edit = button(tools, "Editar", lambda: entry_dialog(True))
    exclude = button(tools, "Excluir", delete)
    group_button = button(tools, "Pausar categoria", toggle_category)
    imp = button(tools, "Importar CSV", import_csv)
    exp = button(tools, "Exportar CSV", export_csv)
    prev = button(page_bar, "Anterior", lambda: turn(-1))
    nxt = button(page_bar, "Próxima", lambda: turn(1))
    ttk.Label(page_bar, textvariable=page_info, background="white").pack(side="left", padx=5)
    def buttons():
        mutable = can_edit()
        chosen = selected() is not None
        group = groups.get(reverse.get(category.get()))
        for item, usable in ((new, mutable), (imp, mutable), (exp, mutable),
                             (edit, mutable and chosen), (exclude, mutable and chosen),
                             (group_button, mutable and bool(group))):
            item.state(["!disabled" if usable else "disabled"])
        group_button.configure(text="Ativar categoria" if group and not group["enabled"] else "Pausar categoria")
    def render(reset=False):
        nonlocal page
        if reset:
            page = 0
        term = search.get().strip().lower()
        code = reverse.get(category.get())
        filtered = [row for row in rows if term in row["domain"] and (code is None or row["category"] == code)]
        pages = max(1, (len(filtered) + per_page - 1) // per_page)
        page = max(0, min(page, pages - 1))
        old = tree.get_children()
        if old: tree.delete(*old)
        shown.clear()
        for row in filtered[page*per_page:(page+1)*per_page]:
            state = "Ativo" if row["effective"] else "Inativo"
            iid = tree.insert("", "end", values=(row["domain"], labels.get(row["category"], row["category"]), state))
            shown[iid] = row
        prev.state(["!disabled" if page else "disabled"])
        nxt.state(["!disabled" if page < pages-1 else "disabled"])
        page_info.set(f"{len(filtered)} encontrados  •  página {page+1} de {pages}")
        buttons()
    def turn(delta):
        nonlocal page
        page += delta
        render()
    def set_snapshot(values, enabled):
        nonlocal rows, groups
        rows, categories = values
        groups = {g["category"]:g for g in categories}
        active = sum(bool(row["effective"]) for row in rows)
        if not is_installed():
            summary.set(f"Catálogo inicial • {len(rows)} domínios em {sum(g['total'] > 0 for g in categories)} categorias com sites. Instale para gerenciar.")
        elif enabled:
            summary.set(f"{active} ativos de {len(rows)} domínios. A TI pode editar um domínio ou pausar uma categoria inteira.")
        else:
            summary.set(f"{len(rows)} domínios cadastrados. O uso do banco está desativado na política da estação.")
        render()
    category.trace_add("write", lambda *_: render(True))
    search.trace_add("write", lambda *_: render(True))
    tree.bind("<<TreeviewSelect>>", lambda _: buttons())
    tree.bind("<Double-1>", lambda _: entry_dialog(True))
    return set_snapshot, buttons


# Administrative window. It is opened only by the interactive entry point.
def show_client_ui():
    import json
    import tkinter as tk
    from concurrent.futures import ThreadPoolExecutor
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("LabGuard Cliente | Administração da estação")
    root.geometry("800x650")
    root.minsize(700, 550)
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
    home, sites, games, bank = [ttk.Frame(tabs, style="Card.TFrame", padding=14) for _ in range(4)]
    for panel, name in ((home, "Estação"), (sites, "Sites"), (games, "Jogos"), (bank, "Banco de sites")):
        tabs.add(panel, text=name)
        panel.columnconfigure(0, weight=1)

    agent_state = tk.StringVar(value="Lendo a estação…")
    agent_time = tk.StringVar()
    feedback = tk.StringVar()
    label(home, "", heading=True, variable=agent_state).grid(row=0, column=0, sticky="w")
    label(home, "", variable=agent_time).grid(row=1, column=0, sticky="w", pady=(4, 10))
    label(home, "Ao instalar, a proteção inicia em segundo plano nesta estação. A tarefa LabGuardCliente volta a iniciar com o Windows. "
                "A TI pode consultá-la no Agendador de Tarefas ou nesta janela.").grid(
                    row=2, column=0, sticky="w", pady=(0, 10))
    label(home, "Em Banco de sites, pesquise domínios e gerencie categorias. Em Sites e Jogos, ajuste o modo de navegação e a remoção dos jogos.").grid(
                    row=3, column=0, sticky="w", pady=(0, 10))
    controls = ttk.Frame(home, style="Card.TFrame")
    controls.grid(row=4, column=0, sticky="w")
    refresh = ttk.Button(controls, text="Atualizar estado", style="LG.TButton")
    activate = ttk.Button(controls, text="Ativar agora", style="LG.TButton")
    details = ttk.Button(controls, text="Detalhes técnicos", style="LG.TButton")
    remove = ttk.Button(controls, text="Desinstalar cliente", style="LG.TButton")
    for button in (activate, refresh, details, remove):
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

    catalog_on = tk.BooleanVar(value=True)
    ttk.Checkbutton(sites, text="Usar os domínios ativos do Banco de sites", variable=catalog_on,
                    style="LG.TCheckbutton").grid(row=3, column=0, sticky="w", pady=2)
    deny = domain_box(4, "Bloqueios adicionais da política • um domínio por linha")
    allow = domain_box(6, "Domínios permitidos no modo restrito • um por linha")

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

    bank_controls = lambda: None

    def buttons():
        ready = initialized and job is None
        for button, active in ((refresh, job is None), (details, ready and bool(snapshot)),
                               (activate, ready and installed and editable and admin),
                               (remove, ready and installed and admin),
                               (apply_button, ready and editable and admin)):
            button.state(["!disabled" if active else "disabled"])
        apply_button.configure(text="Salvar política" if installed else "Instalar e proteger agora")
        bank_controls()

    def fill(data):
        nonlocal policy
        policy = dict(data)
        mode.set(data["mode"])
        catalog_on.set(data.get("catalog_enabled", True))
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
            return {"installed": True, "ok": False, "situacao": "falha na leitura do estado"}, True, None, str(error), ([], [])
        present = bool(value.get("installed"))
        data, issue = None, None
        try:
            data = (value.get("policy") or read_policy()) if present else default_policy()
        except Exception as error:
            issue = str(error)
        try:
            bank_data = _admin_bank_snapshot(present, admin)
        except Exception as error:
            bank_data = ([], [])
            issue = "Falha ao consultar o banco de sites. " + str(error)
        return value, present, data, issue, bank_data

    def display(result, replace_form, note=""):
        nonlocal initialized, snapshot, installed, editable
        value, present, data, issue, bank_data = result
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
            agent_time.set(f"Banco inicial com {len(CLIENT_CATALOG_ROWS)} domínios. Revise a política ou clique em Instalar e proteger agora.")
        else:
            summary = str(value.get("situacao") or "cliente instalado")
            agent_state.set(summary[:1].upper() + summary[1:])
            stamp = worker.get("checked_at")
            agent_time.set("Último registro (UTC)   " + str(stamp) if stamp else
                           "Abra Detalhes técnicos para consultar o estado da proteção.")
        bank_update(bank_data, bool((data or {}).get("catalog_enabled", True)))
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
            edited.update(mode=mode.get(), catalog_enabled=bool(catalog_on.get()), games=[k for k, v in game_flags.items() if v.get()],
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

    def activate_existing():
        def work():
            perform_install(read_policy())
            return load_state()
        submit("Ativando a tarefa do cliente…", work,
               lambda value: display(value, False, "Inicialização solicitada. Atualize o estado para conferir a verificação."))
    activate.configure(command=activate_existing)

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

    bank_update, bank_controls = _admin_bank_tab(bank, root, submit, load_state, display,
                       can_edit=lambda: initialized and installed and admin and job is None,
                       is_installed=lambda: installed)
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
                _json_read(journal)  # Preserve o registro de propriedade das regras anteriores.
            else:
                _atomic_json(config, accepted)
                _atomic_json(journal, {})
            db = ClientCatalog(directory / "banco.sqlite3")
            db.ensure(extra_domains=accepted["domains"] if accepted["catalog_enabled"] else ())
            _effective_domains(accepted, db)
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
        _effective_domains(accepted, ClientCatalog(directory / "banco.sqlite3"))
        _atomic_json(directory / "politica.json", accepted)


def get_site_bank():
    require_client_admin()
    directory = client_directory()
    _lc_load(directory)
    return ClientCatalog(directory / "banco.sqlite3")


def bank_change(operation, *args, **kwargs):
    catalog = get_site_bank()
    directory = client_directory()
    with _operation_lock(directory):
        if (directory / "parar.flag").exists():
            raise RuntimeError("A remoção está em andamento.")
        names = {"put":catalog.put, "delete":catalog.delete, "set_category":catalog.set_category,
                 "import_csv":catalog.import_csv}
        if operation not in names:
            raise ValueError("Operação de catálogo desconhecida.")
        kwargs["extra_domains"] = read_policy()["domains"]
        return names[operation](*args, **kwargs)


def bank_preview_import(csv_text):
    catalog = get_site_bank()
    return catalog.preview_import(csv_text, extra_domains=read_policy()["domains"])


def _effective_domains(policy, catalog):
    return catalog.effective(policy["domains"]) if policy["catalog_enabled"] else policy["domains"]


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
    catalog = ClientCatalog(directory / "banco.sqlite3")
    report["bank_revision"] = catalog.revision()
    report["catalog_enabled"] = report.get("policy", {}).get("catalog_enabled", True)
    same = (worker.get("policy_revision") == _policy_revision(report.get("policy", {}))
            and (not report["catalog_enabled"] or worker.get("bank_revision") == report["bank_revision"]))
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
    revision = bank_revision = None
    sites, system_sites, store_result = {}, {}, None
    catalog = ClientCatalog(directory / "banco.sqlite3")
    while not stop.exists():
        try:
            with _operation_lock(directory):
                if stop.exists():
                    break
                policy = read_policy()
                key = _policy_revision(policy)
                now = time.monotonic()
                latest = catalog.revision() if policy["catalog_enabled"] else None
                if revision != key or bank_revision != latest or now - last_sites >= 60:
                    useful = dict(policy, domains=_effective_domains(policy, catalog))
                    state = _json_read(directory / "estado.json")
                    persist = lambda: _atomic_json(directory / "estado.json", state)
                    sites = _layer("Navegadores", sync_sites, useful, state, checkpoint=persist)
                    system_sites = _layer("Nomes do Windows", sync_system_sites, useful, state, checkpoint=persist)
                    last_sites, bank_revision = now, latest
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
                report = {"version": CLIENT_VERSION, "policy_revision":key, "bank_revision":bank_revision, "active_domains":len(useful["domains"]), "checked_at":_utc_now(),
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
    for name in ("instalar", "politica", "remover", "status", "verificar", "worker", "usuario", "banco-listar"):
        p = ops.add_parser(name)
        if name in ("instalar", "remover", "politica"):
            p.add_argument("--sim", action="store_true", help="confirmar a operação administrativa")
        if name in ("instalar", "politica"):
            p.add_argument("--politica", type=Path, required=name=="politica", help="arquivo JSON da política")
        if name == "banco-listar":
            p.add_argument("--buscar",default="")
            p.add_argument("--categoria",default=None)
        if name in ("status", "verificar", "instalar", "politica", "remover", "usuario", "banco-listar"):
            p.add_argument("--json", action="store_true", help="exibir resultado em JSON")
            p.add_argument("--saida", help="registrar resultado em um arquivo novo")
    return parser.parse_args(argv)


def main_client(argv=None):
    args = _parse_cli(sys.argv[1:] if argv is None else argv)
    try:
        if os.name != "nt":
            raise RuntimeError("O LabGuard Cliente requer Windows 10/11 x64.")
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
        elif args.action == "banco-listar":
            catalog = get_site_bank()
            categories = catalog.categories()
            result = {"ok":True,"total":sum(row["total"] for row in categories),"revision":catalog.revision(),
                      "categories":categories,"rows":catalog.search(args.buscar, args.categoria, limit=100)}
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
