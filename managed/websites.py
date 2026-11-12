"""Small, explicit website catalog for games agents. Legacy protocols stay unchanged."""
from __future__ import annotations
import json
import re
from urllib.parse import urlsplit
import labguard_central as core
from alerts import ManagedStore, ManagedHandler

PRESETS = (
    ('termo', 'Termo', ['term.ooo'], ''),
    ('friv', 'Friv', ['friv.com', 'friv.com.br'], ''),
    ('poki', 'Poki (Poke)', ['poki.com'], 'Poke foi interpretado como Poki. O endereço pode ser corrigido.'),
    ('joguester', 'Joguester', [], 'Endereço não confirmado. Informe o domínio antes de bloquear.'),
    ('chess', 'Chess.com', ['chess.com'], ''),
)
MAX_DOMAINS = 30

def domains(values):
    if not isinstance(values, list) or len(values) > 6:
        raise core.CentralError('Informe de zero a seis domínios para cada site.')
    result = set()
    for raw in values:
        if not isinstance(raw, str) or len(raw) > 2048:
            raise core.CentralError('Endereço de site inválido.')
        value = raw.strip().lower()
        if '://' in value:
            try:
                u = urlsplit(value)
                port = u.port
            except ValueError:
                raise core.CentralError('Endereço inválido.') from None
            if u.scheme not in ('http', 'https') or u.username or u.password or port not in (None, 80, 443):
                raise core.CentralError('Informe um domínio ou um endereço HTTP/HTTPS sem credenciais.')
            value = u.hostname or ''
        try:
            value = value.removesuffix('.').encode('idna').decode('ascii')
        except UnicodeError:
            raise core.CentralError('Domínio inválido.') from None
        if value.startswith('www.'):
            value = value[4:]
        parts = value.split('.')
        if (len(value) > 253 or len(parts) < 2 or parts[-1].isdigit()
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in parts)
            or value in {'com.br', 'net.br', 'org.br', 'edu.br', 'gov.br', 'co.uk'}
            or value.endswith(('.local', '.localhost', '.arpa', '.internal'))):
            raise core.CentralError('Use o domínio específico do jogo, sem *, IP ou endereço local.')
        result.add(value)
    return sorted(result)

class WebsiteStore(ManagedStore):
    def ensure(self, **kwargs):
        answer = super().ensure(**kwargs)
        with self._open(write=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS web_catalog(id TEXT PRIMARY KEY,label TEXT NOT NULL,domains TEXT NOT NULL,blocked INTEGER NOT NULL,note TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS web_meta(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO web_meta VALUES(1,1)')
            db.execute('CREATE TABLE IF NOT EXISTS web_devices(device_id TEXT PRIMARY KEY REFERENCES devices(device_id),revision INTEGER NOT NULL,status TEXT NOT NULL)')
            for key, label, names, note in PRESETS:
                db.execute('INSERT OR IGNORE INTO web_catalog VALUES(?,?,?,?,?)', (key,label,json.dumps(names),int(bool(names)),note))
        return answer

    @staticmethod
    def catalog(db):
        records = {r['id']: dict(r, domains=json.loads(r['domains']), blocked=bool(r['blocked'])) for r in db.execute('SELECT * FROM web_catalog')}
        return [records[key] for key, *_ in PRESETS]

    @staticmethod
    def web_policy(db):
        rows = WebsiteStore.catalog(db)
        names = sorted({d for row in rows if row['blocked'] for d in row['domains']})
        if len(names) > MAX_DOMAINS:
            raise core.CentralError('O catálogo ultrapassou o limite de domínios.')
        return {'revision': db.execute('SELECT revision FROM web_meta WHERE id=1').fetchone()[0], 'blocked_domains': names}

    def change_web(self, body, *, bulk=False):
        core._fields(body, ('expected_revision',) if bulk else ('expected_revision','id','domains','blocked'))
        revision = body['expected_revision']
        if type(revision) is not int or revision < 1:
            raise core.CentralError('Revisão de sites inválida.')
        if not bulk:
            if not isinstance(body['id'],str) or body['id'] not in {p[0] for p in PRESETS}:
                raise core.CentralError('Site não cadastrado.')
            core._boolean(body['blocked'],'Bloqueio')
            names = domains(body['domains'])
            if body['blocked'] and not names:
                raise core.CentralError('Confirme o endereço deste site antes de bloquear.')
        with self._open(write=True) as db:
            if revision != self.web_policy(db)['revision']:
                raise core.ConflictError('A lista mudou em outra janela. Atualize e tente novamente.')
            changed = False
            if bulk:
                changed = bool(db.execute("SELECT count(*) FROM web_catalog WHERE domains!='[]' AND blocked=0").fetchone()[0])
                db.execute("UPDATE web_catalog SET blocked=1 WHERE domains!='[]'")
                # Never enable game removal or alter unrelated categories in this action.
                db.execute('UPDATE managed_policy SET block_youtube=1,revision=revision+1 WHERE id=1 AND block_youtube=0')
            else:
                old = db.execute('SELECT * FROM web_catalog WHERE id=?',(body['id'],)).fetchone()
                changed = json.loads(old['domains']) != names or bool(old['blocked']) != body['blocked']
                note = ('' if names else 'Endereço não confirmado. Informe o domínio antes de bloquear.') if body['id']=='joguester' else old['note']
                db.execute('UPDATE web_catalog SET domains=?,blocked=?,note=? WHERE id=?', (json.dumps(names),int(body['blocked']),note,body['id']))
            if changed:
                db.execute('UPDATE web_meta SET revision=revision+1 WHERE id=1')
            self._audit(db,'web_block_all' if bulk else 'web_site_changed','Lista de jogos + YouTube' if bulk else body['id'])
            policy = self.web_policy(db)
            return {'ok':True,'policy':policy,'pending_names':[r['label'] for r in self.catalog(db) if not r['domains']]}

    def web_telemetry(self, token, report):
        core._fields(report,('device_id','name','client_version','guard','cleanup','youtube','applied_revision','events','web_revision','web_status'))
        revision = report['web_revision']
        if type(revision) is not int or revision < 0 or report['web_status'] not in ('applied','pending','failed','unknown'):
            raise core.CentralError('Confirmação de sites inválida.')
        base = {k:v for k,v in report.items() if k not in ('web_revision','web_status')}
        result = super().telemetry(token,base)
        with self._open(write=True) as db:
            policy = self.web_policy(db)
            if revision > policy['revision']:
                raise core.CentralError('Revisão de sites inexistente.')
            db.execute('INSERT INTO web_devices VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET revision=excluded.revision,status=excluded.status', (report['device_id'],revision,report['web_status']))
            result['web_policy'] = policy
            result['web_protocol'] = 1
        return result

    def state(self):
        result = super().state()
        with self._open() as db:
            result['web_catalog'] = self.catalog(db)
            result['web_policy'] = self.web_policy(db)
            states = {r['device_id']:dict(r) for r in db.execute('SELECT * FROM web_devices')}
        for device in result['devices']:
            s = states.get(device['device_id'])
            device['web'] = s
            device['web_confirmed'] = bool(s and not device['revoked'] and device['status'] == 'online' and s['revision']==result['web_policy']['revision'] and s['status']=='applied')
            if s and not device['revoked'] and device['status'] not in ('offline','error') and not device['web_confirmed']:
                device['status'] = 'error' if s['status']=='failed' else 'pending'
        result['version']='1.2.0'
        result['web_protocol']=1
        result['counts']['online']=sum(d['status']=='online' for d in result['devices'])
        return result

class WebsiteHandler(ManagedHandler):
    def _agent(self, path):
        if path=='/api/agent/managed-info' and self.command=='POST':
            core._fields(self._body(),())
            self._send(200,{'ok':True,'managed_protocol':1,'web_protocol':1});return
        if path!='/api/agent/telemetry-web' or self.command!='POST':
            return super()._agent(path)
        auth=self.headers.get_all('Authorization',[])
        if len(auth)!=1 or not auth[0].startswith('Bearer '):
            raise core.AuthenticationError('Credencial da estação ausente.')
        token=core._secret(auth[0][7:]);app=self.server.application
        if not app.check_rate(('web-telemetry',self.client_address[0],core._digest(token)),15,60):
            self._send(429,{'ok':False,'error':'Aguarde o intervalo de comunicação.'});return
        self._send(200,app.store.web_telemetry(token,self._body()))

    def _panel(self,path):
        if path in ('/api/web-sites/change','/api/web-sites/block-all') and self.command=='POST':
            self._origin();self._session(mutate=True)
            self._send(200,self.server.application.store.change_web(self._body(),bulk=path.endswith('block-all')));return
        return super()._panel(path)

def install():
    core.CentralStore=WebsiteStore
    core._Handler=WebsiteHandler
    core.CENTRAL_VERSION='1.2.0'
