"""Authenticated event channel for the managed LabGuard games client.
No screenshots, URLs visited, command lines, file uploads or remote shell.
"""
from __future__ import annotations
import hmac
import re
import secrets
from datetime import datetime
import labguard_central as core

KINDS = {
    'game_closed': ('Jogo encerrado automaticamente', 'warning'),
    'client_started': ('Cliente iniciado', 'info'),
    'protection_error': ('Falha no monitor de proteção', 'error'),
    'cleanup_error': ('Limpeza requer atenção', 'error'),
    'protection_paused': ('Proteção pausada', 'warning'),
    'offline': ('Computador sem contato há mais de 90 segundos', 'warning'),
    'online': ('Comunicação estabelecida', 'info'),
}
CLIENT_KINDS = set(KINDS) - {'online', 'offline'}
FLAGS = ('cleanup_enabled', 'close_games', 'block_youtube')
_BASE_STORE = core.CentralStore
_BASE_HANDLER = core._Handler

class ManagedStore(_BASE_STORE):
    def ensure(self, **kwargs):
        version = super().ensure(**kwargs)
        with self._open(write=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS managed_policy(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, cleanup_enabled INTEGER NOT NULL, close_games INTEGER NOT NULL, block_youtube INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO managed_policy VALUES (1,1,1,1,1)')
            db.execute("CREATE TABLE IF NOT EXISTS managed_devices(device_id TEXT PRIMARY KEY REFERENCES devices(device_id), guard TEXT NOT NULL, cleanup TEXT NOT NULL, youtube TEXT NOT NULL, applied_revision INTEGER NOT NULL, online INTEGER NOT NULL)")
            db.execute('CREATE TABLE IF NOT EXISTS managed_alerts(id INTEGER PRIMARY KEY,device_id TEXT NOT NULL REFERENCES devices(device_id),event_id TEXT NOT NULL,time REAL NOT NULL,event_time TEXT NOT NULL,kind TEXT NOT NULL,process TEXT NOT NULL,seen INTEGER NOT NULL DEFAULT 0,UNIQUE(device_id,event_id))')
            db.execute('CREATE INDEX IF NOT EXISTS managed_alerts_unread ON managed_alerts(seen,id)')
        return version

    @staticmethod
    def _managed_policy(db):
        r = dict(db.execute('SELECT * FROM managed_policy WHERE id=1').fetchone())
        return dict(revision=r['revision'], **{f:bool(r[f]) for f in FLAGS})

    def enroll(self, *args, **kwargs):
        result = super().enroll(*args, **kwargs)
        result['managed_protocol'] = 1
        return result

    def set_managed_policy(self, body):
        core._fields(body, ('expected_revision', *FLAGS))
        if type(body['expected_revision']) is not int or body['expected_revision'] < 1:
            raise core.CentralError('Revisão de proteção inválida.')
        for f in FLAGS:
            core._boolean(body[f], f)
        with self._open(write=True) as db:
            current = self._managed_policy(db)
            if body['expected_revision'] != current['revision']:
                raise core.ConflictError('A proteção mudou em outra janela. Atualize antes de salvar.')
            if any(current[f] != body[f] for f in FLAGS):
                db.execute('UPDATE managed_policy SET revision=revision+1,cleanup_enabled=?,close_games=?,block_youtube=? WHERE id=1', tuple(int(body[f]) for f in FLAGS))
                self._audit(db,'managed_policy_changed','Proteção dos clientes: '+', '.join(f+'='+str(body[f]) for f in FLAGS))
            return self._managed_policy(db)

    def telemetry(self, token, report):
        core._fields(report, ('device_id','name','client_version','guard','cleanup','youtube','applied_revision','events'))
        token_hash = core._digest(core._secret(token))
        device_id = report['device_id']
        if not isinstance(device_id,str) or not re.fullmatch('[a-f0-9]{32}', device_id):
            raise core.CentralError('Identificação inválida.')
        name = core._text(report['name'],'Computador',64)
        version = core._text(report['client_version'],'Versão',64)
        if report['guard'] not in ('active','paused','failed','unknown') or report['cleanup'] not in ('ok','pending','failed','unknown') or report['youtube'] not in ('blocked','allowed','pending','failed','unknown'):
            raise core.CentralError('Estado inválido.')
        applied = report['applied_revision']
        if type(applied) is not int or applied < 0:
            raise core.CentralError('Revisão de proteção inválida.')
        events = report['events']
        if not isinstance(events,list) or len(events)>25:
            raise core.CentralError('Lote de avisos inválido.')
        cleaned = []
        for event in events:
            core._fields(event, ('id','kind','time','process'))
            if not isinstance(event['id'],str) or not re.fullmatch('[a-f0-9]{32}',event['id']) or event['kind'] not in CLIENT_KINDS:
                raise core.CentralError('Tipo ou identificação de aviso inválido.')
            process = event['process']
            if not isinstance(process,str) or not re.fullmatch(r'[A-Za-z0-9 ._()\-]{0,96}',process):
                raise core.CentralError('O aviso aceita somente o nome do processo, sem caminhos.')
            stamp=core._text(event['time'],'Horário do evento',64)
            try:
                if datetime.fromisoformat(stamp.replace('Z','+00:00')).tzinfo is None: raise ValueError()
            except ValueError:
                raise core.CentralError('Horário do evento inválido.') from None
            cleaned.append((event['id'],stamp,event['kind'],process))
        now=self.clock()
        with self._open(write=True) as db:
            device=db.execute('SELECT * FROM devices WHERE device_id=?',(device_id,)).fetchone()
            if not device or device['revoked'] or not hmac.compare_digest(device['token_hash'],token_hash):
                raise core.AuthenticationError('Vínculo inválido ou revogado.')
            policy=self._managed_policy(db)
            if applied>policy['revision']: raise core.CentralError('Revisão de proteção inexistente.')
            old=db.execute('SELECT online FROM managed_devices WHERE device_id=?',(device_id,)).fetchone()
            if old is None or old['online']==0:
                db.execute('INSERT INTO managed_alerts(device_id,event_id,time,event_time,kind,process) VALUES(?,?,?,?,?,?)',(device_id,secrets.token_hex(16),now,core._stamp(now),'online',''))
            db.execute('UPDATE devices SET name=?,client_version=?,last_seen=? WHERE device_id=?',(name,version,now,device_id))
            db.execute('INSERT INTO managed_devices VALUES(?,?,?,?,?,1) ON CONFLICT(device_id) DO UPDATE SET guard=excluded.guard,cleanup=excluded.cleanup,youtube=excluded.youtube,applied_revision=excluded.applied_revision,online=1', (device_id,report['guard'],report['cleanup'],report['youtube'],applied))
            for event_id,stamp,kind,process in cleaned:
                db.execute('INSERT OR IGNORE INTO managed_alerts(device_id,event_id,time,event_time,kind,process) VALUES(?,?,?,?,?,?)',(device_id,event_id,now,stamp,kind,process))
            db.execute('DELETE FROM managed_alerts WHERE time<?',(now-7*86400,))
            db.execute('DELETE FROM managed_alerts WHERE id IN (SELECT id FROM managed_alerts ORDER BY id DESC LIMIT -1 OFFSET 10000)')
            return {'ok':True,'managed_protocol':1,'ack':[e[0] for e in cleaned],'poll_seconds':15,'policy':policy}

    def acknowledge(self, through):
        if type(through) is not int or through<1:
            raise core.CentralError('Identificação do aviso inválida.')
        with self._open(write=True) as db:
            if not db.execute('SELECT id FROM managed_alerts WHERE id=?',(through,)).fetchone():
                raise core.ConflictError('Aviso ausente. Atualize a lista.')
            db.execute('UPDATE managed_alerts SET seen=1 WHERE id<=?',(through,))
            self._audit(db,'alerts_acknowledged','Avisos conferidos até #'+str(through))

    def state(self):
        now=self.clock()
        with self._open(write=True) as db:
            for r in db.execute('SELECT m.device_id FROM managed_devices m JOIN devices d USING(device_id) WHERE m.online=1 AND d.revoked=0 AND d.last_seen<?',(now-90,)).fetchall():
                db.execute('UPDATE managed_devices SET online=0 WHERE device_id=?',(r['device_id'],))
                db.execute('INSERT INTO managed_alerts(device_id,event_id,time,event_time,kind,process) VALUES(?,?,?,?,?,?)',(r['device_id'],secrets.token_hex(16),now,core._stamp(now),'offline',''))
            db.execute('DELETE FROM managed_alerts WHERE time<?',(now-7*86400,))
            policy=self._managed_policy(db)
            alerts=[]
            for r in db.execute('SELECT a.*,d.name FROM managed_alerts a JOIN devices d USING(device_id) ORDER BY a.id DESC LIMIT 200'):
                alerts.append(dict(r,time=core._stamp(r['time']),seen=bool(r['seen']),title=KINDS[r['kind']][0],severity=KINDS[r['kind']][1]))
            unread=db.execute('SELECT count(*) FROM managed_alerts WHERE seen=0').fetchone()[0]
            managed={r['device_id']:dict(r) for r in db.execute('SELECT * FROM managed_devices')}
        result=super().state()
        for device in result['devices']:
            m=managed.get(device['device_id'])
            if m:
                device['managed']=m
                if not device['revoked']:
                    device['status']='offline' if not m['online'] else 'error' if m['guard']=='failed' or m['cleanup']=='failed' or m['youtube']=='failed' else 'pending' if m['applied_revision']!=policy['revision'] else 'online'
        result.update(version='1.1.0',managed_protocol=1,managed_policy=policy,alerts=alerts,unread_alerts=unread)
        result['counts']['online']=sum(d['status']=='online' for d in result['devices'])
        return result

class ManagedHandler(_BASE_HANDLER):
    def _agent(self,path):
        if path=='/api/agent/managed-info' and self.command=='POST':
            core._fields(self._body(),())
            self._send(200,{'ok':True,'managed_protocol':1});return
        if path!='/api/agent/telemetry' or self.command!='POST':
            return super()._agent(path)
        app=self.server.application
        auth=self.headers.get_all('Authorization',[])
        if len(auth)!=1 or not auth[0].startswith('Bearer '):
            raise core.AuthenticationError('Credencial da estação ausente.')
        token=core._secret(auth[0][7:])
        if not app.check_rate(('telemetry',self.client_address[0],core._digest(token)),15,60):
            self._send(429,{'ok':False,'error':'Aguarde o intervalo de comunicação.'});return
        self._send(200,app.store.telemetry(token,self._body()))

    def _panel(self,path):
        if path in ('/api/alerts/ack','/api/managed-policy') and self.command=='POST':
            self._origin();self._session(mutate=True)
            body=self._body();store=self.server.application.store
            if path.endswith('/ack'):
                core._fields(body,('through',));store.acknowledge(body['through'])
                self._send(200,{'ok':True})
            else:
                self._send(200,{'ok':True,'policy':store.set_managed_policy(body)})
            return
        return super()._panel(path)

def install():
    """Activate only in the managed Central entrypoint; legacy protocol stays compatible."""
    core.CentralStore=ManagedStore
    core._Handler=ManagedHandler
    core.CENTRAL_VERSION='1.1.0'
