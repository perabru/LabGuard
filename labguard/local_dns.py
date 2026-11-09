"""Opt-in DNS filter for clients explicitly configured to use this computer.

No DHCP, router changes, interception, firewall edits or internet-cut claims.
Only a chosen private IPv4 segment is accepted. Query history stays bounded
in memory; only explicitly applied domain rules persist in the private bank.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
from pathlib import Path
import secrets
import selectors
import socket
import struct
import threading
import time

from .demo import normalize_domain

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
CHECK_DOMAIN = 'labguard-check.invalid'
MAX_RULES, MAX_EVENTS, MAX_CLIENTS = 5000, 1000, 512


class DNSError(RuntimeError):
    pass


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def validate_config(listen, network, upstream='1.1.1.1', port=53, upstream_port=53):
    try:
        address = ipaddress.IPv4Address(listen)
        net = ipaddress.IPv4Network(network, strict=True)
        resolver = ipaddress.IPv4Address(upstream)
        private = any(net.subnet_of(p) for p in PRIVATE)
        loopback = net.subnet_of(ipaddress.ip_network('127.0.0.0/8'))
        if not (private and 16 <= net.prefixlen <= 30 or loopback and 8 <= net.prefixlen <= 32):raise ValueError()
        if address not in net or not loopback and address in (net.network_address, net.broadcast_address):raise ValueError()
        if any(type(p) is not int or not 1 <= p <= 65535 for p in (port, upstream_port)):raise ValueError()
        if resolver.is_unspecified or resolver.is_multicast or resolver.is_reserved or str(resolver) == '255.255.255.255':raise ValueError()
        if resolver == address and port == upstream_port:raise ValueError()
    except (ValueError, TypeError, ipaddress.AddressValueError):
        raise DNSError('DNS_LOCAL_CONFIG: informe IP local, rede privada e DNS de saída válidos.') from None
    return str(address), net, str(resolver), port, upstream_port


def read_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        block = stream.recv(count-len(data))
        if not block:raise OSError('Connection closed')
        data.extend(block)
    return bytes(data)


class DNSFilter:
    """Bounded UDP+TCP resolver; opening the listeners is always explicit."""
    def __init__(self, listen, network, *, upstream='1.1.1.1', port=53, upstream_port=53, rules=None):
        self.listen, self.network, self.upstream, self.port, self.upstream_port = validate_config(listen, network, upstream, port, upstream_port)
        self._rules = {}; self._lock = threading.RLock(); self._stop = threading.Event()
        self._events, self._clients, self._rates = deque(maxlen=MAX_EVENTS), OrderedDict(), OrderedDict()
        self._slots = threading.BoundedSemaphore(32)
        self._sockets = []; self._selector = None; self._thread = None; self._pool = None
        self._queries = self._blocked = 0
        self.check_token = 'LabGuard-'+secrets.token_hex(8)
        self.replace_rules(rules or {})

    def replace_rules(self, rules):
        if not isinstance(rules, dict) or len(rules) > MAX_RULES:raise DNSError('DNS_LOCAL_STATE: limite de regras excedido.')
        clean = {normalize_domain(k): str(v)[:80] for k,v in rules.items()}
        with self._lock:self._rules = clean

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(self):
        if self.running:return
        if self._stop.is_set():raise DNSError('DNS_LOCAL_PORT: instância encerrada; configure novamente.')
        try:
            import dnslib  # noqa: F401
        except ImportError:raise DNSError('DNS_LOCAL_DEPENDENCY: instale a edição atual com filtro DNS.') from None
        try:
            self._selector = selectors.DefaultSelector()
            for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                stream = socket.socket(socket.AF_INET, kind)
                self._sockets.append(stream)
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):stream.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                elif kind == socket.SOCK_STREAM:stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                stream.bind((self.listen, self.port))
                if kind == socket.SOCK_STREAM:stream.listen(16)
                stream.setblocking(False)
                self._selector.register(stream, selectors.EVENT_READ, kind)
            self._pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix='labguard-dns')
            self._thread = threading.Thread(target=self._serve, name='labguard-dns-listeners', daemon=True)
            self._thread.start()
        except OSError:
            self.close()
            raise DNSError('DNS_LOCAL_PORT: IP não disponível, porta ocupada ou permissão insuficiente para UDP/TCP 53.') from None

    def _allowed(self, client):
        try:return ipaddress.IPv4Address(client) in self.network
        except (ValueError, TypeError):return False

    def _rate(self, client):
        now = time.monotonic()
        with self._lock:
            key = int(now)
            bucket = self._rates.pop(client, (key, 0))
            count = bucket[1] + 1 if bucket[0] == key else 1
            self._rates[client] = (key, count)
            while len(self._rates) > MAX_CLIENTS:self._rates.popitem(last=False)
            global_bucket = getattr(self, '_global_rate', (key, 0))
            total = global_bucket[1] + 1 if global_bucket[0] == key else 1
            self._global_rate = (key, total)
            return count <= 120 and total <= 600

    def _submit(self, fn, *args):
        if not self._slots.acquire(blocking=False):return False
        def work():
            try:fn(*args)
            finally:self._slots.release()
        try:self._pool.submit(work); return True
        except RuntimeError:self._slots.release(); return False

    def _serve(self):
        while not self._stop.is_set():
            try:
                for key, _ in self._selector.select(.15):
                    if key.data == socket.SOCK_DGRAM:
                        data, peer = key.fileobj.recvfrom(4097)
                        if len(data) <= 4096 and self._allowed(peer[0]) and self._rate(peer[0]):
                            self._submit(self._udp, key.fileobj, data, peer)
                    else:
                        conn, peer = key.fileobj.accept()
                        if not self._allowed(peer[0]) or not self._submit(self._tcp, conn, peer[0]):conn.close()
            except (OSError, ValueError):
                if not self._stop.is_set():time.sleep(.05)

    def _udp(self, listener, data, peer):
        try:
            answer = self.resolve(data, peer[0], tcp=False)
            if answer and not self._stop.is_set():listener.sendto(answer, peer)
        except OSError:pass

    def _tcp(self, conn, client):
        with conn:
            conn.settimeout(2)
            deadline = time.monotonic()+8
            try:
                for _ in range(8):
                    if self._stop.is_set() or time.monotonic() >= deadline:return
                    size = struct.unpack('!H', read_exact(conn, 2))[0]
                    if not 12 <= size <= 4096 or not self._rate(client):return
                    answer = self.resolve(read_exact(conn, size), client, tcp=True)
                    if answer:conn.sendall(struct.pack('!H', len(answer))+answer)
            except (OSError, ValueError, struct.error):pass

    def _matches(self, name):
        name = name.lower().rstrip('.')
        with self._lock:
            return name == 'blocked.'+CHECK_DOMAIN or any('.'.join(name.split('.')[i:]) in self._rules for i in range(len(name.split('.'))))

    def _forward(self, question, tcp):
        from dnslib import DNSRecord
        query = DNSRecord.parse(question.pack())
        query.header.id = secrets.randbits(16)
        wire = query.pack()
        def send(streaming):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if streaming else socket.SOCK_DGRAM) as stream:
                stream.settimeout(2)
                stream.connect((self.upstream, self.upstream_port))
                if streaming:
                    stream.sendall(struct.pack('!H', len(wire))+wire)
                    size = struct.unpack('!H', read_exact(stream, 2))[0]
                    if not 12 <= size <= 65535:raise ValueError()
                    data = read_exact(stream, size)
                else:stream.send(wire); data = stream.recv(65535)
            answer = DNSRecord.parse(data)
            if (answer.header.id != query.header.id or answer.header.qr != 1 or answer.header.opcode != 0
                    or len(answer.questions) != 1 or answer.q.qname != query.q.qname
                    or answer.q.qtype != query.q.qtype or answer.q.qclass != query.q.qclass):raise ValueError()
            return answer
        answer = send(tcp)
        if answer.header.tc and not tcp:answer = send(True)
        if answer.header.tc:raise ValueError()
        answer.header.id = question.header.id
        return answer

    def resolve(self, data, client, *, tcp=False):
        from dnslib import DNSRecord, RCODE, QTYPE, RR, TXT
        if not self._allowed(client) or len(data) > 4096 or self._stop.is_set():return None
        try:
            query = DNSRecord.parse(data)
            if query.header.qr or query.header.opcode or len(query.questions) != 1 or query.rr or query.auth:return None
            reply = query.reply(); reply.header.aa = 0; reply.header.ad = 0
            if query.q.qclass != 1 or query.q.qtype in (QTYPE.ANY, QTYPE.AXFR, QTYPE.IXFR):
                reply.header.rcode = RCODE.REFUSED; return reply.pack()
            labels = query.q.qname.label
            if any(not label or len(label)>63 or any(c<33 or c>126 for c in label) for label in labels):return None
            name = str(query.q.qname).lower().rstrip('.')
            blocked = self._matches(name)
            if name == CHECK_DOMAIN and query.q.qtype == QTYPE.TXT:
                reply.add_answer(RR(CHECK_DOMAIN, QTYPE.TXT, ttl=0, rdata=TXT(self.check_token)))
            elif blocked:reply.header.rcode = RCODE.NXDOMAIN
            else:
                try:
                    reply = self._forward(query, tcp)
                    if any(row.rtype in (QTYPE.CNAME, QTYPE.DNAME) and self._matches(str(row.rdata.label)) for row in reply.rr):
                        blocked = True; reply = query.reply(); reply.header.aa = 0; reply.header.ad = 0; reply.header.rcode = RCODE.NXDOMAIN
                except Exception:
                    reply = query.reply(); reply.header.aa = 0; reply.header.ad = 0; reply.header.rcode = RCODE.SERVFAIL
            status = 'Bloqueio DNS confirmado' if blocked else 'Resposta DNS' if reply.header.rcode == 0 else 'Falha DNS' if reply.header.rcode == RCODE.SERVFAIL else 'Resposta DNS negativa'
            with self._lock:
                self._queries += 1; self._blocked += int(blocked)
                self._clients.pop(client, None); self._clients[client] = stamp()
                while len(self._clients) > MAX_CLIENTS:self._clients.popitem(last=False)
                self._events.appendleft({'time':stamp(), 'client_ip':client, 'domain':name,
                    'query_type':QTYPE.get(query.q.qtype), 'status':status})
            if not tcp:
                maximum = 1232 if any(row.rtype == QTYPE.OPT for row in query.ar) else 512
                if len(reply.pack()) > maximum:
                    reply = query.reply(); reply.header.tc = 1; reply.header.ad = 0; reply.header.aa = 0
            return reply.pack()
        except Exception:return None

    def activity(self):
        with self._lock:
            return {'events':list(self._events), 'clients':dict(self._clients), 'queries':self._queries, 'blocked':self._blocked}

    def close(self):
        self._stop.set()
        for stream in self._sockets:
            try:stream.close()
            except OSError:pass
        if self._thread and self._thread is not threading.current_thread():self._thread.join(1)
        if self._selector:self._selector.close()
        if self._pool:self._pool.shutdown(wait=False, cancel_futures=True)


class LocalDNSTransport:
    def __init__(self, *, host, lab_cidr, upstream='1.1.1.1', port=53, upstream_port=53, manage_rules=False, data_dir=None):
        if manage_rules is not True:raise DNSError('DNS_LOCAL_CONFIG: autorize iniciar o filtro local antes de abrir a porta DNS.')
        from .banlist import BanlistDatabase
        from .discovery import LocalObservationTransport
        self._lock = threading.RLock(); self._closed = False
        config = validate_config(host, lab_cidr, upstream, port, upstream_port)
        self.host = 'local-dns:'+config[0]+'/'+str(config[1]); self.port = port
        identity = hashlib.sha256(self.host.encode()).hexdigest()[:24]
        directory = Path(data_dir) if data_dir is not None else Path.home()/'.labguard'/'local-dns'
        from .preferences import PreferenceStore, _windows_private
        import os
        PreferenceStore(directory)._directory(create=True)
        self.database = BanlistDatabase(directory/(identity+'.sqlite3'))
        if os.name == 'nt':_windows_private(self.database.path, directory=False)
        self._observation = LocalObservationTransport()
        self._audit = deque(maxlen=100)
        rows = []
        for offset in range(0, MAX_RULES, 1000):
            page = self.database.list_sites(enabled=True, limit=1000, offset=offset); rows.extend(page)
            if len(page)<1000:break
        self._rules = {row['domain']:row['category'] for row in rows}
        self.filter = DNSFilter(host, lab_cidr, upstream=upstream, port=port, upstream_port=upstream_port, rules=self._rules)
        try:self.filter.start()
        except Exception:self.database.close(); self._observation.close(); raise

    def verify_dns(self):
        """Verify UDP/TCP on our bound endpoint without testing network coverage."""
        from dnslib import DNSRecord, QTYPE
        with self._lock:
            if self._closed or not self.filter.running:
                raise DNSError('DNS_LOCAL_STATE: filtro não está ativo.')
            results = {}
            for name, tcp in (('udp', False), ('tcp', True)):
                query = DNSRecord.question(CHECK_DOMAIN, 'TXT')
                try:
                    answer = DNSRecord.parse(query.send(self.filter.listen, self.port, tcp=tcp, timeout=2))
                    results[name] = bool(answer.header.id == query.header.id and answer.header.qr
                        and answer.header.rcode == 0 and len(answer.questions) == 1
                        and answer.q == query.q and len(answer.rr) == 1
                        and answer.rr[0].rtype == QTYPE.TXT
                        and str(answer.rr[0].rdata).strip('"') == self.filter.check_token)
                except Exception:
                    # Parser errors are a failed diagnostic, never a verified listener.
                    results[name] = False
            return {**results, 'ok': all(results.values()), 'scope': 'this_computer',
                    'network_scope_verified': False}

    def request(self, action, **params):
        with self._lock:
            if self._closed:raise DNSError('DNS_LOCAL_PORT: filtro encerrado; configure novamente.')
            if action == 'add_domain':
                domain = normalize_domain(params.get('domain', ''))
                if len(self._rules)>=MAX_RULES and domain not in self._rules:raise DNSError('DNS_LOCAL_STATE: limite de regras excedido.')
                category = params.get('category', 'Outros')
                self.database.upsert(domain, category); self._rules[domain] = category
                self.filter.replace_rules(self._rules)
            elif action == 'remove_domain':
                domain = normalize_domain(params.get('domain', ''))
                self.database.delete(domain); self._rules.pop(domain, None); self.filter.replace_rules(self._rules)
            elif action != 'snapshot':raise DNSError('Este filtro controla somente domínios DNS; não corta internet nem controla MAC ou portas.')
            if action != 'snapshot':self._audit.appendleft({'time':stamp(), 'action':action, 'target':domain, 'outcome':'Regra local aplicada'})
            return self._snapshot()

    def _snapshot(self):
        activity = self.filter.activity()
        try:local = self._observation.request('snapshot')
        except Exception:local = {'devices':[], 'interfaces':[]}
        devices = []
        for row in local.get('devices', []):
            try:inside = ipaddress.IPv4Address(row.get('ip','')) in self.filter.network
            except (ValueError, TypeError):inside=False
            if inside:devices.append(dict(row))
        known = {row['ip'] for row in devices}
        for client, last in activity['clients'].items():
            if client not in known:
                devices.append({'ip':client, 'mac':'', 'name':'Cliente DNS', 'protected':client==self.filter.listen,
                    'last_seen':last, 'state':'Consulta DNS recebida · presença atual não confirmada'})
        running = self.filter.running
        return {'mode':'equipment', 'source_type':'local_dns', 'timestamp':stamp(), 'interfaces':[row for row in local.get('interfaces', []) if self._interface_in_scope(row)],
            'local':{}, 'gateway':{'hostname':'LabGuard DNS', 'vendor':'LabGuard', 'model':'Filtro DNS local',
                'lab_cidr':str(self.filter.network), 'management_host':self.filter.listen},
            'capabilities':{'inventory':True, 'domain_filtering':running, 'dns_history':True, 'device_internet_cut':False,
                'address_blocking':False, 'ai_block':False, 'port_control':False},
            'health':{'dns':running, 'firewall':False, 'forwarding':False},
            'devices':devices, 'domains':[{'domain':name, 'category':category, 'source':'manual'} for name,category in sorted(self._rules.items())],
            'events':activity['events'], 'audit':list(self._audit), 'connections':[],
            'metrics':{'queries_window':len(activity['events']), 'blocked_events_window':sum(e['status']=='Bloqueio DNS confirmado' for e in activity['events']),
                'observed_devices':len(devices), 'blocked_devices':0},
            'dns_service':{'listen':self.filter.listen, 'port':self.port, 'network':str(self.filter.network),
                'upstream':self.filter.upstream, 'service_running':running, 'received_clients':len(activity['clients']),
                'network_scope_verified':False, 'queries_received':activity['queries'], 'check_domain':CHECK_DOMAIN, 'check_token':self.filter.check_token},
            'warnings':['Somente clientes configurados para usar este DNS são filtrados. Não há confirmação de cobertura de toda a rede.',
                'Consultas DNS não comprovam visitas. HTTPS, VPN, DoH, DNS alternativo e cache podem contornar o filtro.',
                'O computador e este filtro precisam permanecer ligados. Ao encerrar, restaure o DNS nos clientes para preservar a navegação.',
                'Este modo não altera o roteador Vivo nem o switch e não oferece corte de internet por IP/MAC.']}

    def _interface_in_scope(self,row):
        try:return ipaddress.IPv4Interface(row.get('ipv4','')).ip in self.filter.network
        except (ValueError,TypeError):return False

    def close(self):
        with self._lock:
            if self._closed:return
            self._closed = True
            self.filter.close(); self.database.close(); self._observation.close()


def smoke_test():
    """Exercise real UDP/TCP on loopback only, without router or OS changes."""
    from dnslib import DNSRecord, RCODE
    service = None
    for _ in range(5):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port = probe.getsockname()[1]
        candidate = DNSFilter('127.0.0.1','127.0.0.0/8',port=port,rules={'blocked.example':'Jogos'})
        try:candidate.start();service=candidate;break
        except DNSError:continue
    if service is None:raise DNSError('DNS_LOCAL_PORT: teste local não abriu sockets privados.')
    result = {'loopback_only':True}
    try:
        for tcp in (False, True):
            answer = DNSRecord.parse(DNSRecord.question('blocked.example').send('127.0.0.1',service.port,tcp=tcp,timeout=2))
            if answer.header.rcode != RCODE.NXDOMAIN:raise DNSError('DNS_LOCAL_STATE: resposta de teste incorreta.')
            result['tcp_blocked' if tcp else 'udp_blocked'] = True
        answer = DNSRecord.parse(DNSRecord.question(CHECK_DOMAIN,'TXT').send('127.0.0.1',service.port,timeout=2))
        if not answer.rr or str(answer.rr[0].rdata).strip('"') != service.check_token:raise DNSError('DNS_LOCAL_STATE: diagnóstico de teste incorreto.')
        result['diagnostic_token_verified'] = True
    finally:service.close()
    result['listeners_closed'] = not service.running
    result['ok'] = all(result.values())
    return result
