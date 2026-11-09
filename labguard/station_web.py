"""Authenticated station DNS operations for the local administration server."""
from collections import OrderedDict
from dataclasses import dataclass
import hmac
import ipaddress
from pathlib import Path
import threading
import time

from .remote import create_session, RemoteError
from .server import ServerError

OPERATIONS = frozenset(('test', 'preview', 'apply', 'restore', 'prepare-access'))
STATION_ROUTES = frozenset('/api/station/' + operation for operation in OPERATIONS)


@dataclass(frozen=True)
class PendingPreview:
    id: str
    expires: float
    target: object
    plan: object


class StationOperations:
    """Keep approval plans in memory and scope them to admin, account, target and live source."""
    def __init__(self):
        self._previews = OrderedDict()
        self._lock = threading.Lock()
        self._closed = False

    def close(self):
        with self._lock:
            self._closed = True
            self._previews.clear()

    @staticmethod
    def _arguments(operation, payload):
        required = {'host', 'user', 'password'}
        if operation in ('apply', 'restore', 'prepare-access'):
            required.add('confirm')
        if operation == 'prepare-access':
            required.add('hostname')
        if operation == 'apply':
            required.add('id')
        if operation not in OPERATIONS or not isinstance(payload, dict) or set(payload) != required:
            raise ServerError('Parâmetros de estação inválidos.')
        if not isinstance(payload['host'], str):
            raise ServerError('Informe o IPv4 da estação.')
        try:
            host = str(ipaddress.IPv4Address(payload['host']))
        except ValueError:
            raise ServerError('Informe o IPv4 da estação.') from None
        user, password = payload['user'], payload['password']
        if not isinstance(user, str) or not 1 <= len(user.strip()) <= 200 or not user.isprintable():
            raise ServerError('Informe a conta administrativa da estação.')
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise ServerError('Informe a senha da estação para esta operação.')
        if 'confirm' in required and payload['confirm'] is not True:
            raise ServerError('Confirme a alteração na estação selecionada.')
        if 'hostname' in required and (not isinstance(payload['hostname'], str)
                or not 1 <= len(payload['hostname']) <= 253 or not payload['hostname'].isprintable()):
            raise ServerError('Informe o nome DNS completo da estação.')
        if 'id' in required and (not isinstance(payload['id'], str) or not 1 <= len(payload['id']) <= 128):
            raise ServerError('Atualize a prévia antes de aplicar.')
        return host, user.strip(), password

    @staticmethod
    def _ca(directory):
        path = Path(directory) / 'station-ca.pem'
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ServerError('Confira o certificado station-ca.pem do servidor.')
        return str(path) if path.is_file() else ''

    @staticmethod
    def _source_current(app):
        if (app._closed or app.config.demo or app.config.controller.get('kind') != 'local_dns'
                or app.config.controller.get('manage_rules') is not True):
            raise ServerError('Inicie e autorize o filtro DNS local para continuar.')
        still_attached = getattr(app.transport, 'station_source_current', None)
        if still_attached is not None and not still_attached():
            raise ServerError('A conexão com o filtro mudou. Abra novamente o painel da estação.')

    def current_dns_snapshot(self, app):
        self._source_current(app)
        try:
            raw = app.transport.request('snapshot')
            state = app.public_snapshot(raw)
        except Exception:
            app.stale = True
            raise ServerError('Não foi possível consultar o filtro DNS atual.') from None
        service = state.get('dns_service', {})
        if (not app.collection_current(state) or state.get('health', {}).get('dns') is not True
                or state.get('source_type') != 'local_dns' or service.get('service_running') is not True
                or not service.get('check_token')):
            app.stale = True
            raise ServerError('A coleta do filtro está desatualizada ou o DNS está indisponível.')
        self._source_current(app)
        return raw

    def _scope(self, app, host, *, for_change):
        from .station_policy import station_target_from_snapshot
        raw = self.current_dns_snapshot(app)
        try:
            return raw, station_target_from_snapshot(raw, host, for_change=for_change)
        except RemoteError as error:
            # This validator receives only a canonical IPv4 and locally observed metadata.
            raise ServerError(str(error)) from None

    def _expire_locked(self, now):
        for key in [key for key, value in self._previews.items() if value.expires <= now]:
            del self._previews[key]

    def _keep(self, key, target, result, plan):
        with self._lock:
            if self._closed:
                raise ServerError('O painel de estações foi encerrado.')
            now = time.monotonic()
            self._expire_locked(now)
            self._previews[key] = PendingPreview(result['id'], now + 60, target, plan)
            self._previews.move_to_end(key)
            while len(self._previews) > 32:
                self._previews.popitem(last=False)

    def _take(self, key, target, preview_id):
        with self._lock:
            self._expire_locked(time.monotonic())
            saved = self._previews.get(key)
            if saved is None or saved.id != preview_id:
                raise ServerError('A prévia expirou ou pertence a outra estação ou conta. Gere uma nova prévia.')
            del self._previews[key]
            if saved.target != target:
                raise ServerError('O filtro ou a identidade da estação mudou. Gere uma nova prévia.')
            return saved.plan

    def _prepare_access(self, app, snapshot, payload):
        from .server import asset_directory
        try:
            from .access_push import prepare_remote_access
        except ImportError:
            raise ServerError('Preparação remota indisponível nesta instalação.') from None
        self._source_current(app)
        try:
            return prepare_remote_access(snapshot, payload, asset_directory())
        except RemoteError as error:
            # The fixed WMI preparer exposes only its own messages, never PowerShell output.
            message = str(error)
            if payload['password'] in message:
                message = 'A preparação remota não foi confirmada.'
            raise ServerError(message) from None
        except Exception:
            raise ServerError('A preparação remota não foi confirmada. Confira o nome da estação e o acesso administrativo de domínio.') from None

    def run(self, app, operation, payload, operator):
        from .station_dns import StationDNS
        if not hmac.compare_digest(operator, app.config.token_hashes['admin']):
            raise ServerError('A administração da estação exige o acesso de administrador.')
        host, user, password = self._arguments(operation, payload)
        key = (operator, user, host)
        if not app.network_lock.acquire(timeout=0.1):
            raise ServerError('Há uma operação em andamento. Aguarde antes de continuar.')
        session = None
        try:
            snapshot, target = self._scope(app, host, for_change=operation != 'test')
            if operation == 'prepare-access':
                return self._prepare_access(app, snapshot, payload)
            plan = self._take(key, target, payload['id']) if operation == 'apply' else None
            if operation in ('preview', 'restore'):
                with self._lock:
                    self._previews.pop(key, None)
            session = create_session('windows', host, user, password, ca_file=self._ca(app.config.directory))
            station = StationDNS(session, listen=target.listen, network=target.network, token=target.token)
            self._source_current(app)
            if operation == 'test':
                from .school_policy import sample_blocked_domain
                blocked_domain = sample_blocked_domain(snapshot)
                if blocked_domain:
                    return station.test(blocked_domain=blocked_domain, read_evidence=lambda: self.current_dns_snapshot(app))
                return station.test()
            if operation == 'preview':
                result = station.preview()
                self._source_current(app)
                self._keep(key, target, result, station.take_preview())
                return result
            _, current_target = self._scope(app, host, for_change=True)
            if target != current_target:
                raise ServerError('A conexão ou a estação mudou. Confira o alvo novamente.')
            if operation == 'apply':
                station.resume_preview(plan)
                return station.apply(payload['id'])
            return station.restore()
        except RemoteError:
            raise ServerError('A estação não confirmou a operação. Confira WinRM HTTPS, a conta, o certificado e a configuração atual.') from None
        except ServerError:
            raise
        except Exception:
            raise ServerError('A comunicação com a estação terminou sem confirmação. Confira o estado antes de repetir.') from None
        finally:
            try:
                if session is not None:
                    session.close()
            except Exception:
                app.audit('station_close', 'admin', 'unconfirmed')
            finally:
                app.network_lock.release()
