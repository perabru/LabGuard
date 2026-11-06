"""Protocolo JSON por SSH autenticado; nenhuma senha fica salva no painel."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path


class TransportError(RuntimeError):
    """Falha de conexão ou operação rejeitada pelo gateway."""


class OutputLimitExceeded(RuntimeError):
    """O processo foi interrompido antes de acumular saída sem limite."""


def run_bounded(command, *, input=None, timeout=35, max_output_bytes=4_000_000):
    """Execute sem shell e limite stdout+stderr enquanto os dados chegam.

    A drenagem simultânea das duas saídas evita deadlocks; nenhum arquivo
    temporário com respostas ou credenciais é gravado no computador.
    """
    if input is not None and (not isinstance(input, str) or len(input.encode("utf-8")) > 65536):
        raise ValueError("Entrada do processo excede o limite permitido.")
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {}
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, **options)
    limit = threading.Event()
    guard = threading.Lock()
    chunks = [[], []]
    total = 0

    def drain(stream, destination):
        nonlocal total
        try:
            while True:
                block = stream.read(65536)
                if not block:
                    return
                with guard:
                    remaining = max(0, max_output_bytes - total)
                    chunks[destination].append(block[:remaining])
                    total += len(block)
                    if total > max_output_bytes:
                        limit.set()
                if limit.is_set():
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
        finally:
            stream.close()

    readers = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, 1), daemon=True)]
    for reader in readers:
        reader.start()
    def write_input():
        try:
            process.stdin.write(input.encode("utf-8"))
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    writer = threading.Thread(target=write_input, daemon=True) if input is not None else None
    if writer:
        writer.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        for reader in readers:
            reader.join(timeout=2)
        if writer:
            writer.join(timeout=2)
    if limit.is_set():
        raise OutputLimitExceeded("A resposta excedeu o limite permitido; o SSH foi interrompido.")
    output = [b"".join(part).decode("utf-8", "replace") for part in chunks]
    return subprocess.CompletedProcess(command, process.returncode, output[0], output[1])


def ssh_command_base(executable, port, *, pty=False, key_path="", known_hosts=""):
    """Configuração isolada: não executa ~/.ssh/config ou encaminhamentos."""
    args = [executable, "-F", "none", "-tt" if pty else "-T"]
    settings = ["BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
                "PreferredAuthentications=publickey", "PasswordAuthentication=no",
                "KbdInteractiveAuthentication=no", "HostbasedAuthentication=no",
                "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes",
                "PermitLocalCommand=no", "ProxyCommand=none", "ProxyJump=none",
                "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
                "ConnectionAttempts=1", "ConnectTimeout=8", "ServerAliveInterval=5",
                "ServerAliveCountMax=2", "LogLevel=ERROR"]
    for setting in settings:
        args += ["-o", setting]
    args += ["-p", str(port)]
    if key_path:
        args += ["-o", "IdentitiesOnly=yes", "-i", key_path]
    if known_hosts:
        value = Path(known_hosts).as_posix().replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
        args += ["-o", 'UserKnownHostsFile="' + value + '"']
    return args


def validate_host(host: str) -> str:
    host = host.strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if len(host) > 253 or not host or host.startswith("-"):
        raise ValueError("Informe o IP ou nome do gateway, sem URL nem opções SSH.")
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
               for label in host.split(".")):
        raise ValueError("Nome do gateway inválido. Use somente IP ou nome DNS.")
    return host


class SSHTransport:
    """Um pedido por conexão; a chave remota tem comando forçado no servidor.

    O OpenSSH exige uma identidade já confiável em known_hosts. Não inscrevemos
    chaves automaticamente e não desativamos a verificação da identidade remota.
    """
    mode = "gateway"

    def __init__(self, host: str, port: int = 22, user: str = "labguard",
                 key_path: str = "", known_hosts: str | None = None):
        self.host = validate_host(host)
        self._closed = False
        try:
            self.port = int(port)
        except (ValueError, TypeError):
            raise ValueError("A porta SSH precisa ser um número de 1 a 65535.") from None
        if not 1 <= self.port <= 65535:
            raise ValueError("A porta SSH precisa estar entre 1 e 65535.")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise ValueError("Usuário SSH inválido.")
        self.user = user
        self.key_path = self._path(key_path, "chave privada") if key_path else ""
        self.known_hosts = self._path(known_hosts, "known_hosts") if known_hosts else ""
        self.ssh = shutil.which("ssh")
        if not self.ssh:
            raise TransportError("OpenSSH não encontrado. Instale o Cliente OpenSSH do Windows ou o pacote openssh-client no Linux.")

    @staticmethod
    def _path(path: str, label: str) -> str:
        if not isinstance(path, str) or any(ord(c) < 32 for c in path):
            raise ValueError(f"Caminho de {label} inválido.")
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise ValueError(f"Arquivo de {label} não encontrado.")
        return str(resolved)

    def command(self) -> list[str]:
        if self._closed:
            raise TransportError("A sessão do gateway foi encerrada. Conecte novamente para administrar a rede.")
        args = ssh_command_base(self.ssh, self.port, key_path=self.key_path, known_hosts=self.known_hosts)
        return args + [f"{self.user}@{self.host}", "labguard-agent"]

    def close(self):
        self._closed = True
        self.key_path = self.known_hosts = self.user = self.host = ""

    def request(self, action: str, **params) -> dict:
        if action not in {"snapshot", "add_domain", "remove_domain", "set_device_block", "set_ai_block"}:
            raise ValueError("Operação desconhecida.")
        payload = json.dumps({"version": 1, "action": action, "params": params}, ensure_ascii=True) + "\n"
        if len(payload.encode()) > 8192:
            raise ValueError("Solicitação muito grande.")
        try:
            result = run_bounded(self.command(), input=payload, timeout=35)
        except OutputLimitExceeded as exc:
            raise TransportError(str(exc)) from None
        except subprocess.TimeoutExpired:
            raise TransportError("O gateway não respondeu a tempo. Atualize o painel para conferir se a alteração foi aplicada antes de tentar novamente.") from None
        except OSError as exc:
            raise TransportError(f"Não foi possível executar o SSH: {exc}") from None
        if result.returncode != 0:
            # O processo remoto também usa exit 1 para rejeições da API.
            # Preserve a mensagem da operação em vez de chamá-la falha SSH.
            try:
                rejection = json.loads(result.stdout) if len(result.stdout) <= 4_000_000 else None
            except (json.JSONDecodeError, UnicodeError):
                rejection = None
            if isinstance(rejection, dict) and rejection.get("ok") is False:
                raise TransportError(str(rejection.get("error", "Operação rejeitada pelo gateway.")))
            detail = (result.stderr.strip() or result.stdout.strip())[-1200:]
            if "Host key verification failed" in detail:
                detail = "Identidade SSH não reconhecida ou alterada. Confira a impressão digital no console do gateway e cadastre-a no known_hosts, conforme o manual."
            elif "Permission denied" in detail:
                detail = "Autenticação negada. Confira usuário, chave e ssh-agent; a interface não solicita senha da chave."
            raise TransportError(f"Conexão SSH falhou. {detail}")
        if len(result.stdout) > 4_000_000:
            raise TransportError("Resposta do gateway excedeu o limite esperado.")
        try:
            response = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeError):
            raise TransportError("O gateway retornou uma resposta inválida. Confira o comando SSH forçado e a instalação do agente.") from None
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise TransportError("Resposta incompatível com o protocolo LabGuard.")
        if not response["ok"]:
            raise TransportError(str(response.get("error", "Operação rejeitada pelo gateway.")))
        data = response.get("data")
        if not isinstance(data, dict) or data.get("mode") != "gateway":
            raise TransportError("O destino não retornou um estado real do gateway LabGuard.")
        for field in ("devices", "domains", "events", "connections", "audit", "warnings"):
            if not isinstance(data.get(field), list):
                raise TransportError(f"Resposta incompleta do gateway: {field}.")
            if field != "warnings" and any(not isinstance(row, dict) for row in data[field]):
                raise TransportError(f"Resposta do gateway contém registros inválidos: {field}.")
        health = data.get("health")
        if not isinstance(health, dict) or any(type(health.get(key)) is not bool for key in ("firewall", "dns", "forwarding")):
            raise TransportError("O gateway não informou um estado válido dos serviços.")
        return data
