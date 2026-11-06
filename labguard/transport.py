"""Protocolo JSON por SSH autenticado; nenhuma senha fica salva no painel."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path


class TransportError(RuntimeError):
    """Falha de conexão ou operação rejeitada pelo gateway."""


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
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise ValueError(f"Arquivo de {label} não encontrado.")
        return str(resolved)

    def command(self) -> list[str]:
        args = [self.ssh, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR", "-p", str(self.port)]
        if self.key_path:
            args += ["-o", "IdentitiesOnly=yes", "-i", self.key_path]
        if self.known_hosts:
            args += ["-o", f"UserKnownHostsFile={self.known_hosts}"]
        return args + [f"{self.user}@{self.host}", "labguard-agent"]

    def request(self, action: str, **params) -> dict:
        if action not in {"snapshot", "add_domain", "remove_domain", "set_device_block", "set_ai_block"}:
            raise ValueError("Operação desconhecida.")
        payload = json.dumps({"version": 1, "action": action, "params": params}, ensure_ascii=True) + "\n"
        if len(payload.encode()) > 8192:
            raise ValueError("Solicitação muito grande.")
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {}
        try:
            result = subprocess.run(self.command(), input=payload, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=35,
                                    check=False, **options)
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
        return data
