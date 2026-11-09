"""Testa somente a porta do Windows de uma estação previamente autorizada."""
import errno
import socket


def check_winrm_port(host):
    """O chamador valida o IPv4 da estação e o escopo do laboratório antes do teste."""
    endpoint = f"{host}:5986"
    try:
        with socket.create_connection((host, 5986), timeout=4):
            pass
    except OSError as error:
        number = getattr(error, "winerror", None) or error.errno
        if isinstance(error, ConnectionRefusedError) or number in (errno.ECONNREFUSED, 10061):
            code = "refused"
            message = (f"{endpoint} recusou a conexão. Confira o serviço WinRM HTTPS e a regra de "
                       "entrada da estação para o IP do PC da TI.")
        elif isinstance(error, TimeoutError) or number in (errno.ETIMEDOUT, 10060):
            code = "timeout"
            message = (f"{endpoint} não respondeu em 4 segundos. Confira se o IP ainda é o da estação, "
                       "se ela está ligada e se o firewall permite a conexão a partir da TI.")
        elif number in (errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065):
            code = "unreachable"
            message = f"O PC da TI não alcançou {endpoint}. Confira o IP e o caminho entre as duas redes."
        else:
            code = "error"
            message = f"O PC da TI não conseguiu testar {endpoint}. Confira a conexão de rede e tente novamente."
        return {"ok": False, "code": code, "message": message}
    return {"ok": True, "code": "open",
            "message": f"{endpoint} aceitou a conexão TCP. O teste autenticado verifica o certificado, a conta e o DNS."}
