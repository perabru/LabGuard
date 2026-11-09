"""Render a fixed, scoped computer startup script for managed Windows stations."""
import ipaddress


def prepare_access(payload, assets):
    if not isinstance(payload, dict) or set(payload) != {'management_ip'}:
        raise ValueError('Informe o IPv4 do computador da TI.')
    if not isinstance(payload['management_ip'], str):
        raise ValueError('Informe o IPv4 em texto.')
    try:
        ip = ipaddress.IPv4Address(payload['management_ip'])
    except (ValueError, TypeError) as error:
        raise ValueError('Informe um endereço IPv4 válido da TI.') from error
    ranges = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
    if not any(ip in ipaddress.ip_network(network) for network in ranges):
        raise ValueError('Escolha um IPv4 privado do computador da TI.')
    template = (assets / 'prepare-station.ps1').read_text(encoding='utf-8')
    return {'name':'LabGuard-Preparar-Acesso.ps1', 'script':template.replace('__MANAGEMENT_IPV4__', str(ip))}
