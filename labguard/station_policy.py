"""Elegibilidade de estações para administração DNS central."""
from dataclasses import dataclass
import ipaddress

from .demo import normalize_mac
from .local_dns import DNSError, validate_config
from .remote import RemoteError


@dataclass(frozen=True)
class StationTarget:
    address: str
    listen: str
    network: str
    token: str
    macs: tuple


class StationScope:
    def __init__(self, snapshot):
        service = snapshot.get("dns_service", {})
        if (snapshot.get("mode") != "equipment" or snapshot.get("source_type") != "local_dns"
                or service.get("service_running") is not True or not service.get("check_token")):
            raise RemoteError("Inicie o filtro DNS local antes de selecionar uma estação.")
        if service.get("port") != 53:
            raise RemoteError("As estações usam a porta DNS 53. Confira a porta do filtro.")
        try:
            self.listen, self.network, *_ = validate_config(service.get("listen"), service.get("network"))
        except DNSError:
            raise RemoteError("Confira o IP e a rede autorizada do filtro.") from None
        self.token = service["check_token"]
        local = snapshot.get("local", {})
        gateway = snapshot.get("gateway", {})
        self.can_change = bool(local.get("interface_ips") and local.get("interfaces_read") is True
                               and local.get("routes_read") is True)
        self.protected = {self.listen, local.get("default_gateway"), gateway.get("ip"), gateway.get("management_host")}
        self.protected.update(local.get("interface_ips", []))
        for interface in snapshot.get("interfaces", []):
            self.protected.add(str(interface.get("ipv4", "")).split("/")[0])
        self.macs = {}
        self.conflicts = set()
        for device in snapshot.get("devices", []):
            address = device.get("ip")
            if not isinstance(address, str):
                continue
            known = self.macs.setdefault(address, set())
            try:
                known.add(normalize_mac(device.get("mac", "")))
            except ValueError:
                pass
            if device.get("protected") or device.get("local") or device.get("state") == "Endereço local":
                self.protected.add(address)
            if device.get("identity_conflict") or len(known) > 1:
                self.conflicts.add(address)

    def target(self, entered_ip, *, for_change=False):
        if for_change and not self.can_change:
            raise RemoteError("Atualize a leitura de interfaces e rotas para conferir os endereços protegidos antes da alteração.")

        try:
            address = ipaddress.IPv4Address(entered_ip.strip())
        except (ValueError, AttributeError):
            raise RemoteError("Informe um endereço IPv4 válido para a estação.") from None
        ip = str(address)
        if (address not in self.network or address in (self.network.network_address, self.network.broadcast_address)
                or address.is_loopback or address.is_link_local):
            raise RemoteError("Selecione uma estação da rede autorizada do laboratório.")
        if ip in self.protected:
            raise RemoteError("Este endereço pertence ao PC do filtro, ao gateway ou a um equipamento protegido.")
        if ip in self.conflicts:
            raise RemoteError("O inventário apresenta identidades conflitantes para este IP.")
        return StationTarget(ip, self.listen, str(self.network), self.token, tuple(sorted(self.macs.get(ip, ()))))

    def inventory(self):
        addresses = []
        for ip in self.macs:
            try:
                addresses.append(ipaddress.IPv4Address(self.target(ip).address))
            except RemoteError:
                continue
        return [str(address) for address in sorted(addresses)]


def station_target_from_snapshot(snapshot, entered_ip, *, for_change=False):
    return StationScope(snapshot).target(entered_ip, for_change=for_change)
