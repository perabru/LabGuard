"""Resumo conservador da amostra recebida; não coleta dados nem concede controle.

As contagens de ``devices`` e ``local_devices`` representam endereços com
evidências, não uma contagem física de computadores ou de pessoas.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math
import re

MAX_ROWS = 10000
FRESH_SECONDS = 20
MODES = {"observation", "equipment", "gateway", "demo"}
SOURCE = {"observation": ("local", "Observação local"), "equipment": ("router", "Equipamento conectado"),
          "gateway": ("gateway", "Gateway avançado"), "demo": ("demo", "Demonstração")}
METHODS = {"linux-iproute2", "linux-ioctl", "linux-sysfs-mac", "linux-proc-route", "linux-proc-arp",
           "windows-nettcpip", "windows-cim", "windows-arp"}
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z", re.I)


def collection_recency(snapshot_or_timestamp, *, now=None, max_age_seconds=FRESH_SECONDS):
    """Valida o horário da fonte, sem substituí-lo pelo horário de recebimento.

    ISO com fuso é obrigatório. Datas futuras, inclusive por poucos segundos,
    nunca são recentes. ``now`` permite uma avaliação determinística nos testes.
    """
    value = snapshot_or_timestamp.get("timestamp") if isinstance(snapshot_or_timestamp, dict) else snapshot_or_timestamp
    result = {"timestamp": "", "age_seconds": None, "fresh": False, "time_status": "missing"}
    if value is None or value == "":
        return result
    result["time_status"] = "invalid"
    if not isinstance(value, str) or len(value) > 128:
        return result
    if type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds) or max_age_seconds < 0:
        return result
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        return result
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None or current.utcoffset() is None:
            return result
        stamp = stamp.astimezone(timezone.utc)
        age = (current.astimezone(timezone.utc) - stamp).total_seconds()
        result["timestamp"] = stamp.isoformat(timespec="microseconds")
    except (ValueError, TypeError, OverflowError):
        return result
    if not math.isfinite(age):
        return result
    if age < 0:
        result["time_status"] = "future"
        return result
    result["age_seconds"] = age
    result["fresh"] = age <= max_age_seconds
    result["time_status"] = "fresh" if result["fresh"] else "stale"
    return result


def _ip(value, *, interface=False):
    if not isinstance(value, str) or len(value) > 128 or "%" in value:
        return None
    try:
        address = ipaddress.ip_interface(value.strip()).ip if interface else ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified or address.is_loopback or address.is_multicast or str(address) == "255.255.255.255":
        return None
    return str(address)


def _mac(value):
    if not isinstance(value, str):
        return None
    value = value.replace("-", ":").lower()
    if not MAC_RE.fullmatch(value) or value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        return None
    return value


def _rows(value):
    return value[:MAX_ROWS] if isinstance(value, (list, tuple)) else []


def _flag(data, key):
    value = data.get(key)
    return value if type(value) is bool else None


def summarize_inventory(snapshot, *, now=None, max_age_seconds=FRESH_SECONDS):
    """Descreve somente evidências disponíveis, sem modificar a amostra.

    Nenhuma combinação de DHCP, ARP, capacidades ou horário retorna cobertura
    completa ou confirma presença. Texto arbitrário e segredos não são ecoados.
    """
    data = snapshot if isinstance(snapshot, dict) else {}
    mode = data.get("mode")
    mode = mode if isinstance(mode, str) and mode in MODES else "unknown"
    source, source_label = SOURCE.get(mode, ("unknown", "Fonte não confirmada"))
    discovery = data.get("discovery") if isinstance(data.get("discovery"), dict) else {}
    metadata_valid = None if "discovery" not in data else isinstance(data.get("discovery"), dict)
    if metadata_valid:
        technical = ("read_success", "interfaces_read", "routes_read", "neighbors_read")
        metadata_valid = all(discovery.get(key) is None or type(discovery[key]) is bool for key in technical)
    read_flags = {key: _flag(discovery, key) for key in ("interfaces_read", "routes_read", "neighbors_read")}
    read_success = _flag(discovery, "read_success")
    if read_success is False and any(value is True for value in read_flags.values()):
        metadata_valid = False
    if read_success is None:
        if any(value is True for value in read_flags.values()):
            read_success = True
        elif all(value is False for value in read_flags.values()):
            read_success = False
    elif read_success is True and all(value is False for value in read_flags.values()):
        read_success = False
        metadata_valid = False
    methods = discovery.get("sources")
    methods = sorted({item for item in _rows(methods) if isinstance(item, str) and item in METHODS})
    local_ips, local_interfaces, interface_ip_macs = set(), set(), {}
    local = data.get("local") if isinstance(data.get("local"), dict) else {}
    for row in [*_rows(data.get("interfaces")), *_rows(local.get("interfaces"))]:
        if not isinstance(row, dict):
            continue
        found = {_ip(row.get(key), interface=True) for key in ("ipv4", "ip", "address")}
        found.discard(None)
        if found:
            local_ips.update(found)
            mac = _mac(row.get("mac"))
            if mac:
                for address in found:
                    interface_ip_macs.setdefault(address, set()).add(mac)
            name = row.get("name")
            # Names remain internal; arbitrary labels are never returned.
            local_interfaces.add(name if isinstance(name, str) and name else tuple(sorted(found)))
    records = _rows(data.get("devices"))
    remote_ips, all_ips, excluded_ips, flagged_conflicts = set(), set(), set(), set()
    ip_macs = {ip: set(macs) for ip, macs in interface_ip_macs.items()}
    known_macs = {mac for macs in ip_macs.values() for mac in macs}
    ignored = 0
    for row in records:
        if not isinstance(row, dict):
            ignored += 1
            continue
        address = _ip(row.get("ip"))
        if address is None:
            ignored += 1
            continue
        observed = row.get("observed")
        if observed is False:
            excluded_ips.add(address)
            continue
        if observed is not None and type(observed) is not bool:
            ignored += 1
            continue
        own = row.get("local") is True or row.get("state") == "Endereço local" or address in local_ips
        if own:
            local_ips.add(address)
        else:
            remote_ips.add(address)
        all_ips.add(address)
        mac = _mac(row.get("mac"))
        ip_macs.setdefault(address, set())
        if mac:
            known_macs.add(mac)
            ip_macs[address].add(mac)
        if row.get("identity_conflict") is True:
            flagged_conflicts.add(address)
    # A local interface is evidence even when a source omits a duplicate device row.
    all_ips.update(local_ips)
    remote_ips.difference_update(local_ips)
    conflicts = flagged_conflicts | {ip for ip, macs in ip_macs.items() if len(macs) > 1}
    missing_macs = {ip for ip in remote_ips if not ip_macs.get(ip)}
    counts = {"local_interfaces": len(local_interfaces), "local_devices": len(local_ips),
              "observed_neighbors": len(remote_ips), "devices": len(all_ips), "unique_ips": len(all_ips),
              "known_macs": len(known_macs), "missing_neighbor_macs": len(missing_macs),
              "identity_conflicts": len(conflicts), "records_ignored": ignored,
              "addresses_without_observation": len(excluded_ips - all_ips)}
    caps = data.get("capabilities") if isinstance(data.get("capabilities"), dict) else {}
    has_evidence = bool(all_ips)
    available = mode != "unknown" and metadata_valid is not False and read_success is not False and (read_success is True or has_evidence or caps.get("inventory") is True)
    status = "demo" if mode == "demo" else "partial" if available else "unavailable"
    recency = collection_recency(data, now=now, max_age_seconds=max_age_seconds)
    fresh = bool(recency["fresh"] and status != "unavailable")
    gateway = data.get("gateway") if isinstance(data.get("gateway"), dict) else {}
    gateway_identified = any(_ip(gateway.get(key)) for key in ("ip", "gateway_ip", "management_host")) or bool(_ip(local.get("default_gateway")))
    unknown_words = {"", "unknown", "desconhecido", "desconhecida", "não identificado", "nao identificado", "n/a"}
    model_identified = mode in {"equipment", "gateway"} and all(isinstance(gateway.get(key), str) and gateway[key].strip().casefold() not in unknown_words for key in ("vendor", "model"))
    facts = {"read_success": read_success, "read_confirmed": read_success is True and metadata_valid is not False,
             "collection_metadata_valid": metadata_valid, "has_evidence": has_evidence,
             "gateway_identified": bool(gateway_identified), "model_identified": bool(model_identified),
             **read_flags, "coverage_complete": False, "collection_recent": fresh, "presence_confirmed": False,
             "people_identified": False, "source_methods": methods,
             "fallback_used": any(method in {"linux-ioctl", "linux-sysfs-mac", "linux-proc-route", "linux-proc-arp", "windows-cim", "windows-arp"} for method in methods)}
    gaps = ["A amostra não comprova todos os equipamentos da rede nem identifica pessoas.",
            "DHCP, ARP e cache registram evidências; não confirmam presença atual."]
    if mode == "observation":
        gaps.append("A leitura local pode ser limitada por VLAN, NAT, isolamento Wi-Fi e equipamentos silenciosos; cobre a rede visível ao computador coletor.")
    if read_success is False:
        gaps.insert(0, "A coleta local não confirmou uma leitura válida; registros anteriores não comprovam uma consulta atual.")
    elif read_success is None:
        gaps.append("A fonte não informou o estado técnico de cada tabela consultada.")
    if metadata_valid is False:
        gaps.insert(0, "Os metadados técnicos da coleta são inválidos ou contraditórios; a leitura não foi confirmada.")
    if read_flags["neighbors_read"] is False:
        gaps.append("A tabela de vizinhos não pôde ser lida; isso não significa ausência de equipamentos.")
    elif read_flags["neighbors_read"] is True and not remote_ips:
        gaps.append("A tabela de vizinhos foi lida sem registros válidos; cache vazio pode ser normal.")
    if read_flags["interfaces_read"] is False:
        gaps.append("Os endereços locais não foram confirmados por essa leitura.")
    if read_flags["routes_read"] is False:
        gaps.append("A rota padrão não foi confirmada por essa leitura.")
    if recency["time_status"] != "fresh":
        gaps.append({"stale": "A amostra tem horário antigo; atualize a fonte antes de agir.",
                     "future": "O horário da fonte está no futuro e não pode ser considerado recente.",
                     "missing": "A fonte não informou o horário da coleta.",
                     "invalid": "O horário da coleta não pôde ser validado."}[recency["time_status"]])
    if conflicts:
        gaps.insert(0, "O mesmo IP tem identidades de MAC conflitantes; confirme o equipamento antes de uma ação.")
    if missing_macs:
        gaps.append("Há endereços remotos sem MAC confirmado; o MAC vazio do próprio computador não é tratado como falha.")
    if counts["addresses_without_observation"]:
        gaps.append("Regras salvas sem observação atual não entram na contagem de endereços observados.")
    if isinstance(data.get("devices"), (list, tuple)) and len(data["devices"]) > MAX_ROWS:
        gaps.append("O resumo foi limitado a dez mil registros; a amostra pode conter outros endereços.")
    if status == "demo":
        status_label = "Demonstração · dados fictícios"
        summary = f"Demonstração: {len(all_ips)} endereço(s) fictício(s), sem identificação da rede real."
        next_action = "Escolha Observação para consultar a rede real; o painel não troca o modo automaticamente."
    elif status == "unavailable":
        status_label = "Leitura indisponível"
        summary = "Não foi possível confirmar uma leitura da fonte. Isso não comprova falta de rede ou ausência de equipamentos."
        next_action = "Abra o passo a passo de identificação e confira a fonte; depois solicite uma nova leitura."
    else:
        status_label = "Leitura confirmada · cobertura parcial" if read_success is True and fresh else "Leitura disponível · cobertura parcial"
        summary = f"{len(all_ips)} endereço(s) com evidências, {len(remote_ips)} vizinho(s) conhecido(s) e {len(known_macs)} MAC(s) distinto(s). A cobertura é parcial."
        if conflicts:
            next_action = "Confirme as identidades conflitantes na fonte autorizada antes de bloquear ou remover regras."
        elif not fresh:
            next_action = "Atualize a fonte e confira o horário da coleta antes de agir."
        elif mode == "observation" and not gateway_identified:
            next_action = "Confira a interface e a rota no passo a passo; uma rede apenas local pode não ter gateway padrão."
        elif mode == "observation":
            next_action = "Compare a amostra com o inventário autorizado ou conecte um controlador compatível para ampliar a visibilidade."
        else:
            next_action = "Compare esta amostra com o inventário autorizado e confirme o alvo antes de agir."
    return {"status": status, "status_label": status_label, "mode": mode, "source": source,
            "source_label": source_label, "summary": summary, "counts": counts, "facts": facts,
            "next_action": next_action, "gaps": list(dict.fromkeys(gaps)), "timestamp": recency["timestamp"],
            "age_seconds": recency["age_seconds"], "fresh": fresh, "time_status": recency["time_status"]}
