"""Orientações estáticas de diagnóstico; não executa comandos nem concede controle."""
from __future__ import annotations

import ipaddress
import platform
import re

CASE_LABELS = {
    "no_local_ip": "IPv4 privada não identificada",
    "no_gateway": "Gateway local não identificado",
    "limited_neighbors": "Poucos dispositivos aparecem",
    "missing_mac": "MAC de outro dispositivo não aparece",
    "unknown_model": "Marca ou modelo desconhecido",
    "tls": "HTTPS ou certificado",
    "authentication": "Usuário, senha ou permissão",
    "api_unavailable": "API REST indisponível",
    "timeout": "Consulta demorou ou não respondeu",
    "connection_error": "Falha de conexão sem causa confirmada",
}
ERROR_CASES = {"tls", "authentication", "api_unavailable", "timeout", "connection_error"}
ERROR_MESSAGES = {
    "authentication": "Confira credenciais, permissões e restrições de origem com a TI.",
    "tls": "Confira endereço, certificado e confiança HTTPS com a TI.",
    "api_unavailable": "Confira perfil, disponibilidade da API e permissões com a TI.",
    "timeout": "A consulta não foi confirmada no prazo. Confira a conexão e a disponibilidade do equipamento.",
    "connection_error": "Não foi possível determinar a causa desta falha.",
}
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
COMMANDS = {
    "Windows": {"ip": ("ipconfig /all",), "gateway": ("route print -4",), "neighbors": ("arp -a",)},
    "Linux": {"ip": ("ip -4 addr",), "gateway": ("ip -4 route",), "neighbors": ("ip -4 neigh",)},
}


def _rows(value):
    return [row for row in value[:10000] if isinstance(row, dict)] if isinstance(value, (list, tuple)) else []


def _values(value, depth=0):
    if isinstance(value, str):return [value]
    if depth < 3 and isinstance(value, (list, tuple)):
        return [item for child in value[:256] for item in _values(child, depth + 1)]
    return []


def _private_ips(value):
    found = set()
    for item in _values(value):
        try:address = ipaddress.ip_interface(item.strip()).ip
        except ValueError:continue
        if isinstance(address, ipaddress.IPv4Address) and any(address in network for network in PRIVATE_NETWORKS):
            found.add(str(address))
    return found


def _valid_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value, re.I):return False
    return value.lower() != "00:00:00:00:00:00" and not int(value[:2], 16) & 1


def classify_connection_error(error):
    """Retorna só um código conhecido. A mensagem bruta nunca integra a ajuda."""
    if not isinstance(error, str) or not error:return None
    if error in ERROR_CASES:return error
    text = error[:8192].casefold()
    if "não foi possível confirmar a resposta rest https" in text or "verifique endereço, certificado e conexão" in text:
        return "connection_error"
    if re.search(r"(?<!\d)(401|403)(?!\d)", text) or any(word in text for word in ("unauthorized", "forbidden", "autentica", "authentication", "credenciais")):
        return "authentication"
    if any(word in text for word in ("timeout", "timed out", "tempo esgotado", "prazo", "demorou", "tempo total de consulta", "não respondeu a tempo")):
        return "timeout"
    if any(word in text for word in ("certificate_verify_failed", "sslcert", "self signed", "hostname mismatch", "certificado", "certificate")) or re.search(r"\btls\b", text):
        return "tls"
    if re.search(r"(?<!\d)(404|405)(?!\d)", text) or any(word in text for word in ("/rest", "api rest", "api indisponível", "rest https")):
        return "api_unavailable"
    return "connection_error"


def safe_error_message(category):
    detail = ERROR_MESSAGES.get(category, ERROR_MESSAGES["connection_error"]) if isinstance(category, str) else ERROR_MESSAGES["connection_error"]
    return "Operação não confirmada. " + detail + " Atualize e revise o estado antes de repetir uma alteração. Abra o passo a passo para conferir."


def _facts(snapshot, system):
    data = snapshot if isinstance(snapshot, dict) else {}
    mode = data.get("mode")
    mode = mode if isinstance(mode, str) and mode in {"demo", "observation", "equipment", "gateway"} else "unknown"
    local_ips = set()
    for row in _rows(data.get("interfaces")):
        for field in ("ipv4", "ip", "address", "addresses"):
            local_ips.update(_private_ips(row.get(field)))
    local = data.get("local") if isinstance(data.get("local"), dict) else {}
    for row in _rows(local.get("interfaces")):
        local_ips.update(_private_ips(row.get("ipv4")))
    gateway = data.get("gateway") if isinstance(data.get("gateway"), dict) else {}
    gateways = set()
    for value in (gateway.get("ip"), gateway.get("gateway_ip"), local.get("default_gateway")):
        gateways.update(_private_ips(value))
    neighbors, macs, missing = set(), set(), set()
    for row in _rows(data.get("devices")):
        ips = _private_ips(row.get("ip"))
        own = row.get("local") is True or row.get("state") == "Endereço local" or bool(ips & local_ips)
        if own or row.get("observed") is False:continue
        neighbors.update(ips)
        if _valid_mac(row.get("mac")):macs.add(row["mac"].lower())
        else:missing.update(ips)
    known = {"", "desconhecido", "desconhecida", "unknown", "não identificado", "nao identificado", "n/a"}
    unknown_model = mode == "observation" or any(not isinstance(gateway.get(key), str) or gateway.get(key, "").strip().casefold() in known for key in ("vendor", "model"))
    return {"mode": mode, "system": system, "local_ipv4_count": len(local_ips),
            "gateway_count": len(gateways), "observed_neighbors": len(neighbors),
            "known_macs": len(macs), "missing_neighbor_macs": len(missing), "unknown_model": unknown_model}


def _step(identifier, title, instructions, commands=()):
    return {"id": identifier, "title": title, "instructions": list(instructions), "commands": list(commands)}


def build_diagnostic_plan(snapshot=None, last_error="", system=None, case=None):
    """Plano puro com contagens deduplicadas e orientações sem dados de credenciais.

    ``case`` permite escolher uma verificação. A seleção não confirma a causa.
    Campos arbitrários da rede, nomes e erros brutos não são reproduzidos.
    """
    system = system or platform.system()
    system = system if isinstance(system, str) and system in COMMANDS else "Other"
    facts = _facts(snapshot, system)
    commands = COMMANDS.get(system, {"ip": (), "gateway": (), "neighbors": ()})
    cases = []
    error_case = classify_connection_error(last_error)
    if isinstance(case, str) and case in CASE_LABELS:cases.append(case)
    else:
        if error_case:cases.append(error_case)
        if facts["mode"] in {"observation", "unknown"}:
            if not facts["local_ipv4_count"]:cases.append("no_local_ip")
            if not facts["gateway_count"]:cases.append("no_gateway")
        if facts["mode"] != "demo":
            if facts["observed_neighbors"] <= 2:cases.append("limited_neighbors")
            if facts["missing_neighbor_macs"]:cases.append("missing_mac")
            if facts["unknown_model"]:cases.append("unknown_model")
    cases = list(dict.fromkeys(cases))
    initial = ["Confira se você está no computador e na rede do laboratório. Escolha o caso que descreve o que aparece na tela.",
        "Os comandos abaixo são somente de consulta. Execute-os manualmente em um terminal comum; o assistente não executa comandos nem altera a rede.",
        "As verificações são sugestões, não uma causa confirmada. Não envie senhas, tokens, chaves ou capturas com credenciais para suporte."]
    if system == "Windows":initial.insert(1, "Para abrir o terminal: pressione Win+R, digite cmd e pressione Enter. Use sua conta habitual, sem Executar como administrador.")
    elif system == "Linux":initial.insert(1, "Abra Terminal pelo menu de aplicativos do Linux. Use sua conta habitual, sem sudo ou elevação de privilégios.")
    if facts["mode"] == "demo":initial.insert(0, "Você está na demonstração: os dados são fictícios. Para diagnosticar a rede real, volte à Observação quando desejar; este assistente não troca o modo.")
    steps = [_step("start", "Antes de conferir", initial)]
    templates = {
        "no_local_ip": _step("no_local_ip", CASE_LABELS["no_local_ip"], [
            "Confira o cabo ou a rede Wi-Fi em uso e identifique a interface conectada ao laboratório.",
            "Consulte o endereço e compare com a TI. A observação cobre IPv4 privada 10.x, 172.16 a 172.31.x e 192.168.x. IPv6, IP público e algumas interfaces virtuais podem não aparecer; isso não prova falta de internet.",
            "Se o comando mostra IPv4 privada e o programa não, peça à TI para conferir PowerShell/NetTCPIP no Windows ou ip/iproute2 no Linux. Não troque IP, DHCP ou protocolos pelo assistente."], commands["ip"]),
        "no_gateway": _step("no_gateway", CASE_LABELS["no_gateway"], [
            "Consulte a rota padrão e confira qual interface pertence ao laboratório. VPNs ou várias conexões podem apresentar mais de uma rota.",
            "Compare o gateway com a configuração aprovada pela TI. Se não houver rota, peça revisão da conexão; o assistente não cria rotas nem muda DHCP.",
            "Depois de confirmar a rede correta, use Atualizar consulta. Um gateway identificado não informa automaticamente sua marca ou capacidade de bloqueio."], commands["ip"] + commands["gateway"]),
        "limited_neighbors": _step("limited_neighbors", CASE_LABELS["limited_neighbors"], [
            "A tabela local contém vizinhos já conhecidos, não uma lista completa dos computadores. Poucos registros ou cache vazio podem ser normais.",
            "Consulte o cache e compare com uma estação conhecida da mesma rede. Entradas antigas não confirmam que o aparelho esteja ligado agora.",
            "IP estático pode não aparecer no DHCP; VLAN, isolamento e NAT também limitam a lista. Não faça varreduras ou gere tráfego só para preencher registros; consulte o inventário autorizado do equipamento compatível."], commands["neighbors"]),
        "missing_mac": _step("missing_mac", CASE_LABELS["missing_mac"], [
            "Confira se o IP pertence à mesma rede local e se existe uma entrada no cache de vizinhos.",
            "O MAC do próprio computador fica vazio na observação por contrato; isso não é falha. Um MAC remoto pode não ser visível através de roteadores ou NAT.",
            "Não invente um MAC nem associe o endereço a uma pessoa. Atualizar pode reler o cache, mas não garante descobrir um endereço ausente."], commands["neighbors"]),
        "unknown_model": _step("unknown_model", CASE_LABELS["unknown_model"], [
            "Confira fabricante, modelo e firmware na etiqueta ou no inventário administrativo autorizado.",
            "O nome da operadora não define o fabricante nem uma API universal. Não selecione MikroTik apenas porque o endereço do roteador apareceu.",
            "Use o perfil do modelo efetivamente compatível. Sem uma API e permissões confirmadas, continue em Observação; o assistente não libera botões de bloqueio."], ()),
        "tls": _step("tls", CASE_LABELS["tls"], [
            "Confira endereço, porta HTTPS e data/hora do computador. A mensagem recebida pode não distinguir a causa; confirme esses dados com a TI.",
            "No perfil MikroTik direto, use o IP literal aprovado; o certificado precisa conter esse IP em SAN do tipo IP. Confira a cadeia de confiança e use a CA institucional quando necessário.",
            "Não desative a validação TLS, não aceite um certificado desconhecido e não desligue o firewall. Após corrigir os dados com a TI, volte a Início e reconecte."], ()),
        "authentication": _step("authentication", CASE_LABELS["authentication"], [
            "Respostas 401/403 podem envolver credenciais, permissões ou restrição de origem; não confirmam qual delas. Confira a conta autorizada e o acesso à API.",
            "Não repita senhas em relatórios ou campos de ajuda. Não use uma conta de outro equipamento para tentar contornar a recusa.",
            "Atualizar consulta não troca a credencial da sessão. Volte a Início, confira os dados e use Conectar novamente; a autorização de alterar regras continua sendo uma escolha separada."], ()),
        "api_unavailable": _step("api_unavailable", CASE_LABELS["api_unavailable"], [
            "Confira o perfil, o endereço e a porta de gestão do equipamento. Uma página de administração acessível não garante API REST compatível.",
            "Peça à TI para verificar modelo, firmware, disponibilidade da API e permissão da conta. O programa não habilita serviços de gestão automaticamente.",
            "Se a API não for suportada, use Observação ou consulte Outros equipamentos. Não troque para HTTP nem desative controles de segurança para prosseguir."], ()),
        "timeout": _step("timeout", CASE_LABELS["timeout"], [
            "Confira a conexão do computador com a rede e o endereço de gestão aprovado; a demora não confirma se o equipamento está desligado.",
            "Aguarde o fim da consulta atual. Depois, tente uma atualização de leitura, sem repetir um bloqueio cujo resultado ficou sem confirmação.",
            "Se continuar sem resposta, peça à TI para conferir disponibilidade, porta e restrições de gestão. Não altere o firewall ou procure outros endereços por varredura."], commands["ip"] + commands["gateway"]),
        "connection_error": _step("connection_error", CASE_LABELS["connection_error"], [
            "A falha recebida não permite confirmar a causa. Escolha HTTPS, autenticação, API ou tempo esgotado se conhecer o sintoma.",
            "Confira o perfil e os dados de conexão com a TI. Consulte a interface e a rota local sem modificar configurações.",
            "Uma ação de bloqueio pode ter resultado incerto. Faça uma leitura e confira o estado antes de repetir qualquer alteração."], commands["ip"] + commands["gateway"]),
    }
    steps.extend(templates[name] for name in cases)
    retry = "No perfil SSH legado, Atualizar consulta fica desabilitado: a consulta avançada pode reconciliar políticas existentes. Use o fluxo avançado ou escolha Observação em Início por sua própria decisão." if facts["mode"] == "gateway" else "Atualizar consulta relê somente a conexão atual; não bloqueia, não troca credenciais e não muda o perfil."
    steps.append(_step("finish", "Conferir o resultado", [retry,
        "Se endereço, certificado ou conta precisarem mudar, volte a Início e reconecte. As capacidades continuam dependendo da fonte e das permissões confirmadas.",
        "Se persistir, informe à TI versão, sistema, modo, categoria da falha e etapa realizada. Revise os dados antes de compartilhar; não envie credenciais."]))
    return {"cases": cases, "facts": facts, "summary": "Verificações sugeridas; nenhuma alteração de rede será feita.", "steps": steps}
