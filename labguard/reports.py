"""Relatórios locais da amostra observada e desenho lógico da rede."""
from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
from html import escape
import io
import os
from pathlib import Path
import tempfile


class ReportError(RuntimeError):
    pass


def _text(value, limit=500):
    value = str(value if value is not None else "")[:limit]
    return "".join(c if 32 <= ord(c) < 0xD800 or 0xE000 <= ord(c) < 0xFFFE or 0x10000 <= ord(c) <= 0x10FFFF else " " for c in value)


def _cell(value):
    value = _text(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def report_data(snapshot):
    if not isinstance(snapshot, dict):
        raise ReportError("Atualize os dados da fonte antes de exportar.")
    if any(not isinstance(snapshot.get(key, []), list) for key in ("devices", "events", "address_blocks")):
        raise ReportError("A fonte retornou uma amostra de relatório inválida.")
    devices = [dict(row) for row in snapshot.get("devices", []) if isinstance(row, dict)][:10000]
    events = [row for row in snapshot.get("events", []) if isinstance(row, dict)][:1000]
    rules = [row for row in snapshot.get("address_blocks", []) if isinstance(row, dict)][:10000]
    domains = Counter(_text(row.get("domain", ""), 253) for row in events if row.get("domain"))
    gateway = snapshot.get("gateway") if isinstance(snapshot.get("gateway"), dict) else {}
    stale = bool(snapshot.get("_stale") or snapshot.get("stale"))
    try:
        timestamp = datetime.fromisoformat(str(snapshot.get("timestamp", "")).replace("Z", "+00:00"))
        stale = stale or timestamp.tzinfo is None or not -30 <= (datetime.now(timezone.utc)-timestamp).total_seconds() <= 45
    except (TypeError, ValueError):
        stale = True
    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "stale": stale,
            "timestamp": _text(snapshot.get("timestamp", "Não informado")),
            "demo": snapshot.get("mode") == "demo", "mode": _text(snapshot.get("mode", "desconhecido")),
            "gateway": gateway, "devices": devices, "rules": rules, "events": events,
            "top_domains": domains.most_common(10), "total_received": len(snapshot.get("devices", [])),
            "observed": sum(row.get("observed", True) is not False for row in devices),
            "blocked": sum(bool(row.get("blocked")) for row in devices),
            "queries": len(events), "protected": sum(bool(row.get("protected")) for row in devices)}



def _source_label(data):
    return "Fonte" if data["mode"] == "observation" else "Roteador" if data["mode"] == "equipment" else "Gateway"


def _source_name(data):
    return data["gateway"].get("hostname") or ("Observação local" if data["mode"] == "observation" else
            "Roteador não informado" if data["mode"] == "equipment" else "Gateway LabGuard")


def _mode_notice(data):
    if data["demo"]:
        return "DEMONSTRAÇÃO — dados fictícios"
    if data["mode"] == "observation":
        notice = "Observação parcial local · bloqueios indisponíveis; nenhum bloqueio real aplicado por esta fonte."
    elif data["mode"] == "equipment":
        notice = "Amostra consultada no roteador; ações dependem das capacidades confirmadas."
    else:
        notice = "Amostra observada pelo gateway"
    return notice + (" · LEITURA ANTIGA / NÃO CONFIRMADA" if data["stale"] else "")


def _network_label(data):
    return "Segmento observado pela fonte local" if data["mode"] == "observation" else "LAN / Wi-Fi pelo roteador" if data["mode"] == "equipment" else "LAN / Wi-Fi pelo gateway"


def _limits(data):
    if data["mode"] == "observation":
        return ("Observação parcial das interfaces, rotas e vizinhos disponíveis no sistema local; não é um inventário completo e não comprova presença atual. "
                "Esta fonte não aplica bloqueios reais. Ligações do mapa são inferidas. Cabo/Wi-Fi, SSID e AP só são apresentados quando informados pela fonte. "
                "Consultas DNS, quando disponíveis, não comprovam visitas nem revelam conteúdo HTTPS.")
    if data["mode"] == "equipment":
        return ("Inventário informado pelo equipamento; concessão não comprova presença atual. O mapa é lógico e suas ligações são inferidas. "
                "Cabo/Wi-Fi, SSID e AP só são apresentados quando informados. Consultas DNS não comprovam visitas nem revelam conteúdo HTTPS. "
                "As ações dependem das capacidades confirmadas, permissões e caminho do tráfego pelo equipamento. "
                "NAT e MAC privado podem limitar a identificação; bloquear internet não desassocia o aparelho do rádio Wi-Fi.")
    return LIMITS

def _scope(row, mode=None):
    labels = {"device": "Máquina (legado)", "ip": "IP", "mac": "MAC"}
    scopes = row.get("blocked_by", [])
    if isinstance(scopes, list) and scopes:
        return ", ".join(labels.get(_text(item), _text(item)) for item in scopes[:3])
    if row.get("blocked"):
        return "Bloqueio informado"
    return "Bloqueio não verificado" if mode == "observation" else "Sem bloqueio informado" if mode == "equipment" else "Livre"


def _connection(row):
    kind = {"wifi": "Wi-Fi", "wired": "Cabo"}.get(row.get("connection_type"), "Não informado")
    details = [_text(row.get(key), 80) for key in ("ssid", "ap") if row.get(key)]
    return kind + (" / " + " / ".join(details) if details else "")


def network_map_svg(snapshot):
    data = report_data(snapshot)
    rows = data["devices"][:200]
    columns, width = 4, 1160
    grid_rows = max(1, (len(rows) + columns - 1) // columns)
    height = 285 + grid_rows * 134
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Mapa lógico da rede observada">',
             f'<rect width="{width}" height="{height}" rx="18" fill="#f5f3fc"/>']
    def text(x, y, value, size=13, color="#21183f", weight="normal"):
        parts.append(f'<text x="{x}" y="{y}" font-family="sans-serif" font-size="{size}" fill="{color}" font-weight="{weight}">{escape(_text(value))}</text>')
    text(24, 34, "LabGuard | Mapa lógico da rede", 23, weight="bold")
    text(24, 60, f'Observação parcial local · bloqueios indisponíveis · Amostra: {data["timestamp"]}' if data["mode"] == "observation" else
         "DEMONSTRAÇÃO — dados fictícios" if data["demo"] else f'Amostra: {data["timestamp"]}', 13, "#736b87")
    if data["stale"] and not data["demo"]:
        text(794, 107, "LEITURA ANTIGA / NÃO CONFIRMADA", 11, "#c24769", "bold")
    parts.append('<rect x="385" y="83" width="390" height="60" rx="12" fill="#6c42d9"/>')
    text(404, 108, f'{_source_label(data)}: {_source_name(data)}' if data["mode"] in {"observation", "equipment"} else _source_name(data), 16, "#ffffff", "bold")
    text(404, 129, data["gateway"].get("lab_cidr", "Rede não informada"), 13, "#ffffff")
    parts.append('<path d="M580 143V173" stroke="#3478f6" stroke-width="3"/><rect x="385" y="173" width="390" height="44" rx="10" fill="#e4edff"/>')
    text(410, 201, _network_label(data), 16, "#2259b2", "bold")
    text(24, 243, "Observação parcial; nenhum bloqueio real aplicado. Ligações inferidas; SSID/AP somente quando informados." if data["mode"] == "observation" else
         "Ligações inferidas. Portas físicas, SSID e ponto de acesso só são conhecidos quando informados pela fonte.", 12, "#736b87")
    for index, row in enumerate(rows):
        x, y = 24 + (index % columns) * 282, 265 + (index // columns) * 134
        color = "#13846b" if row.get("protected") else "#c24769" if row.get("blocked") else "#3478f6"
        if row.get("observed") is False:
            color = "#736b87"
        parts.append(f'<path d="M580 217V{y-10}H{x+132}V{y}" stroke="#d3c8eb" stroke-width="1" stroke-dasharray="4 5" fill="none"/><rect x="{x}" y="{y}" width="265" height="116" rx="11" fill="#ffffff" stroke="{color}"/>')
        text(x+12, y+22, _text(row.get("name") or "Sem nome", 29), 14, color, "bold")
        text(x+12, y+43, row.get("ip") or "IP não informado", 13)
        text(x+12, y+63, row.get("mac") or "MAC não informado", 12)
        text(x+12, y+83, "Regra salva; sem observação recente" if row.get("observed") is False else _text(row.get("state", "Observado"), 36), 11, "#736b87")
        text(x+12, y+103, "Protegida" if row.get("protected") else _scope(row, data["mode"]), 11, color)
    if not rows:
        text(24, 286, "Nenhuma máquina presente nesta amostra. O relatório não executa uma varredura adicional.")
    text(24, height-10, f'Desenho: {len(rows)} de {len(data["devices"])} registros; relatório de inventário inclui até 10.000 registros.', 11, "#736b87")
    parts.append('</svg>')
    return "\n".join(parts)


HEADERS = ("Máquina", "IP", "MAC", "Evidência", "Internet / escopos", "Protegida", "Conexão / SSID / AP", "Consultas DNS", "Última evidência")


def _device_values(row, mode=None):
    return (row.get("name") or "Sem nome", row.get("ip", ""), row.get("mac", ""),
            "Regra salva; sem observação recente" if row.get("observed") is False else row.get("state", "Observado"),
            _scope(row, mode), "Sim" if row.get("protected") else "Não", _connection(row), row.get("dns_queries", 0), row.get("last_seen", ""))


def _csv(data):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=";")
    writer.writerow(("Amostra UTC", "Modo", _source_label(data)) + HEADERS)
    for row in data["devices"]:
        writer.writerow([_cell(value) for value in (data["timestamp"], "DEMONSTRAÇÃO" if data["demo"] else data["mode"] + (" / leitura antiga" if data["stale"] else ""),
                         _source_name(data)) + _device_values(row, data["mode"])])
    return output.getvalue()


LIMITS = "Amostra de DHCP e vizinhos de rede; concessão não comprova presença atual. O mapa é lógico e suas ligações são inferidas. Consultas DNS podem vir de serviços automáticos e não comprovam visitas nem mostram conteúdo HTTPS. Wi-Fi precisa passar pelo gateway preservando os endereços dos clientes; NAT e MAC privado podem limitar a identificação. O bloqueio corta internet pelo gateway e não desassocia o aparelho do rádio Wi-Fi."


def _html(data, snapshot):
    def e(value): return escape(_text(value))
    table = "".join("<tr>" + "".join(f"<td>{e(v)}</td>" for v in _device_values(row, data["mode"])) + "</tr>" for row in data["devices"])
    domains = "".join(f"<tr><td>{e(domain)}</td><td>{count}</td></tr>" for domain, count in data["top_domains"])
    rules = "".join(f'<tr><td>{e(row.get("kind"))}</td><td>{e(row.get("address"))}</td></tr>' for row in data["rules"])
    return f'''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>LabGuard — Relatório da rede</title><style>
body{{font:14px/1.5 system-ui,sans-serif;color:#21183f;background:#f5f3fc;margin:0}}main{{max-width:1200px;margin:auto;padding:32px}}h1,h2{{color:#6c42d9}}.banner{{padding:14px;background:#fff0b8;border-radius:10px}}.metrics{{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0}}.metrics div{{background:white;border:1px solid #e5dff3;border-radius:12px;padding:16px;flex:1;min-width:150px}}.metrics strong{{display:block;color:#3478f6;font-size:26px}}table{{border-collapse:collapse;width:100%;background:white;font-size:12px}}td,th{{padding:10px;text-align:left;border:1px solid #e5dff3;overflow-wrap:anywhere}}th{{background:#ede6fc}}.scroll{{overflow:auto}}svg{{width:100%;height:auto}}small{{color:#736b87}}@media print{{body{{background:white}}main{{padding:0}}thead{{display:table-header-group}}tr{{break-inside:avoid}}.scroll{{overflow:visible}}}}
</style></head><body><main><h1>Relatório da rede do laboratório</h1><p class="banner">{e(_mode_notice(data))}</p><p>{e(_source_label(data))}: <strong>{e(_source_name(data))}</strong> · Rede: {e(data['gateway'].get('lab_cidr','Não informada'))}<br>Amostra: {e(data['timestamp'])}<br>Gerado em UTC: {e(data['generated_at'])}</p><div class="metrics"><div>Máquinas observadas<strong>{data['observed']}</strong></div><div>{'Registros com bloqueio informado' if data['mode'] in {'observation', 'equipment'} else 'Registros bloqueados'}<strong>{data['blocked']}</strong></div><div>Consultas na amostra<strong>{data['queries']}</strong></div><div>Registros protegidos<strong>{data['protected']}</strong></div></div><h2>Mapa lógico</h2>{network_map_svg(snapshot)}<h2>Inventário de máquinas</h2><p>{len(data['devices'])} registros exportados de {data['total_received']} recebidos. Limite: 10.000. Cabo/Wi-Fi, SSID e AP ficam como não informados quando a fonte não os fornece.</p><div class="scroll"><table><thead><tr>{''.join(f'<th>{e(h)}</th>' for h in HEADERS)}</tr></thead><tbody>{table or '<tr><td colspan="9">Sem registros nesta amostra.</td></tr>'}</tbody></table></div><h2>Bloqueios diretos por endereço</h2><table><thead><tr><th>Escopo</th><th>Endereço</th></tr></thead><tbody>{rules or '<tr><td colspan="2">Nenhuma regra direta informada. Bloqueios de máquina legados podem existir.</td></tr>'}</tbody></table><h2>Domínios mais solicitados</h2><p>Até 10 domínios da amostra recente, sem inferir visitas.</p><table><thead><tr><th>Domínio</th><th>Consultas</th></tr></thead><tbody>{domains or '<tr><td colspan="2">Sem consultas nesta amostra.</td></tr>'}</tbody></table><h2>Como interpretar</h2><p>{e(_limits(data))}</p><small>O relatório contém informações da rede escolar. Compartilhe somente com a equipe responsável. Arquivo gerado localmente pelo LabGuard.</small></main></body></html>'''


def _pdf(data, snapshot, path):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable, KeepTogether
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import reportlab
    except ImportError as error:
        raise ReportError("Para exportar PDF pelo código-fonte, instale as dependências de requirements.txt. Os instaladores já incluem esse recurso.") from error
    font_regular, font_bold = "Helvetica", "Helvetica-Bold"
    font_dir = Path(reportlab.__file__).parent / "fonts"
    if (font_dir / "Vera.ttf").is_file() and (font_dir / "VeraBd.ttf").is_file():
        if "LabGuardReport" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("LabGuardReport", str(font_dir / "Vera.ttf")))
            pdfmetrics.registerFont(TTFont("LabGuardReportBold", str(font_dir / "VeraBd.ttf")))
        font_regular, font_bold = "LabGuardReport", "LabGuardReportBold"
    styles = getSampleStyleSheet()
    for name in ("Title", "Heading1", "Heading2"):
        styles[name].fontName = font_bold
    styles.add(ParagraphStyle(name="LabSmall", fontName=font_regular, fontSize=7.8, leading=11, wordWrap="CJK"))
    styles["Title"].textColor = colors.HexColor("#6c42d9")
    styles["Heading1"].textColor = colors.HexColor("#3478f6")
    def p(value, style="LabSmall"):
        return Paragraph(escape(_text(value, 1000)), styles[style])
    document = SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=30, leftMargin=30, topMargin=32, bottomMargin=34,
                                 title="LabGuard — Relatório da rede", author="LabGuard")
    width = landscape(A4)[0] - 60
    class Map(Flowable):
        def __init__(self): super().__init__(); self.width=width; self.height=215
        def draw(self):
            canvas=self.canv
            canvas.setStrokeColor(colors.HexColor("#d3c8eb"))
            canvas.setFillColor(colors.HexColor("#6c42d9"))
            canvas.roundRect(width/2-150, 174, 300, 36, 8, fill=1, stroke=0)
            canvas.setFillColor(colors.white);canvas.setFont(font_bold,10)
            canvas.drawCentredString(width/2,187,_text(f'{_source_label(data)}: {_source_name(data)}' if data["mode"] in {"observation", "equipment"} else _source_name(data),45))
            canvas.setStrokeColor(colors.HexColor("#b6a5dd"));canvas.setDash(3,3)
            canvas.line(width/2,174,width/2,51)
            for index,row in enumerate(data["devices"][:12]):
                x=8+(index%4)*(width/4); y=112-(index//4)*54
                canvas.line(width/2,y+47,x+85,y+47);canvas.line(x+85,y+47,x+85,y+42)
            canvas.setDash()
            for index,row in enumerate(data["devices"][:12]):
                x=8+(index%4)*(width/4); y=112-(index//4)*54
                color="#13846b" if row.get("protected") else "#c24769" if row.get("blocked") else "#3478f6"
                canvas.setStrokeColor(colors.HexColor(color))
                canvas.setFillColor(colors.HexColor("#f5f3fc"));canvas.roundRect(x,y,width/4-14,42,5,fill=1,stroke=1)
                canvas.setFillColor(colors.HexColor("#21183f"));canvas.setFont(font_bold,8)
                canvas.drawString(x+6,y+29,_text(row.get("name") or "Sem nome",25))
                canvas.setFont(font_regular,7);canvas.drawString(x+6,y+17,_text(row.get("ip"),25))
                canvas.drawString(x+6,y+6,_text(row.get("mac") or "MAC não informado",25))
    story=[p("Relatório da rede do laboratório","Title"),p(_mode_notice(data),"Heading2"),
           p(f'{_source_label(data)}: {_source_name(data)} | Rede: {data["gateway"].get("lab_cidr","Não informada")}'),
           p(f'Amostra: {data["timestamp"]} | Gerado em UTC: {data["generated_at"]}'), Spacer(1,12),
           p(f'{data["observed"]} observadas | {data["blocked"]} {"bloqueios informados" if data["mode"] in {"observation", "equipment"} else "bloqueadas"} | {data["protected"]} protegidas | {data["queries"]} consultas DNS na amostra',"Heading2"),
           p("Mapa lógico — " + _network_label(data),"Heading1"),Map(),p("Ligações inferidas. Desenho resumido em até 12 máquinas; exporte SVG para o mapa com até 200 nós. O inventário a seguir contém os registros da amostra."),p(_limits(data)),PageBreak(),p("Inventário de máquinas","Heading1"),p(f'{len(data["devices"])} de {data["total_received"]} registros recebidos. Até 10.000 registros. Conexão, SSID e AP não são inferidos.'),Spacer(1,10)]
    widths=[92,74,96,99,88,50,102,36,width-737]
    # Exact sum follows page width; final column holds timestamps with wrapping.
    widths[-1]=width-sum(widths[:-1])
    pdf_headers=HEADERS[:5]+("Proteção",HEADERS[6],"DNS",HEADERS[8])
    rows=[[p(h) for h in pdf_headers]]+[[p(v) for v in _device_values(row, data["mode"])] for row in data["devices"]]
    if len(rows)==1:rows.append([p("Sem registros")]+[p("") for _ in HEADERS[1:]])
    table=Table(rows,colWidths=widths,repeatRows=1,hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#ede6fc")),("VALIGN",(0,0),(-1,-1),"TOP"),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#e5dff3")),("LEFTPADDING",(0,0),(-1,-1),5),("RIGHTPADDING",(0,0),(-1,-1),5),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
    story+=[table,Spacer(1,15),p("Bloqueios diretos por endereço","Heading1")]
    for row in data["rules"]:story.append(p(f'{row.get("kind","")} — {row.get("address","")}'))
    if not data["rules"]:story.append(p("Nenhuma regra direta informada; bloqueios legados de máquina podem existir."))
    domain_section=[p("Domínios mais solicitados — amostra recente","Heading1")]
    for domain,count in data["top_domains"]:domain_section.append(p(f"{domain}: {count} consultas"))
    if not data["top_domains"]:domain_section.append(p("Sem consultas nesta amostra."))
    story+=[Spacer(1,12),KeepTogether(domain_section)]
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont(font_regular,8);canvas.setFillColor(colors.HexColor("#736b87"))
        canvas.drawString(30,18,"LabGuard | Demonstração — dados fictícios" if data["demo"] else "LabGuard | Observação parcial local; bloqueios indisponíveis" if data["mode"] == "observation" else "LabGuard | Relatório da rede escolar")
        canvas.drawRightString(landscape(A4)[0]-30,18,f"Página {doc.page}");canvas.restoreState()
    document.build(story,onFirstPage=footer,onLaterPages=footer)


def export_report(snapshot, path, format="html"):
    if format not in {"html","csv","pdf","svg"}:
        raise ReportError("Formato de relatório inválido.")
    target=Path(path).expanduser().absolute()
    data=report_data(snapshot)
    temporary=None
    try:
        descriptor,temporary=tempfile.mkstemp(prefix=".labguard-report-",suffix="."+format,dir=target.parent)
        os.close(descriptor)
        if format=="pdf": _pdf(data,snapshot,temporary)
        else:
            content=network_map_svg(snapshot) if format=="svg" else _csv(data) if format=="csv" else _html(data,snapshot)
            Path(temporary).write_text(content,encoding="utf-8-sig" if format=="csv" else "utf-8",newline="")
        os.replace(temporary,target)
        return str(target)
    except (OSError,ValueError) as error:
        raise ReportError("Não foi possível salvar o relatório no local escolhido.") from error
    finally:
        if temporary and Path(temporary).exists():Path(temporary).unlink()
