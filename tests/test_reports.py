import copy
import csv
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from labguard.demo import DemoTransport
from labguard.reports import ReportError, export_report, network_map_svg, report_data


class ReportsTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = DemoTransport().request("snapshot")

    def test_svg_and_html_escape_untrusted_network_names(self):
        self.snapshot["devices"][0]["name"] = '<script>alert("network")</script>'
        self.snapshot["gateway"]["hostname"] = '<svg onload="attack()">'
        svg = network_map_svg(self.snapshot)
        ElementTree.fromstring(svg)
        self.assertNotIn("<script>", svg)
        self.assertNotIn('<svg onload=', svg)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report.html"
            export_report(self.snapshot,path,"html")
            html=path.read_text(encoding="utf-8")
            self.assertNotIn("<script>",html)
            self.assertIn("Content-Security-Policy",html)
            self.assertIn("Ligações inferidas",html)
            self.assertIn("DEMONSTRAÇÃO",html)

    def test_csv_neutralizes_formulas_and_contains_every_inventory_record(self):
        self.snapshot["devices"][0]["name"] = "  =HYPERLINK(attack)"
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report.csv"
            export_report(self.snapshot,path,"csv")
            rows=list(csv.reader(io.StringIO(path.read_text(encoding="utf-8-sig")),delimiter=";"))
            self.assertEqual(len(rows),len(self.snapshot["devices"])+1)
            self.assertEqual(rows[1][3],"'  =HYPERLINK(attack)")
            self.assertTrue(all(len(row)==len(rows[0]) for row in rows))
            self.assertIn(self.snapshot["devices"][0]["mac"],rows[1])

    def test_svg_bound_is_explicit_and_report_preserves_full_inventory(self):
        self.snapshot["devices"]=[dict(self.snapshot["devices"][0],name=f"LAB-{index}") for index in range(205)]
        svg=network_map_svg(self.snapshot)
        self.assertIn("200 de 205",svg)
        self.assertEqual(len(report_data(self.snapshot)["devices"]),205)
        self.assertNotIn("LAB-204",svg)

    def test_report_does_not_change_snapshot_or_infer_wireless_origin(self):
        original=copy.deepcopy(self.snapshot)
        data=report_data(self.snapshot)
        self.assertEqual(self.snapshot,original)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report.csv"
            export_report(self.snapshot,path,"csv")
            self.assertIn("Não informado",path.read_text(encoding="utf-8-sig"))
        self.assertEqual(data["observed"],len(original["devices"]))

    def test_observation_reports_are_partial_without_claiming_gateway_or_free_internet(self):
        self.snapshot.update(mode="observation", gateway={}, address_blocks=[])
        self.snapshot["devices"] = [{"name": "LOCAL", "ip": "192.168.50.1", "blocked": False}]
        svg = network_map_svg(self.snapshot)
        ElementTree.fromstring(svg)
        self.assertIn("Observação parcial local", svg)
        self.assertIn("nenhum bloqueio real aplicado", svg)
        self.assertIn("Fonte: Observação local", svg)
        self.assertIn("Bloqueio não verificado", svg)
        self.assertNotIn("LAN / Wi-Fi pelo gateway", svg)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"observation.html"
            export_report(self.snapshot, path, "html")
            html = path.read_text(encoding="utf-8")
            self.assertIn("Fonte:", html)
            self.assertIn("bloqueios indisponíveis", html)
            self.assertIn("não aplica bloqueios reais", html)
            self.assertNotIn("<td>Livre</td>", html)
            self.assertNotIn("Wi-Fi pelo gateway", html)

    def test_direct_equipment_reports_identify_router_without_requiring_extra_gateway(self):
        self.snapshot.update(mode="equipment", gateway={"hostname": "ROUTER-01"})
        svg = network_map_svg(self.snapshot)
        self.assertIn("Roteador: ROUTER-01", svg)
        self.assertIn("LAN / Wi-Fi pelo roteador", svg)
        self.assertNotIn("LAN / Wi-Fi pelo gateway", svg)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"router.html"
            export_report(self.snapshot, path, "html")
            html = path.read_text(encoding="utf-8")
            self.assertIn("Roteador:", html)
            self.assertIn("capacidades confirmadas", html)
            self.assertNotIn("Wi-Fi precisa passar pelo gateway", html)

    def test_failed_export_preserves_existing_file_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report.pdf";path.write_text("existing")
            with patch("labguard.reports._pdf",side_effect=ReportError("Unavailable")):
                with self.assertRaises(ReportError):export_report(self.snapshot,path,"pdf")
            self.assertEqual(path.read_text(encoding="utf-8"),"existing")
            self.assertEqual(list(Path(directory).iterdir()),[path])

    def test_invalid_format_and_malformed_snapshot_are_rejected(self):
        with self.assertRaises(ReportError):export_report(self.snapshot,"report.exe","exe")
        with self.assertRaises(ReportError):report_data({"devices":None})
        with self.assertRaises(ReportError):report_data(None)

    @unittest.skipUnless(importlib.util.find_spec("reportlab"),"PDF dependency optional for source tests")
    def test_pdf_export_is_paginated_and_has_valid_document_header(self):
        self.snapshot["devices"]=[dict(self.snapshot["devices"][0],name=f"LAB-{index}") for index in range(70)]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"report.pdf"
            export_report(self.snapshot,path,"pdf")
            payload=path.read_bytes()
            self.assertTrue(payload.startswith(b"%PDF-"))
            self.assertGreaterEqual(payload.count(b"/Type /Page\n"),2)


if __name__=="__main__":unittest.main()
