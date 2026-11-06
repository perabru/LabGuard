import copy
import json
import unittest
from unittest.mock import patch

from labguard.diagnostics import CASE_LABELS, build_diagnostic_plan, classify_connection_error


class DiagnosticPlanTests(unittest.TestCase):
    def test_private_ip_gateway_lists_are_deduplicated_and_local_mac_is_not_missing(self):
        data = {"mode": "observation", "interfaces": [{"ipv4": ["192.168.1.10", "192.168.1.10/24"]}],
            "gateway": {"ip": ["192.168.1.1", "192.168.1.1"]}, "devices": [
                {"ip": "192.168.1.10", "mac": "", "state": "Endereço local"},
                {"ip": "192.168.1.20", "mac": "02:00:00:00:00:20"},
                {"ip": "192.168.1.20", "mac": "02:00:00:00:00:20"},
                {"ip": "192.168.1.99", "mac": "", "observed": False}]}
        plan = build_diagnostic_plan(data, system="Linux")
        self.assertEqual(plan["facts"]["local_ipv4_count"], 1)
        self.assertEqual(plan["facts"]["gateway_count"], 1)
        self.assertEqual(plan["facts"]["observed_neighbors"], 1)
        self.assertEqual(plan["facts"]["known_macs"], 1)
        self.assertNotIn("missing_mac", plan["cases"])
        self.assertNotIn("no_local_ip", plan["cases"])
        self.assertNotIn("no_gateway", plan["cases"])

    def test_public_ipv6_and_link_local_are_explained_not_treated_as_private_ipv4(self):
        data = {"mode": "observation", "interfaces": [{"ipv4": ["8.8.8.8", "169.254.1.2", "2001:db8::1"]}], "devices": []}
        plan = build_diagnostic_plan(data, system="Windows")
        self.assertIn("no_local_ip", plan["cases"])
        text = json.dumps(plan, ensure_ascii=False)
        self.assertIn("Isso não prova", text.replace("isso não prova", "Isso não prova"))
        self.assertIn("IPv6", text)
        self.assertIn("ipconfig /all", text)

    def test_only_a_remote_missing_mac_adds_that_case(self):
        data = {"mode": "observation", "devices": [{"ip": "192.168.1.20", "mac": ["invalid"]}]}
        self.assertIn("missing_mac", build_diagnostic_plan(data)["cases"])

    def test_equipment_without_local_interfaces_does_not_imply_no_local_ip_or_gateway(self):
        data = {"mode": "equipment", "gateway": {"vendor": "MikroTik", "model": "hAP"}, "devices": []}
        cases = build_diagnostic_plan(data)["cases"]
        self.assertNotIn("no_local_ip", cases); self.assertNotIn("no_gateway", cases)
        self.assertNotIn("unknown_model", cases)

    def test_operator_name_never_implies_model_or_control(self):
        data = {"mode": "observation", "gateway": {"vendor": "Vivo", "model": None}, "capabilities": {"address_blocking": False}}
        original = copy.deepcopy(data)
        plan = build_diagnostic_plan(data, case="unknown_model")
        self.assertEqual(plan["cases"], ["unknown_model"])
        self.assertEqual(data, original)
        self.assertNotIn("capabilities", plan)

    def test_real_generic_rest_error_is_not_a_certificate_diagnosis(self):
        message = "Não foi possível confirmar a resposta REST HTTPS. Verifique endereço, certificado e conexão."
        self.assertEqual(classify_connection_error(message), "connection_error")
        self.assertEqual(build_diagnostic_plan({"mode": "equipment"}, message)["cases"][0], "connection_error")

    def test_error_categories_include_real_timeout_messages(self):
        for message, expected in (("HTTP 401", "authentication"), ("HTTP 403", "authentication"),
            ("SSL: CERTIFICATE_VERIFY_FAILED", "tls"), ("HTTP 404 /rest", "api_unavailable"),
            ("Tempo total de consulta ao roteador esgotado.", "timeout"),
            ("O gateway não respondeu a tempo. Confira a rede.", "timeout"), ("Algo falhou", "connection_error")):
            with self.subTest(message=message):self.assertEqual(classify_connection_error(message), expected)

    def test_secrets_and_arbitrary_network_text_never_enter_help(self):
        secrets = ["UNIQUE-PASSWORD-123", "UNIQUE-TOKEN-456", "UNIQUE-PRIVATE-KEY-789", "PRIVATE-STUDENT-NAME"]
        data = {"mode": "equipment", "password": secrets[0], "token": secrets[1], "key": secrets[2],
            "gateway": {"hostname": secrets[3], "vendor": secrets[0], "model": secrets[1]},
            "devices": [{"name": secrets[3], "ip": "192.168.1.20", "mac": ""}], "warnings": secrets}
        plan = build_diagnostic_plan(data, f"401 https://admin:{secrets[0]}@router/rest?token={secrets[1]} {secrets[2]}")
        rendered = json.dumps(plan, ensure_ascii=False)
        for secret in secrets:self.assertNotIn(secret, rendered)

    def test_help_commands_are_whitelisted_and_nothing_is_executed(self):
        allowed = {"ipconfig /all", "route print -4", "arp -a", "ip -4 addr", "ip -4 route", "ip -4 neigh"}
        with patch("subprocess.Popen", side_effect=AssertionError("Execução inesperada")):
            for system in ("Windows", "Linux", "Other"):
                for case in CASE_LABELS:
                    plan = build_diagnostic_plan({}, system=system, case=case)
                    self.assertTrue(all(command in allowed for step in plan["steps"] for command in step["commands"]))

    def test_legacy_plan_explains_why_retry_is_disabled(self):
        plan = build_diagnostic_plan({"mode": "gateway"}, system="Linux")
        finish = " ".join(plan["steps"][-1]["instructions"])
        self.assertIn("desabilitado", finish); self.assertIn("reconciliar", finish)

    def test_terminal_instructions_and_demo_are_explicit(self):
        windows = json.dumps(build_diagnostic_plan({"mode": "demo"}, system="Windows"), ensure_ascii=False)
        linux = json.dumps(build_diagnostic_plan({}, system="Linux"), ensure_ascii=False)
        self.assertIn("Win+R", windows); self.assertIn("cmd", windows)
        self.assertIn("dados são fictícios", windows); self.assertIn("não troca o modo", windows)
        self.assertIn("Terminal pelo menu", linux)

    def test_incomplete_or_malformed_snapshot_still_has_a_bounded_plan(self):
        for data in (None, [], {"mode": []}, {"mode": {}, "gateway": [], "interfaces": {}, "devices": [None]}):
            plan = build_diagnostic_plan(data, system={}, case={})
            self.assertGreaterEqual(len(plan["steps"]), 2)
            self.assertLessEqual(len(plan["steps"]), 12)
            self.assertEqual(plan["steps"][0]["id"], "start")
            self.assertEqual(plan["steps"][-1]["id"], "finish")


if __name__ == "__main__":unittest.main()
