from concurrent.futures import ThreadPoolExecutor
import errno
import socket
from threading import Event
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from labguard.station_connectivity import check_winrm_port
from labguard.station_dns_gui import StationDNSWindow, WINDOWS


HOST = "192.168.15.105"


class PortTests(unittest.TestCase):
    def test_connect_only_to_fixed_port_then_close_without_sending_data(self):
        connection = MagicMock()
        with patch("socket.create_connection", return_value=connection) as connect:
            result = check_winrm_port(HOST)
        connect.assert_called_once_with((HOST, 5986), timeout=4)
        connection.__exit__.assert_called_once()
        connection.sendall.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertEqual(result["code"], "open")

    def test_only_fixed_messages_for_network_errors(self):
        for error, code in ((ConnectionRefusedError(errno.ECONNREFUSED, "secret"), "refused"),
                            (socket.timeout("secret"), "timeout"),
                            (OSError(errno.EHOSTUNREACH, "secret"), "unreachable"),
                            (OSError(errno.EACCES, "secret"), "error")):
            with self.subTest(code=code), patch("socket.create_connection", side_effect=error):
                result = check_winrm_port(HOST)
                self.assertFalse(result["ok"])
                self.assertEqual(result["code"], code)
                self.assertIn(HOST + ":5986", result["message"])
                self.assertNotIn("secret", result["message"])


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.window = w = StationDNSWindow.__new__(StationDNSWindow)
        w._session = w._api = w._future = w._preview = w._bound = None
        w._closed = False
        w._worker = ThreadPoolExecutor(1)
        self.addCleanup(w._worker.shutdown)
        w.transport = SimpleNamespace(kind="local_dns")
        w.owner = SimpleNamespace(_closed=False, _management_authorized=True, _snapshot_stale=False,
                                  _last_snapshot_monotonic=monotonic(), transport=w.transport, snapshot={
                                      "source_type": "local_dns", "mode": "equipment",
                                      "dns_service": {"listen": "192.168.15.10", "network": "192.168.15.0/24",
                                                      "port": 53, "service_running": True,
                                                      "check_token": "LabGuard-0000000000000001"},
                                      "local": {"default_gateway": "192.168.15.1"}})
        for name in ("_buttons", "platform", "target", "user", "secret", "username", "password",
                     "direct", "default", "blocked", "detail", "status", "port_status", "_session_args"):
            setattr(w, name, Mock())
        w.platform.get.return_value = WINDOWS
        w.target.get.return_value = HOST
        w.user.get.return_value = "Alunos"
        w.secret.get.return_value = ""

    def test_port_background_check_never_uses_credentials_or_marks_dns(self):
        started, release = Event(), Event()
        def connect(address):
            self.assertEqual(address, HOST)
            started.set()
            self.assertTrue(release.wait(timeout=2))
            return {"ok": True, "message": "Porta acessível"}
        w = self.window
        with patch("labguard.station_dns_gui.check_winrm_port", side_effect=connect), \
                patch("labguard.station_dns_gui.create_session") as login:
            w.check_port()
            self.assertTrue(started.wait(timeout=2))
            self.assertFalse(w._future.done())
            release.set()
            w._future.result(timeout=2)
            w._finish()
            login.assert_not_called()
        w.port_status.set.assert_called_with("Porta acessível")
        w._session_args.assert_not_called()
        w.secret.set.assert_not_called()
        self.assertIsNone(w._session)
        self.assertIsNone(w._bound)
        for label in (w.direct, w.default, w.blocked):
            label.set.assert_not_called()

    def test_preflight_rejects_gateway_before_connect(self):
        w = self.window
        w.target.get.return_value = "192.168.15.1"
        with patch("labguard.station_dns_gui.check_winrm_port") as connect:
            w.check_port()
        connect.assert_not_called()
        self.assertIn("protegido", w.status.set.call_args.args[0])

    def test_changing_target_discards_pending_password_and_previous_evidence(self):
        w = self.window
        w._reset_results()
        w.secret.set.assert_called_once_with("")
        for label in (w.direct, w.default, w.blocked):
            label.set.assert_called_once_with("Aguardando teste")

    def test_blank_password_does_not_send_request_or_display_dns_in_progress(self):
        w = self.window
        with patch("labguard.station_dns_gui.create_session") as login:
            w.test()
        login.assert_not_called()
        self.assertIsNone(w._future)
        w._session_args.assert_not_called()
        w.password.focus_set.assert_called_once()
        w.direct.set.assert_not_called()
        self.assertIn("senha", w.status.set.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
