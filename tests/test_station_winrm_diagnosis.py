"""Diagnostics through the same WinRM operation used by the station DNS test."""
import errno
import socket
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from labguard.remote import WindowsSession, WinRMConnectionError


class WinRMFailureTests(unittest.TestCase):
    def failure(self, cause):
        session = WindowsSession.__new__(WindowsSession)
        session._closed = False
        session._protocol = Mock()
        session._protocol.open_shell.side_effect = cause
        with self.assertRaises(WinRMConnectionError) as result:
            session._ps("throw 'sensitive-input'")
        error = result.exception
        self.assertNotIn("sensitive-input", str(error))
        self.assertEqual(str(error), error.public_message)
        return error.code

    def test_nested_socket_causes_and_windows_codes(self):
        for nested, expected in (
            (ConnectionRefusedError(errno.ECONNREFUSED, "sensitive-input"), "refused"),
            (OSError(10061, "sensitive-input"), "refused"),
            (socket.gaierror(-2, "sensitive-input"), "unreachable"),
            (OSError(10065, "sensitive-input"), "unreachable"),
            (OSError(10060, "sensitive-input"), "network_timeout"),
            (socket.timeout("sensitive-input"), "network_timeout"),
            (ConnectionResetError("sensitive-input"), "interrupted"),
        ):
            with self.subTest(expected=expected, error=nested):
                retry = RuntimeError("sensitive-input")
                retry.reason = nested
                self.assertEqual(self.failure(RuntimeError(retry)), expected)

    def test_certificate_reasons_inside_tls_and_retry_wrappers(self):
        for verify_code, category in ((62, "certificate_name"), (64, "certificate_name"),
                                      (9, "certificate_time"), (10, "certificate_time"),
                                      (20, "certificate_trust")):
            with self.subTest(verify_code=verify_code):
                cert = ssl.SSLCertVerificationError(1, "sensitive-input")
                cert.verify_code = verify_code
                tls = ssl.SSLError(1, "sensitive-input")
                tls.__context__ = cert
                self.assertEqual(self.failure(RuntimeError(tls)), category)
        self.assertEqual(self.failure(ssl.SSLError(1, "sensitive-input")), "tls")

    def test_http_errors_are_distinguished_without_showing_server_text(self):
        for code, category in ((401, "authentication"), (403, "permission"), (404, "endpoint"),
                               (405, "endpoint"), (500, "unknown")):
            exc = RuntimeError("sensitive-input")
            exc.response = SimpleNamespace(status_code=code)
            with self.subTest(code=code):
                self.assertEqual(self.failure(exc), category)

    def test_pywinrm_fault_retains_permission_despite_http_500(self):
        try:
            from winrm.exceptions import WSManFaultError
        except ImportError:
            self.skipTest("pywinrm opcional")
        for details in ({"wsman_fault_code": 5}, {"wsman_fault_code": 0x80070005},
                        {"wmierror_code": 0x80041003}, {"fault_subcode": "w:AccessDenied"}):
            exc = WSManFaultError(500, "sensitive-input", "sensitive-input", "sensitive-input", **details)
            with self.subTest(details=details):
                self.assertEqual(self.failure(exc), "permission")

    def test_distinguishes_connect_and_read_timeouts(self):
        try:
            from requests.exceptions import ConnectTimeout, ReadTimeout
        except ImportError:
            self.skipTest("requests opcional")
        self.assertEqual(self.failure(ConnectTimeout("sensitive-input")), "network_timeout")
        exc = ReadTimeout("sensitive-input")
        exc.__cause__ = TimeoutError("sensitive-input")
        self.assertEqual(self.failure(exc), "read_timeout")

    def test_unknown_or_cyclic_error_does_not_leak_arguments(self):
        cause = RuntimeError("sensitive-input")
        cause.__cause__ = cause
        self.assertEqual(self.failure(cause), "unknown")
        self.assertEqual(WinRMConnectionError("sensitive-input").code, "unknown")
