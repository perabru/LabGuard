"""Exercise the WinRM HTTPS client against loopback, without a Windows account."""
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.util import find_spec
from ipaddress import ip_address
from pathlib import Path
import os
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from labguard import remote


class DenyRequest(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.request_paths.append(self.path)
        self.send_response(self.server.response_code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@unittest.skipUnless(find_spec("winrm"), "pywinrm opcional ausente")
class WinRMWireTests(unittest.TestCase):
    def setUp(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        now = datetime.datetime.now(datetime.timezone.utc)
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LabGuard Test CA")])
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - datetime.timedelta(days=1))
              .not_valid_after(now + datetime.timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .sign(ca_key, hashes.SHA256()))
        self.ca_path = self.directory / "ca.pem"
        self.ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "station.test")]))
                .issuer_name(issuer).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]),
                               critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        cert_path = self.directory / "station.pem"
        key_path = self.directory / "station-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        self.server = HTTPServer(("127.0.0.1", 0), DenyRequest)
        self.addCleanup(self.server.server_close)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.server.request_paths = []
        self.server.response_code = 401
        worker = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                                  daemon=True)
        worker.start()
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.server.shutdown)

    def assert_failure(self, expected, *, ca_path=None, host="127.0.0.1", port=None):
        session = remote.WindowsSession("127.0.0.1", "SCHOOL\\wire-test", "wire-test-secret",
                                        ca_file=str(ca_path) if ca_path else "")
        self.addCleanup(session.close)
        # A free port avoids conflicting with an actual WinRM listener on a Windows runner.
        port = self.server.server_port if port is None else port
        session._protocol.transport.endpoint = f"https://{host}:{port}/wsman"
        with self.assertRaises(remote.WinRMConnectionError) as caught:
            session._ps("exit 0")
        self.assertEqual(caught.exception.code, expected)
        self.assertNotIn("wire-test", caught.exception.public_message)

    def test_trust_failure_prevents_http(self):
        self.assert_failure("certificate_trust")
        self.assertEqual(self.server.request_paths, [])

    def test_hostname_mismatch_with_trusted_ca_prevents_http(self):
        self.assert_failure("certificate_name", host="localhost", ca_path=self.ca_path)
        self.assertEqual(self.server.request_paths, [])

    def test_trusted_ip_reaches_authentication_and_permission_checks(self):
        for status, code in ((401, "authentication"), (403, "permission")):
            with self.subTest(status=status):
                self.server.response_code = status
                self.server.request_paths.clear()
                self.assert_failure(code, ca_path=self.ca_path)
                self.assertEqual(self.server.request_paths, ["/wsman"])

    def test_ti_environment_proxy_does_not_intercept_winrm(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            proxy = f"http://127.0.0.1:{reserved.getsockname()[1]}"
            with patch.dict(os.environ, {"https_proxy": proxy, "HTTPS_PROXY": proxy,
                                         "no_proxy": "", "NO_PROXY": ""}):
                self.assert_failure("authentication", ca_path=self.ca_path)
            self.assertEqual(self.server.request_paths, ["/wsman"])

    def test_tcp_refusal_precedes_certificate_and_authentication(self):
        # A bound, non-listening socket reserves the port until the request returns.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            self.assert_failure("refused", port=reserved.getsockname()[1])
