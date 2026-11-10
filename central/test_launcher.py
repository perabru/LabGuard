"""Regressions for cooperative shutdown of the actual HTTP/TLS server process."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

# The executable launcher resolves its sibling backend as a top-level module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from central import labguard_tecnico as launcher
from central.labguard_central import initialize


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LifecycleFilesTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name)
        # These tests exercise nonce ownership. Installation ACLs are tested by
        # the elevated Windows integration gate, not by this temporary folder.
        helper = patch.object(launcher, "windows_helpers", return_value=(None, None, lambda _path: None))
        helper.start()
        self.addCleanup(helper.stop)
        self.a = {"instance": "a" * 32, "pid": 1234}
        self.b = {"instance": "b" * 32, "pid": 5678}

    def test_delayed_old_request_cannot_overwrite_new_instance_request(self):
        launcher._request_instance_stop(self.path, self.b)
        launcher._request_instance_stop(self.path, self.a)
        self.assertNotEqual(launcher._stop_request_path(self.path, self.a), launcher._stop_request_path(self.path, self.b))
        self.assertTrue(launcher._instance_stop_requested(self.path, self.a))
        self.assertTrue(launcher._instance_stop_requested(self.path, self.b))
        self.assertEqual(launcher._lifecycle_record(launcher._stop_request_path(self.path, self.b)), self.b)

    def test_cleanup_preserves_other_instance_marker_and_its_request(self):
        launcher._write_lifecycle_record(self.path / launcher.INSTANCE_FILE, self.b)
        launcher._request_instance_stop(self.path, self.a)
        launcher._request_instance_stop(self.path, self.b)
        launcher._remove_instance_records(self.path, self.a)
        self.assertEqual(launcher._lifecycle_record(self.path / launcher.INSTANCE_FILE), self.b)
        self.assertTrue(launcher._instance_stop_requested(self.path, self.b))
        self.assertFalse(launcher._stop_request_path(self.path, self.a).exists())

    def test_task_ready_is_not_shutdown_until_both_listeners_are_closed(self):
        launcher._write_lifecycle_record(self.path / launcher.INSTANCE_FILE, self.a)
        with patch.object(launcher, "owned_task", return_value=True), \
             patch.object(launcher, "read_config", return_value={}), \
             patch.object(launcher, "_task_details", return_value={"state": 3}), \
             patch.object(launcher, "_listeners_closed", side_effect=[False, False, True]) as listeners, \
             patch.object(launcher, "_request_instance_stop") as request, \
             patch.object(launcher.time, "sleep"):
            launcher._stop_owned_task(self.path)
        self.assertEqual(listeners.call_count, 3)
        request.assert_called_once_with(self.path, self.a)

    def test_missing_task_still_stops_its_orphaned_application(self):
        launcher._write_lifecycle_record(self.path / launcher.INSTANCE_FILE, self.a)
        with patch.object(launcher, "owned_task", return_value=False), \
             patch.object(launcher, "read_config", return_value={}), \
             patch.object(launcher, "_task_details", return_value=None), \
             patch.object(launcher, "_listeners_closed", side_effect=[False, True]) as listeners, \
             patch.object(launcher, "_request_instance_stop") as request, \
             patch.object(launcher.time, "sleep"):
            launcher._stop_owned_task(self.path)
        self.assertEqual(listeners.call_count, 2)
        request.assert_called_once_with(self.path, self.a)


@unittest.skipIf(os.name == "nt", "Windows EXE lifecycle is exercised by central/smoke_windows.py")
class ActualServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "central"
        self.panel_port, self.agent_port = free_port(), free_port()
        while self.panel_port == self.agent_port:
            self.agent_port = free_port()
        initialize(self.path, "Test-only-long-password", "127.0.0.1", "127.0.0.0/8",
                   self.agent_port, self.panel_port)
        self.config = launcher.read_config(self.path)
        self.processes = []
        self.addCleanup(self.stop_test_processes)

    def stop_test_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()  # Only the process created by this test.
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    def start_server(self):
        source = Path(launcher.__file__).resolve()
        process = subprocess.Popen([sys.executable, str(source), "run", "--directory", str(self.path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail("Server exited before startup: " + stderr.decode(errors="replace")[-1500:])
            record = launcher._lifecycle_record(self.path / launcher.INSTANCE_FILE)
            if record and record["pid"] == process.pid and launcher.is_ready(self.path):
                return process, record
            time.sleep(.05)
        self.fail("Server did not publish an instance and open HTTP in time.")

    def assert_tls_running(self):
        context = ssl.create_default_context(cafile=str(self.path / "server-cert.pem"))
        connection = http.client.HTTPSConnection("127.0.0.1", self.agent_port, context=context, timeout=3)
        try:
            connection.request("POST", "/api/agent/enroll", json.dumps({"enrollment_token": "x" * 32,
                "name": "lifecycle-test", "client_version": "1.2.0"}), {"Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 401)  # TLS reached the genuine enrollment endpoint.
        finally:
            connection.close()

    def test_real_shutdown_closes_http_and_tls_and_old_nonce_does_not_stop_restart(self):
        first, a = self.start_server()
        self.assert_tls_running()
        launcher._request_instance_stop(self.path, a)
        self.assertEqual(first.wait(timeout=10), 0)
        self.assertTrue(launcher._listeners_closed(self.config))
        self.assertFalse((self.path / launcher.INSTANCE_FILE).exists())
        self.assertFalse(launcher._stop_request_path(self.path, a).exists())
        # A delayed request for an earlier boot must remain ineffective for B.
        launcher._request_instance_stop(self.path, a)
        # This POSIX source test uses fresh ports to avoid Linux TIME_WAIT bind
        # semantics. The shipped Windows EXE is exercised by the real CI gate.
        self.panel_port, self.agent_port = free_port(), free_port()
        while self.panel_port == self.agent_port:
            self.agent_port = free_port()
        self.config.update(panel_port=self.panel_port, agent_port=self.agent_port)
        (self.path / "config.json").write_text(json.dumps(self.config), encoding="utf-8")
        second, b = self.start_server()
        self.assertNotEqual(a["instance"], b["instance"])
        time.sleep(.8)  # More than one 0.5s cooperative stop observation cycle.
        self.assertIsNone(second.poll())
        self.assertTrue(launcher.is_ready(self.path))
        self.assert_tls_running()
        launcher._request_instance_stop(self.path, b)
        self.assertEqual(second.wait(timeout=10), 0)
        self.assertTrue(launcher._listeners_closed(self.config))
        self.assertFalse((self.path / launcher.INSTANCE_FILE).exists())
        self.assertFalse(launcher._stop_request_path(self.path, b).exists())
        self.assertTrue(launcher._stop_request_path(self.path, a).exists())


if __name__ == "__main__":
    unittest.main()
