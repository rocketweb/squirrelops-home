"""No real network or credentials: validate bounded one-shot client inputs."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("mini_upgrade_client", Path(__file__).with_name("mini_upgrade_client.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ClientGuards(unittest.TestCase):
    def inputs(self):
        now = 1790709500
        endpoints = {"guest_ip": "192.168.1.240", "mappings": [
            {"ip": "192.168.1.240", "port": port, "backend": 50000 + i}
            for i, port in enumerate((22, 445, 1234, 11434, 8765))]}
        login = {"ip": "192.168.1.240", "username": "buildbot", "password": "Juniper!123456"}
        status = {"phase": "ready_for_tests", "sensor_uid": 309, "package_sha256": module.PACKAGE_SHA,
                  "time": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "remaining_seconds": 1100}
        return endpoints, login, status, now

    def test_valid_live_inventory(self):
        self.assertEqual(module.validate_inputs(*self.inputs()), "192.168.1.240")

    def test_wrong_guest_or_credential_is_rejected(self):
        for key, value in (("ip", "192.168.1.115"), ("username", "matt"), ("password", "real-credential")):
            endpoints, login, status, now = self.inputs()
            login[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                module.validate_inputs(endpoints, login, status, now)

    def test_stopped_stale_wrong_package_and_insufficient_deadline_fail_closed(self):
        for key, value in (("phase", "stopped"), ("package_sha256", "old"), ("sensor_uid", 0),
                           ("remaining_seconds", 599), ("time", "2026-01-01T00:00:00Z")):
            endpoints, login, status, now = self.inputs()
            status[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                module.validate_inputs(endpoints, login, status, now)

    def test_invalid_or_duplicate_backend_is_rejected(self):
        for value in (22, 65536, True, "50000"):
            endpoints, login, status, now = self.inputs()
            endpoints["mappings"][0]["backend"] = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                module.validate_inputs(endpoints, login, status, now)
        endpoints, login, status, now = self.inputs()
        endpoints["mappings"].append(endpoints["mappings"][0])
        with self.assertRaises(RuntimeError):
            module.validate_inputs(endpoints, login, status, now)

    def test_banner_read_timeout_keeps_tcp_success_separate(self):
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.recv.side_effect = TimeoutError()
        with patch.object(module.socket, "create_connection", return_value=stream):
            result = module.banner_probe("192.168.1.240")
        self.assertTrue(result["connected"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["stage"], "banner")

    def test_protocol_banner_is_required(self):
        for data, valid in ((b"SSH-2.0-OpenSSH_10\r\n", True), (b"HTTP/1.1 200\r\n", False), (b"", False)):
            stream = MagicMock()
            stream.__enter__.return_value = stream
            stream.recv.return_value = data
            with patch.object(module.socket, "create_connection", return_value=stream):
                self.assertEqual(module.banner_probe("192.168.1.240")["passed"], valid)

    def test_http_requires_service_specific_payload_not_just_json(self):
        for port, body in ((1234, {"data": [{"id": "synthetic"}]}),
                           (11434, {"models": [{"name": "synthetic"}]}),
                           (8765, {"id": 1, "result": {"tools": [{"name": "synthetic"}]}})):
            self.assertTrue(module.http_payload_ok(port, body))
            for invalid in (None, {}, {"error": "unavailable"}, []):
                self.assertFalse(module.http_payload_ok(port, invalid))

    def test_plan_default_has_no_network(self):
        result = subprocess.run([sys.executable, module.__file__], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PLAN ONLY", result.stdout)


if __name__ == "__main__":
    unittest.main()
