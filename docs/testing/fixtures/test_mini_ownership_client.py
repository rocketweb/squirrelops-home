"""Pin the live client to the replacement package and preserve failure exits."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import runpy
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("ownership_client", Path(__file__).with_name("mini_ownership_client.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OwnershipClient(unittest.TestCase):
    def test_only_new_package_readiness_is_accepted(self):
        now = 1790709500
        endpoints = {'guest_ip': '192.168.1.240', 'mappings': [
            {'ip': '192.168.1.240', 'port': port, 'backend': 50000 + i}
            for i, port in enumerate((22, 445, 1234, 11434, 8765))]}
        login = {'ip': '192.168.1.240', 'username': 'buildbot', 'password': 'Juniper!123456'}
        status = {'phase': 'ready_for_tests', 'sensor_uid': 309, 'remaining_seconds': 1100,
                  'package_sha256': module.client.PACKAGE_SHA,
                  'time': datetime.fromtimestamp(now, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
        self.assertEqual(module.client.validate_inputs(endpoints, login, status, now), '192.168.1.240')
        status['package_sha256'] = '541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1'
        with self.assertRaisesRegex(RuntimeError, 'not ready'):
            module.client.validate_inputs(endpoints, login, status, now)

    def test_failure_exit_is_propagated(self):
        fake = MagicMock()
        fake.main.return_value = 1
        with patch.object(importlib.util, 'spec_from_file_location', return_value=MagicMock()), \
                patch.object(importlib.util, 'module_from_spec', return_value=fake), self.assertRaises(SystemExit) as stopped:
            runpy.run_path(module.__file__, run_name='__main__')
        self.assertEqual(stopped.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
