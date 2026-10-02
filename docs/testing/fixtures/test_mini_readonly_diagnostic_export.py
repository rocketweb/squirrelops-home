"""Synthetic parser and export checks. Never contacts or modifies a live host."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('readonly_export', Path(__file__).with_name('mini_readonly_diagnostic_export.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ExportTests(unittest.TestCase):
    def test_packet_direction_bytes_and_retransmits(self):
        lines = [
            '2026-09-30 12:19:00.001 IP 192.168.1.7.40000 > 192.168.1.240.22: tcp 0',
            '2026-09-30 12:19:01.002 IP 192.168.1.240.22 > 192.168.1.7.40000: tcp 25',
            '2026-09-30 12:19:02.002 IP 192.168.1.240.22 > 192.168.1.7.40000: tcp 25',
        ]
        r = m.packets('\n'.join(lines))
        self.assertEqual(r['unparsed_or_out_of_scope_lines'], 0)
        self.assertEqual(r['groups'][0]['direction'], 'from_decoy')
        self.assertEqual(r['groups'][0]['tcp_payload_bytes_with_retransmits'], 50)
        self.assertEqual(r['groups'][0]['packets'], 2)

    def test_packet_unknown_lines_never_echoed(self):
        for line in ('secret-token', '2026-09-30 12:19:00.001 IP 192.168.1.7.40000 > 192.168.1.7.22: tcp 2',
                     '2026-09-30 12:19:00.001 IP 192.168.1.7.40000 > 192.168.1.240.5900: tcp 2',
                     '2026-09-30 12:19:00.001 IP 192.168.1.7.999999 > 192.168.1.240.22: tcp 2'):
            r = m.packets(line)
            self.assertEqual(r, dict(groups=[], unparsed_or_out_of_scope_lines=1))

    def test_log_events_omit_names_urls_and_exception_text(self):
        prefix = '2026-09-30 16:19:00,001 [INFO] squirrelops_home_sensor.decoys.orchestrator: '
        r = m.log_events(prefix + "Deployed decoy 'secret-token' (id=7) on port 51232\n" +
                         prefix.replace('[INFO]', '[ERROR]') + 'api_key=secret-token\n' +
                         'PermissionError: secret-token\n  File "/private/secret-token"\n')
        self.assertEqual(r['events'][0]['numbers'], [7, 51232])
        self.assertEqual(r['withheld_message_counts'], {'ERROR': 1})
        self.assertEqual(r['exception_counts'], {'PermissionError': 1})
        self.assertNotIn('secret-token', json.dumps(r))

    def test_log_scope_and_exception_state_reset(self):
        data = ('2026-09-30 16:19:00,001 [ERROR] squirrelops_home_sensor.decoys.deep: bad\n'
                '2026-09-30 17:19:00,001 [ERROR] squirrelops_home_sensor.decoys.deep: unrelated\n'
                'PermissionError: unrelated\n'
                '2026-09-30 16:19:00,001 [ERROR] other: unrelated\n'
                'TimeoutError: unrelated\n')
        self.assertEqual(m.log_events(data)['exception_counts'], {})

    def test_listener_exact_command_and_endpoint_only(self):
        record = dict(command=m.LISTENERS, exit=0, stdout='p15923\nu309\nn192.168.1.240:49878\nn*:22\nn192.168.1.115:22\nsecret-token\n')
        self.assertEqual(m.listener_records(record), [dict(pid=15923, uid=309, ip=m.VIP, port=49878)])
        self.assertEqual(m.listener_records(dict(record, command=['/sbin/pfctl', '-s', 'References'])), [])
        self.assertEqual(m.listener_records(dict(record, exit=1)), [])

    def test_traffic_is_scoped_and_redacted(self):
        header = 'date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable\n'
        row = '2026-09-30T16:19:00Z,in,309,192.168.1.7,secret-token,6,22,1,0,100,20,"/Library/SquirrelOps/sensor/python/bin/python3.12",secret-token\n'
        r = m.traffic(header + row + row.replace('192.168.1.7', '192.168.1.111'))
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]['process'], 'sensor_python')
        self.assertNotIn('secret-token', json.dumps(r))
        self.assertEqual(m.traffic(header + row.replace(',309,', ',secret-token,')), [])
        guest = row.replace('/Library/SquirrelOps/sensor/python/bin/python3.12', '/Applications/SquirrelOps Home.app/Contents/Library/Helpers/com.squirrelops.deception-guest')
        self.assertEqual(m.traffic(header + guest)[0]['process'], 'guest')

    def test_parent_guard_exact_sticky_exception_and_symlinks(self):
        def info(path, **overrides):
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | (0o1777 if str(path) == '/private/var/tmp' else 0o755), **overrides)
        with patch.object(Path, 'lstat', autospec=True, side_effect=info):
            m.check_parents(m.RECEIPT)
        for mode, uid in ((stat.S_IFLNK | 0o755, 0), (stat.S_IFDIR | 0o777, 0), (stat.S_IFDIR | 0o755, 501)):
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                with self.assertRaises(RuntimeError):
                    m.check_parents(m.BACKUP / 'file')

    def test_safe_read_leaf_guards(self):
        with tempfile.TemporaryDirectory() as d, patch.object(m, 'check_parents'):
            path = Path(d) / 'source'
            path.write_bytes(b'abc')
            path.chmod(0o600)
            self.assertEqual(m.read_safe(path, owners=(os.getuid(),)), b'abc')
            for kwargs in (dict(owners=(-1,)), dict(owners=(os.getuid(),), limit=2)):
                with self.assertRaises(RuntimeError):
                    m.read_safe(path, **kwargs)
            link = Path(d) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                m.read_safe(link, owners=(os.getuid(),))
            os.link(path, Path(d) / 'hardlink')
            with self.assertRaises(RuntimeError):
                m.read_safe(path, owners=(os.getuid(),))
            path.chmod(0o666)
            with self.assertRaises(RuntimeError):
                m.read_safe(path, owners=(os.getuid(),))

    def test_preflight_stops_before_commands_on_receipt_drift(self):
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'read_safe', return_value=b'drift'), patch.object(m, 'command') as run:
            with self.assertRaisesRegex(RuntimeError, 'receipt changed'):
                m.main()
            run.assert_not_called()

    def test_complete_mock_export_only_read_commands(self):
        receipt = b'fixture'
        def reads(path, **kwargs):
            if path == m.RECEIPT:
                return receipt
            if path.name.startswith('packet-'):
                return b'2026-09-30 12:19:00.001 IP 192.168.1.7.40000 > 192.168.1.240.22: tcp 0\n'
            raise FileNotFoundError
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[0] == '/usr/sbin/sysctl':
                return SimpleNamespace(returncode=0, stdout='{ sec = 1790777754, usec = 0 }', stderr='')
            if args[:2] == ['/bin/launchctl', 'print']:
                return SimpleNamespace(returncode=113, stdout='', stderr='Could not find service "' + args[2][7:] + '" in domain for system')
            if args[0] == m.LS:
                return SimpleNamespace(returncode=14, stdout='secret-token', stderr='private-details')
            raise AssertionError('Unexpected command')
        with tempfile.TemporaryDirectory() as d:
            with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'read_safe', side_effect=reads), patch.object(m, 'RECEIPT_SHA', m.hashlib.sha256(receipt).hexdigest()), patch.object(m, 'command', side_effect=run), patch.object(Path, 'glob', return_value=[]), patch.object(m.tempfile, 'mkdtemp', return_value=d), patch.object(m.os, 'chown'), patch('builtins.print'):
                m.main()
            data = (Path(d) / 'diagnostic.json').read_text()
            self.assertNotIn('secret-token', data)
            self.assertNotIn('private-details', data)
            self.assertEqual(len(calls), 4)
            self.assertEqual(json.loads(data)['little_snitch']['exit_code'], 14)


if __name__ == '__main__':
    unittest.main()
