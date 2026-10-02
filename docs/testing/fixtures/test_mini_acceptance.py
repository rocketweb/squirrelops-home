"""Local-only guard tests. No privileged or network commands execute."""
import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mini_acceptance", Path(__file__).with_name("mini_acceptance.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GuardTests(unittest.TestCase):
    def test_bootstrap_arguments_with_macos_bash_nounset(self):
        source = Path(__file__).with_name('start-mini-acceptance.sh').read_text()
        function = 'prepare_run_args() {' + source.split('prepare_run_args() {', 1)[1].split('\n}', 1)[0] + '\n}'
        for resume in (0, 1):
            with self.subTest(resume=resume):
                script = ('set -eu\ntask_dir=/private/var/root/fixture\n'
                          f'resume_failed_install={resume}\n' + function +
                          '\nprepare_run_args\nprintf "%s\\n" "${run_args[@]}"\n')
                result = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = ['--run', '/private/var/root/fixture']
                if resume:
                    expected.append('--resume-failed-install')
                self.assertEqual(result.stdout.splitlines(), expected)

    @contextmanager
    def partial_install_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sensor = root / 'product/sensor'
            sensor.mkdir(parents=True, mode=0o700)
            baseline = root / 'product/acceptance-backups/failed'
            baseline.mkdir(parents=True)
            (baseline / 'preflight-only.json').write_text('{"schema":1,"phase":"install_started"}')
            (baseline / 'mini_acceptance.py').write_text('old script fixture')
            (baseline / 'proposed-config.yaml').write_text('bounded config fixture')
            config = sensor / 'config.yaml'
            config.write_text('bounded config fixture')
            config.chmod(0o600)
            service_paths = {config, sensor / 'data', sensor / 'logs'}
            for name in ('data', 'logs'):
                (sensor / name).mkdir(mode=0o700)
            executables = {}
            for name in ('app', 'helper', 'guest'):
                path = root / name
                path.write_text('pinned ' + name)
                path.chmod(0o755)
                executables[path] = module.digest(path)
            real_lstat, real_digest = Path.lstat, module.digest
            def metadata(path, *args, **kwargs):
                result = list(real_lstat(path, *args, **kwargs))
                result[4] = result[5] = 309 if path in service_paths else 0
                return os.stat_result(result)
            def digest(path):
                if path == baseline / 'mini_acceptance.py':
                    return '365ec06fb20f018ac1acd2ca3b73544a5813fb633a06c652a580a56b254090b0'
                return real_digest(path)
            session = module.Session(root, resume_failed_install=True)
            with patch.object(module, 'SENSOR', sensor), patch.object(module, 'FAILED_BASELINE', baseline), \
                    patch.object(module, 'CONFIG_SHA', real_digest(config)), \
                    patch.object(module, 'EXECUTABLES', executables), patch.object(module, 'digest', side_effect=digest), \
                    patch.object(Path, 'lstat', metadata), \
                    patch.object(module.pwd, 'getpwnam', return_value=SimpleNamespace(
                        pw_uid=309, pw_gid=309, pw_dir='/var/empty', pw_shell='/usr/bin/false')), \
                    patch.object(module.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=309, gr_mem=[])), \
                    patch.object(session, 'command', return_value=subprocess.CompletedProcess([], 1, '', '')) as commands, \
                    patch.object(session, 'owned', return_value=[]):
                yield session, sensor, baseline, executables, commands

    def test_recovery_accepts_only_observed_partial_install(self):
        with self.partial_install_fixture() as (session, sensor, _baseline, _executables, commands):
            session.verify_partial_install()
            self.assertEqual(stat.S_IMODE(sensor.stat().st_mode), 0o700)
            self.assertEqual([call.args[0] for call in commands.call_args_list],
                             [['/usr/bin/pgrep', '-u', '309'], ['/usr/bin/pgrep', '-x', 'SquirrelOpsHome']])

    def test_recovery_rejects_changed_partial_install(self):
        for change in ('data', 'mode', 'config', 'binary', 'phase', 'symlink', 'process', 'uid'):
            with self.subTest(change=change), self.partial_install_fixture() as (
                    session, sensor, baseline, executables, commands):
                if change == 'data':
                    (sensor / 'data/unexpected.sqlite').write_text('preserve me')
                elif change == 'mode':
                    sensor.chmod(0o755)
                elif change == 'config':
                    (sensor / 'config.yaml').write_text('changed')
                elif change == 'binary':
                    next(iter(executables)).write_text('different executable')
                elif change == 'phase':
                    (baseline / 'preflight-only.json').write_text('{"schema":1,"phase":"preflight_only"}')
                elif change == 'symlink':
                    config = sensor / 'config.yaml'
                    config.rename(sensor / 'saved.yaml')
                    config.symlink_to(sensor / 'saved.yaml')
                elif change == 'process':
                    commands.return_value = subprocess.CompletedProcess([], 0, '123', '')
                elif change == 'uid':
                    module.pwd.getpwnam.return_value.pw_uid = 501
                with self.assertRaises(RuntimeError):
                    session.verify_partial_install()
                self.assertFalse(session.install_started)

    def test_preseed_remains_traversable_under_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / 'source.yaml'
            source.write_text('synthetic: true\n')
            directory = base / 'sensor'
            previous = os.umask(0o077)
            try:
                module.prepare_sensor_config(directory, source)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((directory / 'config.yaml').stat().st_mode), 0o600)
            self.assertEqual((directory / 'config.yaml').read_text(), source.read_text())

    def test_preseed_does_not_overwrite_existing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'sensor'
            directory.mkdir(mode=0o700)
            config = directory / 'config.yaml'
            config.write_text('existing data')
            with self.assertRaises(FileExistsError):
                module.prepare_sensor_config(directory, Path(temporary) / 'missing')
            self.assertEqual(config.read_text(), 'existing data')
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    @staticmethod
    def pf_reader(outputs, overrides=None):
        def command(args):
            key = tuple(args[1:])
            if overrides and key in overrides:
                return overrides[key]
            return subprocess.CompletedProcess(args, 0, outputs[key], '')
        return command

    @staticmethod
    def empty_tree():
        return {
            ('-sr',): 'anchor "com.apple/*" all\n', ('-sn',): '',
            ('-s', 'Anchors'): '  com.apple\n',
            ('-a', 'com.apple', '-sr'): 'anchor "250.ApplicationFirewall/*" all\n',
            ('-a', 'com.apple', '-sn'): '',
            ('-a', 'com.apple', '-s', 'Anchors'): '  com.apple/250.ApplicationFirewall\n',
            ('-a', 'com.apple/250.ApplicationFirewall', '-sr'): '',
            ('-a', 'com.apple/250.ApplicationFirewall', '-sn'): '',
            ('-a', 'com.apple/250.ApplicationFirewall', '-s', 'Anchors'): '',
        }

    def test_every_concrete_child_is_read(self):
        for child_listing in ('250.ApplicationFirewall', 'com.apple/250.ApplicationFirewall'):
            outputs = self.empty_tree()
            outputs[('-a', 'com.apple', '-s', 'Anchors')] = child_listing
            session = module.Session(Path('/unused'))
            with patch.object(session, 'command', side_effect=self.pf_reader(outputs)):
                inventory = session.inspect_empty_pf()
            self.assertEqual(set(inventory), {'', 'com.apple', 'com.apple/250.ApplicationFirewall'})

    def test_child_filter_and_nat_rules_require_review(self):
        for flag, rule in (('-sr', 'pass in all'), ('-sn', 'nat on en0 from any to any -> (en0)')):
            outputs = self.empty_tree()
            outputs[('-a', 'com.apple/250.ApplicationFirewall', flag)] = rule
            session = module.Session(Path('/unused'))
            with patch.object(session, 'command', side_effect=self.pf_reader(outputs)):
                with self.assertRaisesRegex(RuntimeError, 'policy.*needs review'):
                    session.inspect_empty_pf()

    def test_incomplete_child_reads_fail_closed(self):
        for code, stderr in ((0, 'pfctl: DIOCGETRULES: Invalid argument'), (1, ''),
                             (0, 'pfctl: /dev/pf: Permission denied')):
            session = module.Session(Path('/unused'))
            overrides = {('-a', 'com.apple/250.ApplicationFirewall', '-sn'):
                         subprocess.CompletedProcess([], code, '', stderr)}
            with patch.object(session, 'command', side_effect=self.pf_reader(self.empty_tree(), overrides)):
                with self.assertRaisesRegex(RuntimeError, 'inventory incomplete'):
                    session.inspect_empty_pf()

    def test_unknown_or_malformed_anchor_requires_review(self):
        for name in ('other', 'com.apple/../other', '*', '/com.apple', 'com.apple\ncom.apple'):
            session = module.Session(Path('/unused'))
            outputs = self.empty_tree()
            outputs[('-s', 'Anchors')] = name
            with patch.object(session, 'command', side_effect=self.pf_reader(outputs)):
                with self.assertRaises(RuntimeError):
                    session.inspect_empty_pf()

    def test_tree_changes_during_inspection_fail_closed(self):
        session = module.Session(Path('/unused'))
        outputs = self.empty_tree()
        calls = 0
        def command(args):
            nonlocal calls
            if args[1:] == ['-s', 'Anchors']:
                calls += 1
                if calls > 1:
                    return subprocess.CompletedProcess(args, 0, '', '')
            return self.pf_reader(outputs)(args)
        with patch.object(session, 'command', side_effect=command):
            with self.assertRaisesRegex(RuntimeError, 'changed during inventory'):
                session.inspect_empty_pf()

    def test_policy_change_before_install_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = module.Session(Path('/unused'))
            session.backup = Path(temporary)
            session.pf_baseline = {'old': {}}
            with patch.object(session, 'inspect_empty_pf', return_value={'new': {}}), \
                    patch.object(session, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'changed after preflight'):
                    session.install()
            self.assertEqual(list(session.backup.iterdir()), [])
            command.assert_not_called()

    def test_inspection_avoids_broken_recursive_query(self):
        session = module.Session(Path('/private/var/root/squirrelops-mini-acceptance.fixture'))
        outputs = {
            ('-sr',): 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n',
            ('-sn',): 'nat-anchor "com.apple/*" all\nrdr-anchor "com.apple/*" all\n',
            ('-s', 'Anchors'): '  com.apple\n',
            ('-a', 'com.apple', '-sr'): '',
            ('-a', 'com.apple', '-sn'): '',
            ('-a', 'com.apple', '-s', 'Anchors'): '',
        }

        def command(args):
            key = tuple(args[1:])
            if key == ('-a', '*', '-sr'):
                # Exact operator output. pfctl can warn without a nonzero exit.
                return subprocess.CompletedProcess(args, 0,
                    'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "*" all {\n}\n',
                    'No ALTQ support in kernel\nALTQ related functions disabled\npfctl: DIOCGETRULES: Invalid argument\n')
            return subprocess.CompletedProcess(args, 0, outputs[key],
                'No ALTQ support in kernel\nALTQ related functions disabled\n')

        with patch.object(session, 'command', side_effect=command) as calls:
            session.inspect_empty_pf()
        self.assertFalse(any('*' in call.args[0] for call in calls.call_args_list))
        self.assertTrue(set(outputs) <= {tuple(call.args[0][1:]) for call in calls.call_args_list})

    def test_pf_error_with_zero_exit_is_not_empty_policy(self):
        session = module.Session(Path('/private/var/root/squirrelops-mini-acceptance.fixture'))
        with patch.object(session, 'command', return_value=subprocess.CompletedProcess(
                [], 0, '', 'pfctl: DIOCGETRULES: Invalid argument\n')):
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                session.inspect_empty_pf()

    def test_retry_preserves_preflight_only_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'SquirrelOps'
            prior = root / 'acceptance-backups' / 'mini-20260928.fixture'
            prior.mkdir(parents=True)
            marker = prior / 'preflight-only.json'
            marker.write_text('{"schema":1,"phase":"preflight_only"}\n')
            evidence = prior / 'command-001.json'
            evidence.write_text('retained evidence')
            # Local test directories are not root-owned. Test the ownership
            # guards separately; do not run these tests as administrator.
            with patch.object(module, 'safe_directory'), patch.object(module, 'safe_file', create=True):
                module.validate_backup_container(root)
            self.assertEqual(evidence.read_text(), 'retained evidence')

    def test_retry_rejects_installation_or_unknown_backup(self):
        for variant in ('sensor', 'unknown_backup', 'install_started', 'invalid_marker'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'SquirrelOps'
                prior = root / 'acceptance-backups' / 'mini-20260928.fixture'
                prior.mkdir(parents=True)
                if variant == 'sensor':
                    (root / 'sensor').mkdir()
                elif variant == 'install_started':
                    (prior / 'preflight-only.json').write_text('{"schema":1,"phase":"install_started"}')
                elif variant == 'invalid_marker':
                    (prior / 'preflight-only.json').write_text('{}')
                with patch.object(module, 'safe_directory'), patch.object(module, 'safe_file'):
                    with self.assertRaises(RuntimeError):
                        module.validate_backup_container(root)

    def test_legacy_retry_requires_exact_read_only_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'SquirrelOps'
            prior = root / 'acceptance-backups' / 'mini-20260928.o9xofp7p'
            prior.mkdir(parents=True)
            for name in ('original-product-state.txt', 'mini_acceptance.py', 'proposed-config.yaml', 'pf.conf.observed-only'):
                (prior / name).write_text('fixture')
            for index, args in enumerate((['/sbin/pfctl', '-s', 'info'], ['/sbin/pfctl', '-s', 'References'],
                                         ['/sbin/pfctl', '-a', '*', '-sr']), 1):
                (prior / f'command-{index:03d}.json').write_text(json.dumps({'command': args}))
            with patch.object(module, 'safe_directory'), patch.object(module, 'safe_file'), \
                    patch.object(module, 'digest', return_value='2852d7f814b66e1c75224d105e41ca11dcf860e5bbac070b10f68172c201f3cd'):
                module.validate_backup_container(root)
                (prior / 'command-003.json').write_text(json.dumps({'command': ['/sbin/pfctl', '-E']}))
                with self.assertRaisesRegex(RuntimeError, 'exceeded read-only'):
                    module.validate_backup_container(root)

    def test_evidence_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'target'
            target.mkdir()
            link = Path(temporary) / 'link'
            link.symlink_to(target)
            for check in (module.safe_file, module.safe_directory):
                with self.assertRaises(RuntimeError):
                    check(link)

    def test_nonrecursive_validator_never_accepts_recursive_error_shape(self):
        for text in ('anchor "*" all {\n}', '}', 'anchor "com.apple/*" all {\n}'):
            with self.assertRaises(RuntimeError):
                module.validate_empty_policy(text)

    def test_actual_health_response(self):
        self.assertTrue(module.health_payload_ok('{"status":"ok","uptime_seconds":4.0}'))

    def test_invalid_health(self):
        for value in ('{}', 'null', '[]', 'invalid', '{"status":"unhealthy"}'):
            with self.subTest(value=value):
                self.assertFalse(module.health_payload_ok(value))

    def test_empty_apple_hooks(self):
        module.validate_empty_policy('scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\nnat-anchor "com.apple/*" all\nrdr-anchor "com.apple/*" all\n')

    def test_active_policy_requires_review(self):
        for line in ('pass in all', 'block drop all', 'nat on en0 from any to any -> (en0)',
                     'rdr pass on en0 inet proto tcp from any to any port 22 -> 127.0.0.1',
                     'anchor "unrelated" all', 'set skip on lo0'):
            with self.subTest(line=line), self.assertRaises(RuntimeError):
                module.validate_empty_policy(line)

    def test_ledger_exact_scope(self):
        self.assertEqual(module.parse_ledger('192.168.1.241|en0\n192.168.1.240|en0\n'), sorted(module.VIPS))
        self.assertEqual(module.parse_ledger(''), [])

    def test_ledger_rejects_extra_ownership(self):
        for text in ('192.168.1.115|en0', '192.168.1.240|en1', '192.168.1.240|en0|bad',
                     '192.168.1.240|en0\n192.168.1.240|en0', 'bad', 'x' * 65537):
            with self.subTest(text=text[:45]), self.assertRaises(RuntimeError):
                module.parse_ledger(text)

    def test_only_one_owned_pf_token(self):
        self.assertEqual(module.parse_pf_token('pf enabled\nToken : 123456\n'), '123456')
        for text in ('', 'Token : nope', 'Token : 123\nToken : 456\n'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                module.parse_pf_token(text)

    def test_listener_comparison_includes_uid(self):
        self.assertEqual(module.listener_endpoints('p1\nu0\nf7\nn*:22\np42\nu501\nf4\nn192.168.1.115:11434\n'),
                         {('0', '*:22'), ('501', '192.168.1.115:11434')})

    def test_uncertain_installer_never_cleans_network(self):
        session = module.Session(Path('/private/var/root/squirrelops-mini-acceptance.fixture'))
        session.install_started = True
        session.install_in_progress = True
        with patch.object(session, 'command') as command, self.assertRaises(RuntimeError):
            session.stop()
        command.assert_not_called()

    def test_no_install_no_token_means_no_cleanup_commands(self):
        session = module.Session(Path('/private/var/root/squirrelops-mini-acceptance.fixture'))
        with patch.object(session, 'command') as command:
            session.stop()
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
