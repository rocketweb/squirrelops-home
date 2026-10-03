"""Local, non-root checks of the destructive reset's scope and backup helpers."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('clean_upgrade', Path(__file__).with_name('mini_clean_upgrade.py'))
reset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)


def test_plan_is_read_only():
    result = subprocess.run([__import__('sys').executable, spec.origin], text=True, capture_output=True, check=True)
    plan = json.loads(result.stdout)
    assert plan['mode'] == 'plan_only'
    assert plan['host'] == '100.108.203.27'
    assert plan['upgrade_run'] is False
    assert '/Library/SquirrelOps/acceptance-backups' not in plan['targets']
    assert '/Library/SquirrelOps' not in plan['targets']


def test_manifest_does_not_follow_links_and_detects_changed_bytes(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'data').write_text('synthetic')
    (source / 'link').symlink_to('/no/such/target')
    before = reset.manifest(source)
    assert before['link']['kind'] == 'link'
    assert before['link']['target'] == '/no/such/target'
    (source / 'data').write_text('different')
    assert reset.manifest(source) != before


def test_copy_verifies_durable_objects_and_omits_socket(tmp_path):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    (source / 'subtree').mkdir()
    (source / 'subtree' / 'data').write_text('synthetic')
    (source / 'subtree' / 'link').symlink_to('data')
    # macOS AF_UNIX paths are short; pytest's full temporary path can exceed it.
    sock = socket.socket(socket.AF_UNIX)
    import os
    previous = os.getcwd()
    calls = []
    try:
        os.chdir(source)
        sock.bind('transient.sock')
        before = reset.manifest(source)
        def command(args, **kwargs):
            calls.append(args)
            return subprocess.run(args, check=True, capture_output=True, timeout=kwargs['timeout'])
        reset.copy_tree(source, target, before, command)
        assert reset.manifest(target) == reset.durable(before)
        assert not (target / 'transient.sock').exists()
        assert len(calls) == 1  # subtree copied once, never per file
    finally:
        sock.close()
        os.chdir(previous)


@pytest.mark.parametrize('result,loaded', [
    (subprocess.CompletedProcess([], 0, 'system/com.squirrelops.sensor = {\n}', ''), True),
    (subprocess.CompletedProcess([], 113, '', 'Could not find service "com.squirrelops.sensor" in domain for system'), False),
])
def test_launchd_known_states(result, loaded):
    assert reset.parse_loaded(result, reset.JOBS[0]) is loaded


def test_launchd_permission_failure_is_not_absence():
    with pytest.raises(RuntimeError):
        reset.parse_loaded(subprocess.CompletedProcess([], 1, '', 'Permission denied'), reset.JOBS[0])


def test_scope_and_original_installer_remain_narrow():
    source = Path(spec.origin).read_text()
    assert reset.ARCHIVES not in reset.TARGETS
    assert not any(reset.ARCHIVES.is_relative_to(p) for p in reset.TARGETS)
    assert reset.OLD_SHA == '252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8'
    assert "'--remove-data'" in source
    assert source.index('manifest(target) == durable(expected)') < source.index("'--remove-data'")
    assert "'--allowUntrusted'" not in source
    assert "'-F', 'all'" not in source
    assert 'scouts:\n  enabled: false' in reset.CONFIG
    assert 'profile: lite' in reset.CONFIG
    assert 'local_enrollment_enabled: true' in reset.CONFIG


def test_old_config_schema_accepts_fixture():
    import yaml
    from squirrelops_home_sensor.config import Settings
    settings = Settings.model_validate(yaml.safe_load(reset.CONFIG))
    assert settings.profile == 'lite'
    assert settings.scouts.enabled is False
    assert settings.home_assistant.enabled is False


def process_check(monkeypatch, inventory, sensor_uid=309):
    session = reset.Reset(Path('/unused-plan-only'))
    def command(args, **kwargs):
        assert args == ['/bin/ps', '-axo', 'uid=,pid=,comm=']
        return subprocess.CompletedProcess(args, 0, inventory, '')
    monkeypatch.setattr(session, 'command', command)
    monkeypatch.setattr(reset.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=sensor_uid))
    return session.no_runtime


def test_mini_negative_uid_process_is_valid_inventory(monkeypatch):
    # Exact UID/PID/executable observed by read-only inspection of the Mini.
    process_check(monkeypatch, '   -2   653 /usr/sbin/distnoted\n'
                  '    0     1 /sbin/launchd\n'
                  '  501   701 /usr/bin/login\n')()


def test_signed_uid_is_not_allowed_to_hide_sensor_process(monkeypatch):
    with pytest.raises(RuntimeError, match='SquirrelOps still running'):
        process_check(monkeypatch, '-2 653 /tmp/owned-process\n', sensor_uid=4294967294)()


@pytest.mark.parametrize('inventory', [
    '--2 653 /usr/sbin/distnoted\n',
    '-2 -653 /usr/sbin/distnoted\n',
    'nobody 653 /usr/sbin/distnoted\n',
    '0\n',
    '0 2.5 /sbin/launchd\n',
    '4294967296 653 /usr/sbin/distnoted\n',
    '-2147483649 653 /usr/sbin/distnoted\n',
    '0 2147483648 /sbin/launchd\n',
])
def test_malformed_process_inventory_still_rejected(monkeypatch, inventory):
    with pytest.raises(RuntimeError, match='Malformed process inventory'):
        process_check(monkeypatch, inventory)()


@pytest.mark.parametrize('inventory', [
    '309 700 /tmp/unknown-process\n',
    '309 700\n',
    '0 700 /Library/SquirrelOps/sensor/python/bin/python3.12\n',
    '501 700 /Applications/SquirrelOps Home.app/Contents/MacOS/SquirrelOpsHome\n',
    '0 700 /Library/PrivilegedHelperTools/com.squirrelops.helper\n',
])
def test_product_processes_still_block_reset(monkeypatch, inventory):
    with pytest.raises(RuntimeError, match='SquirrelOps still running'):
        process_check(monkeypatch, inventory)()


def test_unrelated_process_with_missing_command_is_valid(monkeypatch):
    process_check(monkeypatch, '0 700\n')()


def test_only_exact_sensor_distnoted_exception_is_allowed(monkeypatch):
    process_check(monkeypatch, '309 700 /usr/sbin/distnoted\n')()
    with pytest.raises(RuntimeError, match='SquirrelOps still running'):
        process_check(monkeypatch, '309 700 /tmp/distnoted\n')()


def test_bootstrap_pins_this_exact_runner():
    wrapper = Path(spec.origin).with_name('start-mini-clean-upgrade.sh').read_text()
    assert f'verify_digest mini_clean_upgrade.py {reset.digest(Path(spec.origin))}\n' in wrapper
