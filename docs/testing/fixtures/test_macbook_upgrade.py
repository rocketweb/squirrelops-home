"""Disposable checks for the attended MacBook upgrade, never installed services."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('macbook_upgrade', Path(__file__).with_name('macbook_upgrade.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def fixture_rows():
    return {table: {(1, 'synthetic')} for table in upgrade.TABLES}


def test_plan_does_not_require_privileges_or_mutate():
    result = subprocess.run([sys.executable, spec.origin], check=True, capture_output=True, text=True)
    plan = json.loads(result.stdout)
    assert plan['mode'] == 'plan_only'
    assert plan['host'] == '192.168.1.97'
    assert plan['preserve_data']
    assert not plan['uninstall'] and not plan['manual_pf_writes']


def test_existing_rows_preserved_and_new_rows_allowed():
    before = fixture_rows()
    after = {table: rows | {(2, 'new')} for table, rows in before.items()}
    counts = upgrade.compare_rows(before, after)
    assert all(row == dict(saved=1, current=2, preserved=True) for row in counts.values())


@pytest.mark.parametrize('table', upgrade.TABLES)
def test_missing_or_changed_saved_rows_fail_without_leaking_contents(table):
    before = fixture_rows()
    after = fixture_rows()
    after[table] = {(1, 'private-credential-value')}
    with pytest.raises(RuntimeError, match=f'Preservation mismatch in {table}') as exc:
        upgrade.compare_rows(before, after)
    assert 'private-credential-value' not in str(exc.value)


def test_table_drift_fails_closed():
    with pytest.raises(RuntimeError, match='table mismatch'):
        upgrade.compare_rows(fixture_rows(), {})


def test_rows_can_be_read_from_old_database_schema_without_side_effects():
    with sqlite3.connect(':memory:') as db:
        for table, columns in upgrade.TABLES.items():
            db.execute(f'CREATE TABLE {table} ({", ".join(c + " TEXT" for c in columns)})')
            db.execute(f'INSERT INTO {table} VALUES ({", ".join("?" for _ in columns)})',
                       tuple(f'synthetic-{index}' for index, _ in enumerate(columns)))
        before = db.total_changes
        rows = upgrade.preserved_rows(db)
        assert all(len(values) == 1 for values in rows.values())
        assert db.total_changes == before


def test_unconditional_translation_rejected_after_upgrade():
    old = 'rdr pass on en0 inet proto tcp from any to 192.168.1.203 port = 22 -> 127.0.0.1 port 60000\n'
    assert upgrade.check_translation(old, after=False)['legacy_rdr_pass'] == 1
    with pytest.raises(RuntimeError, match='survived upgrade'):
        upgrade.check_translation(old, after=True)
    new = old.replace('rdr pass', 'rdr')
    assert upgrade.check_translation(new, after=True) == dict(legacy_rdr_pass=0, translations=1)


def test_backup_precedes_installer_and_no_automatic_rollback():
    source = Path(spec.origin).read_text()
    assert source.index("self.db_snapshot('before.sqlite')") < source.index('self.install_started = True')
    assert source.index("'restore-manifest.json'") < source.index('self.install_started = True')
    assert source.index("'BACKUP VERIFIED;") < source.index("['/usr/sbin/installer'")
    assert 'shutil.rmtree' not in source
    assert "'bootout'" not in source
    assert "'-F'" not in source and "'-X'" not in source
    assert 'uninstall.sh' not in source


def test_bootstrap_pins_every_executable_input():
    fixtures = Path(spec.origin).parent
    wrapper = (fixtures / 'start-macbook-upgrade.sh').read_text()
    for name in ('macbook_upgrade.py', 'mini_clean_upgrade.py'):
        assert f'verify_digest {name} {upgrade.base.digest(fixtures / name)}\n' in wrapper
    assert f'verify_digest candidate.pkg {upgrade.PACKAGE_SHA}\n' in wrapper
    assert f'verify_digest old.pkg {upgrade.base.OLD_SHA}\n' in wrapper
    assert 'env -i' in wrapper and '"$runtime" -I -B' in wrapper


def test_live_snapshot_reads_as_sensor_uid_not_root(monkeypatch, tmp_path):
    database = tmp_path / 'live.sqlite'
    with sqlite3.connect(database) as db:
        for table, columns in upgrade.TABLES.items():
            db.execute(f'CREATE TABLE {table} ({", ".join(c + " TEXT" for c in columns)})')
        serialized = db.serialize()
    session = upgrade.Upgrade(tmp_path)
    session.backup = tmp_path / 'backup'
    session.backup.mkdir()
    monkeypatch.setattr(upgrade, 'DATABASE', database)
    monkeypatch.setattr(upgrade.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=database.stat().st_uid))
    original_connect = sqlite3.connect
    calls = []

    def private_connect(path, *args, **kwargs):
        assert str(database) not in str(path), 'Privileged parent must not open the live SQLite database'
        return original_connect(path, *args, **kwargs)

    def worker(args, **kwargs):
        calls.append(args)
        assert args[:3] == ['/usr/bin/sudo', '-u', '_squirrelops']
        kwargs['stdout'].write(serialized)
        return subprocess.CompletedProcess(args, 0, None, b'')

    monkeypatch.setattr(upgrade.sqlite3, 'connect', private_connect)
    monkeypatch.setattr(upgrade.subprocess, 'run', worker)
    assert all(not rows for rows in session.db_snapshot('before.sqlite').values())
    assert len(calls) == 1


def test_real_worker_includes_live_wal_and_preserves_source_ownership(tmp_path):
    database = tmp_path / 'live.sqlite'
    with sqlite3.connect(database) as live:
        live.execute('PRAGMA journal_mode=WAL')
        live.execute('CREATE TABLE data (value TEXT)')
        live.execute("INSERT INTO data VALUES ('synthetic committed WAL data')")
        live.commit()
        assert database.with_name('live.sqlite-wal').stat().st_size > 0
        owners = {p.name: p.stat().st_uid for p in tmp_path.iterdir()}
        result = subprocess.run([sys.executable, '-I', '-B', '-c', upgrade.SNAPSHOT_WORKER,
                                 str(database)], capture_output=True, check=True)
        output = tmp_path / 'consistent.sqlite'
        output.write_bytes(result.stdout)
        with sqlite3.connect(output) as snapshot:
            assert snapshot.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            assert snapshot.execute('SELECT value FROM data').fetchall() == [('synthetic committed WAL data',)]
        assert {name: (tmp_path / name).stat().st_uid for name in owners} == owners
