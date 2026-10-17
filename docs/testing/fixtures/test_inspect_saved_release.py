"""Synthetic-only checks for the narrowly scoped retained-evidence exporter."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).with_name('inspect_saved_release.py')
spec = importlib.util.spec_from_file_location('saved_review', SCRIPT)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

RULE = '@0 block drop in quick inet from any to 192.168.1.240'
COUNTS = '[ Evaluations: 10 Packets: 2 Bytes: 120 States: 0 ]'


def test_plan_reads_no_private_evidence():
    result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), 'macbook'],
                            capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == dict(mode='plan_only', host='macbook', system_mutations=False)


@pytest.mark.parametrize('line,kind', [
    ('[ State Creations: 2 ]', 'state_creations'),
    ('[ Inserted: uid 0 pid 123 State Creations: 2 ]', 'inserted_and_state_creations'),
])
def test_extra_metadata_does_not_override_original_rejection(line, kind):
    result = review.extra_counters('\n'.join((RULE, COUNTS, line)))
    assert result['original']['withheld_lines'] == 1
    assert result['additional_numeric_metadata'][0]['kind'] == kind
    assert result['additional_numeric_metadata'][0]['value'] == 2
    assert result['unrecognized'] == []
    assert result['automatic_gate_pass'] is False
    assert not review.inspector.counter_delta(result['original'], result['original'])['comparable']


@pytest.mark.parametrize('line', [
    '[ State Creations: 18446744073709551616 ]',
    '[ Inserted: uid 4294967296 pid 123 State Creations: 2 ]',
    '[ Inserted: uid 0 pid 2147483648 State Creations: 2 ]',
    '[ State Creations: private-secret ]',
    'private-secret 192.0.2.77 password=hidden',
])
def test_unknown_counter_not_disclosed(line):
    result = review.extra_counters('\n'.join((RULE, COUNTS, line)))
    assert result['unrecognized']
    assert not result['additional_numeric_metadata']
    assert 'private-secret' not in json.dumps(result)
    assert '192.0.2.77' not in json.dumps(result)


def test_original_bad_counter_blocks_retained():
    result = review.extra_counters('\n'.join((RULE, COUNTS, COUNTS)))
    assert result['original']['withheld_lines'] == 1


@pytest.mark.parametrize('event', [
    dict(event='ready', uid=309, gid=309, pid=124, address='192.168.1.240', port=61445),
    dict(event='ready', uid=501, gid=20, pid=125, address='0.0.0.0', port=61445),
    dict(event='bind_failed', uid=501, pid=125, errno=48),
    dict(event='listener_closed', uid=309, clients=2),
])
def test_strict_additional_child_events(event):
    result = review.extra_events(json.dumps(event))
    assert result['additional_events'] == [dict(line=1, **event)]
    assert not result['unrecognized']
    assert result['original']['withheld_lines'] == 1


@pytest.mark.parametrize('event', [
    dict(event='ready', uid=309, gid=309, pid=True, address='192.168.1.240', port=61445),
    dict(event='ready', uid=501, gid=309, pid=125, address='0.0.0.0', port=61445),
    dict(event='bind_failed', uid=501, pid=125, errno=48, credential='private-secret'),
    dict(event='listener_closed', uid=309, clients=True),
    dict(event='listener_closed', uid=309, clients=17),
])
def test_unknown_event_stays_private(event):
    result = review.extra_events(json.dumps(event))
    assert result['additional_events'] == []
    assert result['unrecognized']
    assert 'private-secret' not in json.dumps(result)


def test_states_only_retain_scoped_tcp():
    text = '\n'.join((
        'all tcp 192.168.1.203:22 <- 192.168.1.7:50333 ESTABLISHED:ESTABLISHED',
        'all tcp 192.168.1.97:443 -> 192.0.2.50:443 ESTABLISHED:ESTABLISHED',
        'all tcp 192.168.1.203:22 <- 192.168.1.7:50333 UNRECOGNIZED',
    ))
    result = review.scoped_states(text, {'192.168.1.203'})
    assert len(result['selected']) == 1
    assert result['unrelated_lines'] == result['unrecognized_scoped_lines'] == 1
    assert '192.0.2.50' not in json.dumps(result)


def root_metadata(monkeypatch, path):
    original = Path.lstat
    def metadata(self):
        value = original(self)
        if self == path:
            fields = list(value)
            fields[4] = 0
            return os.stat_result(fields)
        return value
    monkeypatch.setattr(Path, 'lstat', metadata)


@pytest.mark.parametrize('new_schema', [False, True])
def test_archived_database_excludes_private_fields_and_never_changes_file(tmp_path, monkeypatch, new_schema):
    path = tmp_path / 'before.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE decoys (id INTEGER, decoy_type TEXT, bind_address TEXT, port INTEGER, '
                   'status TEXT, name TEXT, config TEXT' +
                   (', retired_at TEXT, retirement_reason TEXT)' if new_schema else ')'))
        row = [1, 'deep', '192.168.1.203', 22, 'active', 'private-name', 'private-secret']
        if new_schema:
            row.extend(['2026-10-02', 'private-reason'])
        db.execute('INSERT INTO decoys VALUES (' + ','.join('?' for _ in row) + ')', row)
    path.chmod(0o600)
    root_metadata(monkeypatch, path)
    original = path.read_bytes()
    rows = review.saved_database_rows(path)
    assert rows[0]['retired'] is new_schema
    assert rows[0]['id'] == 1
    assert 'private-' not in json.dumps(rows)
    assert path.read_bytes() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ['before.sqlite']


def test_saved_sidecar_rejected(tmp_path, monkeypatch):
    path = tmp_path / 'before.sqlite'
    path.touch(mode=0o600)
    (tmp_path / 'before.sqlite-wal').touch()
    root_metadata(monkeypatch, path)
    with pytest.raises(RuntimeError, match='sidecar'):
        review.saved_database_rows(path)


def test_exporter_has_no_command_execution_or_live_database_paths():
    source = SCRIPT.read_text()
    assert 'subprocess' not in source
    assert 'squirrelops.db' not in source
    assert 'mode=ro&immutable=1' in source
    assert len(review.RUNS) == 2
    assert review.BOOK == 'macbook-upgrade-20261002.jikh0k2n'


def test_attended_wrapper_pins_both_scripts_and_is_read_only():
    wrapper = SCRIPT.with_name('inspect-saved-release.sh').read_text()
    for path in (SCRIPT, review.inspector_path):
        assert hashlib.sha256(path.read_bytes()).hexdigest() in wrapper
    for forbidden in ('launchctl', 'pfctl', 'installer', 'chmod', 'chown', 'rm -'):
        assert forbidden not in wrapper.replace('# Read completed private evidence only. No service, network or installer calls.', '')
    assert 'env -i' in wrapper
    assert '[ ! -t 0 ]' in wrapper
    assert '-I -B' in wrapper
