"""Read only pinned completed runs; export bounded, non-credential evidence."""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile

inspector_path = Path(__file__).with_name('inspect_completed.py')
if not inspector_path.exists():
    inspector_path = Path(__file__).parent / 'pf-acceptance' / 'inspect_completed.py'
spec = importlib.util.spec_from_file_location('inspector', inspector_path)
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)
BASE = Path('/Library/SquirrelOps/acceptance-backups')
BOOK = 'macbook-upgrade-20261002.jikh0k2n'
RUNS = (
    ('mini-a5-20261002.DcmC5nO5', 'c21040d915eb', inspector.PHASES, 'child-*-events.jsonl'),
    ('mini-a5-edges-20261002.ouytf6ce', 'cbba59af3e2b',
     ('edge_healthy', 'established_replacement', 'half_open_start',
      'half_open_wrong_uid', 'half_open_quarantine'), 'edge-child-*.jsonl'),
)
STATES = inspector.STATE_NAMES
DECOY_TYPES = {'deep', 'mimic', 'file_share', 'dev_server', 'home_assistant', 'credential_tripwire'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def private_root(name):
    for path in (BASE, BASE / name):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe evidence directory')
    return BASE / name


def read_manifest(path):
    # The verified runtime copy can contain many entries. This larger bound
    # applies only to its manifest; no raw entries leave the private archive.
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        limit = 32 * 1024**2
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= limit, 'Unsafe saved manifest')
        with os.fdopen(fd, 'r', closefd=False) as stream:
            text = stream.read(limit + 1)
        require(len(text) <= limit, 'Saved manifest exceeds bound')
        return json.loads(text)
    finally:
        os.close(fd)


def extra_counters(text):
    """Keep the original strict result; separately identify known numeric metadata.

    No unknown text is exported, and no original comparable=false is changed.
    """
    original = inspector.counter_summary(text)
    additional, unknown = [], []
    current = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        rule = re.fullmatch(r'@(\d{1,3}) .{1,2048}', stripped)
        if rule:
            current = int(rule[1])
            continue
        if 'Evaluations:' in stripped:
            continue  # Original parser retains validation of this block.
        if re.fullmatch(r'\[\s*Inserted:\s*uid \d+ pid \d+\s*\]', stripped):
            continue
        creation = re.fullmatch(r'\[\s*State Creations:\s*(\d{1,20})\s*\]', stripped)
        combined = re.fullmatch(r'\[\s*Inserted:\s*uid (\d{1,10}) pid (\d{1,10})'
                                r'\s+State Creations:\s*(\d{1,20})\s*\]', stripped)
        if (combined and current is not None and int(combined[1]) < 2**32
                and int(combined[2]) < 2**31 and int(combined[3]) <= 2**64 - 1):
            additional.append(dict(line=number, rule_index=current, kind='inserted_and_state_creations',
                                   uid=int(combined[1]), pid=int(combined[2]), value=int(combined[3]),
                                   line_sha256=digest_text(stripped)))
        elif creation and current is not None and int(creation[1]) <= 2**64 - 1:
            additional.append(dict(line=number, rule_index=current, kind='state_creations',
                                   value=int(creation[1]), line_sha256=digest_text(stripped)))
        else:
            # Provide shape, not arbitrary data from an unrecognized log line.
            vocabulary = {'State', 'Creations', 'Inserted', 'uid', 'pid', 'Evaluations',
                          'Packets', 'Bytes', 'States', 'ID', 'id', 'label', 'ridentifier'}
            words = re.findall(r'[A-Za-z_]+', stripped)
            unknown.append(dict(line=number, sha256=digest_text(stripped),
                                known_words=[word for word in words if word in vocabulary],
                                other_word_count=sum(word not in vocabulary for word in words)))
    return dict(original=original, additional_numeric_metadata=additional,
                unrecognized=unknown, automatic_gate_pass=False)


def extra_events(text):
    original = inspector.child_summary(text)
    selected, unknown = [], []
    for number, line in enumerate(text.splitlines(), 1):
        try:
            row = json.loads(line)
        except ValueError:
            row = None
        if inspector.child_summary(line)['withheld_lines'] == 0:
            continue
        valid = isinstance(row, dict) and type(row.get('uid')) is int and row['uid'] in (309, 501)
        if valid and row.get('event') == 'ready':
            valid = (set(row) == {'event', 'pid', 'uid', 'gid', 'address', 'port'}
                     and type(row['pid']) is int and 0 < row['pid'] < 2**31
                     and type(row['gid']) is int and row['gid'] == (309 if row['uid'] == 309 else 20)
                     and row['address'] in {'127.0.0.1', '0.0.0.0', '192.168.1.239', '192.168.1.240'}
                     and type(row['port']) is int and 1 <= row['port'] <= 65535)
        elif valid and row.get('event') == 'bind_failed':
            valid = (set(row) == {'event', 'pid', 'uid', 'errno'}
                     and type(row['pid']) is int and 0 < row['pid'] < 2**31
                     and type(row['errno']) is int and 0 < row['errno'] < 256)
        elif valid and row.get('event') == 'listener_closed':
            valid = (set(row) == {'event', 'uid', 'clients'}
                     and type(row['clients']) is int and 0 <= row['clients'] <= 16)
        else:
            valid = False
        if valid:
            selected.append(dict(line=number, **row))
        else:
            unknown.append(dict(line=number, sha256=digest_text(line)))
    return dict(original=original, additional_events=selected, unrecognized=unknown)


def collect_mini():
    runs = []
    for name, nonce, phases, child_glob in RUNS:
        root = private_root(name)
        receipt = json.loads(inspector.read_safe(root / 'receipt.json'))
        require(receipt['nonce'] == nonce and receipt['release_attempted'] is True
                and receipt['aliases'] == receipt['alias_attempts'] == [], 'Cleanup receipt mismatch')
        result = dict(run=name, nonce=nonce, counters=[], children=[])
        for phase in phases:
            for side in ('before', 'after'):
                filename = phase + '-' + side + '-pf.json'
                text = inspector.read_safe(root / filename)
                value = json.loads(text)
                result['counters'].append(dict(file=filename, source_sha256=digest_text(text),
                                               **extra_counters(value['counters'])))
        children = sorted(root.glob(child_glob))
        require(len(children) == (8 if name == RUNS[0][0] else 14), 'Unexpected child evidence count')
        for path in children:
            require(re.fullmatch(r'(child-\d+-events|edge-child-\d+)\.jsonl', path.name), 'Unexpected child filename')
            text = inspector.read_safe(path)
            result['children'].append(dict(file=path.name, source_sha256=digest_text(text), **extra_events(text)))
        runs.append(result)
    return dict(scope='completed-mini-counters-and-events', system_mutations=False, runs=runs)


def saved_database_rows(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= 512 * 1024**2, 'Unsafe saved database')
    # Immutable mode is only for a completed, standalone archive snapshot, never
    # the live database. Refuse any archived WAL/SHM instead of ignoring it.
    for suffix in ('-wal', '-shm'):
        companion = Path(str(path) + suffix)
        require(not companion.exists() and not companion.is_symlink(), 'Saved database has a sidecar')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as database:
        database.execute('PRAGMA trusted_schema=OFF')
        columns = {row[1] for row in database.execute('PRAGMA table_info(decoys)')}
        names = ['id', 'decoy_type', 'bind_address', 'port', 'status']
        names.extend(name for name in ('retired_at', 'retirement_reason') if name in columns)
        result = []
        for values in database.execute(f'SELECT {", ".join(names)} FROM decoys ORDER BY id'):
            row = dict(zip(names, values))
            require(type(row['id']) is int and type(row['port']) is int and 0 < row['port'] <= 65535,
                    'Unexpected decoy identity')
            row['bind_address'] = str(ipaddress.IPv4Address(row['bind_address']))
            require(row['status'] in {'active', 'stopped', 'degraded'}, 'Unexpected saved decoy status')
            if row['decoy_type'] not in DECOY_TYPES:
                row['decoy_type_sha256'] = digest_text(row.pop('decoy_type'))
            row['retired'] = bool(row.pop('retired_at', None))
            reason = row.pop('retirement_reason', None)
            if reason:
                allowed = {'removed', 'removed_by_user', 'stopped_after_network_cleanup',
                           'duplicate_source_host', 'source_service_removed', 'provisioning_failed'}
                row['retirement_reason'] = reason if reason in allowed else 'other_private_reason'
                row['retirement_reason_sha256'] = digest_text(reason)
            result.append(row)
            require(len(result) <= 1000, 'Too many saved decoys')
        return result


def scoped_states(text, addresses):
    selected, unrelated, unknown = [], 0, 0
    for line in text.splitlines():
        if not line.strip():
            continue
        endpoints = re.findall(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)', line)
        if not any(ip in addresses for ip, _ in endpoints):
            unrelated += 1
            continue
        pairs = [a + ':' + b for a, b in re.findall(r'\b([A-Z_0-9]+):([A-Z_0-9]+)\b', line)
                 if a in STATES and b in STATES]
        if not re.search(r'\btcp\b', line) or len(pairs) != 1 or not 2 <= len(endpoints) <= 4:
            unknown += 1
            continue
        for ip, port in endpoints:
            ipaddress.IPv4Address(ip)
            require(0 < int(port) <= 65535, 'Unexpected saved state port')
        selected.append(dict(endpoints=[dict(ip=ip, port=int(port)) for ip, port in endpoints],
                             state_pair=pairs[0], line_sha256=digest_text(line)))
    return dict(selected=selected, unrelated_lines=unrelated, unrecognized_scoped_lines=unknown)


def collect_macbook():
    root = private_root(BOOK)
    result = dict(scope='completed-macbook-upgrade', system_mutations=False, archive=BOOK)
    for side in ('before', 'after'):
        result[side] = dict(decoys=saved_database_rows(root / (side + '.sqlite')))
    addresses = {row['bind_address'] for side in ('before', 'after') for row in result[side]['decoys']
                 if row['bind_address'] not in {'192.168.1.97', '0.0.0.0', '127.0.0.1'}}
    for side in ('before', 'after'):
        text = inspector.read_safe(root / ('pf-' + side + '.json'))
        value = json.loads(text)
        result[side].update(source_pf_sha256=digest_text(text),
                            scoped_states=scoped_states(value['states'], addresses),
                            legacy_rdr_pass=len(re.findall(r'^rdr pass\b', value['translations'], re.M)),
                            guarded_uid_pass_rules=len(re.findall(r'^pass .*\buser = (?:309|_squirrelops)\b', value['rules'], re.M)),
                            tagged_rules=len(re.findall(r'\btagged squirrelops_[0-9_]+\b', value['rules'])))
    manifest = read_manifest(root / 'restore-manifest.json')
    entry = manifest.get('/var/db/com.squirrelops.helper')
    result['old_owned_aliases'] = []
    if entry:
        require(re.fullmatch(r'payload-\d{3}', entry['copy']), 'Unexpected saved payload path')
        directory = root / entry['copy']
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe saved helper directory')
        text = inspector.read_safe(directory / 'owned-aliases')
        for line in text.splitlines():
            match = re.fullmatch(r'((?:\d{1,3}\.){3}\d{1,3})\|(en[01])', line)
            require(match is not None, 'Unexpected saved alias ledger format')
            result['old_owned_aliases'].append(dict(ip=str(ipaddress.IPv4Address(match[1])), interface=match[2]))
    result['automatic_gate_pass'] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', choices=('mini', 'macbook'))
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        print(json.dumps(dict(mode='plan_only', host=args.host, system_mutations=False)))
        return
    require(os.geteuid() == 0, 'Run the pinned read-only wrapper with sudo')
    os.umask(0o077)
    result = collect_mini() if args.host == 'mini' else collect_macbook()
    directory = Path(tempfile.mkdtemp(prefix='squirrelops-release-review.', dir='/private/var/tmp'))
    output = directory / 'diagnostic.json'
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    output.chmod(0o644)
    directory.chmod(0o755)
    print('READ-ONLY EXPORT COMPLETE: ' + str(output))
    print('Original evidence and permissions unchanged. No service, database, probe or firewall changes.')


if __name__ == '__main__':
    main()
