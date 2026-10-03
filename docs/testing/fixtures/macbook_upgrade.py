"""One attended, data-preserving 2.0.3 to 2.1 upgrade on the approved MacBook.

No uninstall, SQL/config edits, manual service stops, PF writes or client probes.
The package owns its normal lifecycle. Evidence is private; status is sanitized.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location(
    'backup_helpers', Path(__file__).with_name('mini_clean_upgrade.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require = base.require

PACKAGE_SHA = '669e4b2b5762f819b4b07c4f5cddc5b6797bae4cd7519282280ee049d3533c17'
MAC = 'ae:29:0a:e5:cc:c5'
ADDRESS = '192.168.1.97'
APP = Path('/Applications/SquirrelOps Home.app')
SENSOR = Path('/Library/SquirrelOps/sensor')
DATABASE = SENSOR / 'data/squirrelops.db'
ARCHIVES = Path('/Library/SquirrelOps/acceptance-backups')
ANCHOR = 'com.apple/squirrelops'
TABLES = {
    'devices': ('id', 'mac_address', 'custom_name', 'notes'),
    'device_trust': ('device_id', 'status', 'approved_by'),
    'decoys': ('id', 'name', 'decoy_type', 'bind_address', 'port'),
    'home_alerts': ('id', 'alert_type', 'created_at'),
    'pairing': ('id', 'client_cert_fingerprint', 'status'),
    'planted_credentials': ('id', 'credential_type', 'credential_value', 'decoy_id'),
}
SNAPSHOT_WORKER = '''import sqlite3, sys, time
from contextlib import closing
deadline = time.monotonic() + 60
def progress(*_):
    if time.monotonic() > deadline:
        raise RuntimeError("SQLite backup deadline expired")
with closing(sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)) as source:
    source.execute("PRAGMA trusted_schema=OFF")
    with closing(sqlite3.connect(":memory:")) as target:
        source.backup(target, pages=256, progress=progress)
        payload = target.serialize()
        if len(payload) > 512 * 1024**2:
            raise RuntimeError("Snapshot exceeds the approved memory bound")
        sys.stdout.buffer.write(payload)
'''


def preserved_rows(connection):
    """Private values only, never print credentials, names or fingerprints."""
    return {table: set(connection.execute(
        f'SELECT {", ".join(columns)} FROM {table}').fetchall())
        for table, columns in TABLES.items()}


def compare_rows(before, after):
    require(before.keys() == after.keys() == TABLES.keys(), 'Preservation table mismatch')
    counts = {}
    for table in TABLES:
        missing = before[table] - after[table]
        require(not missing, f'Preservation mismatch in {table}: {len(missing)} saved rows')
        counts[table] = dict(saved=len(before[table]), current=len(after[table]), preserved=True)
    return counts


def check_translation(text, *, after):
    legacy = len(re.findall(r'^rdr pass\b', text, re.M))
    translated = len(re.findall(r'^rdr\b', text, re.M))
    if after:
        require(legacy == 0, 'Old unconditional rdr pass rule survived upgrade')
    return dict(legacy_rdr_pass=legacy, translations=translated)


class Upgrade:
    def __init__(self, task):
        self.task = task
        self.backup = None
        self.public = None
        self.index = 0
        self.manifests = {}
        self.install_started = False

    def command(self, args, *, check=True, timeout=90):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if self.backup:
            self.index += 1
            (self.backup / f'command-{self.index:03}.json').write_text(json.dumps(dict(
                command=args, exit=result.returncode, stdout=result.stdout, stderr=result.stderr)))
        require(not check or result.returncode == 0, f'Command failed: {args[0]}; see private evidence')
        return result

    def publish(self, phase, **details):
        result = dict(phase=phase, package_sha256=PACKAGE_SHA, **details)
        if self.public:
            pending = self.public / 'status.pending'
            pending.write_text(json.dumps(result, indent=2) + '\n')
            pending.chmod(0o644)
            pending.replace(self.public / 'status.json')
        print(phase, flush=True)

    def health(self):
        result = self.command(['/usr/bin/curl', '--noproxy', '*', '-kfsS',
                               '--connect-timeout', '3', '--max-time', '8',
                               'https://127.0.0.1:8443/system/health'], check=False)
        try:
            return result.returncode == 0 and json.loads(result.stdout).get('status') == 'ok'
        except ValueError:
            return False

    def version(self):
        with (APP / 'Contents/Info.plist').open('rb') as stream:
            return plistlib.load(stream)['CFBundleShortVersionString']

    def network(self, name):
        outputs = {}
        for label, args in {
            'rules': ['-a', ANCHOR, '-sr'],
            'translations': ['-a', ANCHOR, '-sn'],
            'states': ['-a', ANCHOR, '-ss'],
            'references': ['-s', 'References'],
            'info': ['-s', 'info'],
        }.items():
            outputs[label] = self.command(['/sbin/pfctl', *args]).stdout
        (self.backup / f'pf-{name}.json').write_text(json.dumps(outputs, indent=2))
        self.command(['/sbin/ifconfig', '-a'])
        return outputs

    def copy(self, source):
        require(not source.is_symlink(), f'Linked backup root: {source}')
        target = self.backup / f'payload-{len(self.manifests):03}'
        before = base.manifest(source)
        base.copy_tree(source, target, before, self.command)
        require(base.durable(before) == base.durable(base.manifest(target))
                and before == base.manifest(source), f'Unstable backup: {source}')
        self.manifests[str(source)] = dict(copy=target.name, entries=before)

    def db_snapshot(self, name):
        metadata = DATABASE.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_uid == pwd.getpwnam('_squirrelops').pw_uid
                and not metadata.st_mode & 0o022, 'Unsafe database')
        target_path = self.backup / name
        require(metadata.st_size <= 256 * 1024**2, 'Database exceeds the bounded backup scope')
        # Read the live WAL database under its owner, never root. A read-only
        # SQLite connection may still create SHM/WAL coordination files. Send
        # the consistent memory snapshot directly into a root-private file;
        # the service account never gains access to the recovery archive.
        with target_path.open('xb') as output:
            result = subprocess.run(['/usr/bin/sudo', '-u', '_squirrelops',
                                     str(SENSOR / 'python/bin/python3'), '-I', '-B', '-c',
                                     SNAPSHOT_WORKER, str(DATABASE)], stdout=output,
                                    stderr=subprocess.PIPE, timeout=80)
        target_path.chmod(0o600)
        (self.backup / (name + '.stderr')).write_bytes(result.stderr)
        require(result.returncode == 0, 'Service-owned SQLite snapshot failed; see private evidence')
        with closing(sqlite3.connect(target_path)) as target:
            target.execute('PRAGMA trusted_schema=OFF')
            require(target.execute('PRAGMA integrity_check').fetchone() == ('ok',),
                    'SQLite backup failed integrity check')
            return preserved_rows(target)

    def run(self):
        require(os.geteuid() == 0 and os.isatty(0), 'Use the attended sudo bootstrap')
        require(self.task.parent == Path('/private/var/root')
                and self.task.name.startswith('squirrelops-macbook-upgrade.'), 'Wrong staging path')
        base.safe_root(self.task)
        require(base.digest(self.task / 'candidate.pkg') == PACKAGE_SHA, 'Candidate checksum mismatch')
        require(base.digest(self.task / 'old.pkg') == base.OLD_SHA, 'Recovery package checksum mismatch')
        require(self.command(['/usr/bin/uname', '-m']).stdout.strip() == 'arm64', 'Wrong architecture')
        require(self.command(['/usr/bin/sw_vers', '-buildVersion']).stdout.strip() == '25G76', 'OS drift')
        interface = self.command(['/sbin/ifconfig', 'en0']).stdout
        require(f'ether {MAC}' in interface and f'inet {ADDRESS} ' in interface, 'Wrong MacBook')
        require(self.version() == '2.0.3' and (SENSOR / 'VERSION').read_text().strip() == '2.0.3',
                'Expected installed 2.0.3; do not rerun after an attempted upgrade')
        require(self.command(['/usr/bin/pgrep', '-x', 'SquirrelOpsHome'], check=False).returncode == 1,
                'Quit the SquirrelOps desktop app before running this command')
        require(self.health(), 'Old sensor is not healthy')
        for path in (ARCHIVES.parent, SENSOR, APP):
            base.safe_root(path)
        data = (SENSOR / 'data').lstat()
        require(stat.S_ISDIR(data.st_mode) and data.st_uid == pwd.getpwnam('_squirrelops').pw_uid
                and not data.st_mode & 0o077, 'Unsafe data directory')
        if not ARCHIVES.exists():
            ARCHIVES.mkdir(mode=0o700)
        base.safe_root(ARCHIVES)
        require(shutil.disk_usage(ARCHIVES).free > 5 * 1024**3, 'Less than 5 GiB backup headroom')
        self.backup = Path(tempfile.mkdtemp(prefix='macbook-upgrade-20261002.', dir=ARCHIVES))
        self.public = Path(tempfile.mkdtemp(prefix='squirrelops-macbook-upgrade.', dir='/private/var/tmp'))
        self.public.chmod(0o755)
        print(f'Private recovery archive: {self.backup}', flush=True)
        print(f'Sanitized progress: {self.public}/status.json', flush=True)
        self.publish('Preparing verified backup; installed services unchanged')
        for label in base.JOBS:
            self.command(['/bin/launchctl', 'print', 'system/' + label])
        self.command(['/bin/launchctl', 'print-disabled', 'system'])
        for record in ('/Users/_squirrelops', '/Groups/_squirrelops'):
            self.command(['/usr/bin/dscl', '.', '-read', record])
        before_pf = self.network('before')
        translation_before = check_translation(before_pf['translations'], after=False)
        paths = [APP, Path('/Library/PrivilegedHelperTools/com.squirrelops.helper')]
        paths.extend(Path('/Library/LaunchDaemons') / f'{label}.plist' for label in base.JOBS)
        paths.extend(path for path in SENSOR.iterdir() if path.name not in {'data', 'logs', 'run'})
        # Preserve every other durable data entry, but use SQLite's live backup
        # API for the main database. Raw WAL/SHM copies are not a recovery image.
        paths.extend(path for path in (SENSOR / 'data').iterdir()
                     if path.name not in {'squirrelops.db', 'squirrelops.db-wal', 'squirrelops.db-shm'})
        for directory in ('/var/db/com.squirrelops.helper', '/var/db/com.squirrelops.sensor'):
            if Path(directory).exists():
                paths.append(Path(directory))
        for path in paths:
            self.copy(path)
        saved_rows = self.db_snapshot('before.sqlite')
        with closing(sqlite3.connect(self.backup / 'before.sqlite')) as snapshot:
            active_ids = {row[0] for row in snapshot.execute("SELECT id FROM decoys WHERE status='active'")}
        config_sha = base.digest(SENSOR / 'config.yaml')
        shutil.copyfile(self.task / 'old.pkg', self.backup / 'recovery-2.0.3.pkg')
        require(base.digest(self.backup / 'recovery-2.0.3.pkg') == base.OLD_SHA, 'Recovery copy mismatch')
        (self.backup / 'restore-manifest.json').write_text(json.dumps(self.manifests, indent=2))
        (self.backup / 'RECOVERY.txt').write_text(
            'No automatic downgrade. Review the private installer log first.\n'
            'For recovery, stop only product jobs, verify owned network withdrawal, '
            'then reinstall the saved official 2.0.3 package on this macOS 26 Mac. '
            'Stop product jobs again before restoring config, durable data and before.sqlite '
            'using restore-manifest.json and the original service UID/GID. '
            'Never let 2.0.3 open a migrated 2.1 database. '
            'Do not restore transient sockets, PF references, rules or alias ownership blindly.\n')
        self.publish('BACKUP VERIFIED; installing pinned 2.1.0',
                     saved_counts={name: len(rows) for name, rows in saved_rows.items()},
                     old_translation=translation_before)
        marker = Path('/var/db/com.squirrelops.allow-local-test')
        require(not marker.exists() and not marker.is_symlink(), 'Unexpected local-test marker')
        self.command(['/usr/bin/install', '-o', 'root', '-g', 'wheel', '-m', '600', '/dev/null', str(marker)])
        self.install_started = True
        # Do not timeout/kill PackageKit and then race its ongoing transaction.
        with (self.backup / 'installer.log').open('w') as log:
            result = subprocess.run(['/usr/sbin/installer', '-pkg', str(self.task / 'candidate.pkg'),
                                     '-target', '/'], stdout=log, stderr=subprocess.STDOUT)
        require(result.returncode == 0, 'Installer failed; private log retained; do not rerun')
        require(not marker.exists(), 'Installer did not consume opt-in')
        deadline = time.monotonic() + 1200
        self.publish('Installer completed; waiting for restored sensor health')
        consecutive = 0
        while consecutive < 2:
            consecutive = consecutive + 1 if self.health() else 0
            require(time.monotonic() < deadline, 'Sensor startup deadline expired; retain evidence')
            time.sleep(3)
        require(self.version() == '2.1.0' and (SENSOR / 'VERSION').read_text().strip() == '2.1.0',
                'Installed component version mismatch')
        require(base.digest(SENSOR / 'config.yaml') == config_sha, 'Configuration changed; review required')
        after_rows = self.db_snapshot('after.sqlite')
        counts = compare_rows(saved_rows, after_rows)
        with closing(sqlite3.connect(self.backup / 'after.sqlite')) as snapshot:
            restored_ids = {row[0] for row in snapshot.execute("SELECT id FROM decoys WHERE status='active'")}
        require(active_ids <= restored_ids, 'Previously active decoys are not all active after startup')
        for label in base.JOBS:
            result = self.command(['/bin/launchctl', 'print', 'system/' + label])
            require(re.search(r'^\s*state = running$', result.stdout, re.M), 'Product job is not running')
        after_pf = self.network('after')
        translation_after = check_translation(after_pf['translations'], after=True)
        require(translation_after['translations'] >= translation_before['translations'],
                'Fewer PF translations after upgrade; restoration needs review')
        self.publish('UPGRADE VERIFIED: 2.0.3 to 2.1.0; sensor healthy; saved records preserved',
                     preservation=counts, configuration_preserved=True,
                     old_translation=translation_before, new_translation=translation_after,
                     lan_protocol_tests='not_run', retained_state_migration='not_yet_correlated')
        print('Recovery archive retained. Open the app for pairing/UI acceptance. No uninstall or PF reset.', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode='plan_only', host=ADDRESS, package_sha256=PACKAGE_SHA,
                              preserve_data=True, uninstall=False, manual_pf_writes=False)))
        return
    os.umask(0o077)
    session = Upgrade(args.run)
    try:
        session.run()
    except Exception as exc:
        session.publish('STOPPED: review required', error=str(exc), install_started=session.install_started)
        print(f'Private evidence: {session.backup}. No automatic rerun, downgrade or networking reset.', flush=True)
        raise SystemExit(1) from exc


if __name__ == '__main__':
    main()
