"""Attended Mini reset and official 2.0.3 baseline. No upgrade or PF probes yet."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time

SENSOR = Path('/Library/SquirrelOps/sensor')
APP = Path('/Applications/SquirrelOps Home.app')
ARCHIVES = Path('/Library/SquirrelOps/acceptance-backups')
JOBS = ('com.squirrelops.sensor', 'com.squirrelops.helper')
OLD_SHA = '252bd6bd559b4dbf578410aa959611675d3b627163ee885f404857cb67ab23f8'
UNINSTALL_SHA = '64e1289ad27eacd32cf537ca615fb2a972f62a4d20e2becb3ee124e1ef425dc5'
TARGETS = (
    APP, SENSOR, Path('/Library/SquirrelOps/backups'),
    Path('/Library/PrivilegedHelperTools/com.squirrelops.helper'),
    Path('/Library/LaunchDaemons/com.squirrelops.helper.plist'),
    Path('/Library/LaunchDaemons/com.squirrelops.sensor.plist'),
    Path('/var/db/com.squirrelops.helper'), Path('/var/db/com.squirrelops.sensor'),
)
RESIDUE = ('build-requirements.lock', 'requirements.lock', 'release-components.json')
CONFIG = '''profile: lite
sensor:
  name: Mini 2.0.3 Upgrade Acceptance
  data_dir: /Library/SquirrelOps/sensor/data
  port: 8443
network:
  interface: en0
  subnet: 192.168.1.0/24
scouts:
  enabled: false
home_assistant:
  enabled: false
pairing:
  local_enrollment_enabled: true
'''


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_root(path, directory=True):
    s = path.lstat()
    require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
            and s.st_uid == 0 and not s.st_mode & 0o022,
            f'Unsafe root-owned path: {path}')
    if not directory:
        require(s.st_nlink == 1, f'Linked input: {path}')


def manifest(root):
    """Never follow links; transient Unix sockets are explicitly not restored."""
    result, pending = {}, [(root, '.')]
    while pending:
        path, key = pending.pop()
        s = path.lstat()
        require(len(result) < 200000, 'Backup exceeds file-count bound')
        entry = dict(mode=stat.S_IMODE(s.st_mode), uid=s.st_uid, gid=s.st_gid)
        if stat.S_ISDIR(s.st_mode):
            entry['kind'] = 'directory'
            pending.extend((p, str(p.relative_to(root))) for p in path.iterdir())
        elif stat.S_ISREG(s.st_mode):
            entry.update(kind='file', size=s.st_size, sha256=digest(path))
        elif stat.S_ISLNK(s.st_mode):
            entry.update(kind='link', target=os.readlink(path))
        elif stat.S_ISSOCK(s.st_mode):
            entry.update(kind='socket', omitted=True)
        else:
            raise RuntimeError(f'Unsupported backup object: {path}')
        result[key] = entry
    return result


def durable(items):
    return {name: entry for name, entry in items.items() if entry['kind'] != 'socket'}


def copy_tree(source, target, items, command):
    # Copy each normal subtree in one invocation, not thousands of per-file
    # subprocesses. Split only ancestors of transient sockets.
    if not any(entry['kind'] == 'socket' for entry in items.values()):
        command(['/usr/bin/ditto', str(source), str(target)], timeout=120)
        return
    require(items['.']['kind'] == 'directory', 'Socket cannot be a backup root')
    target.mkdir(mode=0o700)
    for child in source.iterdir():
        key = child.name
        if items[key]['kind'] == 'socket':
            continue
        subset = {'.': items[key]}
        subset.update({name[len(key) + 1:]: entry for name, entry in items.items()
                       if name.startswith(key + '/')})
        copy_tree(child, target / key, subset, command)
    shutil.copystat(source, target, follow_symlinks=False)
    os.chown(target, items['.']['uid'], items['.']['gid'])


def parse_loaded(r, label):
    if r.returncode == 0:
        require(r.stdout.startswith(f'system/{label} = {{'), 'Uncertain launchd response')
        return True
    require(f'Could not find service "{label}"' in r.stderr, 'Uncertain launchd failure')
    return False


class Reset:
    def __init__(self, task):
        self.task = task
        self.backup = None
        self.index = 0
        self.mutated = False
        self.installing = False

    def command(self, args, *, timeout=90, check=True):
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if self.backup:
            self.index += 1
            (self.backup / f'command-{self.index:03}.json').write_text(json.dumps(
                dict(command=args, exit=r.returncode, stdout=r.stdout, stderr=r.stderr), indent=2))
        require(not check or r.returncode == 0, f'Command failed: {args[0]}; see private evidence')
        return r

    def loaded(self, label):
        require(label in JOBS, 'Unexpected service target')
        return parse_loaded(self.command(['/bin/launchctl', 'print', 'system/' + label], check=False), label)

    def no_runtime(self):
        r = self.command(['/bin/ps', '-axo', 'uid=,pid=,comm='])
        try:
            uid = pwd.getpwnam('_squirrelops').pw_uid
        except KeyError:
            uid = None
        for line in r.stdout.splitlines():
            # Some system entries have an empty comm; UID and PID still suffice.
            fields = line.strip().split(None, 2)
            # Darwin ps can render an unsigned uid_t as signed decimal, e.g.
            # nobody (4294967294) appears as -2. Do not discard those rows or
            # confuse the signed display with a different process owner.
            require(len(fields) >= 2 and re.fullmatch(r'-?[0-9]+', fields[0])
                    and re.fullmatch(r'[0-9]+', fields[1]), 'Malformed process inventory')
            raw_uid, pid = int(fields[0]), int(fields[1])
            require(-(2**31) <= raw_uid < 2**32 and 0 <= pid < 2**31,
                    'Malformed process inventory')
            process_uid = raw_uid % (2**32)
            command = fields[2] if len(fields) == 3 else ''
            require(not (uid is not None and process_uid == uid and command != '/usr/sbin/distnoted')
                    and not command.startswith((str(SENSOR) + '/', str(APP) + '/'))
                    and command != '/Library/PrivilegedHelperTools/com.squirrelops.helper',
                    'SquirrelOps still running; no reset authorized while active')

    def network(self):
        info = self.command(['/sbin/pfctl', '-s', 'info']).stdout
        require(re.search(r'^Status: Disabled\b', info, re.M), 'PF is not disabled; review before reset')
        refs = self.command(['/sbin/pfctl', '-s', 'References'])
        require('No pf starter references held' in refs.stdout + refs.stderr,
                'Existing PF reference needs review; no release attempted')
        addresses = self.command(['/sbin/ifconfig', '-a']).stdout
        require(not re.search(r'\binet 192\.168\.1\.(?:239|240|241)\s', addresses),
                'Test alias remains; no reset authorized')
        return {flag: self.command(['/sbin/pfctl', flag]).stdout for flag in ('-sr', '-sn')}

    def stop(self):
        for label in JOBS:
            self.command(['/bin/launchctl', 'disable', 'system/' + label])
            if self.loaded(label):
                self.command(['/bin/launchctl', 'bootout', 'system/' + label], check=False)
                deadline = time.monotonic() + (70 if label == JOBS[0] else 10)
                while self.loaded(label):
                    require(time.monotonic() < deadline, 'Service did not stop; retain state for review')
                    time.sleep(1)
        self.no_runtime()

    def run(self):
        require(os.geteuid() == 0 and os.isatty(0), 'Run attended with sudo on the Mini')
        os.umask(0o077)
        for p in (Path('/Library/SquirrelOps'), ARCHIVES, self.task):
            safe_root(p)
        require('d0:11:e5:12:9a:c2' in self.command(['/sbin/ifconfig', 'en0']).stdout,
                'Wrong machine: this operation is for the Mini only')
        package, uninstall = self.task / 'old.pkg', SENSOR / 'uninstall.sh'
        safe_root(package, False)
        safe_root(uninstall, False)
        require(digest(package) == OLD_SHA and digest(uninstall) == UNINSTALL_SHA, 'Input identity changed')
        for label in JOBS:
            require(not self.loaded(label), 'Stop SquirrelOps before resetting')
        self.no_runtime()
        baseline = self.network()
        self.backup = Path(tempfile.mkdtemp(prefix='mini-clean-upgrade-20261002.', dir=ARCHIVES))
        print(f'Private recovery archive: {self.backup}', flush=True)
        self.command(['/usr/sbin/pkgutil', '--check-signature', str(package)])
        self.command(['/usr/sbin/spctl', '-a', '-vv', '-t', 'install', str(package)])
        for kind in ('Users', 'Groups'):
            self.command(['/usr/bin/dscl', '.', '-read', f'/{kind}/_squirrelops'], check=False)
        for name in ('app', 'sensor'):
            self.command(['/usr/sbin/pkgutil', '--pkg-info-plist', f'com.squirrelops.home.{name}'])
        self.command(['/bin/launchctl', 'print-disabled', 'system'])
        snapshots = {}
        for source in TARGETS:
            if not source.exists() and not source.is_symlink():
                continue
            safe_root(source, source.is_dir())
            snapshots[str(source)] = manifest(source)
        total = sum(e.get('size', 0) for m in snapshots.values() for e in m.values())
        require(shutil.disk_usage(ARCHIVES).free > total + 2 * 1024**3, 'Insufficient backup/install space')
        for number, (source, expected) in enumerate(snapshots.items()):
            target = self.backup / f'payload-{number:02}'
            copy_tree(Path(source), target, expected, self.command)
            require(manifest(target) == durable(expected) and manifest(Path(source)) == expected,
                    'Backup differs from source; nothing removed')
        (self.backup / 'manifest.json').write_text(json.dumps(snapshots, indent=2))
        (self.backup / 'rollback.txt').write_text(
            'No automatic rollback. Reinstall the pinned previous 2.1 package to recreate its service identity; '
            'stop both jobs, verify UID/GID against manifest.json, and restore selected payloads only after review. '
            'Never restore sockets or blindly reinstate owned-alias/PF state. Archive includes the old data, '
            'configuration, app/runtime/helper and package rollback snapshots. Prior acceptance backups are untouched.\n')
        self.no_runtime()
        require(self.network() == baseline, 'Network changed before removal')
        print(f'Verified {len(snapshots)} SquirrelOps paths ({total} file bytes). Removing only product files/data.', flush=True)
        self.mutated = True
        self.command(['/bin/bash', str(uninstall), '--remove-data'], timeout=600)
        self.finish_uninstall_and_install(snapshots, baseline)

    def finish_uninstall_and_install(self, snapshots, baseline):
        package = self.task / 'old.pkg'
        require(not APP.exists(), 'App removal incomplete')
        for source in TARGETS[2:]:
            require(not source.exists() and not source.is_symlink(), f'Removal incomplete: {source}')
        # The reviewed uninstaller leaves these three immutable package metadata files.
        if SENSOR.exists():
            safe_root(SENSOR)
            require(set(p.name for p in SENSOR.iterdir()) <= set(RESIDUE), 'Unexpected uninstall residue')
            for p in SENSOR.iterdir():
                safe_root(p, False)
                expected = snapshots[str(SENSOR)].get(p.name)
                require(expected and manifest(p)['.'] == expected, 'Changed package metadata residue')
                p.unlink()
            SENSOR.rmdir()
        self.no_runtime()
        require(self.network() == baseline, 'Network changed after uninstall; no installer run')
        (self.backup / 'removed.json').write_text(json.dumps(dict(paths=[str(p) for p in TARGETS])))
        SENSOR.mkdir(mode=0o755)
        (SENSOR / 'config.yaml').write_text(CONFIG)
        for label in JOBS:
            self.command(['/bin/launchctl', 'enable', 'system/' + label])
        print('Installing official, unmodified 2.0.3. Lite profile; Scouts off; normal LAN discovery may run.', flush=True)
        self.installing = True
        # Do not kill the installer client on a timer while PackageKit may
        # still be changing the installation in its separate daemon.
        installed = self.command(['/usr/sbin/installer', '-pkg', str(package), '-target', '/'],
                                 timeout=None, check=False)
        self.installing = False
        require(installed.returncode == 0, 'Official 2.0.3 installer failed; see private evidence')
        require((SENSOR / 'VERSION').read_text().strip() == '2.0.3', 'Unexpected installed sensor version')
        app_version = self.command(['/usr/libexec/PlistBuddy', '-c', 'Print :CFBundleShortVersionString',
                                    str(APP / 'Contents/Info.plist')]).stdout.strip()
        require(app_version == '2.0.3', 'Unexpected installed app version')
        require((SENSOR / 'config.yaml').read_text() == CONFIG, 'Installer changed bounded baseline config')
        deadline = time.monotonic() + 90
        while True:
            r = self.command(['/usr/bin/curl', '-ksS', '--max-time', '3',
                              'https://127.0.0.1:8443/system/health'], check=False)
            try:
                healthy = r.returncode == 0 and json.loads(r.stdout).get('status') == 'ok'
            except (ValueError, AttributeError):
                healthy = False
            if healthy:
                break
            require(time.monotonic() < deadline, '2.0.3 health did not pass; see private logs')
            time.sleep(1)
        print('2.0.3 startup passed. Stopping this baseline; upgrade has NOT run yet.', flush=True)
        self.stop()
        require(self.network() == baseline, 'Network changed; stopped installation retained for review')
        for label in JOBS:
            require(not self.loaded(label), 'Product job remains loaded')
        (self.backup / 'result.json').write_text(json.dumps(dict(
            status='old_baseline_installed_stopped', old_package_sha256=OLD_SHA,
            app_version=app_version, health_passed=True, upgrade_run=False), indent=2))
        print('BASELINE READY: 2.0.3 installed and startup verified; both jobs stopped/disabled.', flush=True)
        print('Keep SquirrelOps closed. Recovery archive and previous acceptance evidence retained.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode='plan_only', host='100.108.203.27', targets=list(map(str, TARGETS)),
                              old_package_sha256=OLD_SHA, upgrade_run=False), indent=2))
        return
    reset = Reset(args.run)
    try:
        reset.run()
    except (Exception, KeyboardInterrupt) as exc:
        print(f'STOPPED: {type(exc).__name__}: {exc}', flush=True)
        if reset.installing:
            print('Installer outcome uncertain. No automatic service changes; wait for review.', flush=True)
        elif reset.mutated:
            try:
                reset.stop()
                print('Product jobs stopped/disabled; no automatic restore or PF reset.', flush=True)
            except Exception as cleanup:
                print(f'Stopped state NOT verified: {cleanup}. Do not reset networking.', flush=True)
        print(f'Private evidence: {reset.backup}. Do not rerun automatically.', flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
