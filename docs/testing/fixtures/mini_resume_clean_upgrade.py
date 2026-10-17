"""Resume only the reviewed October 2 partial uninstall, never restart its wipe."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import tempfile

spec = importlib.util.spec_from_file_location('base', Path(__file__).with_name('mini_clean_upgrade.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require = base.require

PRIOR = base.ARCHIVES / 'mini-clean-upgrade-20261002.tvk708n4'
FIX_SHA = '1f2e64b73b20db7cbacf5caf9ac0d79053c7a1db754684dbc96b4e6a9f3166b6'
MARKER_DIR = Path('/var/db/com.squirrelops.sensor')
HELPER_STATE = Path('/var/db/com.squirrelops.helper')
EXPECTED_SOURCES = tuple(str(p) for p in base.TARGETS if p != MARKER_DIR)


def validate_failed_records(records):
    expected = ['/bin/bash', '/Library/SquirrelOps/sensor/uninstall.sh', '--remove-data']
    failed = [r for r in records if r.get('command') == expected]
    require(len(failed) == 1 and failed[0].get('exit') == 1
            and '[!] Could not safely remove the sensor service identity.' in failed[0].get('stdout', ''),
            'Prior attempt is not the reviewed account-teardown failure')
    require(not any(r.get('command', [None])[0] == '/usr/sbin/installer' for r in records),
            'Prior attempt reached installation; do not resume this recovery')


def verify_saved_payloads(prior, snapshots):
    require(tuple(snapshots) == EXPECTED_SOURCES, 'Unexpected original backup scope or order')
    for index, expected in enumerate(snapshots.values()):
        path = prior / f'payload-{index:02}'
        require(base.manifest(path) == base.durable(expected), f'Original backup changed: payload-{index:02}')


class Resume(base.Reset):
    def run(self):
        require(os.geteuid() == 0 and os.isatty(0), 'Run attended with sudo on the Mini')
        os.umask(0o077)
        for p in (Path('/Library/SquirrelOps'), base.ARCHIVES, PRIOR, self.task):
            base.safe_root(p)
        require('d0:11:e5:12:9a:c2' in self.command(['/sbin/ifconfig', 'en0']).stdout,
                'Wrong machine: this operation is for the Mini only')
        for label in base.JOBS:
            require(not self.loaded(label), 'Product job reappeared; no recovery authorized')
        self.no_runtime()
        baseline = self.network()
        manifest_path = PRIOR / 'manifest.json'
        base.safe_root(manifest_path, False)
        require(manifest_path.stat().st_size < 64 * 1024**2, 'Oversized original manifest')
        snapshots = json.loads(manifest_path.read_text())
        verify_saved_payloads(PRIOR, snapshots)
        records = []
        for p in sorted(PRIOR.glob('command-*.json')):
            base.safe_root(p, False)
            require(p.stat().st_size < 4 * 1024**2 and len(records) < 256, 'Oversized command evidence')
            records.append(json.loads(p.read_text()))
        validate_failed_records(records)
        for name in ('removed.json', 'result.json', 'resume-started.json'):
            require(not (PRIOR / name).exists() and not (PRIOR / name).is_symlink(),
                    'Original attempt already advanced or recovery already attempted; review before retry')

        # Validate the exact remaining installation against the verified original
        # archive. No new scan, account rewrite or data restoration is needed.
        base.safe_root(base.SENSOR)
        require(set(p.name for p in base.SENSOR.iterdir()) == set(base.RESIDUE) | {'uninstall.sh'},
                'Remaining sensor files differ from the reviewed partial uninstall')
        for p in base.SENSOR.iterdir():
            base.safe_root(p, False)
            require(base.manifest(p)['.'] == snapshots[str(base.SENSOR)].get(p.name),
                    f'Remaining original file changed: {p.name}')
        for p in base.TARGETS:
            if p not in (base.SENSOR, MARKER_DIR, HELPER_STATE):
                require(not p.exists() and not p.is_symlink(), f'Removed path reappeared: {p}')
        base.safe_root(HELPER_STATE)
        require(not list(HELPER_STATE.iterdir()), 'Helper ownership state is no longer empty')
        base.safe_root(MARKER_DIR)
        require({p.name for p in MARKER_DIR.iterdir()} == {'account-deprovisioning'},
                'Unexpected account lifecycle state')
        marker = MARKER_DIR / 'account-deprovisioning'
        base.safe_root(marker, False)
        require(marker.read_bytes() == b'309\n' and marker.stat().st_mode & 0o777 == 0o600,
                'Account deprovisioning marker changed')
        require(pwd.getpwnam('_squirrelops').pw_uid == 309, 'Service UID changed')

        package, fixed = self.task / 'old.pkg', self.task / 'uninstall-fixed.sh'
        for p in (package, fixed):
            base.safe_root(p, False)
        require(base.digest(package) == base.OLD_SHA and base.digest(fixed) == FIX_SHA,
                'Recovery input digest changed')
        self.backup = Path(tempfile.mkdtemp(prefix='resume-', dir=PRIOR))
        self.command(['/usr/sbin/pkgutil', '--check-signature', str(package)])
        self.command(['/usr/sbin/spctl', '-a', '-vv', '-t', 'install', str(package)])
        for kind in ('Users', 'Groups'):
            self.command(['/usr/bin/dscl', '.', '-read', f'/{kind}/_squirrelops'])
        (self.backup / 'marker-before.txt').write_bytes(marker.read_bytes())
        print(f'Original seven-path recovery archive verified: {PRIOR}', flush=True)
        print(f'Private resume evidence: {self.backup}', flush=True)
        print('Resume only remaining account/helper-state cleanup; then install original 2.0.3.', flush=True)
        self.no_runtime()
        require(self.network() == baseline, 'Network changed before recovery')
        with (PRIOR / 'resume-started.json').open('x') as claim:
            json.dump(dict(evidence=str(self.backup), corrected_uninstaller_sha256=FIX_SHA), claim)
            claim.flush()
            os.fsync(claim.fileno())
        self.mutated = True
        result = self.command(['/bin/bash', str(fixed), '--remove-data'], timeout=600, check=False)
        # Surface only the uninstaller's own operator messages, not private
        # account or database records from other command logs.
        for line in result.stdout.splitlines():
            if line.startswith(('[+]', '[!]')):
                print(line, flush=True)
        require(result.returncode == 0, 'Corrected uninstall failed; see private resume evidence')
        self.finish_uninstall_and_install(snapshots, baseline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode='plan_only', original_archive=str(PRIOR),
                              corrected_uninstaller_sha256=FIX_SHA, upgrade_run=False), indent=2))
        return
    session = Resume(args.run)
    try:
        session.run()
    except (Exception, KeyboardInterrupt) as exc:
        print(f'STOPPED: {type(exc).__name__}: {exc}', flush=True)
        if session.installing:
            print('Installer outcome uncertain. No automatic service changes; wait for review.', flush=True)
        elif session.mutated:
            try:
                session.stop()
                print('Product jobs stopped/disabled; no automatic restore or PF reset.', flush=True)
            except Exception as cleanup:
                print(f'Stopped state NOT verified: {cleanup}. Do not reset networking.', flush=True)
        print(f'Original archive retained: {PRIOR}; resume evidence: {session.backup}. Do not rerun.', flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
