"""Read-only, exact-run diagnostic export. Never starts services or changes filters.

Only derived, allowlisted fields leave the private evidence directories. Packet
summaries have no payloads. Unknown log messages and tracebacks are not exported.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

BACKUP = Path('/Library/SquirrelOps/acceptance-backups/mini-post-reboot-20260930._a_bdeaf')
RECEIPT = Path('/private/var/tmp/squirrelops-mini-reference-cleanup-results.22mxy1fp/status.json')
RECEIPT_SHA = '3a0a7c6a63e73b779d7e3552c9e2fdf42c67acb80676960d27813b61cc488cfc'
LOG = Path('/Library/SquirrelOps/sensor/logs/squirrelops-sensor.log')
CLIENT, VIP = '192.168.1.7', '192.168.1.240'
PORTS = {22, 445, 11434, 1234, 8765, 49878, 49879, 49880, 49881, 49882}
LS = '/Applications/Little Snitch.app/Contents/Components/littlesnitch'
LISTENERS = ['/usr/sbin/lsof', '-nP', '-iTCP', '-sTCP:LISTEN', '-Fpun']
PACKET = re.compile(r'(2026-09-30 \d{2}:\d{2}:\d{2}\.\d{1,9}) IP (192\.168\.1\.(?:7|240))\.(\d+) > (192\.168\.1\.(?:7|240))\.(\d+): tcp (\d+)')
LOG_LINE = re.compile(r'(2026-09-30 (?:12|16):(?:1[2-9]|2[0-7]):\d{2},\d{3}) \[(INFO|WARNING|ERROR|CRITICAL)\] ([a-zA-Z0-9_.]+): (.*)')
EVENTS = (
    ('guest_exit', r'Deep-decoy runtime exited unexpectedly with status (-?\d+)'),
    ('deep_active', r'Studio Mini deep decoy active at 192\.168\.1\.240'),
    ('classic_activation', r'Activated (\d+) classic decoys \((\d+) recovered, (\d+) newly deployed\)'),
    ('classic_deployed', r"Deployed decoy '.*' \(id=(\d+)\) on port (\d+)"),
    ('classic_resumed', r'Resumed (\d+) active decoys from database'),
    ('unknown_service', r'Discarding deep-decoy telemetry for unknown service port (\d+)'),
    ('mdns_failed', r'Deep-decoy mDNS registration failed for port (\d+)'),
    ('activation_failed', r'Deep-decoy activation failed'),
    ('invalid_telemetry', r'Deep-decoy runtime emitted invalid telemetry'),
    ('oversized_telemetry', r'Deep-decoy runtime emitted an oversized telemetry record'),
    ('callback_failed', r'Deep-decoy runtime telemetry callback failed'),
    ('quarantine_failed', r'Deep-decoy quarantine failed after runtime exit'),
    ('server_shutdown', r'(?:Shutting down|Waiting for application shutdown\.|Application shutdown complete\.)'),
    ('server_exit', r'Finished server process \[(\d+)\]'),
)
EXCEPTIONS = ('PermissionError', 'TimeoutError', 'ConnectionResetError', 'ConnectionRefusedError', 'BrokenPipeError', 'OSError', 'RuntimeError', 'ValueError')


def check_parents(path: Path):
    # Parent checks include every component, not just the leaf. No symlink or
    # shared-writable path is accepted, including rotating logs.
    for parent in reversed(path.parents):
        meta = parent.lstat()
        shared_temp = parent == Path('/private/var/tmp') and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o1777
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, 309) or (meta.st_mode & 0o022 and not shared_temp):
            raise RuntimeError('Unsafe evidence parent')


def read_safe(path: Path, *, owners=(0,), limit=16 * 1024 * 1024) -> bytes:
    check_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid not in owners or meta.st_mode & 0o022 or meta.st_nlink != 1 or meta.st_size > limit:
            raise RuntimeError('Unsafe or oversized evidence file')
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(chunk)
            if len(data) > limit:
                raise RuntimeError('Evidence grew beyond limit')
        after = os.fstat(fd)
        if (meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('Evidence changed during read')
        return bytes(data)
    finally:
        os.close(fd)


def packets(data: str) -> dict:
    groups, rejected = {}, 0
    for line in data.splitlines():
        m = PACKET.fullmatch(line.strip())
        if not m:
            rejected += 1
            continue
        stamp, src, sport, dst, dport, size = m.groups()
        sport, dport, size = int(sport), int(dport), int(size)
        if {src, dst} != {CLIENT, VIP} or not (0 < sport <= 65535 and 0 < dport <= 65535) or size > 65535:
            rejected += 1
            continue
        port = sport if src == VIP else dport
        if port not in PORTS:
            rejected += 1
            continue
        direction = 'from_decoy' if src == VIP else 'to_decoy'
        key = (port, direction)
        row = groups.setdefault(key, dict(port=port, direction=direction, packets=0, tcp_payload_bytes_with_retransmits=0, first=stamp, last=stamp))
        row['packets'] += 1
        row['tcp_payload_bytes_with_retransmits'] += size
        row['first'], row['last'] = min(row['first'], stamp), max(row['last'], stamp)
    return dict(groups=[groups[k] for k in sorted(groups)], unparsed_or_out_of_scope_lines=rejected)


def log_events(data: str) -> dict:
    events, unknown, exceptions, active = [], {}, {}, False
    for line in data.splitlines():
        m = LOG_LINE.fullmatch(line)
        if not m:
            if re.match(r'\d{4}-\d{2}-\d{2} ', line):
                active = False
            elif active:
                for name in EXCEPTIONS:
                    if line.startswith(name + ':'):
                        exceptions[name] = exceptions.get(name, 0) + 1
            continue
        stamp, level, logger, message = m.groups()
        active = logger.startswith('squirrelops_home_sensor.') or logger in ('squirrelops_home_sensor', 'uvicorn.error')
        if not active:
            continue
        # Even logger names may contain attacker-controlled input. Never export
        # arbitrary names, messages, paths, URLs, credentials or traceback text.
        for event, pattern in EVENTS:
            match = re.fullmatch(pattern, message)
            if match:
                events.append(dict(time=stamp, level=level, event=event, numbers=[int(v) for v in match.groups()]))
                break
        else:
            if level != 'INFO':
                unknown[level] = unknown.get(level, 0) + 1
    if len(events) > 2000:
        raise RuntimeError('Too many diagnostic events; narrow review required')
    return dict(events=events, withheld_message_counts=unknown, exception_counts=exceptions)


def listener_records(record: dict) -> list:
    if record.get('command') != LISTENERS or record.get('exit') != 0:
        return []
    result, pid, uid = [], None, None
    for line in record.get('stdout', '').splitlines():
        if re.fullmatch(r'p\d+', line):
            pid, uid = int(line[1:]), None
        elif re.fullmatch(r'u\d+', line):
            uid = int(line[1:])
        else:
            match = re.fullmatch(r'n192\.168\.1\.240:(\d+)', line)
            if match and int(match[1]) in PORTS and pid is not None and uid is not None:
                result.append(dict(pid=pid, uid=uid, ip=VIP, port=int(match[1])))
    return result


def traffic(data: str) -> list:
    result = []
    for row in csv.DictReader(io.StringIO(data)):
        if row.get('ipAddress') != CLIENT or row.get('direction') not in ('in', 'out'):
            continue
        if not re.fullmatch(r'2026-09-30T\d{2}:\d{2}:\d{2}Z', row.get('date', '')):
            continue
        numeric = ('uid', 'protocol', 'port', 'connectCount', 'denyCount', 'byteCountIn', 'byteCountOut')
        if not all(re.fullmatch(r'\d{1,18}', row.get(k, '')) for k in numeric):
            continue
        exe = row.get('connectingExecutable', '')
        identity = {
            '/Library/SquirrelOps/sensor/python/bin/python3.12': 'sensor_python',
            '/Applications/SquirrelOps Home.app/Contents/Library/Helpers/com.squirrelops.deception-guest': 'guest',
            '/Library/PrivilegedHelperTools/com.squirrelops.helper': 'helper',
        }.get(exe, 'other_or_unknown')
        result.append(dict(time=row['date'], direction=row['direction'], process=identity, **{k: int(row[k]) for k in numeric}))
    return result


def command(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run the pinned wrapper with sudo on the mini')
    receipt = read_safe(RECEIPT)
    if hashlib.sha256(receipt).hexdigest() != RECEIPT_SHA:
        raise RuntimeError('Cleanup receipt changed')
    boot = command(['/usr/sbin/sysctl', '-n', 'kern.boottime'])
    if boot.returncode or not re.search(r'sec = 1790777754,', boot.stdout):
        raise RuntimeError('Boot changed; review required')
    for label in ('com.squirrelops.sensor', 'com.squirrelops.helper'):
        job = command(['/bin/launchctl', 'print', 'system/' + label])
        if job.returncode == 0 or 'Could not find service' not in job.stderr or label not in job.stderr:
            raise RuntimeError('Stopped service state not verified')
    report = dict(schema=1, scope='retained-september30-post-reboot-evidence-only', cleanup_receipt_sha256=RECEIPT_SHA,
                  exported_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  local_timezone=list(time.tzname), packet_summaries={}, sensor_logs=[], listener_snapshots=[])
    for interface in ('en0', 'en1'):
        raw = read_safe(BACKUP / f'packet-metadata-{interface}.txt')
        report['packet_summaries'][interface] = dict(sha256=hashlib.sha256(raw).hexdigest(), **packets(raw.decode('utf-8', errors='replace')))
    for suffix in ('', '.1', '.2', '.3', '.4', '.5'):
        try:
            raw = read_safe(Path(str(LOG) + suffix), owners=(0, 309))
        except FileNotFoundError:
            continue
        report['sensor_logs'].append(dict(rotation=suffix or 'current', sha256=hashlib.sha256(raw).hexdigest(), **log_events(raw.decode('utf-8', errors='replace'))))
    paths = sorted(BACKUP.glob('command-*.json'))
    if len(paths) > 2000:
        raise RuntimeError('Too many private command records')
    for path in paths:
        if not re.fullmatch(r'command-\d+\.json', path.name):
            continue
        record = json.loads(read_safe(path, limit=1024 * 1024))
        rows = listener_records(record)
        if rows:
            report['listener_snapshots'].append(dict(record=path.name, listeners=rows))
    try:
        logged = command([LS, 'log-traffic', '--begin-date', '2026-09-30 12:18:40', '--end-date', '2026-09-30 12:19:40'], timeout=45)
        report['little_snitch'] = dict(exit_code=logged.returncode, window_local=['2026-09-30 12:18:40', '2026-09-30 12:19:40'], rows=traffic(logged.stdout) if logged.returncode == 0 else [])
    except subprocess.TimeoutExpired:
        report['little_snitch'] = dict(error='read_timeout', rows=[])
    report['limits'] = ['Header summaries, no application payloads or TCP flags; bytes include retransmits.',
                        'Only allowlisted events; other warning/error text and all traceback text withheld.',
                        'Sensor event windows include local and UTC candidates; timestamps retain original clock.',
                        'An empty traffic history is not proof a filter allowed or blocked a connection.',
                        'No service, database, configuration, filter, package or network-probe changes.']
    output = Path(tempfile.mkdtemp(prefix='squirrelops-readonly-results.', dir='/private/var/tmp'))
    result = output / 'diagnostic.json'
    with result.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    os.chmod(result, 0o600)
    os.chown(result, 501, 20)
    os.chmod(output, 0o700)
    os.chown(output, 501, 20)
    print('READ-ONLY EXPORT COMPLETE: ' + str(result))
    print('Original evidence and permissions unchanged. Keep SquirrelOps closed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Unexpected exception strings can include evidence content. Do not leak.
        reason = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print('EXPORT STOPPED: ' + reason + '; no service or filter changes.')
        raise SystemExit(1)
