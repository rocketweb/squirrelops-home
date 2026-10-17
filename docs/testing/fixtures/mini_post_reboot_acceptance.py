"""Attended post-reboot mini acceptance. Plan-only unless invoked by pinned bootstrap.

Uses the stopped, disabled baseline directly, not a historical cleanup receipt.
No database repair, old-daemon shutdown experiment, or third-party filter changes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("single", Path(__file__).with_name("mini_single_ip_acceptance.py"))
single = importlib.util.module_from_spec(spec)
spec.loader.exec_module(single)
launchd, upgrade, base = single.launchd, single.upgrade, single.base
require = base.require
BOOT = 1790777754
BUILD = "26A434"
SCOPE = "mini-post-reboot-240"
CONSENT = "UPGRADE HELD MINI AND TEST 240"
DATABASE = base.SENSOR / "data/squirrelops.db"
EXPECTED_INTENT = [
    [1, "deep", single.VIP, 445, "active"], [2, "deep", single.VIP, 22, "active"],
    [3, "deep", single.VIP, 11434, "active"], [4, "deep", single.VIP, 1234, "active"],
    [5, "deep", single.VIP, 8765, "active"], [6, "dev_server", "192.168.1.115", 60556, "active"],
]
MAX_PAYLOAD_BYTES = 64 * 1024**2


def validate_payload_metadata(info, path):
    require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
            and info.st_nlink == 1 and not info.st_mode & 0o022
            and 0 < info.st_size <= MAX_PAYLOAD_BYTES,
            "Unsafe installed payload metadata: " + path.name)


def check_payload(path, expected):
    """Validate a pinned installed payload, not a size-limited evidence file."""
    initial = path.lstat()
    validate_payload_metadata(initial, path)
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    def identity(info):
        return tuple(getattr(info, field) for field in fields)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        opened = os.fstat(stream.fileno())
        validate_payload_metadata(opened, path)
        require(identity(opened) == identity(initial), "Payload changed during open: " + path.name)
        checksum, total = hashlib.sha256(), 0
        while data := stream.read(1024 * 1024):
            total += len(data)
            require(total <= MAX_PAYLOAD_BYTES, "Payload exceeded size bound: " + path.name)
            checksum.update(data)
        require(total == opened.st_size and identity(os.fstat(stream.fileno())) == identity(opened)
                and identity(path.lstat()) == identity(opened), "Payload changed while hashing: " + path.name)
    require(checksum.hexdigest() == expected, "Installed payload checksum mismatch: " + path.name)


def validate_intent(rows):
    require(rows == EXPECTED_INTENT, "Persisted decoy identity or intent changed; no database repair authorized")


def publication_ready(report):
    expected = {(single.VIP, port) for port in (22, 445, 11434, 1234, 8765)}
    active = {(row["bind_address"], row["port"]) for row in report["decoys"]
              if row["decoy_type"] == "deep" and row["status"] == "active"}
    if (report["owned_aliases"] != [single.VIP] or active != expected
            or not report["pf_rules"].strip() or not report["pf_nat"].strip()):
        return False
    mappings = upgrade.verify_guarded_snapshot(report)
    return {(row["ip"], row["port"]) for row in mappings} == expected


def hold_state(text):
    result = {}
    for job in upgrade.JOBS:
        values = re.findall(r'"' + re.escape(job) + r'"\s*=>\s*(\S+)', text)
        require(len(values) == 1 and values[0] in {"enabled", "disabled", "true", "false"},
                "Missing or ambiguous product disabled-state record")
        result[job] = values[0] in {"disabled", "true"}
    return result


def require_hold(text):
    require(all(hold_state(text).values()), "Both product jobs must remain disabled")


# Executed only as UID/GID 309. Its output is captured privately, never printed.
# The live connection is read-only; only the requested private backup is written.
WORKER = r"""
import json, sqlite3, sys
from contextlib import closing
operation, source = sys.argv[1:3]
with closing(sqlite3.connect('file:' + source + '?mode=ro', uri=True, timeout=5)) as db:
    db.row_factory = sqlite3.Row
    db.execute('BEGIN')
    if operation == 'backup':
        with closing(sqlite3.connect(sys.argv[3])) as target:
            db.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Backup integrity failed')
        value = {'ok': True}
    elif operation == 'intent':
        value = [list(row) for row in db.execute('SELECT id,decoy_type,bind_address,port,status FROM decoys ORDER BY id')]
    elif operation == 'snapshot':
        value = {
            'decoys': [dict(row) for row in db.execute('SELECT id,decoy_type,bind_address,port,status,connection_count,credential_trip_count FROM decoys ORDER BY id')],
            'connections': [dict(row) for row in db.execute('SELECT decoy_id,source_ip,port,protocol,count(*) AS count FROM decoy_connections GROUP BY decoy_id,source_ip,port,protocol')],
            'alerts': [dict(row) for row in db.execute("SELECT id,alert_type,severity,source_ip,decoy_id,created_at FROM home_alerts WHERE source_ip='192.168.1.7' ORDER BY id")],
            'virtual_ips': [dict(row) for row in db.execute('SELECT ip_address,interface,released_at FROM virtual_ips ORDER BY ip_address')],
        }
    elif operation == 'login':
        value = [list(row) for row in db.execute("SELECT d.bind_address,c.credential_value FROM planted_credentials c JOIN decoys d ON d.id=c.decoy_id WHERE c.planted_location='SSH buildbot login' AND d.decoy_type='deep' AND d.port=22 AND d.status='active' AND d.retired_at IS NULL")]
    else:
        raise RuntimeError('Unknown operation')
print(json.dumps(value))
"""


class PostRebootUpgrade(upgrade.Upgrade):
    package_sha = launchd.PACKAGE_SHA
    old_executables = launchd.LaunchdUpgrade.old_executables
    new_executables = launchd.LaunchdUpgrade.new_executables
    receipt_time = launchd.LaunchdUpgrade.receipt_time
    staging_prefix = "squirrelops-mini-post-reboot"
    input_names = (*single.SingleIPUpgrade.input_names, "mini_post_reboot_acceptance.py")
    stop_job = launchd.LaunchdUpgrade.stop_job
    check_conflicts = single.SingleIPUpgrade.check_conflicts
    check_effective_pool = single.SingleIPUpgrade.check_effective_pool
    check_config_acl = single.SingleIPUpgrade.check_config_acl
    observe = single.SingleIPUpgrade.observe

    def __init__(self, task_dir):
        super().__init__(task_dir)
        self.config_sha = single.OLD_CONFIG_SHA
        self.config_change_started = self.config_change_verified = False
        self.upgrade_approved = self.enable_started = False
        self.arp_checks = 0

    def publish(self, phase, **fields):
        super().publish(phase, test_scope=SCOPE, test_vips=[single.VIP], boot_seconds=BOOT,
                        config_change_verified=self.config_change_verified, **fields)
        # Public scratch results are a convenience; durable evidence survives reboot.
        shutil.copyfile(self.public / "status.json", self.backup / "status.json")
        (self.backup / "status.json").chmod(0o600)
        if phase == "stopped":
            shutil.copyfile(self.public / "status.json", self.backup / "cleanup.json")

    def assert_boot(self):
        text = self.command(["/usr/sbin/sysctl", "kern.boottime"]).stdout
        match = re.search(r"\bsec = ([0-9]+),", text)
        require(match is not None and int(match[1]) == BOOT, "Mini rebooted; review required")

    def assert_held_stopped(self):
        self.assert_boot()
        require_hold(self.command(["/bin/launchctl", "print-disabled", "system"]).stdout)
        require(all(not self.service_loaded(job) for job in upgrade.JOBS) and not self.processes(),
                "Product runtime is not held stopped")
        self.assert_no_test_network()

    def owned(self):
        if base.LEDGER.exists() or base.LEDGER.is_symlink():
            info = base.LEDGER.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o600),
                    "Unsafe ownership ledger")
        return super().owned()

    def check_stale_ledger(self):
        require(self.owned() == [single.VIP], "Stale ownership ledger differs from reviewed .240 record")

    def validate_existing(self):
        self.assert_held_stopped()
        for directory in (base.SENSOR.parent, base.SENSOR, base.APP, base.HELPER.parent):
            base.safe_directory(directory)
        user, group = base.pwd.getpwnam("_squirrelops"), base.grp.getgrnam("_squirrelops")
        require((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell) ==
                (309, 309, "/var/empty", "/usr/bin/false") and group.gr_gid == 309 and not group.gr_mem,
                "Service account drift")
        require(base.pwd.getpwnam("matt").pw_uid == 501, "Operator account drift")
        for path, expected in {**self.old_executables, upgrade.RUNTIME: upgrade.PYTHON_SHA}.items():
            check_payload(path, expected)
        _, config = single.checked_config(single.CONFIG)
        require(hashlib.sha256(config).hexdigest() == self.config_sha, "Configuration changed")
        self.check_config_acl()
        self.check_stale_ledger()
        for component in ("app", "sensor"):
            text = self.command(["/usr/sbin/pkgutil", "--pkg-info", "com.squirrelops.home." + component]).stdout
            require("version: 2.1.0\n" in text and f"install-time: {self.receipt_time}\n" in text, "Receipt drift")
        for job in upgrade.JOBS:
            path = Path("/Library/LaunchDaemons") / (job + ".plist")
            base.safe_file(path)
            require(plistlib.loads(path.read_bytes()).get("Label") == job, "Launch plist identity drift")
        for name in ("Users", "Groups"):
            result = self.command(["/usr/bin/dscl", ".", "-read", "/" + name + "/_squirrelops_installing"], check=False)
            require(result.returncode != 0 and "eDSRecordNotFound" in result.stdout + result.stderr,
                    "Temporary installer identity is uncertain")
        marker = Path("/var/db/com.squirrelops.allow-local-test")
        require(not marker.exists() and not marker.is_symlink(), "Unexpected local-test opt-in")

    def check_database_paths(self):
        for name in ("data", "logs"):
            path = base.SENSOR / name
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and
                    (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (309, 309, 0o700),
                    "Mutable directory identity drift")
        info = DATABASE.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and (info.st_uid, info.st_gid) == (309, 309)
                and stat.S_IMODE(info.st_mode) in {0o600, 0o644} and info.st_size <= 64 * 1024**2,
                "Database metadata drift")
        for path in (DATABASE.parent, DATABASE):
            require(len(self.command(["/bin/ls", "-lde", str(path)]).stdout.splitlines()) == 1, "Database ACL drift")

    def database(self, operation, destination=None):
        require(operation in {"intent", "snapshot", "login", "backup"}, "Unknown database operation")
        require((operation == "backup") == (destination is not None), "Invalid database destination")
        self.check_database_paths()
        command = [str(upgrade.RUNTIME), "-I", "-B", "-c", WORKER, operation, str(DATABASE)]
        if destination is not None:
            command.append(str(destination))
        result = subprocess.run(command, user=309, group=309, extra_groups=[],
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                capture_output=True, timeout=30, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 8 * 1024**2,
                "Service-identity database read failed; private data not exposed")
        try:
            return json.loads(result.stdout)
        except Exception:
            raise RuntimeError("Invalid database worker response") from None

    def read_intent(self):
        return self.database("intent")

    def verify_intent(self):
        validate_intent(self.read_intent())

    def backup_existing(self):
        self.check_effective_pool(self.task_dir / "single-ip-config.yaml")
        paths = [base.APP, base.SENSOR, base.HELPER,
                 *(Path("/Library/LaunchDaemons") / (job + ".plist") for job in upgrade.JOBS),
                 Path("/var/db/com.squirrelops.helper"), Path("/var/db/com.squirrelops.sensor"),
                 Path("/Library/SquirrelOps/backups")]
        paths += [Path("/var/db/receipts") / ("com.squirrelops.home." + component + suffix)
                  for component in ("app", "sensor") for suffix in (".plist", ".bom")]
        size = sum(int(self.command(["/usr/bin/du", "-sk", str(path)], timeout=120).stdout.split()[0]) * 1024
                   for path in paths if path.exists())
        require(size < 20 * 1024**3 and shutil.disk_usage("/Library").free > size * 2 + 5 * 1024**3,
                "Insufficient bounded backup space")
        manifest = {}
        for index, source in enumerate(paths):
            if not source.exists() and not source.is_symlink():
                manifest[str(source)] = {"absent": True}
                continue
            require(not source.is_symlink(), "Linked backup root")
            before = upgrade.tree_manifest(source)
            target = self.backup / f"payload-{index:02d}"
            upgrade.copy_durable(source, target, before, self.command)
            require(upgrade.durable_manifest(before) == upgrade.durable_manifest(upgrade.tree_manifest(target))
                    and before == upgrade.tree_manifest(source), "Backup verification failed")
            manifest[str(source)] = {"copy": str(target), "entries": before}
        single.private_write(self.backup / "restore-manifest.json", json.dumps(manifest, indent=2).encode())
        temporary = Path(tempfile.mkdtemp(prefix="squirrelops-post-reboot-db.", dir="/private/var/tmp"))
        os.chown(temporary, 309, 309)
        snapshot = temporary / "snapshot.sqlite"
        require(self.database("backup", snapshot) == {"ok": True}, "SQLite backup failed")
        info = snapshot.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 309
                and info.st_size <= 64 * 1024**2, "Unsafe backup file")
        with os.fdopen(os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "Backup replaced during open")
            data = stream.read(64 * 1024**2 + 1)
        require(len(data) <= 64 * 1024**2, "Oversized SQLite backup")
        single.private_write(self.backup / "pre-upgrade.sqlite", data)
        single.private_write(self.backup / "database-backup.json", json.dumps({
            "sha256": hashlib.sha256(data).hexdigest(), "private_intermediate": str(temporary), "read_uid": 309,
        }).encode())
        single.private_write(self.backup / "inverse.txt", b"Stop and verify guest exit before withdrawing owned networking.\n"
                             b"Restore both disabled jobs, release only this run's PF reference.\n"
                             b"Keep installation, narrowed config, data and backups. No automatic downgrade.\n")
        self.verify_intent()
        self.backup_verified = True

    def preflight(self):
        require(os.geteuid() == 0 and os.isatty(0), "Use attended mini Terminal bootstrap")
        require(self.task_dir.parent == Path("/private/var/root") and
                re.fullmatch(self.staging_prefix + r"\.[A-Za-z0-9_-]+", self.task_dir.name), "Wrong private staging")
        base.safe_directory(self.task_dir)
        require(base.digest(self.task_dir / "candidate.pkg") == self.package_sha, "Package checksum mismatch")
        require(self.command(["/usr/bin/uname", "-m"]).stdout.strip() == "arm64", "Wrong architecture")
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == BUILD, "OS drift")
        require("100.108.203.27" in self.command(["/sbin/ifconfig", "-a"]).stdout, "Wrong host")
        container = Path("/Library/SquirrelOps/acceptance-backups")
        for path in (container.parent, container):
            base.safe_directory(path)
        self.backup = Path(tempfile.mkdtemp(prefix="mini-post-reboot-20260930.", dir=container))
        self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-post-reboot-results.", dir="/private/var/tmp"))
        self.public.chmod(0o755)
        print(f"Durable private backup: {self.backup}\nSanitized results: {self.public}", flush=True)
        for name in self.input_names:
            base.safe_file(self.task_dir / name)
            shutil.copy2(self.task_dir / name, self.backup / name)
        require(base.digest(self.task_dir / "single-ip-config.yaml") == single.NEW_CONFIG_SHA, "Proposed config changed")
        self.publish("preflight")
        self.validate_existing()
        self.baseline_listeners = base.listener_endpoints(self.command(upgrade.LISTENERS).stdout)
        require(not any(uid == "309" or endpoint.endswith(":8443") for uid, endpoint in self.baseline_listeners),
                "Unexpected service/API listener")
        for endpoint in ("*:22", "*:445", "*:5900", "192.168.1.115:11434"):
            require(any(address == endpoint for _, address in self.baseline_listeners), "Native listener missing")
        self.host_baseline()
        info = self.pf(["-s", "info"])
        require(re.search(r"^Status:\s+Disabled\b", info, re.M) and re.search(r"current entries\s+0\b", info),
                "PF is not disabled with zero states")
        self.pf(["-s", "References"])
        self.pf_baseline = self.inspect_empty_pf()
        require(upgrade.PRODUCT_ANCHOR not in self.pf_baseline, "Unexpected product anchor")
        self.check_conflicts()
        self.verify_intent()
        self.backup_existing()
        self.validate_existing()
        self.snapshot("pre-upgrade")
        print("Six saved decoys verified; no SQL edits. Fresh installation and database backups verified.", flush=True)
        print("Change only the mini pool end 241 -> 240 and capacity 2 -> 1; install the pinned package.", flush=True)
        print("Enable only sensor/helper for install, test restart and bounded .240 LAN traffic, then restore the hold.", flush=True)
        print(f"Type {CONSENT} to approve, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Upgrade not approved")
        self.upgrade_approved = True

    def enable_for_install(self):
        require(self.upgrade_approved and self.backup_verified and self.token is not None,
                "Approval, verified backup and owned PF protection required")
        self.assert_held_stopped()
        self.enable_started = True
        for job in upgrade.JOBS:
            self.command(["/bin/launchctl", "enable", "system/" + job])
        require(not any(hold_state(self.command(["/bin/launchctl", "print-disabled", "system"]).stdout).values()),
                "Enablement did not verify")

    def install_package(self):
        require(self.upgrade_approved and self.backup_verified, "Approval and verified backup required")
        self.validate_existing()
        self.verify_intent()
        require(self.inspect_empty_pf() == self.pf_baseline, "PF policy changed")
        self.check_conflicts()
        # Exclusive claim is scoped to this new boot/baseline, not an old failed runner.
        self.claim = self.backup.parent / f"post-reboot-{BOOT}-{self.package_sha[:12]}-attempt.json"
        single.private_write(self.claim, json.dumps({"backup": str(self.backup), "package_sha256": self.package_sha}).encode())
        self.config_change_started = True
        single.replace_config(single.CONFIG, self.backup, self.validate_existing)
        self.config_sha = single.NEW_CONFIG_SHA
        self.validate_existing()
        self.check_effective_pool(single.CONFIG)
        self.config_change_verified = True
        enabled = self.command(["/sbin/pfctl", "-E"])
        self.token = base.parse_pf_token(enabled.stdout + enabled.stderr)
        single.private_write(self.backup / "pf-reference-token", (self.token + "\n").encode())
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF enable not verified")
        self.enable_for_install()
        self.command(["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "600", "/dev/null",
                      "/var/db/com.squirrelops.allow-local-test"])
        self.install_started = self.install_in_progress = True
        self.publish("installing", package_sha256=self.package_sha)
        print("Installing the pinned shutdown-budget package. Keep Terminal open.", flush=True)
        result = self.command(["/usr/sbin/installer", "-pkg", str(self.task_dir / "candidate.pkg"), "-target", "/"],
                              check=False, timeout=1800)
        self.install_in_progress = False
        require(result.returncode == 0, "Installer failed; private evidence retained")
        for path, expected in {**self.new_executables, upgrade.RUNTIME: upgrade.PYTHON_SHA}.items():
            check_payload(path, expected)
        require(base.digest(single.CONFIG) == self.config_sha, "Installed configuration changed")
        self.command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(base.APP)])
        self.wait_until_ready()

    def install(self):
        self.install_package()
        self.restart_check()

    def wait_until_ready(self):
        base.safe_file(launchd.PLIST)
        launchd.validate_shutdown_plist(plistlib.loads(launchd.PLIST.read_bytes()))
        job = self.command(["/bin/launchctl", "print", "system/com.squirrelops.sensor"]).stdout
        require(re.search(r"exit timeout = 60\b", job), "Loaded sensor does not have the 60-second shutdown allowance")
        deadline, healthy = time.monotonic() + 480, 0
        while time.monotonic() < deadline:
            response = self.command(["/usr/bin/curl", "--silent", "--insecure", "--max-time", "3", "--fail",
                                     "https://127.0.0.1:8443/system/health"], check=False)
            healthy = healthy + 1 if response.returncode == 0 and base.health_payload_ok(response.stdout) else 0
            if healthy >= 2:
                break
            time.sleep(3)
        require(healthy >= 2, "Sensor health did not stabilize")
        deadline = time.monotonic() + 180
        while True:
            self.snapshot("before")
            report = json.loads((self.public / "before.json").read_text())
            if publication_ready(report):
                break
            require(time.monotonic() < deadline, "Five guarded guest services did not become ready")
            time.sleep(3)
        self.host_baseline()
        self.verify_intent()
        current = base.listener_endpoints(self.command(upgrade.LISTENERS).stdout)
        require(("309", "192.168.1.115:60556") in current, "Existing classic listener not restored")
        self.export_guest_login()
        endpoints = json.dumps({"guest_ip": single.VIP, "mappings": upgrade.verify_guarded_snapshot(report)}, indent=2)
        for parent, mode in ((self.public, 0o644), (self.backup, 0o600)):
            target = parent / "endpoints.json"
            target.write_text(endpoints)
            target.chmod(mode)

    def restart_check(self):
        self.snapshot("first-start")
        validate_intent(self.read_intent())
        print("First startup passed. Testing a normal sensor restart.", flush=True)
        self.stop_job("com.squirrelops.sensor")
        deadline = time.monotonic() + 60
        while self.processes() and time.monotonic() < deadline:
            time.sleep(1)
        require(not self.processes(), "Runtime survived restart stop; retain protection")
        self.assert_no_test_network()
        require(not self.owned(), "Alias ownership survived restart stop")
        self.verify_intent()
        require(upgrade.empty_policy_matches(self.pf_baseline, self.inspect_empty_pf()), "Restart stop left policy")
        self.command(["/bin/launchctl", "bootstrap", "system", str(launchd.PLIST)])
        self.wait_until_ready()
        self.snapshot("after-restart")
        self.publish("restart_passed", package_sha256=self.package_sha)

    def snapshot(self, label):
        require(re.fullmatch(r"[a-z-]+", label) is not None, "Invalid snapshot label")
        report = self.database("snapshot")
        require(all(row["ip_address"] == single.VIP for row in report["virtual_ips"]), "Database VIP outside scope")
        report["owned_aliases"] = self.owned()
        children = [base.anchor_path(line.strip(), "com.apple") for line in
                    self.pf(["-a", "com.apple", "-s", "Anchors"]).splitlines() if line.strip()]
        present = upgrade.PRODUCT_ANCHOR in children
        report["pf_rules"] = self.pf(["-a", upgrade.PRODUCT_ANCHOR, "-sr"]) if present else ""
        report["pf_nat"] = self.pf(["-a", upgrade.PRODUCT_ANCHOR, "-sn"]) if present else ""
        data = json.dumps(report, indent=2).encode()
        for parent, mode in ((self.public, 0o644), (self.backup, 0o600)):
            temporary = parent / ("." + label + ".tmp")
            temporary.write_bytes(data)
            temporary.chmod(mode)
            temporary.replace(parent / (label + ".json"))

    def export_guest_login(self):
        rows = self.database("login")
        require(len(rows) == 1 and rows[0][0] == single.VIP and
                isinstance(rows[0][1], str) and re.fullmatch(r"Juniper![0-9]{6}", rows[0][1]),
                "Expected one synthetic guest login")
        target = self.public / "synthetic-guest-login.json"
        target.write_text(json.dumps({"ip": single.VIP, "username": "buildbot", "password": rows[0][1]}))
        target.chmod(0o600)
        os.chown(target, 501, 20)

    def restore_hold(self):
        require(not self.processes() and all(not self.service_loaded(job) for job in upgrade.JOBS),
                "Cannot restore hold before verified runtime exit")
        self.assert_boot()
        for job in upgrade.JOBS:
            self.command(["/bin/launchctl", "disable", "system/" + job])
        self.assert_held_stopped()
        self.verify_intent()

    def release_reference(self):
        self.restore_hold()
        launchd.LaunchdUpgrade.release_reference(self)

    def stop(self):
        if not self.install_started and self.token is None:
            if self.enable_started:
                self.restore_hold()
            return
        super().stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "boot_seconds": BOOT,
                          "package_sha256": launchd.PACKAGE_SHA, "test_scope": SCOPE,
                          "test_vips": [single.VIP], "database_recovery": False,
                          "restore_disabled_jobs": True, "confirmation": CONSENT}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    PostRebootUpgrade(args.run).run()


if __name__ == "__main__":
    main()
