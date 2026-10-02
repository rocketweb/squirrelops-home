"""Attended .240-only continuation with an exact, backed-up two-field edit."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("launchd", Path(__file__).with_name("mini_launchd_acceptance.py"))
launchd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launchd)
base, upgrade = launchd.base, launchd.upgrade
require = base.require

VIP = "192.168.1.240"
SCOPE = "mini-single-ip-240"
OLD_CONFIG_SHA = "6e210567e3baae3950d91153b44090876ae6978b2a67677b1690aaf5c8f02330"
NEW_CONFIG_SHA = "6b492246632eee7bc3975e84fc7c75699d3dcdfc15f2ec542ec673ab243b4bd8"
CONFIG = base.SENSOR / "config.yaml"
CONFIG_OWNER = (309, 309)
CONSENT = "USE 240 AND TEST RESTART"
CAPTURE_FILTER = "host 192.168.1.7 and host 192.168.1.240"

# These are private copies loaded through importlib, not installed product
# modules. Scope the inherited ledger, snapshot, login and teardown guards to
# one address without rewriting historical, checksum-pinned runners.
base.VIPS = {VIP}
launchd.CONSENT = CONSENT


def narrow_config(original):
    require(hashlib.sha256(original).hexdigest() == OLD_CONFIG_SHA, "Original configuration changed")
    revised = original
    for before, after in ((b"  virtual_ip_range_end: 241\n", b"  virtual_ip_range_end: 240\n"),
                          (b"  max_virtual_ips: 2\n", b"  max_virtual_ips: 1\n")):
        require(revised.count(before) == 1, "Configuration edit is ambiguous")
        revised = revised.replace(before, after, 1)
    require(hashlib.sha256(revised).hexdigest() == NEW_CONFIG_SHA, "Unexpected revised configuration")
    return revised


def validate_effective_pool(settings):
    scouts = settings.scouts
    require((scouts.virtual_ip_range_start, scouts.virtual_ip_range_end, scouts.max_virtual_ips) == (240, 240, 1),
            "Persisted settings override the approved single-IP configuration")


def checked_config(path):
    base.safe_directory(path.parent)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            (info.st_uid, info.st_gid) == CONFIG_OWNER and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 65536, "Unsafe configuration metadata")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "Configuration replaced while opening")
        data = stream.read(65537)
    require(len(data) <= 65536, "Oversized configuration")
    return info, data


def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def replace_config(path, backup, recheck):
    """No service changes. Refuse drift/replay; retain private inverse evidence."""
    base.safe_directory(backup)
    initial, original = checked_config(path)
    revised = narrow_config(original)
    private_write(backup / "config-before.yaml", original)
    require(base.digest(backup / "config-before.yaml") == OLD_CONFIG_SHA, "Config backup did not verify")
    private_write(backup / "config-change.json", json.dumps({
        "path": str(path), "before_sha256": OLD_CONFIG_SHA, "after_sha256": NEW_CONFIG_SHA,
        "uid": CONFIG_OWNER[0], "gid": CONFIG_OWNER[1], "mode": "0600",
        "changes": {"scouts.virtual_ip_range_end": [241, 240], "scouts.max_virtual_ips": [2, 1]},
    }, indent=2).encode())
    private_write(backup / "config-inverse.txt", (
        "No automatic rollback. The old pool overlaps a live Studio host.\n"
        "A reviewed inverse requires fresh approval, stopped services/guest, no owned aliases,\n"
        "and a current config exactly matching after_sha256. Verify the before backup hash;\n"
        "restore only config-before.yaml atomically with UID/GID 309 and mode 0600.\n"
        "Do not restore the broader pool or restart until .241 ownership is resolved.\n"
        "Never overwrite operator changes or newer data. No database rollback is included.\n"
    ).encode())
    descriptor, temporary = tempfile.mkstemp(prefix=".single-ip-config-", dir=path.parent)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        os.fchown(stream.fileno(), *CONFIG_OWNER)
        stream.write(revised)
        stream.flush()
        os.fsync(stream.fileno())
    recheck()
    current, contents = checked_config(path)
    require((current.st_dev, current.st_ino) == (initial.st_dev, initial.st_ino) and contents == original,
            "Configuration changed before replacement; nothing overwritten")
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    _, actual = checked_config(path)
    require(actual == revised, "Configuration replacement did not verify; retain evidence")


class SingleIPUpgrade(launchd.LaunchdUpgrade):
    staging_prefix = "squirrelops-mini-single-ip"
    input_names = (*launchd.LaunchdUpgrade.input_names, "mini_single_ip_acceptance.py", "single-ip-config.yaml")

    def __init__(self, task_dir):
        super().__init__(task_dir)
        self.config_change_started = False
        self.config_change_verified = False
        self.arp_checks = 0

    def publish(self, phase, **fields):
        super().publish(phase, test_scope=SCOPE, test_vips=[VIP],
                        config_change_started=self.config_change_started,
                        config_change_verified=self.config_change_verified, **fields)

    def preflight(self):
        require(base.CONFIG_SHA == OLD_CONFIG_SHA and base.VIPS == {VIP}, "Runner scope drift")
        require(base.digest(self.task_dir / "single-ip-config.yaml") == NEW_CONFIG_SHA, "Proposed configuration changed")
        print("Approved mini-only configuration change, after a verified backup:", flush=True)
        print("  scouts.virtual_ip_range_end: 241 -> 240\n  scouts.max_virtual_ips: 2 -> 1", flush=True)
        print("The Studio and .241 are outside this run. ARP conflict checks remain enabled for .240.", flush=True)
        super().preflight()

    def check_conflicts(self):
        from scapy.all import ARP, Ether, srp
        require(base.VIPS == {VIP}, "Unexpected probe scope")
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=VIP),
                          iface="en0", timeout=2, retry=2, verbose=False)
        self.arp_checks += 1
        require(self.public is not None, "No sanitized evidence directory")
        rows = [{"target": VIP, "reply_ip": str(reply[ARP].psrc), "reply_mac": str(reply[ARP].hwsrc)}
                for _, reply in list(answered)[:16] if ARP in reply]
        path = self.public / f"arp-check-{self.arp_checks}.json"
        path.write_text(json.dumps({"target": VIP, "interface": "en0", "reply_count": len(answered), "replies": rows}, indent=2))
        path.chmod(0o644)
        require(not answered, "192.168.1.240 answered ARP; see arp-check evidence. No startup authorized")

    def check_effective_pool(self, path):
        from squirrelops_home_sensor.config import load_settings
        persisted = base.SENSOR / "data/config.yaml"
        if persisted.exists() or persisted.is_symlink():
            info = persisted.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    (info.st_uid, info.st_gid) == CONFIG_OWNER and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_size <= 65536, "Unsafe persisted configuration; review required")
            lines = self.command(["/bin/ls", "-lde", str(persisted)]).stdout.splitlines()
            require(len(lines) == 1 and bool(lines[0].strip()), "Persisted configuration ACL drift")
        try:
            settings = load_settings(config_path=path)
        except Exception:
            # Configuration validation errors may contain credential values.
            raise RuntimeError("Effective configuration failed validation; review private files") from None
        validate_effective_pool(settings)

    def backup_existing(self):
        # Check the real layered loader before confirmation or any write to
        # installed files. A data/config.yaml override is never silently edited.
        self.check_effective_pool(self.task_dir / "single-ip-config.yaml")
        super().backup_existing()

    def prepare_upgrade(self):
        super().prepare_upgrade()
        # Full installation/database backup and one-shot attempt claim already
        # exist. Revalidate stopped state, old configuration and identity before
        # replacing only this file, then switch the inherited hash invariant.
        self.check_config_acl()
        self.config_change_started = True
        replace_config(CONFIG, self.backup, self.validate_existing)
        base.CONFIG_SHA = NEW_CONFIG_SHA
        self.validate_existing()
        self.check_config_acl()
        self.check_effective_pool(CONFIG)
        self.config_change_verified = True
        self.publish("configuration_narrowed", package_sha256=self.package_sha,
                     config_sha256=NEW_CONFIG_SHA, database_recovery=False)
        print("Verified .240-only configuration; original and inverse retained in the private backup.", flush=True)

    def check_config_acl(self):
        for path in (CONFIG.parent, CONFIG):
            lines = self.command(["/bin/ls", "-lde", str(path)]).stdout.splitlines()
            require(len(lines) == 1 and bool(lines[0].strip()), "Configuration ACL drift; retain evidence")

    def observe(self):
        require(self.backup is not None and self.config_change_verified, "Verified configuration and backup required")
        for interface in ("en0", "en1"):
            output = (self.backup / f"packet-metadata-{interface}.txt").open("w")
            process = subprocess.Popen([
                "/usr/sbin/tcpdump", "-i", interface, "-n", "-q", "-tttt", "-l", "-s", "96", CAPTURE_FILTER,
            ], stdout=output, stderr=subprocess.DEVNULL)
            self.captures.append((process, output, interface))
        time.sleep(1)
        require(all(p.poll() is None for p, _, _ in self.captures), "Metadata capture startup failed")
        deadline = time.monotonic() + 1200
        self.publish("ready_for_tests", package_sha256=self.package_sha, remaining_seconds=1200, sensor_uid=309)
        print("READY FOR TESTS. Tell Codex it is ready; leave this Terminal open.", flush=True)
        print("Leave new connection prompts unanswered. Return stops early; auto-stop in 20 minutes.", flush=True)
        while time.monotonic() < deadline:
            ready, _, _ = select.select([0], [], [], 5)
            if ready:
                os.read(0, 4096)
                break
            self.snapshot("latest")
            self.publish("ready_for_tests", package_sha256=self.package_sha,
                         remaining_seconds=max(0, int(deadline - time.monotonic())), sensor_uid=309)
        self.snapshot("after")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "package_sha256": launchd.PACKAGE_SHA,
                          "test_scope": SCOPE, "test_vips": [VIP], "configuration_fields_changed": 2,
                          "database_recovery": False, "confirmation": CONSENT,
                          "third_party_filter_rule_changes": False, "fault_injection": False}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    SingleIPUpgrade(args.run).run()


if __name__ == "__main__":
    main()
