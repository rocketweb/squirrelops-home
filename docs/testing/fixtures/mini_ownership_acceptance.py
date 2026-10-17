"""Pinned mini ownership-fix upgrade; five-row recovery needs attended consent."""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import time

spec = importlib.util.spec_from_file_location("mini_upgrade", Path(__file__).with_name("mini_upgrade_acceptance.py"))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)
base = upgrade.base
require = base.require

PACKAGE_SHA = "2d5f4d287ca3ce971fd201f539d27a9272431f160a5a5debddc8d1b0b4dc7c82"
ORCHESTRATOR = base.SENSOR / "python/lib/python3.12/site-packages/squirrelops_home_sensor/decoys/orchestrator.py"
HISTORICAL_DB = Path("/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.knon9pvr/pre-upgrade.sqlite")
DATABASE = base.SENSOR / "data/squirrelops.db"
EXPECTED = {1: 445, 2: 22, 3: 11434, 4: 1234, 5: 8765}
CONSENT = "RESTORE FIVE AND UPGRADE"


def decoy_rows(db):
    db.row_factory = sqlite3.Row
    return [dict(row) for row in db.execute("SELECT * FROM decoys WHERE decoy_type='deep' ORDER BY id")]


def validate_recovery(current, original):
    require(len(current) == len(original) == 5, "Expected exactly five historical and current deep rows")
    require({row["id"]: row["port"] for row in current} == EXPECTED
            and {row["id"]: row["port"] for row in original} == EXPECTED, "Deep row identity drift")
    require(all(row["status"] == "active" for row in original), "Historical host was not fully active")
    require(all(row["status"] == "stopped" for row in current), "Current host is not fully stopped")
    require(all(row["bind_address"] == "192.168.1.240" and row["decoy_type"] == "deep"
                and row["retired_at"] is None for row in original + current), "Host address or retirement drift")
    require(len({row["host_id"] for row in original}) == 1 and original[0]["host_id"] is not None
            and [row["id"] for row in original if row["is_primary"]] == [1], "Invalid grouped host")
    # Status and its change timestamp are the only expected corruption. Do not
    # overlook new evidence, changed credentials/config, or operator changes.
    for now, before in zip(current, original, strict=True):
        require({k: v for k, v in now.items() if k not in {"status", "updated_at"}} ==
                {k: v for k, v in before.items() if k not in {"status", "updated_at"}},
                "Deep row content changed beyond the known ownership defect")
    return [{"id": row["id"], "ip": row["bind_address"], "port": row["port"],
             "before": "stopped", "after": "active"} for row in current]


def preserved_digest(db):
    """Hash all data except these five status fields; never print private rows."""
    result = hashlib.sha256()
    names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    for name in names:
        escaped = '"' + name.replace('"', '""') + '"'
        rows = []
        for row in db.execute("SELECT * FROM " + escaped):
            value = dict(row)
            if name == "decoys" and value.get("id") in EXPECTED:
                value.pop("status", None)
            rows.append(json.dumps(value, sort_keys=True, default=lambda x: {"bytes": x.hex()}))
        result.update(json.dumps([name, sorted(rows)]).encode())
    return result.hexdigest()


def restore_five(db, original, journal):
    """One status-only transaction. The caller has stopped and backed up services."""
    db.execute("BEGIN IMMEDIATE")
    try:
        before = decoy_rows(db)
        preview = validate_recovery(before, original)
        preserved = preserved_digest(db)
        # Exclusive private journal is the exact-path inverse evidence. Do not
        # overwrite it or silently replay a partially completed attempt.
        descriptor = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump({"before": before, "preview": preview, "preserved_sha256": preserved}, output)
            output.flush()
            os.fsync(output.fileno())
        cursor = db.execute("UPDATE decoys SET status='active' WHERE id IN (1,2,3,4,5) AND decoy_type='deep' AND status='stopped'")
        require(cursor.rowcount == 5, "Recovery did not affect exactly five rows")
        require(all(row["status"] == "active" for row in decoy_rows(db)), "Recovery verification failed")
        require(preserved_digest(db) == preserved, "Recovery changed data outside the five status fields")
        require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Recovery integrity failure")
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return preview


class OwnershipUpgrade(upgrade.Upgrade):
    package_sha = PACKAGE_SHA
    old_executables = upgrade.NEW_EXECUTABLES
    new_executables = {
        **upgrade.NEW_EXECUTABLES,
        base.APP / "Contents/MacOS/SquirrelOpsHome": "a0e3ed122b57ed94857d49e8123ac6491672cbb204e150fa252f4046b28910b6",
        ORCHESTRATOR: "b984836e15cb63beb4b548d1f0cc20d123044b0c6625944288cd96b62725b414",
    }
    receipt_time = 1790711659
    staging_prefix = "squirrelops-mini-ownership"
    input_names = (*upgrade.Upgrade.input_names, "mini_ownership_acceptance.py")

    def publish(self, phase, **fields):
        super().publish(phase, **fields)
        if phase == "stopped":
            # Keep successful teardown evidence even when run() subsequently
            # reports the original acceptance failure as needs_review.
            temporary = self.public / ".cleanup.tmp"
            temporary.write_bytes((self.public / "status.json").read_bytes())
            temporary.chmod(0o644)
            temporary.replace(self.public / "cleanup.json")

    def historical_rows(self):
        for directory in (HISTORICAL_DB.parent.parent, HISTORICAL_DB.parent):
            base.safe_directory(directory)
        info = HISTORICAL_DB.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o077 and info.st_size <= 64 * 1024**2,
                "Historical SQLite backup is unsafe")
        with closing(sqlite3.connect(f"file:{HISTORICAL_DB}?mode=ro", uri=True)) as db:
            require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Historical integrity check failed")
            return decoy_rows(db)

    def checked_rows(self):
        self.validate_existing()
        parent = DATABASE.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode)
                and (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) == (309, 309, 0o700),
                "Current SQLite parent is unsafe: "
                f"uid={parent.st_uid} gid={parent.st_gid} mode={stat.S_IMODE(parent.st_mode):04o}")
        info = DATABASE.lstat()
        # The installer protects the directory, not every database file's read
        # bits. SQLite may create mode 0644 under launchd's inherited umask.
        # Accept that observed layout only inside the private, ACL-free parent.
        require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (309, 309)
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o600, 0o644)
                and info.st_size <= 64 * 1024**2,
                "Current SQLite database is unsafe: "
                f"uid={info.st_uid} gid={info.st_gid} mode={stat.S_IMODE(info.st_mode):04o} "
                f"links={info.st_nlink} bytes={info.st_size}")
        for path in (DATABASE.parent, DATABASE):
            # Same ACL inventory contract as the package's postinstall. Any
            # extra ACL line (even a deny entry) requires separate review.
            lines = self.command(["/bin/ls", "-lde", str(path)]).stdout.splitlines()
            require(len(lines) == 1 and bool(lines[0].strip()),
                    f"Current SQLite path has an extended ACL or uncertain inventory: {path.name}")
        with closing(sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)) as db:
            return decoy_rows(db)

    def preflight(self):
        super().preflight()
        self.original_rows = self.historical_rows()
        preview = validate_recovery(self.checked_rows(), self.original_rows)
        print("Verified recovery preview (only these five status fields change):", flush=True)
        print(json.dumps(preview, indent=2), flush=True)
        print("The verified private backup preserves the current DB and old installation.", flush=True)
        print("This installs the pinned ownership fix, tests a sensor restart, then permits bounded LAN tests.", flush=True)
        print("Failure leaves services stopped and evidence retained; there is no automatic data downgrade.", flush=True)
        print(f"Type {CONSENT} to approve this exact recovery and upgrade, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Operator did not approve recovery; no install or recovery performed")
        self.recovery_approved = True

    def prepare_upgrade(self):
        require(getattr(self, "recovery_approved", False) and self.backup_verified and self.backup is not None,
                "Attended approval and verified backup required")
        validate_recovery(self.checked_rows(), self.original_rows)
        require(self.historical_rows() == self.original_rows, "Historical backup changed")
        with closing(sqlite3.connect(f"file:{DATABASE}?mode=rw", uri=True)) as db:
            restore_five(db, self.original_rows, self.backup / "five-row-recovery.json")
        self.publish("five_rows_restored", package_sha256=self.package_sha, changed_ids=sorted(EXPECTED))

    def install(self):
        super().install()
        self.snapshot("first-start")
        with closing(sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)) as db:
            rows = decoy_rows(db)
            require({row["id"]: row["port"] for row in rows} == EXPECTED
                    and all(row["status"] == "active" for row in rows), "Recovered host identity changed")
        print("First startup passed. Testing a normal sensor restart before LAN probes.", flush=True)
        self.stop_job("com.squirrelops.sensor")
        deadline = time.monotonic() + 60
        while self.processes() and time.monotonic() < deadline:
            time.sleep(1)
        require(not self.processes(), "Runtime survived restart stop; retain protection")
        self.assert_no_test_network()
        require(not self.owned(), "Aliases survived restart stop")
        with closing(sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)) as db:
            require(decoy_rows(db) == rows, "Shutdown changed persisted Studio intent")
        self.command(["/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.squirrelops.sensor.plist"])
        self.wait_until_ready()
        with closing(sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)) as db:
            restarted = decoy_rows(db)
            require({row["id"]: row["port"] for row in restarted} == EXPECTED
                    and all(row["status"] == "active" for row in restarted), "Studio did not survive restart")
        self.snapshot("after-restart")
        self.publish("restart_passed", package_sha256=self.package_sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "package_sha256": PACKAGE_SHA,
                          "restore_status_ids": sorted(EXPECTED), "attended_confirmation": CONSENT,
                          "vips": sorted(base.VIPS), "normal_restart": True, "observe_seconds": 1200,
                          "third_party_filter_rule_changes": False, "fault_injection": False}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    OwnershipUpgrade(args.run).run()


if __name__ == "__main__":
    main()
