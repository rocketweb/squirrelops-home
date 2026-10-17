"""Pinned launchd-budget upgrade and normal restart; no database recovery."""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import plistlib
import signal
import time

spec = importlib.util.spec_from_file_location("ownership", Path(__file__).with_name("mini_ownership_acceptance.py"))
ownership = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ownership)
upgrade, base = ownership.upgrade, ownership.base
require = base.require

PACKAGE_SHA = "3a3cda47a7eaec1a015edd82ad42edc91be10b64d181a805d29f114f2357893c"
CLEANUP = Path("/private/var/tmp/squirrelops-mini-restart-cleanup-results.v93amy48/status.json")
CLEANUP_SHA = "707399a27e4e66f62dedc90b9c8b7f6a9cb369dc8c45ba22ea9ffa7caa886042"
PLIST = Path("/Library/LaunchDaemons/com.squirrelops.sensor.plist")
CONSENT = "UPGRADE AND TEST RESTART"


def validate_active_rows(rows):
    require(len(rows) == 5 and {row["id"]: row["port"] for row in rows} == ownership.EXPECTED,
            "Expected exactly the five restored Studio rows")
    require(all(row["status"] == "active" and row["decoy_type"] == "deep" and
                row["bind_address"] == "192.168.1.240" and row["retired_at"] is None for row in rows),
            "Studio intent changed; no automatic row recovery")
    require(len({row["host_id"] for row in rows}) == 1 and rows[0]["host_id"] is not None
            and [row["id"] for row in rows if row["is_primary"]] == [1], "Studio grouping changed")


def validate_shutdown_plist(data):
    require(data.get("Label") == "com.squirrelops.sensor" and data.get("UserName") == "_squirrelops"
            and type(data.get("ExitTimeOut")) is int and data["ExitTimeOut"] == 60,
            "Installed sensor shutdown allowance is not the tested 60 seconds")


class LaunchdUpgrade(ownership.OwnershipUpgrade):
    package_sha = PACKAGE_SHA
    old_executables = ownership.OwnershipUpgrade.new_executables
    new_executables = {
        **old_executables,
        base.APP / "Contents/MacOS/SquirrelOpsHome": "99777e990d7e8db5ea4725899b598a9767095611ed5a0df5062b987b3e6e0298",
        base.SENSOR / "com.squirrelops.sensor.plist": "f0c5a6c1863c9e2ae44f7f399537c178e1c6807927fff3e7543f7a2ea200028c",
    }
    receipt_time = 1790731448
    staging_prefix = "squirrelops-mini-launchd"
    input_names = (*ownership.OwnershipUpgrade.input_names, "mini_launchd_acceptance.py")

    def read_intent(self):
        with closing(ownership.sqlite3.connect(f"file:{ownership.DATABASE}?mode=ro", uri=True)) as db:
            return list(db.execute("SELECT id,decoy_type,bind_address,port,status FROM decoys ORDER BY id"))

    def verify_intent(self):
        require(self.read_intent() == self.original_intent,
                "Persisted decoy identity or intent changed; retain evidence")

    def preflight(self):
        base.safe_directory(CLEANUP.parent)
        base.safe_file(CLEANUP)
        require(base.digest(CLEANUP) == CLEANUP_SHA, "Reviewed cleanup receipt changed")
        receipt = json.loads(CLEANUP.read_text())
        require(receipt.get("phase") == "stopped" and receipt.get("pf_enabled") is False and all(
            receipt.get(key) is True for key in ("guest_stopped", "aliases_absent", "own_pf_reference_released",
                                                "original_listener_endpoints_present")), "Cleanup incomplete")
        # Deliberately bypass ownership-recovery preflight. Those five statuses
        # have already been restored and must never be rewritten by this run.
        upgrade.Upgrade.preflight(self)
        self.original_rows = self.checked_rows()
        validate_active_rows(self.original_rows)
        self.original_intent = self.read_intent()
        print("Verified existing active Studio host: five services. Database edits: zero.", flush=True)
        print("This installs the pinned shutdown-budget package, verifies ExitTimeOut=60,", flush=True)
        print("tests a normal sensor restart, then permits the bounded laptop probes.", flush=True)
        print("Backups are verified. No automatic downgrade or third-party filter-rule changes.", flush=True)
        print(f"Type {CONSENT} to continue, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Upgrade not approved; nothing installed")
        self.upgrade_approved = True

    def prepare_upgrade(self):
        require(getattr(self, "upgrade_approved", False) and self.backup_verified and self.backup is not None,
                "Attended approval and verified backup required")
        require(self.checked_rows() == self.original_rows, "Studio rows changed after preview")
        self.verify_intent()
        # No write transaction or five-row recovery here.

    def wait_until_ready(self):
        base.safe_directory(PLIST.parent)
        base.safe_file(PLIST)
        validate_shutdown_plist(plistlib.loads(PLIST.read_bytes()))
        super().wait_until_ready()
        self.verify_intent()

    def stop_job(self, label):
        require(label in upgrade.JOBS, "Unexpected stop target")
        if self.service_loaded(label):
            self.command(["/bin/launchctl", "bootout", "system/" + label], check=False, timeout=90)
        deadline = time.monotonic() + (70 if label == "com.squirrelops.sensor" else 45)
        while time.monotonic() < deadline:
            if not self.service_loaded(label):
                return
            time.sleep(1)
        raise RuntimeError("Service remains loaded after shutdown allowance; retain protection")

    def assert_no_test_network(self):
        super().assert_no_test_network()
        if self.install_started and hasattr(self, "original_intent"):
            self.verify_intent()

    def release_reference(self):
        try:
            super().release_reference()
        except Exception:
            # A timed-out pfctl invocation can put its private token in an
            # exception's command text after the parent cleared self.token.
            raise RuntimeError("PF reference release not verified; no retry. Review private evidence") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "package_sha256": PACKAGE_SHA,
                          "database_recovery": False, "normal_restart": True, "sensor_exit_timeout": 60,
                          "confirmation": CONSENT, "observe_seconds": 1200,
                          "third_party_filter_rule_changes": False, "fault_injection": False}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    LaunchdUpgrade(args.run).run()


if __name__ == "__main__":
    main()
