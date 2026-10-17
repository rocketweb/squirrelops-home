"""Back up the mini and disable two future service loads; never reboot or stop."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("mini_reboot_recovery.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
require = recovery.require
JOBS = recovery.upgrade.JOBS


class MaintenanceHold(recovery.Recovery):
    def record_baseline(self):
        self.config_digest = recovery.base.CONFIG_SHA
        self.plist_digests = {job: recovery.base.digest(self.backup / (job + ".plist")) for job in JOBS}
        self.ledger_bytes = recovery.checked_bytes(recovery.base.LEDGER, 0, {0o600, 0o644})
        recovery.private_write(self.backup / "owned-aliases-before", self.ledger_bytes)
        recovery.private_write(self.backup / "maintenance-baseline.json", json.dumps({
            "boot_seconds": recovery.BOOT, "os_build": recovery.BUILD,
            "sensor_pid": self.sensor_pid, "helper_pid": self.helper_pid,
            "runtime": self.original_rows, "jobs": self.original_jobs,
            "config_sha256": self.config_digest, "plist_sha256": self.plist_digests,
            "intent": self.original_intent, "pf_policy": self.policy,
            "pf_references": self.references, "native_listeners": sorted(self.listeners),
        }, indent=2).encode())
        recovery.private_write(self.backup / "maintenance-inverse.txt", (
            b"Only two effective overrides change: enabled -> disabled.\n"
            b"No automatic rollback, restart, database restore or PF changes.\n"
            b"The inverse is launchctl enable system/com.squirrelops.sensor and\n"
            b"launchctl enable system/com.squirrelops.helper, only at a separately\n"
            b"reviewed upgrade boundary after stopped-state and .240-only config checks.\n"
            b"Do not reload the old pool while the Studio owns .241.\n"
            b"A pending-reboot receipt is NOT evidence that services have stopped.\n"
        ))

    def preflight(self):
        self.backup_preflight()
        self.record_baseline()
        print(f"Fresh verified backups: {self.backup}", flush=True)
        print("Approved change, exactly two future-load overrides:", flush=True)
        for job in JOBS:
            print(f"  system/{job}: enabled -> disabled", flush=True)
        print("No stop, signal, debug replacement, installer, PF change or automatic reboot.", flush=True)

    def revalidate(self, *, held):
        self.assert_boot()
        require(self.hold_state() == dict.fromkeys(JOBS, held), "Service override drift")
        require(hashlib.sha256(recovery.checked_bytes(recovery.base.SENSOR / "config.yaml", 309, {0o600})).hexdigest()
                == self.config_digest, "Config drift; do not reboot")
        for job in JOBS:
            require(hashlib.sha256(recovery.checked_bytes(Path("/Library/LaunchDaemons") / (job + ".plist"),
                                                          0, {0o600, 0o644})).hexdigest() == self.plist_digests[job],
                    "Launch plist drift; do not reboot")
        rows = self.rows()
        require(recovery.runtime_rows(rows) == recovery.runtime_rows(self.original_rows)
                and rows.get(self.helper_pid) == self.original_rows[self.helper_pid], "Runtime drift; review required")
        for job, pid in ((recovery.SENSOR_JOB, self.sensor_pid), (recovery.HELPER_JOB, self.helper_pid)):
            require(recovery.job_pid(self.job(job) or "", job) == pid, "Launchd PID drift")
        require(self.owned() == ["192.168.1.240"]
                and recovery.checked_bytes(recovery.base.LEDGER, 0, {0o600, 0o644}) == self.ledger_bytes,
                "Alias ownership drift")
        require(self.inventory_policy() == self.policy and self.pf_enabled()
                and self.pf(["-s", "References"]) == self.references, "PF state drift; review required")

    def hold_for_reboot(self):
        self.revalidate(held=False)
        self.mutation_started = True
        recovery.private_write(self.backup / "mutation-started.json", json.dumps({
            "boot_seconds": recovery.BOOT, "operation": "disable_future_loads_only", "jobs": list(JOBS),
        }).encode())
        for job in JOBS:
            self.command(["/bin/launchctl", "disable", "system/" + job])
        require(self.hold_state() == dict.fromkeys(JOBS, True), "Both disabled overrides were not verified; do not reboot")
        self.revalidate(held=True)
        recovery.private_write(self.backup / "pending-reboot.json", json.dumps({
            "schema": 1, "phase": "disabled_pending_attended_reboot", "boot_seconds": recovery.BOOT,
            "disabled_jobs": list(JOBS), "stopped_state_verified": False,
        }, indent=2).encode())
        print("READY FOR ATTENDED RESTART: both SquirrelOps jobs are disabled for future loads.", flush=True)
        print("They are still running now. Save other work, then use Apple menu > Restart.", flush=True)
        print("Keep SquirrelOps closed after reboot. No installation or LAN probes until the post-boot audit.", flush=True)

    def run_hold(self):
        os.umask(0o077)
        try:
            self.preflight()
            self.hold_for_reboot()
        except BaseException as exc:  # noqa: BLE001 - preserve partial hold on interruption
            reason = str(exc) if isinstance(exc, RuntimeError) else "Inspect private evidence"
            recovery.private_write(self.backup / "maintenance-failure.json", json.dumps({
                "phase": "needs_review", "error_type": type(exc).__name__,
                "mutation_started": self.mutation_started, "reason": reason,
            }, indent=2).encode())
            print(f"STOPPED: {reason}. Do not reboot or rerun; paste this result for review.", flush=True)
            print(f"Evidence: {self.backup}. No automatic rollback or restart.", flush=True)
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "disable_jobs": list(JOBS),
                          "stop": False, "reboot": False, "install": False, "pf_changes": False}, indent=2))
    else:
        MaintenanceHold(args.run).run_hold()


if __name__ == "__main__":
    main()
