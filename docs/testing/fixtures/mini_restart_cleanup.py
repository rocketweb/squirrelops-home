"""Attended cleanup of the exact failed September 29 restart, never an install."""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("ownership", Path(__file__).with_name("mini_ownership_acceptance.py"))
ownership = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ownership)
upgrade, base = ownership.upgrade, ownership.base
require = base.require

BASELINE = Path("/Library/SquirrelOps/acceptance-backups/mini-upgrade-20260929.z8rfqzvz")
PUBLIC = Path("/private/var/tmp/squirrelops-mini-upgrade-results.w3qacnps")
STAGE = Path("/private/var/root/squirrelops-mini-ownership.s4L9F0BA")
INPUTS = {
    "mini_acceptance.py": "47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a",
    "mini_upgrade_acceptance.py": "4c732720e89da4b4a872b56e951b1b70b121e2db603185ecb36d298c99c464d3",
    "mini_ownership_acceptance.py": "98d8729e112e8ff48bbf320b094ab96471e597dd48cec6a726b17807d07986e6",
    "approved-scope.md": "6a1b627d0a143a8c7eb661f0b5d13f5e2547c69196bc69b3207ec771fb2b59fe",
}
EVIDENCE = {
    "status.json": "586e1e64908489d7fb26cec9bc517ac49c3064372a10916dbe6ae655ae271a5f",
    "first-start.json": "e17fe6440b900e4ff8518e50fa54168e795e682186d7664a6d1178a8b14bfe55",
}
PIDS = {65802: upgrade.GUEST, 65804: upgrade.VM}
STARTED = "Tue Sep 29 21:24:24 2026"
CONSENT = "STOP TEST GUEST"


def recover_baseline(records, token):
    require(re.fullmatch(r"[0-9]{1,20}", token) is not None, "Malformed private PF reference")
    enables = [i for i, row in enumerate(records) if row["command"] == ["/sbin/pfctl", "-E"]]
    require(len(enables) == 1, "Expected one original PF enable")
    entry = records[enables[0]]
    require(entry["exit"] == 0 and base.parse_pf_token(entry["stdout"] + entry["stderr"]) == token,
            "PF reference does not match original acquisition")
    require(not any(row["command"][:2] == ["/sbin/pfctl", "-X"] for row in records),
            "Prior PF release attempted; do not retry")
    installs = [row for row in records if row["command"][:1] == ["/usr/sbin/installer"]]
    require(len(installs) == 1 and installs[0]["exit"] == 0 and installs[0]["command"] ==
            ["/usr/sbin/installer", "-pkg", str(STAGE / "candidate.pkg"), "-target", "/"],
            "Original successful installation evidence changed")
    prior = records[:enables[0]]
    listeners = [base.listener_endpoints(row["stdout"]) for row in prior
                 if row["command"] == upgrade.LISTENERS and row["exit"] == 0]
    require(bool(listeners) and all(item == listeners[0] for item in listeners),
            "Original listener baseline is missing or inconsistent")
    for endpoint in ("*:22", "*:445", "*:5900", "192.168.1.115:11434", "127.0.0.1:49199"):
        require(any(address == endpoint for _, address in listeners[0]), "Incomplete native listener baseline")
    require(not any(uid == "309" for uid, _ in listeners[0]), "Pre-install runtime listener found")

    # Reconstruct the pre-enable inventory using only the fixed read queries
    # requested by the existing parser. Never execute a command from a log.
    def recorded_command(args, **_kwargs):
        matches = [row for row in prior if row["command"] == args]
        require(bool(matches), "Missing original PF read")
        first = matches[0]
        require(all((row["exit"], row["stdout"], row["stderr"]) ==
                    (first["exit"], first["stdout"], first["stderr"]) for row in matches),
                "Original PF reads differ")
        return subprocess.CompletedProcess(args, first["exit"], first["stdout"], first["stderr"])

    replay = base.Session(Path("/unused"))
    replay.command = recorded_command
    return listeners[0], replay.inspect_empty_pf()


class RestartCleanup(upgrade.Upgrade):
    old_executables = new_executables = ownership.OwnershipUpgrade.new_executables

    def assert_sensor_absent(self):
        require(not self.service_loaded("com.squirrelops.sensor"), "Sensor restarted; retain protection")
        require(set(self.processes()) <= PIDS.keys(), "New runtime process exists; retain protection")
        result = self.command(["/usr/bin/pgrep", "-x", "SquirrelOpsHome"], check=False)
        require(result.returncode == 1 and not result.stderr.strip(), "Close app before cleanup")

    def process_identity(self, pid):
        require(pid in PIDS, "Only the two recorded guest processes are in scope")
        result = self.command(["/bin/ps", "-p", str(pid), "-o", "uid=,comm="], check=False)
        if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
            return None
        require(result.returncode == 0 and result.stdout.strip().split(None, 1) == ["309", PIDS[pid]],
                "Recorded process identity changed")
        started = self.command(["/bin/ps", "-p", str(pid), "-o", "lstart="]).stdout.strip()
        require(started == STARTED, "Recorded process start time changed")
        return (309, PIDS[pid], started)

    def terminate_recorded(self, pid):
        self.assert_sensor_absent()
        if self.process_identity(pid) is None:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process_identity(pid) is None:
                return
            time.sleep(1)
        raise RuntimeError("Recorded guest did not stop; no force-kill or PF release")

    def verify_containment(self):
        self.assert_sensor_absent()
        require(self.service_loaded("com.squirrelops.helper"), "Original helper unavailable")
        for pid in PIDS:
            self.process_identity(pid)
        require(self.owned() == ["192.168.1.240"], "Alias ownership changed")
        for key, flag in (("pf_rules", "-sr"), ("pf_nat", "-sn")):
            require(self.pf(["-a", upgrade.PRODUCT_ANCHOR, flag]) == self.first_start[key],
                    "Product PF rules changed; retain protection")
        pattern = r"(?<![0-9])" + re.escape(self.token) + r"(?![0-9])"
        require(re.search(pattern, self.pf(["-s", "References"])), "Original PF reference missing")
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF no longer enabled")
        self.host_baseline()

    def preflight_cleanup(self):
        require(os.geteuid() == 0 and os.isatty(0), "Use attended mini cleanup bootstrap")
        require(self.task_dir.parent == Path("/private/var/root") and
                re.fullmatch(r"squirrelops-mini-restart-cleanup\.[A-Za-z0-9_-]+", self.task_dir.name),
                "Wrong private staging directory")
        for directory in (self.task_dir, BASELINE.parent.parent, BASELINE.parent, BASELINE, PUBLIC, STAGE):
            base.safe_directory(directory)
        for name, expected in INPUTS.items():
            base.safe_file(BASELINE / name)
            require(base.digest(BASELINE / name) == expected, "Original input changed")
        for name, expected in EVIDENCE.items():
            base.safe_file(PUBLIC / name)
            require(base.digest(PUBLIC / name) == expected, "Failed-run evidence changed")
        require(base.digest(STAGE / "candidate.pkg") == ownership.PACKAGE_SHA, "Original candidate changed")
        token_file = BASELINE / "pf-reference-token"
        base.safe_file(token_file)
        require(stat.S_IMODE(token_file.stat().st_mode) == 0o600, "PF reference must remain private")
        self.token = token_file.read_text().strip()
        self.private_reference = self.token
        paths = sorted(BASELINE.glob("command-*.json"), key=lambda path: int(path.stem.split("-")[1]))
        require(1 <= len(paths) <= 2000, "Unexpected command evidence count")
        records = []
        for path in paths:
            base.safe_file(path)
            records.append(json.loads(path.read_text()))
        self.baseline_listeners, self.pf_baseline = recover_baseline(records, self.token)
        self.first_start = json.loads((PUBLIC / "first-start.json").read_text())
        self.backup = Path(tempfile.mkdtemp(prefix="restart-cleanup-20260930.", dir=BASELINE))
        self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-restart-cleanup-results.", dir="/private/var/tmp"))
        self.public.chmod(0o755)
        shutil.copy2(Path(__file__), self.backup / "mini_restart_cleanup.py")
        for name in EVIDENCE:
            shutil.copy2(PUBLIC / name, self.backup / name)
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == "26A428", "OS changed")
        require("100.108.203.27" in self.command(["/sbin/ifconfig", "-a"]).stdout, "Wrong host")
        require(base.pwd.getpwnam("_squirrelops").pw_uid == 309 and
                base.grp.getgrnam("_squirrelops").gr_gid == 309, "Service identity changed")
        for path, expected in {**self.old_executables, upgrade.RUNTIME: upgrade.PYTHON_SHA}.items():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0) and
                    not info.st_mode & 0o022 and base.digest(path) == expected, "Installed payload changed")
        require(base.digest(base.SENSOR / "config.yaml") == base.CONFIG_SHA, "Bounded configuration changed")
        for component in ("app", "sensor"):
            result = self.command(["/usr/sbin/pkgutil", "--pkg-info", "com.squirrelops.home." + component]).stdout
            require("version: 2.1.0\n" in result and "install-time: 1790731448\n" in result, "Receipt changed")
        self.verify_containment()
        database = ownership.DATABASE
        parent, info = database.parent.lstat(), database.lstat()
        require(stat.S_ISDIR(parent.st_mode) and (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) ==
                (309, 309, 0o700), "Unsafe database parent")
        require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (309, 309) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in (0o600, 0o644) and info.st_size <= 64 * 1024**2,
                "Unsafe database")
        for path in (database.parent, database):
            require(len(self.command(["/bin/ls", "-lde", str(path)]).stdout.splitlines()) == 1, "Database ACL drift")
        with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(self.backup / "pre-cleanup.sqlite")) as target:
                source.backup(target)
                require(target.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Backup integrity failure")
        scope = ("SIGTERM only recorded guest 65802 and VM 65804, UID 309, with matching executable/start time.\n"
                 "Withdraw owned .240 only after guests stop; clear only product rules, stop product helper,\n"
                 "release only the saved PF reference after native listener and empty-policy verification.\n"
                 "No install, force-kill, database edits, global PF reset, or Little Snitch changes.\n"
                 "Keep installation, data and backups. No automatic restart inverse; a new guarded start needs approval.\n")
        (self.backup / "scope.txt").write_text(scope)
        print(f"Private cleanup backup: {self.backup}\nSanitized results: {self.public}\n{scope}", flush=True)
        print(f"Type {CONSENT} to perform this exact cleanup, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Cleanup not approved; nothing stopped")
        with (BASELINE / "restart-cleanup-attempt-20260930.json").open("x") as marker:
            json.dump({"backup": str(self.backup), "results": str(self.public)}, marker)

    def cleanup_runtime(self):
        self.verify_containment()
        self.publish("stopping_recorded_guest")
        for pid in PIDS:
            self.terminate_recorded(pid)
        self.assert_sensor_absent()
        require(not self.processes(), "Guest runtime remains; retain protection")
        self.install_started = True
        # The existing, tested teardown preserves the native endpoint baseline,
        # withdraws only owned aliases and releases only this run's reference.
        self.stop()

    def stop_job(self, label):
        if label == "com.squirrelops.sensor":
            # Do not turn a racing fresh start into a new, unauthorized stop.
            self.assert_sensor_absent()
            return
        require(label == "com.squirrelops.helper", "Unexpected cleanup service")
        super().stop_job(label)

    def run_cleanup(self):
        os.umask(0o077)
        try:
            self.preflight_cleanup()
            self.cleanup_runtime()
        except BaseException as exc:
            message = str(exc)
            token = getattr(self, "private_reference", None) or self.token
            if token:
                message = message.replace(token, "[PRIVATE PF REFERENCE]")
            if self.public is not None:
                self.publish("needs_review", reason=type(exc).__name__ + ": " + message)
            print("STOPPED: " + message + ". No broader cleanup attempted; do not reset networking.", flush=True)
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "signal_pids": list(PIDS), "baseline": str(BASELINE),
                          "confirmation": CONSENT, "install": False, "force_kill": False,
                          "delete_data": False, "global_pf_reset": False}, indent=2))
        return
    RestartCleanup(args.run).run_cleanup()


if __name__ == "__main__":
    main()
