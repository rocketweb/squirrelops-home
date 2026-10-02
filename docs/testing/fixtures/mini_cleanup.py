"""Exact-session cleanup only. No install, PF enable, global flush or file removal."""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import tempfile
import time

spec = importlib.util.spec_from_file_location("mini_acceptance", Path(__file__).with_name("mini_acceptance.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require = base.require

BASELINE = Path("/Library/SquirrelOps/acceptance-backups/mini-20260928.bukymecp")
PUBLIC = Path("/private/var/tmp/squirrelops-mini-results.fxk5kskd")
ORIGINAL_SHA = "47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a"
AFTER_SHA = "49f946c512f0ed7836dffbb72db893f7186ef7e4d9a65b94a7047c107e4337cf"
STATUS_SHA = "0105c16eb8883f98b046c558c42b9e24aeb3b8906f3cd71a81f56f2e2fe3ac2f"
GUEST = str(base.APP / "Contents/Library/Helpers/com.squirrelops.deception-guest")
VM = "/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine"
EXPECTED_PROCESSES = {27646: GUEST, 27647: VM, 27648: "/usr/sbin/distnoted"}
TERMINABLE = (27646, 27647)
LISTENERS = ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpun"]
WARNINGS = {"No ALTQ support in kernel", "ALTQ related functions disabled"}


def parse_reference(text: str) -> str:
    value = text.strip()
    require(re.fullmatch(r"[0-9]{1,20}", value) is not None, "Malformed private PF reference")
    return value


def reference_present(text: str, token: str) -> bool:
    return re.search(r"(?<![0-9])" + re.escape(token) + r"(?![0-9])", text) is not None


def recover_baseline(records: list[dict], token: str) -> set[tuple[str, str]]:
    """Bind cleanup to a successful install and the original, unreleased reference."""
    enable = [i for i, r in enumerate(records) if r["command"] == ["/sbin/pfctl", "-E"]]
    require(len(enable) == 1, "Expected one original PF enable")
    entry = records[enable[0]]
    require(entry["exit"] == 0 and base.parse_pf_token(entry["stdout"] + entry["stderr"]) == token,
            "Private PF reference does not match original acquisition")
    require(not any(r["command"][:2] == ["/sbin/pfctl", "-X"] for r in records),
            "A prior PF release was attempted; review instead of retrying")
    installed = [r for r in records if len(r["command"]) == 5
                 and r["command"][:2] == ["/usr/sbin/installer", "-pkg"]
                 and r["command"][3:] == ["-target", "/"] and r["exit"] == 0]
    require(len(installed) == 1, "Successful original installer evidence missing")
    path = Path(installed[0]["command"][2])
    require(path.name == "candidate.pkg" and path.parent.parent == Path("/private/var/root")
            and path.parent.name.startswith("squirrelops-mini-acceptance."), "Wrong original package location")
    prior = [r for r in records[:enable[0]] if r["command"] == LISTENERS and r["exit"] == 0]
    require(len(prior) == 1, "Original listener baseline is ambiguous")
    listeners = base.listener_endpoints(prior[0]["stdout"])
    for endpoint in ("*:22", "*:445", "*:5900", "192.168.1.115:11434", "127.0.0.1:49199"):
        require(any(address == endpoint for _, address in listeners), "Incomplete original listener baseline")
    return listeners


class Cleanup(base.Session):
    def __init__(self, task_dir: Path):
        super().__init__(task_dir)
        self.identities: dict[int, str] = {}

    def service_loaded(self, label: str) -> bool:
        require(label in ("com.squirrelops.sensor", "com.squirrelops.helper"), "Unexpected launchd target")
        result = self.command(["/bin/launchctl", "print", "system/" + label], check=False)
        if result.returncode == 0:
            require(result.stdout.startswith("system/" + label + " = {"), "Unexpected launchd response")
            return True
        require(f'Could not find service "{label}"' in result.stderr, "Launchd state is uncertain")
        return False

    def stop_job(self, label: str) -> None:
        if self.service_loaded(label):
            self.command(["/bin/launchctl", "bootout", "system/" + label], check=False, timeout=30)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not self.service_loaded(label):
                return
            time.sleep(1)
        raise RuntimeError("Service remains loaded; retaining protection")

    def pf(self, flags: list[str]) -> str:
        result = self.command(["/sbin/pfctl", *flags])
        require(all(not line.strip() or line.strip() in WARNINGS for line in result.stderr.splitlines()),
                "PF read returned an error; private log retained")
        return result.stdout

    def process_identity(self, pid: int) -> str | None:
        result = self.command(["/bin/ps", "-p", str(pid), "-o", "uid=,comm="], check=False)
        if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
            return None
        require(result.returncode == 0 and result.stdout.strip().split(None, 1)
                == ["309", EXPECTED_PROCESSES[pid]], "Recorded process identity changed; no signal sent")
        started = self.command(["/bin/ps", "-p", str(pid), "-o", "lstart="]).stdout.strip()
        require(bool(started), "Process start identity unavailable")
        return result.stdout.strip() + "\n" + started

    def verify_processes(self) -> None:
        result = self.command(["/usr/bin/pgrep", "-u", "309"], check=False)
        require(result.returncode in (0, 1) and not result.stderr.strip(), "Cannot inventory service processes")
        pids = {int(value) for value in result.stdout.split()}
        require(pids <= EXPECTED_PROCESSES.keys(), "New service process exists; preserve and review")
        for pid in pids:
            identity = self.process_identity(pid)
            if identity is not None:
                self.identities.setdefault(pid, identity)
                require(identity == self.identities[pid], "Service process was replaced")

    def terminate_recorded(self, pid: int) -> None:
        require(pid in TERMINABLE, "Only the two recorded test runtimes may receive a signal")
        identity = self.process_identity(pid)
        if identity is None:
            return
        require(identity == self.identities.get(pid), "Process no longer matches validated snapshot")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process_identity(pid) is None:
                return
            time.sleep(1)
        raise RuntimeError("Recorded runtime did not stop; no force-kill or PF release performed")

    def verify_host_baseline(self) -> None:
        require(self.baseline_listeners <= base.listener_endpoints(self.command(LISTENERS).stdout),
                "Original listener endpoint/UID parity changed")
        for interface, address in (("en0", "192.168.1.115"), ("en1", "192.168.1.254")):
            require(self.command(["/usr/sbin/ipconfig", "getifaddr", interface]).stdout.strip() == address,
                    "Mini interface address changed")

    def preflight_cleanup(self) -> None:
        require(os.geteuid() == 0 and os.isatty(0), "Use the attended cleanup bootstrap")
        require(self.task_dir.parent == Path("/private/var/root")
                and self.task_dir.name.startswith("squirrelops-mini-cleanup."), "Wrong private staging path")
        for directory in (self.task_dir, BASELINE.parent.parent, BASELINE.parent, BASELINE, PUBLIC):
            base.safe_directory(directory)
        for name, expected in (("mini_acceptance.py", ORIGINAL_SHA), ("proposed-config.yaml", base.CONFIG_SHA)):
            base.safe_file(BASELINE / name)
            require(base.digest(BASELINE / name) == expected, "Original baseline changed")
        for name, expected in (("after.json", AFTER_SHA), ("status.json", STATUS_SHA)):
            base.safe_file(PUBLIC / name)
            require(base.digest(PUBLIC / name) == expected, "Failed-run evidence changed; review needed")
        token_file = BASELINE / "pf-reference-token"
        base.safe_file(token_file)
        require(stat.S_IMODE(token_file.stat().st_mode) == 0o600, "PF reference is not private")
        self.token = parse_reference(token_file.read_text())
        files = sorted(BASELINE.glob("command-*.json"), key=lambda p: int(p.stem.split("-")[1]))
        require(1 <= len(files) <= 2000, "Unexpected original command record count")
        records = []
        for path in files:
            base.safe_file(path)
            records.append(json.loads(path.read_text()))
        self.baseline_listeners = recover_baseline(records, self.token)
        self.backup = Path(tempfile.mkdtemp(prefix="cleanup-20260929.", dir=BASELINE))
        self.public = PUBLIC
        (self.backup / "initial-status.json").write_text((PUBLIC / "status.json").read_text())
        (self.backup / "mini_cleanup.py").write_bytes(Path(__file__).read_bytes())
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == "26A428", "OS changed")
        require(base.pwd.getpwnam("_squirrelops").pw_uid == 309
                and base.grp.getgrnam("_squirrelops").gr_gid == 309, "Service identity changed")
        for path, expected in base.EXECUTABLES.items():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                    and base.digest(path) == expected, "Installed executable changed")
        require(base.digest(base.SENSOR / "config.yaml") == base.CONFIG_SHA, "Bounded configuration changed")
        for label in ("com.squirrelops.home.app", "com.squirrelops.home.sensor"):
            info = self.command(["/usr/sbin/pkgutil", "--pkg-info", label]).stdout
            require("version: 2.1.0\n" in info and "install-time: 1790689617\n" in info, "Package receipt changed")
        require(not self.service_loaded("com.squirrelops.sensor"), "Sensor restarted; do not touch a new session")
        require(self.service_loaded("com.squirrelops.helper"), "Expected helper unavailable")
        require(self.command(["/usr/bin/pgrep", "-x", "SquirrelOpsHome"], check=False).returncode == 1,
                "Close the app before cleanup")
        self.verify_host_baseline()
        self.verify_processes()
        require(self.owned() == ["192.168.1.240"], "Alias ownership no longer matches the failed run")
        prior = json.loads((PUBLIC / "after.json").read_text())
        for key, flag in (("pf_rules", "-sr"), ("pf_nat", "-sn")):
            require(self.pf(["-a", "com.apple/squirrelops", flag]) == prior[key], "Test PF rules changed")
        require(reference_present(self.pf(["-s", "References"]), self.token), "Owned PF reference missing")
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF is not enabled")
        with closing(sqlite3.connect(f"file:{base.SENSOR}/data/squirrelops.db?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(self.backup / "pre-cleanup.sqlite")) as target:
                source.backup(target)
                require(target.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Database backup failed")
        (self.backup / "scope.txt").write_text(
            "SIGTERM only recorded guest/VM identities; no force-kill. Withdraw only owned .240.\n"
            "Clear only product forwards after alias absence; stop only product helper; release only saved PF reference.\n"
            "Retain installation, account, data, all baselines and unrelated services. No automatic restart inverse.\n")
        # Refuse concurrent/repeated mutation attempts; never remove this marker to force a retry.
        with (BASELINE / "cleanup-attempt-20260929.json").open("x") as marker:
            json.dump({"private_cleanup_backup": str(self.backup), "results": str(PUBLIC)}, marker)
        print(f"Private cleanup backup: {self.backup}", flush=True)

    def cleanup_runtime(self) -> None:
        self.publish("cleanup_stopping")
        # The sensor is already absent; never stop a newly started instance.
        require(not self.service_loaded("com.squirrelops.sensor"), "Sensor restarted; retaining containment")
        self.verify_processes()
        for pid in TERMINABLE:
            self.terminate_recorded(pid)
        self.verify_processes()
        require(all(self.process_identity(pid) is None for pid in TERMINABLE), "Guest runtime remains")
        listeners = base.listener_endpoints(self.command(LISTENERS).stdout)
        require(not any(uid == "309" for uid, _ in listeners), "Service-owned TCP listener remains")
        require(self.owned() == ["192.168.1.240"], "Ownership changed before withdrawal")
        self.rpc("setupPortForwards", {"rules": [], "interface": "en0", "protected_endpoints": [
            {"ip": "192.168.1.240", "direct_ports": []}]})
        self.rpc("removeIPAlias", {"ip": "192.168.1.240", "interface": "en0"})
        self.assert_no_test_network()
        require(not self.owned(), "Ownership remains; keep protection")
        self.rpc("clearPortForwards", {})
        self.stop_job("com.squirrelops.helper")
        self.assert_no_test_network()
        self.inspect_empty_pf()
        self.verify_host_baseline()
        require(not self.service_loaded("com.squirrelops.sensor"), "Sensor restarted before PF release")
        require(reference_present(self.pf(["-s", "References"]), self.token), "Reference changed before release")
        # Only our private saved token is passed; it is never printed or published.
        self.command(["/sbin/pfctl", "-X", self.token])
        require(not reference_present(self.pf(["-s", "References"]), self.token), "Owned reference still present")
        self.token = None
        self.assert_no_test_network()
        self.verify_host_baseline()
        state = self.pf(["-s", "info"])
        self.publish("stopped", installation_retained=True, test_data_retained=True,
                     aliases_absent=True, original_listener_endpoints_present=True,
                     test_guest_stopped=True, own_pf_reference_released=True,
                     pf_enabled=bool(re.search(r"^Status:\s+Enabled\b", state, re.M)))
        print("CLEANUP COMPLETE: test guest and helper stopped; aliases withdrawn; only our PF reference released.", flush=True)
        print("Installation, account, data and backups retained. Keep the app closed pending review.", flush=True)

    def run_cleanup(self) -> None:
        os.umask(0o077)
        try:
            self.preflight_cleanup()
            self.cleanup_runtime()
        except BaseException as exc:
            # Do not retry broad cleanup or release references after an uncertain result.
            message = str(exc)
            if self.token:
                message = message.replace(self.token, "[PRIVATE PF REFERENCE]")
            if self.public is not None:
                self.publish("needs_review", reason=type(exc).__name__ + ": " + message)
            print("STOPPED: " + message + ". No broader cleanup attempted; do not reset PF.", flush=True)
            raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "baseline": str(BASELINE), "results": str(PUBLIC),
                          "install": False, "signal_pids": list(TERMINABLE), "vip": "192.168.1.240",
                          "delete_data": False, "global_pf_reset": False}, indent=2))
        return
    Cleanup(args.run).run_cleanup()


if __name__ == "__main__":
    main()
