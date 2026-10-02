"""Attended, mini-only stop and persistent hold. Never installs or probes LAN."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from contextlib import closing
from pathlib import Path

spec = importlib.util.spec_from_file_location("launchd", Path(__file__).with_name("mini_launchd_acceptance.py"))
launchd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launchd)
base, upgrade = launchd.base, launchd.upgrade
require = base.require
base.VIPS = {"192.168.1.240"}
ROOT = Path("/Library/SquirrelOps/acceptance-backups")
BUILD = "26A434"
BOOT = 1790766531
CONSENT = "STOP MINI AND HOLD"
SLEEP = "/bin/sleep"
SENSOR_JOB, HELPER_JOB = upgrade.JOBS
RUNTIME = base.SENSOR / "python/bin/python3.12"
RUNTIME_NAMES = {str(RUNTIME), str(RUNTIME.with_name("python3"))}
DB = base.SENSOR / "data/squirrelops.db"


def boot_seconds(text):
    match = re.search(r"\bsec = ([0-9]+),", text)
    require(match is not None, "Unrecognized boot identity")
    return int(match[1])


def disabled(text, label):
    require(label in upgrade.JOBS or label.startswith("com.squirrelops.test.recovery."), "Wrong job")
    matches = re.findall(r'"' + re.escape(label) + r'"\s*=>\s*([^\s]+)', text)
    require(len(matches) <= 1 and all(value in ("enabled", "disabled", "true", "false") for value in matches),
            "Unrecognized disabled-state record")
    return bool(matches and matches[0] in ("disabled", "true"))


def job_pid(text, label):
    require(text.startswith("system/" + label + " = {"), "Unexpected launchd job")
    pids = re.findall(r"^\tpid = ([0-9]+)$", text, re.MULTILINE)
    require(len(pids) <= 1, "Ambiguous launchd PID")
    return int(pids[0]) if pids else None


def durable_receipt(receipt, current_boot):
    require(receipt.get("schema") == 1 and receipt.get("phase") == "held_stopped"
            and receipt.get("boot_seconds") == current_boot
            and receipt.get("disabled_jobs") == list(upgrade.JOBS)
            and all(receipt.get(key) is True for key in (
                "runtime_absent", "aliases_absent", "product_rules_empty", "unrelated_policy_unchanged",
                "pf_enablement_unchanged", "pf_references_unchanged", "intent_preserved")),
            "Fresh stopped-state receipt required; a historical receipt is not current authority")


def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def checked_bytes(path, uid, modes, limit=1024 * 1024):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid
            and stat.S_IMODE(info.st_mode) in modes and info.st_size <= limit, "Unsafe source metadata: " + path.name)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_ino, opened.st_dev) == (info.st_ino, info.st_dev), "Source changed during open")
        result = stream.read(limit + 1)
    require(len(result) <= limit, "Source exceeds bound")
    return result


def process_rows(text):
    rows = {}
    for line in text.splitlines():
        fields = line.strip().split(None, 3)
        # Darwin ps renders nobody's uid_t (4294967294) as signed -2.
        # Keep the reported UID; neither representation can match sensor 309.
        # PIDs and parent PIDs remain unsigned, and malformed rows still stop.
        require(len(fields) == 4 and re.fullmatch(r"-?[0-9]+", fields[0]) is not None
                and all(re.fullmatch(r"[0-9]+", value) is not None for value in fields[1:3]),
                "Malformed process inventory")
        uid, pid, parent = map(int, fields[:3])
        require(-(2**31) <= uid < 2**32 and 0 <= pid < 2**31 and 0 <= parent < 2**31,
                "Process identity outside Darwin bounds")
        require(pid not in rows, "Duplicate process")
        rows[pid] = {"uid": uid, "parent": parent, "executable": fields[3]}
    return rows


def runtime_rows(rows, allow_sleep=False):
    result = {}
    for pid, row in rows.items():
        executable = row["executable"]
        if row["uid"] == 309:
            if executable == "/usr/sbin/distnoted":
                continue
            require(executable in RUNTIME_NAMES | {upgrade.GUEST, upgrade.VM}
                    or (allow_sleep and executable == SLEEP), "Unexpected service-account process")
            result[pid] = row
        elif executable in RUNTIME_NAMES | {upgrade.GUEST, str(base.APP / "Contents/MacOS/SquirrelOpsHome")}:
            raise RuntimeError("Close the app or review unexpected product identity")
    return result


def arm_next_launch(command, target):
    command(["/bin/launchctl", "debug", target, "--program", SLEEP, "--", SLEEP, "2147483647"])


def native_probe(command, directory):
    """Root/system-domain proof before any product service mutation."""
    require(os.geteuid() == 0, "The system-domain probe requires attended root")
    label = "com.squirrelops.test.recovery." + uuid.uuid4().hex
    target = "system/" + label
    events = directory / "probe-events.txt"
    worker = directory / "probe-worker.py"
    private_write(worker, (
        b"import os,signal,sys,time\nfrom pathlib import Path\n"
        b"p=Path(sys.argv[1])\n"
        b"def record(s):\n    with p.open('a') as f: f.write(s+'\\n'); f.flush()\n"
        b"def stop(*args):\n    record('TERM'); time.sleep(8); record('DONE'); sys.exit(0)\n"
        b"signal.signal(signal.SIGTERM,stop)\nrecord('READY '+str(os.getpid()))\n"
        b"while True: time.sleep(.1)\n"
    ))
    plist = directory / "probe.plist"
    private_write(plist, plistlib.dumps({
        "Label": label, "RunAtLoad": True, "KeepAlive": True,
        "ProgramArguments": [str(RUNTIME), "-I", "-B", str(worker), str(events)],
        "StandardOutPath": str(directory / "probe-out.txt"),
        "StandardErrorPath": str(directory / "probe-err.txt"),
    }))
    loaded = False
    try:
        command(["/bin/launchctl", "bootstrap", "system", str(plist)])
        loaded = True
        deadline = time.monotonic() + 20
        while not events.exists() or "READY " not in events.read_text():
            require(time.monotonic() < deadline, "Disposable probe did not become ready")
            time.sleep(.1)
        pid = int(events.read_text().splitlines()[0].split()[1])
        require(job_pid(command(["/bin/launchctl", "print", target]).stdout, label) == pid, "Probe PID changed")
        command(["/bin/launchctl", "disable", target])
        require(disabled(command(["/bin/launchctl", "print-disabled", "system"]).stdout, label), "Probe disable failed")
        arm_next_launch(command, target)
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 35
        inert = False
        while time.monotonic() < deadline:
            state = command(["/bin/launchctl", "print", target]).stdout
            current = job_pid(state, label)
            if "DONE" in events.read_text() and current and current != pid:
                result = command(["/bin/ps", "-p", str(current), "-o", "comm="])
                require(result.stdout.strip() == SLEEP, "Probe respawn was not inert")
                inert = True
                break
            time.sleep(.2)
        require(inert and events.read_text().splitlines() == [f"READY {pid}", "TERM", "DONE"],
                "Disposable probe failed; no product shutdown authorized")
    finally:
        if loaded:
            command(["/bin/launchctl", "bootout", target], check=False, timeout=30)
        command(["/bin/launchctl", "enable", target], check=False)
        deadline = time.monotonic() + 15
        gone = command(["/bin/launchctl", "print", target], check=False)
        while gone.returncode == 0 and time.monotonic() < deadline:
            time.sleep(.2)
            gone = command(["/bin/launchctl", "print", target], check=False)
        require(gone.returncode != 0 and f'Could not find service "{label}"' in gone.stderr,
                "Disposable probe cleanup incomplete; do not continue")


class Recovery(upgrade.Upgrade):
    old_executables = new_executables = launchd.LaunchdUpgrade.old_executables

    def __init__(self, task_dir):
        super().__init__(task_dir)
        self.backup = task_dir
        self.mutation_started = False

    def job(self, label):
        result = self.command(["/bin/launchctl", "print", "system/" + label], check=False)
        if upgrade.loaded_result(result, label):
            return result.stdout
        return None

    def rows(self):
        rows = process_rows(self.command(["/bin/ps", "-axo", "uid=,pid=,ppid=,comm="]).stdout)
        # The attended observer itself uses the pinned installed Python. Do not
        # mistake it for a product service, or exempt any other root Python.
        observer = rows.get(os.getpid())
        require(observer is not None and observer["uid"] == os.geteuid()
                and observer["uid"] != 309 and observer["executable"] in RUNTIME_NAMES,
                "Process observer identity is uncertain")
        del rows[os.getpid()]
        return rows

    def hold_state(self):
        text = self.command(["/bin/launchctl", "print-disabled", "system"]).stdout
        return {label: disabled(text, label) for label in upgrade.JOBS}

    def assert_boot(self):
        require(boot_seconds(self.command(["/usr/sbin/sysctl", "kern.boottime"]).stdout) == BOOT, "Mini rebooted; review required")

    def inventory_policy(self):
        result, pending = {}, [""]
        while pending:
            anchor = pending.pop(0)
            require(anchor not in result and len(result) < 128, "PF inventory exceeds bounds")
            prefix = ["-a", anchor] if anchor else []
            children = sorted(base.anchor_path(line.strip(), anchor)
                              for line in self.pf(prefix + ["-s", "Anchors"]).splitlines() if line.strip())
            require(len(children) == len(set(children)), "Ambiguous PF tree")
            result[anchor] = {"children": children, "-sr": self.pf(prefix + ["-sr"]), "-sn": self.pf(prefix + ["-sn"])}
            pending.extend(children)
        return result

    @staticmethod
    def unrelated(policy):
        return {anchor: {**item, "children": [child for child in item["children"] if child != upgrade.PRODUCT_ANCHOR]}
                for anchor, item in policy.items() if anchor != upgrade.PRODUCT_ANCHOR}

    def pf_enabled(self):
        result = re.findall(r"^Status:\s+(Enabled|Disabled)\b", self.pf(["-s", "info"]), re.MULTILINE)
        require(len(result) == 1, "PF enablement uncertain")
        return result[0] == "Enabled"

    def native_listeners(self):
        return {row for row in base.listener_endpoints(self.command(upgrade.LISTENERS).stdout) if row[0] != "309"}

    def no_aliases(self):
        require(not self.owned(), "Alias ledger remains; protection must remain")
        self.assert_no_test_network()

    def database_backup(self, label):
        """Read live SQLite as its service UID, never create root-owned WAL/SHM."""
        base.safe_directory(DB.parent.parent)
        info = DB.parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (309, 309, 0o700),
                "Database directory identity drift")
        checked_bytes(DB, 309, {0o600, 0o644}, 64 * 1024**2)
        for path in (DB.parent, DB):
            require(len(self.command(["/bin/ls", "-lde", str(path)]).stdout.splitlines()) == 1, "Database ACL drift")
        temporary = Path(tempfile.mkdtemp(prefix="squirrelops-reboot-db.", dir="/private/var/tmp"))
        temporary.chmod(0o700)
        os.chown(temporary, 309, 309)
        snapshot = temporary / "snapshot.sqlite"
        worker = (
            "import sqlite3,sys; from contextlib import closing; "
            "s=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=5); "
            "d=sqlite3.connect(sys.argv[2]); s.backup(d); "
            "assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; d.close(); s.close()"
        )
        result = subprocess.run([str(RUNTIME), "-I", "-B", "-c", worker, str(DB), str(snapshot)],
                                user=309, group=309, extra_groups=[], env={"PATH": "/usr/bin:/bin"},
                                capture_output=True, timeout=30, check=False)
        require(result.returncode == 0, "Service-identity SQLite backup failed; no output exposed")
        data = checked_bytes(snapshot, 309, {0o600, 0o644}, 64 * 1024**2)
        destination = self.backup / (label + ".sqlite")
        private_write(destination, data)
        with closing(sqlite3.connect(f"file:{destination}?mode=ro", uri=True)) as db:
            require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Private backup integrity failed")
            intent = list(db.execute("SELECT id,decoy_type,bind_address,port,status FROM decoys ORDER BY id"))
            require(0 < len(intent) <= 50, "Unexpected intent inventory size")
            ips = [row[0] for row in db.execute("SELECT ip_address FROM virtual_ips")]
            require(set(ips) <= base.VIPS, "Persisted virtual IP outside mini scope")
        # Preserve the service-owned intermediate privately, never follow or
        # recursively delete a path the service UID could replace.
        private_write(self.backup / (label + "-snapshot.json"), json.dumps({
            "sha256": hashlib.sha256(data).hexdigest(), "source": str(DB),
            "private_intermediate": str(temporary), "uid": 309,
        }, indent=2).encode())
        return intent

    def backup_preflight(self):
        """Read-only product audit and durable backups; no launchd experiment."""
        require(os.geteuid() == 0 and os.isatty(0), "Use attended root bootstrap")
        require(self.task_dir.parent == ROOT and re.fullmatch(r"mini-reboot-20260930\.[A-Za-z0-9_-]+", self.task_dir.name),
                "Wrong durable evidence directory")
        for directory in (ROOT.parent, ROOT, self.task_dir, base.SENSOR, base.APP, base.HELPER.parent):
            base.safe_directory(directory)
            require(len(self.command(["/bin/ls", "-lde", str(directory)]).stdout.splitlines()) == 1,
                    "Root path ACL drift")
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == BUILD, "OS build changed")
        self.assert_boot()
        interfaces = self.command(["/sbin/ifconfig", "-a"]).stdout
        require("100.108.203.27" in interfaces and not re.search(r"\binet 192\.168\.1\.241\s", interfaces), "Host/scope drift")
        require(self.command(["/usr/sbin/ipconfig", "getifaddr", "en0"]).stdout.strip() == "192.168.1.115", "Wrong LAN host")
        require(base.pwd.getpwnam("_squirrelops").pw_uid == 309 and base.grp.getgrnam("_squirrelops").gr_gid == 309,
                "Service identity changed")
        for path, expected in {**self.old_executables, RUNTIME: upgrade.PYTHON_SHA}.items():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022
                    and base.digest(path) == expected, "Installed payload drift: " + path.name)
        require(RUNTIME.with_name("python3").resolve() == RUNTIME.resolve(), "Python alias drift")
        for component in ("app", "sensor"):
            receipt = self.command(["/usr/sbin/pkgutil", "--pkg-info", "com.squirrelops.home." + component]).stdout
            require("version: 2.1.0\n" in receipt and "install-time: 1790731448\n" in receipt, "Package changed")
        require(not any(self.hold_state().values()), "An existing disabled job needs separate review")
        config = checked_bytes(base.SENSOR / "config.yaml", 309, {0o600})
        require(hashlib.sha256(config).hexdigest() == base.CONFIG_SHA, "Configuration changed")
        private_write(self.backup / "config-before.yaml", config)
        for label in upgrade.JOBS:
            source = Path("/Library/LaunchDaemons") / (label + ".plist")
            data = checked_bytes(source, 0, {0o644, 0o600})
            require(plistlib.loads(data).get("Label") == label, "Launch plist identity changed")
            private_write(self.backup / source.name, data)
        self.original_jobs = {label: self.job(label) for label in upgrade.JOBS}
        require(all(self.original_jobs.values()), "Expected running mini services")
        self.sensor_pid = job_pid(self.original_jobs[SENSOR_JOB], SENSOR_JOB)
        self.helper_pid = job_pid(self.original_jobs[HELPER_JOB], HELPER_JOB)
        self.original_rows = self.rows()
        relevant = runtime_rows(self.original_rows)
        require(self.sensor_pid in relevant and relevant[self.sensor_pid]["executable"] in RUNTIME_NAMES,
                "Sensor identity mismatch")
        require(self.helper_pid in self.original_rows and self.original_rows[self.helper_pid]["uid"] == 0
                and self.original_rows[self.helper_pid]["executable"] == str(base.HELPER), "Helper identity mismatch")
        require(sum(row["executable"] in RUNTIME_NAMES for row in relevant.values()) == 1
                and sum(row["executable"] == upgrade.GUEST for row in relevant.values()) == 1
                and sum(row["executable"] == upgrade.VM for row in relevant.values()) == 1, "Unexpected runtime cohort")
        require(all(row["parent"] == self.sensor_pid for row in relevant.values() if row["executable"] == upgrade.GUEST),
                "Guest parent changed")
        self.started = self.command(["/bin/ps", "-p", str(self.sensor_pid), "-o", "lstart="]).stdout.strip()
        require(self.owned() == ["192.168.1.240"], "Owned alias scope changed")
        self.policy = self.inventory_policy()
        product = self.policy.get(upgrade.PRODUCT_ANCHOR)
        require(product is not None and not product["children"], "Missing product containment policy")
        upgrade.verify_guarded_snapshot({"owned_aliases": self.owned(), "pf_rules": product["-sr"], "pf_nat": product["-sn"]})
        require(self.pf_enabled(), "PF is not enabled around the current guest; separate review required")
        self.references = self.pf(["-s", "References"])
        self.listeners = self.native_listeners()
        self.original_intent = self.database_backup("before-stop")

    def preflight(self):
        self.backup_preflight()
        private_write(self.backup / "recovery-inverse.txt", (
            b"No automatic restart or database rollback. Config/plists are not modified.\n"
            b"Prior effective state: sensor and helper enabled and loaded.\n"
            b"After verified stopped state, separately reviewed upgrade may use launchctl enable\n"
            b"for system/com.squirrelops.sensor and system/com.squirrelops.helper.\n"
            b"Do not bootstrap the old broad-pool configuration while .241 belongs to the Studio.\n"
            b"The one-shot debug replacement is cleared by unloading its exact job.\n"
            b"Never release old PF reference tokens or reset PF. Database backups are evidence, not an automatic downgrade.\n"
        ))
        print(f"Durable private backup: {self.backup}", flush=True)
        print("Preflight backed up config, launch plists, launchd state and a consistent SQLite snapshot.", flush=True)
        print("Testing one disposable system launchd job. No product mutation until this passes and you confirm.", flush=True)
        native_probe(self.command, self.backup)
        print("Disposable shutdown probe passed.", flush=True)
        print("Changes: disable ONLY mini sensor/helper across reboot; arm one inert next sensor launch;", flush=True)
        print("send SIGTERM to the verified sensor and allow 90s cleanup, then unload its inert job and helper.", flush=True)
        print("No installer, database edits, manual alias/PF changes, PF reference release, or Little Snitch changes.", flush=True)
        print(f"Type {CONSENT} to apply, or Return to leave product services unchanged:", flush=True)
        require(input().strip() == CONSENT, "Recovery not approved; product services unchanged")

    def stop_and_hold(self):
        self.assert_boot()
        require(not any(self.hold_state().values()), "Hold state changed after preview")
        current = self.rows()
        require(runtime_rows(current) == runtime_rows(self.original_rows), "Runtime cohort changed after preview")
        require(job_pid(self.job(SENSOR_JOB) or "", SENSOR_JOB) == self.sensor_pid
                and job_pid(self.job(HELPER_JOB) or "", HELPER_JOB) == self.helper_pid, "Service changed after preview")
        require(self.inventory_policy() == self.policy and self.pf_enabled()
                and self.pf(["-s", "References"]) == self.references, "PF state changed after preview")
        require(self.owned() == ["192.168.1.240"], "Alias scope changed after preview")
        self.mutation_started = True
        private_write(self.backup / "mutation-started.json", json.dumps({"boot_seconds": BOOT, "sensor_pid": self.sensor_pid}).encode())
        for label in upgrade.JOBS:
            self.command(["/bin/launchctl", "disable", "system/" + label])
        require(all(self.hold_state().values()), "Persistent hold failed; no signal sent")
        arm_next_launch(self.command, "system/" + SENSOR_JOB)
        require(job_pid(self.job(SENSOR_JOB) or "", SENSOR_JOB) == self.sensor_pid
                and self.rows().get(self.sensor_pid) == self.original_rows[self.sensor_pid]
                and self.command(["/bin/ps", "-p", str(self.sensor_pid), "-o", "lstart="]).stdout.strip() == self.started,
                "Sensor changed before signal; no signal sent")
        os.kill(self.sensor_pid, signal.SIGTERM)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = runtime_rows(self.rows(), allow_sleep=True)
            require(all(pid in self.original_rows or row["executable"] == SLEEP for pid, row in rows.items()),
                    "Unexpected replacement runtime; no further stop attempted")
            if not any(row["executable"] != SLEEP for row in rows.values()):
                break
            time.sleep(1)
        else:
            raise RuntimeError("Sensor/guest exceeded graceful budget; no force-kill or protection removal")
        self.no_aliases()
        policy = self.inventory_policy()
        product = policy.get(upgrade.PRODUCT_ANCHOR, {"-sr": "", "-sn": "", "children": []})
        require(not product["-sr"].strip() and not product["-sn"].strip() and not product["children"],
                "Sensor cleanup left product rules; no manual flush authorized")
        require(self.unrelated(policy) == self.unrelated(self.policy), "Unrelated PF policy changed")
        # The original sensor and guest have gone; a loaded job can now only
        # run the already-armed inert next invocation. Never bootout a live sensor.
        for label in upgrade.JOBS:
            state = self.job(label)
            if state is not None:
                pid = job_pid(state, label)
                if label == SENSOR_JOB:
                    remaining = runtime_rows(self.rows(), allow_sleep=True)
                    require(not remaining or (pid is not None and set(remaining) == {pid}
                            and remaining[pid]["executable"] == SLEEP),
                            "Product runtime returned before bootout; hold retained")
                else:
                    require(pid == self.helper_pid and self.rows().get(pid) == self.original_rows[pid],
                            "Helper identity changed before bootout")
                self.command(["/bin/launchctl", "bootout", "system/" + label], timeout=30)
            deadline = time.monotonic() + 15
            while self.job(label) is not None:
                require(time.monotonic() < deadline, "Job removal incomplete; hold retained")
                time.sleep(.2)
        self.assert_boot()
        require(not runtime_rows(self.rows(), allow_sleep=True), "Runtime remains")
        require(all(self.hold_state().values()), "Persistent hold lost")
        self.no_aliases()
        require(self.native_listeners() == self.listeners, "Native listener baseline changed")
        require(self.unrelated(self.inventory_policy()) == self.unrelated(self.policy), "Unrelated PF changed")
        require(self.pf_enabled() and self.pf(["-s", "References"]) == self.references, "PF enablement/references changed")
        require(self.database_backup("after-stop") == self.original_intent, "Persisted decoy intent changed; evidence retained")
        receipt = {"schema": 1, "phase": "held_stopped", "boot_seconds": BOOT, "os_build": BUILD,
                   "disabled_jobs": list(upgrade.JOBS), "runtime_absent": True, "aliases_absent": True,
                   "product_rules_empty": True, "unrelated_policy_unchanged": True,
                   "pf_enablement_unchanged": True, "pf_references_unchanged": True, "intent_preserved": True,
                   "pf_enabled": True, "config_sha256": base.CONFIG_SHA,
                   "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        durable_receipt(receipt, BOOT)
        private_write(self.backup / "held-stopped.json", json.dumps(receipt, indent=2).encode())
        print("RECOVERY COMPLETE: mini sensor/helper disabled and unloaded; guest and .240 alias gone.", flush=True)
        print("PF enablement/references preserved. Data and durable backups retained. Keep app closed.", flush=True)
        print(f"Receipt: {self.backup / 'held-stopped.json'}", flush=True)

    def run_recovery(self):
        os.umask(0o077)
        try:
            self.preflight()
            self.stop_and_hold()
        except BaseException as exc:  # noqa: BLE001 - retain failure evidence even on operator interruption
            # Do not display command arguments, config validation, or PF tokens.
            record = {"phase": "needs_review", "error_type": type(exc).__name__, "mutation_started": self.mutation_started,
                      "reason": str(exc) if isinstance(exc, RuntimeError) else "Inspect private command evidence"}
            private_write(self.backup / "failure.json", json.dumps(record, indent=2).encode())
            if isinstance(exc, RuntimeError):
                print("STOPPED: " + str(exc), flush=True)
            else:
                print("STOPPED: " + type(exc).__name__ + "; private evidence retained", flush=True)
            print(f"Evidence: {self.backup}. No automatic restart, force-kill or PF reset.", flush=True)
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "os_build": BUILD,
                          "boot_seconds": BOOT, "confirmation": CONSENT,
                          "disable_jobs": list(upgrade.JOBS), "durable_evidence": str(ROOT),
                          "install": False, "pf_enable_disable_or_reference_changes": False,
                          "studio_changes": False, "little_snitch_changes": False}, indent=2))
    else:
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt("Operator interrupted recovery")
        signal.signal(signal.SIGTERM, interrupted)
        Recovery(args.run).run_recovery()


if __name__ == "__main__":
    main()
