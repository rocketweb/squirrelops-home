"""One-shot, operator-authorized Mac mini install/observe/stop session.

No general command interface and no fault injection. No arguments prints a plan.
The bootstrap copies this and the pinned package into root-private storage.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time

VIPS = {"192.168.1.240", "192.168.1.241"}
SENSOR = Path("/Library/SquirrelOps/sensor")
APP = Path("/Applications/SquirrelOps Home.app")
HELPER = Path("/Library/PrivilegedHelperTools/com.squirrelops.helper")
LEDGER = Path("/var/db/com.squirrelops.helper/owned-aliases")
FAILED_BASELINE = Path("/Library/SquirrelOps/acceptance-backups/mini-20260928.4e0684b8")
PACKAGE_SHA = "3e8c0fc78befad3365fdbff5583d9f85c6b6fe01816b5863edbebeceaa4b8f5f"
CONFIG_SHA = "6e210567e3baae3950d91153b44090876ae6978b2a67677b1690aaf5c8f02330"
EXECUTABLES = {
    APP / "Contents/MacOS/SquirrelOpsHome": "ebab6cb0da72201487eafc8452efc81d1540c1f3a7c0b41cdc7563dc1cc598a4",
    HELPER: "56e6986ddedb26f31fb0fc24866b12ddab1d55dad8ff8cb4f55f41ce8150c66a",
    APP / "Contents/Library/Helpers/com.squirrelops.deception-guest": "52f92743dd0b6b4b3bee789ead02cc6275b6445485a6ade4654e52e277612ebe",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_directory(path: Path) -> None:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and not info.st_mode & 0o022, f"Unsafe root directory: {path}")


def safe_file(path: Path) -> None:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and not info.st_mode & 0o022 and info.st_size <= 1024 * 1024,
            f"Unsafe preflight evidence: {path}")


def validate_backup_container(path: Path) -> None:
    """Recognize retained preflight evidence, never an existing installation."""
    if not path.exists() and not path.is_symlink():
        return
    safe_directory(path)
    require({p.name for p in path.iterdir()} == {"acceptance-backups"},
            f"Unexpected existing product content: {path}")
    base = path / "acceptance-backups"
    safe_directory(base)
    backups = list(base.iterdir())
    require(len(backups) <= 32, "Too many prior preflight attempts; review retained evidence")
    for backup in backups:
        require(re.fullmatch(r"mini-20260928\.[A-Za-z0-9_-]+", backup.name) is not None,
                "Unrecognized prior acceptance backup")
        safe_directory(backup)
        files = list(backup.iterdir())
        require(len(files) <= 1024, "Oversized prior preflight backup")
        for item in files:
            safe_file(item)
        marker = backup / "preflight-only.json"
        if marker.exists():
            require(json.loads(marker.read_text()) == {"schema": 1, "phase": "preflight_only"},
                    "Prior attempt reached installation; manual review required")
        else:
            # One legacy attempt predates the explicit phase marker. Its exact
            # name, script digest and read-only command log are known evidence.
            require(backup.name == "mini-20260928.o9xofp7p", "Unmarked prior backup needs review")
            require({p.name for p in files} == {
                "original-product-state.txt", "mini_acceptance.py", "proposed-config.yaml",
                "pf.conf.observed-only", "command-001.json", "command-002.json", "command-003.json",
            }, "Legacy preflight evidence changed")
            require(digest(backup / "mini_acceptance.py") ==
                    "2852d7f814b66e1c75224d105e41ca11dcf860e5bbac070b10f68172c201f3cd",
                    "Unknown legacy setup script")
            for index, args in enumerate((
                ["/sbin/pfctl", "-s", "info"], ["/sbin/pfctl", "-s", "References"],
                ["/sbin/pfctl", "-a", "*", "-sr"],
            ), 1):
                require(json.loads((backup / f"command-{index:03d}.json").read_text()).get("command") == args,
                        "Legacy attempt exceeded read-only preflight")


def anchor_path(name: str, parent: str) -> str:
    """Accept a direct child name or the full direct-child path printed by PF."""
    if parent and not name.startswith(parent + "/"):
        name = parent + "/" + name
    components = name.split("/")
    require(len(components) <= 16 and len(name) <= 512
            and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in (".", "..") for part in components)
            and (name == "com.apple" or name.startswith("com.apple/")),
            "Unrecognized PF anchor; policy needs review")
    require(name.rpartition("/")[0] == parent, "PF anchor listing is not a direct child")
    return name


def validate_empty_policy(text: str, anchor: str = "") -> None:
    """Only anchor hooks pass; every concrete child is inspected separately."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not anchor and line == 'scrub-anchor "com.apple/*" all fragment reassemble':
            continue
        match = re.fullmatch(r'(?:nat-|rdr-)?anchor "([^"\n]+)" all', line)
        if match:
            target = match[1].removesuffix("/*")
            anchor_path(target, anchor)
            continue
        raise RuntimeError(f"Pre-existing PF policy at {anchor or '<main>'} needs review; no PF enable authorized")


def parse_ledger(text: str) -> list[str]:
    require(len(text.encode()) <= 65536, "Oversized ownership ledger")
    ips = []
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split("|")
        require(len(fields) == 2 and fields[0] in VIPS and fields[1] == "en0",
                "Ownership ledger exceeds approved scope")
        require(fields[0] not in ips, "Duplicate ownership entry")
        ips.append(fields[0])
    return sorted(ips)


def parse_pf_token(text: str) -> str:
    tokens = re.findall(r"(?m)^Token\s*:\s*([0-9]+)\s*$", text)
    require(len(tokens) == 1, "Could not identify the test-owned PF reference")
    return tokens[0]


def listener_endpoints(text: str) -> set[tuple[str, str]]:
    uid = ""
    result = set()
    for line in text.splitlines():
        if line.startswith("u"):
            uid = line[1:]
        elif line.startswith("n"):
            result.add((uid, line[1:]))
    return result


def health_payload_ok(text: str) -> bool:
    try:
        value = json.loads(text)
        return isinstance(value, dict) and value.get("status") == "ok"
    except ValueError:
        return False


def prepare_sensor_config(directory: Path, source: Path) -> None:
    directory.mkdir(mode=0o755)
    shutil.copyfile(source, directory / "config.yaml")
    (directory / "config.yaml").chmod(0o600)
    # mkdir's requested mode is masked by the session's private umask. The
    # installed Python must be traversable by the non-root service account.
    directory.chmod(0o755)


class Session:
    def __init__(self, task_dir: Path, *, resume_failed_install: bool = False):
        self.task_dir = task_dir
        self.resume_failed_install = resume_failed_install
        self.backup: Path | None = None
        self.public: Path | None = None
        self.token: str | None = None
        self.install_started = False
        self.install_in_progress = False
        self.sensor_uid: int | None = None
        self.baseline_listeners: set[tuple[str, str]] = set()
        self.counter = 0
        self.captures: list[tuple[subprocess.Popen, object, str]] = []
        self.pf_baseline: dict | None = None

    def verify_partial_install(self) -> None:
        """Only the observed, never-started mini installation can be resumed."""
        for path in (SENSOR.parent, SENSOR, FAILED_BASELINE.parent, FAILED_BASELINE):
            safe_directory(path)
        for name in ("preflight-only.json", "mini_acceptance.py", "proposed-config.yaml"):
            safe_file(FAILED_BASELINE / name)
        require(json.loads((FAILED_BASELINE / "preflight-only.json").read_text()) ==
                {"schema": 1, "phase": "install_started"}, "Wrong failed-attempt phase")
        require(digest(FAILED_BASELINE / "mini_acceptance.py") ==
                "365ec06fb20f018ac1acd2ca3b73544a5813fb633a06c652a580a56b254090b0",
                "Wrong failed-attempt script")
        require(digest(FAILED_BASELINE / "proposed-config.yaml") == CONFIG_SHA,
                "Wrong failed-attempt configuration")
        metadata = SENSOR.lstat()
        require(metadata.st_gid == 0 and stat.S_IMODE(metadata.st_mode) == 0o700,
                "Sensor directory no longer matches the observed failure")
        user = pwd.getpwnam("_squirrelops")
        group = grp.getgrnam("_squirrelops")
        require((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell) ==
                (309, 309, "/var/empty", "/usr/bin/false")
                and group.gr_gid == 309 and not group.gr_mem, "Partial-install identity changed")
        require(self.command(["/usr/bin/pgrep", "-u", "309"], check=False).returncode == 1,
                "Service-account processes remain; recovery stopped")
        require(self.command(["/usr/bin/pgrep", "-x", "SquirrelOpsHome"], check=False).returncode == 1,
                "Close the product app before recovery")
        for path, expected in EXECUTABLES.items():
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and metadata.st_gid == 0 and not metadata.st_mode & 0o022,
                    f"Unsafe partial-install executable: {path.name}")
            require(digest(path) == expected, f"Partial-install executable changed: {path.name}")
        config = SENSOR / "config.yaml"
        metadata = config.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (309, 309, 0o600)
                and digest(config) == CONFIG_SHA, "Partial-install configuration changed")
        for name in ("data", "logs"):
            path = SENSOR / name
            metadata = path.lstat()
            require(stat.S_ISDIR(metadata.st_mode)
                    and (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == (309, 309, 0o700)
                    and not list(path.iterdir()), "Unexpected existing sensor data; preserve and review")
        require(not self.owned(), "Unexpected test networking ownership")

    def command(self, args: list[str], *, check: bool = True, timeout: int = 30):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
        if self.backup is not None:
            self.counter += 1
            # Private logs can include PF reference tokens. Never publish these.
            (self.backup / f"command-{self.counter:03d}.json").write_text(json.dumps({
                "command": args, "exit": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr,
            }, indent=2))
        if check:
            require(result.returncode == 0, f"Command failed: {args[0]} (private log retained)")
        return result

    def publish(self, phase: str, **fields) -> None:
        require(self.public is not None, "No results directory")
        data = {"phase": phase, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}
        temporary = self.public / ".status.tmp"
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        temporary.chmod(0o644)
        temporary.replace(self.public / "status.json")

    def owned(self) -> list[str]:
        if not LEDGER.exists() and not LEDGER.is_symlink():
            return []
        safe_directory(LEDGER.parent)
        metadata = LEDGER.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022, "Unsafe ownership ledger")
        return parse_ledger(LEDGER.read_text())

    def assert_no_test_network(self) -> None:
        interfaces = self.command(["/sbin/ifconfig", "-a"]).stdout
        arp = self.command(["/usr/sbin/arp", "-an"]).stdout
        for ip in VIPS:
            require(not re.search(r"\binet " + re.escape(ip) + r"\s", interfaces),
                    f"Test alias still exists: {ip}")
            for line in arp.splitlines():
                require(not (f"({ip})" in line and "published" in line.lower()),
                        f"Test proxy ARP still exists: {ip}")

    def inspect_empty_pf(self) -> dict:
        # macOS 27 printed anchor "*" and DIOCGETRULES for -a '*',
        # without propagating that nested error in the exit status. Enumerate
        # concrete anchors instead. Stderr is part of the success contract.
        warnings = {"No ALTQ support in kernel", "ALTQ related functions disabled"}

        def read(anchor, flags):
            args = ["/sbin/pfctl"] + (["-a", anchor] if anchor else []) + flags
            result = self.command(args)
            require(result.returncode == 0 and all(
                not line.strip() or line.strip() in warnings for line in result.stderr.splitlines()),
                f"PF inventory incomplete at {anchor or '<main>'} ({' '.join(flags)}); private log retained")
            require(len(result.stdout) <= 1024 * 1024, "Oversized PF inventory")
            return result.stdout

        def children(anchor):
            names = [anchor_path(line.strip(), anchor)
                     for line in read(anchor, ["-s", "Anchors"]).splitlines() if line.strip()]
            require(len(names) == len(set(names)), "Duplicate PF anchor in inventory")
            return sorted(names)

        inventory = {}
        pending = [""]
        while pending:
            anchor = pending.pop(0)
            require(anchor not in inventory and len(inventory) < 128, "PF inventory exceeds review bounds")
            child_names = children(anchor)
            policy = {}
            for flag in ("-sr", "-sn"):
                policy[flag] = read(anchor, [flag])
                validate_empty_policy(policy[flag], anchor)
            inventory[anchor] = {"children": child_names, **policy}
            pending.extend(child_names)
        for anchor, item in inventory.items():
            require(children(anchor) == item["children"], "PF anchor tree changed during inventory")
        return inventory

    def preflight(self) -> None:
        require(os.geteuid() == 0, "Run through the administrator-approved bootstrap")
        require(os.isatty(0), "An attended local Terminal session is required")
        require(self.task_dir.parent == Path("/private/var/root")
                and self.task_dir.name.startswith("squirrelops-mini-acceptance."), "Wrong staging path")
        safe_directory(self.task_dir)
        require(self.command(["/usr/bin/uname", "-m"]).stdout.strip() == "arm64", "Wrong architecture")
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == "26A428", "OS drift")
        require(self.command(["/usr/sbin/ipconfig", "getifaddr", "en0"]).stdout.strip() == "192.168.1.115", "Wrong Ethernet address")
        require(self.command(["/usr/sbin/ipconfig", "getifaddr", "en1"]).stdout.strip() == "192.168.1.254", "Wi-Fi drift")
        require("100.108.203.27" in self.command(["/sbin/ifconfig", "-a"]).stdout, "Wrong Tailscale host")
        route = self.command(["/sbin/route", "-n", "get", "-inet", "default"]).stdout
        require(re.search(r"interface:\s+en0\b", route) is not None
                and re.search(r"gateway:\s+192\.168\.1\.1\b", route) is not None, "Route drift")
        require(shutil.disk_usage("/Library").free > 5 * 1024**3, "Less than 5 GiB free")
        if self.resume_failed_install:
            self.verify_partial_install()
            absent_paths = (Path("/var/db/com.squirrelops.allow-local-test"),)
            absent_accounts = (("Users", "_squirrelops_installing"), ("Groups", "_squirrelops_installing"))
        else:
            validate_backup_container(Path("/Library/SquirrelOps"))
            absent_paths = (APP, HELPER, LEDGER.parent,
                     Path("/var/db/com.squirrelops.sensor"),
                     Path("/var/db/com.squirrelops.allow-local-test"),
                     Path("/Library/LaunchDaemons/com.squirrelops.sensor.plist"),
                     Path("/Library/LaunchDaemons/com.squirrelops.helper.plist"))
            absent_accounts = (("Users", "_squirrelops"), ("Groups", "_squirrelops"),
                               ("Users", "_squirrelops_installing"), ("Groups", "_squirrelops_installing"))
        for path in absent_paths:
            require(not path.exists() and not path.is_symlink(), f"Unexpected existing product path: {path}")
        for kind, name in absent_accounts:
            require(self.command(["/usr/bin/dscl", ".", "-read", f"/{kind}/{name}"], check=False).returncode != 0,
                    "Unexpected existing product account")
        for component in ("app", "sensor"):
            require(self.command(["/usr/sbin/pkgutil", "--pkg-info", f"com.squirrelops.home.{component}"], check=False).returncode != 0,
                    "Unexpected product receipt")
        for label in ("com.squirrelops.sensor", "com.squirrelops.helper"):
            require(self.command(["/bin/launchctl", "print", f"system/{label}"], check=False).returncode != 0,
                    "Unexpected existing product service")
        require(digest(self.task_dir / "candidate.pkg") == PACKAGE_SHA, "Package checksum mismatch")
        require(digest(self.task_dir / "mini-a5-config.yaml") == CONFIG_SHA, "Config checksum mismatch")
        self.assert_no_test_network()
        # Only prior preflight evidence may exist. Preserve it without changes.
        safe_directory(Path("/Library"))
        Path("/Library/SquirrelOps").mkdir(mode=0o755, exist_ok=True)
        base = Path("/Library/SquirrelOps/acceptance-backups")
        base.mkdir(mode=0o700, exist_ok=True)
        self.backup = Path(tempfile.mkdtemp(prefix="mini-20260928.", dir=base))
        (self.backup / "preflight-only.json").write_text(json.dumps({"schema": 1, "phase": "preflight_only"}))
        (self.backup / "original-product-state.txt").write_text(
            "Exact partial installation retained; sensor directory root:wheel 0700; service UID/GID 309; data/logs empty.\n"
            if self.resume_failed_install else
            "Installed product paths, receipts, accounts and services absent. Prior preflight backups retained.\n")
        if self.resume_failed_install:
            shutil.copy2(SENSOR / "config.yaml", self.backup / "config-before.yaml")
            (self.backup / "config-before.yaml").chmod(0o600)
            (self.backup / "recovery-inverse.txt").write_text(
                "Only after product services are stopped and test aliases absent: restore /Library/SquirrelOps/sensor to root:wheel mode 0700.\n"
                "Retain the account, installation, configuration, data, logs and all backups. Never globally reset PF.\n")
        shutil.copy2(self.task_dir / "mini_acceptance.py", self.backup / "mini_acceptance.py")
        shutil.copy2(self.task_dir / "mini-a5-config.yaml", self.backup / "proposed-config.yaml")
        shutil.copy2("/etc/pf.conf", self.backup / "pf.conf.observed-only")
        self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-results.", dir="/private/var/tmp"))
        self.public.chmod(0o755)
        print(f"Private baseline: {self.backup}", flush=True)
        print(f"Sanitized results: {self.public}", flush=True)
        self.publish("preflight")
        pf_status = self.command(["/sbin/pfctl", "-s", "info"]).stdout
        require(re.search(r"^Status:\s+Disabled\b", pf_status, re.M) is not None, "PF status changed")
        require(re.search(r"current entries\s+0\b", pf_status) is not None, "Unexpected PF states")
        self.command(["/sbin/pfctl", "-s", "References"])
        self.pf_baseline = self.inspect_empty_pf()
        self.command(["/sbin/ifconfig", "-a"])
        self.command(["/usr/sbin/arp", "-an"])
        self.command(["/sbin/route", "-n", "get", "-inet", "default"])
        listeners = self.command(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout
        self.baseline_listeners = listener_endpoints(listeners)
        require(not any(endpoint.endswith(":8443") for _, endpoint in self.baseline_listeners), "API port occupied")
        for endpoint in ("*:22", "*:445", "*:5900", "192.168.1.115:11434", "127.0.0.1:49199"):
            require(any(address == endpoint for _, address in self.baseline_listeners), f"Baseline service missing: {endpoint}")
        self.publish("preflight_passed", private_baseline=str(self.backup))

    def install(self) -> None:
        require(self.backup is not None, "No baseline")
        require(self.pf_baseline is not None and self.inspect_empty_pf() == self.pf_baseline,
                "PF policy changed after preflight; no PF enable authorized")
        (self.backup / "preflight-only.json").write_text(json.dumps({"schema": 1, "phase": "install_started"}))
        Path("/Library/SquirrelOps").chmod(0o755)
        if self.resume_failed_install:
            self.verify_partial_install()
            SENSOR.chmod(0o755)  # Exact single-directory correction; never recursive.
            runtime = SENSOR / "python/bin/python3.12"
            safe_directory(runtime.parent)
            require(digest(runtime) == digest(self.task_dir / "expanded/sensor.pkg/Payload/Library/SquirrelOps/sensor/python/bin/python3.12"),
                    "Installed Python differs from the pinned package")
            probe = self.command(["/usr/bin/sudo", "-n", "-u", "_squirrelops", "/usr/bin/env", "-i",
                                  "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", str(runtime),
                                  "-I", "-S", "-c", "import os; print(os.geteuid())"])
            require(probe.stdout.strip() == "309", "Service-account Python execution failed")
        else:
            prepare_sensor_config(SENSOR, self.task_dir / "mini-a5-config.yaml")
        enable = self.command(["/sbin/pfctl", "-E"])
        self.token = parse_pf_token(enable.stdout + enable.stderr)
        (self.backup / "pf-reference-token").write_text(self.token + "\n")
        require(re.search(r"^Status:\s+Enabled\b", self.command(["/sbin/pfctl", "-s", "info"]).stdout, re.M) is not None,
                "PF enable not verified")
        self.command(["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "600", "/dev/null", "/var/db/com.squirrelops.allow-local-test"])
        self.install_started = True
        self.install_in_progress = True
        self.publish("installing")
        print("Installing the checksum-pinned 2.1 package. Keep this Terminal open.", flush=True)
        installed = self.command(["/usr/sbin/installer", "-pkg", str(self.task_dir / "candidate.pkg"), "-target", "/"], timeout=1800, check=False)
        self.install_in_progress = False
        require(installed.returncode == 0, "Installer failed; private log retained")
        for path, expected in EXECUTABLES.items():
            require(digest(path) == expected, f"Installed executable mismatch: {path.name}")
        require(digest(SENSOR / "config.yaml") == CONFIG_SHA, "Installer changed the bounded configuration")
        self.sensor_uid = pwd.getpwnam("_squirrelops").pw_uid
        require(300 <= self.sensor_uid <= 499, "Unexpected service UID")
        deadline = time.monotonic() + 480
        healthy = 0
        while time.monotonic() < deadline:
            self.owned()
            result = self.command(["/usr/bin/curl", "--silent", "--insecure", "--max-time", "3", "--fail",
                                   "https://127.0.0.1:8443/system/health"], check=False)
            ok = result.returncode == 0 and health_payload_ok(result.stdout)
            healthy = healthy + 1 if ok else 0
            if healthy >= 2:
                break
            time.sleep(3)
        require(healthy >= 2, "Sensor health did not stabilize within eight minutes")
        self.command(["/sbin/pfctl", "-a", "com.apple/squirrelops", "-sr"])
        self.command(["/sbin/pfctl", "-a", "com.apple/squirrelops", "-sn"])
        current = listener_endpoints(self.command(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout)
        require(self.baseline_listeners <= current, "An existing listener changed during setup")
        self.snapshot("before")
        self.export_guest_login()

    def export_guest_login(self) -> None:
        """Operator-only synthetic guest login, never control-plane credentials."""
        require(self.public is not None, "No results directory")
        with closing(sqlite3.connect(f"file:{SENSOR}/data/squirrelops.db?mode=ro", uri=True)) as db:
            rows = db.execute("""SELECT d.bind_address, c.credential_value
                FROM planted_credentials c JOIN decoys d ON d.id=c.decoy_id
                WHERE c.planted_location='SSH buildbot login' AND d.decoy_type='deep'
                AND d.port=22 AND d.status='active' AND d.retired_at IS NULL""").fetchall()
            require(len(rows) == 1 and rows[0][0] in VIPS, "No single active guest SSH endpoint")
            ip, password = rows[0]
            require(isinstance(password, str) and re.fullmatch(r"Juniper![0-9]{6}", password) is not None,
                    "Unexpected synthetic guest credential format")
            require(db.execute("SELECT count(*) FROM decoys WHERE decoy_type='deep' AND bind_address=? AND port=445 AND status='active' AND retired_at IS NULL", (ip,)).fetchone()[0] == 1,
                    "Matching guest SMB endpoint is not active")
        require(pwd.getpwnam("matt").pw_uid == 501, "Operator UID changed")
        target = self.public / "synthetic-guest-login.json"
        target.write_text(json.dumps({"ip": ip, "username": "buildbot", "password": password}) + "\n")
        target.chmod(0o600)
        os.chown(target, 501, 20)

    def snapshot(self, label: str) -> None:
        require(self.public is not None, "No public result path")
        with closing(sqlite3.connect(f"file:{SENSOR}/data/squirrelops.db?mode=ro", uri=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            report = {
                "decoys": [dict(row) for row in db.execute("SELECT id,decoy_type,bind_address,port,status,connection_count,credential_trip_count FROM decoys ORDER BY id")],
                "connections": [dict(row) for row in db.execute("SELECT decoy_id,source_ip,port,protocol,count(*) AS count FROM decoy_connections GROUP BY decoy_id,source_ip,port,protocol")],
                "alerts": [dict(row) for row in db.execute("SELECT id,alert_type,severity,source_ip,decoy_id,created_at FROM home_alerts WHERE source_ip='192.168.1.7' ORDER BY id")],
                "virtual_ips": [dict(row) for row in db.execute("SELECT ip_address,interface,released_at FROM virtual_ips ORDER BY ip_address")],
            }
        require(all(row["ip_address"] in VIPS for row in report["virtual_ips"]), "Database VIP outside approved pool")
        report["owned_aliases"] = self.owned()
        report["pf_rules"] = self.command(["/sbin/pfctl", "-a", "com.apple/squirrelops", "-sr"]).stdout
        report["pf_nat"] = self.command(["/sbin/pfctl", "-a", "com.apple/squirrelops", "-sn"]).stdout
        target = self.public / f"{label}.json"
        temporary = self.public / f".{label}.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.chmod(0o644)
        temporary.replace(target)

    def rpc(self, method: str, params: dict) -> None:
        # Fixed call sites below, never a command supplied by a remote caller.
        require(digest(HELPER) == EXECUTABLES[HELPER], "Helper changed before cleanup")
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(30)
            stream.connect("/var/run/squirrelops-helper.sock")
            stream.sendall(json.dumps(request).encode() + b"\n")
            response = stream.makefile("rb").readline(65537)
        require(response.endswith(b"\n") and len(response) <= 65536, "Invalid cleanup RPC response")
        data = json.loads(response)
        require(data.get("id") == 1 and "error" not in data and data.get("result", {}).get("success") is True,
                f"Cleanup RPC failed: {method}")

    def observe(self) -> None:
        require(self.public is not None, "No result directory")
        require(self.backup is not None, "No private baseline")
        for interface in ("en0", "en1"):
            error_file = (self.backup / f"capture-{interface}.log").open("w")
            capture = subprocess.Popen([
                "/usr/sbin/tcpdump", "-i", interface, "-n", "-U", "-s", "96", "-w",
                str(self.backup / f"capture-{interface}.pcap"),
                "host 192.168.1.7 and (host 192.168.1.240 or host 192.168.1.241)",
            ], stdout=subprocess.DEVNULL, stderr=error_file)
            self.captures.append((capture, error_file, interface))
        time.sleep(1)
        require(all(process.poll() is None for process, _, _ in self.captures), "Packet capture startup failed")
        self.publish("ready_for_tests", observation_minutes=20, sensor_uid=self.sensor_uid)
        print("READY FOR TESTS. Tell Codex it is ready; leave this Terminal open.", flush=True)
        print("Press Return ONLY after Codex finishes the laptop tests. Auto-stop in 20 minutes.", flush=True)
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            ready, _, _ = select.select([0], [], [], 5)
            if ready:
                os.read(0, 4096)
                break
            self.snapshot("latest")
        self.snapshot("after")

    def stop(self) -> None:
        for capture, error_file, interface in self.captures:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                capture.wait(timeout=10)
            error_file.close()
            if self.backup is not None and self.public is not None:
                headers = self.command(["/usr/sbin/tcpdump", "-n", "-q", "-tttt", "-r",
                                        str(self.backup / f"capture-{interface}.pcap")], check=False)
                if headers.returncode == 0:
                    target = self.public / f"packet-summary-{interface}.txt"
                    target.write_text(headers.stdout)
                    target.chmod(0o644)
        self.captures.clear()
        require(not self.install_in_progress,
                "Installer completion is uncertain; retain protection and inspect PackageKit before cleanup")
        if not self.install_started:
            if self.token:
                self.assert_no_test_network()
                self.command(["/sbin/pfctl", "-X", self.token])
                self.token = None
            return
        self.publish("stopping")
        for path in (HELPER,):
            if path.exists():
                require(digest(path) == EXECUTABLES[path], "Unexpected installed helper; retaining isolation")
        self.owned()  # Never remove an unapproved endpoint.
        loaded = self.command(["/bin/launchctl", "print", "system/com.squirrelops.sensor"], check=False)
        if loaded.returncode == 0:
            self.command(["/bin/launchctl", "bootout", "system/com.squirrelops.sensor"], timeout=90)
        require(self.command(["/bin/launchctl", "print", "system/com.squirrelops.sensor"], check=False).returncode != 0,
                "Sensor service remains loaded")
        try:
            uid = pwd.getpwnam("_squirrelops").pw_uid
        except KeyError:
            uid = None
        if uid is not None:
            require(300 <= uid <= 499, "Unsafe cleanup UID")
            require(self.sensor_uid is None or uid == self.sensor_uid, "Service UID changed since setup")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if self.command(["/usr/bin/pgrep", "-u", str(uid)], check=False).returncode == 1:
                    break
                time.sleep(2)
            require(self.command(["/usr/bin/pgrep", "-u", str(uid)], check=False).returncode == 1,
                    "Sensor UID processes remain; retaining PF isolation")
        owned = self.owned()
        if owned:
            self.rpc("setupPortForwards", {"rules": [], "interface": "en0",
                     "protected_endpoints": [{"ip": ip, "direct_ports": []} for ip in owned]})
            for ip in owned:
                self.rpc("removeIPAlias", {"ip": ip, "interface": "en0"})
        self.assert_no_test_network()
        require(not self.owned(), "Ownership remains after cleanup")
        helper_loaded = self.command(["/bin/launchctl", "print", "system/com.squirrelops.helper"], check=False).returncode == 0
        if helper_loaded:
            self.rpc("clearPortForwards", {})
            self.command(["/bin/launchctl", "bootout", "system/com.squirrelops.helper"], timeout=60)
        # No root code or data is deleted. Retain the installation for the next stage.
        self.inspect_empty_pf()
        if self.token:
            self.command(["/sbin/pfctl", "-X", self.token])
            self.token = None
        self.command(["/sbin/pfctl", "-s", "info"])
        self.command(["/sbin/pfctl", "-s", "References"])
        after = listener_endpoints(self.command(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout)
        require(self.baseline_listeners <= after, "Baseline listener parity not restored")
        require(self.command(["/usr/sbin/ipconfig", "getifaddr", "en0"]).stdout.strip() == "192.168.1.115", "Ethernet changed")
        require(self.command(["/usr/sbin/ipconfig", "getifaddr", "en1"]).stdout.strip() == "192.168.1.254", "Wi-Fi changed")
        self.command(["/sbin/route", "-n", "get", "-inet", "default"])
        require(self.backup is not None, "No private backup path")
        database = SENSOR / "data/squirrelops.db"
        if database.exists():
            with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as source:
                with closing(sqlite3.connect(self.backup / "post-test.sqlite")) as destination:
                    source.backup(destination)
                    require(destination.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Backup integrity failed")
        self.publish("stopped", installation_retained=True, test_data_retained=True,
                     aliases_absent=True, original_listener_endpoints_present=True)
        print("Test services stopped; aliases withdrawn; only our PF reference released.", flush=True)
        print("Installation and private test data retained. Do not reopen the app yet.", flush=True)

    def run(self) -> None:
        os.umask(0o077)
        error = None
        try:
            self.preflight()
            self.install()
            self.observe()
        except BaseException as exc:
            error = type(exc).__name__ + ": " + str(exc)
            print(f"STOPPED: {error}", flush=True)
        finally:
            try:
                self.stop()
            except BaseException as exc:
                error = (error or "") + " Cleanup incomplete: " + str(exc)
                print("Cleanup incomplete. PF protection retained; do not reset networking.", flush=True)
            if error:
                if self.public is not None:
                    self.publish("needs_review", reason=error)
                raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--resume-failed-install", action="store_true")
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "resume_failed_install": args.resume_failed_install,
                          "host": "100.108.203.27", "vips": sorted(VIPS),
                          "package_sha256": PACKAGE_SHA, "fault_injection": False,
                          "observe_seconds": 1200, "cleanup": "stop only; preserve installation and data"}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    Session(args.run, resume_failed_install=args.resume_failed_install).run()


if __name__ == "__main__":
    main()
