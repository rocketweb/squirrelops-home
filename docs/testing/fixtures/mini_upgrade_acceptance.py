"""Bounded, attended upgrade of the already-installed mini. Plan-only by default."""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
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

spec = importlib.util.spec_from_file_location("mini_acceptance", Path(__file__).with_name("mini_acceptance.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require = base.require

PACKAGE_SHA = "541fc783c41fd2f9a6baba1fe8edae93078a0a24089b8e6d4ede77ba051b7fb1"
PYTHON_SHA = "d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147"
NEW_EXECUTABLES = {
    base.APP / "Contents/MacOS/SquirrelOpsHome": "6b4785162f19a01abb8efc3539ad1bd36101cc93442523b7a8912758336cf03f",
    base.HELPER: "e903f082d194b153782c6435c6dda1c6ae12d8566e51e6b83cc3bd922cebc67a",
    base.APP / "Contents/Library/Helpers/com.squirrelops.deception-guest": "41b74f04f6a25a4f5fc50aba4120356ea4231eb8c03c83e122e44dc902296819",
    base.SENSOR / "python/lib/python3.12/site-packages/squirrelops_home_sensor/__main__.py": "c0819d199b6f609c2a012070b8451c68fcf8771821cda5a8a459c4601dde0181",
}
LISTENERS = ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpun"]
RUNTIME = base.SENSOR / "python/bin/python3.12"
GUEST = str(base.APP / "Contents/Library/Helpers/com.squirrelops.deception-guest")
VM = "/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine"
JOBS = ("com.squirrelops.sensor", "com.squirrelops.helper")
WARNINGS = {"No ALTQ support in kernel", "ALTQ related functions disabled"}
PRODUCT_ANCHOR = "com.apple/squirrelops"


def runtime_pids(text: str) -> list[int]:
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 2)
        require(len(fields) == 3 and fields[0].lstrip("-").isdigit() and fields[1].isdigit(),
                "Malformed process inventory")
        uid, pid, command = fields
        if uid == "309":
            if command == "/usr/sbin/distnoted":
                continue
            require(command in (str(RUNTIME), GUEST, VM), "Unexpected service process; retain protection")
            result.append(int(pid))
        elif command in (str(RUNTIME), GUEST, str(base.APP / "Contents/MacOS/SquirrelOpsHome")):
            raise RuntimeError("Product running under unexpected identity; close app and review")
    return result


def loaded_result(result, label: str) -> bool:
    require(label in JOBS, "Unexpected launchd target")
    if result.returncode == 0:
        require(result.stdout.startswith("system/" + label + " = {"), "Launchd response is uncertain")
        return True
    require(f'Could not find service "{label}"' in result.stderr, "Launchd state is uncertain")
    return False


def empty_policy_matches(before: dict, after: dict) -> bool:
    # The helper can leave its now-empty anchor allocated. No unrelated new
    # anchor or changed rule is equivalent to the recorded baseline.
    def normalize(tree):
        return {name: {**value, "children": [child for child in value["children"]
                                             if child != PRODUCT_ANCHOR]}
                for name, value in tree.items() if name != PRODUCT_ANCHOR}
    product = after.get(PRODUCT_ANCHOR)
    if product and (product["-sr"].strip() or product["-sn"].strip() or product["children"]):
        return False
    return normalize(before) == normalize(after)


def tree_manifest(root: Path) -> dict:
    """Do not follow links or read sockets. Bound enumeration and hash regular files."""
    items = {}
    pending = [(root, ".")]
    while pending:
        path, key = pending.pop()
        require(len(items) < 150000, "Backup tree exceeds review bounds")
        info = path.lstat()
        entry = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
        if stat.S_ISLNK(info.st_mode):
            entry.update(kind="link", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            entry.update(kind="directory")
            pending.extend((child, str(child.relative_to(root))) for child in path.iterdir())
        elif stat.S_ISREG(info.st_mode):
            entry.update(kind="file", size=info.st_size, sha256=base.digest(path))
        elif stat.S_ISSOCK(info.st_mode):
            # Stopped runtime sockets are not durable data and cannot be copied.
            entry.update(kind="socket", omitted=True)
        else:
            raise RuntimeError("Unexpected special file in backup scope")
        items[key] = entry
    return items


def durable_manifest(items: dict) -> dict:
    return {key: value for key, value in items.items() if value["kind"] != "socket"}


def copy_durable(source: Path, target: Path, manifest: dict, command) -> None:
    """ditto preserves normal trees; split only ancestors of stale Unix sockets."""
    if not any(value["kind"] == "socket" for value in manifest.values()):
        command(["/usr/bin/ditto", str(source), str(target)], timeout=600)
        return
    require(manifest["."]["kind"] == "directory", "Socket cannot be a backup root")
    target.mkdir(mode=0o700)
    for child in source.iterdir():
        key = child.name
        if manifest[key]["kind"] == "socket":
            continue
        subset = {".": manifest[key]}
        subset.update({name[len(key) + 1:]: value for name, value in manifest.items()
                       if name.startswith(key + "/")})
        copy_durable(child, target / key, subset, command)
    shutil.copystat(source, target)
    os.chown(target, manifest["."]["uid"], manifest["."]["gid"])


def verify_guarded_snapshot(snapshot: dict) -> list[dict]:
    """Require the exact current TCP tag/UID guard grammar before client traffic."""
    rules = snapshot["pf_rules"].splitlines()
    allowed = set()
    mappings = []
    for line in snapshot["pf_nat"].splitlines():
        match = re.fullmatch(
            r"rdr on en0 inet proto tcp from any to (192\.168\.1\.(?:240|241)) port = ([0-9]+) "
            r"tag (squirrelops_[0-9_]+) -> (192\.168\.1\.(?:240|241)) port ([0-9]+)", line)
        require(match is not None, "Unexpected PF translation grammar")
        ip, advertised, tag, backend_ip, backend = match.groups()
        require(ip == backend_ip and ip in snapshot["owned_aliases"] and 1024 <= int(backend) <= 65535
                and 1 <= int(advertised) <= 65535
                and tag == f"squirrelops_{ip.replace('.', '_')}_{advertised}_{backend}",
                "Invalid redirect identity")
        guard = (f"pass in quick on en0 inet proto tcp from any to {ip} port = {backend} "
                 f"user = 309 flags any keep state tagged {tag}")
        require(guard in rules, "Missing exact UID/tag guard")
        allowed.add(guard)
        mappings.append({"ip": ip, "port": int(advertised), "backend": int(backend)})
    for ip in snapshot["owned_aliases"]:
        deny = f"block drop in quick inet from any to {ip}"
        require(deny in rules, "Missing VIP default-deny rule")
        allowed.update((deny, f"pass in quick on en0 inet proto icmp from any to {ip} icmp-type echoreq keep state"))
    require(set(rules) <= allowed and len({(m['ip'], m['port']) for m in mappings}) == len(mappings),
            "Unexpected or duplicate PF publication")
    return mappings


class Upgrade(base.Session):
    package_sha = PACKAGE_SHA
    old_executables = base.EXECUTABLES
    new_executables = NEW_EXECUTABLES
    receipt_time = 1790689617
    staging_prefix = "squirrelops-mini-upgrade"
    input_names = ("mini_upgrade_acceptance.py", "mini_acceptance.py", "approved-scope.md")

    def __init__(self, task_dir: Path):
        super().__init__(task_dir)
        self.sensor_uid = 309
        self.backup_verified = False
        self.claim: Path | None = None

    def service_loaded(self, label: str) -> bool:
        return loaded_result(self.command(["/bin/launchctl", "print", "system/" + label], check=False), label)

    def stop_job(self, label: str) -> None:
        if self.service_loaded(label):
            self.command(["/bin/launchctl", "bootout", "system/" + label], check=False, timeout=90)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if not self.service_loaded(label):
                return
            time.sleep(1)
        raise RuntimeError("Service remains loaded; retaining protection")

    def processes(self) -> list[int]:
        return runtime_pids(self.command(["/bin/ps", "-axo", "uid=,pid=,comm="]).stdout)

    def pf(self, flags: list[str]) -> str:
        result = self.command(["/sbin/pfctl", *flags])
        require(all(not line.strip() or line.strip() in WARNINGS for line in result.stderr.splitlines()),
                "PF inventory returned an error; private log retained")
        return result.stdout

    def validate_existing(self) -> None:
        for path in (base.SENSOR.parent, base.SENSOR, base.APP, base.HELPER.parent):
            base.safe_directory(path)
        user = base.pwd.getpwnam("_squirrelops")
        group = base.grp.getgrnam("_squirrelops")
        require((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell) ==
                (309, 309, "/var/empty", "/usr/bin/false") and group.gr_gid == 309 and not group.gr_mem,
                "Service account drift")
        require(base.pwd.getpwnam("matt").pw_uid == 501, "Operator account drift")
        for path, expected in {**self.old_executables, RUNTIME: PYTHON_SHA}.items():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                    and not info.st_mode & 0o022 and base.digest(path) == expected,
                    f"Old installed payload drift: {path.name}")
        config = base.SENSOR / "config.yaml"
        info = config.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (309, 309, 0o600)
                and base.digest(config) == base.CONFIG_SHA, "Existing bounded configuration drift")
        for name in ("data", "logs"):
            info = (base.SENSOR / name).lstat()
            require(stat.S_ISDIR(info.st_mode)
                    and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (309, 309, 0o700),
                    "Mutable data directory identity drift")
        for label in JOBS:
            require(not self.service_loaded(label), "Product service already running")
        require(not self.processes(), "Product runtime already running")
        require(not self.owned(), "Unexpected alias ownership")
        self.assert_no_test_network()
        for component in ("app", "sensor"):
            info = self.command(["/usr/sbin/pkgutil", "--pkg-info", "com.squirrelops.home." + component]).stdout
            require("version: 2.1.0\n" in info and f"install-time: {self.receipt_time}\n" in info,
                    "Package receipt drift")
        for name in ("Users", "Groups"):
            result = self.command(["/usr/bin/dscl", ".", "-read", "/" + name + "/_squirrelops_installing"], check=False)
            require(result.returncode != 0 and "eDSRecordNotFound" in result.stdout + result.stderr,
                    "Temporary installer identity state is uncertain")
        marker = Path("/var/db/com.squirrelops.allow-local-test")
        require(not marker.exists() and not marker.is_symlink(), "Unexpected local-test opt-in")

    def host_baseline(self) -> None:
        for interface, address in (("en0", "192.168.1.115"), ("en1", "192.168.1.254")):
            require(self.command(["/usr/sbin/ipconfig", "getifaddr", interface]).stdout.strip() == address,
                    "Mini interface address drift")
        current = base.listener_endpoints(self.command(LISTENERS).stdout)
        require(self.baseline_listeners <= current, "Original endpoint/UID parity changed")
        route = self.command(["/sbin/route", "-n", "get", "-inet", "default"]).stdout
        for value in (r"interface:\s+en0\b", r"gateway:\s+192\.168\.1\.1\b"):
            require(re.search(value, route), "Default route changed")

    def check_conflicts(self) -> None:
        # Fixed six ARP requests, no broad scan; this supplement is not a DHCP reservation.
        from scapy.all import ARP, Ether, srp
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=sorted(base.VIPS)),
                          iface="en0", timeout=2, retry=2, verbose=False)
        require(not answered, "A proposed virtual IP answered ARP; no startup authorized")

    def backup_existing(self) -> None:
        require(self.backup is not None, "Missing private backup")
        paths = [base.APP, base.SENSOR, base.HELPER,
                 *(Path("/Library/LaunchDaemons") / (label + ".plist") for label in JOBS),
                 Path("/var/db/com.squirrelops.helper"), Path("/var/db/com.squirrelops.sensor"),
                 Path("/Library/SquirrelOps/backups")]
        paths += [Path("/var/db/receipts") / ("com.squirrelops.home." + component + suffix)
                  for component in ("app", "sensor") for suffix in (".plist", ".bom")]
        size = 0
        for path in paths:
            if path.exists():
                result = self.command(["/usr/bin/du", "-sk", str(path)], timeout=120)
                size += int(result.stdout.split()[0]) * 1024
        require(size < 20 * 1024**3 and shutil.disk_usage("/Library").free > size * 2 + 5 * 1024**3,
                "Insufficient bounded backup space")
        manifest = {}
        for index, path in enumerate(paths):
            if not path.exists() and not path.is_symlink():
                manifest[str(path)] = {"absent": True}
                continue
            require(not path.is_symlink(), "Unexpected linked backup root")
            before = tree_manifest(path)
            target = self.backup / f"payload-{index:02d}"
            copy_durable(path, target, before, self.command)
            require(durable_manifest(before) == durable_manifest(tree_manifest(target))
                    and before == tree_manifest(path), "Backup copy or source stability check failed")
            manifest[str(path)] = {"copy": str(target), "entries": before}
        (self.backup / "restore-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        database = base.SENSOR / "data/squirrelops.db"
        require(database.is_file() and not database.is_symlink(), "Missing regular sensor database")
        with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(self.backup / "pre-upgrade.sqlite")) as target:
                source.backup(target)
                require(target.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SQLite backup integrity failed")
        (self.backup / "inverse.txt").write_text(
            "Default inverse: stop product services, verify guest exit, withdraw only ledger-owned VIPs, "
            "clear only product rules, stop helper, release only owned PF reference.\n"
            "Keep installation/data/backups. No automatic downgrade. Reviewed, separately approved "
            "restoration can use restore-manifest.json and pre-upgrade.sqlite while stopped.\n")
        self.backup_verified = True

    def preflight(self) -> None:
        require(os.geteuid() == 0 and os.isatty(0), "Use attended mini Terminal bootstrap")
        require(self.task_dir.parent == Path("/private/var/root")
                and re.fullmatch(re.escape(self.staging_prefix) + r"\.[A-Za-z0-9_-]+", self.task_dir.name), "Wrong private staging path")
        base.safe_directory(self.task_dir)
        require(base.digest(self.task_dir / "candidate.pkg") == self.package_sha, "Package checksum mismatch")
        require(self.command(["/usr/bin/uname", "-m"]).stdout.strip() == "arm64", "Wrong architecture")
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == "26A428", "OS drift")
        require("100.108.203.27" in self.command(["/sbin/ifconfig", "-a"]).stdout, "Wrong Tailscale host")
        container = Path("/Library/SquirrelOps/acceptance-backups")
        for path in (container.parent, container):
            base.safe_directory(path)
        self.backup = Path(tempfile.mkdtemp(prefix="mini-upgrade-20260929.", dir=container))
        self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-upgrade-results.", dir="/private/var/tmp"))
        self.public.chmod(0o755)
        print(f"Private upgrade backup: {self.backup}", flush=True)
        print(f"Sanitized results: {self.public}", flush=True)
        for name in self.input_names:
            shutil.copy2(self.task_dir / name, self.backup / name)
        self.publish("preflight")
        self.validate_existing()
        for record in ("Users/_squirrelops", "Groups/_squirrelops"):
            self.command(["/usr/bin/dscl", ".", "-read", "/" + record])
        self.baseline_listeners = base.listener_endpoints(self.command(LISTENERS).stdout)
        require(not any(endpoint.endswith(":8443") for _, endpoint in self.baseline_listeners), "API port occupied")
        for endpoint in ("*:22", "*:445", "*:5900", "192.168.1.115:11434", "127.0.0.1:49199"):
            require(any(address == endpoint for _, address in self.baseline_listeners), "Original listener missing")
        self.host_baseline()
        info = self.pf(["-s", "info"])
        require(re.search(r"^Status:\s+Disabled\b", info, re.M)
                and re.search(r"current entries\s+0\b", info), "PF status/states drift")
        self.pf(["-s", "References"])
        self.pf_baseline = self.inspect_empty_pf()
        self.check_conflicts()
        self.backup_existing()
        self.validate_existing()
        self.snapshot("pre-upgrade")
        self.publish("preflight_passed", backup_verified=True, package_sha256=self.package_sha)

    def prepare_upgrade(self) -> None:
        """Optional pinned continuation step, after backup and single-use claim."""

    def install(self) -> None:
        require(self.backup_verified and self.backup is not None, "Verified backup required before mutation")
        require(self.pf_baseline is not None and self.inspect_empty_pf() == self.pf_baseline,
                "PF policy changed; no enable authorized")
        self.validate_existing()
        self.check_conflicts()
        self.claim = self.backup.parent / f"upgrade-{self.package_sha[:12]}-attempt.json"
        with self.claim.open("x") as stream:
            json.dump({"backup": str(self.backup), "results": str(self.public), "package_sha256": self.package_sha}, stream)
        self.prepare_upgrade()
        enabled = self.command(["/sbin/pfctl", "-E"])
        self.token = base.parse_pf_token(enabled.stdout + enabled.stderr)
        (self.backup / "pf-reference-token").write_text(self.token + "\n")
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF enable not verified")
        self.command(["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "600", "/dev/null",
                      "/var/db/com.squirrelops.allow-local-test"])
        self.install_started = True
        self.install_in_progress = True
        self.publish("installing", package_sha256=self.package_sha)
        print("Upgrading the checksum-pinned package. Keep this Terminal open.", flush=True)
        result = self.command(["/usr/sbin/installer", "-pkg", str(self.task_dir / "candidate.pkg"), "-target", "/"],
                              timeout=1800, check=False)
        self.install_in_progress = False
        require(result.returncode == 0, "Installer failed; private evidence retained")
        for path, expected in {**self.new_executables, RUNTIME: PYTHON_SHA}.items():
            require(base.digest(path) == expected, "Installed payload verification failed")
        require(base.digest(base.SENSOR / "config.yaml") == base.CONFIG_SHA, "Bounded configuration changed")
        require(base.pwd.getpwnam("_squirrelops").pw_uid == 309, "Service identity changed")
        self.command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(base.APP)])
        self.wait_until_ready()

    def wait_until_ready(self) -> None:
        deadline = time.monotonic() + 480
        healthy = 0
        while time.monotonic() < deadline:
            self.owned()
            response = self.command(["/usr/bin/curl", "--silent", "--insecure", "--max-time", "3", "--fail",
                                     "https://127.0.0.1:8443/system/health"], check=False)
            healthy = healthy + 1 if response.returncode == 0 and base.health_payload_ok(response.stdout) else 0
            if healthy >= 2:
                break
            time.sleep(3)
        require(healthy >= 2, "Sensor health did not stabilize")
        self.host_baseline()
        deadline = time.monotonic() + 180
        while True:
            self.snapshot("before")
            snapshot = json.loads((self.public / "before.json").read_text())
            active = [(row["bind_address"], row["port"]) for row in snapshot["decoys"]
                      if row["decoy_type"] == "deep" and row["status"] == "active"]
            if any((ip, 22) in active and (ip, 445) in active for ip in base.VIPS):
                break
            require(time.monotonic() < deadline, "Guest did not become ready within three minutes")
            time.sleep(3)
        mappings = verify_guarded_snapshot(snapshot)
        self.export_guest_login()
        login = json.loads((self.public / "synthetic-guest-login.json").read_text())
        require(all(any(m["ip"] == login["ip"] and m["port"] == port for m in mappings)
                    for port in (22, 445, 11434, 1234, 8765)), "Guest publication incomplete")
        target = self.public / "endpoints.json"
        target.write_text(json.dumps({"guest_ip": login["ip"], "mappings": mappings}, indent=2) + "\n")
        target.chmod(0o644)

    def rpc(self, method: str, params: dict) -> None:
        require(method in ("setupPortForwards", "removeIPAlias", "clearPortForwards"), "Unexpected cleanup method")
        require(base.digest(base.HELPER) in (self.old_executables[base.HELPER], self.new_executables[base.HELPER]),
                "Unknown helper; retain protection")
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(30)
            stream.connect("/var/run/squirrelops-helper.sock")
            stream.sendall(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
            response = stream.makefile("rb").readline(65537)
        require(response.endswith(b"\n") and len(response) <= 65536, "Invalid cleanup RPC response")
        data = json.loads(response)
        require(data.get("id") == 1 and "error" not in data and data.get("result", {}).get("success") is True,
                "Cleanup RPC failed; retain protection")

    def observe(self) -> None:
        require(self.backup is not None, "No private evidence directory")
        for interface in ("en0", "en1"):
            output = (self.backup / f"packet-metadata-{interface}.txt").open("w")
            process = subprocess.Popen([
                "/usr/sbin/tcpdump", "-i", interface, "-n", "-q", "-tttt", "-l", "-s", "96",
                "host 192.168.1.7 and (host 192.168.1.240 or host 192.168.1.241)",
            ], stdout=output, stderr=subprocess.DEVNULL)
            self.captures.append((process, output, interface))
        time.sleep(1)
        require(all(p.poll() is None for p, _, _ in self.captures), "Metadata capture startup failed")
        deadline = time.monotonic() + 1200
        self.publish("ready_for_tests", package_sha256=self.package_sha, observation_minutes=20, sensor_uid=309)
        print("READY FOR TESTS. Tell Codex it is ready; leave this Terminal open.", flush=True)
        print("Leave any filter prompt unanswered. Return stops early; auto-stop in 20 minutes.", flush=True)
        while time.monotonic() < deadline:
            ready, _, _ = select.select([0], [], [], 5)
            if ready:
                os.read(0, 4096)
                break
            self.snapshot("latest")
            self.publish("ready_for_tests", package_sha256=self.package_sha,
                         remaining_seconds=max(0, int(deadline - time.monotonic())), sensor_uid=309)
        self.snapshot("after")

    def release_reference(self) -> None:
        if self.token is None:
            return
        token = self.token
        pattern = r"(?<![0-9])" + re.escape(token) + r"(?![0-9])"
        require(re.search(pattern, self.pf(["-s", "References"])), "Own PF reference missing; review required")
        # Do not retry a release with an uncertain result.
        self.token = None
        self.command(["/sbin/pfctl", "-X", token])
        require(not re.search(pattern, self.pf(["-s", "References"])), "PF release not verified")

    def stop(self) -> None:
        for process, output, _ in self.captures:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
            output.close()
        self.captures.clear()
        require(not self.install_in_progress, "Installer completion uncertain; no teardown, retain protection")
        if not self.install_started and self.token is None:
            return
        self.publish("stopping")
        self.owned()
        if self.install_started:
            self.stop_job("com.squirrelops.sensor")
            deadline = time.monotonic() + 60
            while self.processes() and time.monotonic() < deadline:
                time.sleep(1)
            require(not self.processes(), "Guest/runtime remains; no force-kill or PF release")
            current = base.listener_endpoints(self.command(LISTENERS).stdout)
            require(not any(uid == "309" for uid, _ in current), "Service-owned listener remains")
            owned = self.owned()
            if owned:
                self.rpc("setupPortForwards", {"rules": [], "interface": "en0",
                         "protected_endpoints": [{"ip": ip, "direct_ports": []} for ip in owned]})
                for ip in owned:
                    self.rpc("removeIPAlias", {"ip": ip, "interface": "en0"})
            self.assert_no_test_network()
            require(not self.owned(), "Ownership remains; retain protection")
            if self.service_loaded("com.squirrelops.helper"):
                self.rpc("clearPortForwards", {})
                self.stop_job("com.squirrelops.helper")
        self.assert_no_test_network()
        require(not self.processes() and all(not self.service_loaded(label) for label in JOBS),
                "Product restarted; retain protection")
        require(empty_policy_matches(self.pf_baseline, self.inspect_empty_pf()), "PF baseline differs; retain reference")
        self.host_baseline()
        self.release_reference()
        self.assert_no_test_network()
        self.host_baseline()
        info = self.pf(["-s", "info"])
        self.publish("stopped", installation_retained=True, test_data_retained=True,
                     aliases_absent=True, guest_stopped=True, original_listener_endpoints_present=True,
                     own_pf_reference_released=True,
                     pf_enabled=bool(re.search(r"^Status:\s+Enabled\b", info, re.M)))
        print("CLEANUP COMPLETE: services/guest stopped, aliases withdrawn, only our PF reference released.", flush=True)
        print("Installation, data and backups retained. Keep the app closed pending review.", flush=True)

    def run(self) -> None:
        os.umask(0o077)
        error = None
        try:
            self.preflight()
            self.install()
            self.observe()
        except BaseException as exc:
            error = type(exc).__name__ + ": " + str(exc)
            print("STOPPED: " + error, flush=True)
        finally:
            try:
                self.stop()
            except BaseException as exc:
                error = (error or "") + " Cleanup incomplete: " + str(exc)
                print("Cleanup incomplete; state requires review. Do not reset networking.", flush=True)
            if error:
                if self.token:
                    error = error.replace(self.token, "[PRIVATE PF REFERENCE]")
                if self.public is not None:
                    self.publish("needs_review", reason=error)
                raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "package_sha256": PACKAGE_SHA,
                          "vips": sorted(base.VIPS), "observe_seconds": 1200, "upgrade_existing": True,
                          "third_party_filter_rule_changes": False, "fault_injection": False}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    Upgrade(args.run).run()


if __name__ == "__main__":
    main()
