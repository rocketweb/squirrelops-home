"""One attended diagnostic upgrade of the held Mini; no mutations in plan mode."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("post", Path(__file__).with_name("mini_post_reboot_acceptance.py"))
post = importlib.util.module_from_spec(spec)
spec.loader.exec_module(post)
base, upgrade, single, launchd = post.base, post.upgrade, post.single, post.launchd
require = base.require
PACKAGE_SHA = "3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea"
SCOPE = "mini-relay-diagnostics-240"
CONSENT = "INSTALL DIAGNOSTICS AND TEST 240"
EXPECTED_INTENT = [*post.EXPECTED_INTENT, [7, "home_assistant", "192.168.1.115", 51232, "active"]]
STAGES = frozenset("listener_activated listener_readable accept_failed client_setup_failed accepted "
                   "main_actor_entered capacity_rejected guest_connect_started guest_connected "
                   "guest_connect_failed guest_connect_timeout relay_started first_read read_eof "
                   "read_failed write_failed poll_failed nonblocking_failed relay_timed_out "
                   "relay_closed diagnostics_truncated".split())
CHECKPOINT = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \[INFO\] "
    r"squirrelops_home_sensor.decoys.deep.guest_runtime: Guest relay checkpoint "
    r"stage=(?P<stage>[a-z_]+) service=(?P<service>22|445) "
    r"connection=(?P<connection>\d{1,10}) sequence=(?P<sequence>\d{1,3}) "
    r"errno=(?P<errno>\d{1,10}) direction=(?P<direction>none|client_to_guest|guest_to_client)"
)


def validate_intent(rows, *, additions=False):
    """Never rewrite saved rows. Retain/report normal classic auto-deployment."""
    require(isinstance(rows, list) and len(rows) <= 128, "Decoy inventory exceeds review bound")
    require(all(isinstance(row, list) and len(row) == 5 and type(row[0]) is int for row in rows),
            "Malformed decoy inventory")
    indexed = {row[0]: row for row in rows}
    require(len(indexed) == len(rows) and all(indexed.get(row[0]) == row for row in EXPECTED_INTENT),
            "One of the seven saved decoys changed; no repair authorized")
    extras = [row for row in rows if row[0] not in {saved[0] for saved in EXPECTED_INTENT}]
    require(additions or not extras, "Stopped baseline contains unreviewed decoys")
    require(all(row[0] > 7 and isinstance(row[1], str) and re.fullmatch(r"[a-z_]{1,40}", row[1])
                and row[1] not in {"deep", "mimic"} and row[2] == "192.168.1.115"
                and type(row[3]) is int and 1024 <= row[3] <= 65535
                and row[4] in {"active", "stopped", "degraded"} for row in extras),
            "New decoy outside host-listener scope; retain evidence")
    return extras


def checkpoints(text, since):
    """Publish only exact fixed-vocabulary logger records, never arbitrary text."""
    result = []
    for line in text.splitlines():
        match = CHECKPOINT.fullmatch(line)
        if not match or match["stage"] not in STAGES or match["time"] < since:
            continue
        row = match.groupdict()
        for name in ("service", "connection", "sequence", "errno"):
            row[name] = int(row[name])
        if not 1 <= row["sequence"] <= 513 or row["errno"] > 2147483647:
            continue
        result.append(row)
        if len(result) == 1539:  # Three process budgets, including startup/restart.
            break
    return result


def socket_metadata(text):
    """Fixed numeric queue metadata for .240 and the one approved client only."""
    result = []
    pid = uid = None
    current = None
    for line in text.splitlines():
        if line.startswith("p"):
            pid = int(line[1:]) if line[1:].isdigit() else None
            uid, current = None, None
        elif line.startswith("u"):
            uid = line[1:]
        elif line.startswith("f"):
            current = None
        elif line.startswith("n"):
            current = None
            endpoint = re.fullmatch(r"n192\.168\.1\.240:(\d{1,5})(?:->192\.168\.1\.7:(\d{1,5}))?", line)
            if not endpoint or uid != "309" or pid is None or len(result) >= 128:
                continue
            local, remote = int(endpoint[1]), int(endpoint[2]) if endpoint[2] else None
            if not 1024 <= local <= 65535 or remote is not None and not 1 <= remote <= 65535:
                continue
            current = {"pid": pid, "local_port": local, "client_port": remote}
            result.append(current)
        elif current is not None:
            if line in {"TST=" + value for value in ("LISTEN", "ESTABLISHED", "SYN_SENT", "SYN_RCVD", "FIN_WAIT_1",
                                                   "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "CLOSED")}:
                current["state"] = line[4:]
            else:
                queue = re.fullmatch(r"T(QR|QS)=(\d{1,10})", line)
                if queue:
                    current[{"QR": "receive_queue", "QS": "send_queue"}[queue[1]]] = int(queue[2])
    return result


class RelayDiagnosticUpgrade(post.PostRebootUpgrade):
    package_sha = PACKAGE_SHA
    old_executables = launchd.LaunchdUpgrade.new_executables
    new_executables = {
        **old_executables,
        base.HELPER: "60b7292f8b843fe0196f8c0025511df0a0d5665528f0c9902895f5939995c351",
        base.APP / "Contents/MacOS/SquirrelOpsHome": "1a93d0c0a3d9dc3e7fc43697f48f9d46e3fb09c6e5f64f8217d84f922c67f2dc",
        Path(upgrade.GUEST): "762e6825939f2eecc1c4c2d704060b7cea624f9ba85801681ca83b7c411fb3f3",
        base.SENSOR / "python/lib/python3.12/site-packages/squirrelops_home_sensor/decoys/deep/guest_runtime.py":
            "f3dc0207945136bfac3ef599a2cf90fed72979421e4469685ae9b8e6a798fa73",
    }
    receipt_time = 1790784842
    staging_prefix = "squirrelops-mini-relay"
    input_names = (*post.PostRebootUpgrade.input_names, "mini_relay_diagnostic_acceptance.py")
    backup_prefix = "mini-relay-20260930."
    results_prefix = "squirrelops-mini-relay-results."

    def __init__(self, task_dir):
        super().__init__(task_dir)
        self.config_sha = single.NEW_CONFIG_SHA
        self.since = time.strftime("%Y-%m-%d %H:%M:%S")

    def publish(self, phase, **fields):
        # Bypass the old scope label without changing the historical module.
        upgrade.Upgrade.publish(self, phase, test_scope=SCOPE, test_vips=[single.VIP],
                                boot_seconds=post.BOOT, configuration_unchanged=True,
                                config_change_verified=self.config_change_verified, **fields)
        shutil.copyfile(self.public / "status.json", self.backup / "status.json")
        (self.backup / "status.json").chmod(0o600)
        if phase == "stopped":
            shutil.copyfile(self.public / "status.json", self.backup / "cleanup.json")

    def check_stale_ledger(self):
        require(not self.owned(), "Stopped baseline still owns an alias; no automatic recovery")

    def verify_intent(self):
        return validate_intent(self.read_intent(), additions=self.install_started)

    def release_reference(self):
        self.restore_hold()
        try:
            # PostRebootUpgrade is an Upgrade, not a LaunchdUpgrade. Borrowing
            # the latter's method fails at its zero-argument super() before PF
            # is inspected. Use the actual base implementation while retaining
            # the same ownership, single-dispatch and secret-redaction guards.
            upgrade.Upgrade.release_reference(self)
        except Exception:
            raise RuntimeError("PF reference release not verified; no retry. Review private evidence") from None

    def preflight(self):
        require(os.geteuid() == 0 and os.isatty(0), "Use attended Mini Terminal bootstrap")
        require(self.task_dir.parent == Path("/private/var/root") and
                re.fullmatch(self.staging_prefix + r"\.[A-Za-z0-9_-]+", self.task_dir.name), "Wrong private staging")
        base.safe_directory(self.task_dir)
        require(base.digest(self.task_dir / "candidate.pkg") == PACKAGE_SHA, "Package checksum mismatch")
        require(self.command(["/usr/bin/uname", "-m"]).stdout.strip() == "arm64", "Wrong architecture")
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == post.BUILD, "OS drift")
        require("100.108.203.27" in self.command(["/sbin/ifconfig", "-a"]).stdout, "Wrong host")
        container = Path("/Library/SquirrelOps/acceptance-backups")
        for path in (container.parent, container):
            base.safe_directory(path)
        self.backup = Path(tempfile.mkdtemp(prefix=self.backup_prefix, dir=container))
        self.public = Path(tempfile.mkdtemp(prefix=self.results_prefix, dir="/private/var/tmp"))
        self.public.chmod(0o755)
        print(f"Durable private backup: {self.backup}\nSanitized results: {self.public}", flush=True)
        for name in self.input_names:
            base.safe_file(self.task_dir / name)
            shutil.copy2(self.task_dir / name, self.backup / name)
        require(base.digest(self.task_dir / "single-ip-config.yaml") == single.NEW_CONFIG_SHA, "Reference config changed")
        self.publish("preflight")
        self.validate_existing()
        self.check_effective_pool(single.CONFIG)
        self.config_change_verified = True  # Verified existing pool, not an edit.
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
        self.verify_intent()
        self.backup_existing()
        self.validate_existing()
        self.snapshot("pre-upgrade")
        print("Seven saved decoys and current .240-only configuration verified. SQL/config edits: zero.", flush=True)
        self.confirm_scope()
        self.upgrade_approved = True

    def confirm_scope(self):
        print("Verified backups retained. Install pinned diagnostics, restart once, permit one bounded laptop run.", flush=True)
        print("Existing sensor discovery/auto-deployment can run; new host listeners are retained and reported.", flush=True)
        print("No Little Snitch, global PF policy, Studio or .241 changes. Restore both disabled jobs after tests.", flush=True)
        print(f"Type {CONSENT} to approve, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Diagnostic upgrade not approved")

    def install_package(self):
        require(self.upgrade_approved and self.backup_verified, "Approval and verified backup required")
        self.validate_existing()
        self.verify_intent()
        self.check_effective_pool(single.CONFIG)
        require(self.inspect_empty_pf() == self.pf_baseline, "PF policy changed")
        self.check_conflicts()  # Only .240; after attended approval, before mutation.
        self.claim = self.backup.parent / f"relay-{post.BOOT}-{PACKAGE_SHA[:12]}-attempt.json"
        single.private_write(self.claim, json.dumps({"backup": str(self.backup), "package_sha256": PACKAGE_SHA}).encode())
        enabled = self.command(["/sbin/pfctl", "-E"])
        self.token = base.parse_pf_token(enabled.stdout + enabled.stderr)
        single.private_write(self.backup / "pf-reference-token", (self.token + "\n").encode())
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF enable not verified")
        self.enable_for_install()
        self.command(["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "600", "/dev/null",
                      "/var/db/com.squirrelops.allow-local-test"])
        self.install_started = self.install_in_progress = True
        self.publish("installing", package_sha256=PACKAGE_SHA)
        print("Installing the pinned diagnostic package. Keep Terminal open.", flush=True)
        result = self.command(["/usr/sbin/installer", "-pkg", str(self.task_dir / "candidate.pkg"), "-target", "/"],
                              check=False, timeout=1800)
        self.install_in_progress = False
        require(result.returncode == 0, "Installer failed; private evidence retained")
        for path, expected in {**self.new_executables, upgrade.RUNTIME: upgrade.PYTHON_SHA}.items():
            post.check_payload(path, expected)
        require(base.digest(single.CONFIG) == self.config_sha, "Installed configuration changed")
        self.command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(base.APP)])
        self.wait_until_ready()

    def wait_until_ready(self):
        super().wait_until_ready()
        current = base.listener_endpoints(self.command(upgrade.LISTENERS).stdout)
        require(all(("309", f"{row[2]}:{row[3]}") in current for row in EXPECTED_INTENT if row[1] != "deep"),
                "One of the two saved classic listeners did not resume")

    def restart_check(self):
        self.snapshot("first-start")
        self.verify_intent()
        print("First startup passed. Testing one normal sensor restart.", flush=True)
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
        self.publish("restart_passed", package_sha256=PACKAGE_SHA)

    def snapshot(self, label):
        super().snapshot(label)
        extras = self.verify_intent()
        log = base.SENSOR / "logs/squirrelops-sensor.log"
        info = log.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 309,
                "Unsafe sensor log; no diagnostic read")
        with os.fdopen(os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "Log replaced during open")
            stream.seek(max(0, opened.st_size - 8 * 1024**2))
            data = stream.read(8 * 1024**2)
        report = {"checkpoints": checkpoints(data.decode("utf-8", "replace"), self.since),
                  "additional_host_listeners": extras, "log_tail_limit_bytes": 8 * 1024**2,
                  "log_rotation_history_included": False}
        if self.install_started:
            sockets = self.command(["/usr/sbin/lsof", "-nP", "-a", "-u", "309", "-iTCP", "-Tqs", "-FpcufnT"], check=False)
            report["socket_inventory_exit"] = sockets.returncode
            report["scoped_socket_queues"] = socket_metadata(sockets.stdout) if sockets.returncode == 0 else []
            self.pf(["-s", "states"])  # Full state metadata remains root-private.
        for parent, mode in ((self.public, 0o644), (self.backup, 0o600)):
            path = parent / (label + "-diagnostics.json")
            temporary = parent / ("." + label + "-diagnostics.tmp")
            temporary.write_text(json.dumps(report, indent=2))
            temporary.chmod(mode)
            temporary.replace(path)

    def observe(self):
        require(self.backup_verified and self.config_change_verified, "Verified backup and configuration required")
        for interface in ("en0", "en1"):
            output = (self.backup / f"packet-metadata-{interface}.txt").open("w")
            process = subprocess.Popen([
                "/usr/sbin/tcpdump", "-i", interface, "-n", "-q", "-tttt", "-l", "-s", "96", single.CAPTURE_FILTER,
            ], stdout=output, stderr=subprocess.DEVNULL)
            self.captures.append((process, output, interface))
        time.sleep(1)
        require(all(p.poll() is None for p, _, _ in self.captures), "Metadata capture startup failed")
        deadline = time.monotonic() + 1200
        self.publish("ready_for_tests", package_sha256=PACKAGE_SHA, remaining_seconds=1200, sensor_uid=309)
        print("READY FOR TESTS. Tell Codex; leave Terminal open. No repeat client run.", flush=True)
        print("Leave new filter prompts unanswered. Return stops early; auto-stop in 20 minutes.", flush=True)
        while time.monotonic() < deadline:
            ready, _, _ = select.select([0], [], [], 2)
            if ready:
                os.read(0, 4096)
                break
            self.snapshot("latest")
            self.publish("ready_for_tests", package_sha256=PACKAGE_SHA,
                         remaining_seconds=max(0, int(deadline - time.monotonic())), sensor_uid=309)
        self.snapshot("after")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "boot_seconds": post.BOOT,
                          "package_sha256": PACKAGE_SHA, "test_scope": SCOPE, "test_vips": [single.VIP],
                          "configuration_edits": 0, "database_recovery": False,
                          "normal_restart": True, "restore_disabled_jobs": True,
                          "third_party_filter_rule_changes": False, "confirmation": CONSENT}, indent=2))
        return
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("Operator interrupted session")
    signal.signal(signal.SIGTERM, interrupted)
    RelayDiagnosticUpgrade(args.run).run()


if __name__ == "__main__":
    main()
