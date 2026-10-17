"""Cleanup-only continuation for the exact held mini session; no product repair."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("post", Path(__file__).with_name("mini_post_reboot_acceptance.py"))
post = importlib.util.module_from_spec(spec)
spec.loader.exec_module(post)
base, upgrade, single = post.base, post.upgrade, post.single
require = base.require

EXPECTED = [*post.EXPECTED_INTENT, [7, "home_assistant", "192.168.1.115", 51232, "active"]]
CONTAINER = Path("/Library/SquirrelOps/acceptance-backups")
CLAIM = CONTAINER / f"post-reboot-{post.BOOT}-{post.launchd.PACKAGE_SHA[:12]}-attempt.json"
PUBLIC = Path("/private/var/tmp/squirrelops-mini-post-reboot-results.3p_hssk9")
STAGE = Path("/private/var/root/squirrelops-mini-post-reboot.lQlvs3JI")
CONSENT = "RELEASE THIS TEST PF REFERENCE"
PINS = {
    "mini_acceptance.py": "47b6c6df59083230ac63f97f1b32c55fa804f71839d433bfbc9fb952bf7bd40a",
    "mini_upgrade_acceptance.py": "4c732720e89da4b4a872b56e951b1b70b121e2db603185ecb36d298c99c464d3",
    "mini_ownership_acceptance.py": "98d8729e112e8ff48bbf320b094ab96471e597dd48cec6a726b17807d07986e6",
    "mini_launchd_acceptance.py": "7b2517b3c59fff71741be115267b1687e50c26c5e48c40b903bb3bfdebffa6ba",
    "mini_single_ip_acceptance.py": "3a37156ff54ee8e0086b84036cbe155f4758509d93471047e6a28262e165e943",
    "mini_post_reboot_acceptance.py": "b97147d63a35f8a7b93eade3f01c7a2dfc03a80a6f09b3c29cec7156885cc068",
    "approved-scope.md": "288eb8eb45a50caaac9538f02ac1cc23ca697573e967771a06314cfb2725f24e",
}
EVIDENCE = {
    "status.json": "4bbb6d8ffd6068bf9631c21b6d32fa71e21a06e7124b90b408588f8e4ace0246",
    "after.json": "da012d57b6a1d8e11dd96c68ae830be2a4d503173272fb3d43c4c0cf2b7efcb1",
    "pre-upgrade.json": "c9d71765d626496d066eb3cd321e4b69c1860bd51f41ade48bef238257597d50",
}


def validate_cleanup_intent(rows):
    require(rows == EXPECTED, "Seven reviewed decoy identities or intent changed; retain reference")


def evidence_file(path, expected=None, private=False):
    base.safe_file(path)
    info = path.lstat()
    require(info.st_nlink == 1 and info.st_gid == 0 and
            (not private or stat.S_IMODE(info.st_mode) == 0o600), "Unsafe private evidence metadata")
    if expected is not None:
        require(base.digest(path) == expected, "Pinned evidence changed: " + path.name)


def baseline_path(claim):
    require(set(claim) == {"backup", "package_sha256"} and
            claim["package_sha256"] == post.launchd.PACKAGE_SHA, "Wrong original attempt")
    path = Path(claim["backup"])
    require(path.parent == CONTAINER and
            re.fullmatch(r"mini-post-reboot-20260930\.[A-Za-z0-9_-]+", path.name), "Wrong private backup path")
    return path


def recover_baseline(records, token):
    require(re.fullmatch(r"[0-9]{1,20}", token) is not None, "Malformed private reference")
    for row in records:
        require(set(row) == {"command", "exit", "stdout", "stderr"} and
                isinstance(row["command"], list) and all(isinstance(x, str) for x in row["command"]) and
                type(row["exit"]) is int and all(isinstance(row[k], str) for k in ("stdout", "stderr")),
                "Malformed command evidence")
    enables = [i for i, row in enumerate(records) if row["command"] == ["/sbin/pfctl", "-E"]]
    require(len(enables) == 1, "Expected one original reference acquisition")
    acquired = records[enables[0]]
    require(acquired["exit"] == 0 and base.parse_pf_token(acquired["stdout"] + acquired["stderr"]) == token,
            "Reference does not match original acquisition")
    require(not any(row["command"][:2] == ["/sbin/pfctl", "-X"] for row in records),
            "Original release already attempted; do not retry")
    installs = [row for row in records if row["command"][:1] == ["/usr/sbin/installer"]]
    require(len(installs) == 1 and installs[0]["exit"] == 0 and installs[0]["command"] ==
            ["/usr/sbin/installer", "-pkg", str(STAGE / "candidate.pkg"), "-target", "/"],
            "Original successful install not proven")
    holds = [row for row in records if row["command"] == ["/bin/launchctl", "print-disabled", "system"]]
    require(bool(holds) and holds[-1]["exit"] == 0, "Missing original hold verification")
    post.require_hold(holds[-1]["stdout"])
    prior = records[:enables[0]]
    listeners = [row for row in prior if row["command"] == upgrade.LISTENERS]
    require(bool(listeners) and listeners[0]["exit"] == 0, "Missing original native listeners")
    endpoints = base.listener_endpoints(listeners[0]["stdout"])
    require(not any(uid == "309" for uid, _ in endpoints) and all(
        any(address == endpoint for _, address in endpoints)
        for endpoint in ("*:22", "*:445", "*:5900", "192.168.1.115:11434")), "Incomplete native baseline")

    # Replay only fixed reads issued by the concrete-anchor parser. Commands
    # loaded from logs are data, never passed to a shell or subprocess.
    def recorded(args, **_kwargs):
        matches = [row for row in prior if row["command"] == args]
        require(bool(matches), "Missing original PF read")
        first = matches[0]
        require(all((r["exit"], r["stdout"], r["stderr"]) ==
                    (first["exit"], first["stdout"], first["stderr"]) for r in matches), "Original PF reads differ")
        return subprocess.CompletedProcess(args, first["exit"], first["stdout"], first["stderr"])

    replay = base.Session(Path("/unused"))
    replay.command = recorded
    info = recorded(["/sbin/pfctl", "-s", "info"])
    require(info.returncode == 0 and re.search(r"^Status:\s+Disabled\b", info.stdout, re.M)
            and re.search(r"current entries\s+0\b", info.stdout), "Original disabled PF baseline missing")
    return endpoints, replay.inspect_empty_pf()


def read_command_allowed(args):
    fixed = [upgrade.LISTENERS, ["/bin/ps", "-axo", "uid=,pid=,comm="],
             ["/usr/sbin/sysctl", "kern.boottime"], ["/sbin/ifconfig", "-a"], ["/usr/sbin/arp", "-an"],
             ["/bin/launchctl", "print-disabled", "system"],
             ["/usr/bin/uname", "-m"], ["/usr/bin/sw_vers", "-buildVersion"],
             ["/sbin/route", "-n", "get", "-inet", "default"]]
    fixed += [["/bin/launchctl", "print", "system/" + job] for job in upgrade.JOBS]
    fixed += [["/usr/sbin/ipconfig", "getifaddr", interface] for interface in ("en0", "en1")]
    fixed += [["/usr/sbin/pkgutil", "--pkg-info", "com.squirrelops.home." + part] for part in ("app", "sensor")]
    fixed += [["/bin/ls", "-lde", str(path)] for path in
              (post.DATABASE.parent, post.DATABASE, single.CONFIG.parent, single.CONFIG)]
    if args in fixed:
        return True
    if args[:1] != ["/sbin/pfctl"]:
        return False
    flags = args[1:]
    if flags[:1] == ["-a"]:
        if len(flags) < 3 or not re.fullmatch(r"com\.apple(?:/[A-Za-z0-9_.-]+)*", flags[1]):
            return False
        flags = flags[2:]
    return flags in (["-sr"], ["-sn"], ["-s", "Anchors"], ["-s", "info"], ["-s", "References"])


class Cleanup(post.PostRebootUpgrade):
    def __init__(self, task_dir):
        super().__init__(task_dir)
        self.private_reference = None
        self.release_armed = self.release_started = self.release_attempted = False
        self.backup_verified = False
        self.approved = False

    def command(self, args, **kwargs):
        if args[:2] == ["/sbin/pfctl", "-X"]:
            require(self.release_armed and not self.release_attempted and
                    args == ["/sbin/pfctl", "-X", self.private_reference], "Unapproved reference release")
            self.release_attempted = True
        else:
            require(read_command_allowed(args), "Command outside cleanup-only scope")
        return super().command(args, **kwargs)

    def verify_intent(self):
        validate_cleanup_intent(self.read_intent())

    def verify_stopped(self):
        self.assert_held_stopped()
        require(not self.owned(), "Alias ownership remains; no network withdrawal authorized")
        require(upgrade.empty_policy_matches(self.pf_baseline, self.inspect_empty_pf()),
                "Current PF policy differs; retain reference")
        self.host_baseline()
        current = base.listener_endpoints(self.command(upgrade.LISTENERS).stdout)
        require(not any(uid == "309" or endpoint.endswith(":8443") for uid, endpoint in current),
                "Product listener remains")
        _, data = single.checked_config(single.CONFIG)
        require(hashlib.sha256(data).hexdigest() == single.NEW_CONFIG_SHA, "Configuration drift")
        self.check_config_acl()
        self.verify_intent()
        self.config_change_verified = True

    def verify_reference(self):
        require(self.private_reference is not None, "Missing verified private reference")
        pattern = r"(?<![0-9])" + re.escape(self.private_reference) + r"(?![0-9])"
        require(re.search(pattern, self.pf(["-s", "References"])), "Original reference not present; do not retry")
        require(re.search(r"^Status:\s+Enabled\b", self.pf(["-s", "info"]), re.M), "PF enablement changed")

    def backup_database(self):
        temporary = Path(tempfile.mkdtemp(prefix="squirrelops-reference-db.", dir="/private/var/tmp"))
        os.chown(temporary, 309, 309)
        snapshot = temporary / "snapshot.sqlite"
        require(self.database("backup", snapshot) == {"ok": True}, "Database backup failed")
        info = snapshot.lstat()
        require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (309, 309) and
                info.st_nlink == 1 and 0 < info.st_size <= 64 * 1024**2, "Unsafe database snapshot")
        with os.fdopen(os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "Snapshot identity changed")
            data = stream.read(64 * 1024**2 + 1)
        require(len(data) == info.st_size, "Snapshot size changed")
        single.private_write(self.backup / "pre-cleanup.sqlite", data)
        single.private_write(self.backup / "database-backup.json", json.dumps({
            "sha256": hashlib.sha256(data).hexdigest(), "read_uid": 309, "private_intermediate": str(temporary),
        }).encode())

    def preflight_cleanup(self):
        require(os.geteuid() == 0 and os.isatty(0), "Use attended mini cleanup Terminal")
        require(self.task_dir.parent == Path("/private/var/root") and
                re.fullmatch(r"squirrelops-mini-reference-cleanup\.[A-Za-z0-9_-]+", self.task_dir.name), "Wrong staging")
        for path in (self.task_dir, CONTAINER.parent, CONTAINER, PUBLIC, STAGE):
            base.safe_directory(path)
        evidence_file(CLAIM, private=True)
        self.original = baseline_path(json.loads(CLAIM.read_text()))
        base.safe_directory(self.original)
        self.attempt = self.original / "post-reboot-reference-release-attempt.json"
        require(not self.attempt.exists() and not self.attempt.is_symlink(), "Cleanup already attempted; no retry")
        for name, expected in PINS.items():
            evidence_file(self.original / name, expected, private=True)
        for name, expected in EVIDENCE.items():
            evidence_file(PUBLIC / name, expected)
            evidence_file(self.original / name, expected, private=True)
        token_file = self.original / "pf-reference-token"
        evidence_file(token_file, private=True)
        self.private_reference = token_file.read_text().strip()
        paths = sorted(self.original.glob("command-*.json"), key=lambda p: int(p.stem.split("-")[1]))
        require(1 <= len(paths) <= 20000, "Unexpected original command count")
        records, total_bytes = [], 0
        for index, path in enumerate(paths, 1):
            require(int(path.stem.split("-")[1]) == index, "Original command sequence incomplete")
            evidence_file(path, private=True)
            total_bytes += path.stat().st_size
            require(total_bytes <= 32 * 1024**2, "Original command evidence exceeds size bound")
            records.append(json.loads(path.read_text()))
        self.baseline_listeners, self.pf_baseline = recover_baseline(records, self.private_reference)
        self.backup = Path(tempfile.mkdtemp(prefix="reference-cleanup-20260930.", dir=self.original))
        self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-reference-cleanup-results.", dir="/private/var/tmp"))
        self.public.chmod(0o755)
        print(f"Private cleanup evidence: {self.backup}\nSanitized results: {self.public}", flush=True)
        shutil.copyfile(Path(__file__), self.backup / "mini_post_reboot_cleanup.py")
        for name in EVIDENCE:
            shutil.copyfile(PUBLIC / name, self.backup / ("original-" + name))
        require(self.command(["/usr/bin/uname", "-m"]).stdout.strip() == "arm64" and
                self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == post.BUILD, "Host/OS changed")
        require("100.108.203.27" in self.command(["/sbin/ifconfig", "-a"]).stdout, "Wrong host")
        user, group = base.pwd.getpwnam("_squirrelops"), base.grp.getgrnam("_squirrelops")
        require((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell) ==
                (309, 309, "/var/empty", "/usr/bin/false") and group.gr_gid == 309 and not group.gr_mem,
                "Service account drift")
        for path, expected in {**self.new_executables, upgrade.RUNTIME: upgrade.PYTHON_SHA}.items():
            post.check_payload(path, expected)
        for part in ("app", "sensor"):
            text = self.command(["/usr/sbin/pkgutil", "--pkg-info", "com.squirrelops.home." + part]).stdout
            require("version: 2.1.0\n" in text and "install-time: 1790784842\n" in text, "Receipt drift")
        self.verify_stopped()
        self.verify_reference()
        self.backup_database()
        _, data = single.checked_config(single.CONFIG)
        single.private_write(self.backup / "config-before.yaml", data)
        single.private_write(self.backup / "scope.txt", (
            "Preserve all seven reviewed decoy rows, configuration and installation.\n"
            "Release exactly this session's proven PF reference once; preserve other references.\n"
            "No installer, process signal, service change, database repair, rule edit or global PF reset.\n"
            "No automatic inverse: a new guarded startup requires separate approval.\n"
        ).encode())
        self.backup_verified = True
        self.verify_stopped()
        print("All seven reviewed decoys preserved; stopped state and private reference verified.", flush=True)
        print("Only one PF reference release is proposed. No service, database or filter-rule changes.", flush=True)
        print(f"Type {CONSENT} to continue, or Return to stop:", flush=True)
        require(input().strip() == CONSENT, "Cleanup not approved; reference retained")
        self.approved = True

    def release_once(self):
        require(self.approved and self.backup_verified, "Approval and verified backup required")
        self.verify_stopped()
        self.verify_reference()
        single.private_write(self.attempt, json.dumps({
            "backup": str(self.backup), "results": str(self.public), "boot_seconds": post.BOOT,
            "phase": "release_may_be_attempted_no_retry",
        }).encode())
        self.release_started = self.release_armed = True
        self.token = self.private_reference
        try:
            # The established release checks exact ownership, performs one -X,
            # clears the in-memory token before dispatch, and verifies absence.
            upgrade.Upgrade.release_reference(self)
        finally:
            self.release_armed = False
        self.verify_stopped()
        info = self.pf(["-s", "info"])
        require(re.search(r"^Status:\s+(Enabled|Disabled)\b", info, re.M), "PF status not verified")
        self.publish("stopped", own_pf_reference_released=True, guest_stopped=True,
                     aliases_absent=True, jobs_disabled=True, reviewed_decoy_count=7,
                     source_results=str(PUBLIC), package_sha256=self.package_sha,
                     pf_enabled=bool(re.search(r"^Status:\s+Enabled\b", info, re.M)))
        print("CLEANUP COMPLETE: jobs remain stopped/disabled; aliases absent; only this test's PF reference released.", flush=True)
        print("All seven decoys, installation, configuration and backups retained. Keep app closed pending review.", flush=True)

    def run_cleanup(self):
        os.umask(0o077)
        try:
            self.preflight_cleanup()
            self.release_once()
        except BaseException as exc:
            message = type(exc).__name__ + ": " + str(exc)
            if self.private_reference:
                message = message.replace(self.private_reference, "[PRIVATE PF REFERENCE]")
            print("STOPPED: " + message, flush=True)
            print("No automatic restart, reinstall, database edit or PF reset. Do not rerun; report this output.", flush=True)
            if self.public is not None:
                self.publish("needs_review", reason=message, release_may_have_been_attempted=self.release_started)
            raise SystemExit(1) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "host": "100.108.203.27", "boot_seconds": post.BOOT,
                          "source_results": str(PUBLIC), "reviewed_decoy_count": 7,
                          "only_mutation": "release_original_test_pf_reference_once",
                          "install": False, "restart": False, "database_edits": False,
                          "confirmation": CONSENT}, indent=2))
        return
    Cleanup(args.run).run_cleanup()


if __name__ == "__main__":
    main()
