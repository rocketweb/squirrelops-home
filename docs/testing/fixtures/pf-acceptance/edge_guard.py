"""Laptop-only, two-tuple reset suppression with kernel expiry and an EOF watchdog.

No arguments prints the exact plan. Root --watch owns all mutations. Never
flushes/restores a ruleset: it removes only its verified unique table.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import time

NFT = "/usr/sbin/nft"
SOURCE = "192.168.1.7"
TARGETS = (("192.168.1.239", 22, 42839), ("192.168.1.240", 445, 42840))
TTL = 80
WATCH_SECONDS = 65
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}


def table_name(nonce):
    if not re.fullmatch(r"[a-f0-9]{12}", nonce):
        raise ValueError("Invalid test nonce")
    return "squirrelops_a5_" + nonce


def rules(nonce):
    table = table_name(nonce)
    lines = [f"add table ip {table}",
             f"add set ip {table} live_ports {{ type inet_service; flags timeout; timeout {TTL}s; }}",
             f"add element ip {table} live_ports {{ 42839 timeout {TTL}s, 42840 timeout {TTL}s }}",
             f"add chain ip {table} out {{ type filter hook output priority -301; policy accept; }}"]
    for ip, port, source_port in TARGETS:
        lines.append(f"add rule ip {table} out ip saddr {SOURCE} ip daddr {ip} tcp sport {source_port} "
                     f"tcp dport {port} tcp flags & rst == rst tcp sport @live_ports counter drop "
                     f'comment "{table}_{source_port}"')
    return "\n".join(lines) + "\n"


def canonical(value, keep_handles=False):
    def normalize(item):
        if isinstance(item, list):
            return [normalize(row) for row in item if not (isinstance(row, dict) and "metainfo" in row)]
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if key == "expires" or (key == "handle" and not keep_handles):
                    continue
                if key == "counter" and isinstance(child, dict):
                    child = {k: (0 if k in ("packets", "bytes") else v) for k, v in child.items()}
                result[key] = normalize(child)
            return result
        return item
    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"))


def write(path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def supervise(fd, deadline, cleanup, now=time.monotonic):
    try:
        while now() < deadline:
            if select.select([fd], [], [], min(0.2, max(0, deadline - now())))[0]:
                if os.read(fd, 1):
                    raise RuntimeError("Unexpected watchdog input")
                break
    finally:
        cleanup()


class Guard:
    def __init__(self, root, nonce):
        self.root, self.nonce, self.table = root, nonce, table_name(nonce)
        self.initial = self.owned = None
        self.add_attempted = self.delete_attempted = self.cleaned = False
        self.sequence = 0

    def record(self, phase, **extra):
        write(self.root / "guard-status.json", {"phase": phase, "nonce": self.nonce,
              "table": self.table, "add_attempted": self.add_attempted,
              "delete_attempted": self.delete_attempted, "cleanup_complete": self.cleaned, **extra})

    def run(self, args, data=None):
        self.sequence += 1
        path = self.root / ("nft-%03d.json" % self.sequence)
        write(path, {"args": args, "started": True, "completed": False})
        result = subprocess.run([NFT, *args], input=data, capture_output=True, text=True, env=ENV, timeout=3)
        if len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024:
            raise RuntimeError("Filter inventory exceeds bound")
        write(path, {"args": args, "completed": True, "exit": result.returncode,
                     "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Filter command failed; private evidence retained")
        return result.stdout

    def snapshot(self):
        result = json.loads(self.run(["-j", "list", "ruleset"]))
        if not isinstance(result, dict) or not isinstance(result.get("nftables"), list):
            raise RuntimeError("Malformed filter inventory")
        return result

    def selected(self, value):
        rows = []
        for entry in value["nftables"]:
            for kind, item in entry.items():
                if isinstance(item, dict) and item.get("family") == "ip" and (
                        item.get("table") == self.table or (kind == "table" and item.get("name") == self.table)):
                    item = dict(item)
                    # Kernel expiration removes these two set elements. Rules
                    # still carry both literal ports, addresses and RST match.
                    if kind == "set" and item.get("name") == "live_ports":
                        item.pop("elem", None)
                    rows.append({kind: item})
        return {"nftables": rows}

    def install(self):
        if self.add_attempted:
            raise RuntimeError("Add already attempted; no retry")
        self.initial = self.snapshot()
        if self.selected(self.initial)["nftables"]:
            raise RuntimeError("Unique test table already exists")
        write(self.root / "filter-baseline.json", self.initial)
        baseline_hash = hashlib.sha256(canonical(self.initial).encode()).hexdigest()
        preview = rules(self.nonce)
        (self.root / "rules-preview.nft").write_text(preview)
        self.run(["--check", "-f", "-"], preview)
        self.add_attempted = True
        self.record("adding", baseline_sha256=baseline_hash)
        self.started = time.monotonic()
        self.run(["-f", "-"], preview)
        self.owned = self.selected(self.snapshot())
        kinds = [next(iter(row)) for row in self.owned["nftables"]]
        if sorted(kinds) != sorted(["table", "chain", "set", "rule", "rule"]):
            self.owned = None
            raise RuntimeError("Unexpected owned-table shape")
        write(self.root / "owned-filter.json", self.owned)
        self.record("active", baseline_sha256=baseline_hash,
                    expires_after_seconds=TTL, watchdog_seconds=WATCH_SECONDS)

    def cleanup(self):
        if self.delete_attempted:
            raise RuntimeError("Delete already attempted; no retry")
        if not self.add_attempted:
            self.cleaned = True
            self.record("cleaned")
            return
        current = self.snapshot()
        selected = self.selected(current)
        if selected["nftables"]:
            if self.owned is None or canonical(selected, True) != canonical(self.owned, True):
                raise RuntimeError("Test table ownership changed or is uncertain; kernel expiry remains bounded")
            self.delete_attempted = True
            self.record("deleting")
            self.run(["delete", "table", "ip", self.table])
            current = self.snapshot()
        if canonical(current) != canonical(self.initial):
            raise RuntimeError("Filter baseline differs; no automatic restoration")
        self.cleaned = True
        self.record("cleaned", baseline_sha256=hashlib.sha256(canonical(self.initial).encode()).hexdigest())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch", type=Path)
    parser.add_argument("--nonce", default="a" * 12)
    args = parser.parse_args(argv)
    if args.watch is None:
        print(rules(args.nonce), end="")
        return 0
    root = args.watch
    info = root.lstat()
    if (os.geteuid() != 0 or root.parent != Path("/root") or not root.name.startswith("squirrelops-edge-client.")
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077):
        raise RuntimeError("Unsafe private guard directory")
    os.umask(0o077)
    session = Guard(root, args.nonce)
    def interrupted(*unused):
        raise InterruptedError("Guard interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    # This detached child follows stdin EOF, not the SSH terminal's SIGHUP.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    supervised = False
    try:
        session.install()
        print(json.dumps({"event": "guard_ready", "nonce": args.nonce, "kernel_ttl": TTL}), flush=True)
        supervised = True
        supervise(0, session.started + WATCH_SECONDS, session.cleanup)
        return 0
    except BaseException as error:
        if not supervised:
            try:
                session.cleanup()
            except BaseException as cleanup_error:
                session.record("needs_review", error_type=type(error).__name__,
                               cleanup_error_type=type(cleanup_error).__name__)
                return 1
        if not session.cleaned:
            session.record("needs_review", error_type=type(error).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
