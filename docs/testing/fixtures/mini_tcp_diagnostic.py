"""Attended, fixed-scope mini diagnostic. No arguments only prints the plan.

The privileged parent uses Apple's Python, never sensor libraries. Only the two
privilege-dropped children use the pinned sensor executable. Nothing invokes
launchd mutations, PF mutations, an installer, a shell or a guest runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import stat
import subprocess
import tempfile
import time

ADDRESS = "192.168.1.115"
PEER = "192.168.1.7"
ETHER = "d0:11:e5:12:9a:c2"
PYTHON = "/Library/SquirrelOps/sensor/python/bin/python3.12"
PYTHON_SHA = "d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147"
ACCOUNTS = ((309, 309), (501, 20))
BANNER = b"SquirrelOps TCP diagnostic v3\r\n"
SECONDS = 180
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}

# Arguments are supplied only by the fixed parent. Tests substitute loopback.
CHILD = r'''
import json, os, select, signal, socket, sys, time
def clock():
    return time.clock_gettime(time.CLOCK_MONOTONIC)
address, peer, raw_deadline = sys.argv[1:]
deadline = float(raw_deadline)
if not 0 < deadline - clock() <= 180:
    raise SystemExit("invalid deadline")
stop = False
def stop_requested(*unused):
    global stop
    stop = True
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, stop_requested)
def emit(**values):
    print(json.dumps(values), flush=True)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind((address, 0))
    port = listener.getsockname()[1]
    if not 49152 <= port <= 65535:
        raise SystemExit("ephemeral port outside approved range")
    listener.listen(8)
    listener.setblocking(False)
    emit(event="ready", pid=os.getpid(), uid=os.getuid(), gid=os.getgid(), address=address, port=port)
    count = 0
    while not stop and clock() < deadline and count < 32:
        ready, _, _ = select.select([listener, 0], [], [], min(0.2, max(0, deadline-clock())))
        if 0 in ready:
            # EOF means parent exited. Any unexpected input also ends the test.
            break
        if listener not in ready:
            continue
        try:
            stream, remote = listener.accept()
        except BlockingIOError:
            continue
        count += 1
        with stream:
            if remote[0] != peer:
                emit(event="other_peer_closed")
                continue
            try:
                stream.settimeout(min(1, max(0.001, deadline-clock())))
                stream.sendall(b"SquirrelOps TCP diagnostic v3\r\n")
                emit(event="banner_sent", count=count)
            except OSError as exc:
                emit(event="send_failed", error=type(exc).__name__)
emit(event="stopped")
'''

COMMANDS = {
    "build": ["/usr/bin/sw_vers", "-buildVersion"],
    "architecture": ["/usr/bin/uname", "-m"],
    "address": ["/usr/sbin/ipconfig", "getifaddr", "en0"],
    "en0": ["/sbin/ifconfig", "en0"],
    "interfaces": ["/sbin/ifconfig", "-a"],
    "arp": ["/usr/sbin/arp", "-an"],
    "route": ["/sbin/route", "-n", "get", PEER],
    "pf": ["/sbin/pfctl", "-s", "info"],
    "pf_rules": ["/sbin/pfctl", "-sr"],
    "pf_nat": ["/sbin/pfctl", "-sn"],
    "sensor_job": ["/bin/launchctl", "print", "system/com.squirrelops.sensor"],
    "helper_job": ["/bin/launchctl", "print", "system/com.squirrelops.helper"],
    "processes": ["/bin/ps", "-axo", "pid=,uid=,comm="],
    "listeners": ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpun"],
    "sockets": ["/usr/sbin/netstat", "-anv", "-p", "tcp"],
    "queues": ["/usr/sbin/netstat", "-Lan", "-p", "tcp"],
    "filters": ["/usr/sbin/sysctl", "net.cfil.active_count", "net.cfil.sock_attached_count"],
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def clock():
    # Explicit OS clock shared by Apple's Python 3.9 and the sensor's 3.12.
    # time.monotonic() on Apple's 3.9 has a process-relative origin on this Mac.
    return time.clock_gettime(time.CLOCK_MONOTONIC)


def trusted(path, owner=0):
    info = path.lstat()
    require((stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            and info.st_uid == owner and not info.st_mode & 0o022,
            "Untrusted file ownership, permissions or link: " + str(path))


def validate_accounts(accounts):
    require(tuple(accounts) == ACCOUNTS, "Account UID/GID changed")


def validate_runtime():
    runtime = Path(PYTHON)
    for path in (runtime, *runtime.parents, runtime.parent.parent / "lib/python3.12"):
        trusted(path)
    require(hashlib.sha256(runtime.read_bytes()).hexdigest() == PYTHON_SHA, "Pinned runtime changed")


def require_unloaded(code, output, error, label):
    require(code != 0 and not output.strip() and f'Could not find service "{label}"' in error,
            "Service loaded or launchd state uncertain: " + label)


def validate_snapshot(snapshot):
    require(snapshot["build"].strip() == "26A428" and snapshot["architecture"].strip() == "arm64", "Mini OS changed")
    require(snapshot["address"].strip() == ADDRESS and "ether " + ETHER in snapshot["en0"], "Mini interface identity changed")
    require(re.search(r"interface:\s+en0\b", snapshot["route"]), "Laptop route changed")
    require(re.search(r"^Status:\s+Disabled\b", snapshot["pf"], re.M), "PF no longer disabled; no change authorized")
    for ip in ("192.168.1.240", "192.168.1.241"):
        require(not re.search(r"\binet\s+" + re.escape(ip) + r"\s", snapshot["interfaces"]), "Test VIP is assigned")
        require(not any(ip in line and ("published" in line or "permanent" in line)
                        for line in snapshot["arp"].splitlines()), "Test proxy ARP exists")
    require(not re.search(r"SquirrelOpsHome|SquirrelOpsHelper|com\.squirrelops\.deception-guest|/Library/SquirrelOps/sensor/python/",
                          snapshot["processes"]), "Product process is running; keep the app closed")


def listener_rows(output):
    pid = uid = None
    rows = set()
    for line in output.splitlines():
        if line.startswith("p"):
            pid, uid = int(line[1:]), None
        elif line.startswith("u"):
            uid = int(line[1:])
        elif line.startswith("n"):
            require(pid is not None and uid is not None, "Incomplete socket owner inventory")
            rows.add((pid, uid, line[1:]))
    return rows


def validate_ready(row, pid, account, used):
    require(row.get("event") == "ready" and row.get("pid") == pid
            and (row.get("uid"), row.get("gid")) == account and row.get("address") == ADDRESS,
            "Unexpected listener identity")
    port = row.get("port")
    require(type(port) is int and 49152 <= port <= 65535 and port not in used, "Invalid or duplicate probe port")


def read_line(child, timeout):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline and len(data) < 2048:
        ready, _, _ = select.select([child.stdout], [], [], min(0.1, max(0, deadline-time.monotonic())))
        if ready:
            value = os.read(child.stdout.fileno(), 1)
            require(bool(value), "Child exited before readiness")
            data.extend(value)
            if value == b"\n":
                return bytes(data)
    raise RuntimeError("Child readiness timeout or oversized response")


def stop_child(child):
    if child.stdin and not child.stdin.closed:
        child.stdin.close()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            # Only a direct, unreaped diagnostic child. Never a discovered PID.
            child.kill()
            child.wait(timeout=2)


def stop_all(children):
    errors = []
    for child in children:
        try:
            stop_child(child)
        except Exception as exc:
            errors.append(type(exc).__name__)
    return errors


def scoped_rows(output, ports):
    patterns = [re.compile(re.escape(ADDRESS) + r"[.:]" + str(port) + r"(?=\s|$)") for port in ports]
    return [line for line in output.splitlines() if any(pattern.search(line) for pattern in patterns)][:128]


class Session:
    def __init__(self, folder):
        self.folder = folder
        self.logs = []
        self.children = []
        self.probes = []
        self.public = None
        self.counter = 0
        self.stop = False

    def observe(self, key, allow_failure=False):
        require(key in COMMANDS, "Unknown observation")
        result = subprocess.run(COMMANDS[key], capture_output=True, text=True, timeout=3, env=ENV)
        self.counter += 1
        (self.folder / ("observation-%04d.json" % self.counter)).write_text(json.dumps({
            "key": key, "time": time.time(), "command": COMMANDS[key], "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
        require(allow_failure or result.returncode == 0, "Read-only observation failed: " + key)
        return result

    def baseline(self):
        for key, label in (("sensor_job", "com.squirrelops.sensor"), ("helper_job", "com.squirrelops.helper")):
            result = self.observe(key, allow_failure=True)
            require_unloaded(result.returncode, result.stdout, result.stderr, label)
        snapshot = {key: self.observe(key).stdout for key in
                    ("build", "architecture", "address", "en0", "interfaces", "arp", "route", "pf",
                     "pf_rules", "pf_nat", "processes", "listeners", "filters")}
        validate_snapshot(snapshot)
        return snapshot

    def spawn(self, uid, gid, deadline):
        error_log = (self.folder / ("child-%d.stderr" % uid)).open("wb")
        self.logs.append(error_log)
        child = subprocess.Popen([PYTHON, "-I", "-S", "-B", "-u", "-c", CHILD, ADDRESS, PEER, str(deadline)],
                                 user=uid, group=gid, extra_groups=[], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=error_log, start_new_session=True,
                                 env=ENV, cwd="/")
        self.children.append(child)
        return child

    def publish(self, phase, **fields):
        record = dict(phase=phase, time=time.time(), address=ADDRESS, peer=PEER, probes=self.probes, **fields)
        if self.public is not None:
            temporary = self.public / "status.pending"
            temporary.write_text(json.dumps(record, indent=2) + "\n")
            temporary.chmod(0o644)
            temporary.replace(self.public / "status.json")

    def requested_stop(self, *unused):
        self.stop = True

    def preflight(self):
        require(os.geteuid() == 0 and os.isatty(0), "Use the attended sudo bootstrap")
        require(self.folder.parent == Path("/private/var/root") and self.folder.name.startswith("squirrelops-tcp-diag."),
                "Unexpected private directory")
        for path in (self.folder, self.folder / "mini_tcp_diagnostic.py", self.folder / "approved-scope.md"):
            trusted(path)
        validate_accounts([(pwd.getpwnam(name).pw_uid, pwd.getpwnam(name).pw_gid) for name in ("_squirrelops", "matt")])
        validate_runtime()
        return self.baseline()

    def run(self):
        before = self.preflight()
        (self.folder / "baseline.json").write_text(json.dumps(before, indent=2) + "\n")
        (self.folder / "runtime-sha256.txt").write_text(PYTHON_SHA + "\n")
        endpoints = {(uid, address) for _, uid, address in listener_rows(before["listeners"])}
        for endpoint in ("*:22", "*:445", "*:5900", ADDRESS + ":11434"):
            require(any(address == endpoint for _, address in endpoints), "Expected native listener missing")
        self.public = Path(tempfile.mkdtemp(prefix="squirrelops-tcp-results.", dir="/private/var/tmp"))
        self.public.chmod(0o755)
        print("Private evidence: " + str(self.folder), flush=True)
        print("Sanitized results: " + str(self.public), flush=True)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, self.requested_stop)
        deadline = clock() + SECONDS
        errors = []
        used = set()
        events = []
        samples = []
        try:
            self.publish("starting")
            for account in ACCOUNTS:
                require(not self.stop and clock() < deadline, "Startup interrupted")
                child = self.spawn(*account, deadline)
                row = json.loads(read_line(child, min(8, max(0, deadline-clock()))))
                validate_ready(row, child.pid, account, used)
                used.add(row["port"])
                self.probes.append(row)
            sockets = listener_rows(self.observe("listeners").stdout)
            for row in self.probes:
                require((row["pid"], row["uid"], ADDRESS + ":" + str(row["port"])) in sockets, "Socket owner verification failed")
            buffers = {child.pid: bytearray() for child in self.children}
            next_observation = 0
            self.publish("ready", seconds_remaining=max(0, round(deadline-clock())))
            print("READY FOR SIX CLIENT PROBES. Tell Codex it is ready; leave this Terminal open.", flush=True)
            print("No filter-rule changes. Note any prompt without accepting it. Return stops early.", flush=True)
            while not self.stop and clock() < deadline - 1:
                require(all(child.poll() is None for child in self.children), "Probe exited early")
                ready, _, _ = select.select([0] + [child.stdout for child in self.children], [], [], 0.2)
                if 0 in ready:
                    break
                for child in self.children:
                    if child.stdout in ready:
                        data = os.read(child.stdout.fileno(), 4096)
                        require(bool(data), "Probe stream ended")
                        buffer = buffers[child.pid]
                        buffer.extend(data)
                        require(len(buffer) < 8192, "Oversized child observation")
                        while b"\n" in buffer:
                            raw, _, tail = buffer.partition(b"\n")
                            buffer[:] = tail
                            event = json.loads(raw)
                            require(event.get("event") in ("banner_sent", "other_peer_closed", "send_failed", "stopped"), "Unknown probe event")
                            events.append(dict(pid=child.pid, time=time.time(), **event))
                            require(len(events) <= 70, "Observation bound exceeded")
                if clock() >= next_observation:
                    observation = {key: scoped_rows(self.observe(key).stdout, used) for key in ("sockets", "queues")}
                    observation["filters"] = self.observe("filters").stdout.strip().splitlines()
                    samples.append(dict(time=time.time(), **observation))
                    observation["events"] = events
                    self.publish("observing", seconds_remaining=max(0, round(deadline-clock())), **observation)
                    next_observation = clock() + 2
        except Exception as exc:
            errors.append(str(exc))
        finally:
            errors.extend(stop_all(self.children))
            for child in self.children:
                child.stdout.close()
            for handle in self.logs:
                handle.close()
            baseline_verified = False
            try:
                after = self.baseline()
                (self.folder / "after.json").write_text(json.dumps(after, indent=2) + "\n")
                after_rows = listener_rows(after["listeners"])
                require(not any(address == ADDRESS + ":" + str(port) for _, _, address in after_rows for port in used),
                        "Probe port remains open")
                require(endpoints <= {(uid, address) for _, uid, address in after_rows}, "Pre-existing listener endpoint/UID changed")
                require(all(before[key] == after[key] for key in ("pf_rules", "pf_nat")), "PF policy changed during diagnostic")
                baseline_verified = True
            except Exception as exc:
                errors.append(str(exc))
            (self.folder / "events.json").write_text(json.dumps(events, indent=2) + "\n")
            self.publish("needs_review" if errors else "stopped", events=events, errors=errors,
                         samples=samples,
                         child_exit_codes=[child.returncode for child in self.children],
                         baseline_verified=baseline_verified)
        if errors:
            print("STOPPED; review required: " + "; ".join(errors), flush=True)
            return 1
        print("COMPLETE: both probes reaped, ports closed, prior listeners present, PF still disabled.", flush=True)
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args(argv)
    if args.run is None:
        print("PLAN ONLY: two fixed-banner listeners on 192.168.1.115, UIDs 309/501; maximum 180 seconds. No host operations.")
        return 0
    os.umask(0o077)
    try:
        return Session(args.run).run()
    except Exception as exc:
        print("STOPPED before readiness: " + str(exc), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
