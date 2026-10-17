"""Attended Mini-only A5 experiment. Default is a side-effect-free plan.

No installed service, package, database, configuration or firewall preference
is changed. All mutable PF operations target this run's anchor, reference or
the two conflict-checked temporary destination IPs. Results are observations,
not an automatic release approval.
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
import socket
import stat
import subprocess
import tempfile
import time
import uuid

IPS = ("192.168.1.239", "192.168.1.240")
PORTS = (61322, 61445)
PUBLIC_PORTS = (22, 445)
PEER = "192.168.1.7"
PYTHON = "/Library/SquirrelOps/sensor/python/bin/python3.12"
PYTHON_SHA = "d2555cd22a33506826f9eb069bb13fb0cc41303c7da41da5b761967d616f4147"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
WARNINGS = {"No ALTQ support in kernel", "ALTQ related functions disabled"}
LABELS = ("com.squirrelops.sensor", "com.squirrelops.helper")
PHASES = ("healthy", "retained_states", "quarantined", "healthy_again",
          "wrong_uid_retained_state", "missing", "wildcard_wrong_uid", "recovered")

# Child accepts only the approved peer, echoes only a fixed synthetic token,
# has a deadline and stdin lifeline, and never reads product data or commands.
CHILD = r'''
import json, os, select, signal, socket, sys, time
address, raw_port, peer, raw_deadline = sys.argv[1:]
deadline = float(raw_deadline)
clock = lambda: time.clock_gettime(time.CLOCK_MONOTONIC)
if not 0 < deadline - clock() <= 1200:
    raise SystemExit("invalid deadline")
stop = False
def halted(*unused):
    global stop
    stop = True
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, halted)
def emit(**values):
    print(json.dumps(values), flush=True)
clients = []
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, int(raw_port)))
    listener.listen(8)
    listener.setblocking(False)
    emit(event="ready", pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
         address=address, port=listener.getsockname()[1])
    count = 0
    while not stop and clock() < deadline and count < 256:
        ready, _, _ = select.select([0, listener, *clients], [], [], 0.2)
        if 0 in ready:
            break
        if listener in ready:
            try:
                stream, remote = listener.accept()
                stream.settimeout(0.2)
                if remote[0] != peer or len(clients) >= 16:
                    stream.close()
                else:
                    stream.sendall(("A5 uid=%d\n" % os.getuid()).encode())
                    clients.append(stream)
                    emit(event="accepted", source=remote[0], source_port=remote[1], uid=os.getuid())
                    count += 1
            except OSError:
                pass
        for stream in clients[:]:
            if stream not in ready:
                continue
            try:
                data = stream.recv(64)
                if data != b"A5-PING\n":
                    raise OSError("closed or invalid synthetic token")
                stream.sendall(("A5-PONG uid=%d\n" % os.getuid()).encode())
                emit(event="echo", uid=os.getuid())
            except OSError:
                stream.close()
                clients.remove(stream)
    for stream in clients:
        stream.close()
emit(event="stopped")
'''


def require(value, message):
    if not value:
        raise RuntimeError(message)


def clock():
    return time.clock_gettime(time.CLOCK_MONOTONIC)


def safe_read(path, owner=0, limit=16 * 1024 * 1024):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner
                and not info.st_mode & 0o022 and info.st_nlink == 1 and info.st_size <= limit,
                "Unsafe input: " + str(path))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        require(len(result) <= limit, "Input grew beyond bound")
        return result
    finally:
        os.close(fd)


def write_json(path, value, public=False):
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="utf8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o644 if public else 0o600)
    temporary.replace(path)


def valid_ack(value, nonce, phase):
    return isinstance(value, dict) and value == {"nonce": nonce, "phase": phase, "action": "probes_done"}


def packet_metadata(text):
    rows = []
    pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.]\d+) IP "
                         r"(\d+[.]\d+[.]\d+[.]\d+)[.](\d+) > (\d+[.]\d+[.]\d+[.]\d+)[.](\d+): "
                         r"Flags \[([FSRPAUEW.]+)\],")
    for line in text.splitlines():
        match = pattern.match(line)
        if not match or {match[2], match[4]} not in ({PEER, ip} for ip in IPS):
            continue
        rows.append({"time": match[1], "source": match[2], "source_port": int(match[3]),
                     "destination": match[4], "destination_port": int(match[5]), "flags": match[6]})
        if len(rows) >= 3000:
            break
    return rows


def scoped_states(text):
    rows = []
    state_names = {"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "CLOSE_WAIT",
                   "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING", "LAST_ACK", "TIME_WAIT"}
    for line in text.splitlines():
        if not re.match(r"(?:all|ALL|en[01]) tcp ", line):
            continue
        addresses = re.findall(r"(\d+[.]\d+[.]\d+[.]\d+):(\d+)", line)
        seen = {address for address, _ in addresses}
        states = re.search(r"\b([A-Z_0-9]+:[A-Z_0-9]+)\s*$", line)
        if (not states or not set(states[1].split(":")) <= state_names
                or not 2 <= len(addresses) <= 4 or not all(1 <= int(port) <= 65535 for _, port in addresses)
                or PEER not in seen or not seen.intersection(IPS) or not seen <= {*IPS, PEER}):
            continue
        rows.append({"endpoints": [{"ip": address, "port": int(port)} for address, port in addresses],
                     "state": states[1]})
        if len(rows) >= 256:
            break
    return rows


def has_retained_closing_state(rows):
    closing = {"FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "LAST_ACK", "CLOSING", "TIME_WAIT"}
    return any({"ip": IPS[0], "port": PORTS[0]} in row["endpoints"]
               and any(endpoint["ip"] == PEER for endpoint in row["endpoints"])
               and set(row["state"].split(":")) <= closing for row in rows)


def anchor_path(name, parent):
    if parent and not name.startswith(parent + "/"):
        name = parent + "/" + name
    pieces = name.split("/")
    require(len(pieces) <= 16 and all(re.fullmatch(r"[A-Za-z0-9_.-]+", x) and x not in (".", "..") for x in pieces)
            and (name == "com.apple" or name.startswith("com.apple/"))
            and name.rpartition("/")[0] == parent, "Unexpected PF anchor path")
    return name


def validate_policy(text, anchor):
    for line in text.splitlines():
        line = line.strip()
        if not line or (not anchor and line == 'scrub-anchor "com.apple/*" all fragment reassemble'):
            continue
        match = re.fullmatch(r'(?:nat-|rdr-)?anchor "([^"\n]+)" all', line)
        require(match is not None, "Pre-existing PF policy needs review")
        target = match[1][:-2] if match[1].endswith("/*") else match[1]
        anchor_path(target, anchor)


def read_line(child, timeout=20):
    require(select.select([child.stdout], [], [], timeout)[0], "Child readiness/response timeout")
    line = child.stdout.readline(1024 * 1024 + 1)
    require(line and len(line) <= 1024 * 1024 and line.endswith(b"\n"), "Child exited or malformed response")
    return json.loads(line)


def stop_child(child):
    if child.stdin and not child.stdin.closed:
        child.stdin.close()
    if child.poll() is None:
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # Only a direct, unreaped disposable child, never a discovered PID.
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)


class Session:
    def __init__(self, root):
        self.root = root
        self.nonce = uuid.uuid4().hex[:12]
        self.anchor = "com.apple/squirrelops-a5-" + self.nonce
        self.token = None
        self.enable_attempted = self.release_attempted = False
        self.aliases = set()
        self.alias_attempts = set()
        self.children = []
        self.captures = []
        self.handles = []
        self.helper = None
        self.public = None
        self.inbox = None
        self.policy = None
        self.saved = {}
        self.native_listeners = set()
        self.stop = False
        self.sequence = 0
        self.deadline = clock() + 1200

    def record(self):
        write_json(self.root / "receipt.json", {"anchor": self.anchor, "nonce": self.nonce,
                   "vips": IPS, "aliases": sorted(self.aliases), "alias_attempts": sorted(self.alias_attempts),
                   "enable_attempted": self.enable_attempted, "release_attempted": self.release_attempted,
                   "private_pf_token": self.token, "deadline": self.deadline})

    def command(self, args, data=None, check=True):
        self.sequence += 1
        path = self.root / ("command-%04d.json" % self.sequence)
        write_json(path, {"args": args, "started": True, "completed": False})
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=ENV, timeout=20)
        require(len(result.stdout) + len(result.stderr) <= 4 * 1024 * 1024, "Command output exceeds bound")
        write_json(path, {"args": args, "completed": True, "exit": result.returncode,
                          "stdout": result.stdout, "stderr": result.stderr})
        require(not check or result.returncode == 0, "Command failed; private command log retained")
        return result

    def pf(self, args, data=None):
        result = self.command(["/sbin/pfctl", *args], data)
        require(all(not line.strip() or line.strip() in WARNINGS for line in result.stderr.splitlines()),
                "PF returned an unexpected diagnostic; inspect private record")
        return result.stdout

    def native_listener_inventory(self):
        text = self.command(["/usr/sbin/lsof", "-nP", "-l", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout
        uid, result = None, set()
        for line in text.splitlines():
            if line.startswith("p"):
                uid = None
            elif line.startswith("u"):
                uid = line[1:]
            elif line.startswith("n") and line[1:].rsplit(":", 1)[-1] in ("22", "445", "5900"):
                require(uid is not None, "Malformed native listener inventory")
                result.add((uid, line[1:]))
        require({("0", "*:22"), ("0", "*:445"), ("0", "*:5900")} <= result,
                "Mini native SSH/SMB/screen-sharing listener baseline changed")
        return result

    def inventory_policy(self):
        result, pending = {}, [""]
        while pending:
            anchor = pending.pop(0)
            require(anchor not in result and len(result) < 64, "PF tree is ambiguous or too large")
            prefix = ["-a", anchor] if anchor else []
            children = sorted(anchor_path(x.strip(), anchor) for x in self.pf([*prefix, "-s", "Anchors"]).splitlines() if x.strip())
            require(len(children) == len(set(children)), "Duplicate PF anchor")
            children = [x for x in children if x != self.anchor]
            result[anchor] = {"children": children}
            for flag in ("-sr", "-sn"):
                text = self.pf([*prefix, flag])
                validate_policy(text, anchor)
                result[anchor][flag] = text
            pending.extend(children)
        return result

    def held_services(self):
        disabled = self.command(["/bin/launchctl", "print-disabled", "system"]).stdout
        for label in LABELS:
            require('"' + label + '" => disabled' in disabled, "Product job no longer disabled")
            result = self.command(["/bin/launchctl", "print", "system/" + label], check=False)
            require(result.returncode != 0 and not result.stdout.strip()
                    and 'Could not find service "' + label + '"' in result.stderr, "Product job loaded or uncertain")
        processes = self.command(["/bin/ps", "-axo", "pid=,uid=,comm="]).stdout
        require(not any(marker in processes for marker in
                        ("com.squirrelops.deception-guest", "SquirrelOpsHome", "com.squirrelops.helper")),
                "Product process is running")
        # The interpreter is only allowed when this session owns the children.
        own_pids = {x.pid for x in self.children}
        for line in processes.splitlines():
            fields = line.split(None, 2)
            if len(fields) == 3 and fields[2] == PYTHON:
                require(int(fields[0]) in own_pids, "Unowned sensor interpreter is running")

    def no_aliases(self):
        interfaces = self.command(["/sbin/ifconfig", "-a"]).stdout
        arp = self.command(["/usr/sbin/arp", "-an"]).stdout
        for ip in IPS:
            require(not re.search(r"\binet " + re.escape(ip) + r"\s", interfaces), "Test address already assigned")
            require(not any("(" + ip + ")" in line and "published" in line.lower() for line in arp.splitlines()),
                    "Test address has a proxy ARP owner")

    def preserve_files(self, verify=False):
        paths = [Path("/Library/SquirrelOps/sensor/config.yaml"),
                 Path("/Library/SquirrelOps/sensor/data/squirrelops.db"),
                 Path("/Library/SquirrelOps/sensor/data/squirrelops.db-wal"),
                 Path("/Library/SquirrelOps/sensor/data/squirrelops.db-shm"),
                 Path("/Library/LaunchDaemons/com.squirrelops.sensor.plist"),
                 Path("/Library/LaunchDaemons/com.squirrelops.helper.plist"),
                 Path("/var/db/com.squirrelops.helper/owned-aliases")]
        for index, path in enumerate(paths):
            if index in (0, 1, 4, 5):
                require(path.exists(), "Required retained product file is missing")
            item = None
            if path.exists():
                info = path.lstat()
                require(info.st_uid in (0, 309), "Unreviewed product file ownership")
                data = safe_read(path, info.st_uid)
                item = {"sha256": hashlib.sha256(data).hexdigest(), "uid": info.st_uid,
                        "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
                if not verify:
                    (self.root / ("backup-%02d.bin" % index)).write_bytes(data)
            if verify:
                require(self.saved[str(path)] == item, "Retained product data or permissions changed")
            else:
                self.saved[str(path)] = item
        if not verify:
            write_json(self.root / "preserved-files.json", self.saved)

    def preflight(self):
        require(os.geteuid() == 0 and os.isatty(0), "Run attended with sudo")
        require(self.root.parent == Path("/Library/SquirrelOps/acceptance-backups")
                and self.root.name.startswith("mini-a5-"), "Unexpected private evidence path")
        require(self.command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.strip() == "26A434", "Mini OS changed")
        require(self.command(["/usr/bin/uname", "-m"]).stdout.strip() == "arm64", "Wrong architecture")
        for interface, address, mac in (("en0", "192.168.1.115", "d0:11:e5:12:9a:c2"),
                                        ("en1", "192.168.1.254", "ea:03:72:63:7e:01")):
            text = self.command(["/sbin/ifconfig", interface]).stdout
            require("inet " + address + " " in text and "ether " + mac in text and "status: active" in text,
                    "Mini interface identity changed")
        route = self.command(["/sbin/route", "-n", "get", PEER]).stdout
        require(re.search(r"interface:\s+en0\b", route), "Laptop route changed")
        require([(pwd.getpwnam(name).pw_uid, pwd.getpwnam(name).pw_gid) for name in ("_squirrelops", "matt")]
                == [(309, 309), (501, 20)], "Account identity changed")
        require(hashlib.sha256(safe_read(Path(PYTHON))).hexdigest() == PYTHON_SHA, "Pinned child runtime changed")
        for directory in [*Path(PYTHON).parents, Path(PYTHON).parent.parent / "lib/python3.12"]:
            metadata = directory.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022,
                    "Unsafe runtime parent directory")
        self.held_services()
        self.no_aliases()
        require(self.pf(["-s", "info"]).startswith("Status: Disabled"), "PF no longer disabled; review required")
        require(self.pf(["-s", "References"]).strip() == "No pf starter references held", "PF reference already exists")
        self.policy = self.inventory_policy()
        require('anchor "com.apple/*" all' in self.policy[""]["-sr"].splitlines()
                and 'rdr-anchor "com.apple/*" all' in self.policy[""]["-sn"].splitlines(), "Missing parent PF hooks")
        self.preserve_files()
        self.native_listeners = self.native_listener_inventory()
        listeners = self.command(["/usr/sbin/lsof", "-nP", "-l", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout
        for port in PORTS:
            require(not re.search(r"(?m)^n.*:" + str(port) + r"$", listeners), "Disposable backend port occupied")
        write_json(self.root / "baseline-policy.json", self.policy)
        # Verify the changed handoff with real UIDs before aliases or PF writes.
        self.loopback_handoff()
        self.helper = subprocess.Popen([str(self.root / "SquirrelOpsPFProbe"), "--attended", self.anchor],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log("helper-stderr.log"), env=ENV)
        require(self.rpc("unused")["ok"], "A proposed VIP is occupied or ARP check was inconclusive")

    def log(self, name):
        handle = (self.root / name).open("wb")
        self.handles.append(handle)
        return handle

    def rpc(self, op):
        require(self.helper is not None and self.helper.poll() is None, "Private helper exited")
        self.helper.stdin.write(json.dumps({"op": op}).encode() + b"\n")
        self.helper.stdin.flush()
        result = read_line(self.helper, 100)
        self.sequence += 1
        write_json(self.root / ("helper-%04d-%s.json" % (self.sequence, op)), result)
        if self.public is not None:
            write_json(self.public / ("helper-%04d-%s.json" % (self.sequence, op)), {
                "operation": op, "ok": result["ok"], "alias_authorized": result["alias_authorized"],
                "calls": [{key: call[key] for key in ("args", "status", "injected_failure") if key in call}
                          for call in result["calls"]]}, public=True)
        return result

    def enable_reference(self):
        require(not self.enable_attempted, "PF enable already attempted; no retry")
        self.enable_attempted = True
        self.record()
        result = self.command(["/sbin/pfctl", "-E"])
        tokens = re.findall(r"(?m)^Token\s*:\s*([0-9]+)\s*$", result.stdout + result.stderr)
        require(len(tokens) == 1, "PF enable result ambiguous; retain evidence and do not retry")
        self.token = tokens[0]
        self.record()
        require(self.pf(["-s", "info"]).startswith("Status: Enabled"), "PF enable not verified")

    def release_reference(self):
        require(not self.release_attempted, "Reference release already attempted; no retry")
        require(self.token is not None, "No verified private reference")
        text = self.command(["/sbin/pfctl", "-s", "References"]).stdout
        require(any(re.fullmatch(r"\s*\d+\s+pfctl\s+" + re.escape(self.token) + r"\s+.+", line)
                    for line in text.splitlines()), "Owned PF reference not found exactly")
        self.release_attempted = True
        self.record()
        self.command(["/sbin/pfctl", "-X", self.token])

    def add_aliases(self):
        self.no_aliases()
        require(self.rpc("unused")["ok"], "Last-minute address conflict")
        for ip in IPS:
            self.alias_attempts.add(ip)
            self.record()
            self.command(["/sbin/ifconfig", "en0", "inet", ip, "netmask", "255.255.255.255", "alias"])
            self.aliases.add(ip)
            self.record()

    def remove_aliases(self):
        require(self.alias_attempts == self.aliases, "Alias operation was ambiguous; retain quarantine")
        errors = []
        for ip in sorted(self.aliases):
            try:
                self.command(["/sbin/ifconfig", "en0", "inet", ip, "-alias"])
                self.aliases.remove(ip)
                self.alias_attempts.remove(ip)
                self.record()
            except Exception as error:
                errors.append(type(error).__name__)
        require(not errors, "Alias withdrawal incomplete")
        self.no_aliases()

    def spawn_child(self, uid, address, port, peer):
        require(uid in (309, 501), "Invalid disposable UID")
        require((address == peer == "127.0.0.1" and 0 <= port <= 65535)
                or (peer == PEER and ((address, port) in zip(IPS, PORTS)
                                     or (address == "0.0.0.0" and port in PORTS))),
                "Out-of-scope disposable listener")
        child = subprocess.Popen([PYTHON, "-I", "-S", "-B", "-u", "-c", CHILD, address,
            str(port), peer, str(self.deadline)], user=uid, group=309 if uid == 309 else 20,
            extra_groups=[], start_new_session=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.log("child-%s-%s-%s.stderr" % (len(self.children), uid, self.sequence)), env=ENV)
        self.children.append(child)
        row = read_line(child)
        bound_port = row.get("port")
        require(type(bound_port) is int and 1 <= bound_port <= 65535
                and (port == 0 or port == bound_port)
                and row == {"event": "ready", "pid": child.pid, "uid": uid, "gid": 309 if uid == 309 else 20,
                            "address": address, "port": bound_port}, "Child identity mismatch")
        return bound_port

    def loopback_handoff(self):
        port = 0
        for uid in (309, 501):
            port = self.spawn_child(uid, "127.0.0.1", port, "127.0.0.1")
            with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
                require(stream.recv(64) == ("A5 uid=%d\n" % uid).encode(), "Loopback child banner mismatch")
                stream.shutdown(socket.SHUT_WR)
                require(stream.recv(64) == b"", "Loopback close handshake incomplete")
            self.stop_children()
        write_json(self.root / "loopback-handoff.json", {"uids": [309, 501], "port": port,
                                                        "same_backend_port": True, "eof_verified": True})
        print("Loopback UID handoff passed before PF or alias changes.", flush=True)

    def spawn(self, uid, wildcard=False):
        for index, ip in enumerate(IPS):
            address = "0.0.0.0" if wildcard else ip
            self.spawn_child(uid, address, PORTS[index], PEER)

    def stop_children(self):
        errors = []
        for child in self.children:
            try:
                stop_child(child)
                output = child.stdout.read(128 * 1024)
                (self.root / ("child-%s-events.jsonl" % child.pid)).write_bytes(output)
            except Exception as error:
                errors.append(type(error).__name__)
        require(not errors, "Disposable children did not all stop")
        self.children = []

    def publish(self, phase, **details):
        if self.public is not None:
            write_json(self.public / "status.json", {"scope": "mini-a5-disposable", "nonce": self.nonce,
                "phase": phase, "vips": IPS, "public_ports": PUBLIC_PORTS, "backend_ports": PORTS,
                "peer": PEER, "inbox": str(self.inbox), "private_evidence": str(self.root), **details}, public=True)

    def packet_capture(self):
        expression = "tcp and host " + PEER + " and (host " + IPS[0] + " or host " + IPS[1] + ")"
        for interface in ("en0", "en1"):
            child = subprocess.Popen(["/usr/sbin/tcpdump", "-n", "-U", "-i", interface, "-s", "96", "-c", "3000",
                "-w", str(self.root / (interface + ".pcap")), expression], stdout=subprocess.DEVNULL,
                stderr=self.log(interface + "-capture.log"), env=ENV)
            self.captures.append(child)
        time.sleep(0.4)
        require(all(child.poll() is None for child in self.captures), "Packet capture failed to start")

    def evidence(self, phase):
        # All state/rule content stays root-private. Public status is only scope and progress.
        evidence = {
            "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rules": self.pf(["-a", self.anchor, "-sr"]), "nat": self.pf(["-a", self.anchor, "-sn"]),
            "states": self.pf(["-ss"]), "counters": self.pf(["-a", self.anchor, "-vvsr"]),
            "listeners": self.command(["/usr/sbin/lsof", "-nP", "-l", "-iTCP", "-sTCP:LISTEN", "-Fpun"]).stdout}
        write_json(self.root / (phase + "-pf.json"), evidence)
        write_json(self.public / (phase + "-states.json"), {
            "time_utc": evidence["time_utc"], "states": scoped_states(evidence["states"]),
            "raw_state_inventory_retained_privately": True}, public=True)
        return scoped_states(evidence["states"])

    def wait_probes(self, phase, helper_result=None):
        require(phase in PHASES, "Unknown phase")
        self.held_services()
        require(self.pf(["-s", "info"]).startswith("Status: Enabled"), "PF protection disappeared")
        states = self.evidence(phase + "-before")
        if phase == "wrong_uid_retained_state":
            require(has_retained_closing_state(states),
                    "No retained closing PF state on the first endpoint; reuse case not proven")
        self.publish(phase, ready=True, helper_ok=helper_result.get("ok") if helper_result else None,
                     alias_authorized=helper_result.get("alias_authorized") if helper_result else None)
        print("READY: " + phase + ". Waiting for the single bounded laptop phase.", flush=True)
        until = min(clock() + (480 if phase == "healthy" else 150), self.deadline)
        ack_path = self.inbox / (phase + ".json")
        while not self.stop and clock() < until:
            if select.select([0], [], [], 0.2)[0]:
                self.stop = True
                break
            if ack_path.exists():
                value = json.loads(safe_read(ack_path, owner=501, limit=1024))
                require(valid_ack(value, self.nonce, phase), "Invalid phase acknowledgement")
                self.evidence(phase + "-after")
                return
        raise RuntimeError("Attended stop or phase deadline; beginning scoped cleanup")

    def cleanup(self):
        try:
            child_error = None
            try:
                self.stop_children()
            except Exception as error:
                child_error = error
            if self.enable_attempted:
                # If the helper failed, do not invent an alternate recovery implementation.
                # A failed child stop must not prevent independent quarantine.
                require(self.rpc("quarantine")["ok"], "Quarantine recovery incomplete")
                require(child_error is None, "Child stop incomplete; quarantine retained")
                self.remove_aliases()
                self.held_services()
                self.preserve_files(verify=True)
                require(self.native_listener_inventory() == self.native_listeners, "Native listener parity changed")
                require(self.inventory_policy() == self.policy, "Unrelated PF policy changed")
                # A mutation's status is checked; warning text is retained privately.
                # Readback below, unlike loading, must contain only known ALTQ warnings.
                self.command(["/sbin/pfctl", "-a", self.anchor, "-f", "-"], "")
                require(not self.pf(["-a", self.anchor, "-sr"]).strip()
                        and not self.pf(["-a", self.anchor, "-sn"]).strip(), "Test anchor not empty")
                self.release_reference()
                require(self.pf(["-s", "info"]).startswith("Status: Disabled"),
                        "PF did not return to disabled; do not release any other reference")
            require(child_error is None, "Child stop incomplete")
            self.publish("cleaned", ready=False, cleanup_complete=True, result="observations_require_review")
            print("CLEANUP COMPLETE: disposable listeners stopped, aliases withdrawn, only this PF reference released."
                  if self.enable_attempted else "No test network changes were made.", flush=True)
            return True
        except Exception as error:
            write_json(self.root / "cleanup-error.json", {"error": str(error)})
            self.publish("needs_review", ready=False, cleanup_complete=False)
            print("Cleanup incomplete. Retain evidence/protection; do not reset PF or networking.", flush=True)
            return False
        finally:
            for child in self.captures:
                if child.poll() is None:
                    child.send_signal(signal.SIGINT)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.terminate()
                        child.wait(timeout=3)
            if self.helper is not None:
                stop_child(self.helper)
            if self.public is not None and self.captures:
                try:
                    for interface in ("en0", "en1"):
                        result = self.command(["/usr/sbin/tcpdump", "-nn", "-tttt", "-r", str(self.root / (interface + ".pcap"))])
                        write_json(self.public / (interface + "-packet-metadata.json"), {
                            "interface": interface, "packets": packet_metadata(result.stdout)}, public=True)
                except Exception as error:
                    write_json(self.public / "metadata-export-error.json", {"error_type": type(error).__name__}, public=True)
                    print("Packet metadata export incomplete; original private captures retained.", flush=True)
            for handle in self.handles:
                handle.close()

    def run(self):
        def interrupted(*unused):
            self.stop = True
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, interrupted)
        completed = False
        try:
            self.preflight()
            self.public = Path(tempfile.mkdtemp(prefix="squirrelops-mini-a5-results.", dir="/private/var/tmp"))
            self.public.chmod(0o755)
            self.inbox = self.public / "acknowledgements"
            self.inbox.mkdir(mode=0o700)
            os.chown(self.inbox, 501, 20)
            self.record()
            print("Private evidence: " + str(self.root), flush=True)
            print("Sanitized progress: " + str(self.public / "status.json"), flush=True)
            print("No installed service, data or Little Snitch changes. Return stops; deadline 20 minutes.", flush=True)
            # Revalidate before enabling dormant system policy or publishing aliases.
            self.held_services()
            self.no_aliases()
            self.preserve_files(verify=True)
            require(self.inventory_policy() == self.policy, "PF drift before activation")
            self.enable_reference()
            require(self.rpc("quarantine")["ok"], "Initial quarantine failed")
            self.add_aliases()
            self.packet_capture()
            self.spawn(309)
            require(self.rpc("publish")["ok"], "Healthy publication failed")
            self.wait_probes("healthy")
            result = self.rpc("fail_load_first_kill")
            require(not result["ok"] and result["alias_authorized"] == [False, False], "Failed recovery misreported safety")
            self.wait_probes("retained_states", result)
            result = self.rpc("quarantine")
            require(result["ok"] and result["alias_authorized"] == [True, True], "Recovery did not clear debt")
            self.wait_probes("quarantined", result)
            require(self.rpc("publish")["ok"], "Republish failed")
            self.wait_probes("healthy_again")
            self.stop_children()
            self.spawn(501)
            require(not self.rpc("listener_check")["ok"], "Wrong UID accepted by preflight")
            result = self.rpc("fail_load_first_kill")
            require(not result["ok"] and result["alias_authorized"] == [False, False], "Failed recovery lost debt")
            self.wait_probes("wrong_uid_retained_state", result)
            self.stop_children()
            require(not self.rpc("listener_check")["ok"], "Missing listener accepted")
            self.wait_probes("missing", self.rpc("fail_load"))
            self.spawn(501, wildcard=True)
            require(not self.rpc("listener_check")["ok"], "Wildcard listener accepted")
            self.wait_probes("wildcard_wrong_uid", self.rpc("fail_load"))
            result = self.rpc("quarantine")
            require(result["ok"] and result["alias_authorized"] == [True, True], "Final recovery failed")
            self.wait_probes("recovered", result)
            completed = True
        except Exception as error:
            write_json(self.root / "failure.json", {"error": str(error), "type": type(error).__name__})
            print("STOPPED: " + str(error) + ". Private evidence: " + str(self.root), flush=True)
        cleaned = self.cleanup()
        return 0 if completed and cleaned else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args(argv)
    if args.run is None:
        print(json.dumps({"mode": "plan_only", "vips": IPS, "phases": PHASES,
                          "installed_changes": False, "release_approval": False}, indent=2))
        return 0
    return Session(args.run).run()


if __name__ == "__main__":
    raise SystemExit(main())
