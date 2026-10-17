"""Approved fixed-scope edge client; default is a no-action plan."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = sibling("client")
guard_module = sibling("edge_guard")
PHASES = ("edge_healthy", "established_replacement", "half_open_start",
          "half_open_wrong_uid", "half_open_quarantine")
TARGETS = guard_module.TARGETS


def syn_packet(index):
    if index not in (0, 1):
        raise ValueError("Invalid fixed target")
    ip, port, source_port = TARGETS[index]
    src, dst = socket.inet_aton("192.168.1.7"), socket.inet_aton(ip)
    tcp = struct.pack("!HHIIBBHHH", source_port, port, 202610020 + index, 0, 0x50, 2, 64240, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", base.checksum(pseudo + tcp)) + tcp[18:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 20262, 0x4000, 64, 6, 0, src, dst)
    header = header[:10] + struct.pack("!H", base.checksum(header)) + header[12:]
    return header + tcp


def response_metadata(packet):
    if len(packet) < 40 or packet[0] >> 4 != 4 or packet[9] != 6:
        return None
    size = (packet[0] & 15) * 4
    if size < 20 or len(packet) < size + 20 or packet[6] & 0x3F or packet[7]:
        return None
    ip, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
    src_port, dst_port, seq, ack, offset, flags, *_ = struct.unpack("!HHIIBBHHH", packet[size:size + 20])
    if (destination != "192.168.1.7" or (ip, src_port, dst_port) not in TARGETS
            or offset >> 4 < 5 or len(packet) < size + (offset >> 4) * 4):
        return None
    return {"ip": ip, "port": src_port, "source_port": dst_port, "seq": seq, "ack": ack, "flags": flags}


class EdgeClient:
    def __init__(self, root):
        self.root, self.held, self.reservations = root, {}, []
        self.guard = self.receive = self.send = self.guard_log = None
        self.guard_started = None
        self.partial = {}

    def preflight(self):
        for ip, _, _ in TARGETS:
            result = subprocess.run(["/usr/sbin/ip", "-j", "route", "get", ip],
                                    capture_output=True, text=True, timeout=3)
            rows = json.loads(result.stdout)
            if result.returncode or len(rows) != 1 or rows[0].get("dev") != "wlp0s20f3" or rows[0].get("prefsrc") != "192.168.1.7":
                raise RuntimeError("Approved source route changed")

    def start_guard(self):
        if self.guard is not None:
            raise RuntimeError("Guard already attempted; no retry")
        for _, _, port in TARGETS:
            stream = socket.socket()
            self.reservations.append(stream)
            stream.bind(("192.168.1.7", port))
        self.guard_log = (self.root / "guard-stderr.log").open("wb")
        nonce = uuid.uuid4().hex[:12]
        self.guard_started = time.monotonic()
        self.guard = subprocess.Popen([sys.executable, "-I", "-S", "-B",
            str(Path(__file__).with_name("edge_guard.py")), "--watch", str(self.root), "--nonce", nonce],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.guard_log,
            start_new_session=True, bufsize=0, env=guard_module.ENV)
        if not select.select([self.guard.stdout], [], [], 12)[0]:
            raise RuntimeError("Guard readiness timeout")
        row = json.loads(self.guard.stdout.readline(1024))
        if row != {"event": "guard_ready", "nonce": nonce, "kernel_ttl": 80}:
            raise RuntimeError("Guard readiness mismatch")
        self.receive = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.receive.setblocking(False)
        self.send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def guard_active(self):
        if self.guard is None or self.guard.poll() is not None or time.monotonic() - self.guard_started > 55:
            raise RuntimeError("Guard no longer active or client deadline exceeded")

    def raw_probes(self):
        self.guard_active()
        # Drain only already-arrived scoped replies, recording them separately
        # rather than mistaking a queued SYN-ACK for the next phase's response.
        prior = []
        for _ in range(256):
            if not select.select([self.receive], [], [], 0)[0]:
                break
            row = response_metadata(self.receive.recv(4096))
            if row:
                prior.append(row)
        for _ in range(2):
            for index, (ip, port, _) in enumerate(TARGETS):
                self.send.sendto(syn_packet(index), (ip, port))
            time.sleep(0.25)
        received = []
        until = time.monotonic() + 1.5
        while time.monotonic() < until and len(received) < 128:
            if select.select([self.receive], [], [], 0.1)[0]:
                row = response_metadata(self.receive.recv(4096))
                if row:
                    received.append(row)
        self.guard_active()
        return {"sent_syn": 4, "prior_replies": prior, "replies": received}

    def phase(self, name):
        self.partial = {}
        if name == "edge_healthy":
            rows = []
            self.partial = {"connections": rows}
            for ip, port, _ in TARGETS:
                row, stream = base.fresh(ip, port, keep=True)
                rows.append(row)
                if stream is None:
                    raise RuntimeError("Healthy control failed")
                self.held[ip] = stream
            return {"connections": rows}
        if name == "established_replacement":
            rows = []
            self.partial = {"connections": rows}
            for ip, port, _ in TARGETS:
                stream = self.held.pop(ip)
                try:
                    stream.sendall(b"A5-PING\n")
                    response = stream.recv(64).decode("ascii", "replace")
                    fresh, _ = base.fresh(ip, port)
                    rows.append({"ip": ip, "held_response": response, "new_connection": fresh})
                    if response != "A5-PONG uid=309\n" or fresh.get("response"):
                        raise RuntimeError("Unexpected established replacement response")
                    base.close_orderly(stream)
                finally:
                    stream.close()
            return {"connections": rows}
        if name == "half_open_start":
            self.start_guard()
            row = self.raw_probes()
            self.partial = row
            if not all(any(reply["ip"] == ip and reply["flags"] & 0x12 == 0x12
                           and reply["ack"] == 202610021 + index for reply in row["replies"])
                       for index, (ip, _, _) in enumerate(TARGETS)):
                raise RuntimeError("Expected SYN-ACK control missing; no half-open acceptance")
            return row
        if name in ("half_open_wrong_uid", "half_open_quarantine"):
            row = self.raw_probes()
            self.partial = row
            row["unexpected_synack"] = any(reply["flags"] & 0x12 == 0x12 for reply in row["replies"])
            if name == "half_open_quarantine":
                row["guard_cleanup"] = self.stop_guard()
            return row
        raise ValueError("Unexpected client phase")

    def stop_guard(self):
        if self.guard is None:
            return {"started": False}
        if not self.guard.stdin.closed:
            self.guard.stdin.close()
        # Do not kill the independent cleanup watchdog on a wait timeout.
        self.guard.wait(timeout=15)
        result = json.loads((self.root / "guard-status.json").read_text())
        if self.guard.returncode or result.get("phase") != "cleaned" or result.get("cleanup_complete") is not True:
            raise RuntimeError("Reset guard cleanup requires review; no retry")
        return {"cleanup_complete": True, "baseline_sha256": result["baseline_sha256"]}

    def close(self):
        try:
            if self.guard is not None:
                self.stop_guard()
        finally:
            for stream in [*self.held.values(), *self.reservations, self.send, self.receive, self.guard_log]:
                if stream is not None:
                    stream.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"mode": "plan_only", "phases": PHASES, "targets": TARGETS,
                          "rule_kernel_ttl": 80, "guard_watchdog": 65}))
        return 0
    if os.geteuid() != 0:
        raise RuntimeError("Approved laptop client requires root")
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="squirrelops-edge-client.", dir="/root"))
    session = EdgeClient(root)
    def interrupted(*unused):
        raise InterruptedError("Client interrupted")
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        session.preflight()
        for expected in PHASES:
            line = sys.stdin.readline(512)
            if not line:
                raise RuntimeError("Client lifeline ended before all phases")
            if json.loads(line) != {"phase": expected}:
                raise RuntimeError("Client phases cannot be skipped or repeated")
            result = {"phase": expected, "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "private_evidence": str(root)}
            try:
                result["observations"] = session.phase(expected)
            except Exception as error:
                result["error_type"] = type(error).__name__
                result["observations"] = session.partial
                guard_module.write(root / (expected + ".json"), result)
                print(json.dumps(result), flush=True)
                raise
            guard_module.write(root / (expected + ".json"), result)
            print(json.dumps(result), flush=True)
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
