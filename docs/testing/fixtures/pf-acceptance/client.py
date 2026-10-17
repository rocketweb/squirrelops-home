"""Fixed-target laptop client. No arguments prints the plan; --run reads phases.

No filter, route or system configuration changes. Keeps two real TCP sessions
between phases and records actual synthetic responses. Second-ingress raw SYN
probes use Linux AF_PACKET with only the two approved VIPs. No dependencies.
"""
import argparse
import json
import socket
import struct
import sys
import time

IPS = ("192.168.1.239", "192.168.1.240")
PUBLIC_PORTS = (22, 445)
BACKEND_PORTS = (61322, 61445)
PHASES = ("healthy", "retained_states", "quarantined", "healthy_again",
          "wrong_uid_retained_state", "missing", "wildcard_wrong_uid", "recovered")


def fresh(ip, port, source_port=0, keep=False):
    stream = socket.socket()
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stream.settimeout(2)
    row = {"ip": ip, "port": port, "requested_source_port": source_port}
    try:
        stream.bind(("192.168.1.7", source_port))
        row["source_port"] = stream.getsockname()[1]
        stream.connect((ip, port))
        row["connected"] = True
        row["response"] = stream.recv(64).decode("ascii", "replace")
        if keep and row["response"] == "A5 uid=309\n":
            return row, stream
    except OSError as error:
        row["error"] = type(error).__name__
    stream.close()
    return row, None


def close_orderly(stream):
    # Client sends FIN first. Do not leave the server owning a FIN_WAIT socket
    # when the next phase binds the same backend address under a different UID.
    # PF closing-state retention is checked separately on the Mini.
    try:
        stream.shutdown(socket.SHUT_WR)
        if stream.recv(64) != b"":
            raise RuntimeError("Unexpected bytes during client close handshake")
    finally:
        stream.close()


def phase(name, held):
    if name not in PHASES:
        raise ValueError("Unknown phase")
    rows = []
    for index, ip in enumerate(IPS):
        old = held.pop(ip, None)
        if old is not None:
            stream, source_port = old
            if stream is None:
                if name != "wrong_uid_retained_state":
                    raise RuntimeError("Closed tuple appeared in an unexpected phase")
                retry, _ = fresh(ip, PUBLIC_PORTS[index], source_port)
                rows.append({"kind": "same_tuple_reconnect", **retry})
                old = None
        if old is not None:
            stream, source_port = old
            row = {"kind": "established", "ip": ip, "source_port": source_port}
            try:
                stream.sendall(b"A5-PING\n")
                row["response"] = stream.recv(64).decode("ascii", "replace")
            except OSError as error:
                row["error"] = type(error).__name__
            rows.append(row)
            if name in ("healthy", "healthy_again"):
                stream.close()
            elif name == "wrong_uid_retained_state":
                stream.close()
                retry, _ = fresh(ip, PUBLIC_PORTS[index], source_port)
                rows.append({"kind": "same_tuple_reconnect", **retry})
            else:
                held[ip] = (stream, source_port)
        row, stream = fresh(ip, PUBLIC_PORTS[index], keep=name in ("healthy", "healthy_again"))
        rows.append({"kind": "forwarded", **row})
        if stream is not None:
            source_port = stream.getsockname()[1]
            if name == "healthy_again":
                close_orderly(stream)
                rows.append({"kind": "client_close", "ip": ip, "source_port": source_port, "eof": True})
                held[ip] = (None, source_port)
            else:
                held[ip] = (stream, source_port)
        direct, _ = fresh(ip, BACKEND_PORTS[index])
        rows.append({"kind": "direct_backend", **direct})
    return rows


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def second_ingress_frames(source_mac):
    if len(source_mac) != 6:
        raise ValueError("Invalid interface MAC")
    result = []
    src = socket.inet_aton("192.168.1.7")
    ethernet = bytes.fromhex("ea0372637e01") + source_mac + b"\x08\x00"
    for index, ip in enumerate(IPS):
        dst = socket.inet_aton(ip)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 20261, 0x4000, 64, 6, 0, src, dst)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        tcp = struct.pack("!HHIIBBHHH", 42739 + index, PUBLIC_PORTS[index], 20261002, 0, 0x50, 2, 64240, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
        result.append(ethernet + header + tcp)
    return result


def second_ingress():
    # Packet delivery must be confirmed in the Mini's en1 capture. A timeout
    # alone is not a successful second-ingress check. SYN retransmission here
    # does not claim a deliberately retained half-open state (the client kernel
    # may send RST), which remains a separate acceptance case.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
        raw.bind(("wlp0s20f3", 0))
        for packet in second_ingress_frames(raw.getsockname()[4]):
            for _ in range(2):
                raw.send(packet)
                time.sleep(0.4)
    return {"sent": 4, "confirmation": "requires Mini en1 packet capture"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"mode": "plan_only", "targets": IPS, "phases": PHASES}))
        return 0
    held = {}
    started = time.monotonic()
    try:
        for expected in PHASES:
            raw = sys.stdin.readline(1024)
            if not raw or time.monotonic() - started > 1200:
                break
            request = json.loads(raw)
            if request != {"phase": expected}:
                raise ValueError("Phase out of order; no repeat probes")
            result = {"phase": expected, "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "observations": phase(expected, held)}
            if expected == "healthy":
                try:
                    result["second_ingress"] = second_ingress()
                except Exception as error:
                    result["second_ingress"] = {"error": type(error).__name__, "status": "not_proven"}
            print(json.dumps(result), flush=True)
    finally:
        for stream, _ in held.values():
            if stream is not None:
                stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
