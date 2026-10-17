"""Laptop-only, six fixed banner reads. Plan-only without --run PORT PORT."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

ADDRESS = "192.168.1.115"
SOURCE = "192.168.1.7"
BANNER = b"SquirrelOps TCP diagnostic v3\r\n"


def validate_ports(ports):
    if len(ports) != 2 or len(set(ports)) != 2 or not all(type(port) is int and 49152 <= port <= 65535 for port in ports):
        raise RuntimeError("Exactly two distinct approved high ports required")
    return ports


def validate_route(rows):
    if len(rows) != 1 or rows[0].get("dev") != "wlp0s20f3" or rows[0].get("prefsrc") != SOURCE:
        raise RuntimeError("Laptop route or source changed")


def attempts(ports):
    validate_ports(ports)
    return [(number, port) for number in range(1, 4) for port in ports]


def probe(port):
    row = dict(port=port, time=time.time(), connected=False, banner_valid=False, stage="connect")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.bind((SOURCE, 0))
            stream.settimeout(3)
            began = time.monotonic()
            stream.connect((ADDRESS, port))
            row.update(connected=True, connect_seconds=round(time.monotonic()-began, 4), stage="banner")
            deadline = time.monotonic() + 5
            data = bytearray()
            while len(data) < len(BANNER):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                stream.settimeout(remaining)
                part = stream.recv(len(BANNER)-len(data))
                if not part:
                    break
                data.extend(part)
            row.update(banner_valid=bytes(data) == BANNER, response_bytes=len(data), stage="complete")
    except OSError as exc:
        row["error"] = type(exc).__name__
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", nargs=2, type=int, metavar=("SENSOR_PORT", "MATT_PORT"))
    args = parser.parse_args()
    if args.run is None:
        print("PLAN ONLY: exactly six fixed-banner reads to mini .115. No network operations.")
        return 0
    ports = validate_ports(args.run)
    route = subprocess.run(["/usr/sbin/ip", "-j", "route", "get", ADDRESS],
                           check=True, capture_output=True, text=True, timeout=3)
    validate_route(json.loads(route.stdout))
    os.umask(0o077)
    # Exclusive creation prevents replaying this staged client's six-attempt budget.
    path = Path(__file__).resolve().with_name("tcp-client-results.jsonl")
    with path.open("x") as output:
        for number, port in attempts(ports):
            row = dict(attempt=number, **probe(port))
            record = json.dumps(row)
            print(record, flush=True)
            output.write(record + "\n")
            output.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
