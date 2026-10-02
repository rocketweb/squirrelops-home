"""Read only the completed October 1 protocol run; no live probes or PF calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("readonly_common", Path(__file__).with_name("mini_readonly_diagnostic_export.py"))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)

BASE = Path("/Library/SquirrelOps/acceptance-backups")
CLAIM = BASE / "protocol-1790777754-3d18ebac2fae-attempt.json"
RECEIPT = Path("/private/var/tmp/squirrelops-mini-protocol-results.75e9py0n/status.json")
RECEIPT_SHA = "796977f62c6f4e67bf1350c7f2094ebce8325a5f01b75583ea6f9343f523d7c0"
PACKAGE_SHA = "3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea"
CLIENT, VIP = "192.168.1.7", "192.168.1.240"
PORTS = {22, 445, 1234, 11434, 8765, 59738, 59739, 59740, 59741, 59742}
PF_STATES = ["/sbin/pfctl", "-s", "states"]
STATE_NAMES = {"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "CLOSE_WAIT",
               "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT"}
WINDOW = ["2026-10-01 05:28:50", "2026-10-01 05:29:45"]
common.PORTS = PORTS
common.PACKET = re.compile(r"(2026-10-01 \d{2}:\d{2}:\d{2}\.\d{1,9}) IP (192\.168\.1\.(?:7|240))\.(\d+) > (192\.168\.1\.(?:7|240))\.(\d+): tcp (\d+)")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def resolve_backup():
    receipt = common.read_safe(RECEIPT, limit=65536)
    require(hashlib.sha256(receipt).hexdigest() == RECEIPT_SHA, "Cleanup receipt changed")
    claim = json.loads(common.read_safe(CLAIM, limit=65536))
    require(isinstance(claim, dict) and claim.get("package_sha256") == PACKAGE_SHA
            and isinstance(claim.get("backup"), str), "Wrong protocol claim")
    backup = Path(claim["backup"])
    require(backup.parent == BASE and re.fullmatch(r"mini-protocol-20261001\.[A-Za-z0-9_-]+", backup.name),
            "Wrong retained evidence directory")
    private_receipt = common.read_safe(backup / "cleanup.json", limit=65536)
    require(hashlib.sha256(private_receipt).hexdigest() == RECEIPT_SHA, "Private cleanup receipt mismatch")
    return backup


def packet_summary(text):
    selected, withheld = [], 0
    for line in text.splitlines():
        match = common.PACKET.fullmatch(line.strip())
        if match and not WINDOW[0] <= match[1][:19] <= WINDOW[1]:
            withheld += 1
        else:
            selected.append(line)
    return dict(**common.packets("\n".join(selected)), withheld_outside_window_lines=withheld)


def pf_states(record):
    if not isinstance(record, dict) or record.get("command") != PF_STATES:
        return None
    require(type(record.get("exit")) is int, "Malformed state command result")
    states, withheld = [], 0
    if record["exit"] != 0:
        return dict(exit=record["exit"], states=[], withheld_lines=0)
    require(isinstance(record.get("stdout"), str), "Malformed state output")
    for line in record["stdout"].splitlines():
        if not line.strip():
            continue
        addresses = re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line)
        endpoints = re.findall(r"(?<![\d.])(192\.168\.1\.(?:7|240)):(\d{1,5})(?!\d)", line)
        pairs = re.findall(r"\b([A-Z_0-9]+):([A-Z_0-9]+)\b", line)
        pairs = [(left, right) for left, right in pairs if left in STATE_NAMES and right in STATE_NAMES]
        valid = (re.search(r"\btcp\b", line) and set(addresses) == {CLIENT, VIP}
                 and 2 <= len(endpoints) <= 4 and len(pairs) == 1
                 and all(1 <= int(port) <= 65535 and (ip != VIP or int(port) in PORTS)
                         for ip, port in endpoints)
                 and {ip for ip, _ in endpoints} == {CLIENT, VIP})
        if not valid:
            withheld += 1
            continue
        # Never export arbitrary state text, reference numbers, payloads or names.
        states.append(dict(vip_ports=sorted({int(p) for ip, p in endpoints if ip == VIP}),
                           client_ports=sorted({int(p) for ip, p in endpoints if ip == CLIENT}),
                           state_pair=":".join(pairs[0]),
                           arrow="<-" if "<-" in line else "->" if "->" in line else "unknown"))
        require(len(states) <= 128, "Too many scoped states")
    return dict(exit=record["exit"], states=states, withheld_lines=withheld)


def collect(backup):
    report = dict(schema=1, scope="completed-october1-protocol-evidence-only", backup=backup.name,
                  cleanup_receipt_sha256=RECEIPT_SHA, exported_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  packet_window_local=WINDOW, packet_summaries={}, state_snapshots=[])
    for interface in ("en0", "en1"):
        raw = common.read_safe(backup / ("packet-metadata-" + interface + ".txt"))
        report["packet_summaries"][interface] = dict(sha256=hashlib.sha256(raw).hexdigest(),
                                                    **packet_summary(raw.decode("utf-8", "replace")))
    paths = sorted(backup.glob("command-*.json"))
    require(len(paths) <= 6000, "Too many command records")
    total = 0
    for path in paths:
        require(re.fullmatch(r"command-\d{3,6}\.json", path.name), "Unexpected command record name")
        raw = common.read_safe(path, limit=1024 * 1024)
        total += len(raw)
        require(total <= 64 * 1024 * 1024, "Evidence exceeds read budget")
        result = pf_states(json.loads(raw))
        if result is not None:
            report["state_snapshots"].append(dict(record=path.name, **result))
    report["state_snapshot_count"] = len(report["state_snapshots"])
    report["limits"] = ["No packet payloads or flags. Byte totals include retransmissions.",
                        "State records have ordering but no timestamps; all snapshots of this one run are included.",
                        "Unknown formats and unrelated traffic are withheld, not interpreted as absence.",
                        "No Little Snitch history or rules inspected. No live PF commands or probes.",
                        "No changes to services, filters, installation, configuration, database or original evidence."]
    return report


def command(args):
    allowed = [["/usr/sbin/sysctl", "-n", "kern.boottime"],
               ["/bin/launchctl", "print", "system/com.squirrelops.sensor"],
               ["/bin/launchctl", "print", "system/com.squirrelops.helper"]]
    require(args in allowed, "Read command outside allowlist")
    return subprocess.run(args, capture_output=True, text=True, timeout=10,
                          env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})


def main():
    require(os.geteuid() == 0, "Use the pinned wrapper with sudo on the Mini")
    os.umask(0o077)
    backup = resolve_backup()
    boot = command(["/usr/sbin/sysctl", "-n", "kern.boottime"])
    require(boot.returncode == 0 and re.search(r"sec = 1790777754,", boot.stdout), "Boot changed")
    for job in ("com.squirrelops.sensor", "com.squirrelops.helper"):
        state = command(["/bin/launchctl", "print", "system/" + job])
        require(state.returncode != 0 and 'Could not find service "' + job + '"' in state.stderr,
                "Stopped state not verified")
    report = collect(backup)
    output = Path(tempfile.mkdtemp(prefix="squirrelops-protocol-evidence.", dir="/private/var/tmp"))
    result = output / "diagnostic.json"
    with result.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    os.chmod(result, 0o600)
    os.chown(result, 501, 20)
    os.chmod(output, 0o700)
    os.chown(output, 501, 20)
    print("READ-ONLY EXPORT COMPLETE: " + str(result))
    print("Original evidence and permissions unchanged. No services, filters or probes changed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("EXPORT STOPPED: " + type(exc).__name__ + "; original evidence retained; no service or filter changes.")
        raise SystemExit(1)
