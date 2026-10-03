"""Export pinned completed October 2 evidence. No subprocesses or live probes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

BASE = Path("/Library/SquirrelOps/acceptance-backups")
RUNS = (
    ("mini-a5-20261002.E0xeDbUY", "3f996b3d7f94", "squirrelops-mini-a5-results.3iww7ltq"),
    ("mini-a5-20261002.cJ0axKPR", "cd6249333a04", "squirrelops-mini-a5-results.18k_6lvo"),
)
SUCCESSFUL_RUN = ("mini-a5-20261002.DcmC5nO5", "c21040d915eb", "squirrelops-mini-a5-results.tj3gpkxe")
PHASES = ("healthy", "retained_states", "quarantined", "healthy_again",
          "wrong_uid_retained_state", "missing", "wildcard_wrong_uid", "recovered")
IPS = {"192.168.1.7", "192.168.1.239", "192.168.1.240"}
STATE_NAMES = {"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "CLOSE_WAIT",
               "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING", "LAST_ACK", "TIME_WAIT"}


def read_safe(path, owner=0):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= 4 * 1024 * 1024):
            raise RuntimeError("Unsafe evidence file")
        with os.fdopen(fd, "r", closefd=False) as stream:
            result = stream.read(4 * 1024 * 1024 + 1)
        if len(result) > 4 * 1024 * 1024:
            raise RuntimeError("Evidence exceeds bound")
        return result
    finally:
        os.close(fd)


def error_summary(text):
    # Never copy arbitrary traceback or subprocess arguments into public output.
    return {
        "empty": not text.strip(),
        "error_classes": sorted(set(re.findall(
            r"\b(PermissionError|OSError|RuntimeError|ModuleNotFoundError|ImportError|FileNotFoundError|TimeoutError)\b", text))),
        "errno": sorted({int(x) for x in re.findall(r"\[Errno (\d{1,3})\]", text)}),
        "address_in_use": "Address already in use" in text,
        "permission_denied": "Permission denied" in text,
        "child_exited_or_malformed": "Child exited or malformed response" in text,
        "readiness_timeout": "Child readiness/response timeout" in text,
        "attended_stop_or_deadline": "Attended stop or phase deadline" in text,
        "fatal_python_error": "Fatal Python error" in text,
    }


def state_summary(text):
    selected, shapes, withheld = [], set(), 0
    for line in text.splitlines():
        if not line.strip():
            continue
        addresses = set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line))
        endpoints = re.findall(r"(?<![\d.])(192\.168\.1\.(?:7|239|240)):(\d{1,5})(?!\d)", line)
        pairs = [(a, b) for a, b in re.findall(r"\b([A-Z_0-9]+):([A-Z_0-9]+)\b", line)
                 if a in STATE_NAMES and b in STATE_NAMES]
        if (not re.search(r"\btcp\b", line) or not addresses <= IPS or "192.168.1.7" not in addresses
                or not addresses.intersection({"192.168.1.239", "192.168.1.240"})
                or not 2 <= len(endpoints) <= 4 or len(pairs) != 1
                or not all(1 <= int(port) <= 65535 for _, port in endpoints)):
            withheld += 1
            continue
        first = line.split()[0]
        shapes.add(first if first in ("all", "ALL", "en0", "en1", "tcp") else "other")
        selected.append({"endpoints": [{"ip": ip, "port": int(port)} for ip, port in endpoints],
                         "state_pair": ":".join(pairs[0]), "prefix": first if first in shapes else "other"})
        if len(selected) > 256:
            raise RuntimeError("Too many scoped states")
    return {"selected": selected, "selected_prefixes": sorted(shapes), "withheld_lines": withheld,
            "nonempty_lines": sum(bool(line.strip()) for line in text.splitlines())}


def counter_summary(text):
    """Export hashes, allowlisted rule identities and numbers, never raw rules."""
    rules, current, withheld = [], None, 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.fullmatch(r"@(\d{1,3}) (.{1,2048})", line)
        if match:
            rule = match[2]
            current = {"index": int(match[1]), "rule_sha256": hashlib.sha256(rule.encode()).hexdigest(),
                       "kind": "unrecognized", "counters": None}
            for ip, port, public in (("192.168.1.239", 61322, 22), ("192.168.1.240", 61445, 445)):
                target = re.escape(ip) + r"(?:/32)?"
                block = re.fullmatch(r"block drop in quick inet from any to " + target, rule)
                echo = re.fullmatch(r"pass in quick on en0 inet proto icmp from any to " + target
                                    + r" icmp-type (?:echoreq|8)(?: keep state)?", rule)
                tcp = re.match(r"pass in quick on en0 inet proto tcp from any to " + target
                               + r" port = " + str(port) + r" ", rule)
                if block or echo:
                    current.update(kind="vip_block" if block else "echo_pass", ip=ip)
                if tcp:
                    tail = rule[tcp.end():]
                    tag = "squirrelops_" + ip.replace(".", "_") + "_%s_%s" % (public, port)
                    valid = True
                    for field in (r"user = (?:309|_squirrelops)", r"flags any", r"keep state", "tagged " + tag):
                        tail, count = re.subn(r"(?<!\S)" + field + r"(?!\S)", "", tail)
                        valid = valid and count == 1
                    if valid and not tail.strip():
                        current.update(kind="uid_tag_pass", ip=ip, port=port, uid=309)
            rules.append(current)
            if len(rules) > 64:
                raise RuntimeError("Too many retained rules")
        elif "Evaluations:" in line:
            match = re.fullmatch(r"\[\s*Evaluations:\s*(\d{1,20})\s+Packets:\s*(\d{1,20})"
                                 r"\s+Bytes:\s*(\d{1,20})\s+States:\s*(\d{1,20})\s*\]", line)
            if (current is not None and current["counters"] is None and match
                    and all(int(n) <= 2**64 - 1 for n in match.groups())):
                current["counters"] = dict(zip(("evaluations", "packets", "bytes", "states"),
                                                map(int, match.groups())))
            else:
                withheld += 1
        elif not re.fullmatch(r"\[\s*Inserted:\s*uid \d+ pid \d+\s*\]", line):
            withheld += 1
    return {"rules": rules, "withheld_lines": withheld}


def counter_delta(before, after):
    unavailable = {"comparable": False, "rules": []}
    if (before["withheld_lines"] or after["withheld_lines"] or not before["rules"]
            or len(before["rules"]) != len(after["rules"])):
        return unavailable
    rows = []
    for left, right in zip(before["rules"], after["rules"]):
        if (left["rule_sha256"] != right["rule_sha256"] or left["index"] != right["index"]
                or left["kind"] == "unrecognized" or not left["counters"] or not right["counters"]
                or any(right["counters"][key] < left["counters"][key]
                       for key in ("evaluations", "packets", "bytes"))):
            return unavailable
        row = {key: left[key] for key in ("index", "kind", "ip", "rule_sha256")}
        row.update({key + "_delta": right["counters"][key] - left["counters"][key]
                    for key in ("evaluations", "packets", "bytes", "states")})
        rows.append(row)
    return {"comparable": True, "rules": rows}


def child_summary(text):
    result = {"lan_accepts": {"309": 0, "501": 0}, "loopback_accepts": {"309": 0, "501": 0},
              "echoes": {"309": 0, "501": 0}, "stopped": False, "withheld_lines": 0}
    lines = text.splitlines()
    if len(lines) > 1024:
        raise RuntimeError("Too many child events")
    for line in lines:
        result["stopped"] = False
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            event = None
        if event == {"event": "stopped"}:
            result["stopped"] = True
        elif (isinstance(event, dict) and event.get("uid") in (309, 501)
              and event.get("event") == "echo" and set(event) == {"uid", "event"}):
            result["echoes"][str(event["uid"])] += 1
        elif (isinstance(event, dict) and event.get("event") == "accepted"
              and set(event) == {"event", "uid", "source", "source_port"}
              and event["uid"] in (309, 501) and event["source"] in ("127.0.0.1", "192.168.1.7")
              and type(event["source_port"]) is int and 1 <= event["source_port"] <= 65535):
            key = "lan_accepts" if event["source"] == "192.168.1.7" else "loopback_accepts"
            result[key][str(event["uid"])] += 1
        else:
            result["withheld_lines"] += 1
    return result


def verified_root(run):
    name, nonce, public_name = run
    root = BASE / name
    public = Path("/private/var/tmp") / public_name
    for directory in (BASE, root, public):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("Unsafe retained evidence directory")
    status = json.loads(read_safe(public / "status.json"))
    receipt = json.loads(read_safe(root / "receipt.json"))
    if not (status["nonce"] == receipt["nonce"] == nonce and status["phase"] == "cleaned"
            and status["cleanup_complete"] is True and receipt["release_attempted"] is True
            and receipt["aliases"] == receipt["alias_attempts"] == []):
        raise RuntimeError("Completed-run identity or cleanup changed")
    return root


def collect_successful():
    root = verified_root(SUCCESSFUL_RUN)
    result = {"scope": "completed-mini-a5-counter-review", "nonce": SUCCESSFUL_RUN[1],
              "backup": SUCCESSFUL_RUN[0], "cleanup_verified": True, "system_mutations": False,
              "snapshots": [], "phase_deltas": [], "children": [], "child_errors": []}
    for phase in PHASES:
        counts = []
        for side in ("before", "after"):
            name = phase + "-" + side + "-pf.json"
            value = json.loads(read_safe(root / name))
            if not re.fullmatch(r"2026-10-02T\d{2}:\d{2}:\d{2}Z", value["time_utc"]):
                raise RuntimeError("Unexpected snapshot date")
            counts.append(counter_summary(value["counters"]))
            result["snapshots"].append({"file": name, "time_utc": value["time_utc"],
                                        "counters": counts[-1], "states": state_summary(value["states"])})
        result["phase_deltas"].append({"phase": phase, **counter_delta(*counts)})
    for path in sorted(root.glob("child-*-events.jsonl")):
        if re.fullmatch(r"child-\d+-events[.]jsonl", path.name):
            result["children"].append({"file": path.name, **child_summary(read_safe(path))})
    if len(result["children"]) != 8:
        raise RuntimeError("Expected exactly eight retained child event streams")
    for path in sorted(root.glob("child-*.stderr")):
        match = re.fullmatch(r"child-\d+-(309|501)-\d+[.]stderr", path.name)
        if match:
            result["child_errors"].append({"file": path.name, "uid": int(match[1]),
                                            **error_summary(read_safe(path))})
    return result


def collect():
    result = []
    for name, nonce, public_name in RUNS:
        root = BASE / name
        for directory in (BASE, root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("Unsafe retained evidence directory")
        status = json.loads(read_safe(Path("/private/var/tmp") / public_name / "status.json"))
        receipt = json.loads(read_safe(root / "receipt.json"))
        if not (status["nonce"] == receipt["nonce"] == nonce and status["phase"] == "cleaned"
                and status["cleanup_complete"] is True and receipt["release_attempted"] is True
                and receipt["aliases"] == receipt["alias_attempts"] == []):
            raise RuntimeError("Completed-run identity or cleanup changed")
        row = {"backup": name, "nonce": nonce, "cleanup_verified": True,
               "failure": error_summary(read_safe(root / "failure.json")), "children": [], "snapshots": []}
        for path in sorted(root.glob("child-*.stderr")):
            match = re.fullmatch(r"child-\d+-(309|501)-\d+[.]stderr", path.name)
            if match:
                row["children"].append({"file": path.name, "uid": int(match[1]),
                                        **error_summary(read_safe(path))})
        for path in sorted(root.glob("*-pf.json")):
            if re.fullmatch(r"(?:healthy|healthy_again|retained_states|quarantined)-(?:before|after)-pf[.]json", path.name):
                value = json.loads(read_safe(path))
                row["snapshots"].append({"file": path.name, "time_utc": value["time_utc"],
                                         **state_summary(value["states"])})
        result.append(row)
    return {"scope": "completed-mini-a5-readonly", "runs": result, "system_mutations": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--successful-run", action="store_true", help="Read only the pinned eight-phase run")
    args = parser.parse_args(argv)
    if not args.run:
        selected = (SUCCESSFUL_RUN,) if args.successful_run else RUNS
        print(json.dumps({"mode": "plan_only", "completed_runs": [row[0] for row in selected]}))
        return 0
    if os.geteuid() != 0:
        raise RuntimeError("Run the pinned export wrapper with sudo")
    value = collect_successful() if args.successful_run else collect()
    directory = Path(tempfile.mkdtemp(prefix="squirrelops-mini-a5-inspection.", dir="/private/var/tmp"))
    path = directory / "diagnostic.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True))
    path.chmod(0o644)
    directory.chmod(0o755)
    print("READ-ONLY EXPORT COMPLETE: " + str(path))
    print("No services, PF rules, references, addresses or original evidence changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
