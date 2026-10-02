"""Read-only inspection of one completed Mini run; never releases a PF reference."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess

BACKUP = Path("/Library/SquirrelOps/acceptance-backups/mini-relay-20260930.m06dh5r3")
PF = "/sbin/pfctl"


def read_private(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4 * 1024 * 1024):
        raise RuntimeError("Unsafe private evidence")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError("Evidence replaced")
        return stream.read(4 * 1024 * 1024 + 1).decode()


def sanitized(text):
    # PF reference values, including unrelated references, never leave this process.
    return re.sub(r"0[xX][0-9a-fA-F]+|[0-9]+", "[number]", text)[:8192]


def selected(record):
    command = record.get("command", [])
    return (command in ([PF, "-E"], [PF, "-s", "References"])
            or isinstance(command, list) and len(command) == 3 and command[:2] == [PF, "-X"])


def summarize(record, token):
    command = record["command"]
    output = record.get("stdout", "") + record.get("stderr", "")
    pattern = r"(?<![0-9])" + re.escape(token) + r"(?![0-9])"
    return {"operation": " ".join(command[1:2] if command[1] == "-X" else command[1:]),
            "exit": record.get("exit"),
            "own_reference_decimal_match": bool(re.search(pattern, output)),
            "output_numbers_redacted": sanitized(output)}


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo on the Mini")
    for path in (BACKUP.parent.parent, BACKUP.parent, BACKUP):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("Unsafe evidence directory")
    token = read_private(BACKUP / "pf-reference-token").strip()
    if not re.fullmatch(r"[0-9]{1,20}", token):
        raise RuntimeError("Unexpected private reference format")
    files = sorted(BACKUP.glob("command-*.json"), key=lambda p: int(p.stem.split("-")[1]))
    if len(files) > 30000:
        raise RuntimeError("Evidence count exceeds inspection bound")
    history = []
    release_records = 0
    for path in files:
        record = json.loads(read_private(path))
        if selected(record):
            history.append({"record": path.name, **summarize(record, token)})
            release_records += record["command"][:2] == [PF, "-X"]
    report = {"completed_release_call_records": release_records,
              "note": "Timed-out subprocesses may have no completed command record; absence is not retry authorization.",
              "recent_pf_records": history[-6:], "current": []}
    # Fixed read-only argv, never a command recovered from the evidence.
    for flags in (["-s", "info"], ["-s", "References"]):
        result = subprocess.run([PF, *flags], capture_output=True, text=True, timeout=10,
                                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
        report["current"].append(summarize({"command": [PF, *flags], "exit": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr}, token))
    print(json.dumps(report, indent=2))
    print("READ-ONLY CHECK COMPLETE. No reference, service, rule or data changes.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Do not print subprocess exceptions: they can include unredacted output.
        print("Read-only check stopped: " + type(error).__name__ + ". No system changes.")
        raise SystemExit(1)
