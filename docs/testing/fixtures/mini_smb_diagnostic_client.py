"""One credential-free SMB trace of the approved Mini guest. Plan-only by default."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

SCOPE = "mini-smb-only-diagnostic-240"
PACKAGE_SHA = "3d18ebac2fae343fd9c710ad2a187ec3f4bf6e4fd9cfda3bc3654214db7c67ea"
VIP, SOURCE = "192.168.1.240", "192.168.1.7"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_inputs(endpoints, status, now):
    require(status.get("phase") == "ready_for_tests" and status.get("diagnostic_scope") == SCOPE
            and status.get("test_scope") == "mini-relay-diagnostics-240"
            and status.get("test_vips") == [VIP] and status.get("boot_seconds") == 1790777754
            and status.get("sensor_uid") == 309 and status.get("package_sha256") == PACKAGE_SHA
            and status.get("configuration_unchanged") is True and status.get("config_change_verified") is True
            and type(status.get("remaining_seconds")) is int and status["remaining_seconds"] >= 600,
            "Wrong or expired SMB diagnostic window")
    stamp = datetime.datetime.strptime(status["time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
    require(-5 <= now - stamp <= 30, "Stale readiness")
    rows = endpoints.get("mappings")
    require(endpoints.get("guest_ip") == VIP and isinstance(rows, list) and len(rows) == 5,
            "Wrong endpoint inventory")
    require(all(isinstance(row, dict) and row.get("ip") == VIP and type(row.get("port")) is int
                and type(row.get("backend")) is int and 1024 <= row["backend"] <= 65535 for row in rows)
            and {row["port"] for row in rows} == {22, 445, 11434, 1234, 8765}
            and len({row["backend"] for row in rows}) == 5, "Unexpected mapping")


def command():
    # Explicit null session, no cached credentials/config, no fallback to port 139.
    return ["/usr/bin/smbclient", "--configfile=/dev/null", "--use-kerberos=off",
            "-m", "SMB3", "--option=client min protocol=SMB2", "-t", "5", "-p", "445",
            "-I", VIP, "-L", "//" + VIP, "-U", "%", "-N", "-d", "3", "--debug-stdout"]


def classify(text):
    """Fixed vocabulary only; never echo arbitrary server/debug text publicly."""
    result = []
    checks = (("Connecting to 192.168.1.240 at port 445", "connect_attempt"),
              ("Anonymous login successful", "anonymous_session"),
              ("session setup failed", "session_setup_failed"),
              ("protocol negotiation failed", "negotiation_failed"),
              ("tree connect failed", "tree_connect_failed"),
              ("Error returning browse list", "share_listing_failed"),
              ("Sharename", "share_listing_header"), ("SMB1 disabled", "smb1_disabled"))
    for literal, stage in checks:
        if literal in text:
            result.append(dict(stage=stage))
    for value in sorted(set(re.findall(r"\bNT_STATUS_[A-Z0-9_]{1,64}\b", text))):
        result.append(dict(stage="status", value=value))
    for value in sorted(set(re.findall(r"negotiated dialect\[(SMB[0-9_]{1,8})\]", text))):
        result.append(dict(stage="dialect", value=value))
    for name in ("Builds", "Engineering", "Time Machine Backups", "IPC$"):
        if re.search(r"^\s*" + re.escape(name) + r"\s+(?:Disk|IPC)\b", text, re.M):
            result.append(dict(stage="share_seen", value=name))
    return result


def capture(args, raw, emit, *, duration=45, byte_limit=262144):
    start = time.monotonic()
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    total, buffered, seen = 0, "", set()
    timed_out = output_limited = False
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)

    def accept_text(text, elapsed):
        nonlocal buffered
        raw.write(json.dumps(dict(elapsed_seconds=round(elapsed, 3), text=text)) + "\n")
        raw.flush()
        buffered += text
        for event in classify(buffered):
            key = json.dumps(event, sort_keys=True)
            if key not in seen:
                seen.add(key)
                emit(dict(elapsed_seconds=round(elapsed, 3), **event))
        # Keep an incomplete final line, not all attacker-provided output.
        buffered = buffered.rsplit("\n", 1)[-1][-8192:]

    try:
        while True:
            elapsed = time.monotonic() - start
            if elapsed >= duration:
                timed_out = True
                break
            if not selector.select(min(0.1, duration - elapsed)):
                continue
            chunk = os.read(process.stdout.fileno(), min(4096, byte_limit - total + 1))
            if not chunk:
                # EOF can precede process exit. Preserve the real result rather
                # than racing a successful client with our cleanup signal.
                try:
                    process.wait(timeout=max(0, min(1, duration - (time.monotonic() - start))))
                except subprocess.TimeoutExpired:
                    pass
                break
            take = chunk[:byte_limit - total]
            total += len(take)
            accept_text(take.decode("utf-8", "replace"), time.monotonic() - start)
            if len(take) != len(chunk) or total >= byte_limit:
                output_limited = True
                break
    finally:
        selector.close()
        # This group contains only the diagnostic child created above.
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        process.stdout.close()
    return dict(exit=process.returncode, timed_out=timed_out, output_limited=output_limited,
                captured_bytes=total, elapsed_seconds=round(time.monotonic() - start, 3))


def exclusive_result(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "w")


def safe_json(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= 65536, "Unsafe private input")
    return json.loads(path.read_text())


def run(directory):
    os.umask(0o077)
    require(directory.parent == Path("/root")
            and re.fullmatch(r"squirrelops-mini-smb-client\.[A-Za-z0-9_-]+", directory.name), "Wrong staging")
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, "Unsafe staging")
    endpoints, status = (safe_json(directory / name) for name in ("endpoints.json", "status.json"))
    validate_inputs(endpoints, status, time.time())
    route = subprocess.run(["/usr/sbin/ip", "-j", "route", "get", VIP], check=True,
                           capture_output=True, text=True, timeout=3)
    rows = json.loads(route.stdout)
    require(len(rows) == 1 and rows[0].get("dev") == "wlp0s20f3" and rows[0].get("prefsrc") == SOURCE,
            "Laptop route changed")
    with exclusive_result(directory / "results.jsonl") as output:
        events = []

        def record(row):
            row = dict(utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **row)
            output.write(json.dumps(row) + "\n")
            output.flush()
            print(json.dumps(row), flush=True)
            events.append(row)

        record(dict(stage="diagnostic_started", target=VIP, port=445, max_seconds=45,
                    credentials=False, file_operations=False, anonymous=True))
        raw_path = directory / "private-debug.jsonl"
        with exclusive_result(raw_path) as raw:
            result = capture(command(), raw, record)
        shares = {event.get("value") for event in events if event.get("stage") == "share_seen"}
        complete = result["exit"] == 0 and {"Engineering", "Builds"} <= shares and not result["timed_out"]
        record(dict(stage="diagnostic_finished", listing_complete=complete,
                    raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(), **result))
    return 0 if complete else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print(json.dumps(dict(mode="plan_only", diagnostic_scope=SCOPE, target=VIP, port=445,
                              client_invocations=1, max_seconds=45, credentials=False,
                              file_operations=False, anonymous=True)))
        return 0
    return run(args.run)


if __name__ == "__main__":
    raise SystemExit(main())
