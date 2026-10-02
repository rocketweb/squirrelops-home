"""Resolver acceptance: pinned Mini, one private laptop run, no traffic by default.

Derived from mini_upgrade_client.py. Historical clients stay unchanged.
"""
import argparse
import datetime
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import time
import uuid

PACKAGE_SHA = "47774088cd9eadc5aaddf38949e00a8b8f6eeb56c2192a5a72830d06d84a8aec"
VIPS = {"192.168.1.240"}
SCOPE = "mini-guest-resolver-240"
SOURCE = "192.168.1.7"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_inputs(endpoints, login, status, now):
    require(status.get("test_scope") == SCOPE and status.get("test_vips") == ["192.168.1.240"]
            and status.get("boot_seconds") == 1790777754
            and status.get("configuration_unchanged") is True and status.get("config_change_verified") is True,
            "Wrong resolver server scope, boot or configuration")
    ip = endpoints.get("guest_ip")
    require(ip in VIPS and login.get("ip") == ip and login.get("username") == "buildbot",
            "Unapproved guest identity")
    require(isinstance(login.get("password"), str) and re.fullmatch(r"Juniper![0-9]{6}", login["password"]),
            "Unexpected synthetic credential format")
    require(status.get("phase") == "ready_for_tests" and status.get("package_sha256") == PACKAGE_SHA
            and status.get("sensor_uid") == 309 and status.get("remaining_seconds", 0) >= 600,
            "Server is not ready for this test")
    stamp = datetime.datetime.strptime(status["time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
    require(-5 <= now - stamp <= 30, "Stale server readiness snapshot")
    mappings = endpoints.get("mappings")
    require(isinstance(mappings, list) and 5 <= len(mappings) <= 20, "Unbounded endpoint inventory")
    seen = set()
    for row in mappings:
        require(row.get("ip") in VIPS and type(row.get("port")) is int and 1 <= row["port"] <= 65535
                and type(row.get("backend")) is int and 1024 <= row["backend"] <= 65535,
                "Invalid endpoint mapping")
        key = (row["ip"], row["port"])
        require(key not in seen, "Duplicate advertised endpoint")
        seen.add(key)
    require(all((ip, port) in seen for port in (22, 445, 1234, 11434, 8765)), "Incomplete guest endpoints")
    require(len(mappings) == 5 and len({row["backend"] for row in mappings}) == 5,
            "Only five distinct resolver mappings are approved")
    return ip


def smb_arguments(ip):
    return ["/usr/bin/smbclient", "-s", "/dev/null", "--use-kerberos=off",
            "-I", ip, "-p", "445", "-m", "SMB3", "--option=client min protocol=SMB2", "-t", "5"]


def anonymous_arguments(ip):
    return [*smb_arguments(ip), "-L", "//" + ip, "-N", "-U", "%"]


def timing_ok(name, elapsed):
    # Keep the normal protocol gate: a delayed success is still a resolver failure.
    return name != "smb_share_discovery" or 0 <= elapsed <= 5.0


def banner_probe(ip):
    row = {"connected": False, "stage": "connect"}
    try:
        with socket.create_connection((ip, 22), timeout=5, source_address=(SOURCE, 0)) as stream:
            row.update(connected=True, stage="banner")
            response = stream.recv(255)
            row.update(passed=response.startswith(b"SSH-2.0-"), response_bytes=len(response),
                       banner=response.decode("ascii", "replace"))
    except OSError as exc:
        row.update(passed=False, error=type(exc).__name__)
    return row


def http_payload_ok(port, body):
    if not isinstance(body, dict):
        return False
    if port == 1234:
        models = body.get("data")
        return isinstance(models, list) and bool(models) and all(isinstance(m, dict) and m.get("id") for m in models)
    if port == 11434:
        models = body.get("models")
        return isinstance(models, list) and bool(models) and all(isinstance(m, dict) and m.get("name") for m in models)
    result = body.get("result")
    return (port == 8765 and body.get("id") == 1 and isinstance(result, dict)
            and isinstance(result.get("tools"), list) and bool(result["tools"]))


def safe_input(directory, name):
    path = directory / name
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o077 and info.st_size <= 65536, "Unsafe private client input")
    return json.loads(path.read_text())


def run(directory):
    import pexpect
    os.umask(0o077)
    require(directory.parent == Path("/root") and re.fullmatch(r"squirrelops-mini-resolver-client\.[A-Za-z0-9_-]+", directory.name),
            "Wrong client staging directory")
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            "Client staging must be root-private")
    endpoints, login, status = (safe_input(directory, name) for name in ("endpoints.json", "login.json", "status.json"))
    ip = validate_inputs(endpoints, login, status, time.time())
    password = login["password"]
    route = subprocess.run(["/usr/sbin/ip", "-j", "route", "get", ip], check=True, capture_output=True, text=True, timeout=3)
    routes = json.loads(route.stdout)
    require(len(routes) == 1 and routes[0].get("dev") == "wlp0s20f3" and routes[0].get("prefsrc") == SOURCE,
            "Laptop source or route changed")
    # No retry/reset switch. Retain evidence if a partial test needs review.
    with (directory / "results.jsonl").open("x") as output:
        failures = []
        def record(name, passed, **fields):
            row = {"name": name, "passed": bool(passed), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}
            line = json.dumps(row).replace(password, "[REDACTED]")
            output.write(line + "\n")
            output.flush()
            print(line, flush=True)
            if not passed:
                failures.append(name)
            return bool(passed)

        def client(name, arguments, secret=None, expected=(), failure=False):
            started = time.monotonic()
            child = pexpect.spawn(arguments[0], arguments[1:], encoding="utf-8", timeout=20, echo=False)
            transcript = ""
            try:
                outcome = child.expect([r"(?i)password[^\r\n]*:", pexpect.EOF, pexpect.TIMEOUT])
                transcript += child.before
                if outcome == 0 and secret is not None:
                    child.sendline(secret)
                    outcome = child.expect([pexpect.EOF, pexpect.TIMEOUT])
                    transcript += child.before
                    require(outcome == 0, "Client did not exit after one password")
                else:
                    require(outcome == 1, "Unexpected client prompt or timeout")
                child.close()
                code = child.exitstatus
                passed = (code is not None and code != 0 if failure else code == 0) and all(term in transcript for term in expected)
                elapsed = time.monotonic() - started
                return record(name, passed and timing_ok(name, elapsed), exit=code,
                              elapsed_seconds=round(elapsed, 3), output=transcript[-8000:])
            except Exception as exc:
                return record(name, False, error=type(exc).__name__, output=transcript[-4000:])
            finally:
                child.close(force=True)

        banner = banner_probe(ip)
        ssh_ok = record("ssh_banner", **banner)
        smb = smb_arguments(ip)
        smb_ok = client("smb_share_discovery", anonymous_arguments(ip),
                        expected=("Engineering", "Builds", "Time Machine Backups", "IPC$"))
        http_ok = True
        for port, path in ((1234, "/v1/models"), (11434, "/api/tags"), (8765, "/mcp")):
            connection = http.client.HTTPConnection(ip, port, timeout=5, source_address=(SOURCE, 0))
            try:
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) if port == 8765 else None
                connection.request("POST" if body else "GET", path, body=body,
                                   headers={"Content-Type": "application/json"} if body else {})
                response = connection.getresponse()
                data = response.read(131073)
                valid = response.status == 200 and len(data) <= 131072 and http_payload_ok(port, json.loads(data))
                http_ok = record(f"http_{port}", valid, status=response.status, response_bytes=len(data)) and http_ok
            except Exception as exc:
                http_ok = record(f"http_{port}", False, error=type(exc).__name__) and http_ok
            finally:
                connection.close()
        if not (ssh_ok and smb_ok and http_ok):
            record("protocol_gate", False, reason="No authentication or file operations attempted")
            return 1

        backend_targets = {(m["ip"], m["backend"]) for m in endpoints["mappings"]}
        backend_targets.add((ip, 5900))
        contained = True
        for address, port in sorted(backend_targets):
            denied = False
            reason = "connected"
            try:
                with socket.create_connection((address, port), timeout=3, source_address=(SOURCE, 0)):
                    pass
            except OSError as exc:
                denied = isinstance(exc, (TimeoutError, ConnectionRefusedError)) or exc.errno == errno.EHOSTUNREACH
                reason = type(exc).__name__
            contained = record("private_or_native_port_denied", denied, ip=address, port=port, result=reason) and contained
        if not contained:
            record("containment_gate", False, reason="No authentication or file operations attempted")
            return 1

        options = ["-F", "/dev/null", "-b", SOURCE, "-o", "StrictHostKeyChecking=accept-new",
                   "-o", f"UserKnownHostsFile={directory / 'guest_known_hosts'}", "-o", "GlobalKnownHostsFile=/dev/null",
                   "-o", "UpdateHostKeys=no", "-o", "IdentityAgent=none", "-o", "PubkeyAuthentication=no",
                   "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1",
                   "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1"]
        ssh = ["/usr/bin/ssh", *options, "buildbot@" + ip]
        wrong = "SquirrelOps-deliberately-wrong-" + uuid.uuid4().hex
        wrong_ssh = client("ssh_wrong_password", [*ssh, "whoami"], secret=wrong, expected=("Permission denied",), failure=True)
        persona = client("ssh_persona", [*ssh, "whoami; id; hostname; uname -a; pwd; ls /Users/buildbot/Projects/fieldkit-ios"],
                         secret=password, expected=("buildbot", "Darwin", "README.md"))
        wrong_smb = client("smb_wrong_password", [*smb, f"//{ip}/Engineering", "-U", "buildbot", "-c", "ls"],
                           secret=wrong, expected=("NT_STATUS_LOGON_FAILURE",), failure=True)
        if not (wrong_ssh and persona and wrong_smb):
            record("file_write_gate", False, reason="Authentication/persona result unexpected; no writes attempted")
            return 1

        token = "squirrelops-mini-acceptance-" + uuid.uuid4().hex + ".txt"
        upload = directory / "upload.txt"
        upload.write_text("Synthetic SquirrelOps protocol acceptance\n" + token + "\n")
        remote_file = "/Users/buildbot/Builds/" + token
        download = directory / "sftp-download.txt"
        readme = directory / "sftp-readme.md"
        # sftp uses -b for batch files, so express binding through its SSH -o option.
        sftp_options = ["-o", "BindAddress=" + SOURCE, *options[:2], *options[4:]]
        child = pexpect.spawn("/usr/bin/sftp", [*sftp_options, "buildbot@" + ip], encoding="utf-8", timeout=20, echo=False)
        pending_cleanup = False
        transcript = ""
        try:
            child.expect(r"(?i)password[^\r\n]*:")
            child.sendline(password)
            child.expect("sftp> ")
            for command in (f"get /Users/buildbot/Projects/fieldkit-ios/README.md {readme}",
                            f"put {upload} {remote_file}", f"get {remote_file} {download}", f"rm {remote_file}"):
                if command.startswith("put "):
                    pending_cleanup = True  # Includes a timeout after a successful write.
                child.sendline(command)
                child.expect("sftp> ")
                transcript += child.before
                require(not any(error in child.before for error in ("Failure", "Permission denied", "No such file", "Couldn't")),
                        "SFTP operation failed")
            child.sendline(f"ls {remote_file}")
            child.expect("sftp> ")
            require("No such file" in child.before or "not found" in child.before, "SFTP delete not verified")
            pending_cleanup = False
            child.sendline("bye")
            child.expect(pexpect.EOF)
            child.close()
            record("sftp_read_write_delete", child.exitstatus == 0 and download.read_bytes() == upload.read_bytes()
                   and "FieldKit" in readme.read_text(), artifact=token, cleanup_may_be_needed=pending_cleanup,
                   sha256=hashlib.sha256(download.read_bytes()).hexdigest())
        except Exception as exc:
            record("sftp_read_write_delete", False, error=type(exc).__name__, artifact=token,
                   cleanup_may_be_needed=pending_cleanup, output=transcript[-4000:])
        finally:
            child.close(force=True)

        smb_token = "smb-" + token
        smb_readme, smb_download = directory / "smb-readme.md", directory / "smb-download.txt"
        commands = (f"ls; cd fieldkit-ios; get README.md {smb_readme}; put {upload} {smb_token}; "
                    f"get {smb_token} {smb_download}; del {smb_token}; ls {smb_token}")
        deleted = client("smb_read_write_delete", [*smb, f"//{ip}/Engineering", "-U", "buildbot", "-c", commands],
                         secret=password, expected=("NT_STATUS_NO_SUCH_FILE",), failure=True)
        # smbclient returns failure for the final deliberate missing-file query.
        parity = (smb_readme.exists() and "FieldKit" in smb_readme.read_text()
                  and smb_download.exists() and smb_download.read_bytes() == upload.read_bytes())
        record("smb_file_parity", parity and deleted, artifact=smb_token, cleanup_may_be_needed=not deleted)
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.run is None:
        print("PLAN ONLY: approved mini guest, fresh readiness, one-shot results; no network activity.")
        return 0
    return run(args.run)


if __name__ == "__main__":
    raise SystemExit(main())
