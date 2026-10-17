"""Bounded laptop-only protocol probes for the approved mini VIP.

No exploits, scanning outside the single VIP, credential spraying or host
configuration changes. Guest writes use a unique file and remove only that file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import time
import uuid

import pexpect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.directory.resolve()
    credentials = json.loads((directory / "login.json").read_text())
    ip = credentials["ip"]
    assert ip == "192.168.1.240" and credentials["username"] == "buildbot"
    password = credentials["password"]
    records = []

    def record(name, passed, **fields):
        value = {"name": name, "passed": passed, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}
        records.append(value)
        data = json.dumps(records, indent=2).replace(password, "[REDACTED]")
        (directory / "results.json").write_text(data + "\n")
        print(json.dumps(value).replace(password, "[REDACTED]"), flush=True)

    def run(name, arguments, *, secret=None, expected=(), failure=False):
        child = pexpect.spawn(arguments[0], arguments[1:], encoding="utf-8", timeout=20, echo=False)
        output = ""
        try:
            result = child.expect([r"(?i)password[^\r\n]*:", pexpect.EOF, pexpect.TIMEOUT])
            output += child.before
            if result == 0 and secret is not None:
                child.sendline(secret)
                result = child.expect([pexpect.EOF, pexpect.TIMEOUT])
                output += child.before
                if result == 1:
                    raise TimeoutError("client did not exit after authentication")
            elif result != 1:
                raise TimeoutError("unexpected prompt or client timeout")
            child.close()
            code = child.exitstatus
            passed = (code != 0 if failure else code == 0) and all(term in output for term in expected)
            record(name, passed, exit=code, output=output[-12000:])
            return passed
        except Exception as exc:
            record(name, False, error=type(exc).__name__, output=output[-4000:])
            return False
        finally:
            child.close(force=True)

    # Ports are from the root harness's live PF snapshot, not guessed ranges.
    reachable = {}
    for port in (22, 445, 50708, 50709, 50710, 50711, 50712, 5900):
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=3) as stream:
                stream.settimeout(3)
                source = stream.getsockname()
                banner = stream.recv(256).decode("ascii", "replace") if port == 22 else ""
                reachable[port] = True
                record(f"tcp_{port}", port in (22, 445), connected=True, source=source,
                       banner=banner, seconds=round(time.monotonic() - start, 3))
        except OSError as exc:
            reachable[port] = False
            record(f"tcp_{port}", port not in (22, 445), connected=False,
                   error=type(exc).__name__, seconds=round(time.monotonic() - start, 3))
    if not reachable.get(22) or not reachable.get(445):
        record("protocol_gate", False, reason="Advertised SSH/SMB unavailable; no login or write attempted")
        return

    options = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=accept-new",
               "-o", f"UserKnownHostsFile={directory / 'guest_known_hosts'}", "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "UpdateHostKeys=no", "-o", "IdentityAgent=none", "-o", "PubkeyAuthentication=no",
               "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1",
               "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1"]
    ssh = ["/usr/bin/ssh", *options, f"buildbot@{ip}"]
    wrong = "SquirrelOps-deliberately-wrong-" + uuid.uuid4().hex
    run("ssh_wrong_password", [*ssh, "whoami"], secret=wrong, failure=True, expected=("Permission denied",))
    identity = run("ssh_persona", [*ssh, "whoami; id; hostname; uname -a; pwd; ls /Users/buildbot/Projects/fieldkit-ios"],
                   secret=password, expected=("buildbot", "Darwin", "README.md"))
    if not identity:
        record("file_write_gate", False, reason="Guest persona not verified; no file writes attempted")
        return

    token = "squirrelops-mini-acceptance-" + uuid.uuid4().hex + ".txt"
    upload = directory / "upload.txt"
    upload.write_text("Synthetic SquirrelOps mini protocol acceptance\n" + token + "\n")
    remote_file = "/Users/buildbot/Builds/" + token
    download = directory / "sftp-download.txt"
    readme = directory / "sftp-readme.md"
    child = pexpect.spawn("/usr/bin/sftp", [*options, f"buildbot@{ip}"], encoding="utf-8", timeout=20, echo=False)
    transcript = ""
    wrote = False
    try:
        child.expect(r"(?i)password[^\r\n]*:")
        child.sendline(password)
        child.expect("sftp> ")
        for command in ("pwd", "ls /Users/buildbot/Projects/fieldkit-ios",
                        f"get /Users/buildbot/Projects/fieldkit-ios/README.md {readme}",
                        f"put {upload} {remote_file}", f"get {remote_file} {download}", f"rm {remote_file}"):
            child.sendline(command)
            child.expect("sftp> ")
            transcript += child.before
            if command.startswith("put "):
                wrote = True
            if command.startswith("rm ") and "Failure" not in child.before and "Permission denied" not in child.before:
                wrote = False
        child.sendline("bye")
        child.expect(pexpect.EOF)
        child.close()
        passed = (child.exitstatus == 0 and download.read_bytes() == upload.read_bytes()
                  and "FieldKit" in readme.read_text() and not wrote)
        record("sftp_read_write_delete", passed, artifact=token, sha256=hashlib.sha256(download.read_bytes()).hexdigest(),
               output=transcript[-8000:])
    except Exception as exc:
        record("sftp_read_write_delete", False, error=type(exc).__name__, artifact=token,
               cleanup_may_be_needed=wrote, output=transcript[-8000:])
    finally:
        child.close(force=True)

    smb = ["/usr/bin/smbclient", "-m", "SMB3", "--option=client min protocol=SMB2", "-t", "5"]
    run("smb_anonymous_share_list", [*smb, "-L", "//" + ip, "-N"], expected=("Engineering", "Builds"))
    run("smb_wrong_password", [*smb, f"//{ip}/Engineering", "-U", "buildbot", "-c", "ls"],
        secret=wrong, failure=True, expected=("NT_STATUS_LOGON_FAILURE",))
    smb_readme = directory / "smb-readme.md"
    smb_download = directory / "smb-download.txt"
    smb_commands = (f"ls; cd fieldkit-ios; get README.md {smb_readme}; put {upload} {token}; "
                    f"get {token} {smb_download}; del {token}")
    run("smb_read_write_delete_client", [*smb, f"//{ip}/Engineering", "-U", "buildbot", "-c", smb_commands],
        secret=password)
    passed = (smb_download.exists() and smb_download.read_bytes() == upload.read_bytes()
              and smb_readme.exists() and "FieldKit" in smb_readme.read_text())
    record("smb_file_parity", passed, artifact=token,
           sha256=hashlib.sha256(smb_download.read_bytes()).hexdigest() if smb_download.exists() else None)
    run("guest_test_files_absent", [*ssh, f"test ! -e {remote_file} && test ! -e /Users/buildbot/Projects/fieldkit-ios/{token} && echo TEST_FILES_ABSENT"],
        secret=password, expected=("TEST_FILES_ABSENT",))


if __name__ == "__main__":
    main()
