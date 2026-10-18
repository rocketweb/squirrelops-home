"""Pin the guest-side half of login attribution.

The runtime chooses each relay's TCP source port and the guest shim binds it,
so ``sshd``/``smbd`` auth lines name the peer exactly. That contract lives in
shell and daemon configuration the Python and Swift tests cannot execute, so
it is pinned here instead of being rediscovered on the next guest rebuild.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOTFS = REPO_ROOT / "guest" / "studio-mini" / "rootfs"


def _read(relative: str) -> str:
    return (ROOTFS / relative).read_text(encoding="utf-8")


def test_relay_shim_reads_one_preamble_line_then_binds_the_host_chosen_port() -> None:
    shim = _read("usr/local/bin/relay-shim")
    assert shim.startswith("#!/bin/sh\n")
    assert "IFS= read -r port" in shim
    # Digits only, inside the port range, or no relay at all.
    assert re.search(r'case "\$port" in\s*""\|\*\[!0-9\]\*\) exit 1', shim)
    assert '[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || exit 1' in shim
    assert 'exec socat STDIO "TCP:127.0.0.1:$target,sourceport=$port,reuseaddr"' in shim
    # Nothing else may read the client's bytes before socat does.
    assert shim.count("read ") == 1


def test_init_relays_through_the_shim_and_publishes_the_auth_ring() -> None:
    init = _read("sbin/init")
    assert "syslogd -C256" in init, "auth lines live in the memory ring, not a file"
    assert "sshd -D -e" not in init, "-e would send auth logs to the console, not syslog"
    assert "/usr/sbin/sshd -D &" in init
    assert 'EXEC:"/usr/local/bin/relay-shim 22"' in init
    assert 'EXEC:"/usr/local/bin/relay-shim 445"' in init
    assert "TCP:127.0.0.1:22 &" not in init and "TCP:127.0.0.1:445 &" not in init
    channel = re.search(
        r'socat VSOCK-LISTEN:10514,reuseaddr,fork,max-children=(\d+) EXEC:"logread -f" &\n'
        r"auth_channel_pid=\$!",
        init,
    )
    assert channel, "auth channel listener missing or not supervised"
    # Bidirectional on purpose: with -U socat never reads the vsock side and
    # cannot notice the host leaving, so a stale logread would hold the slot.
    assert "socat -U VSOCK-LISTEN:10514" not in init
    assert "logread -F" not in init, "-F replays the ring and would re-emit every earlier login"
    assert '"$auth_channel_pid"' in init.split("while kill -0", 1)[1]


def test_sshd_logs_verbosely_to_syslog() -> None:
    sshd = _read("etc/ssh/sshd_config")
    assert re.search(r"^LogLevel VERBOSE$", sshd, re.M)
    assert re.search(r"^SyslogFacility AUTH$", sshd, re.M)


def test_samba_logs_auth_audit_to_syslog_only() -> None:
    smb = _read("etc/samba/smb.conf")
    assert re.search(r"^\s*logging = syslog@3$", smb, re.M)
    assert re.search(r"^\s*log level = 1 auth_audit:3$", smb, re.M)
    assert "log file" not in smb and "max log size" not in smb


def test_dockerfile_installs_the_shim_executable() -> None:
    dockerfile = (REPO_ROOT / "guest" / "studio-mini" / "Dockerfile").read_text(encoding="utf-8")
    assert "chmod 0755 /sbin/init /usr/local/bin/macos-shim /usr/local/bin/relay-shim" in dockerfile


def test_swift_runtime_and_guest_agree_on_the_channel_port_and_pool() -> None:
    channel = (
        REPO_ROOT / "app/Sources/SquirrelOpsDeceptionGuest/GuestAuthenticationChannel.swift"
    ).read_text(encoding="utf-8")
    table = (
        REPO_ROOT / "app/Sources/SquirrelOpsDeceptionGuest/RelayAttribution.swift"
    ).read_text(encoding="utf-8")
    assert "static let guestVSOCKPort: UInt32 = 10_514" in channel
    # The shim accepts 1024..65535; the host pool must sit inside it and clear
    # of every guest listener and ephemeral range socat might otherwise use.
    pool = re.search(r"range: ClosedRange<UInt16> = (\d[\d_]*)\.\.\.(\d[\d_]*)", table)
    assert pool
    low, high = (int(value.replace("_", "")) for value in pool.groups())
    assert 1024 <= low < high <= 65535
    assert high < 32768, "stay below Linux's default ephemeral range to avoid bind collisions"


def test_relay_listeners_queue_a_full_burst_before_accept() -> None:
    """#66: the host admits up to 16 relays and connects them concurrently.

    socat's default listen backlog is 5, and Linux vsock resets a connect
    that arrives while the accept queue is full (the host sees ECONNRESET,
    code 54). Each relay listener must queue the whole admission ceiling.
    """
    init = _read("sbin/init")
    ceiling = 16
    for port in (10022, 10445):
        listener = re.search(
            rf"socat VSOCK-LISTEN:{port},(?P<options>[^ ]+) EXEC:", init
        )
        assert listener, f"relay listener on {port} missing"
        options = dict(
            option.split("=", 1) if "=" in option else (option, "")
            for option in listener.group("options").split(",")
        )
        assert options.get("max-children") == str(ceiling)
        assert options.get("backlog") == str(ceiling), (
            f"listener {port} must queue {ceiling} pending connects; a burst "
            "larger than the default backlog is reset by the guest kernel"
        )
