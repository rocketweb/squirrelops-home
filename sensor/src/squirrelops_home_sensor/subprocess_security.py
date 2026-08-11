"""Resolve operating-system tools without trusting the service PATH."""

from __future__ import annotations

import os
from pathlib import Path

_TRUSTED_EXECUTABLE_PATHS: dict[str, tuple[str, ...]] = {
    "ifconfig": ("/sbin/ifconfig", "/usr/sbin/ifconfig"),
    "ip": ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"),
    "iptables-restore": ("/usr/sbin/iptables-restore", "/sbin/iptables-restore"),
    "iptables-save": ("/usr/sbin/iptables-save", "/sbin/iptables-save"),
    "nmap": ("/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"),
    "scutil": ("/usr/sbin/scutil",),
}


def trusted_executable(name: str) -> str:
    """Return an absolute executable path from the fixed allowlist."""
    candidates = _TRUSTED_EXECUTABLE_PATHS.get(name)
    if candidates is None:
        raise ValueError(f"Executable is not allow-listed: {name!r}")
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    # Preserve an absolute, fail-closed lookup even when an optional tool is
    # absent. The subprocess call will report FileNotFoundError without ever
    # falling back to PATH, and mocked unit tests remain platform-independent.
    return candidates[0]
