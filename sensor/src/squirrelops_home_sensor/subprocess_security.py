"""Resolve operating-system tools without trusting the service PATH."""

from __future__ import annotations

import os
from pathlib import Path

_TRUSTED_EXECUTABLE_PATHS: dict[str, tuple[str, ...]] = {
    "ifconfig": ("/sbin/ifconfig", "/usr/sbin/ifconfig"),
    "ip": ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"),
    "iptables-restore": ("/usr/sbin/iptables-restore", "/sbin/iptables-restore"),
    "iptables-save": ("/usr/sbin/iptables-save", "/sbin/iptables-save"),
    # nmap is the Linux service-scan path only; macOS uses the Swift helper's
    # TCP/banner probes. The Homebrew prefixes that used to be listed here are
    # macOS paths, owned by the installing admin rather than root, so they
    # could never satisfy the trust check below. Listing a path the policy must
    # reject is how "root-owned" stayed documented but unenforced.
    "nmap": ("/usr/bin/nmap", "/usr/sbin/nmap"),
    "scutil": ("/usr/sbin/scutil",),
}


def trusted_executable(name: str) -> str:
    """Return an absolute executable path from the fixed allowlist.

    Raises
    ------
    ValueError
        If ``name`` is not allow-listed.
    PermissionError
        If every allow-listed path that exists fails the trust check. Returning
        the first candidate in that case would hand back the exact untrusted
        binary the allowlist exists to reject, so this fails closed instead.
    """
    candidates = _TRUSTED_EXECUTABLE_PATHS.get(name)
    if candidates is None:
        raise ValueError(f"Executable is not allow-listed: {name!r}")

    present: list[str] = []
    for candidate in candidates:
        path = Path(candidate)
        if _is_trusted_executable(path):
            return str(path)
        if path.exists():
            present.append(candidate)

    if present:
        raise PermissionError(
            f"No trusted {name!r} executable: "
            f"{', '.join(present)} exist but are not root-owned, "
            "are group/other writable, or are not regular executable files"
        )

    # Nothing is installed. Return an absolute path so the caller's subprocess
    # reports FileNotFoundError for a genuinely absent optional tool and never
    # falls back to PATH. Mocked unit tests stay platform-independent.
    return candidates[0]


def _is_trusted_executable(path: Path) -> bool:
    """Require a root-owned executable with no group/other write access."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        path.is_file()
        and not path.is_symlink()
        and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0
        and os.access(path, os.X_OK)
    )
