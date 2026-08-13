"""Resolve operating-system tools without trusting the service PATH."""

from __future__ import annotations

import os
import stat
from pathlib import Path

# Only these owners may control an executable the sensor runs. Named so the
# policy is patchable in tests that build a real symlink chain under a
# temporary directory owned by the test user.
_TRUSTED_UIDS: frozenset[int] = frozenset({0})

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
            f"No trusted {name!r} executable: {', '.join(present)} exist, but "
            "the resolved binary or a directory on its path is not root-owned, "
            "is group/other writable, or is not a regular executable file"
        )

    # Nothing is installed. Return an absolute path so the caller's subprocess
    # reports FileNotFoundError for a genuinely absent optional tool and never
    # falls back to PATH. Mocked unit tests stay platform-independent.
    return candidates[0]


def _is_trusted_directory(path: Path) -> bool:
    """Whether only a trusted uid can create or replace names in ``path``."""
    try:
        # Follow symlinks deliberately. On a usrmerge system /sbin is a link to
        # /usr/sbin, and the real directory is what governs write access.
        metadata = path.stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid in _TRUSTED_UIDS
        and metadata.st_mode & 0o022 == 0
    )


def _is_trusted_executable(path: Path) -> bool:
    """Whether no untrusted user can change what running ``path`` executes.

    Rejecting symlinks outright was wrong. Debian and Ubuntu route every
    iptables tool through ``/etc/alternatives``, so the normal packaged layout
    is a symlink chain and the check failed on the one platform that uses
    these binaries. Refusing the standard layout is not a security property,
    it just moved the whole allowlist onto the unvalidated fallback path.

    What actually matters is who can swap the target. A symlink's own mode is
    meaningless on Linux, and its ownership is not the control either: writing
    a name into a directory requires write permission on that directory. So
    this resolves the chain, checks the real executable, and then checks every
    directory along both the literal and resolved paths.
    """
    if not path.is_absolute():
        return False
    try:
        resolved = Path(os.path.realpath(path, strict=True))
        metadata = resolved.stat()
    except OSError:
        return False

    if not stat.S_ISREG(metadata.st_mode):
        return False
    if metadata.st_uid not in _TRUSTED_UIDS:
        return False
    if metadata.st_mode & 0o022:
        return False
    if not os.access(resolved, os.X_OK):
        return False

    return all(
        _is_trusted_directory(ancestor)
        for ancestor in (*path.parents, *resolved.parents)
    )
