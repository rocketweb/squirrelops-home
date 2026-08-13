from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from squirrelops_home_sensor import subprocess_security
from squirrelops_home_sensor.subprocess_security import trusted_executable


@pytest.fixture
def trusted_tree():
    """A fixture tree whose ancestors already satisfy the directory rule.

    Not ``tmp_path``. On Linux that lives under ``/tmp``, which is mode 1777,
    so every ancestor check fails and nothing below it can ever be trusted.
    The rule is right to refuse a world-writable directory, so the fixture
    moves rather than the rule loosening to accommodate it. macOS hid this:
    its per-user temp directory is mode 700, so these passed locally and
    failed on the runner.

    That mattered beyond the accept cases. Under ``/tmp`` every rejection test
    would pass no matter what the check did, because the ancestor was already
    disqualifying. A negative test that cannot fail is not a test.

    Trusting the test user is the one concession: tests cannot create
    root-owned files. Root stays trusted because the ancestors here are real
    system directories.
    """
    try:
        base = Path(tempfile.mkdtemp(dir=Path.home(), prefix=".squirrelops-test-"))
    except OSError as exc:
        pytest.skip(f"cannot create a fixture tree under HOME: {exc}")
    base.chmod(0o755)
    try:
        with patch.object(
            subprocess_security, "_TRUSTED_UIDS", frozenset({0, os.getuid()})
        ):
            untrusted = [
                str(parent)
                for parent in (base, *base.parents)
                if not subprocess_security._is_trusted_directory(parent)
            ]
            if untrusted:
                pytest.skip(
                    "no trusted directory chain available here: "
                    + ", ".join(untrusted)
                )
            yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _executable(path: Path, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(mode)
    return path


def test_the_fixture_root_is_itself_trusted(trusted_tree: Path) -> None:
    """Guard for every rejection test below.

    If the fixture root were untrusted, each of those would pass without
    exercising the condition it names.
    """
    accepted = _executable(trusted_tree / "usr" / "sbin" / "ip")
    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(accepted),)}
    ):
        assert trusted_executable("ip") == str(accepted)


def test_rejects_unknown_executable_names() -> None:
    with pytest.raises(ValueError, match="not allow-listed"):
        trusted_executable("attacker-tool")


def test_returns_an_absolute_path_for_an_allow_listed_name() -> None:
    """Smoke test on the real host, tolerant of how it packages its tools.

    Whether this machine ships a trustworthy copy is not the assertion. Both
    outcomes are correct: a resolved absolute path, or failing closed. Coupling
    this to host packaging is what made CI fail on a runner whose iptables is
    installed through ``/etc/alternatives``.
    """
    name = "scutil" if os.uname().sysname == "Darwin" else "ip"
    try:
        resolved = trusted_executable(name)
    except PermissionError:
        return
    assert Path(resolved).is_absolute()


def test_accepts_a_symlink_chain_like_debian_alternatives(trusted_tree: Path) -> None:
    """The packaged Linux layout must pass.

    On Debian and Ubuntu ``/usr/sbin/iptables-restore`` is a symlink into
    ``/etc/alternatives``, which points at ``xtables-nft-multi``. Rejecting
    symlinks outright failed on the only platform that runs these binaries.
    """
    sbin = trusted_tree / "usr" / "sbin"
    alternatives = trusted_tree / "etc" / "alternatives"
    alternatives.mkdir(parents=True)
    real = _executable(sbin / "xtables-nft-multi")

    (alternatives / "iptables-restore").symlink_to(real)
    link = sbin / "iptables-restore"
    link.symlink_to(alternatives / "iptables-restore")

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"iptables-restore": (str(link),)},
    ):
        # The stable admin-managed name is returned, not the chain target.
        assert trusted_executable("iptables-restore") == str(link)


def test_rejects_a_chain_whose_target_is_group_writable(trusted_tree: Path) -> None:
    real = _executable(trusted_tree / "usr" / "sbin" / "tool", mode=0o775)
    link = trusted_tree / "usr" / "sbin" / "ip"
    link.symlink_to(real)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(link),)}
    ):
        with pytest.raises(PermissionError, match="No trusted 'ip' executable"):
            trusted_executable("ip")


def test_rejects_a_binary_in_a_world_writable_directory(trusted_tree: Path) -> None:
    """Directory write permission is what lets an attacker swap the name."""
    loose = trusted_tree / "loose"
    _executable(loose / "ip")
    loose.chmod(0o777)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"ip": (str(loose / "ip"),)},
    ):
        with pytest.raises(PermissionError, match="No trusted 'ip' executable"):
            trusted_executable("ip")


def test_rejects_a_symlink_that_escapes_into_a_writable_directory(
    trusted_tree: Path,
) -> None:
    """A trusted-looking name must not launder an untrusted target."""
    writable = trusted_tree / "writable"
    real = _executable(writable / "payload")
    writable.chmod(0o777)

    sbin = trusted_tree / "usr" / "sbin"
    sbin.mkdir(parents=True)
    link = sbin / "ip"
    link.symlink_to(real)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(link),)}
    ):
        with pytest.raises(PermissionError, match="No trusted 'ip' executable"):
            trusted_executable("ip")


def test_prefers_a_trusted_candidate_over_an_untrusted_earlier_one(
    trusted_tree: Path,
) -> None:
    insecure = _executable(trusted_tree / "local" / "nmap", mode=0o777)
    secure = _executable(trusted_tree / "usr" / "bin" / "nmap")

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"nmap": (str(insecure), str(secure))},
    ):
        assert trusted_executable("nmap") == str(secure)


def test_fails_closed_when_every_present_candidate_is_untrusted(
    trusted_tree: Path,
) -> None:
    """An untrusted binary must never be returned just because it is first.

    Falling back to ``candidates[0]`` handed back the exact writable
    executable the allowlist exists to reject, so the ownership and mode check
    was documented but not enforced.
    """
    insecure = _executable(trusted_tree / "local" / "nmap", mode=0o777)
    absent = trusted_tree / "nowhere" / "nmap"

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"nmap": (str(insecure), str(absent))},
    ):
        with pytest.raises(PermissionError, match="No trusted 'nmap' executable"):
            trusted_executable("nmap")


def test_returns_an_absolute_path_when_an_optional_tool_is_absent(
    trusted_tree: Path,
) -> None:
    """A genuinely missing tool still resolves absolutely, never via PATH."""
    first = trusted_tree / "usr" / "sbin" / "ip"
    second = trusted_tree / "sbin" / "ip"

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"ip": (str(first), str(second))},
    ):
        assert trusted_executable("ip") == str(first)


def test_nmap_allowlist_holds_no_admin_writable_prefix() -> None:
    """nmap is the Linux path only; Homebrew prefixes are admin-owned.

    Listing a path the policy must always reject is how the root-owned rule
    stayed documented but unenforced.
    """
    candidates = subprocess_security._TRUSTED_EXECUTABLE_PATHS["nmap"]
    assert not any(
        candidate.startswith(("/usr/local/", "/opt/homebrew/"))
        for candidate in candidates
    )


def test_untrusted_executable_error_is_distinguishable(trusted_tree: Path) -> None:
    """The refusal must be its own type, not a generic failure.

    "The tool is missing" and "somebody replaced the tool" look identical to a
    caller that only checks for a falsy return, which is how a compromised host
    reads as merely degraded.
    """
    insecure = _executable(trusted_tree / "local" / "ip", mode=0o777)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(insecure),)}
    ):
        with pytest.raises(subprocess_security.UntrustedExecutableError):
            trusted_executable("ip")

    # Still an OSError, so best-effort probes keep degrading through the
    # handlers they already have instead of taking the sensor down.
    assert issubclass(subprocess_security.UntrustedExecutableError, PermissionError)
    assert issubclass(subprocess_security.UntrustedExecutableError, OSError)
