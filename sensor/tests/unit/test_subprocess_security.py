from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from squirrelops_home_sensor import subprocess_security
from squirrelops_home_sensor.subprocess_security import trusted_executable


@pytest.fixture
def trust_this_user():
    """Trust the test user so a fixture tree can stand in for a system path.

    The policy under test is "only a trusted uid can change what executes".
    Tests cannot create root-owned files, so they move the trusted uid rather
    than weakening the rule. The ownership and mode logic stays real instead
    of being mocked away.

    Root stays trusted because the ancestors of any temporary directory
    include real system directories such as ``/private/var``.
    """
    with patch.object(
        subprocess_security, "_TRUSTED_UIDS", frozenset({0, os.getuid()})
    ):
        yield


def _executable(path: Path, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(mode)
    return path


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


@pytest.mark.usefixtures("trust_this_user")
def test_accepts_a_symlink_chain_like_debian_alternatives(tmp_path: Path) -> None:
    """The packaged Linux layout must pass.

    On Debian and Ubuntu ``/usr/sbin/iptables-restore`` is a symlink into
    ``/etc/alternatives``, which points at ``xtables-nft-multi``. Rejecting
    symlinks outright failed on the only platform that runs these binaries.
    """
    sbin = tmp_path / "usr" / "sbin"
    alternatives = tmp_path / "etc" / "alternatives"
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


@pytest.mark.usefixtures("trust_this_user")
def test_rejects_a_chain_whose_target_is_group_writable(tmp_path: Path) -> None:
    real = _executable(tmp_path / "usr" / "sbin" / "tool", mode=0o775)
    link = tmp_path / "usr" / "sbin" / "ip"
    link.symlink_to(real)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(link),)}
    ):
        with pytest.raises(PermissionError, match="No trusted 'ip' executable"):
            trusted_executable("ip")


@pytest.mark.usefixtures("trust_this_user")
def test_rejects_a_binary_in_a_world_writable_directory(tmp_path: Path) -> None:
    """Directory write permission is what lets an attacker swap the name."""
    loose = tmp_path / "loose"
    _executable(loose / "ip")
    loose.chmod(0o777)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"ip": (str(loose / "ip"),)},
    ):
        with pytest.raises(PermissionError, match="No trusted 'ip' executable"):
            trusted_executable("ip")


@pytest.mark.usefixtures("trust_this_user")
def test_rejects_a_symlink_that_escapes_into_a_writable_directory(
    tmp_path: Path,
) -> None:
    """A trusted-looking name must not launder an untrusted target."""
    writable = tmp_path / "writable"
    real = _executable(writable / "payload")
    writable.chmod(0o777)

    sbin = tmp_path / "usr" / "sbin"
    sbin.mkdir(parents=True)
    link = sbin / "ip"
    link.symlink_to(real)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(link),)}
    ):
        with pytest.raises(PermissionError, match="No trusted 'ip' executable"):
            trusted_executable("ip")


@pytest.mark.usefixtures("trust_this_user")
def test_prefers_a_trusted_candidate_over_an_untrusted_earlier_one(
    tmp_path: Path,
) -> None:
    insecure = _executable(tmp_path / "local" / "nmap", mode=0o777)
    secure = _executable(tmp_path / "usr" / "bin" / "nmap")

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"nmap": (str(insecure), str(secure))},
    ):
        assert trusted_executable("nmap") == str(secure)


@pytest.mark.usefixtures("trust_this_user")
def test_fails_closed_when_every_present_candidate_is_untrusted(
    tmp_path: Path,
) -> None:
    """An untrusted binary must never be returned just because it is first.

    Falling back to ``candidates[0]`` handed back the exact writable
    executable the allowlist exists to reject, so the ownership and mode check
    was documented but not enforced.
    """
    insecure = _executable(tmp_path / "local" / "nmap", mode=0o777)
    absent = tmp_path / "nowhere" / "nmap"

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS,
        {"nmap": (str(insecure), str(absent))},
    ):
        with pytest.raises(PermissionError, match="No trusted 'nmap' executable"):
            trusted_executable("nmap")


def test_returns_an_absolute_path_when_an_optional_tool_is_absent(
    tmp_path: Path,
) -> None:
    """A genuinely missing tool still resolves absolutely, never via PATH."""
    first = tmp_path / "usr" / "sbin" / "ip"
    second = tmp_path / "sbin" / "ip"

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


@pytest.mark.usefixtures("trust_this_user")
def test_untrusted_executable_error_is_distinguishable(tmp_path: Path) -> None:
    """The refusal must be its own type, not a generic failure.

    "The tool is missing" and "somebody replaced the tool" look identical to a
    caller that only checks for a falsy return, which is how a compromised host
    reads as merely degraded.
    """
    insecure = _executable(tmp_path / "local" / "ip", mode=0o777)

    with patch.dict(
        subprocess_security._TRUSTED_EXECUTABLE_PATHS, {"ip": (str(insecure),)}
    ):
        with pytest.raises(subprocess_security.UntrustedExecutableError):
            trusted_executable("ip")

    # Still an OSError, so best-effort probes keep degrading through the
    # handlers they already have instead of taking the sensor down.
    assert issubclass(subprocess_security.UntrustedExecutableError, PermissionError)
    assert issubclass(subprocess_security.UntrustedExecutableError, OSError)
