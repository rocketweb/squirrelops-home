"""An untrusted system tool must never read as an ordinary failure.

Root-executing paths raise. Best-effort probes still degrade, but report the
refusal above debug level so it is visible in an operator's logs.
"""

from __future__ import annotations

import logging
import subprocess
from unittest.mock import patch

import pytest

from squirrelops_home_sensor.privileged.helper import LinuxPrivilegedOps
from squirrelops_home_sensor.subprocess_security import UntrustedExecutableError

REFUSAL = UntrustedExecutableError("no trusted binary")


def _refuse(_name: str) -> str:
    raise REFUSAL


# ---------------------------------------------------------------------------
# Root-executing paths: raise, never return a falsy "it just failed"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("call", "expected_log"),
    [
        (
            lambda ops: ops._run_iptables_restore("*filter\nCOMMIT\n", test=True),
            "Refusing to run iptables-restore",
        ),
        (
            lambda ops: ops._capture_iptables_table("filter"),
            "Refusing to inspect the filter iptables table",
        ),
        (
            lambda ops: ops.add_ip_alias("192.168.1.50", "eth0", "255.255.255.0"),
            "Refusing to add IP alias",
        ),
        (
            lambda ops: ops.remove_ip_alias("192.168.1.50", "eth0"),
            "Refusing to remove IP alias",
        ),
        (
            lambda ops: ops.service_scan(["192.168.1.50"], [22]),
            "Refusing to run a service scan",
        ),
    ],
)
async def test_privileged_paths_raise_and_log_critical(
    call, expected_log: str, caplog: pytest.LogCaptureFixture
) -> None:
    ops = LinuxPrivilegedOps()
    with patch(
        "squirrelops_home_sensor.privileged.helper.trusted_executable",
        side_effect=_refuse,
    ):
        with caplog.at_level(logging.CRITICAL):
            with pytest.raises(UntrustedExecutableError):
                await call(ops)

    assert any(
        record.levelno == logging.CRITICAL and expected_log in record.getMessage()
        for record in caplog.records
    ), f"expected a CRITICAL log containing {expected_log!r}"


# ---------------------------------------------------------------------------
# Best-effort probes: degrade, but above debug level
# ---------------------------------------------------------------------------


def test_mdns_interface_probe_degrades_but_reports(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from squirrelops_home_sensor import mdns

    with patch(
        "squirrelops_home_sensor.mdns.trusted_executable", side_effect=_refuse
    ):
        with caplog.at_level(logging.DEBUG):
            assert mdns._collect_interface_ips() == []

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "an untrusted interface tool must not be logged at debug"
    assert "no trusted interface tool" in errors[0].getMessage()


def test_decoy_interface_probe_degrades_but_reports(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from squirrelops_home_sensor.decoys import orchestrator

    with patch(
        "squirrelops_home_sensor.decoys.orchestrator.trusted_executable",
        side_effect=_refuse,
    ):
        with caplog.at_level(logging.DEBUG):
            assert orchestrator._interface_ipv4_addresses("eth0") == []

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "an untrusted interface tool must not be logged at debug"
    assert "no trusted interface tool" in errors[0].getMessage()


def test_ordinary_subprocess_failure_still_degrades_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A missing optional tool is not a security event and must stay quiet."""
    from squirrelops_home_sensor import mdns

    with patch(
        "squirrelops_home_sensor.mdns.subprocess.run",
        side_effect=subprocess.SubprocessError("boom"),
    ):
        with caplog.at_level(logging.DEBUG):
            assert mdns._collect_interface_ips() == []

    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
