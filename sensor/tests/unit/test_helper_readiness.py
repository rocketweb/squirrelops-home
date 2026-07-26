"""Regression tests for the macOS helper and package readiness contract."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.privileged.xpc import (
    REQUIRED_HELPER_CAPABILITIES,
    MacOSPrivilegedOps,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _mock_connection(result: dict) -> tuple[AsyncMock, MagicMock]:
    response = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": result,
            }
        ).encode()
        + b"\n"
    )
    reader = AsyncMock()
    reader.readline = AsyncMock(return_value=response)
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


@pytest.mark.asyncio
async def test_helper_availability_requires_versioned_capability_ping() -> None:
    reader, writer = _mock_connection(
        {
            "status": "ok",
            "protocol_version": 1,
            "capabilities": [
                "arp_scan",
                "virtual_ip",
                "port_forward_isolation",
            ],
        }
    )
    with (
        patch("os.path.exists", return_value=True),
        patch(
            "asyncio.open_unix_connection",
            return_value=(reader, writer),
        ),
    ):
        ops = MacOSPrivilegedOps()
        assert await ops.is_available()

    expected_capabilities = frozenset(
        {"arp_scan", "virtual_ip", "port_forward_isolation"}
    )
    assert expected_capabilities == REQUIRED_HELPER_CAPABILITIES
    assert "service_scan" not in REQUIRED_HELPER_CAPABILITIES
    assert "dns_sniff" not in REQUIRED_HELPER_CAPABILITIES
    assert "bind_listener" not in REQUIRED_HELPER_CAPABILITIES
    payload = writer.write.call_args.args[0]
    assert payload.endswith(b"\n")
    request = json.loads(payload)
    assert request["method"] == "ping"


@pytest.mark.asyncio
async def test_helper_availability_rejects_incomplete_capabilities() -> None:
    reader, writer = _mock_connection(
        {
            "status": "ok",
            "protocol_version": 1,
            "capabilities": ["arp_scan", "virtual_ip"],
        }
    )
    with (
        patch("os.path.exists", return_value=True),
        patch(
            "asyncio.open_unix_connection",
            return_value=(reader, writer),
        ),
    ):
        ops = MacOSPrivilegedOps()
        assert not await ops.is_available()


@pytest.mark.asyncio
async def test_helper_availability_rejects_mismatched_rpc_id() -> None:
    response = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "result": {
                    "status": "ok",
                    "protocol_version": 1,
                    "capabilities": [
                        "arp_scan",
                        "virtual_ip",
                        "port_forward_isolation",
                    ],
                },
            }
        ).encode()
        + b"\n"
    )
    reader = AsyncMock()
    reader.readline = AsyncMock(return_value=response)
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    with (
        patch("os.path.exists", return_value=True),
        patch(
            "asyncio.open_unix_connection",
            return_value=(reader, writer),
        ),
    ):
        ops = MacOSPrivilegedOps()
        assert not await ops.is_available()


@pytest.mark.asyncio
async def test_helper_availability_rejects_accept_then_close() -> None:
    reader = AsyncMock()
    reader.readline = AsyncMock(return_value=b"")
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    with (
        patch("os.path.exists", return_value=True),
        patch(
            "asyncio.open_unix_connection",
            return_value=(reader, writer),
        ),
    ):
        ops = MacOSPrivilegedOps()
        assert not await ops.is_available()


def test_package_probes_helper_rpc_as_sensor_account() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text(encoding="utf-8")

    assert (
        '/usr/bin/sudo -n -u "$SENSOR_USER" /usr/bin/env -i'
        in postinstall
    )
    assert '"$PYTHON_PATH" -I - "$HELPER_SOCKET"' in postinstall
    assert '"method": "ping"' in postinstall
    assert '"protocol_version"' in postinstall
    assert '"arp_scan"' in postinstall
    assert '"virtual_ip"' in postinstall
    assert '"port_forward_isolation"' in postinstall
    assert '"service_scan"' not in postinstall
    assert '"dns_sniff"' not in postinstall
    assert '"bind_listener"' not in postinstall
    assert '/usr/bin/nc -zU "$HELPER_SOCKET"' not in postinstall

    app_postinstall = (
        REPO_ROOT / "scripts/pkg/app-scripts/postinstall"
    ).read_text(encoding="utf-8")
    assert "arp_scan" in app_postinstall
    assert "virtual_ip" in app_postinstall
    assert "port_forward_isolation" in app_postinstall
    assert "service_scan" not in app_postinstall
    assert "dns_sniff" not in app_postinstall
    assert "bind_listener" not in app_postinstall


def test_package_fails_closed_unless_launchd_identity_is_set_and_verified() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text(encoding="utf-8")
    identity_start = postinstall.index("# Step 3b: Run the daemon")
    identity_end = postinstall.index(
        "# The app package starts the helper",
        identity_start,
    )
    identity_block = postinstall[identity_start:identity_end]

    assert 'set_launchd_identity "UserName" "$SENSOR_USER"' in identity_block
    assert 'set_launchd_identity "GroupName" "$SENSOR_GROUP"' in identity_block
    assert 'PlistBuddy -c "Print :${key}" "$PLIST_TEMP"' in identity_block
    assert 'if [ "$actual_value" != "$expected_value" ]; then' in identity_block
    assert "Cannot configure the required launchd service identity" in identity_block
    assert "exit 1" in identity_block
    assert "|| true" not in identity_block

    verification = postinstall.index('set_launchd_identity "GroupName"')
    bootstrap = postinstall.index('launchctl bootstrap system "$PLIST_DEST"')
    assert verification < bootstrap


def test_package_fails_closed_when_launchd_template_is_missing() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text(encoding="utf-8")
    template_start = postinstall.index('if [ -L "$PLIST_TEMPLATE" ]')
    template_end = postinstall.index("# Step 3b: Run the daemon", template_start)
    template_block = postinstall[template_start:template_end]

    assert "Plist template is missing or unsafe" in template_block
    assert "'%Su:%Sg:%HT:%l'" in template_block
    assert "root:wheel:Regular File:1" in template_block
    assert "/usr/bin/mktemp" in template_block
    assert '"$PLIST_TEMPLATE" > "$PLIST_TEMP"' in template_block
    assert ">&2" in template_block
    assert "exit 1" in template_block
    assert "exit 0" not in template_block


def test_package_requires_and_verifies_sensor_storage_permissions() -> None:
    postinstall = (REPO_ROOT / "scripts/pkg/postinstall").read_text(encoding="utf-8")
    identity_start = postinstall.index("# Step 3b: Run the daemon")
    identity_end = postinstall.index(
        "# The app package starts the helper",
        identity_start,
    )
    identity_block = postinstall[identity_start:identity_end]

    assert 'if ! configure_sensor_permissions; then' in identity_block
    assert "chown -R" not in postinstall
    assert (
        '/usr/sbin/chown "${SENSOR_USER}:${SENSOR_GROUP}" \\\n'
        '        "$DATA_DIR" "$INSTALL_DIR/run" "$CONFIG_FILE"'
        in identity_block
    )
    assert 'chmod 700 "$DATA_DIR"' in identity_block
    assert 'chmod 700 "$LOG_DIR"' in identity_block
    assert 'chmod 755 "$INSTALL_DIR/run"' in identity_block
    assert 'chmod 600 "$CONFIG_FILE"' in identity_block
    assert '/usr/bin/find "$LOG_DIR" -xdev -maxdepth 1 -type f' in identity_block
    assert "-exec /bin/chmod 600 {} \\;" in identity_block
    assert 'validate_mutable_tree "$DATA_DIR"' in postinstall
    assert 'validate_mutable_tree "$LOG_DIR"' in postinstall
    assert "'%Su|%Sg|%HT|%l'" in postinstall
    assert '/usr/bin/stat -f "%Su:%Sg:%Lp"' in identity_block
    assert 'verify_owner_mode "$DATA_DIR" "700"' in identity_block
    assert 'verify_owner_mode "$LOG_DIR" "700"' in identity_block
    assert 'verify_owner_mode "$INSTALL_DIR/run" "755"' in identity_block
    assert 'verify_owner_mode "$CONFIG_FILE" "600"' in identity_block
    assert "verify_existing_log_permissions" in identity_block
    assert "Cannot configure required sensor storage permissions" in identity_block
    assert "|| true" not in identity_block

    verification = postinstall.index("verify_existing_log_permissions")
    bootstrap = postinstall.index('launchctl bootstrap system "$PLIST_DEST"')
    assert verification < bootstrap
