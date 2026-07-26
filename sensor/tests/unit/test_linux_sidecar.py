"""Security-contract tests for the constrained Linux network helper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.privileged.helper import LinuxPrivilegedOps
from squirrelops_home_sensor.privileged.linux_sidecar import (
    CAPABILITIES,
    LinuxNetworkHelperClient,
    LinuxNetworkHelperServer,
    SidecarProtocolError,
)


def _server(operations: LinuxPrivilegedOps | None = None) -> LinuxNetworkHelperServer:
    server = LinuxNetworkHelperServer(
        socket_path="/tmp/test-squirrelops-helper.sock",
        allowed_uid=10001,
        allowed_subnet="192.168.50.0/24",
        sensor_ip="172.30.0.2",
        interface="eth9",
        operations=operations,
    )
    server._persist_state = MagicMock()  # type: ignore[method-assign]
    return server


@pytest.mark.asyncio
async def test_ping_exposes_only_reviewed_capabilities() -> None:
    result = await _server().dispatch("ping", {})

    assert result == {
        "status": "ok",
        "protocol_version": 1,
        "capabilities": list(CAPABILITIES),
    }


@pytest.mark.asyncio
async def test_server_rejects_unknown_methods() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        await _server().dispatch("run_command", {"command": "id"})


@pytest.mark.asyncio
async def test_arp_scan_cannot_escape_configured_lan() -> None:
    operations = AsyncMock(spec=LinuxPrivilegedOps)
    server = _server(operations)

    with pytest.raises(ValueError, match="outside"):
        await server.dispatch("arp_scan", {"subnet": "10.0.0.0/24"})
    operations.arp_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_alias_removal_is_limited_to_helper_owned_addresses() -> None:
    operations = AsyncMock(spec=LinuxPrivilegedOps)
    server = _server(operations)

    with pytest.raises(ValueError, match="not owned"):
        await server.dispatch(
            "remove_ip_alias",
            {"ip": "192.168.50.200", "interface": "eth0"},
        )
    operations.remove_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_helper_rejects_caller_selected_forward_destination() -> None:
    operations = AsyncMock(spec=LinuxPrivilegedOps)
    server = _server(operations)

    with pytest.raises(ValueError, match="configured sensor"):
        await server.dispatch(
            "setup_port_forwards",
            {
                "interface": "eth0",
                "rules": [
                    {
                        "from_ip": "192.168.50.200",
                        "from_port": 443,
                        "to_ip": "192.168.50.1",
                        "to_port": 24443,
                    }
                ],
                "protected_endpoints": [],
            },
        )
    operations.setup_port_forwards.assert_not_awaited()


@pytest.mark.asyncio
async def test_helper_validates_and_pins_forward_target_and_interface() -> None:
    operations = AsyncMock(spec=LinuxPrivilegedOps)
    operations.setup_port_forwards.return_value = True
    server = _server(operations)

    result = await server.dispatch(
        "setup_port_forwards",
        {
            "interface": "sensor-controlled-interface",
            "rules": [
                {
                    "from_ip": "192.168.50.200",
                    "from_port": 443,
                    "to_ip": "172.30.0.2",
                    "to_port": 24443,
                }
            ],
            "protected_endpoints": [
                {"ip": "192.168.50.200", "direct_ports": []},
            ],
        },
    )

    assert result == {"success": True}
    operations.setup_port_forwards.assert_awaited_once_with(
        [
            {
                "from_ip": "192.168.50.200",
                "from_port": 443,
                "to_ip": "172.30.0.2",
                "to_port": 24443,
            }
        ],
        interface="eth9",
        protected_endpoints=[
            {"ip": "192.168.50.200", "direct_ports": []},
        ],
    )


@pytest.mark.asyncio
async def test_classic_listener_publication_is_pinned_to_host_and_sensor(
) -> None:
    operations = AsyncMock(spec=LinuxPrivilegedOps)
    operations.setup_port_forwards.return_value = True
    server = _server(operations)

    with patch.object(server, "_host_lan_ip", return_value="192.168.50.10"):
        result = await server.dispatch(
            "publish_listener",
            {"listener_id": 7, "port": 18080},
        )

    assert result == {"success": True}
    operations.setup_port_forwards.assert_awaited_once_with(
        [
            {
                "from_ip": "192.168.50.10",
                "from_port": 18080,
                "to_ip": "172.30.0.2",
                "to_port": 18080,
            }
        ],
        interface="eth9",
        protected_endpoints=[],
    )


def test_persisted_state_is_private_and_revalidated(tmp_path: Path) -> None:
    server = LinuxNetworkHelperServer(
        socket_path=str(tmp_path / "network-helper.sock"),
        allowed_uid=10001,
        allowed_subnet="192.168.50.0/24",
        sensor_ip="172.30.0.2",
        interface="eth9",
    )
    server._owned_aliases = {"192.168.50.200"}
    server._mimic_rules = [
        {
            "from_ip": "192.168.50.200",
            "from_port": 443,
            "to_ip": "172.30.0.2",
            "to_port": 24443,
        }
    ]
    server._protected_endpoints = [
        {"ip": "192.168.50.200", "direct_ports": []},
    ]
    server._classic_listeners = {7: 18080}
    server._mdns_registrations = {
        "mimic:7": {
            "virtual_ip": "192.168.50.200",
            "port": 18080,
            "service_type": "_http._tcp.local.",
            "hostname": "friendly-printer",
            "instance_name": "Friendly Printer",
            "properties": {"path": "/"},
        }
    }

    server._persist_state()
    assert server.state_path.stat().st_mode & 0o777 == 0o600

    restored = LinuxNetworkHelperServer(
        socket_path=str(tmp_path / "network-helper.sock"),
        allowed_uid=10001,
        allowed_subnet="192.168.50.0/24",
        sensor_ip="172.30.0.2",
        interface="eth9",
    )
    # Tests run as the desktop user rather than root; emulate the container's
    # root-owned journal while preserving all schema/parameter validation.
    with patch.object(Path, "lstat") as metadata:
        real = server.state_path.stat()
        metadata.return_value = MagicMock(
            st_mode=real.st_mode,
            st_uid=0,
        )
        restored._load_state()

    assert restored._owned_aliases == {"192.168.50.200"}
    assert restored._mimic_rules == server._mimic_rules
    assert restored._protected_endpoints == server._protected_endpoints
    assert restored._classic_listeners == {7: 18080}
    assert restored._mdns_registrations == server._mdns_registrations


@pytest.mark.asyncio
async def test_client_rewrites_every_forward_target_to_fixed_sensor_ip() -> None:
    client = LinuxNetworkHelperClient(
        "/tmp/unused.sock",
        sensor_ip="172.30.0.2",
    )
    client._call = AsyncMock(return_value={"success": True})  # type: ignore[method-assign]

    assert await client.setup_port_forwards(
        [
            {
                "from_ip": "192.168.50.200",
                "from_port": 80,
                "to_ip": "203.0.113.7",
                "to_port": 18080,
            }
        ],
        protected_endpoints=[
            {"ip": "192.168.50.200", "direct_ports": []},
        ],
    )

    client._call.assert_awaited_once_with(  # type: ignore[attr-defined]
        "setup_port_forwards",
        {
            "rules": [
                {
                    "from_ip": "192.168.50.200",
                    "from_port": 80,
                    "to_ip": "172.30.0.2",
                    "to_port": 18080,
                }
            ],
            "interface": "eth0",
            "protected_endpoints": [
                {"ip": "192.168.50.200", "direct_ports": []},
            ],
        },
    )


@pytest.mark.asyncio
async def test_client_listener_refuses_privileged_ports() -> None:
    client = LinuxNetworkHelperClient("/tmp/unused.sock")

    with pytest.raises(PermissionError, match="unprivileged"):
        await client.bind_listener("0.0.0.0", 443)


@pytest.mark.asyncio
async def test_client_availability_fails_closed_on_protocol_mismatch() -> None:
    client = LinuxNetworkHelperClient("/tmp/unused.sock")
    client._call = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "status": "ok",
            "protocol_version": 999,
            "capabilities": list(CAPABILITIES),
        }
    )

    assert not await client.is_available()


@pytest.mark.asyncio
async def test_client_surfaces_helper_errors_without_fallback_to_direct_ops() -> None:
    client = LinuxNetworkHelperClient("/tmp/unused.sock")
    client._call = AsyncMock(  # type: ignore[method-assign]
        side_effect=SidecarProtocolError("rejected")
    )

    with pytest.raises(SidecarProtocolError, match="rejected"):
        await client.add_ip_alias("192.168.50.200")


def test_factory_uses_sidecar_client_on_linux() -> None:
    from squirrelops_home_sensor.privileged.helper import create_privileged_ops

    with (
        patch("squirrelops_home_sensor.privileged.helper.sys.platform", "linux"),
        patch.dict(
            "os.environ",
            {"SQUIRRELOPS_NETWORK_HELPER_SOCKET": "/tmp/custom-helper.sock"},
        ),
    ):
        result = create_privileged_ops()

    assert isinstance(result, LinuxNetworkHelperClient)
    assert result._socket_path == "/tmp/custom-helper.sock"
