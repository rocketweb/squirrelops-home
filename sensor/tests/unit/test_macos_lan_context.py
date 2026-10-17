"""The privileged helper and every network subsystem must select the same LAN."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor import __main__ as entry
from squirrelops_home_sensor.privileged.xpc import MacOSPrivilegedOps

LAN = {
    "interface": "en0",
    "sensor_ip": "192.168.1.18",
    "gateway_ip": "192.168.1.1",
    "subnet": "192.168.1.0/24",
}


@pytest.mark.asyncio
async def test_vpn_default_does_not_select_tunnel_for_sensor():
    config = {"network": {"interface": "auto", "subnet": "auto"}}
    helper = MagicMock()
    helper.lan_context = AsyncMock(return_value=LAN)
    with (
        patch.object(entry.sys, "platform", "darwin"),
        patch("squirrelops_home_sensor.privileged.helper.create_privileged_ops", return_value=helper),
        patch.object(entry, "_detect_sensor_ip", return_value="100.96.4.79") as vpn_detect,
    ):
        await entry.resolve_runtime_network(config)
        assert entry._runtime_network_config(config)["subnet"] == LAN["subnet"]
        assert entry._runtime_network_config(config)["interface"] == "en0"
        assert config["network"] == {"interface": "auto", "subnet": "auto"}
        assert entry._sensor_ip_for_config(config, "127.0.0.1") == LAN["sensor_ip"]
        vpn_detect.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("network", [
    {"interface": "utun12", "subnet": "auto"},
    {"interface": "auto", "subnet": "10.0.0.0/24"},
])
async def test_explicit_network_mismatch_fails_closed(network):
    helper = MagicMock()
    helper.lan_context = AsyncMock(return_value=LAN)
    with (
        patch.object(entry.sys, "platform", "darwin"),
        patch("squirrelops_home_sensor.privileged.helper.create_privileged_ops", return_value=helper),
        pytest.raises(RuntimeError, match="configured network"),
    ):
        await entry.resolve_runtime_network({"network": network})


@pytest.mark.asyncio
async def test_linux_keeps_existing_network_resolution():
    config = {"network": {"interface": "auto", "subnet": "auto"}}
    with patch.object(entry.sys, "platform", "linux"):
        await entry.resolve_runtime_network(config)
    assert config == {"network": {"interface": "auto", "subnet": "auto"}}


@pytest.mark.asyncio
async def test_helper_lan_context_is_read_only_and_validated():
    helper = MacOSPrivilegedOps()
    with patch.object(helper, "_call", new_callable=AsyncMock, return_value=LAN) as call:
        assert await helper.lan_context() == LAN
    call.assert_awaited_once_with("getLANContext")


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [
    {"interface": "utun12"}, {"interface": "en0;id"},
    {"subnet": "0.0.0.0/0"}, {"subnet": "192.168.0.0/16"},
    {"sensor_ip": "100.96.4.79"}, {"gateway_ip": "8.8.8.8"},
    {"sensor_ip": "192.168.1.0"}, {"sensor_ip": "192.168.1.255"},
    {"gateway_ip": "192.168.1.18"}, {"subnet": None},
])
async def test_invalid_helper_context_is_rejected(override):
    helper = MacOSPrivilegedOps()
    with (
        patch.object(helper, "_call", new_callable=AsyncMock, return_value={**LAN, **override}),
        pytest.raises(RuntimeError),
    ):
        await helper.lan_context()


def test_runtime_lan_does_not_freeze_auto_settings_on_save(tmp_path):
    import yaml

    from squirrelops_home_sensor.api.routes_config import _persist_config

    config = {
        "sensor": {"data_dir": str(tmp_path)},
        "network": {"interface": "auto", "subnet": "auto"},
        "_lan_context": LAN,
    }
    _persist_config(config)
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert saved["network"] == {"interface": "auto", "subnet": "auto"}
    assert "_lan_context" not in saved


def test_mdns_uses_physical_lan_even_when_vpn_owns_default():
    with (
        patch.object(entry, "_detect_sensor_ip", side_effect=AssertionError("VPN lookup")),
        patch("squirrelops_home_sensor.mdns.ServiceAdvertiser") as advertiser,
    ):
        entry.create_mdns_advertiser({"_lan_context": LAN}, 8443)
    assert advertiser.call_args.kwargs["preferred_ip"] == LAN["sensor_ip"]
