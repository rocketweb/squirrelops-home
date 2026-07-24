"""Tests for the mDNS service advertisement module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.mdns import (
    ServiceAdvertiser,
    _collect_interface_ips,
    _get_local_ip,
    _is_lan_ip,
)


def test_entry_point_supplies_route_selected_sensor_ip() -> None:
    import squirrelops_home_sensor.__main__ as entry

    advertiser = MagicMock()
    with (
        patch.object(
            entry,
            "_detect_sensor_ip",
            return_value="192.168.1.18",
        ),
        patch(
            "squirrelops_home_sensor.mdns.ServiceAdvertiser",
            return_value=advertiser,
        ) as factory,
    ):
        created = entry.create_mdns_advertiser(
            {"sensor": {"name": "TestSensor"}},
            8443,
        )

    assert created is advertiser
    factory.assert_called_once_with(
        name="TestSensor",
        port=8443,
        preferred_ip="192.168.1.18",
    )


class TestServiceAdvertiser:
    """Verify mDNS service registration lifecycle."""

    def test_init_stores_config(self) -> None:
        adv = ServiceAdvertiser(name="TestSensor", port=8443)
        assert adv.name == "TestSensor"
        assert adv.port == 8443

    def test_service_type_is_squirrelops_tcp(self) -> None:
        assert ServiceAdvertiser.service_type == "_squirrelops._tcp.local."

    @pytest.mark.asyncio
    async def test_start_registers_service(self) -> None:
        mock_zc = AsyncMock()
        with patch("squirrelops_home_sensor.mdns.AsyncZeroconf", return_value=mock_zc):
            adv = ServiceAdvertiser(name="TestSensor", port=8443)
            await adv.start()

        mock_zc.async_register_service.assert_awaited_once()
        registered_info = mock_zc.async_register_service.call_args[0][0]
        assert registered_info.type == "_squirrelops._tcp.local."
        assert registered_info.name == "TestSensor._squirrelops._tcp.local."
        assert registered_info.port == 8443

    @pytest.mark.asyncio
    async def test_stop_unregisters_service(self) -> None:
        mock_zc = AsyncMock()
        with patch("squirrelops_home_sensor.mdns.AsyncZeroconf", return_value=mock_zc):
            adv = ServiceAdvertiser(name="TestSensor", port=8443)
            await adv.start()
            await adv.stop()

        mock_zc.async_unregister_service.assert_awaited_once()
        mock_zc.async_close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_noop(self) -> None:
        adv = ServiceAdvertiser(name="TestSensor", port=8443)
        # Should not raise
        await adv.stop()

    @pytest.mark.asyncio
    async def test_start_logs_chosen_ip(self) -> None:
        """start() should advertise the IP chosen by _get_local_ip."""
        mock_zc = AsyncMock()
        with (
            patch("squirrelops_home_sensor.mdns.AsyncZeroconf", return_value=mock_zc),
            patch("squirrelops_home_sensor.mdns._get_local_ip", return_value="192.168.1.42"),
        ):
            adv = ServiceAdvertiser(name="TestSensor", port=8443)
            await adv.start()

        registered_info = mock_zc.async_register_service.call_args[0][0]
        import socket
        assert registered_info.addresses == [socket.inet_aton("192.168.1.42")]

    @pytest.mark.asyncio
    async def test_route_selected_sensor_ip_wins_over_virtual_aliases(self) -> None:
        """Loopback mimic addresses must never replace the real API address."""
        mock_zc = AsyncMock()
        with (
            patch(
                "squirrelops_home_sensor.mdns._collect_interface_ips",
                return_value=[
                    "192.168.1.200",
                    "192.168.1.201",
                    "192.168.1.18",
                ],
            ),
            patch(
                "squirrelops_home_sensor.mdns.AsyncZeroconf",
                return_value=mock_zc,
            ),
        ):
            adv = ServiceAdvertiser(
                name="TestSensor",
                port=8443,
                preferred_ip="192.168.1.18",
            )
            await adv.start()

        registered_info = mock_zc.async_register_service.call_args[0][0]
        import socket

        assert registered_info.addresses == [socket.inet_aton("192.168.1.18")]


class TestIsLanIp:
    """Verify _is_lan_ip correctly classifies addresses."""

    @pytest.mark.parametrize(
        "addr",
        [
            "192.168.1.1",
            "192.168.0.100",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
        ],
    )
    def test_standard_private_ranges_are_lan(self, addr: str) -> None:
        assert _is_lan_ip(addr) is True

    @pytest.mark.parametrize(
        "addr",
        [
            "100.64.0.1",    # CGNAT start
            "100.96.3.13",   # Tailscale typical
            "100.127.255.255",  # CGNAT end
        ],
    )
    def test_cgnat_tailscale_not_lan(self, addr: str) -> None:
        assert _is_lan_ip(addr) is False

    def test_loopback_not_lan(self) -> None:
        assert _is_lan_ip("127.0.0.1") is False

    def test_link_local_not_lan(self) -> None:
        assert _is_lan_ip("169.254.1.1") is False

    def test_public_ip_not_lan(self) -> None:
        assert _is_lan_ip("8.8.8.8") is False

    def test_invalid_addr_not_lan(self) -> None:
        assert _is_lan_ip("not-an-ip") is False


class TestGetLocalIp:
    """Verify _get_local_ip prefers LAN over CGNAT/VPN."""

    def test_prefers_lan_over_cgnat(self) -> None:
        """When both LAN and CGNAT IPs are available, LAN wins."""
        with patch(
            "squirrelops_home_sensor.mdns._collect_interface_ips",
            return_value=["100.96.3.13", "192.168.1.18"],
        ):
            assert _get_local_ip() == "192.168.1.18"

    def test_cgnat_only_falls_back_to_udp(self) -> None:
        """CGNAT-only IPs are not private in Python — falls back to UDP."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("100.96.3.13", 0)
        with (
            patch(
                "squirrelops_home_sensor.mdns._collect_interface_ips",
                return_value=["100.96.3.13"],
            ),
            patch("socket.socket", return_value=mock_sock),
        ):
            result = _get_local_ip()
            # CGNAT (100.64/10) is neither RFC 1918 private nor Python-private,
            # so it's skipped entirely and UDP socket trick runs instead.
            assert result == "100.96.3.13"

    def test_no_interfaces_falls_back_to_udp(self) -> None:
        """When no interfaces found, fall back to UDP socket trick."""
        with patch(
            "squirrelops_home_sensor.mdns._collect_interface_ips",
            return_value=[],
        ):
            ip = _get_local_ip()
            # Should return *something* — either a real IP or 127.0.0.1
            assert ip

    def test_multiple_lan_ips_returns_first(self) -> None:
        with patch(
            "squirrelops_home_sensor.mdns._collect_interface_ips",
            return_value=["10.0.0.5", "192.168.1.18"],
        ):
            assert _get_local_ip() == "10.0.0.5"


class TestCollectInterfaceIps:
    """Verify _collect_interface_ips parses OS output."""

    def test_excludes_loopback(self) -> None:
        ips = _collect_interface_ips()
        assert "127.0.0.1" not in ips

    def test_returns_list(self) -> None:
        assert isinstance(_collect_interface_ips(), list)

    def test_handles_command_failure(self) -> None:
        """Should return empty list if OS command fails."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert _collect_interface_ips() == []

    def test_macos_parser_excludes_non_loopback_addresses_on_lo0(self) -> None:
        output = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>
    inet 127.0.0.1 netmask 0xff000000
    inet 192.168.1.200 netmask 0xffffffff
    inet 192.168.1.201 netmask 0xffffffff
en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.1.18 netmask 0xffffff00 broadcast 192.168.1.255
"""
        result = MagicMock(stdout=output)
        with (
            patch("squirrelops_home_sensor.mdns.sys.platform", "darwin"),
            patch("subprocess.run", return_value=result),
        ):
            assert _collect_interface_ips() == ["192.168.1.18"]
