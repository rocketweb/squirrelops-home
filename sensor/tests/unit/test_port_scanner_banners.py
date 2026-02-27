"""Tests for PortScanner banner grabbing."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.scanner.port_scanner import (
    PortResult,
    PortScanner,
    _sanitize_banner,
)


class TestPortResult:
    """Test the PortResult dataclass."""

    def test_basic_fields(self) -> None:
        r = PortResult(port=22, service_name="SSH", banner="SSH-2.0-OpenSSH_9.6")
        assert r.port == 22
        assert r.service_name == "SSH"
        assert r.banner == "SSH-2.0-OpenSSH_9.6"

    def test_defaults(self) -> None:
        r = PortResult(port=8080)
        assert r.service_name is None
        assert r.banner is None

    def test_frozen(self) -> None:
        r = PortResult(port=22)
        with pytest.raises(AttributeError):
            r.port = 80  # type: ignore[misc]


class TestBannerSanitize:
    """Test banner sanitization."""

    def test_strips_non_printable(self) -> None:
        raw = b"SSH-2.0\x00-OpenSSH\x01"
        result = _sanitize_banner(raw)
        assert "\x00" not in result
        assert "\x01" not in result

    def test_truncates_long_banners(self) -> None:
        raw = b"A" * 500
        result = _sanitize_banner(raw)
        assert len(result) <= 256

    def test_strips_whitespace(self) -> None:
        raw = b"  SSH-2.0-OpenSSH  \r\n"
        result = _sanitize_banner(raw)
        assert not result.startswith(" ")
        assert not result.endswith("\n")


class TestScanWithBanners:
    """Test the scan_with_banners method with mocked connections."""

    @pytest.mark.asyncio
    async def test_returns_port_results(self) -> None:
        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_9.6\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            results = await scanner.scan_with_banners(
                targets=["192.168.1.1"],
                ports=[22],
                banner_timeout=1.0,
            )

        assert "192.168.1.1" in results
        assert len(results["192.168.1.1"]) == 1
        result = results["192.168.1.1"][0]
        assert isinstance(result, PortResult)
        assert result.port == 22
        assert result.service_name == "SSH"
        assert result.banner is not None
        assert "OpenSSH" in result.banner

    @pytest.mark.asyncio
    async def test_connection_refused_returns_empty(self) -> None:
        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)

        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            results = await scanner.scan_with_banners(
                targets=["192.168.1.1"],
                ports=[22],
            )

        assert results.get("192.168.1.1", []) == []

    @pytest.mark.asyncio
    async def test_timeout_returns_no_banner(self) -> None:
        scanner = PortScanner(timeout_per_port=0.1, max_concurrent=10)

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            results = await scanner.scan_with_banners(
                targets=["192.168.1.1"],
                ports=[22],
                banner_timeout=0.1,
            )

        # Port is still recorded as open even without banner
        assert "192.168.1.1" in results
        assert len(results["192.168.1.1"]) == 1
        assert results["192.168.1.1"][0].port == 22
        # Banner may be None due to timeout
        assert results["192.168.1.1"][0].service_name == "SSH"

    @pytest.mark.asyncio
    async def test_http_port_sends_probe(self) -> None:
        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            results = await scanner.scan_with_banners(
                targets=["192.168.1.1"],
                ports=[80],
                banner_timeout=1.0,
            )

        assert "192.168.1.1" in results
        result = results["192.168.1.1"][0]
        assert result.port == 80
        assert result.service_name == "HTTP"
        # HTTP probe should have been sent
        mock_writer.write.assert_called()

    @pytest.mark.asyncio
    async def test_multiple_targets_and_ports(self) -> None:
        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)

        call_count = 0

        async def mock_connect(host, port, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_reader = AsyncMock()
            mock_reader.read = AsyncMock(return_value=b"banner\r\n")
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", side_effect=mock_connect):
            results = await scanner.scan_with_banners(
                targets=["192.168.1.1", "192.168.1.2"],
                ports=[22, 80],
            )

        # 2 targets x 2 ports = 4 connections
        assert call_count == 4
        assert len(results["192.168.1.1"]) == 2
        assert len(results["192.168.1.2"]) == 2
