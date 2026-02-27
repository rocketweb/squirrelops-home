"""Unit tests for async TCP port scanner."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from squirrelops_home_sensor.scanner.port_scanner import PortScanner


class TestPortScannerSingleHost:
    """Test scanning a single host."""

    @pytest.mark.asyncio
    async def test_open_port_detected(self) -> None:
        """An open port is returned in the results."""
        server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]
        try:
            scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)
            results = await scanner.scan(["127.0.0.1"], [port])
            assert "127.0.0.1" in results
            assert port in results["127.0.0.1"]
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_closed_port_not_returned(self) -> None:
        """A closed port is not in results."""
        scanner = PortScanner(timeout_per_port=0.5, max_concurrent=10)
        results = await scanner.scan(["127.0.0.1"], [1])
        open_ports = results.get("127.0.0.1", [])
        assert 1 not in open_ports

    @pytest.mark.asyncio
    async def test_multiple_ports_scanned(self) -> None:
        """Multiple ports on one host are scanned."""
        server1 = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        server2 = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0
        )
        port1 = server1.sockets[0].getsockname()[1]
        port2 = server2.sockets[0].getsockname()[1]
        try:
            scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)
            results = await scanner.scan(["127.0.0.1"], [port1, port2])
            assert port1 in results["127.0.0.1"]
            assert port2 in results["127.0.0.1"]
        finally:
            server1.close()
            server2.close()
            await server1.wait_closed()
            await server2.wait_closed()


class TestPortScannerMultipleHosts:
    """Test scanning multiple hosts concurrently."""

    @pytest.mark.asyncio
    async def test_multiple_hosts(self) -> None:
        """Scanning two distinct IPs returns separate per-host results."""
        # Mock open_connection so that each IP has a different open port,
        # proving results are keyed per-host. This avoids depending on
        # 127.0.0.2 being available (it isn't on macOS by default).
        open_ports = {("10.0.0.1", 80), ("10.0.0.2", 443)}

        async def fake_open_connection(host, port):
            if (host, port) in open_ports:
                reader = AsyncMock()
                writer = AsyncMock()
                writer.close = lambda: None
                writer.wait_closed = AsyncMock(return_value=None)
                return reader, writer
            raise ConnectionRefusedError()

        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)
        with patch(
            "squirrelops_home_sensor.scanner.port_scanner.asyncio.open_connection",
            side_effect=fake_open_connection,
        ):
            results = await scanner.scan(
                ["10.0.0.1", "10.0.0.2"], [80, 443]
            )

        # Each host should have exactly its own open port
        assert results["10.0.0.1"] == [80]
        assert results["10.0.0.2"] == [443]


class TestPortScannerTimeout:
    """Test timeout behavior."""

    @pytest.mark.asyncio
    async def test_unreachable_host_times_out(self) -> None:
        """Scanning a non-routable IP times out without hanging."""
        scanner = PortScanner(timeout_per_port=0.3, max_concurrent=10)
        results = await scanner.scan(["192.0.2.1"], [80])
        assert results.get("192.0.2.1", []) == []

    @pytest.mark.asyncio
    async def test_overall_scan_completes_in_bounded_time(self) -> None:
        """Total scan time is bounded by concurrency, not sequential."""
        scanner = PortScanner(timeout_per_port=0.3, max_concurrent=50)
        start = asyncio.get_event_loop().time()
        await scanner.scan(["192.0.2.1"], [80, 81, 82, 83, 84])
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed < 1.0


class TestPortScannerConcurrency:
    """Test concurrency limiting."""

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrent_connections(self) -> None:
        """max_concurrent limits simultaneous connection attempts."""
        max_concurrent = 2
        current = 0
        high_water = 0

        real_open_connection = asyncio.open_connection

        async def tracking_open_connection(*args, **kwargs):
            nonlocal current, high_water
            current += 1
            if current > high_water:
                high_water = current
            try:
                # Small sleep so tasks overlap and concurrency is observable
                await asyncio.sleep(0.05)
                return await real_open_connection(*args, **kwargs)
            finally:
                current -= 1

        scanner = PortScanner(timeout_per_port=0.5, max_concurrent=max_concurrent)
        with patch("squirrelops_home_sensor.scanner.port_scanner.asyncio.open_connection",
                    side_effect=tracking_open_connection):
            await scanner.scan(["127.0.0.1"], [1, 2, 3, 4, 5])

        assert high_water <= max_concurrent, (
            f"Expected at most {max_concurrent} concurrent connections, "
            f"but observed {high_water}"
        )
        # Verify work actually happened (high_water > 0 means the mock ran)
        assert high_water > 0, "Mock was never called"


class TestPortScannerEmptyInput:
    """Test edge cases with empty input."""

    @pytest.mark.asyncio
    async def test_no_targets(self) -> None:
        """Empty target list returns empty results."""
        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)
        results = await scanner.scan([], [80])
        assert results == {}

    @pytest.mark.asyncio
    async def test_no_ports(self) -> None:
        """Empty port list returns empty results."""
        scanner = PortScanner(timeout_per_port=1.0, max_concurrent=10)
        results = await scanner.scan(["127.0.0.1"], [])
        assert results == {}
