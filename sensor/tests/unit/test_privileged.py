"""Unit tests for privileged operations with mocked system calls.

Tests cover:
- PrivilegedOperations ABC contract
- LinuxPrivilegedOps with mocked scapy/nmap
- MacOSPrivilegedOps with mocked Unix domain socket JSON-RPC
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from squirrelops_home_sensor.privileged.helper import (
    PrivilegedOperations,
    LinuxPrivilegedOps,
    ServiceResult,
    DNSQuery,
)
from squirrelops_home_sensor.privileged.xpc import MacOSPrivilegedOps


# ---------------------------------------------------------------------------
# ABC contract
# ---------------------------------------------------------------------------

class TestPrivilegedOperationsABC:
    """PrivilegedOperations cannot be instantiated directly."""

    def test_cannot_instantiate(self) -> None:
        with pytest.raises(TypeError):
            PrivilegedOperations()  # type: ignore[abstract]

    def test_has_required_methods(self) -> None:
        methods = {
            "arp_scan", "service_scan", "bind_listener",
            "start_dns_sniff", "stop_dns_sniff", "get_dns_queries",
        }
        for method in methods:
            assert hasattr(PrivilegedOperations, method), (
                f"PrivilegedOperations must define {method}"
            )


# ---------------------------------------------------------------------------
# ServiceResult and DNSQuery dataclasses
# ---------------------------------------------------------------------------

class TestServiceResult:
    """Verify ServiceResult dataclass."""

    def test_fields(self) -> None:
        r = ServiceResult(ip="192.168.1.1", port=80, banner="nginx/1.24")
        assert r.ip == "192.168.1.1"
        assert r.port == 80
        assert r.banner == "nginx/1.24"

    def test_optional_banner(self) -> None:
        r = ServiceResult(ip="192.168.1.1", port=22, banner=None)
        assert r.banner is None


class TestDNSQuery:
    """Verify DNSQuery dataclass."""

    def test_fields(self) -> None:
        now = datetime.now(timezone.utc)
        q = DNSQuery(query_name="example.com", source_ip="192.168.1.50", timestamp=now)
        assert q.query_name == "example.com"
        assert q.source_ip == "192.168.1.50"
        assert q.timestamp == now


# ---------------------------------------------------------------------------
# LinuxPrivilegedOps (mocked scapy)
# ---------------------------------------------------------------------------

class TestLinuxPrivilegedOpsARPScan:
    """Test ARP scan using mocked scapy."""

    @pytest.mark.asyncio
    async def test_arp_scan_returns_ip_mac_pairs(self) -> None:
        mock_srp = MagicMock()
        # scapy srp returns (answered, unanswered)
        # answered is a list of (sent, received) pairs
        mock_recv1 = MagicMock()
        mock_recv1.psrc = "192.168.1.1"
        mock_recv1.hwsrc = "aa:bb:cc:dd:ee:01"
        mock_recv2 = MagicMock()
        mock_recv2.psrc = "192.168.1.2"
        mock_recv2.hwsrc = "aa:bb:cc:dd:ee:02"

        mock_answered = [(MagicMock(), mock_recv1), (MagicMock(), mock_recv2)]
        mock_srp.return_value = (mock_answered, [])

        with patch.dict("sys.modules", {
            "scapy.all": MagicMock(srp=mock_srp, ARP=MagicMock(), Ether=MagicMock()),
        }):
            ops = LinuxPrivilegedOps()
            results = await ops.arp_scan("192.168.1.0/24")

        assert len(results) == 2
        assert ("192.168.1.1", "aa:bb:cc:dd:ee:01") in results
        assert ("192.168.1.2", "aa:bb:cc:dd:ee:02") in results

    @pytest.mark.asyncio
    async def test_arp_scan_empty_network(self) -> None:
        mock_srp = MagicMock()
        mock_srp.return_value = ([], [])

        with patch.dict("sys.modules", {
            "scapy.all": MagicMock(srp=mock_srp, ARP=MagicMock(), Ether=MagicMock()),
        }):
            ops = LinuxPrivilegedOps()
            results = await ops.arp_scan("192.168.1.0/24")

        assert results == []


class TestLinuxPrivilegedOpsServiceScan:
    """Test service scan using mocked nmap subprocess."""

    @pytest.mark.asyncio
    async def test_service_scan_returns_results(self) -> None:
        nmap_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service product="nginx" version="1.24"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service product="nginx" version="1.24" tunnel="ssl"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(nmap_xml.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            ops = LinuxPrivilegedOps()
            results = await ops.service_scan(
                targets=["192.168.1.1"],
                ports=[80, 443],
            )

        assert len(results) == 2
        assert any(r.port == 80 and r.ip == "192.168.1.1" for r in results)
        assert any(r.port == 443 for r in results)

    @pytest.mark.asyncio
    async def test_service_scan_no_open_ports(self) -> None:
        nmap_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <ports/>
            </host>
        </nmaprun>"""

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(nmap_xml.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            ops = LinuxPrivilegedOps()
            results = await ops.service_scan(
                targets=["192.168.1.1"],
                ports=[80],
            )

        assert results == []


class TestLinuxPrivilegedOpsDNS:
    """Test DNS sniffing with mocked scapy."""

    @pytest.mark.asyncio
    async def test_start_dns_sniff(self) -> None:
        with patch.dict("sys.modules", {
            "scapy.all": MagicMock(),
        }):
            ops = LinuxPrivilegedOps()
            await ops.start_dns_sniff("eth0")
            # Should not raise

    @pytest.mark.asyncio
    async def test_stop_dns_sniff(self) -> None:
        with patch.dict("sys.modules", {
            "scapy.all": MagicMock(),
        }):
            ops = LinuxPrivilegedOps()
            await ops.start_dns_sniff("eth0")
            await ops.stop_dns_sniff()
            # Should not raise

    @pytest.mark.asyncio
    async def test_get_dns_queries_returns_list(self) -> None:
        with patch.dict("sys.modules", {
            "scapy.all": MagicMock(),
        }):
            ops = LinuxPrivilegedOps()
            since = datetime.now(timezone.utc)
            queries = await ops.get_dns_queries(since)
            assert isinstance(queries, list)


# ---------------------------------------------------------------------------
# MacOSPrivilegedOps (mocked Unix domain socket)
# ---------------------------------------------------------------------------

class TestMacOSPrivilegedOpsARPScan:
    """Test macOS ARP scan via mocked JSON-RPC over Unix socket."""

    @pytest.mark.asyncio
    async def test_arp_scan_via_socket(self) -> None:
        response = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"},
                {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:02"},
            ],
        }).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response)
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "asyncio.open_unix_connection",
            return_value=(mock_reader, mock_writer),
        ):
            ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
            results = await ops.arp_scan("192.168.1.0/24")

        assert len(results) == 2
        assert ("192.168.1.1", "aa:bb:cc:dd:ee:01") in results
        assert ("192.168.1.2", "aa:bb:cc:dd:ee:02") in results

    @pytest.mark.asyncio
    async def test_arp_scan_socket_error(self) -> None:
        with patch(
            "asyncio.open_unix_connection",
            side_effect=ConnectionRefusedError("Helper not running"),
        ):
            ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
            with pytest.raises(ConnectionRefusedError):
                await ops.arp_scan("192.168.1.0/24")


class TestMacOSPrivilegedOpsServiceScan:
    """Test macOS service scan via mocked JSON-RPC."""

    @pytest.mark.asyncio
    async def test_service_scan_via_socket(self) -> None:
        response = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {"ip": "192.168.1.1", "port": 80, "banner": "nginx/1.24"},
                {"ip": "192.168.1.1", "port": 443, "banner": "nginx/1.24"},
            ],
        }).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response)
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "asyncio.open_unix_connection",
            return_value=(mock_reader, mock_writer),
        ):
            ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
            results = await ops.service_scan(
                targets=["192.168.1.1"],
                ports=[80, 443],
            )

        assert len(results) == 2
        assert results[0].ip == "192.168.1.1"
        assert results[0].port == 80
        assert results[0].banner == "nginx/1.24"


class TestMacOSPrivilegedOpsDNS:
    """Test macOS DNS sniff operations via mocked JSON-RPC."""

    @pytest.mark.asyncio
    async def test_start_dns_sniff_via_socket(self) -> None:
        response = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"status": "ok"},
        }).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response)
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "asyncio.open_unix_connection",
            return_value=(mock_reader, mock_writer),
        ):
            ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
            await ops.start_dns_sniff("en0")
            # Should not raise

    @pytest.mark.asyncio
    async def test_get_dns_queries_via_socket(self) -> None:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        response = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "query_name": "example.com",
                    "source_ip": "192.168.1.50",
                    "timestamp": now_iso,
                },
            ],
        }).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response)
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "asyncio.open_unix_connection",
            return_value=(mock_reader, mock_writer),
        ):
            ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
            queries = await ops.get_dns_queries(now)

        assert len(queries) == 1
        assert queries[0].query_name == "example.com"
        assert queries[0].source_ip == "192.168.1.50"


class TestMacOSPrivilegedOpsBindListener:
    """Test macOS bind_listener via mocked JSON-RPC."""

    @pytest.mark.asyncio
    async def test_bind_listener_returns_socket(self) -> None:
        response = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"fd": 5, "status": "ok"},
        }).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response)
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_socket = MagicMock()

        with patch(
            "asyncio.open_unix_connection",
            return_value=(mock_reader, mock_writer),
        ), patch("socket.socket", return_value=mock_socket):
            ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
            sock = await ops.bind_listener("0.0.0.0", 8443)

        assert sock is not None


# ---------------------------------------------------------------------------
# create_privileged_ops factory function
# ---------------------------------------------------------------------------

class TestCreatePrivilegedOps:
    """Test the factory function that selects the right PrivilegedOps impl."""

    def test_returns_linux_ops_on_linux(self) -> None:
        from squirrelops_home_sensor.privileged.helper import create_privileged_ops

        with patch("squirrelops_home_sensor.privileged.helper.sys") as mock_sys:
            mock_sys.platform = "linux"
            ops = create_privileged_ops()

        assert isinstance(ops, LinuxPrivilegedOps)

    def test_returns_macos_ops_on_darwin(self) -> None:
        from squirrelops_home_sensor.privileged.helper import create_privileged_ops

        with patch("squirrelops_home_sensor.privileged.helper.sys") as mock_sys:
            mock_sys.platform = "darwin"
            ops = create_privileged_ops()

        assert isinstance(ops, MacOSPrivilegedOps)

    def test_returns_linux_ops_on_unknown_platform(self) -> None:
        from squirrelops_home_sensor.privileged.helper import create_privileged_ops

        with patch("squirrelops_home_sensor.privileged.helper.sys") as mock_sys:
            mock_sys.platform = "freebsd14"
            ops = create_privileged_ops()

        assert isinstance(ops, LinuxPrivilegedOps)


# ---------------------------------------------------------------------------
# MacOSPrivilegedOps timeout behavior
# ---------------------------------------------------------------------------

class TestMacOSPrivilegedOpsTimeout:
    """Test RPC call timeout behavior."""

    @pytest.mark.asyncio
    async def test_call_times_out(self) -> None:
        """RPC call raises TimeoutError if helper doesn't respond."""
        import os
        import tempfile

        # Create a temp socket path
        sock_path = os.path.join(tempfile.mkdtemp(), "test-helper-timeout.sock")

        # Start a server that accepts but never responds
        server = await asyncio.start_unix_server(
            lambda r, w: None,  # Accept but never write back
            path=sock_path,
        )
        try:
            ops = MacOSPrivilegedOps(
                socket_path=sock_path,
                rpc_timeout=0.5,
            )
            with pytest.raises(asyncio.TimeoutError):
                await ops.arp_scan("192.168.1.0/24")
        finally:
            server.close()
            await server.wait_closed()
            os.unlink(sock_path)
