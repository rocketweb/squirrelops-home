"""Unit tests for privileged operations with mocked system calls.

Tests cover:
- PrivilegedOperations ABC contract
- LinuxPrivilegedOps with mocked scapy/nmap
- MacOSPrivilegedOps with mocked Unix domain socket JSON-RPC
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.privileged.helper import (
    DNSQuery,
    LinuxPrivilegedOps,
    PrivilegedOperations,
    ServiceResult,
)
from squirrelops_home_sensor.privileged.linux_sidecar import LinuxNetworkHelperClient
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
            "arp_scan",
            "service_scan",
            "bind_listener",
            "start_dns_sniff",
            "stop_dns_sniff",
            "get_dns_queries",
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
        now = datetime.now(UTC)
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

        with patch.dict(
            "sys.modules",
            {
                "scapy.all": MagicMock(srp=mock_srp, ARP=MagicMock(), Ether=MagicMock()),
            },
        ):
            ops = LinuxPrivilegedOps()
            results = await ops.arp_scan("192.168.1.0/24")

        assert len(results) == 2
        assert ("192.168.1.1", "aa:bb:cc:dd:ee:01") in results
        assert ("192.168.1.2", "aa:bb:cc:dd:ee:02") in results

    @pytest.mark.asyncio
    async def test_arp_scan_empty_network(self) -> None:
        mock_srp = MagicMock()
        mock_srp.return_value = ([], [])

        with patch.dict(
            "sys.modules",
            {
                "scapy.all": MagicMock(srp=mock_srp, ARP=MagicMock(), Ether=MagicMock()),
            },
        ):
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

    @pytest.mark.asyncio
    async def test_service_scan_rejects_argument_injection_target(self) -> None:
        """A non-IPv4 target (e.g. an nmap option) must be rejected before exec."""
        ops = LinuxPrivilegedOps()
        with patch("asyncio.create_subprocess_exec") as spawn:
            for bad in ("--script=http-vuln", "-oG/tmp/x", "evil.example.com"):
                with pytest.raises(ValueError):
                    await ops.service_scan(targets=[bad], ports=[80])
            spawn.assert_not_called()


class TestLinuxPrivilegedOpsDNS:
    """Test DNS sniffing with mocked scapy."""

    @pytest.mark.asyncio
    async def test_start_dns_sniff(self) -> None:
        with patch.dict(
            "sys.modules",
            {
                "scapy.all": MagicMock(),
            },
        ):
            ops = LinuxPrivilegedOps()
            await ops.start_dns_sniff("eth0")
            # Should not raise

    @pytest.mark.asyncio
    async def test_stop_dns_sniff(self) -> None:
        with patch.dict(
            "sys.modules",
            {
                "scapy.all": MagicMock(),
            },
        ):
            ops = LinuxPrivilegedOps()
            await ops.start_dns_sniff("eth0")
            await ops.stop_dns_sniff()
            # Should not raise

    @pytest.mark.asyncio
    async def test_get_dns_queries_returns_list(self) -> None:
        with patch.dict(
            "sys.modules",
            {
                "scapy.all": MagicMock(),
            },
        ):
            ops = LinuxPrivilegedOps()
            since = datetime.now(UTC)
            queries = await ops.get_dns_queries(since)
            assert isinstance(queries, list)


class TestLinuxPrivilegedOpsVirtualNetworking:
    """Test Linux forwarding and alias-isolation command construction."""

    _FILTER_SNAPSHOT = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:HOST_GUARD - [0:0]
-A INPUT -j HOST_GUARD
-A HOST_GUARD -s 10.0.0.0/8 -j ACCEPT
COMMIT
"""
    _FILTER_WITH_OWNED = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:HOST_GUARD - [0:0]
:SQUIRRELOPS_MIMIC - [0:0]
-A INPUT -j SQUIRRELOPS_MIMIC
-A INPUT -j HOST_GUARD
-A HOST_GUARD -s 10.0.0.0/8 -j ACCEPT
-A SQUIRRELOPS_MIMIC -d 192.168.1.200 -j DROP
COMMIT
"""
    _NAT_WITH_OWNED = """\
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:HOST_NAT - [0:0]
:SQUIRRELOPS_MIMIC - [0:0]
-A PREROUTING -j SQUIRRELOPS_MIMIC
-A PREROUTING -j HOST_NAT
-A HOST_NAT -s 10.0.0.0/8 -j RETURN
-A SQUIRRELOPS_MIMIC -p tcp -d 192.168.1.200 --dport 80 \
-j DNAT --to-destination 192.168.1.200:10080
COMMIT
"""
    _NAT_SNAPSHOT = """\
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:HOST_NAT - [0:0]
-A PREROUTING -j HOST_NAT
-A HOST_NAT -s 10.0.0.0/8 -j RETURN
COMMIT
"""

    @staticmethod
    def _mock_snapshots(ops: LinuxPrivilegedOps) -> None:
        ops._capture_iptables_table = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                TestLinuxPrivilegedOpsVirtualNetworking._FILTER_SNAPSHOT,
                TestLinuxPrivilegedOpsVirtualNetworking._NAT_SNAPSHOT,
            ]
        )

    @pytest.mark.asyncio
    async def test_setup_applies_one_validated_atomic_restore(self) -> None:
        ops = LinuxPrivilegedOps()
        self._mock_snapshots(ops)
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            return_value=True
        )
        ops._run_iptables = AsyncMock(return_value=True)  # type: ignore[attr-defined]
        rules = [
            {
                "from_ip": "192.168.1.200",
                "from_port": 80,
                "to_ip": "192.168.1.200",
                "to_port": 10080,
            }
        ]

        ok = await ops.setup_port_forwards(
            rules=rules,
            protected_endpoints=[
                {
                    "ip": "192.168.1.200",
                    "direct_ports": [8080],
                }
            ],
            interface="eth0",
        )

        assert ok is True
        assert ops._run_iptables_restore.await_count == 2  # type: ignore[attr-defined]
        validate_call, apply_call = (  # type: ignore[attr-defined]
            ops._run_iptables_restore.await_args_list
        )
        payload = validate_call.args[0]
        assert validate_call.kwargs == {"test": True}
        assert apply_call.args == (payload,)
        assert apply_call.kwargs == {"test": False}
        assert payload.index("*filter") < payload.index("*nat")
        assert "HOST_GUARD" not in payload
        assert "HOST_NAT" not in payload
        assert ":SQUIRRELOPS_MIMIC - [0:0]" in payload
        assert "-I INPUT 1 -j SQUIRRELOPS_MIMIC" in payload
        assert "-I FORWARD 1 -j SQUIRRELOPS_MIMIC" in payload
        assert "-I PREROUTING 1 -j SQUIRRELOPS_MIMIC" in payload
        assert (
            "-A SQUIRRELOPS_MIMIC -p tcp -d 192.168.1.200 "
            "--dport 80 -j DNAT --to-destination 192.168.1.200:10080"
        ) in payload
        assert (
            "-A SQUIRRELOPS_MIMIC -p tcp -d 192.168.1.200 "
            "--dport 8080 -j ACCEPT"
        ) in payload
        assert (
            "-A SQUIRRELOPS_MIMIC -m conntrack --ctstate DNAT "
            "-p tcp -d 192.168.1.200 --dport 10080 -j ACCEPT"
        ) in payload
        assert "-A SQUIRRELOPS_MIMIC -d 192.168.1.200 -j DROP" in payload
        assert "-F SQUIRRELOPS_MIMIC" not in payload
        assert "-N SQUIRRELOPS_MIMIC" not in payload
        ops._run_iptables.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_setup_preflight_failure_does_not_apply(self) -> None:
        ops = LinuxPrivilegedOps()
        self._mock_snapshots(ops)
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            return_value=False
        )

        ok = await ops.setup_port_forwards(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.200", "direct_ports": []}
            ],
            interface="eth0",
        )

        assert ok is False
        ops._run_iptables_restore.assert_awaited_once()  # type: ignore[attr-defined]
        assert (  # type: ignore[attr-defined]
            ops._run_iptables_restore.await_args.kwargs == {"test": True}
        )

    @pytest.mark.asyncio
    async def test_setup_rebuilds_owned_chains_without_copying_host_rules(
        self,
    ) -> None:
        ops = LinuxPrivilegedOps()
        ops._capture_iptables_table = AsyncMock(  # type: ignore[method-assign]
            side_effect=[self._FILTER_WITH_OWNED, self._NAT_WITH_OWNED]
        )
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            return_value=True
        )

        assert await ops.setup_port_forwards(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.201", "direct_ports": []}
            ],
            interface="eth0",
        ) is True

        payload = ops._run_iptables_restore.await_args_list[0].args[0]  # type: ignore[attr-defined]
        assert "HOST_GUARD" not in payload
        assert "HOST_NAT" not in payload
        assert "-D INPUT -j SQUIRRELOPS_MIMIC" in payload
        assert "-I INPUT 1 -j SQUIRRELOPS_MIMIC" in payload
        assert "-D PREROUTING -j SQUIRRELOPS_MIMIC" in payload
        assert "-I PREROUTING 1 -j SQUIRRELOPS_MIMIC" in payload
        assert "-d 192.168.1.200 -j DROP" not in payload
        assert "-d 192.168.1.201 -j DROP" in payload

    @pytest.mark.asyncio
    async def test_setup_apply_failure_restores_prior_tables_and_returns_false(
        self,
    ) -> None:
        ops = LinuxPrivilegedOps()
        ops._capture_iptables_table = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                self._FILTER_SNAPSHOT,
                self._NAT_SNAPSHOT,
                self._FILTER_WITH_OWNED,
                self._NAT_WITH_OWNED,
            ]
        )
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            side_effect=[True, False, True, True]
        )

        ok = await ops.setup_port_forwards(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.200", "direct_ports": []}
            ],
            interface="eth0",
        )

        assert ok is False
        assert ops._run_iptables_restore.await_count == 4  # type: ignore[attr-defined]
        rollback_validate = ops._run_iptables_restore.await_args_list[2]  # type: ignore[attr-defined]
        rollback_call = ops._run_iptables_restore.await_args_list[3]  # type: ignore[attr-defined]
        rollback_payload = rollback_validate.args[0]
        assert rollback_validate.kwargs == {"test": True}
        assert rollback_call.args == (rollback_payload,)
        assert rollback_call.kwargs == {"test": False}
        assert rollback_payload.index("*nat") < rollback_payload.index("*filter")
        assert "HOST_NAT" not in rollback_payload
        assert "HOST_GUARD" not in rollback_payload
        assert "-D PREROUTING -j SQUIRRELOPS_MIMIC" in rollback_payload
        assert "-D INPUT -j SQUIRRELOPS_MIMIC" in rollback_payload
        assert rollback_payload.count("-X SQUIRRELOPS_MIMIC") == 2

    @pytest.mark.asyncio
    async def test_setup_apply_failure_restores_previous_owned_rules(self) -> None:
        ops = LinuxPrivilegedOps()
        current_filter = self._FILTER_WITH_OWNED.replace(
            "192.168.1.200",
            "192.168.1.201",
        )
        current_nat = self._NAT_WITH_OWNED.replace(
            "192.168.1.200",
            "192.168.1.201",
        )
        ops._capture_iptables_table = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                self._FILTER_WITH_OWNED,
                self._NAT_WITH_OWNED,
                current_filter,
                current_nat,
            ]
        )
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            side_effect=[True, False, True, True]
        )

        assert await ops.setup_port_forwards(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.201", "direct_ports": []}
            ],
            interface="eth0",
        ) is False

        rollback_payload = ops._run_iptables_restore.await_args_list[2].args[0]  # type: ignore[attr-defined]
        assert rollback_payload.index("*nat") < rollback_payload.index("*filter")
        assert "HOST_GUARD" not in rollback_payload
        assert "HOST_NAT" not in rollback_payload
        assert "192.168.1.200" in rollback_payload
        assert "192.168.1.201" not in rollback_payload

    @pytest.mark.asyncio
    async def test_clear_atomically_removes_only_owned_chains(self) -> None:
        ops = LinuxPrivilegedOps()
        ops._capture_iptables_table = AsyncMock(  # type: ignore[method-assign]
            side_effect=[self._FILTER_WITH_OWNED, self._NAT_WITH_OWNED]
        )
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            return_value=True
        )

        assert await ops.clear_port_forwards() is True

        payload = ops._run_iptables_restore.await_args_list[0].args[0]  # type: ignore[attr-defined]
        assert payload.index("*nat") < payload.index("*filter")
        assert "HOST_NAT" not in payload
        assert "HOST_GUARD" not in payload
        assert "-D PREROUTING -j SQUIRRELOPS_MIMIC" in payload
        assert "-D INPUT -j SQUIRRELOPS_MIMIC" in payload
        assert payload.count("-X SQUIRRELOPS_MIMIC") == 2

    @pytest.mark.asyncio
    async def test_clear_is_idempotent_when_owned_chains_are_absent(self) -> None:
        ops = LinuxPrivilegedOps()
        self._mock_snapshots(ops)
        ops._run_iptables_restore = AsyncMock(  # type: ignore[method-assign]
            return_value=True
        )

        assert await ops.clear_port_forwards() is True

        ops._run_iptables_restore.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_restore_uses_noflush_and_xtables_lock(self) -> None:
        ops = LinuxPrivilegedOps()
        proc = MagicMock(returncode=0)
        proc.communicate = AsyncMock(return_value=(b"", b""))
        payload = "*filter\nCOMMIT\n"

        with patch(
            "asyncio.create_subprocess_exec",
            return_value=proc,
        ) as spawn:
            assert await ops._run_iptables_restore(payload, test=True) is True

        args = spawn.await_args.args
        assert args[0].startswith("/")
        assert args[0].endswith("/iptables-restore")
        assert "--noflush" in args
        assert args[args.index("-w"):args.index("-w") + 2] == ("-w", "5")
        assert "--test" in args
        proc.communicate.assert_awaited_once_with(payload.encode())


# ---------------------------------------------------------------------------
# MacOSPrivilegedOps (mocked Unix domain socket)
# ---------------------------------------------------------------------------


class TestMacOSPrivilegedOpsARPScan:
    """Test macOS ARP scan via mocked JSON-RPC over Unix socket."""

    @pytest.mark.asyncio
    async def test_arp_scan_via_socket(self) -> None:
        response = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": [
                        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"},
                        {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:02"},
                    ],
                }
            ).encode()
            + b"\n"
        )

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
    """Test the unprivileged macOS TCP service scanner."""

    @pytest.mark.asyncio
    async def test_service_scan_connects_directly_and_captures_banner(
        self,
    ) -> None:
        async def send_banner(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(send_banner, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            ops = MacOSPrivilegedOps()
            ops._call = AsyncMock(  # type: ignore[method-assign]
                side_effect=AssertionError("service scan must not use helper RPC")
            )
            results = await ops.service_scan(
                targets=["127.0.0.1"],
                ports=[port],
            )
        finally:
            server.close()
            await server.wait_closed()

        assert results == [
            ServiceResult(
                ip="127.0.0.1",
                port=port,
                banner="SSH-2.0-OpenSSH_9.6",
            )
        ]
        ops._call.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("targets", "ports"),
        [
            (["--script=evil"], [80]),
            (["example.local"], [80]),
            (["192.168.1.1/24"], [80]),
            (["192.168.1.1"], [True]),
            (["192.168.1.1"], [0]),
            (["192.168.1.1"], [65536]),
            (["192.168.1.1"], [80.0]),
        ],
    )
    async def test_service_scan_strictly_validates_targets_and_ports(
        self,
        targets,
        ports,
    ) -> None:
        ops = MacOSPrivilegedOps()
        ops._call = AsyncMock(return_value=[])  # type: ignore[method-assign]

        with pytest.raises(ValueError):
            await ops.service_scan(targets=targets, ports=ports)

        ops._call.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_service_scan_bounds_concurrent_connects(self) -> None:
        current = 0
        high_water = 0

        async def connect(_host: str, _port: int):
            nonlocal current, high_water
            current += 1
            high_water = max(high_water, current)
            await asyncio.sleep(0.01)
            current -= 1
            reader = AsyncMock()
            reader.read = AsyncMock(return_value=b"")
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return reader, writer

        ops = MacOSPrivilegedOps()
        ops._call = AsyncMock(return_value=[])  # type: ignore[method-assign]
        with patch(
            "squirrelops_home_sensor.scanner.port_scanner.asyncio.open_connection",
            side_effect=connect,
        ):
            results = await ops.service_scan(
                targets=["192.168.1.1"],
                ports=list(range(1, 65)),
            )

        assert len(results) == 64
        assert 1 < high_water <= 32
        ops._call.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_service_scan_rejects_excessive_probe_matrix(self) -> None:
        ops = MacOSPrivilegedOps()

        with pytest.raises(ValueError, match="too many"):
            await ops.service_scan(
                targets=["192.168.1.1"],
                ports=list(range(1, 4098)),
            )


class TestMacOSPrivilegedOpsDNS:
    """macOS DNS capture is not readiness-certified or silently faked."""

    @pytest.mark.asyncio
    async def test_start_dns_sniff_is_explicitly_unsupported(self) -> None:
        ops = MacOSPrivilegedOps()
        ops._call = AsyncMock()  # type: ignore[method-assign]

        with pytest.raises(NotImplementedError, match="DNS capture"):
            await ops.start_dns_sniff("en0")

        ops._call.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_get_dns_queries_is_explicitly_unsupported(self) -> None:
        ops = MacOSPrivilegedOps()
        ops._call = AsyncMock()  # type: ignore[method-assign]

        with pytest.raises(NotImplementedError, match="DNS capture"):
            await ops.get_dns_queries(datetime.now(UTC))

        ops._call.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_stop_dns_sniff_is_an_inert_cleanup(self) -> None:
        ops = MacOSPrivilegedOps()
        ops._call = AsyncMock()  # type: ignore[method-assign]

        await ops.stop_dns_sniff()

        ops._call.assert_not_awaited()  # type: ignore[attr-defined]


class TestMacOSPrivilegedOpsVirtualNetworking:
    """Test alias and PF isolation RPC payloads."""

    @staticmethod
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
    async def test_alias_defaults_to_host_route_netmask(self) -> None:
        reader, writer = self._mock_connection({"success": True})
        with patch(
            "asyncio.open_unix_connection",
            return_value=(reader, writer),
        ):
            ops = MacOSPrivilegedOps()
            assert await ops.add_ip_alias("192.168.1.200", interface="en0")

        request = json.loads(writer.write.call_args.args[0])
        assert request["params"]["mask"] == "255.255.255.255"

    @pytest.mark.asyncio
    async def test_port_forward_rpc_includes_protected_endpoints(self) -> None:
        reader, writer = self._mock_connection(
            {
                "success": True,
                "rules_count": 1,
                "protected_endpoints_count": 1,
            }
        )
        protected = [{"ip": "192.168.1.200", "direct_ports": [8080]}]
        rules = [
            {
                "from_ip": "192.168.1.200",
                "from_port": 80,
                "to_ip": "192.168.1.200",
                "to_port": 10080,
            }
        ]

        with patch(
            "asyncio.open_unix_connection",
            return_value=(reader, writer),
        ):
            ops = MacOSPrivilegedOps()
            assert await ops.setup_port_forwards(
                rules=rules,
                protected_endpoints=protected,
                interface="en0",
            )

        request = json.loads(writer.write.call_args.args[0])
        assert request["method"] == "setupPortForwards"
        assert request["params"]["rules"] == rules
        assert request["params"]["protected_endpoints"] == protected


class TestMacOSPrivilegedOpsBindListener:
    """Test honest local-only macOS listener binding."""

    @pytest.mark.asyncio
    async def test_unprivileged_bind_is_direct_and_returns_socket(self) -> None:
        mock_socket = MagicMock()
        ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
        ops._call = AsyncMock()  # type: ignore[method-assign]

        with patch("socket.socket", return_value=mock_socket):
            sock = await ops.bind_listener("0.0.0.0", 8443)

        assert sock is mock_socket
        ops._call.assert_not_awaited()
        mock_socket.setsockopt.assert_called_once()
        mock_socket.bind.assert_called_once_with(("0.0.0.0", 8443))
        mock_socket.listen.assert_called_once_with(128)
        mock_socket.setblocking.assert_called_once_with(False)

    @pytest.mark.asyncio
    async def test_privileged_bind_is_rejected_without_helper_rpc(self) -> None:
        ops = MacOSPrivilegedOps(socket_path="/var/run/squirrelops-helper.sock")
        ops._call = AsyncMock()  # type: ignore[method-assign]

        with (
            patch("socket.socket") as socket_constructor,
            pytest.raises(
                PermissionError,
                match="cannot transfer listening socket descriptors",
            ),
        ):
            await ops.bind_listener("0.0.0.0", 443)

        ops._call.assert_not_awaited()
        socket_constructor.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("port", [-1, 0, 65536])
    async def test_invalid_bind_port_is_rejected(self, port: int) -> None:
        ops = MacOSPrivilegedOps()

        with pytest.raises(ValueError, match="between 1 and 65535"):
            await ops.bind_listener("127.0.0.1", port)


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

        assert isinstance(ops, LinuxNetworkHelperClient)

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

        assert isinstance(ops, LinuxNetworkHelperClient)


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
        client_writers = []
        stop_event = asyncio.Event()

        async def never_respond(reader, writer):
            client_writers.append(writer)
            await stop_event.wait()

        # Start a server that accepts but never responds
        server = await asyncio.start_unix_server(
            never_respond,
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
            stop_event.set()
            for writer in client_writers:
                writer.close()
                await writer.wait_closed()
            server.close()
            await server.wait_closed()
            if os.path.exists(sock_path):
                os.unlink(sock_path)
