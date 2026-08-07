"""Group C: network isolation and PF, Python side.

Covers C-06, C-08, C-09, C-13 to C-16. C-04 lives in test_known_defects.py.
C-01, C-02, C-03, C-05, and C-07 assert the output of buildPFRules, which is
Swift, so they live in app/Tests/SquirrelOpsHomeTests/PFRuleBuilderTests.swift.
C-10 to C-12 are live checks in qa/live/.

Asserts the behavior the product should have. A failure is a finding.
"""

import ipaddress
from types import SimpleNamespace

import pytest

from squirrelops_home_sensor.network.port_forward import PortForwardManager
from squirrelops_home_sensor.network.virtual_ip import IPAllocator


class RecordingOps:
    def __init__(self, *, succeed=True):
        self.calls = []
        self._succeed = succeed

    async def setup_port_forwards(self, rules, interface, protected_endpoints=None):
        self.calls.append(
            {
                "rules": rules,
                "interface": interface,
                "protected_endpoints": protected_endpoints or [],
            }
        )
        return self._succeed

    async def clear_port_forwards(self):
        self.calls.append({"cleared": True})
        return self._succeed


class TestC06InvalidRulesRejected:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad_ip", ["", "999.1.1.1", "not-an-ip", "::1"])
    async def test_invalid_bind_ip_is_refused(self, bad_ip):
        manager = PortForwardManager(RecordingOps(), interface="en0")
        with pytest.raises(ValueError):
            await manager.add_forwards(
                decoy_id=1, bind_ip=bad_ip, port_remaps={80: 10080}
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad_port", [0, -1, 65536, 99999])
    async def test_out_of_range_ports_are_refused(self, bad_port):
        manager = PortForwardManager(RecordingOps(), interface="en0")
        with pytest.raises(ValueError):
            await manager.add_forwards(
                decoy_id=1, bind_ip="192.168.1.200",
                port_remaps={bad_port: 10080},
            )

    @pytest.mark.asyncio
    async def test_a_refused_rule_is_never_sent_to_the_helper(self):
        ops = RecordingOps()
        manager = PortForwardManager(ops, interface="en0")
        with pytest.raises(ValueError):
            await manager.add_forwards(
                decoy_id=1, bind_ip="192.168.1.200", port_remaps={80: 80}
            )
        assert ops.calls == [], "an invalid rule must not reach the root helper"


class TestC08StartupQuarantine:
    @pytest.mark.asyncio
    async def test_every_persisted_alias_is_denied_in_one_load(self):
        ops = RecordingOps()
        manager = PortForwardManager(ops, interface="en0")

        ok = await manager.quarantine_endpoints(
            {1: "192.168.1.200", 2: "192.168.1.201", 3: "192.168.1.202"}
        )

        assert ok
        assert len(ops.calls) == 1, "quarantine must be a single atomic ruleset"
        endpoints = ops.calls[0]["protected_endpoints"]
        assert {e["ip"] for e in endpoints} == {
            "192.168.1.200", "192.168.1.201", "192.168.1.202",
        }
        assert ops.calls[0]["rules"] == [], "quarantine forwards nothing"

    @pytest.mark.asyncio
    async def test_empty_quarantine_is_a_no_op(self):
        ops = RecordingOps()
        manager = PortForwardManager(ops, interface="en0")
        assert await manager.quarantine_endpoints({}) is True
        assert ops.calls == []


class TestC09FailedCleanupRetainsIsolation:
    @pytest.mark.asyncio
    async def test_a_rejected_sync_does_not_leave_the_endpoint_registered(self):
        ops = RecordingOps(succeed=False)
        manager = PortForwardManager(ops, interface="en0")

        ok = await manager.add_forwards(
            decoy_id=1, bind_ip="192.168.1.200", port_remaps={80: 10080}
        )

        assert ok is False
        assert 1 not in manager._protected_endpoints, (
            "a decoy whose rules were rejected must not stay registered"
        )

    @pytest.mark.asyncio
    async def test_failed_quarantine_retains_state_rather_than_flushing(self):
        ops = RecordingOps(succeed=False)
        manager = PortForwardManager(ops, interface="en0")

        ok = await manager.quarantine_endpoints({1: "192.168.1.200"})

        assert ok is False
        # A new process does not know what its predecessor left in the anchor,
        # so it must keep the endpoint rather than assume the alias is closed.
        assert 1 in manager._protected_endpoints


class TestC13AllocatorStaysInRange:
    def test_allocation_is_inside_the_configured_window(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
            range_start=200, range_end=210,
        )
        for ip in allocator.allocate(11):
            assert 200 <= int(ipaddress.IPv4Address(ip)) % 256 <= 210

    def test_gateway_sensor_network_and_broadcast_are_excluded(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.200", "192.168.1.201",
            range_start=200, range_end=205,
        )
        allocated = set(allocator.allocate(6))
        assert "192.168.1.200" not in allocated, "gateway must be excluded"
        assert "192.168.1.201" not in allocated, "sensor must be excluded"


class TestC14AllocatorRespectsCapacity:
    def test_allocation_cannot_exceed_the_available_window(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
            range_start=200, range_end=204,
        )
        assert len(allocator.allocate(50)) == 5

    def test_exhausted_range_returns_empty_rather_than_raising(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
            range_start=200, range_end=201,
        )
        allocator.allocate(2)
        assert allocator.allocate(1) == []


class TestC15AllocatorDoesNotReuseLiveAddresses:
    def test_an_ip_seen_on_the_wire_is_not_handed_out(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
            range_start=200, range_end=202,
        )
        allocator.set_active_ips([("192.168.1.201", "aa:bb:cc:dd:ee:ff")])
        assert "192.168.1.201" not in set(allocator.allocate(3))

    def test_an_already_allocated_ip_is_not_handed_out_twice(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
            range_start=200, range_end=202,
        )
        first = set(allocator.allocate(1))
        assert first.isdisjoint(set(allocator.allocate(2)))

    def test_release_returns_an_ip_to_the_pool(self):
        allocator = IPAllocator(
            "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
            range_start=200, range_end=200,
        )
        [only] = allocator.allocate(1)
        assert allocator.allocate(1) == []
        allocator.release(only)
        assert allocator.allocate(1) == [only]


class TestC16PrivilegedBoundaryValidation:
    """The trust boundary to a root process must reject malformed input.

    On macOS the boundary is the Swift helper, covered by
    app/Tests/SquirrelOpsHomeTests/PFRuleBuilderTests.swift. This exercises the
    Linux sidecar, which performs the same job in Python.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "endpoint",
        [
            {"ip": "not-an-ip", "direct_ports": []},
            {"ip": 12345, "direct_ports": []},
            {"ip": "192.168.1.200", "direct_ports": "80"},
            {"ip": "192.168.1.200", "direct_ports": [0]},
            {"ip": "192.168.1.200", "direct_ports": [70000]},
            {"ip": "192.168.1.200"},
        ],
    )
    async def test_malformed_protected_endpoint_is_refused(self, endpoint):
        from squirrelops_home_sensor.privileged.linux_sidecar import (
            LinuxNetworkHelperServer,
        )

        sidecar = LinuxNetworkHelperServer.__new__(LinuxNetworkHelperServer)
        sidecar._protected_endpoints = []
        with pytest.raises((ValueError, TypeError, AttributeError)):
            await sidecar._setup_port_forwards(
                {"rules": [], "protected_endpoints": [endpoint]}
            )

    @pytest.mark.asyncio
    async def test_unbounded_payloads_are_refused(self):
        from squirrelops_home_sensor.privileged.linux_sidecar import (
            MAX_PROTECTED_ENDPOINTS,
            LinuxNetworkHelperServer,
        )

        sidecar = LinuxNetworkHelperServer.__new__(LinuxNetworkHelperServer)
        sidecar._protected_endpoints = []
        too_many = [
            {"ip": "192.168.1.200", "direct_ports": []}
            for _ in range(MAX_PROTECTED_ENDPOINTS + 1)
        ]
        with pytest.raises(ValueError, match="bounded"):
            await sidecar._setup_port_forwards(
                {"rules": [], "protected_endpoints": too_many}
            )
