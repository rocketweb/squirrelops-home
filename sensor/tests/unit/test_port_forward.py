"""Tests for port forwarding manager and port remapping logic."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from squirrelops_home_sensor.network.port_forward import (
    PORT_OFFSET,
    PortForwardManager,
    needs_remap,
    remap_port,
)


class TestRemapPort:
    """Tests for the remap_port() utility function."""

    def test_privileged_port_remapped(self):
        """Ports below 1024 should be remapped to port + 10000."""
        assert remap_port(80) == 80 + PORT_OFFSET
        assert remap_port(443) == 443 + PORT_OFFSET
        assert remap_port(22) == 22 + PORT_OFFSET
        assert remap_port(1) == 1 + PORT_OFFSET

    def test_non_privileged_port_unchanged(self):
        """Ports >= 1024 should be returned unchanged."""
        assert remap_port(1024) == 1024
        assert remap_port(3000) == 3000
        assert remap_port(8080) == 8080
        assert remap_port(8443) == 8443

    def test_boundary(self):
        """Port 1023 is remapped, port 1024 is not."""
        assert remap_port(1023) == 1023 + PORT_OFFSET
        assert remap_port(1024) == 1024


class TestNeedsRemap:
    """Tests for the needs_remap() utility function."""

    def test_privileged_ports_need_remap(self):
        assert needs_remap(22) is True
        assert needs_remap(80) is True
        assert needs_remap(443) is True

    def test_non_privileged_ports_no_remap(self):
        assert needs_remap(1024) is False
        assert needs_remap(8080) is False
        assert needs_remap(3000) is False


class TestPortForwardManager:
    """Tests for PortForwardManager lifecycle and rule syncing."""

    def _make_manager(self) -> tuple[PortForwardManager, AsyncMock]:
        priv_ops = AsyncMock()
        priv_ops.setup_port_forwards = AsyncMock(return_value=True)
        priv_ops.clear_port_forwards = AsyncMock(return_value=True)
        mgr = PortForwardManager(privileged_ops=priv_ops, interface="en0")
        return mgr, priv_ops

    @pytest.mark.asyncio
    async def test_add_forwards_calls_priv_ops(self):
        """Adding forwards should call setup_port_forwards with correct rules."""
        mgr, priv_ops = self._make_manager()

        ok = await mgr.add_forwards(
            decoy_id=1,
            bind_ip="192.168.1.200",
            port_remaps={80: 10080, 443: 10443, 8080: 58080},
            exposed_ports={80, 443, 8080},
        )

        assert ok is True
        priv_ops.setup_port_forwards.assert_called_once()
        call_args = priv_ops.setup_port_forwards.call_args
        rules = call_args.kwargs.get("rules") or call_args[0][0]
        assert len(rules) == 3
        assert {"from_ip": "192.168.1.200", "from_port": 80, "to_ip": "192.168.1.200", "to_port": 10080} in rules
        assert {"from_ip": "192.168.1.200", "from_port": 443, "to_ip": "192.168.1.200", "to_port": 10443} in rules
        assert {"from_ip": "192.168.1.200", "from_port": 8080, "to_ip": "192.168.1.200", "to_port": 58080} in rules
        endpoints = call_args.kwargs["protected_endpoints"]
        assert endpoints == [{"ip": "192.168.1.200", "direct_ports": []}]

    @pytest.mark.asyncio
    async def test_non_privileged_only_mimic_is_still_isolated(self):
        """Non-privileged advertised ports are redirected and isolated too."""
        mgr, priv_ops = self._make_manager()

        ok = await mgr.add_forwards(
            decoy_id=1,
            bind_ip="192.168.1.200",
            port_remaps={8080: 58080, 8443: 58443},
            exposed_ports={8080, 8443},
        )

        assert ok is True
        priv_ops.setup_port_forwards.assert_awaited_once_with(
            rules=[
                {
                    "from_ip": "192.168.1.200",
                    "from_port": 8080,
                    "to_ip": "192.168.1.200",
                    "to_port": 58080,
                },
                {
                    "from_ip": "192.168.1.200",
                    "from_port": 8443,
                    "to_ip": "192.168.1.200",
                    "to_port": 58443,
                },
            ],
            protected_endpoints=[
                {"ip": "192.168.1.200", "direct_ports": []},
            ],
            interface="en0",
        )

    @pytest.mark.asyncio
    async def test_no_exposed_ports_is_rejected(self):
        """Never silently put an unisolated alias on the host."""
        mgr, priv_ops = self._make_manager()

        ok = await mgr.add_forwards(
            decoy_id=1,
            bind_ip="192.168.1.200",
            port_remaps={},
        )

        assert ok is False
        priv_ops.setup_port_forwards.assert_not_called()
        priv_ops.clear_port_forwards.assert_not_called()

    @pytest.mark.asyncio
    async def test_every_advertised_port_requires_a_redirect(self):
        """No direct allow may expose a host wildcard listener on a mimic IP."""
        mgr, priv_ops = self._make_manager()

        with pytest.raises(ValueError, match="every exposed port"):
            await mgr.add_forwards(
                decoy_id=1,
                bind_ip="192.168.1.200",
                port_remaps={80: 52001},
                exposed_ports={80, 8443},
            )
        priv_ops.setup_port_forwards.assert_not_called()

    @pytest.mark.asyncio
    async def test_backend_ports_must_be_private_and_nonzero(self):
        mgr, priv_ops = self._make_manager()

        with pytest.raises(ValueError, match="must differ"):
            await mgr.add_forwards(
                1,
                "192.168.1.200",
                {8443: 8443},
                {8443},
            )
        with pytest.raises(ValueError, match="range"):
            await mgr.add_forwards(
                1,
                "192.168.1.200",
                {8443: 0},
                {8443},
            )
        with pytest.raises(ValueError, match="unique"):
            await mgr.add_forwards(
                1,
                "192.168.1.200",
                {8080: 58080, 8443: 58080},
                {8080, 8443},
            )
        with pytest.raises(ValueError, match="overlap"):
            await mgr.add_forwards(
                1,
                "192.168.1.200",
                {8080: 8443, 8443: 58443},
                {8080, 8443},
            )
        priv_ops.setup_port_forwards.assert_not_called()

    @pytest.mark.asyncio
    async def test_multiple_decoys_sync_all_rules(self):
        """Rules from multiple decoys should be combined in a single sync."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(
            1,
            "192.168.1.200",
            {80: 10080, 8080: 58080},
            {80, 8080},
        )
        await mgr.add_forwards(
            2,
            "192.168.1.201",
            {443: 10443, 22: 10022, 8443: 58443},
            {22, 443, 8443},
        )

        # Last call should have a private redirect for every advertised port.
        call_args = priv_ops.setup_port_forwards.call_args
        rules = call_args.kwargs.get("rules") or call_args[0][0]
        assert len(rules) == 5
        assert call_args.kwargs["protected_endpoints"] == [
            {"ip": "192.168.1.200", "direct_ports": []},
            {"ip": "192.168.1.201", "direct_ports": []},
        ]

    @pytest.mark.asyncio
    async def test_concurrent_mutations_are_serialized(self):
        mgr, priv_ops = self._make_manager()
        in_flight = 0
        max_in_flight = 0

        async def slow_setup(**_kwargs):
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.02)
            in_flight -= 1
            return True

        priv_ops.setup_port_forwards.side_effect = slow_setup

        results = await asyncio.gather(
            mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80}),
            mgr.add_forwards(2, "192.168.1.201", {443: 10443}, {443}),
        )

        assert results == [True, True]
        assert max_in_flight == 1
        assert mgr.protected_endpoint_count == 2

    @pytest.mark.asyncio
    async def test_remove_forwards_syncs_remaining(self):
        """Removing one decoy's rules should sync only remaining rules."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80})
        await mgr.add_forwards(2, "192.168.1.201", {443: 10443}, {443})
        await mgr.remove_forwards(1)

        call_args = priv_ops.setup_port_forwards.call_args
        rules = call_args.kwargs.get("rules") or call_args[0][0]
        assert len(rules) == 1
        assert rules[0]["from_ip"] == "192.168.1.201"
        assert call_args.kwargs["protected_endpoints"] == [
            {"ip": "192.168.1.201", "direct_ports": []},
        ]

    @pytest.mark.asyncio
    async def test_startup_quarantine_protects_all_aliases_atomically(self):
        mgr, priv_ops = self._make_manager()

        ok = await mgr.quarantine_endpoints({
            1: "192.168.1.200",
            2: "192.168.1.201",
        })

        assert ok is True
        priv_ops.setup_port_forwards.assert_awaited_once_with(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.200", "direct_ports": []},
                {"ip": "192.168.1.201", "direct_ports": []},
            ],
            interface="en0",
        )
        assert mgr.protected_endpoint_count == 2

    @pytest.mark.asyncio
    async def test_startup_quarantine_deduplicates_historical_rows_by_ip(self):
        """Stopped history sharing an active IP is one helper endpoint."""
        mgr, priv_ops = self._make_manager()

        assert await mgr.quarantine_endpoints({
            1: "192.168.1.200",
            2: "192.168.1.200",
            3: "192.168.1.201",
        })

        priv_ops.setup_port_forwards.assert_awaited_once_with(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.200", "direct_ports": []},
                {"ip": "192.168.1.201", "direct_ports": []},
            ],
            interface="en0",
        )

        priv_ops.setup_port_forwards.reset_mock()
        assert await mgr.remove_forwards(1)
        priv_ops.setup_port_forwards.assert_awaited_once_with(
            rules=[],
            protected_endpoints=[
                {"ip": "192.168.1.200", "direct_ports": []},
                {"ip": "192.168.1.201", "direct_ports": []},
            ],
            interface="en0",
        )

    @pytest.mark.asyncio
    async def test_normal_rules_replace_startup_quarantine(self):
        mgr, priv_ops = self._make_manager()
        await mgr.quarantine_endpoints({1: "192.168.1.200"})

        assert await mgr.add_forwards(
            1,
            "192.168.1.200",
            {80: 10080, 8080: 58080},
            {80, 8080},
        )

        call_args = priv_ops.setup_port_forwards.call_args
        assert call_args.kwargs["protected_endpoints"] == [
            {"ip": "192.168.1.200", "direct_ports": []},
        ]

    @pytest.mark.asyncio
    async def test_failed_startup_quarantine_never_flushes_unknown_live_state(self):
        mgr, priv_ops = self._make_manager()
        priv_ops.setup_port_forwards.return_value = False

        assert not await mgr.quarantine_endpoints({1: "192.168.1.200"})
        assert mgr.protected_endpoint_count == 1
        assert mgr.active_rule_count == 0
        priv_ops.clear_port_forwards.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_remove_last_decoy_clears_rules(self):
        """Removing the last decoy should clear all rules."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80})
        await mgr.remove_forwards(1)

        priv_ops.clear_port_forwards.assert_called()

    @pytest.mark.asyncio
    async def test_remove_nonexistent_is_noop(self):
        """Removing rules for a decoy that was never added should succeed."""
        mgr, priv_ops = self._make_manager()

        ok = await mgr.remove_forwards(999)
        assert ok is True

    @pytest.mark.asyncio
    async def test_clear_all(self):
        """clear_all should remove internal state and call clear_port_forwards."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80})
        await mgr.add_forwards(2, "192.168.1.201", {22: 10022}, {22})

        ok = await mgr.clear_all()
        assert ok is True
        assert mgr.active_rule_count == 0
        assert mgr.protected_endpoint_count == 0
        priv_ops.clear_port_forwards.assert_called()

    @pytest.mark.asyncio
    async def test_active_rule_count(self):
        """active_rule_count should track total rules across all decoys."""
        mgr, _ = self._make_manager()

        assert mgr.active_rule_count == 0
        await mgr.add_forwards(
            1, "192.168.1.200", {80: 10080, 443: 10443}, {80, 443}
        )
        assert mgr.active_rule_count == 2
        assert mgr.protected_endpoint_count == 1
        await mgr.add_forwards(2, "192.168.1.201", {22: 10022}, {22})
        assert mgr.active_rule_count == 3
        assert mgr.protected_endpoint_count == 2
        await mgr.remove_forwards(1)
        assert mgr.active_rule_count == 1
        assert mgr.protected_endpoint_count == 1
        await mgr.clear_all()
        assert mgr.active_rule_count == 0
        assert mgr.protected_endpoint_count == 0

    @pytest.mark.asyncio
    async def test_setup_failure_returns_false(self):
        """If setup_port_forwards fails, add_forwards should return False."""
        mgr, priv_ops = self._make_manager()
        priv_ops.setup_port_forwards = AsyncMock(return_value=False)

        ok = await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80})
        assert ok is False
        assert mgr.active_rule_count == 0
        assert mgr.protected_endpoint_count == 0

    @pytest.mark.asyncio
    async def test_remove_failure_rolls_back_internal_state(self):
        mgr, priv_ops = self._make_manager()
        await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80})
        priv_ops.clear_port_forwards.return_value = False

        ok = await mgr.remove_forwards(1)

        assert ok is False
        assert mgr.active_rule_count == 1
        assert mgr.protected_endpoint_count == 1

    @pytest.mark.asyncio
    async def test_clear_failure_preserves_internal_state(self):
        mgr, priv_ops = self._make_manager()
        await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {80})
        priv_ops.clear_port_forwards.return_value = False

        ok = await mgr.clear_all()

        assert ok is False
        assert mgr.active_rule_count == 1
        assert mgr.protected_endpoint_count == 1

    @pytest.mark.asyncio
    async def test_rejects_invalid_or_inconsistent_ports(self):
        mgr, _ = self._make_manager()
        with pytest.raises(ValueError):
            await mgr.add_forwards(1, "192.168.1.200", {80: 10080}, {443})
        with pytest.raises(ValueError):
            await mgr.add_forwards(1, "192.168.1.200", {}, {0})

    @pytest.mark.asyncio
    async def test_interface_passed_through(self):
        """The configured interface should be passed to setup_port_forwards."""
        priv_ops = AsyncMock()
        priv_ops.setup_port_forwards = AsyncMock(return_value=True)
        mgr = PortForwardManager(privileged_ops=priv_ops, interface="eth0")

        await mgr.add_forwards(1, "10.0.0.5", {80: 10080}, {80})

        call_args = priv_ops.setup_port_forwards.call_args
        assert call_args.kwargs.get("interface") == "eth0"
