"""Tests for port forwarding manager and port remapping logic."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from squirrelops_home_sensor.network.port_forward import (
    PORT_OFFSET,
    PRIVILEGED_PORT_THRESHOLD,
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
            port_remaps={80: 10080, 443: 10443},
        )

        assert ok is True
        priv_ops.setup_port_forwards.assert_called_once()
        call_args = priv_ops.setup_port_forwards.call_args
        rules = call_args.kwargs.get("rules") or call_args[0][0]
        assert len(rules) == 2
        assert {"from_ip": "192.168.1.200", "from_port": 80, "to_ip": "192.168.1.200", "to_port": 10080} in rules
        assert {"from_ip": "192.168.1.200", "from_port": 443, "to_ip": "192.168.1.200", "to_port": 10443} in rules

    @pytest.mark.asyncio
    async def test_empty_remaps_is_noop(self):
        """Empty port_remaps should not call priv_ops."""
        mgr, priv_ops = self._make_manager()

        ok = await mgr.add_forwards(decoy_id=1, bind_ip="192.168.1.200", port_remaps={})
        assert ok is True
        priv_ops.setup_port_forwards.assert_not_called()

    @pytest.mark.asyncio
    async def test_multiple_decoys_sync_all_rules(self):
        """Rules from multiple decoys should be combined in a single sync."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080})
        await mgr.add_forwards(2, "192.168.1.201", {443: 10443, 22: 10022})

        # Last call should have all 3 rules
        call_args = priv_ops.setup_port_forwards.call_args
        rules = call_args.kwargs.get("rules") or call_args[0][0]
        assert len(rules) == 3

    @pytest.mark.asyncio
    async def test_remove_forwards_syncs_remaining(self):
        """Removing one decoy's rules should sync only remaining rules."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080})
        await mgr.add_forwards(2, "192.168.1.201", {443: 10443})
        await mgr.remove_forwards(1)

        call_args = priv_ops.setup_port_forwards.call_args
        rules = call_args.kwargs.get("rules") or call_args[0][0]
        assert len(rules) == 1
        assert rules[0]["from_ip"] == "192.168.1.201"

    @pytest.mark.asyncio
    async def test_remove_last_decoy_clears_rules(self):
        """Removing the last decoy should clear all rules."""
        mgr, priv_ops = self._make_manager()

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080})
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

        await mgr.add_forwards(1, "192.168.1.200", {80: 10080})
        await mgr.add_forwards(2, "192.168.1.201", {22: 10022})

        ok = await mgr.clear_all()
        assert ok is True
        assert mgr.active_rule_count == 0
        priv_ops.clear_port_forwards.assert_called()

    @pytest.mark.asyncio
    async def test_active_rule_count(self):
        """active_rule_count should track total rules across all decoys."""
        mgr, _ = self._make_manager()

        assert mgr.active_rule_count == 0
        await mgr.add_forwards(1, "192.168.1.200", {80: 10080, 443: 10443})
        assert mgr.active_rule_count == 2
        await mgr.add_forwards(2, "192.168.1.201", {22: 10022})
        assert mgr.active_rule_count == 3
        await mgr.remove_forwards(1)
        assert mgr.active_rule_count == 1
        await mgr.clear_all()
        assert mgr.active_rule_count == 0

    @pytest.mark.asyncio
    async def test_setup_failure_returns_false(self):
        """If setup_port_forwards fails, add_forwards should return False."""
        mgr, priv_ops = self._make_manager()
        priv_ops.setup_port_forwards = AsyncMock(return_value=False)

        ok = await mgr.add_forwards(1, "192.168.1.200", {80: 10080})
        assert ok is False

    @pytest.mark.asyncio
    async def test_interface_passed_through(self):
        """The configured interface should be passed to setup_port_forwards."""
        priv_ops = AsyncMock()
        priv_ops.setup_port_forwards = AsyncMock(return_value=True)
        mgr = PortForwardManager(privileged_ops=priv_ops, interface="eth0")

        await mgr.add_forwards(1, "10.0.0.5", {80: 10080})

        call_args = priv_ops.setup_port_forwards.call_args
        assert call_args.kwargs.get("interface") == "eth0"
