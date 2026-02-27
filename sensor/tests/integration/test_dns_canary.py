"""Integration tests for DNS canary monitoring.

Verifies CanaryManager hostname matching, observation recording,
and DNSMonitor event publishing via mocked privileged_ops.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.decoys.canary import CanaryManager
from squirrelops_home_sensor.scanner.dns import DNSMonitor


# ---------------------------------------------------------------------------
# CanaryManager — hostname matching
# ---------------------------------------------------------------------------

class TestCanaryManagerInit:
    """CanaryManager should load canary hostnames from a provided set."""

    def test_loads_hostnames(self):
        """Manager should accept a set of known canary hostnames."""
        hostnames = {
            "abc123.canary.squirrelops.io",
            "def456.canary.squirrelops.io",
        }
        manager = CanaryManager(hostnames)
        assert len(manager.hostnames) == 2

    def test_empty_hostnames(self):
        """Manager should work with an empty hostname set."""
        manager = CanaryManager(set())
        assert len(manager.hostnames) == 0


class TestCanaryManagerCheckQuery:
    """check_query() should match DNS queries against known canary hostnames."""

    @pytest.fixture
    def manager(self):
        return CanaryManager({
            "abc123def456.canary.squirrelops.io",
            "789xyz000aaa.canary.squirrelops.io",
        })

    def test_exact_match(self, manager):
        """Exact hostname match should return True."""
        result = manager.check_query("abc123def456.canary.squirrelops.io")
        assert result is True

    def test_trailing_dot_stripped(self, manager):
        """DNS queries often have a trailing dot — should still match."""
        result = manager.check_query("abc123def456.canary.squirrelops.io.")
        assert result is True

    def test_no_match(self, manager):
        """Non-canary hostnames should return False."""
        result = manager.check_query("google.com")
        assert result is False

    def test_partial_match_fails(self, manager):
        """A partial match (substring) should not count."""
        result = manager.check_query("canary.squirrelops.io")
        assert result is False

    def test_case_insensitive(self, manager):
        """DNS names are case-insensitive."""
        result = manager.check_query("ABC123DEF456.CANARY.SQUIRRELOPS.IO")
        assert result is True

    def test_add_hostname(self, manager):
        """Adding a new hostname should make it matchable."""
        manager.add_hostname("newhost123.canary.squirrelops.io")
        assert manager.check_query("newhost123.canary.squirrelops.io") is True

    def test_remove_hostname(self, manager):
        """Removing a hostname should prevent matching."""
        manager.remove_hostname("abc123def456.canary.squirrelops.io")
        assert manager.check_query("abc123def456.canary.squirrelops.io") is False


class TestCanaryManagerGetCredentialId:
    """get_credential_id() should return the credential ID for a canary hostname."""

    def test_returns_credential_id(self):
        """Should return the mapped credential ID."""
        manager = CanaryManager(set())
        manager.register_credential("abc.canary.squirrelops.io", credential_id=42)
        assert manager.get_credential_id("abc.canary.squirrelops.io") == 42

    def test_returns_none_for_unknown(self):
        """Should return None for unregistered hostnames."""
        manager = CanaryManager(set())
        assert manager.get_credential_id("unknown.canary.squirrelops.io") is None

    def test_trailing_dot_stripped_on_lookup(self):
        """Trailing dot should be stripped for lookup."""
        manager = CanaryManager(set())
        manager.register_credential("abc.canary.squirrelops.io", credential_id=42)
        assert manager.get_credential_id("abc.canary.squirrelops.io.") == 42


# ---------------------------------------------------------------------------
# CanaryManager — observation recording
# ---------------------------------------------------------------------------

class TestCanaryManagerObservation:
    """record_observation() should track canary DNS hits."""

    @pytest.fixture
    def manager(self):
        m = CanaryManager({"test.canary.squirrelops.io"})
        m.register_credential("test.canary.squirrelops.io", credential_id=1)
        return m

    def test_records_observation(self, manager):
        """Recording an observation should store the details."""
        obs = manager.record_observation(
            hostname="test.canary.squirrelops.io",
            queried_by_ip="192.168.1.50",
            queried_by_mac="aa:bb:cc:dd:ee:ff",
        )
        assert obs is not None
        assert obs["hostname"] == "test.canary.squirrelops.io"
        assert obs["queried_by_ip"] == "192.168.1.50"
        assert obs["credential_id"] == 1

    def test_observation_has_timestamp(self, manager):
        """Observation should include a timestamp."""
        obs = manager.record_observation(
            hostname="test.canary.squirrelops.io",
            queried_by_ip="10.0.0.1",
        )
        assert "observed_at" in obs
        assert isinstance(obs["observed_at"], datetime)


# ---------------------------------------------------------------------------
# DNSMonitor — polls privileged_ops and feeds CanaryManager
# ---------------------------------------------------------------------------

class TestDNSMonitorInit:
    """DNSMonitor should accept dependencies."""

    def test_construction(self):
        """DNSMonitor should accept privileged_ops and canary_manager."""
        privileged_ops = AsyncMock()
        canary_manager = CanaryManager(set())
        event_bus = AsyncMock()
        monitor = DNSMonitor(
            privileged_ops=privileged_ops,
            canary_manager=canary_manager,
            event_bus=event_bus,
        )
        assert monitor is not None


class TestDNSMonitorPolling:
    """DNSMonitor.poll() should fetch DNS queries and check against canary manager."""

    @pytest.fixture
    def canary_manager(self):
        m = CanaryManager({"alert.canary.squirrelops.io"})
        m.register_credential("alert.canary.squirrelops.io", credential_id=5)
        return m

    @pytest.fixture
    def event_bus(self):
        bus = AsyncMock()
        bus.publish = AsyncMock(return_value=1)
        return bus

    @pytest.mark.asyncio
    async def test_canary_match_publishes_event(self, canary_manager, event_bus):
        """When a DNS query matches a canary hostname, an event should be published."""
        privileged_ops = AsyncMock()
        privileged_ops.get_dns_queries = AsyncMock(return_value=[
            MagicMock(
                query_name="alert.canary.squirrelops.io",
                source_ip="192.168.1.99",
                timestamp=datetime.now(timezone.utc),
            ),
        ])

        monitor = DNSMonitor(
            privileged_ops=privileged_ops,
            canary_manager=canary_manager,
            event_bus=event_bus,
        )

        await monitor.poll()

        # Should publish a decoy.credential_trip event
        event_bus.publish.assert_called_once()
        call_args = event_bus.publish.call_args
        assert call_args[0][0] == "decoy.credential_trip"
        payload = call_args[0][1]
        assert payload["canary_hostname"] == "alert.canary.squirrelops.io"
        assert payload["queried_by_ip"] == "192.168.1.99"

    @pytest.mark.asyncio
    async def test_non_canary_query_ignored(self, canary_manager, event_bus):
        """DNS queries that don't match canary hostnames should be ignored."""
        privileged_ops = AsyncMock()
        privileged_ops.get_dns_queries = AsyncMock(return_value=[
            MagicMock(
                query_name="google.com",
                source_ip="192.168.1.50",
                timestamp=datetime.now(timezone.utc),
            ),
        ])

        monitor = DNSMonitor(
            privileged_ops=privileged_ops,
            canary_manager=canary_manager,
            event_bus=event_bus,
        )

        await monitor.poll()

        event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_observation_recorded_on_match(self, canary_manager, event_bus):
        """A canary match should record an observation in the canary manager."""
        privileged_ops = AsyncMock()
        privileged_ops.get_dns_queries = AsyncMock(return_value=[
            MagicMock(
                query_name="alert.canary.squirrelops.io",
                source_ip="10.0.0.1",
                timestamp=datetime.now(timezone.utc),
            ),
        ])

        monitor = DNSMonitor(
            privileged_ops=privileged_ops,
            canary_manager=canary_manager,
            event_bus=event_bus,
        )

        await monitor.poll()

        # Verify the observation was recorded
        # CanaryManager.record_observation should have been called
        # (We check via the event payload which includes credential_id)
        call_args = event_bus.publish.call_args
        payload = call_args[0][1]
        assert payload["credential_id"] == 5

    @pytest.mark.asyncio
    async def test_multiple_queries_processed(self, canary_manager, event_bus):
        """Multiple DNS queries should each be checked independently."""
        privileged_ops = AsyncMock()
        privileged_ops.get_dns_queries = AsyncMock(return_value=[
            MagicMock(query_name="google.com", source_ip="10.0.0.1",
                      timestamp=datetime.now(timezone.utc)),
            MagicMock(query_name="alert.canary.squirrelops.io", source_ip="10.0.0.2",
                      timestamp=datetime.now(timezone.utc)),
            MagicMock(query_name="github.com", source_ip="10.0.0.3",
                      timestamp=datetime.now(timezone.utc)),
        ])

        monitor = DNSMonitor(
            privileged_ops=privileged_ops,
            canary_manager=canary_manager,
            event_bus=event_bus,
        )

        await monitor.poll()

        # Only the canary match should publish
        assert event_bus.publish.call_count == 1

    @pytest.mark.asyncio
    async def test_empty_query_list(self, canary_manager, event_bus):
        """Empty DNS query list should not cause errors."""
        privileged_ops = AsyncMock()
        privileged_ops.get_dns_queries = AsyncMock(return_value=[])

        monitor = DNSMonitor(
            privileged_ops=privileged_ops,
            canary_manager=canary_manager,
            event_bus=event_bus,
        )

        await monitor.poll()

        event_bus.publish.assert_not_called()
