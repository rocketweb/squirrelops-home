"""Integration tests for the Decoy Orchestrator.

Verifies decoy selection logic, deployment lifecycle, health state machine,
restart behavior, degradation handling, connection event processing,
and resource profile limit enforcement.
"""

import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from squirrelops_home_sensor.decoys.orchestrator import (
    DecoyOrchestrator,
    DecoyHealth,
    DecoyRecord,
)
from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent
from squirrelops_home_sensor.decoys.credentials import CredentialGenerator


# ---------------------------------------------------------------------------
# Helpers: fake decoy for testing
# ---------------------------------------------------------------------------

class FakeDecoy(BaseDecoy):
    """Controllable fake decoy for orchestrator tests."""

    def __init__(self, decoy_id: int, name: str, port: int, decoy_type: str = "file_share",
                 bind_address: str = "127.0.0.1"):
        super().__init__(decoy_id=decoy_id, name=name, port=port,
                         bind_address=bind_address, decoy_type=decoy_type)
        self._running = False
        self.start_count = 0
        self.stop_count = 0
        self.fail_on_start = False
        self.fail_on_health = False

    async def start(self) -> None:
        self.start_count += 1
        if self.fail_on_start:
            raise RuntimeError("Simulated start failure")
        self._running = True

    async def stop(self) -> None:
        self.stop_count += 1
        self._running = False

    async def health_check(self) -> bool:
        if self.fail_on_health:
            return False
        return self._running

    @property
    def is_running(self) -> bool:
        return self._running


# ---------------------------------------------------------------------------
# Decoy selection
# ---------------------------------------------------------------------------

class TestDecoySelection:
    """Orchestrator should select decoys based on discovered services."""

    @pytest.fixture
    def orchestrator(self):
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        return DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)

    def test_dev_server_selected_for_dev_ports(self, orchestrator):
        """Ports 3000, 3001, 5173, 8000, 8080 should trigger dev server decoy."""
        services = [
            {"ip": "192.168.1.10", "port": 3000, "protocol": "tcp"},
        ]
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=set(),
        )
        types = [c["decoy_type"] for c in candidates]
        assert "dev_server" in types

    def test_home_assistant_selected_for_mdns(self, orchestrator):
        """_home-assistant._tcp mDNS should trigger HA decoy."""
        services = []
        mdns = {"_home-assistant._tcp"}
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=mdns,
        )
        types = [c["decoy_type"] for c in candidates]
        assert "home_assistant" in types

    def test_home_assistant_selected_for_port_8123(self, orchestrator):
        """Port 8123 should trigger HA decoy."""
        services = [
            {"ip": "192.168.1.20", "port": 8123, "protocol": "tcp"},
        ]
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=set(),
        )
        types = [c["decoy_type"] for c in candidates]
        assert "home_assistant" in types

    def test_file_share_selected_for_smb_port(self, orchestrator):
        """Port 445 (SMB) should trigger file share decoy."""
        services = [
            {"ip": "192.168.1.30", "port": 445, "protocol": "tcp"},
        ]
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=set(),
        )
        types = [c["decoy_type"] for c in candidates]
        assert "file_share" in types

    def test_file_share_selected_for_afp_port(self, orchestrator):
        """Port 548 (AFP) should trigger file share decoy."""
        services = [
            {"ip": "192.168.1.30", "port": 548, "protocol": "tcp"},
        ]
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=set(),
        )
        types = [c["decoy_type"] for c in candidates]
        assert "file_share" in types

    def test_fallback_file_share_when_nothing_detected(self, orchestrator):
        """With no detected services, a file share decoy should still be selected."""
        candidates = orchestrator.select_decoys(
            discovered_services=[],
            mdns_services=set(),
        )
        assert len(candidates) >= 1
        types = [c["decoy_type"] for c in candidates]
        assert "file_share" in types

    def test_multiple_types_selected(self, orchestrator):
        """Multiple service types should produce multiple decoy candidates."""
        services = [
            {"ip": "192.168.1.10", "port": 3000, "protocol": "tcp"},
            {"ip": "192.168.1.30", "port": 445, "protocol": "tcp"},
        ]
        mdns = {"_home-assistant._tcp"}
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=mdns,
        )
        types = {c["decoy_type"] for c in candidates}
        assert "dev_server" in types
        assert "home_assistant" in types
        assert "file_share" in types


# ---------------------------------------------------------------------------
# Profile limit enforcement
# ---------------------------------------------------------------------------

class TestProfileLimits:
    """Orchestrator must enforce max_decoys from resource profile."""

    def test_respects_max_decoys_limit(self):
        """Should not select more candidates than max_decoys."""
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        orchestrator = DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=1)

        services = [
            {"ip": "192.168.1.10", "port": 3000, "protocol": "tcp"},
            {"ip": "192.168.1.20", "port": 8123, "protocol": "tcp"},
            {"ip": "192.168.1.30", "port": 445, "protocol": "tcp"},
        ]
        candidates = orchestrator.select_decoys(
            discovered_services=services,
            mdns_services=set(),
        )
        assert len(candidates) <= 1

    def test_zero_max_decoys(self):
        """max_decoys=0 should produce no candidates."""
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        orchestrator = DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=0)

        candidates = orchestrator.select_decoys(
            discovered_services=[],
            mdns_services=set(),
        )
        assert len(candidates) == 0


# ---------------------------------------------------------------------------
# Deployment lifecycle
# ---------------------------------------------------------------------------

class TestDeployment:
    """deploy_decoy() should start a decoy and track it."""

    @pytest.fixture
    def orchestrator(self):
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        return DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)

    @pytest.mark.asyncio
    async def test_deploy_starts_decoy(self, orchestrator):
        """deploy_decoy should call start() on the decoy."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)
        assert decoy.start_count == 1
        assert decoy.is_running

    @pytest.mark.asyncio
    async def test_deploy_tracks_decoy(self, orchestrator):
        """Deployed decoy should appear in orchestrator's active list."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)
        assert orchestrator.get_decoy(1) is not None

    @pytest.mark.asyncio
    async def test_deploy_publishes_event(self, orchestrator):
        """Deploying a decoy should publish a decoy.health_changed event."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)
        orchestrator._event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_deploy_sets_connection_callback(self, orchestrator):
        """Deployed decoy should have its connection callback set."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)
        assert decoy.on_connection is not None

    @pytest.mark.asyncio
    async def test_stop_all(self, orchestrator):
        """stop_all() should stop all deployed decoys."""
        d1 = FakeDecoy(decoy_id=1, name="d1", port=9001)
        d2 = FakeDecoy(decoy_id=2, name="d2", port=9002)
        await orchestrator.deploy_decoy(d1)
        await orchestrator.deploy_decoy(d2)
        await orchestrator.stop_all()
        assert not d1.is_running
        assert not d2.is_running


# ---------------------------------------------------------------------------
# Health state machine
# ---------------------------------------------------------------------------

class TestHealthStateMachine:
    """Health state machine: ACTIVE -> RESTARTING -> DEGRADED cycle."""

    @pytest.fixture
    def orchestrator(self):
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        return DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)

    @pytest.mark.asyncio
    async def test_initial_state_is_active(self, orchestrator):
        """After deployment, health state should be ACTIVE."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)
        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.ACTIVE

    @pytest.mark.asyncio
    async def test_crash_triggers_restart(self, orchestrator):
        """A failed health check should trigger restart attempt."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        # Simulate crash
        decoy._running = False
        decoy.fail_on_health = True

        await orchestrator.check_health()

        # Should have attempted restart
        assert decoy.start_count >= 2  # initial start + restart

    @pytest.mark.asyncio
    async def test_successful_restart_returns_to_active(self, orchestrator):
        """After a successful restart, state should return to ACTIVE."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        # Simulate crash then recovery
        decoy._running = False
        decoy.fail_on_health = True
        # The restart will call start() which succeeds (fail_on_start is False)
        decoy.fail_on_health = False

        await orchestrator.check_health()

        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.ACTIVE

    @pytest.mark.asyncio
    async def test_three_failures_within_window_degrades(self, orchestrator):
        """3 failures within 5 minutes should transition to DEGRADED."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        # Simulate 3 consecutive start failures
        decoy._running = False
        decoy.fail_on_start = True

        for _ in range(3):
            await orchestrator.check_health()

        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.DEGRADED

    @pytest.mark.asyncio
    async def test_manual_restart_resets_failure_count(self, orchestrator):
        """Manual restart should reset failure count and return to ACTIVE."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        # Accumulate failures
        decoy._running = False
        decoy.fail_on_start = True
        for _ in range(2):
            await orchestrator.check_health()

        # Manual restart with working decoy
        decoy.fail_on_start = False
        await orchestrator.restart_decoy(1)

        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.ACTIVE
        assert record.failure_count == 0


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

class TestConnectionHandler:
    """Orchestrator should process connection events from decoys."""

    @pytest.fixture
    def orchestrator(self):
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        return DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)

    @pytest.mark.asyncio
    async def test_connection_publishes_trip_event(self, orchestrator):
        """A decoy connection should publish a decoy.trip event."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        # Simulate a connection by invoking the callback
        event = DecoyConnectionEvent(
            source_ip="192.168.1.99",
            source_port=54321,
            dest_port=9999,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
            request_path="/api/health",
        )
        decoy._notify_connection(event)

        # Allow async processing
        await asyncio.sleep(0.1)

        # Should have published decoy.trip
        calls = orchestrator._event_bus.publish.call_args_list
        trip_calls = [c for c in calls if c[0][0] == "decoy.trip"]
        assert len(trip_calls) >= 1

    @pytest.mark.asyncio
    async def test_credential_trip_publishes_credential_event(self, orchestrator):
        """A connection with credential_used should publish decoy.credential_trip."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        event = DecoyConnectionEvent(
            source_ip="192.168.1.99",
            source_port=54321,
            dest_port=9999,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
            request_path="/.env",
            credential_used="AKIA1234567890ABCDEF",
        )
        decoy._notify_connection(event)

        await asyncio.sleep(0.1)

        calls = orchestrator._event_bus.publish.call_args_list
        cred_calls = [c for c in calls if c[0][0] == "decoy.credential_trip"]
        assert len(cred_calls) >= 1
        payload = cred_calls[0][0][1]
        assert payload["credential_used"] == "AKIA1234567890ABCDEF"

    @pytest.mark.asyncio
    async def test_connection_without_credential_no_credential_event(self, orchestrator):
        """A connection without credential_used should NOT publish decoy.credential_trip."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        event = DecoyConnectionEvent(
            source_ip="192.168.1.50",
            source_port=12345,
            dest_port=9999,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
            request_path="/",
        )
        decoy._notify_connection(event)

        await asyncio.sleep(0.1)

        calls = orchestrator._event_bus.publish.call_args_list
        cred_calls = [c for c in calls if c[0][0] == "decoy.credential_trip"]
        assert len(cred_calls) == 0


# ---------------------------------------------------------------------------
# Degradation and recovery
# ---------------------------------------------------------------------------

class TestDegradationRecovery:
    """DEGRADED decoys should attempt recovery after 30 minutes."""

    @pytest.fixture
    def orchestrator(self):
        event_bus = AsyncMock()
        event_bus.publish = AsyncMock(return_value=1)
        db = AsyncMock()
        return DecoyOrchestrator(event_bus=event_bus, db=db, max_decoys=8)

    @pytest.mark.asyncio
    async def test_degraded_decoy_tracked(self, orchestrator):
        """Degraded decoys should remain in the orchestrator's records."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        decoy._running = False
        decoy.fail_on_start = True
        for _ in range(3):
            await orchestrator.check_health()

        record = orchestrator.get_decoy(1)
        assert record is not None
        assert record.health == DecoyHealth.DEGRADED

    @pytest.mark.asyncio
    async def test_degraded_recovery_attempt(self, orchestrator):
        """check_degraded() should attempt restart on degraded decoys past the retry window."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        decoy._running = False
        decoy.fail_on_start = True
        for _ in range(3):
            await orchestrator.check_health()

        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.DEGRADED

        # Fix the decoy and pretend 30 minutes passed
        decoy.fail_on_start = False
        record.last_failure_at = datetime(2020, 1, 1, tzinfo=timezone.utc)

        await orchestrator.check_degraded()

        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.ACTIVE

    @pytest.mark.asyncio
    async def test_degraded_stays_degraded_on_failure(self, orchestrator):
        """If recovery attempt fails, decoy should remain DEGRADED."""
        decoy = FakeDecoy(decoy_id=1, name="test", port=9999)
        await orchestrator.deploy_decoy(decoy)

        decoy._running = False
        decoy.fail_on_start = True
        for _ in range(3):
            await orchestrator.check_health()

        record = orchestrator.get_decoy(1)
        record.last_failure_at = datetime(2020, 1, 1, tzinfo=timezone.utc)

        await orchestrator.check_degraded()

        record = orchestrator.get_decoy(1)
        assert record.health == DecoyHealth.DEGRADED
