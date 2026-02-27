"""Unit tests for BaseDecoy abstract class and DecoyConnectionEvent."""

import asyncio
import dataclasses
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent


# ---------------------------------------------------------------------------
# DecoyConnectionEvent dataclass tests
# ---------------------------------------------------------------------------

class TestDecoyConnectionEvent:
    """Verify the DecoyConnectionEvent dataclass has the correct fields and defaults."""

    def test_required_fields(self):
        """Event must require source_ip, source_port, dest_port, protocol, timestamp."""
        now = datetime.now(timezone.utc)
        event = DecoyConnectionEvent(
            source_ip="192.168.1.100",
            source_port=54321,
            dest_port=3001,
            protocol="tcp",
            timestamp=now,
        )
        assert event.source_ip == "192.168.1.100"
        assert event.source_port == 54321
        assert event.dest_port == 3001
        assert event.protocol == "tcp"
        assert event.timestamp == now

    def test_optional_fields_default_to_none(self):
        """request_path and credential_used should default to None."""
        event = DecoyConnectionEvent(
            source_ip="10.0.0.5",
            source_port=12345,
            dest_port=8080,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
        )
        assert event.request_path is None
        assert event.credential_used is None

    def test_optional_fields_set(self):
        """Optional fields should accept values."""
        event = DecoyConnectionEvent(
            source_ip="10.0.0.5",
            source_port=12345,
            dest_port=8080,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
            request_path="/api/health",
            credential_used="AKIAIOSFODNN7EXAMPLE",
        )
        assert event.request_path == "/api/health"
        assert event.credential_used == "AKIAIOSFODNN7EXAMPLE"

    def test_is_dataclass(self):
        """DecoyConnectionEvent must be a dataclass."""
        assert dataclasses.is_dataclass(DecoyConnectionEvent)

    def test_fields_are_immutable(self):
        """DecoyConnectionEvent should be frozen (immutable)."""
        event = DecoyConnectionEvent(
            source_ip="10.0.0.5",
            source_port=12345,
            dest_port=8080,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            event.source_ip = "changed"


# ---------------------------------------------------------------------------
# BaseDecoy abstract class tests
# ---------------------------------------------------------------------------

class ConcreteDecoy(BaseDecoy):
    """Minimal concrete subclass for testing the abstract interface."""

    def __init__(self, decoy_id: int, name: str, port: int, bind_address: str = "127.0.0.1"):
        super().__init__(decoy_id=decoy_id, name=name, port=port, bind_address=bind_address)
        self._running = False
        self.start_called = False
        self.stop_called = False

    async def start(self) -> None:
        self.start_called = True
        self._running = True

    async def stop(self) -> None:
        self.stop_called = True
        self._running = False

    async def health_check(self) -> bool:
        return self._running

    @property
    def is_running(self) -> bool:
        return self._running


class TestBaseDecoyAbstractContract:
    """BaseDecoy must enforce the abstract method contract."""

    def test_cannot_instantiate_directly(self):
        """BaseDecoy itself cannot be instantiated."""
        with pytest.raises(TypeError):
            BaseDecoy(decoy_id=1, name="test", port=8080, bind_address="127.0.0.1")

    def test_concrete_subclass_instantiates(self):
        """A fully-implemented subclass can be instantiated."""
        decoy = ConcreteDecoy(decoy_id=1, name="test-decoy", port=3001)
        assert decoy.decoy_id == 1
        assert decoy.name == "test-decoy"
        assert decoy.port == 3001
        assert decoy.bind_address == "127.0.0.1"


class TestBaseDecoyLifecycle:
    """Lifecycle methods start/stop/health_check must work correctly."""

    @pytest.fixture
    def decoy(self):
        return ConcreteDecoy(decoy_id=1, name="test-decoy", port=3001)

    @pytest.mark.asyncio
    async def test_start(self, decoy):
        """start() should be callable and set running state."""
        assert not decoy.is_running
        await decoy.start()
        assert decoy.start_called
        assert decoy.is_running

    @pytest.mark.asyncio
    async def test_stop(self, decoy):
        """stop() should be callable and clear running state."""
        await decoy.start()
        await decoy.stop()
        assert decoy.stop_called
        assert not decoy.is_running

    @pytest.mark.asyncio
    async def test_health_check_when_running(self, decoy):
        """health_check() should return True when running."""
        await decoy.start()
        assert await decoy.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_when_stopped(self, decoy):
        """health_check() should return False when not running."""
        assert await decoy.health_check() is False


class TestBaseDecoyConnectionCallback:
    """_notify_connection must invoke registered callback with a DecoyConnectionEvent."""

    @pytest.fixture
    def decoy(self):
        return ConcreteDecoy(decoy_id=1, name="test-decoy", port=3001)

    def test_set_connection_callback(self, decoy):
        """on_connection property should accept and store a callback."""
        callback = MagicMock()
        decoy.on_connection = callback
        assert decoy.on_connection is callback

    def test_default_callback_is_none(self, decoy):
        """Default connection callback should be None."""
        assert decoy.on_connection is None

    def test_notify_connection_invokes_callback(self, decoy):
        """_notify_connection should call the registered callback with the event."""
        callback = MagicMock()
        decoy.on_connection = callback

        event = DecoyConnectionEvent(
            source_ip="192.168.1.50",
            source_port=54321,
            dest_port=3001,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
        )
        decoy._notify_connection(event)
        callback.assert_called_once_with(event)

    def test_notify_connection_no_callback_no_error(self, decoy):
        """_notify_connection should not raise if no callback is set."""
        event = DecoyConnectionEvent(
            source_ip="192.168.1.50",
            source_port=54321,
            dest_port=3001,
            protocol="tcp",
            timestamp=datetime.now(timezone.utc),
        )
        # Should not raise
        decoy._notify_connection(event)

    def test_notify_connection_passes_event_unchanged(self, decoy):
        """The event passed to _notify_connection must arrive at the callback unchanged."""
        received_events = []
        decoy.on_connection = lambda e: received_events.append(e)

        now = datetime.now(timezone.utc)
        event = DecoyConnectionEvent(
            source_ip="10.0.0.1",
            source_port=9999,
            dest_port=3001,
            protocol="tcp",
            timestamp=now,
            request_path="/secret",
            credential_used="ghp_abc123",
        )
        decoy._notify_connection(event)
        assert len(received_events) == 1
        assert received_events[0] is event


class TestBaseDecoyProperties:
    """Verify init parameters are stored and accessible."""

    def test_decoy_type_attribute(self):
        """Subclass should be able to set decoy_type."""
        decoy = ConcreteDecoy(decoy_id=1, name="test", port=3001)
        # BaseDecoy stores decoy_type as 'unknown' by default; subclasses override
        assert hasattr(decoy, "decoy_type")

    def test_custom_bind_address(self):
        """bind_address should be configurable."""
        decoy = ConcreteDecoy(decoy_id=2, name="test", port=8080, bind_address="0.0.0.0")
        assert decoy.bind_address == "0.0.0.0"
