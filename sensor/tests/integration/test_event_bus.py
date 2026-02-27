"""Integration tests for the event bus and persistent event log."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.events.bus import EventBus, Subscription
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.events.types import EventType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def db() -> aiosqlite.Connection:
    """Create an in-memory database with schema applied."""
    conn = await aiosqlite.connect(":memory:")
    await conn.execute("PRAGMA foreign_keys = ON")
    await apply_migrations(conn)
    yield conn
    await conn.close()


@pytest.fixture
def event_log(db: aiosqlite.Connection) -> EventLog:
    return EventLog(db)


@pytest.fixture
def bus(event_log: EventLog) -> EventBus:
    return EventBus(event_log)


# ---------------------------------------------------------------------------
# EventType tests
# ---------------------------------------------------------------------------

class TestEventTypes:
    """Verify event type constants."""

    def test_device_event_types(self) -> None:
        assert EventType.DEVICE_DISCOVERED == "device.discovered"
        assert EventType.DEVICE_UPDATED == "device.updated"
        assert EventType.DEVICE_ONLINE == "device.online"
        assert EventType.DEVICE_OFFLINE == "device.offline"

    def test_decoy_event_types(self) -> None:
        assert EventType.DECOY_TRIP == "decoy.trip"
        assert EventType.DECOY_CREDENTIAL_TRIP == "decoy.credential_trip"
        assert EventType.DECOY_HEALTH_CHANGED == "decoy.health_changed"

    def test_alert_event_types(self) -> None:
        assert EventType.ALERT_NEW == "alert.new"
        assert EventType.ALERT_UPDATED == "alert.updated"

    def test_incident_event_types(self) -> None:
        assert EventType.INCIDENT_NEW == "incident.new"
        assert EventType.INCIDENT_UPDATED == "incident.updated"

    def test_system_event_types(self) -> None:
        assert EventType.SYSTEM_SCAN_COMPLETE == "system.scan_complete"
        assert EventType.SYSTEM_PROFILE_CHANGED == "system.profile_changed"
        assert EventType.SYSTEM_LEARNING_PROGRESS == "system.learning_progress"


# ---------------------------------------------------------------------------
# EventLog tests
# ---------------------------------------------------------------------------

class TestEventLog:
    """Test persistent event log backed by SQLite."""

    @pytest.mark.asyncio
    async def test_append_returns_sequence_number(
        self, event_log: EventLog
    ) -> None:
        seq = await event_log.append("test.event", {"key": "value"})
        assert seq == 1

    @pytest.mark.asyncio
    async def test_append_monotonic_sequence(self, event_log: EventLog) -> None:
        seq1 = await event_log.append("test.event", {"n": 1})
        seq2 = await event_log.append("test.event", {"n": 2})
        seq3 = await event_log.append("test.event", {"n": 3})
        assert seq1 < seq2 < seq3

    @pytest.mark.asyncio
    async def test_append_with_source_id(self, event_log: EventLog) -> None:
        seq = await event_log.append("test.event", {"k": "v"}, source_id="device-1")
        events = await event_log.replay(since_seq=0)
        assert events[0]["source_id"] == "device-1"

    @pytest.mark.asyncio
    async def test_replay_from_zero_returns_all(self, event_log: EventLog) -> None:
        await event_log.append("a", {"n": 1})
        await event_log.append("b", {"n": 2})
        await event_log.append("c", {"n": 3})
        events = await event_log.replay(since_seq=0)
        assert len(events) == 3
        assert events[0]["event_type"] == "a"
        assert events[2]["event_type"] == "c"

    @pytest.mark.asyncio
    async def test_replay_from_specific_seq(self, event_log: EventLog) -> None:
        await event_log.append("a", {"n": 1})
        seq2 = await event_log.append("b", {"n": 2})
        await event_log.append("c", {"n": 3})
        events = await event_log.replay(since_seq=seq2)
        assert len(events) == 1
        assert events[0]["event_type"] == "c"

    @pytest.mark.asyncio
    async def test_replay_returns_empty_when_caught_up(
        self, event_log: EventLog
    ) -> None:
        seq = await event_log.append("a", {"n": 1})
        events = await event_log.replay(since_seq=seq)
        assert events == []

    @pytest.mark.asyncio
    async def test_replay_includes_payload(self, event_log: EventLog) -> None:
        await event_log.append("test", {"ip": "192.168.1.1", "port": 8080})
        events = await event_log.replay(since_seq=0)
        payload = events[0]["payload"]
        assert payload["ip"] == "192.168.1.1"
        assert payload["port"] == 8080

    @pytest.mark.asyncio
    async def test_get_latest_seq_empty(self, event_log: EventLog) -> None:
        seq = await event_log.get_latest_seq()
        assert seq == 0

    @pytest.mark.asyncio
    async def test_get_latest_seq_after_writes(self, event_log: EventLog) -> None:
        await event_log.append("a", {})
        await event_log.append("b", {})
        seq = await event_log.get_latest_seq()
        assert seq == 2


# ---------------------------------------------------------------------------
# EventBus tests
# ---------------------------------------------------------------------------

class TestEventBus:
    """Test async pub/sub event bus."""

    @pytest.mark.asyncio
    async def test_publish_returns_seq(self, bus: EventBus) -> None:
        seq = await bus.publish("test.event", {"key": "val"})
        assert isinstance(seq, int)
        assert seq >= 1

    @pytest.mark.asyncio
    async def test_publish_persists_to_log(
        self, bus: EventBus, event_log: EventLog
    ) -> None:
        await bus.publish("test.event", {"key": "val"})
        events = await event_log.replay(since_seq=0)
        assert len(events) == 1
        assert events[0]["event_type"] == "test.event"

    @pytest.mark.asyncio
    async def test_subscribe_receives_matching_event(self, bus: EventBus) -> None:
        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        bus.subscribe(["test.event"], handler)
        await bus.publish("test.event", {"n": 1})

        # Give the async callback a chance to execute
        await asyncio.sleep(0.05)
        assert len(received) == 1
        assert received[0]["payload"]["n"] == 1

    @pytest.mark.asyncio
    async def test_subscribe_ignores_non_matching_event(
        self, bus: EventBus
    ) -> None:
        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        bus.subscribe(["device.online"], handler)
        await bus.publish("decoy.trip", {"n": 1})

        await asyncio.sleep(0.05)
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_wildcard_subscription(self, bus: EventBus) -> None:
        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        bus.subscribe(["*"], handler)
        await bus.publish("device.online", {"n": 1})
        await bus.publish("decoy.trip", {"n": 2})

        await asyncio.sleep(0.05)
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, bus: EventBus) -> None:
        received_a: list[dict] = []
        received_b: list[dict] = []

        async def handler_a(event: dict) -> None:
            received_a.append(event)

        async def handler_b(event: dict) -> None:
            received_b.append(event)

        bus.subscribe(["test.event"], handler_a)
        bus.subscribe(["test.event"], handler_b)
        await bus.publish("test.event", {"n": 1})

        await asyncio.sleep(0.05)
        assert len(received_a) == 1
        assert len(received_b) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus: EventBus) -> None:
        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        sub = bus.subscribe(["test.event"], handler)
        await bus.publish("test.event", {"n": 1})
        await asyncio.sleep(0.05)
        assert len(received) == 1

        bus.unsubscribe(sub)
        await bus.publish("test.event", {"n": 2})
        await asyncio.sleep(0.05)
        assert len(received) == 1  # No new event received

    @pytest.mark.asyncio
    async def test_replay_delegates_to_log(
        self, bus: EventBus, event_log: EventLog
    ) -> None:
        await bus.publish("a", {"n": 1})
        seq2 = await bus.publish("b", {"n": 2})
        await bus.publish("c", {"n": 3})
        events = await bus.replay(since_seq=seq2)
        assert len(events) == 1
        assert events[0]["event_type"] == "c"

    @pytest.mark.asyncio
    async def test_concurrent_publishers(
        self, bus: EventBus, event_log: EventLog
    ) -> None:
        """Multiple concurrent publishes should all persist with unique seqs."""

        async def publish_n(n: int) -> int:
            return await bus.publish("concurrent", {"n": n})

        seqs = await asyncio.gather(*[publish_n(i) for i in range(20)])
        assert len(set(seqs)) == 20  # All unique
        events = await event_log.replay(since_seq=0)
        assert len(events) == 20

    @pytest.mark.asyncio
    async def test_subscribe_multiple_types(self, bus: EventBus) -> None:
        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        bus.subscribe(["device.online", "decoy.trip"], handler)
        await bus.publish("device.online", {"n": 1})
        await bus.publish("decoy.trip", {"n": 2})
        await bus.publish("alert.new", {"n": 3})

        await asyncio.sleep(0.05)
        assert len(received) == 2
