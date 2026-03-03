"""Integration tests for DecoyAlertHandler.

Verifies that decoy.trip and decoy.credential_trip events produce
home_alerts rows, publish alert.new events, and invoke incident grouping.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import aiosqlite
import pytest
import pytest_asyncio

from squirrelops_home_sensor.alerts.decoy_handler import DecoyAlertHandler
from squirrelops_home_sensor.alerts.types import AlertType, Severity


# -- Helpers ---------------------------------------------------------------

class FakeEventBus:
    """Minimal event bus that records publications and delivers to subscribers."""

    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any]]] = []
        self._subscribers: dict[str, list[Any]] = {}
        self._next_seq = 1

    async def publish(
        self, event_type: str, payload: dict[str, Any], source_id: str | None = None,
    ) -> int:
        seq = self._next_seq
        self._next_seq += 1
        self.published.append((event_type, payload))
        return seq

    def subscribe(self, event_types: list[str], callback: Any) -> None:
        for et in event_types:
            self._subscribers.setdefault(et, []).append(callback)

    async def deliver(self, event_type: str, payload: dict[str, Any]) -> None:
        """Simulate event delivery to subscribers."""
        event = {"seq": self._next_seq, "event_type": event_type, "payload": payload}
        for cb in self._subscribers.get(event_type, []):
            await cb(event)

    def events_of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [p for t, p in self.published if t == event_type]


# -- Fixtures --------------------------------------------------------------

@pytest_asyncio.fixture
async def db():
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON")
    from squirrelops_home_sensor.db.schema import create_all_tables
    await create_all_tables(conn)
    yield conn
    await conn.close()


@pytest.fixture
def bus():
    return FakeEventBus()


@pytest.fixture
def incident_grouper():
    return AsyncMock()


@pytest.fixture
def handler(db, bus, incident_grouper):
    h = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=incident_grouper)
    h.subscribe_to(bus)
    return h


# -- Tests -----------------------------------------------------------------

class TestDecoyTrip:
    """A decoy.trip event should create a HIGH severity alert."""

    @pytest.mark.asyncio
    async def test_creates_alert_row(self, handler, bus, db):
        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 8080,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
        })

        async with db.execute("SELECT * FROM home_alerts") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 1
        row = rows[0]
        assert row["alert_type"] == AlertType.DECOY_TRIP.value
        assert row["severity"] == Severity.HIGH.value
        assert row["source_ip"] == "10.0.0.5"
        assert "port 8080" in row["title"]

    @pytest.mark.asyncio
    async def test_publishes_alert_new(self, handler, bus, db):
        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 8080,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
        })

        alert_new_events = bus.events_of_type("alert.new")
        assert len(alert_new_events) == 1
        assert alert_new_events[0]["alert_type"] == AlertType.DECOY_TRIP.value
        assert alert_new_events[0]["severity"] == Severity.HIGH.value

    @pytest.mark.asyncio
    async def test_calls_incident_grouper(self, handler, bus, db, incident_grouper):
        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 8080,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
        })

        incident_grouper.process_alert.assert_awaited_once()
        alert_id = incident_grouper.process_alert.call_args[0][0]
        assert isinstance(alert_id, int)


class TestCredentialTrip:
    """A decoy.credential_trip event should create a CRITICAL severity alert."""

    @pytest.mark.asyncio
    async def test_creates_critical_alert(self, handler, bus, db):
        await bus.deliver("decoy.credential_trip", {
            "source_ip": "10.0.0.99",
            "source_port": 12345,
            "dest_port": 445,
            "credential_used": "admin:P@ssw0rd",
            "request_path": "/passwords.txt",
            "timestamp": "2026-03-02T12:05:00Z",
            "detection_method": "decoy_http",
        })

        async with db.execute("SELECT * FROM home_alerts") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 1
        row = rows[0]
        assert row["alert_type"] == AlertType.DECOY_CREDENTIAL_TRIP.value
        assert row["severity"] == Severity.CRITICAL.value
        assert row["source_ip"] == "10.0.0.99"
        assert "Credential stolen" in row["title"]

        detail = json.loads(row["detail"])
        assert detail["credential_used"] == "admin:P@ssw0rd"
        assert detail["request_path"] == "/passwords.txt"

    @pytest.mark.asyncio
    async def test_publishes_alert_new_critical(self, handler, bus, db):
        await bus.deliver("decoy.credential_trip", {
            "source_ip": "10.0.0.99",
            "source_port": 12345,
            "dest_port": 445,
            "credential_used": "admin:P@ssw0rd",
            "timestamp": "2026-03-02T12:05:00Z",
            "detection_method": "decoy_http",
        })

        alert_new_events = bus.events_of_type("alert.new")
        assert len(alert_new_events) == 1
        assert alert_new_events[0]["severity"] == Severity.CRITICAL.value


class TestScanConnection:
    """A minimal decoy.trip (e.g. from an nmap scan) with no request path."""

    @pytest.mark.asyncio
    async def test_minimal_payload(self, handler, bus, db):
        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.7",
            "source_port": 60000,
            "dest_port": 3000,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:10:00Z",
        })

        async with db.execute("SELECT * FROM home_alerts") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"])
        assert detail["dest_port"] == 3000
        assert "request_path" not in detail


class TestDeviceEnrichment:
    """When a known device trips a decoy, alert is enriched with MAC/hostname/vendor."""

    @pytest.mark.asyncio
    async def test_enriches_with_device_info(self, handler, bus, db):
        # Seed a device record for the source IP
        await db.execute(
            """INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type,
               first_seen, last_seen, is_online)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("10.0.0.5", "AA:BB:CC:DD:EE:FF", "intruder-laptop", "EvilCorp",
             "unknown", "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", 1),
        )
        await db.execute(
            "INSERT INTO device_trust (device_id, status, updated_at) VALUES (last_insert_rowid(), 'unknown', ?)",
            ("2026-03-02T00:00:00Z",),
        )
        await db.commit()

        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 8080,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
        })

        async with db.execute("SELECT * FROM home_alerts") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 1
        row = rows[0]
        assert row["source_mac"] == "AA:BB:CC:DD:EE:FF"
        assert row["device_id"] is not None

        detail = json.loads(row["detail"])
        assert detail["hostname"] == "intruder-laptop"
        assert detail["vendor"] == "EvilCorp"

    @pytest.mark.asyncio
    async def test_unknown_device_has_no_mac(self, handler, bus, db):
        """Source IP not in devices table: source_mac and device_id should be NULL."""
        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.99",
            "source_port": 54321,
            "dest_port": 8080,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
        })

        async with db.execute("SELECT * FROM home_alerts") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 1
        row = rows[0]
        assert row["source_mac"] is None
        assert row["device_id"] is None


class TestDecoyIdPropagation:
    """decoy_id from the event payload should be stored in the alert."""

    @pytest.mark.asyncio
    async def test_stores_decoy_id(self, handler, bus, db):
        # Seed a decoy record
        await db.execute(
            """INSERT INTO decoys (name, decoy_type, bind_address, port, status, config,
               connection_count, credential_trip_count, failure_count, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("test-decoy", "file_share", "192.168.1.200", 445, "active", "{}",
             0, 0, 0, "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z"),
        )
        await db.commit()

        # Get the decoy ID
        async with db.execute("SELECT id FROM decoys WHERE name = 'test-decoy'") as cur:
            decoy_row = await cur.fetchone()
        decoy_id = decoy_row["id"]

        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 445,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
            "decoy_id": decoy_id,
            "decoy_name": "test-decoy",
        })

        async with db.execute("SELECT * FROM home_alerts") as cur:
            rows = await cur.fetchall()

        assert len(rows) == 1
        row = rows[0]
        assert row["decoy_id"] == decoy_id

        detail = json.loads(row["detail"])
        assert detail["decoy_name"] == "test-decoy"

    @pytest.mark.asyncio
    async def test_alert_new_includes_source_mac(self, handler, bus, db):
        """The alert.new event should include source_mac when device is known."""
        await db.execute(
            """INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type,
               first_seen, last_seen, is_online)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("10.0.0.5", "11:22:33:44:55:66", "scanner", "ScanCo",
             "unknown", "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", 1),
        )
        await db.execute(
            "INSERT INTO device_trust (device_id, status, updated_at) VALUES (last_insert_rowid(), 'unknown', ?)",
            ("2026-03-02T00:00:00Z",),
        )
        await db.commit()

        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 8080,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:00:00Z",
        })

        alert_new_events = bus.events_of_type("alert.new")
        assert len(alert_new_events) == 1
        assert alert_new_events[0]["source_mac"] == "11:22:33:44:55:66"


class TestNoIncidentGrouper:
    """Handler works without an incident grouper."""

    @pytest.mark.asyncio
    async def test_no_grouper(self, db, bus):
        handler = DecoyAlertHandler(db=db, event_bus=bus, incident_grouper=None)
        handler.subscribe_to(bus)

        await bus.deliver("decoy.trip", {
            "source_ip": "10.0.0.1",
            "source_port": 55555,
            "dest_port": 8123,
            "protocol": "tcp",
            "timestamp": "2026-03-02T12:15:00Z",
        })

        async with db.execute("SELECT COUNT(*) as cnt FROM home_alerts") as cur:
            row = await cur.fetchone()

        assert row["cnt"] == 1
