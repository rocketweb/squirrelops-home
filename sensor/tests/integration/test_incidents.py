"""Integration tests for session-based incident grouping.

Tests use a real SQLite database and a lightweight event bus stub.
The IncidentGrouper watches for alert.new events and groups alerts
from the same source_ip within a configurable time window into
parent incidents.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite
import pytest
import pytest_asyncio


# -- Lightweight event bus stub --------------------------------------

class StubEventBus:
    """Minimal event bus for testing. Tracks published events and allows
    subscribers to receive them."""

    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any]]] = []
        self._subscribers: dict[str, list[Any]] = {}
        self._next_seq = 1

    async def publish(self, event_type: str, payload: dict[str, Any]) -> int:
        seq = self._next_seq
        self._next_seq += 1
        self.published.append((event_type, payload))
        for cb in self._subscribers.get(event_type, []):
            await cb(event_type, payload, seq)
        for cb in self._subscribers.get("*", []):
            await cb(event_type, payload, seq)
        return seq

    def subscribe(self, event_types: list[str], callback: Any) -> None:
        for et in event_types:
            self._subscribers.setdefault(et, []).append(callback)

    def events_of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [p for t, p in self.published if t == event_type]


# -- Schema setup ----------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY,
    source_ip TEXT NOT NULL,
    source_mac TEXT,
    status TEXT NOT NULL CHECK(status IN ('active', 'closed')) DEFAULT 'active',
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    alert_count INTEGER NOT NULL DEFAULT 1,
    first_alert_at TEXT NOT NULL,
    last_alert_at TEXT NOT NULL,
    closed_at TEXT,
    summary TEXT
);
CREATE INDEX idx_incidents_source ON incidents(source_ip);
CREATE INDEX idx_incidents_active ON incidents(status) WHERE status = 'active';

CREATE TABLE home_alerts (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id),
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    source_ip TEXT,
    source_mac TEXT,
    device_id INTEGER,
    decoy_id INTEGER,
    read_at TEXT,
    actioned_at TEXT,
    event_seq INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_alerts_incident ON home_alerts(incident_id);

CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    source_id TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


@pytest_asyncio.fixture
async def db():
    """Create an in-memory SQLite database with the required schema."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn


@pytest_asyncio.fixture
async def event_bus():
    return StubEventBus()


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _iso_at(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# -- Helper to insert an alert row and drive the grouper -------------

async def _create_alert_via_grouper(
    grouper: Any,
    db: aiosqlite.Connection,
    *,
    alert_type: str,
    severity: str,
    title: str,
    detail: str,
    source_ip: str | None = None,
    source_mac: str | None = None,
    created_at: str | None = None,
) -> int:
    """Insert an alert row, then call the grouper to process it.
    Returns the alert id."""
    ts = created_at or _iso_now()
    cursor = await db.execute(
        """INSERT INTO home_alerts (alert_type, severity, title, detail,
           source_ip, source_mac, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (alert_type, severity, title, detail, source_ip, source_mac, ts),
    )
    alert_id = cursor.lastrowid
    await db.commit()
    await grouper.process_alert(alert_id)
    return alert_id


# -- Tests -----------------------------------------------------------


class TestSameSourceGrouping:
    """Alerts from the same source_ip within the window are grouped."""

    @pytest.mark.asyncio
    async def test_first_alert_creates_new_incident(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        alert_id = await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Connection to fake-nas:8445",
            source_ip="192.168.1.99",
        )

        # Verify incident was created
        async with db.execute("SELECT * FROM incidents") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1
        incident = rows[0]
        assert incident["source_ip"] == "192.168.1.99"
        assert incident["status"] == "active"
        assert incident["severity"] == "high"
        assert incident["alert_count"] == 1

        # Verify alert was linked to incident
        async with db.execute(
            "SELECT incident_id FROM home_alerts WHERE id = ?", (alert_id,)
        ) as cur:
            row = await cur.fetchone()
        assert row["incident_id"] == incident["id"]

        # Verify incident.new event was published
        incident_events = event_bus.events_of_type("incident.new")
        assert len(incident_events) == 1
        assert incident_events[0]["incident_id"] == incident["id"]

    @pytest.mark.asyncio
    async def test_second_alert_same_source_joins_existing_incident(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        now = datetime.now(timezone.utc)

        alert1_id = await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Connection to fake-nas:8445",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        alert2_id = await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.credential_trip",
            severity="critical",
            title="Credential used",
            detail="passwords.txt downloaded",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=3)),
        )

        # Only one incident should exist
        async with db.execute("SELECT * FROM incidents") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1
        incident = rows[0]
        assert incident["alert_count"] == 2

        # Both alerts linked to same incident
        async with db.execute(
            "SELECT incident_id FROM home_alerts WHERE id IN (?, ?) ORDER BY id",
            (alert1_id, alert2_id),
        ) as cur:
            alert_rows = await cur.fetchall()
        assert alert_rows[0]["incident_id"] == incident["id"]
        assert alert_rows[1]["incident_id"] == incident["id"]

        # incident.updated event should have been published
        updated_events = event_bus.events_of_type("incident.updated")
        assert len(updated_events) == 1
        assert updated_events[0]["incident_id"] == incident["id"]


class TestDifferentSourceSeparation:
    """Alerts from different source_ips create separate incidents."""

    @pytest.mark.asyncio
    async def test_different_ips_create_separate_incidents(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Connection from .99",
            source_ip="192.168.1.99",
        )

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="device.new",
            severity="medium",
            title="New device",
            detail="New device from .50",
            source_ip="192.168.1.50",
        )

        async with db.execute("SELECT * FROM incidents ORDER BY id") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 2
        assert rows[0]["source_ip"] == "192.168.1.99"
        assert rows[1]["source_ip"] == "192.168.1.50"


class TestWindowExpiry:
    """Alerts outside the incident window start a new incident."""

    @pytest.mark.asyncio
    async def test_alert_outside_window_creates_new_incident(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(
            db=db,
            event_bus=event_bus,
            incident_window_minutes=15,
        )

        now = datetime.now(timezone.utc)

        # First alert
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="First probe",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        # Second alert 20 minutes later -- outside the 15-minute window
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped again",
            detail="Second probe",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=20)),
        )

        async with db.execute("SELECT * FROM incidents ORDER BY id") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 2, "Expired window should create a second incident"
        assert rows[0]["source_ip"] == "192.168.1.99"
        assert rows[1]["source_ip"] == "192.168.1.99"
        assert rows[0]["alert_count"] == 1
        assert rows[1]["alert_count"] == 1

    @pytest.mark.asyncio
    async def test_alert_inside_window_extends_incident(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(
            db=db,
            event_bus=event_bus,
            incident_window_minutes=15,
        )

        now = datetime.now(timezone.utc)

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="First",
            detail="First",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        # 10 minutes later -- within window
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Second",
            detail="Second",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=10)),
        )

        # 22 minutes after first, but only 12 after second -- still within
        # the window of the *last* alert (sliding window)
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.credential_trip",
            severity="critical",
            title="Third",
            detail="Third",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=22)),
        )

        async with db.execute("SELECT * FROM incidents") as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1, "Window slides with each new alert"
        assert rows[0]["alert_count"] == 3


class TestSeverityEscalation:
    """Incident severity escalates to the maximum of its child alerts."""

    @pytest.mark.asyncio
    async def test_severity_escalates_from_medium_to_high(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        now = datetime.now(timezone.utc)

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="device.new",
            severity="medium",
            title="New device",
            detail="Detected",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        async with db.execute("SELECT severity FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["severity"] == "medium"

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Tripped",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=2)),
        )

        async with db.execute("SELECT severity FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["severity"] == "high"

    @pytest.mark.asyncio
    async def test_severity_does_not_deescalate(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        now = datetime.now(timezone.utc)

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.credential_trip",
            severity="critical",
            title="Credential used",
            detail="Cred used",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="device.new",
            severity="medium",
            title="New device",
            detail="Device seen",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=1)),
        )

        async with db.execute("SELECT severity FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["severity"] == "critical", "Severity should not downgrade"

    @pytest.mark.asyncio
    async def test_severity_escalates_through_all_levels(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        now = datetime.now(timezone.utc)

        # Start with medium
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="device.new",
            severity="medium",
            title="New device",
            detail="Detected",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        # Escalate to high
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Probed",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=1)),
        )

        # Escalate to critical
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.credential_trip",
            severity="critical",
            title="Credential used",
            detail="Cred used",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=2)),
        )

        async with db.execute("SELECT severity FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["severity"] == "critical"


class TestSummaryGeneration:
    """Incident summary is generated and updated as alerts accumulate."""

    @pytest.mark.asyncio
    async def test_single_alert_summary(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Connection to fake-nas",
            source_ip="192.168.1.99",
        )

        async with db.execute("SELECT summary FROM incidents") as cur:
            row = await cur.fetchone()
        summary = row["summary"]
        assert "192.168.1.99" in summary
        assert "1 event" in summary

    @pytest.mark.asyncio
    async def test_multi_alert_summary_includes_types_and_count(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        now = datetime.now(timezone.utc)

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="device.new",
            severity="medium",
            title="New device",
            detail="Detected",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped",
            detail="Probed",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=1)),
        )

        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.credential_trip",
            severity="critical",
            title="Credential used",
            detail="Cred used",
            source_ip="192.168.1.99",
            created_at=_iso_at(now + timedelta(minutes=2)),
        )

        async with db.execute("SELECT summary FROM incidents") as cur:
            row = await cur.fetchone()
        summary = row["summary"]
        assert "3 events" in summary
        assert "192.168.1.99" in summary
        # Should contain alert type names in chronological order
        assert "device.new" in summary
        assert "decoy.trip" in summary
        assert "decoy.credential_trip" in summary


class TestNoSourceIpStandalone:
    """Alerts without source_ip are standalone -- no incident grouping."""

    @pytest.mark.asyncio
    async def test_system_alert_no_incident(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        alert_id = await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="system.sensor_offline",
            severity="low",
            title="Sensor offline",
            detail="Lost connection",
            source_ip=None,
        )

        # No incidents created
        async with db.execute("SELECT COUNT(*) as cnt FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["cnt"] == 0

        # Alert remains unlinked
        async with db.execute(
            "SELECT incident_id FROM home_alerts WHERE id = ?", (alert_id,)
        ) as cur:
            row = await cur.fetchone()
        assert row["incident_id"] is None


class TestIncidentClosing:
    """Background closer marks incidents as closed after the close window."""

    @pytest.mark.asyncio
    async def test_close_stale_incidents(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(
            db=db,
            event_bus=event_bus,
            incident_close_window_minutes=30,
        )

        # Insert an incident that last had activity 45 minutes ago
        old_time = datetime.now(timezone.utc) - timedelta(minutes=45)
        await db.execute(
            """INSERT INTO incidents (source_ip, status, severity, alert_count,
               first_alert_at, last_alert_at, summary)
               VALUES (?, 'active', 'high', 2, ?, ?, '2 events from 192.168.1.99')""",
            ("192.168.1.99", _iso_at(old_time - timedelta(minutes=5)), _iso_at(old_time)),
        )
        await db.commit()

        closed_count = await grouper.close_stale_incidents()
        assert closed_count == 1

        async with db.execute("SELECT status, closed_at FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["status"] == "closed"
        assert row["closed_at"] is not None

    @pytest.mark.asyncio
    async def test_does_not_close_recent_incidents(self, db, event_bus):
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(
            db=db,
            event_bus=event_bus,
            incident_close_window_minutes=30,
        )

        # Insert an incident that last had activity 10 minutes ago
        recent_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        await db.execute(
            """INSERT INTO incidents (source_ip, status, severity, alert_count,
               first_alert_at, last_alert_at, summary)
               VALUES (?, 'active', 'high', 1, ?, ?, '1 event from 192.168.1.99')""",
            ("192.168.1.99", _iso_at(recent_time), _iso_at(recent_time)),
        )
        await db.commit()

        closed_count = await grouper.close_stale_incidents()
        assert closed_count == 0

        async with db.execute("SELECT status FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["status"] == "active"

    @pytest.mark.asyncio
    async def test_closed_incidents_are_immutable_to_new_alerts(self, db, event_bus):
        """New alerts from the same source after closure create a new incident."""
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        grouper = IncidentGrouper(db=db, event_bus=event_bus)

        now = datetime.now(timezone.utc)

        # Create and close an incident manually
        await db.execute(
            """INSERT INTO incidents (id, source_ip, status, severity, alert_count,
               first_alert_at, last_alert_at, closed_at, summary)
               VALUES (1, '192.168.1.99', 'closed', 'high', 1, ?, ?, ?,
                       '1 event from 192.168.1.99')""",
            (
                _iso_at(now - timedelta(hours=1)),
                _iso_at(now - timedelta(hours=1)),
                _iso_at(now - timedelta(minutes=30)),
            ),
        )
        await db.commit()

        # New alert from same source
        await _create_alert_via_grouper(
            grouper,
            db,
            alert_type="decoy.trip",
            severity="high",
            title="Decoy tripped again",
            detail="New probe",
            source_ip="192.168.1.99",
            created_at=_iso_at(now),
        )

        async with db.execute(
            "SELECT * FROM incidents ORDER BY id"
        ) as cur:
            rows = await cur.fetchall()
        assert len(rows) == 2, "Closed incident should not be reused"
        assert rows[0]["status"] == "closed"
        assert rows[1]["status"] == "active"
