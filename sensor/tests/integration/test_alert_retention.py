"""Integration tests for the alert retention service.

The retention service runs daily and purges:
- home_alerts older than 90 days (unless linked to an active incident)
- events older than 90 days
- decoy_connections older than 90 days
- canary_observations older than 90 days
- closed incidents older than 90 days

Sequence numbers are never reused (AUTOINCREMENT).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest
import pytest_asyncio


# -- Schema ----------------------------------------------------------

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

CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    source_id TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE decoys (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    decoy_type TEXT NOT NULL,
    bind_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    config TEXT,
    connection_count INTEGER NOT NULL DEFAULT 0,
    credential_trip_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_failure_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE decoy_connections (
    id INTEGER PRIMARY KEY,
    decoy_id INTEGER NOT NULL REFERENCES decoys(id),
    source_ip TEXT NOT NULL,
    source_mac TEXT,
    port INTEGER NOT NULL,
    protocol TEXT,
    request_path TEXT,
    credential_used TEXT,
    credential_id INTEGER,
    event_seq INTEGER,
    timestamp TEXT NOT NULL
);

CREATE TABLE planted_credentials (
    id INTEGER PRIMARY KEY,
    credential_type TEXT NOT NULL,
    credential_value TEXT NOT NULL,
    canary_hostname TEXT,
    planted_location TEXT NOT NULL,
    decoy_id INTEGER,
    tripped INTEGER NOT NULL DEFAULT 0,
    first_tripped_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE canary_observations (
    id INTEGER PRIMARY KEY,
    credential_id INTEGER NOT NULL REFERENCES planted_credentials(id),
    canary_hostname TEXT NOT NULL,
    queried_by_ip TEXT NOT NULL,
    queried_by_mac TEXT,
    event_seq INTEGER,
    observed_at TEXT NOT NULL
);
"""


def _iso_at(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@pytest_asyncio.fixture
async def db():
    """In-memory SQLite database with full schema."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn


NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(days=100)  # 100 days ago -- beyond 90-day retention
RECENT = NOW - timedelta(days=30)  # 30 days ago -- within retention


# -- Helpers ---------------------------------------------------------

async def _insert_alert(
    db: aiosqlite.Connection,
    *,
    incident_id: int | None = None,
    alert_type: str = "decoy.trip",
    severity: str = "high",
    created_at: datetime = RECENT,
) -> int:
    cursor = await db.execute(
        """INSERT INTO home_alerts
           (incident_id, alert_type, severity, title, detail, created_at)
           VALUES (?, ?, ?, 'Test', 'Detail', ?)""",
        (incident_id, alert_type, severity, _iso_at(created_at)),
    )
    await db.commit()
    return cursor.lastrowid


async def _insert_event(
    db: aiosqlite.Connection,
    *,
    event_type: str = "decoy.trip",
    created_at: datetime = RECENT,
) -> int:
    cursor = await db.execute(
        """INSERT INTO events (event_type, payload, created_at)
           VALUES (?, '{}', ?)""",
        (event_type, _iso_at(created_at)),
    )
    await db.commit()
    return cursor.lastrowid


async def _insert_decoy(db: aiosqlite.Connection) -> int:
    cursor = await db.execute(
        """INSERT INTO decoys
           (name, decoy_type, bind_address, port, status, connection_count,
            credential_trip_count, failure_count, created_at, updated_at)
           VALUES ('fake-nas', 'file_share', '0.0.0.0', 8445, 'active',
                   0, 0, 0, ?, ?)""",
        (_iso_at(NOW), _iso_at(NOW)),
    )
    await db.commit()
    return cursor.lastrowid


async def _insert_decoy_connection(
    db: aiosqlite.Connection,
    *,
    decoy_id: int,
    timestamp: datetime = RECENT,
) -> int:
    cursor = await db.execute(
        """INSERT INTO decoy_connections
           (decoy_id, source_ip, port, timestamp)
           VALUES (?, '192.168.1.99', 8445, ?)""",
        (decoy_id, _iso_at(timestamp)),
    )
    await db.commit()
    return cursor.lastrowid


async def _insert_credential(db: aiosqlite.Connection) -> int:
    cursor = await db.execute(
        """INSERT INTO planted_credentials
           (credential_type, credential_value, planted_location, created_at)
           VALUES ('aws_key', 'AKIAIOSFODNN7EXAMPLE', 'passwords.txt', ?)""",
        (_iso_at(NOW),),
    )
    await db.commit()
    return cursor.lastrowid


async def _insert_canary_observation(
    db: aiosqlite.Connection,
    *,
    credential_id: int,
    observed_at: datetime = RECENT,
) -> int:
    cursor = await db.execute(
        """INSERT INTO canary_observations
           (credential_id, canary_hostname, queried_by_ip, observed_at)
           VALUES (?, 'abc123.canary.squirrelops.io', '192.168.1.99', ?)""",
        (credential_id, _iso_at(observed_at)),
    )
    await db.commit()
    return cursor.lastrowid


async def _insert_incident(
    db: aiosqlite.Connection,
    *,
    status: str = "active",
    first_alert_at: datetime = RECENT,
    last_alert_at: datetime = RECENT,
    closed_at: datetime | None = None,
) -> int:
    cursor = await db.execute(
        """INSERT INTO incidents
           (source_ip, status, severity, alert_count,
            first_alert_at, last_alert_at, closed_at, summary)
           VALUES ('192.168.1.99', ?, 'high', 1, ?, ?, ?, 'Test incident')""",
        (
            status,
            _iso_at(first_alert_at),
            _iso_at(last_alert_at),
            _iso_at(closed_at) if closed_at else None,
        ),
    )
    await db.commit()
    return cursor.lastrowid


async def _count(db: aiosqlite.Connection, table: str) -> int:
    async with db.execute(f"SELECT COUNT(*) as cnt FROM {table}") as cur:
        row = await cur.fetchone()
    return row["cnt"]


# -- Tests -----------------------------------------------------------


class TestAlertPurge:
    """Alerts older than 90 days are purged."""

    @pytest.mark.asyncio
    async def test_purges_old_standalone_alerts(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        await _insert_alert(db, created_at=OLD)  # 100 days old -- purge
        await _insert_alert(db, created_at=RECENT)  # 30 days old -- keep

        result = await service.purge()

        assert result.alerts_purged == 1
        assert await _count(db, "home_alerts") == 1

    @pytest.mark.asyncio
    async def test_preserves_alerts_linked_to_active_incidents(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        # Create an active incident
        incident_id = await _insert_incident(
            db,
            status="active",
            first_alert_at=OLD,
            last_alert_at=OLD,
        )

        # Old alert linked to active incident -- should be preserved
        await _insert_alert(db, incident_id=incident_id, created_at=OLD)
        # Old standalone alert -- should be purged
        await _insert_alert(db, created_at=OLD)

        result = await service.purge()

        assert result.alerts_purged == 1
        assert await _count(db, "home_alerts") == 1

        # The remaining alert should be the one linked to the active incident
        async with db.execute("SELECT incident_id FROM home_alerts") as cur:
            row = await cur.fetchone()
        assert row["incident_id"] == incident_id

    @pytest.mark.asyncio
    async def test_purges_alerts_linked_to_closed_incidents(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        # Create a closed incident
        incident_id = await _insert_incident(
            db,
            status="closed",
            first_alert_at=OLD,
            last_alert_at=OLD,
            closed_at=OLD,
        )

        # Old alert linked to closed incident -- should be purged
        await _insert_alert(db, incident_id=incident_id, created_at=OLD)

        result = await service.purge()

        assert result.alerts_purged == 1
        assert await _count(db, "home_alerts") == 0


class TestEventPurge:
    """Events older than 90 days are purged."""

    @pytest.mark.asyncio
    async def test_purges_old_events(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        await _insert_event(db, created_at=OLD)
        await _insert_event(db, created_at=RECENT)

        result = await service.purge()

        assert result.events_purged == 1
        assert await _count(db, "events") == 1

    @pytest.mark.asyncio
    async def test_sequence_numbers_not_reused(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        # Insert and record the first seq
        seq1 = await _insert_event(db, created_at=OLD)

        await service.purge()

        # Insert a new event -- its seq must be higher than the purged one
        seq2 = await _insert_event(db, created_at=RECENT)
        assert seq2 > seq1


class TestDecoyConnectionPurge:
    """Decoy connections older than 90 days are purged."""

    @pytest.mark.asyncio
    async def test_purges_old_decoy_connections(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        decoy_id = await _insert_decoy(db)
        await _insert_decoy_connection(db, decoy_id=decoy_id, timestamp=OLD)
        await _insert_decoy_connection(db, decoy_id=decoy_id, timestamp=RECENT)

        result = await service.purge()

        assert result.decoy_connections_purged == 1
        assert await _count(db, "decoy_connections") == 1


class TestCanaryObservationPurge:
    """Canary observations older than 90 days are purged."""

    @pytest.mark.asyncio
    async def test_purges_old_canary_observations(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        cred_id = await _insert_credential(db)
        await _insert_canary_observation(db, credential_id=cred_id, observed_at=OLD)
        await _insert_canary_observation(db, credential_id=cred_id, observed_at=RECENT)

        result = await service.purge()

        assert result.canary_observations_purged == 1
        assert await _count(db, "canary_observations") == 1


class TestClosedIncidentPurge:
    """Closed incidents older than 90 days are purged (with their child alerts)."""

    @pytest.mark.asyncio
    async def test_purges_old_closed_incidents(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        # Old closed incident
        old_incident_id = await _insert_incident(
            db,
            status="closed",
            first_alert_at=OLD,
            last_alert_at=OLD,
            closed_at=OLD,
        )
        await _insert_alert(db, incident_id=old_incident_id, created_at=OLD)

        # Recent closed incident -- keep
        recent_incident_id = await _insert_incident(
            db,
            status="closed",
            first_alert_at=RECENT,
            last_alert_at=RECENT,
            closed_at=RECENT,
        )
        await _insert_alert(db, incident_id=recent_incident_id, created_at=RECENT)

        result = await service.purge()

        assert result.incidents_purged == 1
        assert await _count(db, "incidents") == 1

        # The remaining incident should be the recent one
        async with db.execute("SELECT id FROM incidents") as cur:
            row = await cur.fetchone()
        assert row["id"] == recent_incident_id

    @pytest.mark.asyncio
    async def test_preserves_active_incidents_even_if_old(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        # Active incident that is old -- preserve
        await _insert_incident(
            db,
            status="active",
            first_alert_at=OLD,
            last_alert_at=OLD,
        )

        result = await service.purge()

        assert result.incidents_purged == 0
        assert await _count(db, "incidents") == 1


class TestPurgeResult:
    """The purge result reports counts for all categories."""

    @pytest.mark.asyncio
    async def test_purge_result_aggregates_all_counts(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        # Set up one old item in each category
        await _insert_alert(db, created_at=OLD)
        await _insert_event(db, created_at=OLD)
        decoy_id = await _insert_decoy(db)
        await _insert_decoy_connection(db, decoy_id=decoy_id, timestamp=OLD)
        cred_id = await _insert_credential(db)
        await _insert_canary_observation(db, credential_id=cred_id, observed_at=OLD)

        result = await service.purge()

        assert result.alerts_purged == 1
        assert result.events_purged == 1
        assert result.decoy_connections_purged == 1
        assert result.canary_observations_purged == 1
        assert result.total_purged >= 4

    @pytest.mark.asyncio
    async def test_purge_on_empty_database(self, db):
        from squirrelops_home_sensor.alerts.retention import AlertRetentionService

        service = AlertRetentionService(db=db, retention_days=90)

        result = await service.purge()

        assert result.alerts_purged == 0
        assert result.events_purged == 0
        assert result.decoy_connections_purged == 0
        assert result.canary_observations_purged == 0
        assert result.incidents_purged == 0
        assert result.total_purged == 0
