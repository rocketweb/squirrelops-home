"""Tests for connection baseline collection and anomaly detection."""

from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite
import pytest

from squirrelops_home_sensor.db.schema import SCHEMA_V1_SQL
from squirrelops_home_sensor.db.queries import get_device_baseline, has_baseline
from squirrelops_home_sensor.devices.baseline import AnomalyDetector, BaselineCollector


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
async def db():
    """In-memory SQLite DB with full schema and a test device."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.executescript(SCHEMA_V1_SQL)
        await conn.execute(
            """INSERT INTO devices
               (id, ip_address, mac_address, hostname, device_type, first_seen, last_seen)
               VALUES (1, '192.168.1.100', 'AA:BB:CC:DD:EE:FF', 'test-device',
                       'unknown', ?, ?)""",
            (_now_iso(), _now_iso()),
        )
        await conn.commit()
        yield conn


# ---------------------------------------------------------------------------
# BaselineCollector tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collector_records_destinations(db):
    """Records 2 destinations and verifies both appear in the baseline."""
    collector = BaselineCollector(db=db)
    count = await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443), ("10.0.0.2", 80)],
    )
    assert count == 2

    baseline = await get_device_baseline(db, 1)
    assert ("10.0.0.1", 443) in baseline
    assert ("10.0.0.2", 80) in baseline
    assert len(baseline) == 2


@pytest.mark.asyncio
async def test_collector_deduplicates(db):
    """Same destination recorded twice results in a single baseline entry."""
    collector = BaselineCollector(db=db)
    await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
    )
    await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
    )

    baseline = await get_device_baseline(db, 1)
    assert len(baseline) == 1
    assert ("10.0.0.1", 443) in baseline


# ---------------------------------------------------------------------------
# has_baseline tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_has_baseline_false_when_empty(db):
    """No recordings means has_baseline returns False."""
    result = await has_baseline(db, 1)
    assert result is False


@pytest.mark.asyncio
async def test_has_baseline_true_after_recording(db):
    """After recording a destination, has_baseline returns True."""
    collector = BaselineCollector(db=db)
    await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
    )
    result = await has_baseline(db, 1)
    assert result is True


# ---------------------------------------------------------------------------
# AnomalyDetector tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detector_no_anomaly_for_known_destination(db):
    """A destination in the baseline produces no anomaly."""
    collector = BaselineCollector(db=db)
    await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
    )

    detector = AnomalyDetector(db=db)
    anomalies = await detector.check_device(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
        source_ip="192.168.1.100",
    )
    assert anomalies == []


@pytest.mark.asyncio
async def test_detector_anomaly_for_new_destination(db):
    """A destination not in the baseline produces an anomaly with correct fields."""
    collector = BaselineCollector(db=db)
    await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
    )

    detector = AnomalyDetector(db=db)
    anomalies = await detector.check_device(
        device_id=1,
        destinations=[("10.0.0.99", 8080)],
        source_ip="192.168.1.100",
        source_mac="AA:BB:CC:DD:EE:FF",
    )
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly["dest_ip"] == "10.0.0.99"
    assert anomaly["dest_port"] == 8080
    assert anomaly["device_id"] == 1
    assert "alert_id" in anomaly


@pytest.mark.asyncio
async def test_detector_skips_device_without_baseline(db):
    """A device with no baseline produces no anomalies (not yet learned)."""
    detector = AnomalyDetector(db=db)
    anomalies = await detector.check_device(
        device_id=1,
        destinations=[("10.0.0.99", 8080)],
        source_ip="192.168.1.100",
    )
    assert anomalies == []


@pytest.mark.asyncio
async def test_detector_creates_alert_and_incident(db):
    """An anomaly creates both an alert and an incident in the DB."""
    collector = BaselineCollector(db=db)
    await collector.record_connections(
        device_id=1,
        destinations=[("10.0.0.1", 443)],
    )

    detector = AnomalyDetector(db=db)
    anomalies = await detector.check_device(
        device_id=1,
        destinations=[("10.0.0.99", 8080)],
        source_ip="192.168.1.100",
        source_mac="AA:BB:CC:DD:EE:FF",
    )
    assert len(anomalies) == 1
    alert_id = anomalies[0]["alert_id"]

    # Verify alert exists in DB
    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE id = ?", (alert_id,)
    )
    alert_row = await cursor.fetchone()
    assert alert_row is not None
    # Get column names for dict access
    columns = [desc[0] for desc in cursor.description]
    alert = dict(zip(columns, alert_row))
    assert alert["alert_type"] == "behavioral.anomaly"
    assert alert["severity"] == "medium"
    assert alert["device_id"] == 1
    assert alert["source_ip"] == "192.168.1.100"
    assert alert["source_mac"] == "AA:BB:CC:DD:EE:FF"
    assert "10.0.0.99:8080" in alert["title"]

    # Verify incident exists in DB
    incident_id = alert["incident_id"]
    assert incident_id is not None
    cursor = await db.execute(
        "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    )
    incident_row = await cursor.fetchone()
    assert incident_row is not None
    columns = [desc[0] for desc in cursor.description]
    incident = dict(zip(columns, incident_row))
    assert incident["severity"] == "medium"
    assert incident["source_ip"] == "192.168.1.100"
    assert "10.0.0.99:8080" in incident["summary"]
