"""Tests for DeviceReviewService."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest

from squirrelops_home_sensor.devices.review import DeviceReviewService


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@pytest.fixture
async def db():
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.executescript(
            """
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT NOT NULL DEFAULT 'unknown',
                custom_name TEXT,
                notes TEXT,
                is_online INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE device_trust (
                device_id INTEGER PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'unknown',
                approved_by TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE home_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT,
                source_ip TEXT,
                source_mac TEXT,
                device_id INTEGER,
                decoy_id INTEGER,
                event_seq INTEGER,
                read_at TEXT,
                actioned_at TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        yield conn


@pytest.mark.asyncio
async def test_no_reminders_for_recent_devices(db):
    """Devices first seen less than 24h ago should not get reminders."""
    now = datetime.now(timezone.utc)
    await db.execute(
        "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (1, "192.168.1.10", "unknown", _iso(now - timedelta(hours=12)), _iso(now)),
    )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count = await svc.check_for_reviews()
    assert count == 0


@pytest.mark.asyncio
async def test_reminder_created_for_old_unknown_device(db):
    """Devices >24h old with no trust row should get a reminder."""
    now = datetime.now(timezone.utc)
    await db.execute(
        "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (1, "192.168.1.10", "unknown", _iso(now - timedelta(hours=25)), _iso(now)),
    )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count = await svc.check_for_reviews()
    assert count == 1

    # Verify alert was created
    cursor = await db.execute("SELECT * FROM home_alerts WHERE alert_type = 'device.review_reminder'")
    rows = await cursor.fetchall()
    assert len(rows) == 1
    assert rows[0]["device_id"] == 1
    assert rows[0]["severity"] == "low"


@pytest.mark.asyncio
async def test_no_reminder_for_approved_device(db):
    """Devices with trust status 'approved' should not get reminders."""
    now = datetime.now(timezone.utc)
    await db.execute(
        "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (1, "192.168.1.10", "unknown", _iso(now - timedelta(hours=25)), _iso(now)),
    )
    await db.execute(
        "INSERT INTO device_trust (device_id, status, updated_at) VALUES (?, ?, ?)",
        (1, "approved", _iso(now)),
    )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count = await svc.check_for_reviews()
    assert count == 0


@pytest.mark.asyncio
async def test_no_reminder_for_rejected_device(db):
    """Devices with trust status 'rejected' should not get reminders."""
    now = datetime.now(timezone.utc)
    await db.execute(
        "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (1, "192.168.1.10", "unknown", _iso(now - timedelta(hours=25)), _iso(now)),
    )
    await db.execute(
        "INSERT INTO device_trust (device_id, status, updated_at) VALUES (?, ?, ?)",
        (1, "rejected", _iso(now)),
    )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count = await svc.check_for_reviews()
    assert count == 0


@pytest.mark.asyncio
async def test_idempotent_no_duplicate_reminders(db):
    """Running check_for_reviews twice should not create duplicate reminders."""
    now = datetime.now(timezone.utc)
    await db.execute(
        "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (1, "192.168.1.10", "unknown", _iso(now - timedelta(hours=25)), _iso(now)),
    )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count1 = await svc.check_for_reviews()
    count2 = await svc.check_for_reviews()
    assert count1 == 1
    assert count2 == 0

    cursor = await db.execute("SELECT COUNT(*) FROM home_alerts WHERE alert_type = 'device.review_reminder'")
    row = await cursor.fetchone()
    assert row[0] == 1


@pytest.mark.asyncio
async def test_multiple_devices_get_individual_reminders(db):
    """Each uncategorized device should get its own reminder."""
    now = datetime.now(timezone.utc)
    for i in range(3):
        await db.execute(
            "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (i + 1, f"192.168.1.{10 + i}", "unknown", _iso(now - timedelta(hours=30)), _iso(now)),
        )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count = await svc.check_for_reviews()
    assert count == 3


@pytest.mark.asyncio
async def test_explicit_unknown_trust_still_gets_reminder(db):
    """Devices with explicit trust status 'unknown' should still get reminders."""
    now = datetime.now(timezone.utc)
    await db.execute(
        "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (1, "192.168.1.10", "unknown", _iso(now - timedelta(hours=25)), _iso(now)),
    )
    await db.execute(
        "INSERT INTO device_trust (device_id, status, updated_at) VALUES (?, ?, ?)",
        (1, "unknown", _iso(now - timedelta(hours=25))),
    )
    await db.commit()

    svc = DeviceReviewService(db=db)
    count = await svc.check_for_reviews()
    assert count == 1
