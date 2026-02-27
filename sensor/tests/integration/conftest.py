# sensor/tests/integration/conftest.py
import asyncio
import json
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest
import pytest_asyncio

from squirrelops_home_sensor.db.schema import create_all_tables
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.events.bus import EventBus


@pytest_asyncio.fixture
async def db():
    """Create an in-memory SQLite database with full schema."""
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON")
    await create_all_tables(conn)
    yield conn
    await conn.close()


@pytest.fixture
def event_bus(db):
    """Create a real EventBus backed by the test database."""
    log = EventLog(db)
    bus = EventBus(log)
    return bus


@pytest.fixture
def sensor_config():
    """Return a test sensor configuration dict."""
    return {
        "sensor_id": "test-sensor-001",
        "sensor_name": "SquirrelOps-TEST",
        "version": "0.1.0",
        "profile": "standard",
        "learning_mode": {
            "enabled": False,
            "started_at": "2026-02-20T00:00:00Z",
            "duration_hours": 48,
        },
        "scan_interval_seconds": 300,
        "max_decoys": 8,
        "alert_methods": {
            "log": {"enabled": True},
            "slack": {"enabled": False, "webhook_url": ""},
        },
        "subnet": "192.168.1.0/24",
    }


@pytest.fixture
def app(db, event_bus, sensor_config):
    """Create a FastAPI app with dependency overrides for testing."""
    from squirrelops_home_sensor.app import create_app
    from squirrelops_home_sensor.api.deps import get_db, get_event_bus, get_config, verify_client_cert

    application = create_app(sensor_config, ca_key=None, ca_cert=None)

    async def override_db():
        yield db

    async def override_event_bus():
        return event_bus

    async def override_config():
        return sensor_config

    async def override_auth():
        return {"client_name": "test-client", "fingerprint": "sha256:testfp"}

    application.dependency_overrides[get_db] = override_db
    application.dependency_overrides[get_event_bus] = override_event_bus
    application.dependency_overrides[get_config] = override_config
    application.dependency_overrides[verify_client_cert] = override_auth

    return application


@pytest.fixture
def client(app):
    """Create a TestClient for the FastAPI app."""
    from fastapi.testclient import TestClient
    return TestClient(app)


async def seed_devices(db, count=3):
    """Insert test devices into the database. Returns list of device IDs."""
    ids = []
    for i in range(1, count + 1):
        cursor = await db.execute(
            """INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type,
               first_seen, last_seen, is_online)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"192.168.1.{100 + i}",
                f"AA:BB:CC:DD:EE:{i:02X}",
                f"device-{i}",
                f"Vendor-{i}",
                "unknown",
                "2026-02-20T00:00:00Z",
                "2026-02-22T00:00:00Z",
                1,
            ),
        )
        device_id = cursor.lastrowid
        await db.execute(
            "INSERT INTO device_trust (device_id, status, updated_at) VALUES (?, 'unknown', ?)",
            (device_id, "2026-02-22T00:00:00Z"),
        )
        ids.append(device_id)
    await db.commit()
    return ids


async def seed_decoys(db, count=2):
    """Insert test decoys into the database. Returns list of decoy IDs."""
    ids = []
    decoy_types = ["dev_server", "file_share", "home_assistant"]
    for i in range(1, count + 1):
        cursor = await db.execute(
            """INSERT INTO decoys (name, decoy_type, bind_address, port, status, config,
               connection_count, credential_trip_count, failure_count, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"decoy-{i}",
                decoy_types[i % len(decoy_types)],
                "192.168.1.200",
                8080 + i,
                "active",
                json.dumps({"banner": f"test-banner-{i}"}),
                i * 5,
                i,
                0,
                "2026-02-20T00:00:00Z",
                "2026-02-22T00:00:00Z",
            ),
        )
        ids.append(cursor.lastrowid)
    await db.commit()
    return ids


async def seed_alerts(db, count=3, incident_id=None):
    """Insert test alerts into the database. Returns list of alert IDs."""
    ids = []
    severities = ["critical", "high", "medium", "low"]
    alert_types = ["decoy_trip", "credential_trip", "new_device", "device_verification"]
    for i in range(1, count + 1):
        cursor = await db.execute(
            """INSERT INTO home_alerts (incident_id, alert_type, severity, title, detail,
               source_ip, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                incident_id,
                alert_types[i % len(alert_types)],
                severities[i % len(severities)],
                f"Test Alert {i}",
                json.dumps({"info": f"detail-{i}"}),
                f"192.168.1.{50 + i}",
                f"2026-02-22T{i:02d}:00:00Z",
            ),
        )
        ids.append(cursor.lastrowid)
    await db.commit()
    return ids


async def seed_incidents(db):
    """Insert a test incident with child alerts. Returns (incident_id, alert_ids)."""
    cursor = await db.execute(
        """INSERT INTO incidents (source_ip, source_mac, status, severity, alert_count,
           first_alert_at, last_alert_at, summary)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "192.168.1.99",
            "FF:FF:FF:FF:FF:01",
            "active",
            "high",
            3,
            "2026-02-22T01:00:00Z",
            "2026-02-22T01:10:00Z",
            "3 events from 192.168.1.99 over 10 minutes: decoy trip, credential trip",
        ),
    )
    incident_id = cursor.lastrowid
    alert_ids = await seed_alerts(db, count=3, incident_id=incident_id)
    return incident_id, alert_ids


async def seed_pairing(db):
    """Insert a test pairing record. Returns pairing ID."""
    cursor = await db.execute(
        """INSERT INTO pairing (client_name, client_cert_fingerprint, is_local, paired_at)
           VALUES (?, ?, ?, ?)""",
        ("test-client", "sha256:testfp", 0, "2026-02-22T00:00:00Z"),
    )
    await db.commit()
    return cursor.lastrowid
