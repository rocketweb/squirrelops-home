"""Tests for SecurityInsightAnalyzer -- alert generation from port scan data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import aiosqlite
import pytest

from squirrelops_home_sensor.alerts.types import AlertType, Severity
from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.security.analyzer import SecurityInsightAnalyzer


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def _insert_test_device(
    db: aiosqlite.Connection,
    device_id: int = 1,
    ip_address: str = "192.168.1.100",
    mac_address: str = "AA:BB:CC:DD:EE:FF",
    device_type: str = "smart_speaker",
    hostname: str = "test-device",
) -> int:
    """Insert a test device into the devices and device_trust tables.

    Returns the device_id.
    """
    now = _now_iso()
    await db.execute(
        """INSERT INTO devices
           (id, ip_address, mac_address, hostname, device_type, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (device_id, ip_address, mac_address, hostname, device_type, now, now),
    )
    await db.execute(
        """INSERT INTO device_trust (device_id, status, updated_at)
           VALUES (?, 'unknown', ?)""",
        (device_id, now),
    )
    await db.commit()
    return device_id


@pytest.fixture
async def db():
    """In-memory SQLite DB with full schema (V1-V4 migrations applied)."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await apply_migrations(conn)
        yield conn


@pytest.fixture
def mock_event_bus() -> AsyncMock:
    """AsyncMock event bus with a publish method that returns a sequence number."""
    bus = AsyncMock()
    bus.publish = AsyncMock(return_value=1)
    return bus


# ---------------------------------------------------------------------------
# Test 1: analyze_device creates alert for risky port
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_device_creates_alert_for_risky_port(db, mock_event_bus):
    """Analyzing a device with Telnet open should INSERT a row into home_alerts."""
    await _insert_test_device(db, device_id=1, device_type="smart_speaker")
    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    new_count = await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )

    assert new_count == 1

    # Verify the alert row was inserted
    cursor = await db.execute("SELECT * FROM home_alerts WHERE device_id = 1")
    row = await cursor.fetchone()
    assert row is not None
    assert row["alert_type"] == AlertType.SECURITY_PORT_RISK.value
    assert row["severity"] == Severity.HIGH.value
    assert "Telnet" in row["title"]
    assert row["source_ip"] == "192.168.1.100"
    assert row["source_mac"] == "AA:BB:CC:DD:EE:FF"

    # Verify detail JSON contains expected fields
    detail = json.loads(row["detail"])
    assert detail["port"] == 23
    assert detail["service_name"] == "Telnet"
    assert "remediation_steps" in detail


# ---------------------------------------------------------------------------
# Test 2: Deduplication -- same device+port does not create duplicate alert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deduplication_prevents_duplicate_alerts(db, mock_event_bus):
    """Running analyze_device twice for the same port should only create one alert."""
    await _insert_test_device(db, device_id=1, device_type="smart_speaker")
    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    first_count = await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )
    assert first_count == 1

    second_count = await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )
    assert second_count == 0

    # Verify the insight_state row exists and has no resolved_at
    cursor = await db.execute(
        "SELECT * FROM security_insight_state WHERE device_id = 1"
    )
    rows = await cursor.fetchall()
    assert len(rows) == 1
    assert rows[0]["insight_key"] == "risky_port:23"
    assert rows[0]["resolved_at"] is None

    # Verify only one alert in home_alerts
    cursor = await db.execute("SELECT COUNT(*) as cnt FROM home_alerts WHERE device_id = 1")
    row = await cursor.fetchone()
    assert row["cnt"] == 1


# ---------------------------------------------------------------------------
# Test 3: Resolution -- when port closes, resolved_at is set
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolution_sets_resolved_at_when_port_closes(db, mock_event_bus):
    """When a previously risky port is no longer open, resolved_at should be set."""
    await _insert_test_device(db, device_id=1, device_type="smart_speaker")
    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # First scan: port 23 open
    await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )

    # Verify not resolved yet
    cursor = await db.execute(
        "SELECT resolved_at FROM security_insight_state "
        "WHERE device_id = 1 AND insight_key = 'risky_port:23'"
    )
    row = await cursor.fetchone()
    assert row["resolved_at"] is None

    # Second scan: port 23 no longer open
    await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset(),
        display_name="Living Room Speaker",
    )

    # Verify resolved_at is now set
    cursor = await db.execute(
        "SELECT resolved_at FROM security_insight_state "
        "WHERE device_id = 1 AND insight_key = 'risky_port:23'"
    )
    row = await cursor.fetchone()
    assert row["resolved_at"] is not None


# ---------------------------------------------------------------------------
# Test 4: No re-alerting -- resolved insight does NOT create a new alert
# when port reappears (device went offline and came back).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_re_alerting_after_resolution(db, mock_event_bus):
    """A resolved insight should NOT produce a second alert when the port
    reappears -- one notification per device+port is enough."""
    await _insert_test_device(db, device_id=1, device_type="smart_speaker")
    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: port 23 open -> alert created
    count1 = await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )
    assert count1 == 1

    # Scan 2: port 23 closed -> insight resolved
    await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset(),
        display_name="Living Room Speaker",
    )

    # Scan 3: port 23 reopened -> NO new alert (already notified once)
    count3 = await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )
    assert count3 == 0

    # Still only one alert in home_alerts
    cursor = await db.execute(
        "SELECT COUNT(*) as cnt FROM home_alerts WHERE device_id = 1"
    )
    row = await cursor.fetchone()
    assert row["cnt"] == 1

    # Insight state was reactivated (resolved_at cleared back to NULL)
    cursor = await db.execute(
        "SELECT resolved_at FROM security_insight_state "
        "WHERE device_id = 1 AND insight_key = 'risky_port:23'"
    )
    row = await cursor.fetchone()
    assert row["resolved_at"] is None


# ---------------------------------------------------------------------------
# Test 5: analyze_all_devices returns correct count of new alerts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_all_devices_returns_total_new_alerts(db, mock_event_bus):
    """analyze_all_devices should return the sum of new alerts across all devices."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )
    await _insert_test_device(
        db, device_id=2, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:02", device_type="camera",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    devices = [
        {
            "device_id": 1,
            "ip_address": "192.168.1.100",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "device_type": "smart_speaker",
            "open_ports": frozenset({23}),  # Telnet -- 1 finding
            "display_name": "Speaker",
        },
        {
            "device_id": 2,
            "ip_address": "192.168.1.101",
            "mac_address": "AA:BB:CC:DD:EE:02",
            "device_type": "camera",
            "open_ports": frozenset({21, 80}),  # FTP + unencrypted admin -- 2 findings
            "display_name": "Front Camera",
        },
    ]

    total = await analyzer.analyze_all_devices(devices)
    assert total == 3

    # Verify per-device alert counts
    cursor = await db.execute(
        "SELECT COUNT(*) as cnt FROM home_alerts WHERE device_id = 1"
    )
    assert (await cursor.fetchone())["cnt"] == 1

    cursor = await db.execute(
        "SELECT COUNT(*) as cnt FROM home_alerts WHERE device_id = 2"
    )
    assert (await cursor.fetchone())["cnt"] == 2


# ---------------------------------------------------------------------------
# Test 6: Event bus publishes alert.new event when alert is created
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_bus_publishes_alert_new_on_creation(db, mock_event_bus):
    """Creating an alert should publish an 'alert.new' event via the event bus."""
    await _insert_test_device(db, device_id=1, device_type="smart_speaker")
    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    await analyzer.analyze_device(
        device_id=1,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="smart_speaker",
        open_ports=frozenset({23}),
        display_name="Living Room Speaker",
    )

    # Verify publish was called exactly once with the right event type
    mock_event_bus.publish.assert_called_once()
    call_args = mock_event_bus.publish.call_args

    # First positional arg is the event type
    assert call_args[0][0] == "alert.new"

    # Second positional arg is the payload dict
    payload = call_args[0][1]
    assert payload["alert_type"] == AlertType.SECURITY_PORT_RISK.value
    assert payload["severity"] == Severity.HIGH.value
    assert "Telnet" in payload["title"]
    assert payload["source_ip"] == "192.168.1.100"
    assert payload["id"] is not None
    assert payload["incident_id"] is None
    assert payload["read_at"] is None
    assert payload["actioned_at"] is None

    # source_id kwarg should be the string device_id
    assert call_args[1]["source_id"] == "1"
