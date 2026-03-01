"""Tests for SecurityInsightAnalyzer -- grouped alert generation from port scan data.

The analyzer produces ONE alert per issue type (e.g., "SSH open") listing all
affected devices, rather than one alert per device+port.
"""

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
    """Insert a test device into the devices and device_trust tables."""
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


def _make_device_dict(
    device_id: int,
    ip_address: str,
    mac_address: str,
    device_type: str,
    open_ports: frozenset[int],
    display_name: str,
) -> dict:
    """Build a device dict in the format expected by analyze_all_devices."""
    return {
        "device_id": device_id,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "device_type": device_type,
        "open_ports": open_ports,
        "display_name": display_name,
    }


@pytest.fixture
async def db():
    """In-memory SQLite DB with full schema (all migrations applied)."""
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
# Test 1: Grouping -- multiple devices with same port → 1 grouped alert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grouping_multiple_devices_same_port(db, mock_event_bus):
    """4 devices with SSH open should produce 1 grouped alert with device_count=4."""
    for i in range(1, 5):
        await _insert_test_device(
            db,
            device_id=i,
            ip_address=f"192.168.1.{100 + i}",
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            device_type="smart_speaker",
            hostname=f"speaker-{i}",
        )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)
    devices = [
        _make_device_dict(i, f"192.168.1.{100 + i}", f"AA:BB:CC:DD:EE:{i:02X}",
                          "smart_speaker", frozenset({22}), f"Speaker {i}")
        for i in range(1, 5)
    ]

    new_count = await analyzer.analyze_all_devices(devices)

    # Should create exactly 1 grouped alert
    assert new_count == 1

    # Verify the alert row
    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE issue_key IS NOT NULL"
    )
    rows = await cursor.fetchall()
    assert len(rows) == 1

    row = rows[0]
    assert row["issue_key"] == "port_risk:ssh:22"
    assert row["device_count"] == 4
    assert row["alert_type"] == AlertType.SECURITY_PORT_RISK.value
    assert row["severity"] == Severity.MEDIUM.value
    assert "SSH" in row["title"]
    assert "4 devices" in row["title"]
    assert row["risk_description"] is not None
    assert row["remediation"] is not None

    # Verify affected_devices JSON
    affected = json.loads(row["affected_devices"])
    assert len(affected) == 4
    device_ids = {d["device_id"] for d in affected}
    assert device_ids == {1, 2, 3, 4}


# ---------------------------------------------------------------------------
# Test 2: New device updates existing group (alert.updated event)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_device_updates_existing_group(db, mock_event_bus):
    """Adding a new device with the same issue should update the existing grouped alert."""
    for i in range(1, 4):
        await _insert_test_device(
            db, device_id=i,
            ip_address=f"192.168.1.{100 + i}",
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            device_type="smart_speaker",
        )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: 2 devices with Telnet
    devices_scan1 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({23}), "Speaker 2"),
    ]
    count1 = await analyzer.analyze_all_devices(devices_scan1)
    assert count1 == 1

    mock_event_bus.publish.reset_mock()

    # Scan 2: 3 devices with Telnet (device 3 added)
    devices_scan2 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({23}), "Speaker 2"),
        _make_device_dict(3, "192.168.1.103", "AA:BB:CC:DD:EE:03",
                          "smart_speaker", frozenset({23}), "Speaker 3"),
    ]
    count2 = await analyzer.analyze_all_devices(devices_scan2)
    # No NEW alerts — existing one was updated
    assert count2 == 0

    # Verify alert was updated in DB
    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE issue_key = 'port_risk:telnet:23'"
    )
    row = await cursor.fetchone()
    assert row["device_count"] == 3
    assert "3 devices" in row["title"]

    affected = json.loads(row["affected_devices"])
    assert len(affected) == 3

    # Verify alert.updated event was published
    mock_event_bus.publish.assert_called_once()
    event_type = mock_event_bus.publish.call_args[0][0]
    assert event_type == "alert.updated"
    payload = mock_event_bus.publish.call_args[0][1]
    assert payload["device_count"] == 3


# ---------------------------------------------------------------------------
# Test 3: Device removed from group when port closes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_removed_from_group(db, mock_event_bus):
    """When a device's risky port closes, it should be removed from the grouped alert."""
    for i in range(1, 4):
        await _insert_test_device(
            db, device_id=i,
            ip_address=f"192.168.1.{100 + i}",
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            device_type="smart_speaker",
        )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: 3 devices with FTP
    devices_scan1 = [
        _make_device_dict(i, f"192.168.1.{100 + i}", f"AA:BB:CC:DD:EE:{i:02X}",
                          "smart_speaker", frozenset({21}), f"Speaker {i}")
        for i in range(1, 4)
    ]
    await analyzer.analyze_all_devices(devices_scan1)

    # Scan 2: device 3 no longer has FTP open
    devices_scan2 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({21}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({21}), "Speaker 2"),
        _make_device_dict(3, "192.168.1.103", "AA:BB:CC:DD:EE:03",
                          "smart_speaker", frozenset(), "Speaker 3"),
    ]
    await analyzer.analyze_all_devices(devices_scan2)

    # Verify device 3 was pruned from affected_devices
    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE issue_key = 'port_risk:ftp:21'"
    )
    row = await cursor.fetchone()
    assert row["device_count"] == 2

    affected = json.loads(row["affected_devices"])
    device_ids = {d["device_id"] for d in affected}
    assert device_ids == {1, 2}

    # Verify insight_state for device 3 is resolved
    cursor = await db.execute(
        "SELECT resolved_at FROM security_insight_state "
        "WHERE device_id = 3 AND insight_key = 'risky_port:21'"
    )
    row = await cursor.fetchone()
    assert row is not None
    assert row["resolved_at"] is not None


# ---------------------------------------------------------------------------
# Test 4: Acknowledged alert not re-alerted (same devices)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledged_alert_not_re_alerted(db, mock_event_bus):
    """Acknowledging a grouped alert should NOT cause re-notification on next scan
    if the same devices still have the same ports open."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )
    await _insert_test_device(
        db, device_id=2, ip_address="192.168.1.102",
        mac_address="AA:BB:CC:DD:EE:02", device_type="smart_speaker",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)
    devices = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({23}), "Speaker 2"),
    ]

    # Scan 1: create alert
    await analyzer.analyze_all_devices(devices)

    # Acknowledge the alert
    cursor = await db.execute(
        "SELECT id FROM home_alerts WHERE issue_key = 'port_risk:telnet:23'"
    )
    alert_row = await cursor.fetchone()
    await db.execute(
        "UPDATE home_alerts SET read_at = ? WHERE id = ?",
        (_now_iso(), alert_row["id"]),
    )
    await db.commit()

    mock_event_bus.publish.reset_mock()

    # Scan 2: same devices, same ports — should NOT publish any event
    await analyzer.analyze_all_devices(devices)

    mock_event_bus.publish.assert_not_called()

    # read_at should still be set
    cursor = await db.execute(
        "SELECT read_at FROM home_alerts WHERE id = ?", (alert_row["id"],)
    )
    row = await cursor.fetchone()
    assert row["read_at"] is not None


# ---------------------------------------------------------------------------
# Test 5: Acknowledged alert un-acks when new device appears
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledged_alert_un_acks_on_new_device(db, mock_event_bus):
    """When a previously acknowledged grouped alert gets a new device, read_at
    should be cleared so the user is re-notified."""
    for i in range(1, 4):
        await _insert_test_device(
            db, device_id=i,
            ip_address=f"192.168.1.{100 + i}",
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            device_type="smart_speaker",
        )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: 2 devices with Telnet
    devices_scan1 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({23}), "Speaker 2"),
    ]
    await analyzer.analyze_all_devices(devices_scan1)

    # Acknowledge the alert
    cursor = await db.execute(
        "SELECT id FROM home_alerts WHERE issue_key = 'port_risk:telnet:23'"
    )
    alert_row = await cursor.fetchone()
    alert_id = alert_row["id"]
    await db.execute(
        "UPDATE home_alerts SET read_at = ? WHERE id = ?",
        (_now_iso(), alert_id),
    )
    await db.commit()

    mock_event_bus.publish.reset_mock()

    # Scan 2: 3 devices — device 3 is new
    devices_scan2 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({23}), "Speaker 2"),
        _make_device_dict(3, "192.168.1.103", "AA:BB:CC:DD:EE:03",
                          "smart_speaker", frozenset({23}), "Speaker 3"),
    ]
    await analyzer.analyze_all_devices(devices_scan2)

    # read_at should be cleared
    cursor = await db.execute(
        "SELECT read_at FROM home_alerts WHERE id = ?", (alert_id,)
    )
    row = await cursor.fetchone()
    assert row["read_at"] is None

    # alert.updated event should have been published
    mock_event_bus.publish.assert_called_once()
    event_type = mock_event_bus.publish.call_args[0][0]
    assert event_type == "alert.updated"
    payload = mock_event_bus.publish.call_args[0][1]
    assert payload["read_at"] is None
    assert payload["device_count"] == 3


# ---------------------------------------------------------------------------
# Test 6: Different issues produce separate alerts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_different_issues_produce_separate_alerts(db, mock_event_bus):
    """SSH and Telnet should produce 2 separate grouped alerts."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    devices = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({22, 23}), "Speaker 1"),
    ]

    new_count = await analyzer.analyze_all_devices(devices)
    assert new_count == 2

    # Verify two distinct grouped alerts
    cursor = await db.execute(
        "SELECT issue_key FROM home_alerts WHERE issue_key IS NOT NULL "
        "ORDER BY issue_key"
    )
    rows = await cursor.fetchall()
    issue_keys = {row["issue_key"] for row in rows}
    assert "port_risk:ssh:22" in issue_keys
    assert "port_risk:telnet:23" in issue_keys


# ---------------------------------------------------------------------------
# Test 7: Unencrypted admin ports are grouped into one alert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unencrypted_admin_ports_grouped(db, mock_event_bus):
    """Port 80 and 8080 on IoT devices should both be grouped under
    port_risk:unencrypted_admin as a single alert."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )
    await _insert_test_device(
        db, device_id=2, ip_address="192.168.1.102",
        mac_address="AA:BB:CC:DD:EE:02", device_type="camera",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    devices = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({80}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "camera", frozenset({8080}), "Front Camera"),
    ]

    new_count = await analyzer.analyze_all_devices(devices)

    # Should create 1 grouped alert (unencrypted admin) — not 2 separate ones
    assert new_count == 1

    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE issue_key = 'port_risk:unencrypted_admin'"
    )
    row = await cursor.fetchone()
    assert row is not None
    assert row["device_count"] == 2
    assert "2 devices" in row["title"]


# ---------------------------------------------------------------------------
# Test 8: Event bus publishes alert.new on grouped alert creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_bus_publishes_alert_new_on_creation(db, mock_event_bus):
    """Creating a grouped alert should publish an 'alert.new' event."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    devices = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
    ]

    await analyzer.analyze_all_devices(devices)

    # Verify publish was called with alert.new
    mock_event_bus.publish.assert_called_once()
    call_args = mock_event_bus.publish.call_args

    assert call_args[0][0] == "alert.new"

    payload = call_args[0][1]
    assert payload["alert_type"] == AlertType.SECURITY_PORT_RISK.value
    assert payload["severity"] == Severity.HIGH.value
    assert "Telnet" in payload["title"]
    assert payload["id"] is not None
    assert payload["incident_id"] is None
    assert payload["read_at"] is None
    assert payload["actioned_at"] is None
    assert payload["device_count"] == 1
    assert payload["issue_key"] == "port_risk:telnet:23"
    assert payload["source_ip"] is None  # grouped alerts have no single source_ip

    # source_id should be the issue key
    assert call_args[1]["source_id"] == "issue:port_risk:telnet:23"


# ---------------------------------------------------------------------------
# Test 9: Event bus publishes alert.updated when group changes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_bus_publishes_alert_updated(db, mock_event_bus):
    """When a grouped alert's device list changes, alert.updated should be published."""
    for i in range(1, 3):
        await _insert_test_device(
            db, device_id=i,
            ip_address=f"192.168.1.{100 + i}",
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            device_type="smart_speaker",
        )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: 1 device
    devices_scan1 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
    ]
    await analyzer.analyze_all_devices(devices_scan1)
    mock_event_bus.publish.reset_mock()

    # Scan 2: 2 devices
    devices_scan2 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
        _make_device_dict(2, "192.168.1.102", "AA:BB:CC:DD:EE:02",
                          "smart_speaker", frozenset({23}), "Speaker 2"),
    ]
    await analyzer.analyze_all_devices(devices_scan2)

    # Should publish alert.updated (not alert.new)
    mock_event_bus.publish.assert_called_once()
    call_args = mock_event_bus.publish.call_args
    assert call_args[0][0] == "alert.updated"

    payload = call_args[0][1]
    assert payload["device_count"] == 2
    assert "2 devices" in payload["title"]


# ---------------------------------------------------------------------------
# Test 10: Insight state resolved when port closes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insight_state_resolved_when_port_closes(db, mock_event_bus):
    """When a device's risky port closes, its insight_state resolved_at should be set."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: port 23 open
    devices_scan1 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
    ]
    await analyzer.analyze_all_devices(devices_scan1)

    # Verify insight_state exists and is active
    cursor = await db.execute(
        "SELECT resolved_at FROM security_insight_state "
        "WHERE device_id = 1 AND insight_key = 'risky_port:23'"
    )
    row = await cursor.fetchone()
    assert row is not None
    assert row["resolved_at"] is None

    # Scan 2: port closed
    devices_scan2 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset(), "Speaker 1"),
    ]
    await analyzer.analyze_all_devices(devices_scan2)

    # Verify resolved_at is now set
    cursor = await db.execute(
        "SELECT resolved_at FROM security_insight_state "
        "WHERE device_id = 1 AND insight_key = 'risky_port:23'"
    )
    row = await cursor.fetchone()
    assert row["resolved_at"] is not None


# ---------------------------------------------------------------------------
# Test 11: DHCP reassignment (IP change) updates silently
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ip_change_updates_silently(db, mock_event_bus):
    """When a device's IP changes (DHCP reassignment) but the same port is open,
    the grouped alert should update affected_devices but NOT publish an event."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="smart_speaker",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    # Scan 1: device at .101
    devices_scan1 = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
    ]
    await analyzer.analyze_all_devices(devices_scan1)
    mock_event_bus.publish.reset_mock()

    # Scan 2: same device at .150 (DHCP changed)
    devices_scan2 = [
        _make_device_dict(1, "192.168.1.150", "AA:BB:CC:DD:EE:01",
                          "smart_speaker", frozenset({23}), "Speaker 1"),
    ]
    await analyzer.analyze_all_devices(devices_scan2)

    # Should NOT publish any event (silent IP update)
    mock_event_bus.publish.assert_not_called()

    # But the IP should be updated in affected_devices
    cursor = await db.execute(
        "SELECT affected_devices FROM home_alerts WHERE issue_key = 'port_risk:telnet:23'"
    )
    row = await cursor.fetchone()
    affected = json.loads(row["affected_devices"])
    assert affected[0]["ip_address"] == "192.168.1.150"


# ---------------------------------------------------------------------------
# Test 12: No alerts for expected device types
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_alert_for_expected_device_type(db, mock_event_bus):
    """SSH on a computer should not produce an alert (it's expected)."""
    await _insert_test_device(
        db, device_id=1, ip_address="192.168.1.101",
        mac_address="AA:BB:CC:DD:EE:01", device_type="computer",
    )

    analyzer = SecurityInsightAnalyzer(db=db, event_bus=mock_event_bus)

    devices = [
        _make_device_dict(1, "192.168.1.101", "AA:BB:CC:DD:EE:01",
                          "computer", frozenset({22}), "My PC"),
    ]

    new_count = await analyzer.analyze_all_devices(devices)
    assert new_count == 0

    cursor = await db.execute("SELECT COUNT(*) as cnt FROM home_alerts")
    row = await cursor.fetchone()
    assert row["cnt"] == 0
