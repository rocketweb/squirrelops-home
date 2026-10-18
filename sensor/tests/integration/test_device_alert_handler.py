"""device.new, device.mac_changed, and device.verification_needed become alerts.

The producers have existed since the device manager was written; until now no
subscriber turned them into alert rows, so a rogue device joining the LAN was
visible in the inventory and nowhere else.
"""

from __future__ import annotations

import json
from typing import Any

import aiosqlite
import pytest
import pytest_asyncio

from squirrelops_home_sensor.alerts.device_handler import DeviceAlertHandler
from squirrelops_home_sensor.alerts.types import AlertType, Severity


class FakeEventBus:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any]]] = []
        self._subscribers: dict[str, list[Any]] = {}
        self._next_seq = 1

    async def publish(self, event_type, payload, source_id=None) -> int:
        seq = self._next_seq
        self._next_seq += 1
        self.published.append((event_type, payload))
        return seq

    def subscribe(self, event_types, callback) -> None:
        for event_type in event_types:
            self._subscribers.setdefault(event_type, []).append(callback)

    async def deliver(self, event_type, payload, *, seq: int | None = None) -> None:
        if seq is None:
            seq = self._next_seq
            self._next_seq += 1
        event = {"seq": seq, "event_type": event_type, "payload": payload}
        for callback in self._subscribers.get(event_type, []):
            await callback(event)

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [p for t, p in self.published if t == event_type]


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


@pytest_asyncio.fixture
async def handler(db, bus):
    instance = DeviceAlertHandler(db=db, event_bus=bus)
    instance.subscribe_to(bus)
    return instance


async def _device(db, device_id: int, *, trust: str | None = "unknown", **fields) -> dict[str, Any]:
    row = {
        "ip_address": "192.168.1.77", "mac_address": "aa:bb:cc:dd:ee:01",
        "hostname": "pixel-9", "vendor": "Google", "device_type": "smartphone",
        "custom_name": None,
    }
    row.update(fields)
    await db.execute(
        "INSERT INTO devices (id, ip_address, mac_address, hostname, vendor, device_type, "
        "custom_name, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (device_id, row["ip_address"], row["mac_address"], row["hostname"], row["vendor"],
         row["device_type"], row["custom_name"], "2026-10-18T01:00:00.000000Z",
         "2026-10-18T01:00:00.000000Z"),
    )
    if trust is not None:
        await db.execute(
            "INSERT INTO device_trust (device_id, status, approved_by, updated_at) "
            "VALUES (?, ?, 'test', '2026-10-18T01:00:00.000000Z')",
            (device_id, trust),
        )
    await db.commit()
    return {
        "id": device_id, "trust_status": trust or "unknown", "is_online": True,
        "model_name": None, "area": None,
        "first_seen": "2026-10-18T01:00:00.000000Z", "last_seen": "2026-10-18T01:00:05.000000Z",
        **row,
    }


async def _alerts(db) -> list[aiosqlite.Row]:
    async with db.execute("SELECT * FROM home_alerts ORDER BY id") as cursor:
        return list(await cursor.fetchall())


# --- device.new -------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_untrusted_device_raises_a_medium_alert(handler, bus, db):
    payload = await _device(db, 7)

    await bus.deliver("device.new", payload)

    rows = await _alerts(db)
    assert len(rows) == 1
    row = rows[0]
    assert row["alert_type"] == AlertType.DEVICE_NEW.value
    assert row["severity"] == Severity.MEDIUM.value
    assert row["title"] == "New device: pixel-9 (192.168.1.77)"
    assert row["source_ip"] == "192.168.1.77"
    assert row["source_mac"] == "aa:bb:cc:dd:ee:01"
    assert row["device_id"] == 7
    assert row["issue_key"] == "device:new:7"
    detail = json.loads(row["detail"])
    assert detail["vendor"] == "Google"
    assert detail["device_type"] == "smartphone"
    assert detail["trust_status"] == "unknown"
    assert detail["mac_address"] == "aa:bb:cc:dd:ee:01"

    announced = bus.of_type("alert.new")
    assert len(announced) == 1
    assert announced[0]["id"] == row["id"]
    assert announced[0]["alert_type"] == "device.new"
    assert announced[0]["severity"] == "medium"
    assert announced[0]["source_ip"] == "192.168.1.77"
    assert announced[0]["issue_key"] == "device:new:7"
    # Outbound handlers render a string; a dict here would reach Slack as a repr.
    assert "detail" not in announced[0]
    assert announced[0]["summary"] == "Google smartphone, MAC aa:bb:cc:dd:ee:01, trust unknown"


@pytest.mark.asyncio
async def test_new_device_title_prefers_the_operator_name_then_hostname_then_mac(handler, bus, db):
    named = await _device(db, 1, custom_name="Kitchen tablet", ip_address="192.168.1.10")
    bare = await _device(db, 2, hostname=None, vendor=None, ip_address="192.168.1.11",
                         mac_address="aa:bb:cc:dd:ee:02")
    await bus.deliver("device.new", named)
    await bus.deliver("device.new", bare)

    titles = [row["title"] for row in await _alerts(db)]
    assert titles == [
        "New device: Kitchen tablet (192.168.1.10)",
        "New device: aa:bb:cc:dd:ee:02 (192.168.1.11)",
    ]


@pytest.mark.asyncio
async def test_new_device_already_approved_does_not_alert(handler, bus, db):
    payload = await _device(db, 7, trust="approved")

    await bus.deliver("device.new", payload)

    assert await _alerts(db) == []
    assert bus.published == []


@pytest.mark.asyncio
async def test_new_device_is_announced_once_per_device(handler, bus, db):
    payload = await _device(db, 7)

    await bus.deliver("device.new", payload)
    await bus.deliver("device.new", payload)

    assert len(await _alerts(db)) == 1
    assert len(bus.of_type("alert.new")) == 1
    assert bus.of_type("alert.updated") == []


# --- device.mac_changed -----------------------------------------------------


@pytest.mark.asyncio
async def test_mac_change_raises_a_high_alert_even_for_an_approved_device(handler, bus, db):
    await _device(db, 7, trust="approved")

    await bus.deliver("device.mac_changed", {
        "device_id": 7, "old_mac": "aa:bb:cc:dd:ee:01",
        "new_mac": "aa:bb:cc:dd:ee:99", "confidence": 0.81,
    })

    rows = await _alerts(db)
    assert len(rows) == 1
    row = rows[0]
    assert row["alert_type"] == AlertType.DEVICE_MAC_CHANGED.value
    assert row["severity"] == Severity.HIGH.value
    assert row["title"] == "MAC address changed for pixel-9 (192.168.1.77)"
    assert row["source_ip"] == "192.168.1.77"
    assert row["source_mac"] == "aa:bb:cc:dd:ee:99"
    assert row["issue_key"] == "device:mac_changed:7"
    detail = json.loads(row["detail"])
    assert detail["old_mac"] == "aa:bb:cc:dd:ee:01"
    assert detail["new_mac"] == "aa:bb:cc:dd:ee:99"
    assert detail["confidence"] == 0.81
    assert detail["change_count"] == 1
    assert bus.of_type("alert.new")[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_repeated_mac_changes_fold_into_one_active_alert(handler, bus, db):
    await _device(db, 7)
    first = {"device_id": 7, "old_mac": "aa:bb:cc:dd:ee:01", "new_mac": "aa:bb:cc:dd:ee:02", "confidence": 0.8}
    second = {"device_id": 7, "old_mac": "aa:bb:cc:dd:ee:02", "new_mac": "aa:bb:cc:dd:ee:03", "confidence": 0.7}

    await bus.deliver("device.mac_changed", first)
    await bus.deliver("device.mac_changed", second)

    rows = await _alerts(db)
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["change_count"] == 2
    assert detail["new_mac"] == "aa:bb:cc:dd:ee:03"
    assert [m["new_mac"] for m in detail["recent_changes"]] == ["aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]
    assert rows[0]["source_mac"] == "aa:bb:cc:dd:ee:03"
    assert len(bus.of_type("alert.new")) == 1
    updated = bus.of_type("alert.updated")
    assert len(updated) == 1
    assert updated[0]["id"] == rows[0]["id"]
    assert updated[0]["read_at"] is None
    assert updated[0]["summary"] == "Google, MAC aa:bb:cc:dd:ee:02 to aa:bb:cc:dd:ee:03, 2 changes"


@pytest.mark.asyncio
async def test_a_dismissed_mac_change_alert_reactivates_on_the_next_change(handler, bus, db):
    await _device(db, 7)
    await bus.deliver("device.mac_changed", {
        "device_id": 7, "old_mac": "a", "new_mac": "b", "confidence": 0.8,
    })
    await db.execute("UPDATE home_alerts SET read_at = '2026-10-18T02:00:00.000000Z'")
    await db.commit()

    await bus.deliver("device.mac_changed", {
        "device_id": 7, "old_mac": "b", "new_mac": "c", "confidence": 0.8,
    })

    rows = await _alerts(db)
    assert len(rows) == 1
    assert rows[0]["read_at"] is None, "a fresh change must come back into the active feed"
    assert bus.of_type("alert.updated")[-1]["read_at"] is None


# --- device.verification_needed --------------------------------------------


@pytest.mark.asyncio
async def test_verification_needed_raises_a_medium_alert_for_an_unknown_device(handler, bus, db):
    payload = await _device(db, 7)

    await bus.deliver("device.verification_needed", payload)
    await bus.deliver("device.verification_needed", payload)

    rows = await _alerts(db)
    assert len(rows) == 1
    assert rows[0]["alert_type"] == AlertType.DEVICE_VERIFICATION_NEEDED.value
    assert rows[0]["severity"] == Severity.MEDIUM.value
    assert rows[0]["title"] == "Device needs verification: pixel-9 (192.168.1.77)"
    assert rows[0]["issue_key"] == "device:verify:7"
    assert len(bus.of_type("alert.new")) == 1


@pytest.mark.asyncio
async def test_verification_needed_for_an_approved_device_is_silent(handler, bus, db):
    payload = await _device(db, 7, trust="approved")

    await bus.deliver("device.verification_needed", payload)

    assert await _alerts(db) == []


# --- Guards -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_events_from_before_a_history_clear_do_not_resurrect_alerts(handler, bus, db):
    payload = await _device(db, 7)
    await db.execute(
        "INSERT INTO events (seq, event_type, payload) VALUES (50, 'alerts.history_cleared', '{}')"
    )
    await db.commit()

    await bus.deliver("device.new", payload, seq=49)

    assert await _alerts(db) == []


@pytest.mark.asyncio
async def test_malformed_device_events_are_ignored(handler, bus, db):
    await bus.deliver("device.new", {"ip_address": "192.168.1.5"})
    await bus.deliver("device.mac_changed", {"device_id": "seven"})
    await bus.deliver("device.mac_changed", {"device_id": 404, "old_mac": "a", "new_mac": "b"})
    await bus.deliver("device.verification_needed", "not a dict")

    assert await _alerts(db) == []
    assert bus.published == []
