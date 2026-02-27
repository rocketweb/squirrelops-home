"""Integration tests for Home Assistant device enrichment.

Tests verify that enrich_device_ha():
- Matches tracked devices by MAC address
- Updates hostname, model_name, vendor, and area from HA data
- Never overwrites custom_name
- Publishes device.updated events with area field
- Persists area to the SQLite database
"""

from __future__ import annotations

import asyncio
import pathlib

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.devices.classifier import DeviceClassifier
from squirrelops_home_sensor.devices.manager import DeviceManager, ScanResult
from squirrelops_home_sensor.devices.signatures import SignatureDB
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.integrations.home_assistant import HAArea, HADevice


SENSOR_ROOT = pathlib.Path(__file__).resolve().parents[2]
SIGNATURES_PATH = SENSOR_ROOT / "signatures" / "device_signatures.json"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def db():
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON")
    await apply_migrations(conn)
    yield conn
    await conn.close()


@pytest.fixture
def event_log(db: aiosqlite.Connection) -> EventLog:
    return EventLog(db)


@pytest.fixture
def event_bus(event_log: EventLog) -> EventBus:
    return EventBus(event_log)


@pytest.fixture
def signature_db() -> SignatureDB:
    return SignatureDB.load(SIGNATURES_PATH)


@pytest.fixture
def classifier(signature_db: SignatureDB) -> DeviceClassifier:
    return DeviceClassifier(signature_db=signature_db, llm=None)


@pytest.fixture
def device_manager(
    db: aiosqlite.Connection,
    event_bus: EventBus,
    classifier: DeviceClassifier,
) -> DeviceManager:
    return DeviceManager(db=db, event_bus=event_bus, classifier=classifier)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEnrichDeviceHA:
    """Test HA-based device enrichment via MAC matching."""

    @pytest.mark.asyncio
    async def test_enriches_by_mac_match(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """Device matched by MAC gets hostname, model_name, and area updated."""
        scan = ScanResult(ip_address="192.168.1.50", mac_address="AA:BB:CC:DD:EE:50")
        await device_manager.process_scan_result(scan)

        ha_devices = [
            HADevice(
                id="ha-dev-1",
                name="Living Room Light",
                manufacturer="Philips",
                model="Hue Bulb",
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:50"}),
                area_id="area-1",
            ),
        ]
        ha_areas = [HAArea(id="area-1", name="Living Room")]

        await device_manager.enrich_device_ha(ha_devices, ha_areas)

        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.50"
        )
        assert tracked.hostname == "Living Room Light"
        assert tracked.model_name == "Hue Bulb"
        assert tracked.area == "Living Room"

    @pytest.mark.asyncio
    async def test_vendor_updated_if_unknown(
        self, device_manager: DeviceManager
    ) -> None:
        """Vendor updated from HA manufacturer when current is 'Unknown'."""
        # Locally administered MAC -> vendor will be "Unknown"
        scan = ScanResult(ip_address="192.168.1.51", mac_address="02:BB:CC:DD:EE:51")
        await device_manager.process_scan_result(scan)

        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.51"
        )
        assert tracked.vendor == "Unknown"

        ha_devices = [
            HADevice(
                id="ha-dev-2",
                name="Smart Switch",
                manufacturer="TP-Link",
                model="HS200",
                mac_addresses=frozenset({"02:bb:cc:dd:ee:51"}),
                area_id=None,
            ),
        ]

        await device_manager.enrich_device_ha(ha_devices, [])

        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.51"
        )
        assert tracked.vendor == "TP-Link"

    @pytest.mark.asyncio
    async def test_custom_name_never_overwritten(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """HA name does not overwrite existing custom_name in the DB."""
        scan = ScanResult(ip_address="192.168.1.52", mac_address="AA:BB:CC:DD:EE:52")
        await device_manager.process_scan_result(scan)

        # Set custom_name directly in DB
        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.52"
        )
        await db.execute(
            "UPDATE devices SET custom_name = ? WHERE id = ?",
            ("My Custom Device", tracked.device_id),
        )
        await db.commit()

        ha_devices = [
            HADevice(
                id="ha-dev-3",
                name="HA Name For Device",
                manufacturer=None,
                model=None,
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:52"}),
                area_id=None,
            ),
        ]

        await device_manager.enrich_device_ha(ha_devices, [])

        # custom_name in DB should still be the user-set value
        cursor = await db.execute(
            "SELECT custom_name FROM devices WHERE id = ?",
            (tracked.device_id,),
        )
        row = await cursor.fetchone()
        assert row["custom_name"] == "My Custom Device"

        # hostname should NOT have been updated (custom_name takes precedence)
        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.52"
        )
        assert tracked.hostname is None  # original scan had no hostname

    @pytest.mark.asyncio
    async def test_area_null_when_no_area_id(
        self, device_manager: DeviceManager
    ) -> None:
        """HA device with area_id=None results in area=None."""
        scan = ScanResult(ip_address="192.168.1.53", mac_address="AA:BB:CC:DD:EE:53")
        await device_manager.process_scan_result(scan)

        ha_devices = [
            HADevice(
                id="ha-dev-4",
                name="Unplaced Device",
                manufacturer=None,
                model="SomeModel",
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:53"}),
                area_id=None,
            ),
        ]

        await device_manager.enrich_device_ha(ha_devices, [])

        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.53"
        )
        assert tracked.area is None

    @pytest.mark.asyncio
    async def test_no_match_no_update(
        self, device_manager: DeviceManager
    ) -> None:
        """Device with a different MAC is not affected by HA enrichment."""
        scan = ScanResult(ip_address="192.168.1.54", mac_address="AA:BB:CC:DD:EE:54")
        await device_manager.process_scan_result(scan)

        ha_devices = [
            HADevice(
                id="ha-dev-5",
                name="Other Device",
                manufacturer="Sonos",
                model="One",
                mac_addresses=frozenset({"ff:ff:ff:ff:ff:ff"}),
                area_id="area-2",
            ),
        ]
        ha_areas = [HAArea(id="area-2", name="Kitchen")]

        await device_manager.enrich_device_ha(ha_devices, ha_areas)

        tracked = next(
            d for d in device_manager.get_known_devices()
            if d.ip_address == "192.168.1.54"
        )
        assert tracked.hostname is None
        assert tracked.model_name is None
        assert tracked.area is None

    @pytest.mark.asyncio
    async def test_publishes_device_updated_event(
        self, device_manager: DeviceManager, event_bus: EventBus
    ) -> None:
        """Enrichment publishes device.updated event with area field."""
        scan = ScanResult(ip_address="192.168.1.55", mac_address="AA:BB:CC:DD:EE:55")
        await device_manager.process_scan_result(scan)

        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        event_bus.subscribe(["device.updated"], handler)

        ha_devices = [
            HADevice(
                id="ha-dev-6",
                name="Bedroom TV",
                manufacturer=None,
                model="LG OLED",
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:55"}),
                area_id="area-3",
            ),
        ]
        ha_areas = [HAArea(id="area-3", name="Bedroom")]

        await device_manager.enrich_device_ha(ha_devices, ha_areas)
        await asyncio.sleep(0.1)

        updated = [e for e in received if e["event_type"] == "device.updated"]
        assert len(updated) >= 1
        payload = updated[-1]["payload"]
        assert payload["area"] == "Bedroom"

    @pytest.mark.asyncio
    async def test_area_persisted_to_db(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """Area value is persisted to the devices table in SQLite."""
        scan = ScanResult(ip_address="192.168.1.56", mac_address="AA:BB:CC:DD:EE:56")
        await device_manager.process_scan_result(scan)

        ha_devices = [
            HADevice(
                id="ha-dev-7",
                name="Office Printer",
                manufacturer="HP",
                model="LaserJet",
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:56"}),
                area_id="area-4",
            ),
        ]
        ha_areas = [HAArea(id="area-4", name="Office")]

        await device_manager.enrich_device_ha(ha_devices, ha_areas)

        cursor = await db.execute(
            "SELECT area FROM devices WHERE mac_address = 'AA:BB:CC:DD:EE:56'"
        )
        row = await cursor.fetchone()
        assert row["area"] == "Office"
