"""Integration tests for device manager pipeline:
discovery -> fingerprint -> match -> classify -> store -> events.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.devices.classifier import DeviceClassifier
from squirrelops_home_sensor.devices.manager import DeviceManager, ScanResult
from squirrelops_home_sensor.devices.signatures import SignatureDB
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.events.types import EventType
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint

import pathlib


SENSOR_ROOT = pathlib.Path(__file__).resolve().parents[2]
SIGNATURES_PATH = SENSOR_ROOT / "signatures" / "device_signatures.json"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def db():
    """In-memory SQLite with full schema applied."""
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
def manager(
    db: aiosqlite.Connection,
    event_bus: EventBus,
    classifier: DeviceClassifier,
) -> DeviceManager:
    return DeviceManager(db=db, event_bus=event_bus, classifier=classifier)


# ---------------------------------------------------------------------------
# Full pipeline tests
# ---------------------------------------------------------------------------

class TestDeviceManagerPipeline:
    """Test the full discovery -> fingerprint -> match -> classify -> store -> event pipeline."""

    @pytest.mark.asyncio
    async def test_new_device_discovered(self, manager: DeviceManager, event_bus: EventBus) -> None:
        """A new device produces a device.new event and is stored."""
        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe(["device.new", "device.updated"], handler)

        scan = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80, 443],
            dhcp_options=None,
            connections=None,
        )
        await manager.process_scan_result(scan)
        await asyncio.sleep(0.1)

        assert len(received_events) >= 1
        new_events = [e for e in received_events if e["event_type"] == "device.new"]
        assert len(new_events) == 1
        payload = new_events[0]["payload"]
        assert payload["ip_address"] == "192.168.1.100"
        assert payload["mac_address"] == "A4:83:E7:11:22:33"

    @pytest.mark.asyncio
    async def test_known_device_updated(self, manager: DeviceManager, event_bus: EventBus) -> None:
        """A returning device produces a device.updated event."""
        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe(["device.new", "device.updated"], handler)

        scan = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80, 443],
            dhcp_options=None,
            connections=None,
        )
        # First scan -- new device
        await manager.process_scan_result(scan)
        await asyncio.sleep(0.1)

        # Second scan -- same device returns
        await manager.process_scan_result(scan)
        await asyncio.sleep(0.1)

        updated_events = [e for e in received_events if e["event_type"] == "device.updated"]
        assert len(updated_events) >= 1

    @pytest.mark.asyncio
    async def test_device_fingerprint_stored(
        self, manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """The device fingerprint is persisted in the database."""
        scan = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80, 443],
            dhcp_options=None,
            connections=None,
        )
        await manager.process_scan_result(scan)

        cursor = await db.execute(
            "SELECT * FROM device_fingerprints WHERE mac_address = ?",
            ("A4:83:E7:11:22:33",),
        )
        rows = await cursor.fetchall()
        assert len(rows) >= 1

    @pytest.mark.asyncio
    async def test_device_classified(self, manager: DeviceManager) -> None:
        """The device is classified and classification info is available."""
        scan = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80, 443],
            dhcp_options=None,
            connections=None,
        )
        await manager.process_scan_result(scan)

        devices = manager.get_known_devices()
        assert len(devices) >= 1

    @pytest.mark.asyncio
    async def test_verification_needed_event(
        self, manager: DeviceManager, event_bus: EventBus
    ) -> None:
        """A device matching with low confidence emits device.verification_needed."""
        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe(["device.verification_needed"], handler)

        # First: register a device
        scan1 = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80, 443],
            dhcp_options=[1, 3, 6, 15, 28, 51, 53],
            connections=[("8.8.8.8", 443)],
        )
        await manager.process_scan_result(scan1)
        await asyncio.sleep(0.1)

        # Second: same device, different MAC but similar mDNS
        # Only 1 non-MAC signal matches -> capped at 0.50 -> verification needed
        scan2 = ScanResult(
            ip_address="192.168.1.101",
            mac_address="11:22:33:44:55:66",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[8080, 9090],          # Different ports
            dhcp_options=[53, 61, 12],        # Different DHCP
            connections=[("10.0.0.1", 80)],   # Different connections
        )
        await manager.process_scan_result(scan2)
        await asyncio.sleep(0.1)

        verify_events = [e for e in received_events if e["event_type"] == "device.verification_needed"]
        assert len(verify_events) >= 1

    @pytest.mark.asyncio
    async def test_mac_changed_event(
        self, manager: DeviceManager, event_bus: EventBus
    ) -> None:
        """When a known device returns with a new MAC, emit device.mac_changed."""
        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe(["device.mac_changed"], handler)

        # Register device with full signals
        scan1 = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80, 443],
            dhcp_options=[1, 3, 6, 15, 28, 51, 53],
            connections=[("8.8.8.8", 443), ("1.1.1.1", 53)],
        )
        await manager.process_scan_result(scan1)
        await asyncio.sleep(0.1)

        # Same device returns with different MAC but strong signal match
        scan2 = ScanResult(
            ip_address="192.168.1.100",
            mac_address="11:22:33:44:55:66",  # Different MAC
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",  # Same mDNS
            open_ports=[22, 80, 443],            # Same ports
            dhcp_options=[1, 3, 6, 15, 28, 51, 53],  # Same DHCP
            connections=[("8.8.8.8", 443), ("1.1.1.1", 53)],  # Same connections
        )
        await manager.process_scan_result(scan2)
        await asyncio.sleep(0.1)

        mac_events = [e for e in received_events if e["event_type"] == "device.mac_changed"]
        assert len(mac_events) >= 1
        payload = mac_events[0]["payload"]
        assert payload["old_mac"] == "A4:83:E7:11:22:33"
        assert payload["new_mac"] == "11:22:33:44:55:66"


class TestDeviceManagerMultipleDevices:
    """Test handling of multiple distinct devices."""

    @pytest.mark.asyncio
    async def test_two_distinct_devices(
        self, manager: DeviceManager, event_bus: EventBus
    ) -> None:
        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe(["device.new"], handler)

        scan1 = ScanResult(
            ip_address="192.168.1.100",
            mac_address="A4:83:E7:11:22:33",
            hostname="macbook-pro.local",
            mdns_hostname="macbook-pro.local",
            open_ports=[22, 80],
            dhcp_options=None,
            connections=None,
        )
        scan2 = ScanResult(
            ip_address="192.168.1.101",
            mac_address="DC:A6:32:AA:BB:CC",
            hostname="raspberrypi.local",
            mdns_hostname="raspberrypi.local",
            open_ports=[22],
            dhcp_options=None,
            connections=None,
        )
        await manager.process_scan_result(scan1)
        await manager.process_scan_result(scan2)
        await asyncio.sleep(0.1)

        new_events = [e for e in received_events if e["event_type"] == "device.new"]
        assert len(new_events) == 2

        devices = manager.get_known_devices()
        assert len(devices) == 2
