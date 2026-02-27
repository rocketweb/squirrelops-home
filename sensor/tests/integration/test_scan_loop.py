"""Integration tests for the scan loop.

Tests verify that the scan loop:
- Runs three-phase scans (ARP discovery + port scan + mDNS/SSDP enrichment)
- Creates devices immediately from ARP (Phase 1)
- Enriches devices with port data (Phase 2)
- Enriches devices with mDNS/SSDP discovery data (Phase 3)
- Phase 2/3 failure never blocks device creation
- Publishes system.scan_complete events
- Respects the configured scan interval
- Shuts down gracefully via asyncio.Event
"""

from __future__ import annotations

import asyncio
import pathlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.devices.classifier import DeviceClassifier
from squirrelops_home_sensor.devices.manager import DeviceManager, ScanResult
from squirrelops_home_sensor.devices.signatures import SignatureDB
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.events.types import EventType
from squirrelops_home_sensor.privileged.helper import (
    LinuxPrivilegedOps,
    PrivilegedOperations,
)
from squirrelops_home_sensor.scanner.loop import ScanLoop
from squirrelops_home_sensor.scanner.mdns_browser import MDNSBrowser, MDNSResult
from squirrelops_home_sensor.scanner.port_scanner import PortScanner
from squirrelops_home_sensor.scanner.ssdp_scanner import SSDPResult, SSDPScanner


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


@pytest.fixture
def mock_ops() -> AsyncMock:
    """Mocked privileged operations."""
    ops = AsyncMock(spec=PrivilegedOperations)
    ops.arp_scan.return_value = [
        ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
        ("192.168.1.2", "AA:BB:CC:DD:EE:02"),
    ]
    return ops


@pytest.fixture
def mock_port_scanner() -> AsyncMock:
    """Mocked port scanner."""
    scanner = AsyncMock(spec=PortScanner)
    scanner.scan.return_value = {
        "192.168.1.1": [80, 443],
        "192.168.1.2": [22],
    }
    return scanner


@pytest.fixture
def mock_mdns_browser() -> AsyncMock:
    """Mocked mDNS browser."""
    browser = AsyncMock(spec=MDNSBrowser)
    browser.browse.return_value = []
    return browser


@pytest.fixture
def mock_ssdp_scanner() -> AsyncMock:
    """Mocked SSDP scanner."""
    scanner = AsyncMock(spec=SSDPScanner)
    scanner.scan.return_value = []
    return scanner


@pytest.fixture
def scan_loop(
    device_manager: DeviceManager,
    event_bus: EventBus,
    mock_ops: AsyncMock,
    mock_port_scanner: AsyncMock,
    mock_mdns_browser: AsyncMock,
    mock_ssdp_scanner: AsyncMock,
) -> ScanLoop:
    return ScanLoop(
        device_manager=device_manager,
        event_bus=event_bus,
        privileged_ops=mock_ops,
        subnet="192.168.1.0/24",
        scan_interval=1,
        port_scanner=mock_port_scanner,
        mdns_browser=mock_mdns_browser,
        ssdp_scanner=mock_ssdp_scanner,
    )


# ---------------------------------------------------------------------------
# Basic scan execution
# ---------------------------------------------------------------------------

class TestScanLoopExecution:
    """Test that the scan loop calls scanners and feeds the device manager."""

    @pytest.mark.asyncio
    async def test_single_scan_creates_devices_from_arp(
        self, scan_loop: ScanLoop, mock_ops: AsyncMock, device_manager: DeviceManager
    ) -> None:
        """Phase 1: ARP scan creates devices immediately."""
        await scan_loop.run_single_scan()
        mock_ops.arp_scan.assert_called_once_with("192.168.1.0/24")
        devices = device_manager.get_known_devices()
        assert len(devices) == 2

    @pytest.mark.asyncio
    async def test_single_scan_enriches_with_ports(
        self, scan_loop: ScanLoop, mock_port_scanner: AsyncMock, device_manager: DeviceManager
    ) -> None:
        """Phase 2: port scan enriches devices with open ports."""
        await scan_loop.run_single_scan()
        mock_port_scanner.scan.assert_called_once()
        device_1 = next(
            (d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1"),
            None,
        )
        assert device_1 is not None
        assert 80 in device_1.open_ports
        assert 443 in device_1.open_ports

    @pytest.mark.asyncio
    async def test_scan_publishes_scan_complete(
        self, scan_loop: ScanLoop, event_bus: EventBus
    ) -> None:
        """Each scan cycle publishes a system.scan_complete event."""
        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe([EventType.SYSTEM_SCAN_COMPLETE], handler)
        await scan_loop.run_single_scan()
        await asyncio.sleep(0.1)

        complete_events = [
            e for e in received_events
            if e["event_type"] == EventType.SYSTEM_SCAN_COMPLETE
        ]
        assert len(complete_events) == 1
        payload = complete_events[0]["payload"]
        assert payload["device_count"] == 2

    @pytest.mark.asyncio
    async def test_port_scan_failure_doesnt_block_devices(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock,
    ) -> None:
        """If port scan fails, devices are still created from ARP."""
        failing_scanner = AsyncMock(spec=PortScanner)
        failing_scanner.scan.side_effect = OSError("network error")

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=failing_scanner,
        )

        await loop.run_single_scan()
        devices = device_manager.get_known_devices()
        assert len(devices) == 2


# ---------------------------------------------------------------------------
# Interval timing
# ---------------------------------------------------------------------------

class TestScanLoopTiming:
    """Test scan interval behavior."""

    @pytest.mark.asyncio
    async def test_loop_runs_at_interval(
        self, scan_loop: ScanLoop, mock_ops: AsyncMock
    ) -> None:
        """The loop runs multiple scans at the configured interval."""
        shutdown = asyncio.Event()

        async def stop_after_delay() -> None:
            await asyncio.sleep(2.5)  # Run for ~2.5 seconds with 1s interval
            shutdown.set()

        stop_task = asyncio.create_task(stop_after_delay())
        loop_task = asyncio.create_task(scan_loop.run(shutdown_event=shutdown))

        await asyncio.gather(stop_task, loop_task)

        # With 1s interval over 2.5s, should get 2-3 scans
        assert mock_ops.arp_scan.call_count >= 2

    @pytest.mark.asyncio
    async def test_custom_interval(
        self, device_manager: DeviceManager, event_bus: EventBus, mock_ops: AsyncMock
    ) -> None:
        """The loop respects a custom scan interval."""
        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=60,  # Would be 60 seconds in production
        )
        assert loop.scan_interval == 60


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

class TestScanLoopShutdown:
    """Test graceful shutdown via asyncio.Event."""

    @pytest.mark.asyncio
    async def test_shutdown_stops_loop(
        self, scan_loop: ScanLoop, mock_ops: AsyncMock
    ) -> None:
        """Setting the shutdown event stops the loop promptly."""
        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.5)
            shutdown.set()

        stop_task = asyncio.create_task(stop_soon())
        loop_task = asyncio.create_task(scan_loop.run(shutdown_event=shutdown))

        await asyncio.gather(stop_task, loop_task)

        # Loop should have completed without error
        assert loop_task.done()
        assert not loop_task.cancelled()

    @pytest.mark.asyncio
    async def test_immediate_shutdown(
        self, scan_loop: ScanLoop, mock_ops: AsyncMock
    ) -> None:
        """If shutdown is already set, the loop exits immediately."""
        shutdown = asyncio.Event()
        shutdown.set()

        await scan_loop.run(shutdown_event=shutdown)

        # Should have run 0 scans (exits before first scan)
        assert mock_ops.arp_scan.call_count == 0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestScanLoopErrorHandling:
    """Test that scan errors don't crash the loop."""

    @pytest.mark.asyncio
    async def test_arp_scan_failure_continues(
        self, scan_loop: ScanLoop, mock_ops: AsyncMock
    ) -> None:
        """If ARP scan fails, the loop continues to the next cycle."""
        mock_ops.arp_scan.side_effect = [
            OSError("Network unreachable"),
            [("192.168.1.1", "AA:BB:CC:DD:EE:01")],
        ]

        shutdown = asyncio.Event()

        async def stop_after() -> None:
            await asyncio.sleep(2.5)
            shutdown.set()

        stop_task = asyncio.create_task(stop_after())
        loop_task = asyncio.create_task(scan_loop.run(shutdown_event=shutdown))
        await asyncio.gather(stop_task, loop_task)
        assert mock_ops.arp_scan.call_count >= 2

    @pytest.mark.asyncio
    async def test_port_scan_failure_continues(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock,
    ) -> None:
        """If port scan fails, ARP results are still processed."""
        failing_scanner = AsyncMock(spec=PortScanner)
        failing_scanner.scan.side_effect = OSError("network error")

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=failing_scanner,
        )
        await loop.run_single_scan()
        mock_ops.arp_scan.assert_called_once()
        assert len(device_manager.get_known_devices()) == 2


# ---------------------------------------------------------------------------
# Scan result merging
# ---------------------------------------------------------------------------

class TestScanResultMerging:
    """Test that ARP + port scan results are properly merged."""

    @pytest.mark.asyncio
    async def test_device_without_open_ports(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock,
    ) -> None:
        """Devices found by ARP but with no open ports still exist."""
        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
            ("192.168.1.99", "AA:BB:CC:DD:EE:99"),
        ]
        scanner = AsyncMock(spec=PortScanner)
        scanner.scan.return_value = {"192.168.1.1": [80]}

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=scanner,
        )

        await loop.run_single_scan()
        devices = device_manager.get_known_devices()
        assert len(devices) == 2

        device_99 = next(
            (d for d in devices if d.ip_address == "192.168.1.99"), None
        )
        assert device_99 is not None
        assert len(device_99.open_ports) == 0


# ---------------------------------------------------------------------------
# Device port enrichment
# ---------------------------------------------------------------------------

class TestDevicePortEnrichment:
    """Test that port enrichment updates existing devices."""

    @pytest.mark.asyncio
    async def test_enrich_updates_tracked_device(
        self, device_manager: DeviceManager
    ) -> None:
        """enrich_device_ports adds port data to a known device."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        devices_before = device_manager.get_known_devices()
        assert len(devices_before) == 1
        assert len(devices_before[0].open_ports) == 0

        await device_manager.enrich_device_ports("192.168.1.1", [80, 443])

        devices_after = device_manager.get_known_devices()
        assert 80 in devices_after[0].open_ports
        assert 443 in devices_after[0].open_ports

    @pytest.mark.asyncio
    async def test_enrich_unknown_ip_is_noop(
        self, device_manager: DeviceManager
    ) -> None:
        """enrich_device_ports for unknown IP does nothing."""
        # No devices registered yet
        await device_manager.enrich_device_ports("192.168.1.99", [80])
        # Should not raise, just do nothing
        assert len(device_manager.get_known_devices()) == 0

    @pytest.mark.asyncio
    async def test_enrich_publishes_device_updated(
        self, device_manager: DeviceManager, event_bus: EventBus, db: aiosqlite.Connection
    ) -> None:
        """enrich_device_ports publishes a device.updated event."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        received_events: list[dict] = []

        async def handler(event: dict) -> None:
            received_events.append(event)

        event_bus.subscribe(["device.updated"], handler)

        await device_manager.enrich_device_ports("192.168.1.1", [80, 443])
        await asyncio.sleep(0.1)

        updated_events = [e for e in received_events if e["event_type"] == "device.updated"]
        assert len(updated_events) >= 1


# ---------------------------------------------------------------------------
# Device loading from DB across restarts
# ---------------------------------------------------------------------------

class TestDeviceManagerLoadKnownDevices:
    """Test that DeviceManager can restore state from the database."""

    @pytest.mark.asyncio
    async def test_load_empty_db(self, device_manager: DeviceManager) -> None:
        """Loading from an empty DB produces no devices."""
        await device_manager.load_known_devices()
        assert len(device_manager.get_known_devices()) == 0

    @pytest.mark.asyncio
    async def test_load_restores_devices(
        self, db: aiosqlite.Connection, event_bus: EventBus, classifier: DeviceClassifier
    ) -> None:
        """Devices created in a previous session are loaded on restart."""
        # Session 1: create two devices
        mgr1 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr1.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )
        await mgr1.process_scan_result(
            ScanResult(ip_address="192.168.1.20", mac_address="AA:BB:CC:DD:EE:20")
        )
        assert len(mgr1.get_known_devices()) == 2

        # Session 2: fresh DeviceManager loads from DB
        mgr2 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        assert len(mgr2.get_known_devices()) == 0
        await mgr2.load_known_devices()
        assert len(mgr2.get_known_devices()) == 2

        macs = {d.mac_address for d in mgr2.get_known_devices()}
        assert "AA:BB:CC:DD:EE:10" in macs
        assert "AA:BB:CC:DD:EE:20" in macs

    @pytest.mark.asyncio
    async def test_load_restores_fingerprints(
        self, db: aiosqlite.Connection, event_bus: EventBus, classifier: DeviceClassifier
    ) -> None:
        """Loaded devices have correct fingerprint data."""
        mgr1 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr1.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )
        original = mgr1.get_known_devices()[0]

        mgr2 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr2.load_known_devices()
        loaded = mgr2.get_known_devices()[0]

        assert loaded.fingerprint.mac_address == original.fingerprint.mac_address
        assert loaded.fingerprint.composite_hash == original.fingerprint.composite_hash

    @pytest.mark.asyncio
    async def test_load_restores_connection_baselines(
        self, db: aiosqlite.Connection, event_bus: EventBus, classifier: DeviceClassifier
    ) -> None:
        """Connection baselines from DB are loaded into connection_destinations."""
        mgr1 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr1.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )
        device_id = mgr1.get_known_devices()[0].device_id

        # Insert a connection baseline
        now_iso = "2026-02-25T00:00:00.000000Z"
        await db.execute(
            "INSERT INTO connection_baselines "
            "(device_id, dest_ip, dest_port, hit_count, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, "8.8.8.8", 443, 5, now_iso, now_iso),
        )
        await db.commit()

        mgr2 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr2.load_known_devices()
        loaded = mgr2.get_known_devices()[0]

        assert "8.8.8.8:443" in loaded.connection_destinations


class TestMacPreMatch:
    """Test that returning devices are recognised by MAC without needing
    multi-signal fingerprint matching."""

    @pytest.mark.asyncio
    async def test_same_mac_updates_instead_of_duplicating(
        self, db: aiosqlite.Connection, event_bus: EventBus, classifier: DeviceClassifier
    ) -> None:
        """Scanning a device with a known MAC updates it rather than
        creating a duplicate."""
        # Session 1: create device
        mgr1 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr1.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )
        assert len(mgr1.get_known_devices()) == 1

        # Session 2: load from DB, scan same MAC
        mgr2 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr2.load_known_devices()
        await mgr2.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )
        # Should still be 1 device, not 2
        assert len(mgr2.get_known_devices()) == 1

    @pytest.mark.asyncio
    async def test_same_mac_new_ip_updates_ip(
        self, db: aiosqlite.Connection, event_bus: EventBus, classifier: DeviceClassifier
    ) -> None:
        """A known MAC with a new IP updates the tracked device's IP."""
        mgr = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )
        # Device gets a new IP via DHCP
        await mgr.process_scan_result(
            ScanResult(ip_address="192.168.1.99", mac_address="AA:BB:CC:DD:EE:10")
        )
        devices = mgr.get_known_devices()
        assert len(devices) == 1
        assert devices[0].ip_address == "192.168.1.99"

    @pytest.mark.asyncio
    async def test_no_duplicate_db_rows_across_restart(
        self, db: aiosqlite.Connection, event_bus: EventBus, classifier: DeviceClassifier
    ) -> None:
        """No duplicate rows in the devices table after restart + rescan."""
        mgr1 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr1.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )

        mgr2 = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)
        await mgr2.load_known_devices()
        await mgr2.process_scan_result(
            ScanResult(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:10")
        )

        cursor = await db.execute("SELECT COUNT(*) FROM devices")
        row = await cursor.fetchone()
        assert row[0] == 1


# ---------------------------------------------------------------------------
# Reclassify Unknown devices on load
# ---------------------------------------------------------------------------

class TestReclassifyOnLoad:
    """When loading known devices, reclassify any with vendor='Unknown'."""

    @pytest.mark.asyncio
    async def test_unknown_device_gets_reclassified(self, tmp_path):
        """A device stored as Unknown but with a known Apple MAC gets reclassified on load."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        # Insert a device with vendor=Unknown but a recognizable Apple MAC
        now_iso = "2026-02-25T00:00:00.000000Z"
        await db.execute(
            "INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type, is_online, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("192.168.1.100", "A4:83:E7:11:22:33", None, "Unknown", "unknown", 1, now_iso, now_iso),
        )
        await db.commit()

        event_bus = EventBus(EventLog(db))
        sig_db = SignatureDB.load(SIGNATURES_PATH)
        classifier = DeviceClassifier(signature_db=sig_db, llm=None)
        manager = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)

        await manager.load_known_devices()

        # Verify the DB was updated
        cursor = await db.execute("SELECT vendor, device_type FROM devices WHERE mac_address = ?", ("A4:83:E7:11:22:33",))
        row = await cursor.fetchone()
        assert row[0] != "Unknown"  # vendor should now be "Apple"
        assert row[0] == "Apple"

        await db.close()

    @pytest.mark.asyncio
    async def test_already_classified_not_changed(self, tmp_path):
        """A device that already has a non-Unknown vendor should NOT be reclassified."""
        db = await aiosqlite.connect(str(tmp_path / "test.db"))
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)

        now_iso = "2026-02-25T00:00:00.000000Z"
        await db.execute(
            "INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type, is_online, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("192.168.1.100", "A4:83:E7:11:22:33", None, "My Custom Name", "my_type", 1, now_iso, now_iso),
        )
        await db.commit()

        event_bus = EventBus(EventLog(db))
        sig_db = SignatureDB.load(SIGNATURES_PATH)
        classifier = DeviceClassifier(signature_db=sig_db, llm=None)
        manager = DeviceManager(db=db, event_bus=event_bus, classifier=classifier)

        await manager.load_known_devices()

        cursor = await db.execute("SELECT vendor, device_type FROM devices WHERE mac_address = ?", ("A4:83:E7:11:22:33",))
        row = await cursor.fetchone()
        assert row[0] == "My Custom Name"  # Should NOT have been overwritten
        assert row[1] == "my_type"

        await db.close()


# ---------------------------------------------------------------------------
# Discovery enrichment (Phase 3)
# ---------------------------------------------------------------------------

class TestEnrichDeviceDiscovery:
    """Test device enrichment from mDNS/SSDP discovery data."""

    @pytest.mark.asyncio
    async def test_mdns_hostname_sets_device_hostname(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """mDNS hostname updates device hostname."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            mdns_hostname="living-room.local.",
        )

        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert tracked.hostname == "living-room.local."

        # Verify DB was updated too
        cursor = await db.execute("SELECT hostname FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row[0] == "living-room.local."

    @pytest.mark.asyncio
    async def test_upnp_friendly_name_sets_hostname_when_no_mdns(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """UPnP friendly name used as hostname when no mDNS hostname."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            upnp_friendly_name="Living Room Speaker",
        )

        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert tracked.hostname == "Living Room Speaker"

    @pytest.mark.asyncio
    async def test_mdns_wins_over_upnp_for_hostname(
        self, device_manager: DeviceManager
    ) -> None:
        """mDNS hostname takes priority over UPnP friendly name."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            mdns_hostname="sonos-living.local.",
            upnp_friendly_name="Living Room Speaker",
        )

        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert tracked.hostname == "sonos-living.local."

    @pytest.mark.asyncio
    async def test_model_name_set_from_upnp(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """UPnP model name is stored in the DB."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            upnp_model_name="Sonos One",
        )

        cursor = await db.execute("SELECT model_name FROM devices WHERE ip_address = '192.168.1.1'")
        row = await cursor.fetchone()
        assert row[0] == "Sonos One"

    @pytest.mark.asyncio
    async def test_vendor_reclassified_from_upnp_manufacturer(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """UPnP manufacturer updates vendor when current is Unknown."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="02:BB:CC:DD:EE:01")  # locally administered
        await device_manager.process_scan_result(scan)

        # Device should have Unknown vendor (locally administered MAC)
        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert tracked.vendor == "Unknown"

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            upnp_manufacturer="Sonos, Inc.",
        )

        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert tracked.vendor == "Sonos, Inc."

    @pytest.mark.asyncio
    async def test_vendor_not_overwritten_when_already_known(
        self, device_manager: DeviceManager
    ) -> None:
        """UPnP manufacturer does NOT overwrite an existing known vendor."""
        # Apple MAC -> vendor will be "Apple"
        scan = ScanResult(ip_address="192.168.1.1", mac_address="A4:83:E7:DD:EE:01")
        await device_manager.process_scan_result(scan)

        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        original_vendor = tracked.vendor

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            upnp_manufacturer="Apple Inc.",
        )

        tracked = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert tracked.vendor == original_vendor  # Not changed

    @pytest.mark.asyncio
    async def test_unknown_ip_is_noop(
        self, device_manager: DeviceManager
    ) -> None:
        """Enrichment for unknown IP does nothing."""
        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.99",
            mdns_hostname="unknown.local.",
        )
        assert len(device_manager.get_known_devices()) == 0

    @pytest.mark.asyncio
    async def test_publishes_device_updated_event(
        self, device_manager: DeviceManager, event_bus: EventBus
    ) -> None:
        """Enrichment publishes a device.updated event."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        received: list[dict] = []

        async def handler(event: dict) -> None:
            received.append(event)

        event_bus.subscribe(["device.updated"], handler)

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            mdns_hostname="mydevice.local.",
        )
        await asyncio.sleep(0.1)

        updated = [e for e in received if e["event_type"] == "device.updated"]
        assert len(updated) >= 1

    @pytest.mark.asyncio
    async def test_fingerprint_updated_with_mdns_hostname(
        self, device_manager: DeviceManager, db: aiosqlite.Connection
    ) -> None:
        """Enrichment updates the fingerprint with mdns_hostname signal."""
        scan = ScanResult(ip_address="192.168.1.1", mac_address="AA:BB:CC:DD:EE:01")
        await device_manager.process_scan_result(scan)

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            mdns_hostname="mydevice.local.",
        )

        cursor = await db.execute(
            "SELECT mdns_hostname FROM device_fingerprints "
            "WHERE device_id = (SELECT id FROM devices WHERE ip_address = '192.168.1.1') "
            "ORDER BY last_seen DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        # normalize_mdns strips .local. suffix for fingerprint comparison
        assert row[0] == "mydevice"


# ---------------------------------------------------------------------------
# Phase 3: Discovery protocol enrichment
# ---------------------------------------------------------------------------

class TestScanLoopPhase3:
    """Test Phase 3: mDNS/SSDP discovery enrichment in scan loop."""

    @pytest.mark.asyncio
    async def test_phase3_enriches_with_mdns_hostname(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock, mock_port_scanner: AsyncMock,
    ) -> None:
        """Phase 3 sets device hostname from mDNS results."""
        mock_mdns = AsyncMock(spec=MDNSBrowser)
        mock_mdns.browse.return_value = [
            MDNSResult(ip="192.168.1.1", hostname="living-room.local.", service_types=frozenset({"_http._tcp.local."})),
        ]
        mock_ssdp = AsyncMock(spec=SSDPScanner)
        mock_ssdp.scan.return_value = []

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns,
            ssdp_scanner=mock_ssdp,
        )
        await loop.run_single_scan()

        device = next(
            (d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1"),
            None,
        )
        assert device is not None
        assert device.hostname == "living-room.local."

    @pytest.mark.asyncio
    async def test_phase3_enriches_with_ssdp_model(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock, mock_port_scanner: AsyncMock, db: aiosqlite.Connection,
    ) -> None:
        """Phase 3 stores UPnP model name from SSDP results."""
        mock_mdns = AsyncMock(spec=MDNSBrowser)
        mock_mdns.browse.return_value = []
        mock_ssdp = AsyncMock(spec=SSDPScanner)
        mock_ssdp.scan.return_value = [
            SSDPResult(
                ip="192.168.1.2",
                friendly_name="Bedroom Speaker",
                manufacturer="Sonos, Inc.",
                model_name="Sonos One",
                server_header="Linux UPnP Sonos",
            ),
        ]

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns,
            ssdp_scanner=mock_ssdp,
        )
        await loop.run_single_scan()

        cursor = await db.execute("SELECT model_name FROM devices WHERE ip_address = '192.168.1.2'")
        row = await cursor.fetchone()
        assert row[0] == "Sonos One"

    @pytest.mark.asyncio
    async def test_phase3_mdns_wins_over_ssdp_for_hostname(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock, mock_port_scanner: AsyncMock,
    ) -> None:
        """When both mDNS and SSDP provide names, mDNS hostname wins."""
        mock_mdns = AsyncMock(spec=MDNSBrowser)
        mock_mdns.browse.return_value = [
            MDNSResult(ip="192.168.1.1", hostname="sonos-living.local.", service_types=frozenset()),
        ]
        mock_ssdp = AsyncMock(spec=SSDPScanner)
        mock_ssdp.scan.return_value = [
            SSDPResult(ip="192.168.1.1", friendly_name="Living Room Speaker"),
        ]

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns,
            ssdp_scanner=mock_ssdp,
        )
        await loop.run_single_scan()

        device = next(d for d in device_manager.get_known_devices() if d.ip_address == "192.168.1.1")
        assert device.hostname == "sonos-living.local."

    @pytest.mark.asyncio
    async def test_phase3_failure_doesnt_block_scan(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock, mock_port_scanner: AsyncMock,
    ) -> None:
        """If Phase 3 fails entirely, devices from Phase 1/2 still exist."""
        mock_mdns = AsyncMock(spec=MDNSBrowser)
        mock_mdns.browse.side_effect = OSError("network error")
        mock_ssdp = AsyncMock(spec=SSDPScanner)
        mock_ssdp.scan.side_effect = OSError("network error")

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns,
            ssdp_scanner=mock_ssdp,
        )
        await loop.run_single_scan()

        devices = device_manager.get_known_devices()
        assert len(devices) == 2  # Still have ARP-discovered devices

    @pytest.mark.asyncio
    async def test_phase3_runs_mdns_and_ssdp_concurrently(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock, mock_port_scanner: AsyncMock,
    ) -> None:
        """Phase 3 calls both mDNS browse and SSDP scan."""
        mock_mdns = AsyncMock(spec=MDNSBrowser)
        mock_mdns.browse.return_value = []
        mock_ssdp = AsyncMock(spec=SSDPScanner)
        mock_ssdp.scan.return_value = []

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns,
            ssdp_scanner=mock_ssdp,
        )
        await loop.run_single_scan()

        mock_mdns.browse.assert_called_once()
        mock_ssdp.scan.assert_called_once()


# ---------------------------------------------------------------------------
# Phase 3 conditional: HA enrichment vs mDNS/SSDP fallback
# ---------------------------------------------------------------------------

class TestScanLoopPhase3Conditional:
    """Test that Phase 3 uses HA enrichment when configured, falling back to mDNS/SSDP."""

    @pytest.mark.asyncio
    async def test_phase3_uses_ha_when_configured(
        self,
        device_manager: DeviceManager,
        event_bus: EventBus,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        mock_mdns_browser: AsyncMock,
        mock_ssdp_scanner: AsyncMock,
    ) -> None:
        """When HA is enabled with valid config, Phase 3 calls HA client and skips mDNS/SSDP."""
        from squirrelops_home_sensor.integrations.home_assistant import (
            HAArea,
            HADevice,
            HomeAssistantClient,
        )

        mock_ha = AsyncMock(spec=HomeAssistantClient)
        mock_ha.get_devices.return_value = [
            HADevice(
                id="ha-dev-1",
                name="Living Room Light",
                manufacturer="Philips",
                model="Hue Bulb",
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:01"}),
                area_id="area-1",
            ),
        ]
        mock_ha.get_areas.return_value = [
            HAArea(id="area-1", name="Living Room"),
        ]

        ha_config = {"enabled": True, "url": "http://ha.local:8123", "token": "test-token"}

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns_browser,
            ssdp_scanner=mock_ssdp_scanner,
            ha_client=mock_ha,
            ha_config=ha_config,
        )
        await loop.run_single_scan()

        # HA client should have been called
        mock_ha.get_devices.assert_called_once()
        mock_ha.get_areas.assert_called_once()

        # mDNS/SSDP should NOT have been called
        mock_mdns_browser.browse.assert_not_called()
        mock_ssdp_scanner.scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_phase3_falls_back_when_ha_disabled(
        self,
        device_manager: DeviceManager,
        event_bus: EventBus,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        mock_mdns_browser: AsyncMock,
        mock_ssdp_scanner: AsyncMock,
    ) -> None:
        """When HA is disabled, Phase 3 uses mDNS/SSDP directly."""
        from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient

        mock_ha = AsyncMock(spec=HomeAssistantClient)

        ha_config = {"enabled": False, "url": "http://ha.local:8123", "token": "test-token"}

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns_browser,
            ssdp_scanner=mock_ssdp_scanner,
            ha_client=mock_ha,
            ha_config=ha_config,
        )
        await loop.run_single_scan()

        # HA client should NOT have been called
        mock_ha.get_devices.assert_not_called()
        mock_ha.get_areas.assert_not_called()

        # mDNS/SSDP should have been called
        mock_mdns_browser.browse.assert_called_once()
        mock_ssdp_scanner.scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_phase3_falls_back_when_ha_fails(
        self,
        device_manager: DeviceManager,
        event_bus: EventBus,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        mock_mdns_browser: AsyncMock,
        mock_ssdp_scanner: AsyncMock,
    ) -> None:
        """When HA client raises an exception, Phase 3 falls back to mDNS/SSDP."""
        from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient

        mock_ha = AsyncMock(spec=HomeAssistantClient)
        mock_ha.get_devices.side_effect = Exception("HA unreachable")

        ha_config = {"enabled": True, "url": "http://ha.local:8123", "token": "test-token"}

        loop = ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=mock_ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=mock_port_scanner,
            mdns_browser=mock_mdns_browser,
            ssdp_scanner=mock_ssdp_scanner,
            ha_client=mock_ha,
            ha_config=ha_config,
        )
        await loop.run_single_scan()

        # HA client was attempted
        mock_ha.get_devices.assert_called_once()

        # mDNS/SSDP should have been called as fallback
        mock_mdns_browser.browse.assert_called_once()
        mock_ssdp_scanner.scan.assert_called_once()
