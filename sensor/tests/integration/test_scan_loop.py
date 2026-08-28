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
from unittest.mock import AsyncMock

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.devices.classifier import (
    DeviceClassificationEvidence,
    DeviceClassifier,
    LLMClassifier,
)
from squirrelops_home_sensor.devices.manager import DeviceManager, ScanResult
from squirrelops_home_sensor.devices.signatures import DeviceClassification, SignatureDB
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.log import EventLog
from squirrelops_home_sensor.events.types import EventType
from squirrelops_home_sensor.privileged.helper import (
    PrivilegedOperations,
)
from squirrelops_home_sensor.scanner.loop import ScanLoop
from squirrelops_home_sensor.scanner.mdns_browser import MDNSBrowser, MDNSResult
from squirrelops_home_sensor.scanner.port_scanner import (
    PortResult,
    PortScanner,
    PortScanResults,
)
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
    scanner.scan_with_banners.return_value = {
        "192.168.1.1": [
            PortResult(port=80, service_name="http"),
            PortResult(port=443, service_name="https"),
        ],
        "192.168.1.2": [PortResult(port=22, service_name="ssh")],
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
    async def test_successful_scan_reconciles_device_online_state(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        db: aiosqlite.Connection,
        event_bus: EventBus,
    ) -> None:
        await scan_loop.run_single_scan()
        offline_events: list[dict] = []

        async def record_offline(event: dict) -> None:
            offline_events.append(event)

        event_bus.subscribe([EventType.DEVICE_OFFLINE], record_offline)

        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
        ]
        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT ip_address, is_online FROM devices ORDER BY ip_address"
        )).fetchall()
        assert [(row["ip_address"], row["is_online"]) for row in rows] == [
            ("192.168.1.1", 1),
            ("192.168.1.2", 0),
        ]
        assert [event["payload"]["device_id"] for event in offline_events] == [2]

    @pytest.mark.asyncio
    async def test_failed_scan_preserves_device_online_state(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        db: aiosqlite.Connection,
    ) -> None:
        await scan_loop.run_single_scan()
        mock_ops.arp_scan.side_effect = RuntimeError("helper unavailable")

        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT is_online FROM devices ORDER BY ip_address"
        )).fetchall()
        assert [row["is_online"] for row in rows] == [1, 1]

    @pytest.mark.asyncio
    async def test_reconciliation_failure_does_not_advance_in_memory_state(
        self,
        scan_loop: ScanLoop,
        device_manager: DeviceManager,
        db: aiosqlite.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await scan_loop.run_single_scan()
        first_id = device_manager.get_known_devices()[0].device_id
        monkeypatch.setattr(
            db,
            "commit",
            AsyncMock(side_effect=OSError("disk unavailable")),
        )

        with pytest.raises(OSError, match="disk unavailable"):
            await device_manager.reconcile_online_state({first_id})

        assert [device.is_online for device in device_manager.get_known_devices()] == [
            True,
            True,
        ]

    @pytest.mark.asyncio
    async def test_returning_offline_device_publishes_online_transition(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        event_bus: EventBus,
    ) -> None:
        await scan_loop.run_single_scan()
        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
        ]
        await scan_loop.run_single_scan()
        online_events: list[dict] = []

        async def record_online(event: dict) -> None:
            online_events.append(event)

        event_bus.subscribe([EventType.DEVICE_ONLINE], record_online)
        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
            ("192.168.1.2", "AA:BB:CC:DD:EE:02"),
        ]

        await scan_loop.run_single_scan()

        assert [event["payload"]["device_id"] for event in online_events] == [2]

    @pytest.mark.asyncio
    async def test_empty_arp_snapshot_preserves_device_online_state(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        db: aiosqlite.Connection,
    ) -> None:
        await scan_loop.run_single_scan()
        mock_ops.arp_scan.return_value = []

        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT is_online FROM devices ORDER BY ip_address"
        )).fetchall()
        assert [row["is_online"] for row in rows] == [1, 1]

    @pytest.mark.asyncio
    async def test_ip_reuse_marks_previous_mac_offline(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        db: aiosqlite.Connection,
    ) -> None:
        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", "AA:BB:CC:DD:EE:50"),
        ]
        await scan_loop.run_single_scan()
        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", "AA:BB:CC:DD:EE:51"),
        ]

        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT mac_address, is_online FROM devices ORDER BY id"
        )).fetchall()
        assert [(row["mac_address"], row["is_online"]) for row in rows] == [
            ("AA:BB:CC:DD:EE:50", 0),
            ("AA:BB:CC:DD:EE:51", 1),
        ]

    @pytest.mark.asyncio
    async def test_ip_reuse_attributes_ports_and_analysis_to_current_mac(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        device_manager: DeviceManager,
    ) -> None:
        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", "AA:BB:CC:DD:EE:50"),
        ]
        mock_port_scanner.scan_with_banners.return_value = {}
        await scan_loop.run_single_scan()

        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", "AA:BB:CC:DD:EE:51"),
        ]
        mock_port_scanner.scan_with_banners.return_value = {
            "192.168.1.50": [PortResult(port=445, service_name="smb")],
        }
        analyzer = AsyncMock()
        analyzer.analyze_all_devices.return_value = 0
        scan_loop._security_analyzer = analyzer

        await scan_loop.run_single_scan()

        by_mac = {
            device.mac_address: device
            for device in device_manager.get_known_devices()
        }
        assert by_mac["AA:BB:CC:DD:EE:50"].open_ports == frozenset()
        assert by_mac["AA:BB:CC:DD:EE:51"].open_ports == frozenset({445})
        analyzed = analyzer.analyze_all_devices.await_args.args[0]
        assert [device["device_id"] for device in analyzed] == [
            by_mac["AA:BB:CC:DD:EE:51"].device_id
        ]

    @pytest.mark.asyncio
    async def test_ip_reuse_attributes_discovery_to_current_mac(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        mock_mdns_browser: AsyncMock,
        device_manager: DeviceManager,
    ) -> None:
        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", "AA:BB:CC:DD:EE:50"),
        ]
        await scan_loop.run_single_scan()

        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", "AA:BB:CC:DD:EE:51"),
        ]
        mock_mdns_browser.browse.return_value = [
            MDNSResult(ip="192.168.1.50", hostname="new-host.local."),
        ]

        await scan_loop.run_single_scan()

        by_mac = {
            device.mac_address: device
            for device in device_manager.get_known_devices()
        }
        assert by_mac["AA:BB:CC:DD:EE:50"].hostname is None
        assert by_mac["AA:BB:CC:DD:EE:51"].hostname == "new-host.local."

    @pytest.mark.asyncio
    async def test_duplicate_proxy_rows_do_not_register_the_sensor_as_a_device(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        db: aiosqlite.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        local_mac = "1c:1d:d3:e0:7d:03"
        external_mac = "38:42:0b:48:51:07"
        monkeypatch.setattr(
            "squirrelops_home_sensor.scanner.loop._local_interface_macs",
            lambda: {local_mac},
            raising=False,
        )
        mock_ops.arp_scan.return_value = [
            ("192.168.1.18", local_mac),
            ("192.168.1.200", local_mac),
            ("192.168.1.200", external_mac),
        ]

        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT ip_address, mac_address FROM devices ORDER BY id"
        )).fetchall()
        assert [(row["ip_address"], row["mac_address"]) for row in rows] == [
            ("192.168.1.200", "38:42:0B:48:51:07"),
        ]

    @pytest.mark.asyncio
    async def test_same_mac_multi_ip_is_quarantined(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        db: aiosqlite.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "squirrelops_home_sensor.scanner.loop._local_interface_macs",
            lambda: set(),
            raising=False,
        )
        mock_ops.arp_scan.return_value = [
            ("192.168.1.203", "AE:29:0A:E5:CC:C5"),
            ("192.168.1.209", "AE:29:0A:E5:CC:C5"),
        ]

        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT ip_address, mac_address FROM devices"
        )).fetchall()
        assert rows == []

    @pytest.mark.asyncio
    async def test_forged_lower_ip_cannot_move_device_or_wipe_verified_ports(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        device_manager: DeviceManager,
        db: aiosqlite.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ambiguous MAC claims quarantine both targets and preserve inventory."""
        monkeypatch.setattr(
            "squirrelops_home_sensor.scanner.loop._local_interface_macs",
            lambda: set(),
            raising=False,
        )
        victim_mac = "AA:BB:CC:00:00:50"
        other_mac = "DE:AD:BE:EF:00:99"
        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", victim_mac),
            ("192.168.1.99", other_mac),
        ]
        mock_port_scanner.scan_with_banners.return_value = {
            "192.168.1.50": [
                PortResult(port=22, service_name="ssh"),
                PortResult(port=445, service_name="smb"),
            ],
            "192.168.1.99": [
                PortResult(port=80, service_name="http"),
            ],
        }
        await scan_loop.run_single_scan()

        analyzer = AsyncMock()
        analyzer.analyze_all_devices.return_value = 0
        scan_loop._security_analyzer = analyzer
        mock_port_scanner.reset_mock()
        mock_ops.arp_scan.return_value = [
            ("192.168.1.50", victim_mac),
            ("192.168.1.3", victim_mac),
            ("192.168.1.99", other_mac),
        ]
        mock_port_scanner.scan_with_banners.return_value = {}

        await scan_loop.run_single_scan()

        victim = next(
            device
            for device in device_manager.get_known_devices()
            if device.mac_address == victim_mac
        )
        assert victim.ip_address == "192.168.1.50"
        assert victim.open_ports == frozenset({22, 445})
        assert mock_port_scanner.scan_with_banners.call_args.kwargs["targets"] == [
            "192.168.1.99"
        ]
        rows = await (await db.execute(
            "SELECT port FROM device_open_ports "
            "WHERE device_id = ? ORDER BY port",
            (victim.device_id,),
        )).fetchall()
        assert [row["port"] for row in rows] == [22, 445]
        analyzer.record_arp_conflicts.assert_awaited_once_with(
            [{
                "kind": "mac_observed_at_multiple_ips",
                "ip_addresses": ["192.168.1.3", "192.168.1.50"],
                "mac_addresses": [victim_mac],
            }]
        )

    @pytest.mark.asyncio
    async def test_security_analysis_uses_only_hosts_seen_in_current_scan(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        device_manager: DeviceManager,
    ) -> None:
        await device_manager.process_scan_result(
            ScanResult(
                ip_address="192.168.1.50",
                mac_address="AA:BB:CC:DD:EE:50",
                open_ports=[22],
            )
        )
        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
        ]
        analyzer = AsyncMock()
        analyzer.analyze_all_devices.return_value = 0
        scan_loop._security_analyzer = analyzer

        await scan_loop.run_single_scan()

        analyzed = analyzer.analyze_all_devices.await_args.args[0]
        assert {device["ip_address"] for device in analyzed} == {"192.168.1.1"}

    @pytest.mark.asyncio
    async def test_closed_ports_are_cleared_and_reach_security_analysis(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        device_manager: DeviceManager,
        db: aiosqlite.Connection,
    ) -> None:
        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
        ]
        mock_port_scanner.scan_with_banners.return_value = {
            "192.168.1.1": [PortResult(port=22, service_name="ssh")],
        }
        analyzer = AsyncMock()
        analyzer.analyze_all_devices.return_value = 0
        scan_loop._security_analyzer = analyzer
        await scan_loop.run_single_scan()
        analyzer.analyze_all_devices.reset_mock()
        mock_port_scanner.scan_with_banners.return_value = {}

        await scan_loop.run_single_scan()

        tracked = device_manager.get_known_devices()
        assert len(tracked) == 1
        assert tracked[0].open_ports == frozenset()
        assert (await (await db.execute(
            "SELECT COUNT(*) FROM device_open_ports"
        )).fetchone())[0] == 0
        analyzed = analyzer.analyze_all_devices.await_args.args[0]
        assert len(analyzed) == 1
        assert analyzed[0]["open_ports"] == frozenset()

    @pytest.mark.asyncio
    async def test_single_scan_enriches_with_ports(
        self, scan_loop: ScanLoop, mock_port_scanner: AsyncMock, device_manager: DeviceManager
    ) -> None:
        """Phase 2: port scan enriches devices with open ports."""
        await scan_loop.run_single_scan()
        mock_port_scanner.scan_with_banners.assert_called_once()
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
    async def test_ip_conflicts_are_reconciled_before_device_filtering(
        self, scan_loop: ScanLoop, mock_ops: AsyncMock, db: aiosqlite.Connection,
    ) -> None:
        observed_device_counts: list[int] = []

        async def reconcile(raw_arp: list[tuple[str, str]]) -> None:
            assert raw_arp == mock_ops.arp_scan.return_value
            cursor = await db.execute("SELECT COUNT(*) FROM devices")
            observed_device_counts.append((await cursor.fetchone())[0])

        scan_loop.set_ip_conflict_handler(reconcile)
        await scan_loop.run_single_scan()

        assert observed_device_counts == [0]

    @pytest.mark.asyncio
    async def test_system_mimics_are_never_scanned_by_the_sensor(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        mock_port_scanner: AsyncMock,
        db: aiosqlite.Connection,
        event_bus: EventBus,
    ) -> None:
        """Proxy-ARP responses for mimics must not make scheduled scans self-trigger."""
        mock_ops.arp_scan.return_value = [
            ("192.168.1.10", "AA:BB:CC:DD:EE:10"),
            ("192.168.1.200", "02:00:00:00:00:01"),
        ]
        mock_port_scanner.scan_with_banners.return_value = {
            "192.168.1.10": [PortResult(port=22, service_name="ssh")],
        }
        await db.execute(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config,
                created_at, updated_at)
               VALUES ('Mimic: Printer', 'mimic', '192.168.1.200', 80,
                       'active', '{}', '2026-07-23T00:00:00Z',
                       '2026-07-23T00:00:00Z')"""
        )
        await db.commit()

        conflict_inputs: list[list[tuple[str, str]]] = []

        async def reconcile(raw_arp: list[tuple[str, str]]) -> None:
            conflict_inputs.append(raw_arp)

        completed: list[dict] = []

        async def record_complete(event: dict) -> None:
            completed.append(event)

        scan_loop.set_ip_conflict_handler(reconcile)
        event_bus.subscribe([EventType.SYSTEM_SCAN_COMPLETE], record_complete)

        await scan_loop.run_single_scan()
        await asyncio.sleep(0.1)

        assert conflict_inputs == [mock_ops.arp_scan.return_value]
        assert mock_port_scanner.scan_with_banners.call_args.kwargs["targets"] == [
            "192.168.1.10"
        ]
        cursor = await db.execute(
            "SELECT ip_address FROM devices ORDER BY ip_address"
        )
        assert [row[0] for row in await cursor.fetchall()] == ["192.168.1.10"]
        assert completed[-1]["payload"]["hosts_discovered"] == 1

    @pytest.mark.asyncio
    async def test_port_scan_failure_doesnt_block_devices(
        self, device_manager: DeviceManager, event_bus: EventBus,
        mock_ops: AsyncMock,
    ) -> None:
        """If port scan fails, devices are still created from ARP."""
        failing_scanner = AsyncMock(spec=PortScanner)
        failing_scanner.scan_with_banners.side_effect = OSError("network error")

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

    @pytest.mark.asyncio
    async def test_port_scan_failure_preserves_last_verified_ports(
        self,
        scan_loop: ScanLoop,
        mock_port_scanner: AsyncMock,
        device_manager: DeviceManager,
        db: aiosqlite.Connection,
    ) -> None:
        await scan_loop.run_single_scan()
        analyzer = AsyncMock()
        scan_loop._security_analyzer = analyzer
        mock_port_scanner.scan_with_banners.side_effect = OSError("network error")

        await scan_loop.run_single_scan()

        tracked = next(
            device
            for device in device_manager.get_known_devices()
            if device.ip_address == "192.168.1.1"
        )
        assert tracked.open_ports == frozenset({80, 443})
        rows = await (await db.execute(
            "SELECT port FROM device_open_ports "
            "WHERE device_id = ? ORDER BY port",
            (tracked.device_id,),
        )).fetchall()
        assert [row["port"] for row in rows] == [80, 443]
        analyzer.analyze_all_devices.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_inconclusive_probe_preserves_only_that_verified_port(
        self,
        scan_loop: ScanLoop,
        mock_port_scanner: AsyncMock,
        device_manager: DeviceManager,
        db: aiosqlite.Connection,
    ) -> None:
        await scan_loop.run_single_scan()
        mock_port_scanner.scan_with_banners.return_value = PortScanResults(
            {
                "192.168.1.1": [
                    PortResult(port=80, service_name="http"),
                ],
            },
            inconclusive_ports={
                "192.168.1.1": frozenset({443}),
            },
        )

        await scan_loop.run_single_scan()

        tracked = next(
            device
            for device in device_manager.get_known_devices()
            if device.ip_address == "192.168.1.1"
        )
        assert tracked.open_ports == frozenset({80, 443})
        rows = await (await db.execute(
            "SELECT port, service_name FROM device_open_ports "
            "WHERE device_id = ? ORDER BY port",
            (tracked.device_id,),
        )).fetchall()
        assert [(row["port"], row["service_name"]) for row in rows] == [
            (80, "http"),
            (443, "https"),
        ]

    @pytest.mark.asyncio
    async def test_processing_error_skips_authoritative_offline_reconciliation(
        self,
        scan_loop: ScanLoop,
        mock_ops: AsyncMock,
        device_manager: DeviceManager,
        db: aiosqlite.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await scan_loop.run_single_scan()
        mock_ops.arp_scan.return_value = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
        ]

        async def fail_processing(_scan: ScanResult) -> int:
            raise RuntimeError("database unavailable")

        monkeypatch.setattr(device_manager, "process_scan_result", fail_processing)
        await scan_loop.run_single_scan()

        rows = await (await db.execute(
            "SELECT is_online FROM devices ORDER BY ip_address"
        )).fetchall()
        assert [row["is_online"] for row in rows] == [1, 1]


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

    def test_interval_can_be_reconfigured_live(self, scan_loop: ScanLoop) -> None:
        scan_loop.set_scan_interval(60)

        assert scan_loop.scan_interval == 60
        assert scan_loop._reschedule.is_set()

    @pytest.mark.parametrize("value", [0, -1])
    def test_rejects_invalid_live_interval(
        self, scan_loop: ScanLoop, value: int,
    ) -> None:
        with pytest.raises(ValueError, match="greater than zero"):
            scan_loop.set_scan_interval(value)


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
        failing_scanner.scan_with_banners.side_effect = OSError("network error")

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
        scanner.scan_with_banners.return_value = {
            "192.168.1.1": [PortResult(port=80, service_name="http")]
        }

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

    @pytest.mark.asyncio
    async def test_port_enrichment_preserves_other_fingerprint_signals(
        self,
        device_manager: DeviceManager,
    ) -> None:
        await device_manager.process_scan_result(ScanResult(
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:DD:EE:01",
            mdns_hostname="printer.local.",
            dhcp_options=[1, 3, 6, 15],
            connections=[("1.1.1.1", 443)],
            open_ports=[22],
        ))
        before = device_manager.get_known_devices()[0].fingerprint

        await device_manager.enrich_device_ports("192.168.1.1", [80, 443])

        after = device_manager.get_known_devices()[0].fingerprint
        assert after.mdns_hostname == before.mdns_hostname
        assert after.dhcp_fingerprint_hash == before.dhcp_fingerprint_hash
        assert after.connection_pattern_hash == before.connection_pattern_hash
        assert after.open_ports_hash != before.open_ports_hash


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

    @pytest.mark.asyncio
    async def test_discovery_enrichment_preserves_other_fingerprint_signals(
        self,
        device_manager: DeviceManager,
    ) -> None:
        await device_manager.process_scan_result(ScanResult(
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:DD:EE:01",
            mdns_hostname="old-name.local.",
            dhcp_options=[1, 3, 6, 15],
            connections=[("1.1.1.1", 443)],
            open_ports=[22],
        ))
        before = device_manager.get_known_devices()[0].fingerprint

        await device_manager.enrich_device_discovery(
            ip_address="192.168.1.1",
            mdns_hostname="new-name.local.",
        )

        after = device_manager.get_known_devices()[0].fingerprint
        assert after.mdns_hostname != before.mdns_hostname
        assert after.dhcp_fingerprint_hash == before.dhcp_fingerprint_hash
        assert after.connection_pattern_hash == before.connection_pattern_hash
        assert after.open_ports_hash == before.open_ports_hash


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
    async def test_ai_classification_runs_after_port_and_discovery_enrichment(
        self,
        db: aiosqlite.Connection,
        event_bus: EventBus,
    ) -> None:
        """The provider receives useful Phase 2/3 evidence in one final call."""

        class CapturingLLM(LLMClassifier):
            evidence: DeviceClassificationEvidence | None = None

            async def classify(
                self,
                fingerprint,
                evidence=None,
            ) -> DeviceClassification:
                self.evidence = evidence
                return DeviceClassification(
                    manufacturer="Acme",
                    device_type="nas",
                    model="Vault 2000",
                    confidence=0.8,
                    source="llm",
                )

        llm = CapturingLLM()
        manager = DeviceManager(
            db=db,
            event_bus=event_bus,
            classifier=DeviceClassifier(
                SignatureDB({}, {}, []),
                llm,
            ),
        )
        ops = AsyncMock(spec=PrivilegedOperations)
        ops.arp_scan.return_value = [
            ("192.168.1.77", "02:00:00:00:00:77"),
        ]
        port_scanner = AsyncMock(spec=PortScanner)
        port_scanner.scan_with_banners.return_value = {
            "192.168.1.77": [
                PortResult(port=22, service_name="ssh"),
                PortResult(port=445, service_name="microsoft-ds"),
            ],
        }
        mdns = AsyncMock(spec=MDNSBrowser)
        mdns.browse.return_value = [
            MDNSResult(
                ip="192.168.1.77",
                hostname="vault.local.",
                service_types=frozenset({"_smb._tcp.local."}),
            ),
        ]
        ssdp = AsyncMock(spec=SSDPScanner)
        ssdp.scan.return_value = [
            SSDPResult(
                ip="192.168.1.77",
                friendly_name="Office Vault",
                manufacturer="Acme Hardware",
                model_name="Vault 2000",
                server_header="Linux UPnP/1.0",
            ),
        ]
        loop = ScanLoop(
            device_manager=manager,
            event_bus=event_bus,
            privileged_ops=ops,
            subnet="192.168.1.0/24",
            scan_interval=1,
            port_scanner=port_scanner,
            mdns_browser=mdns,
            ssdp_scanner=ssdp,
        )

        await loop.run_single_scan()

        assert llm.evidence is not None
        assert llm.evidence.open_ports == (22, 445)
        assert llm.evidence.detected_services == ("microsoft-ds", "ssh")
        assert llm.evidence.mdns_hostname == "vault.local."
        assert llm.evidence.mdns_service_types == ("_smb._tcp.local.",)
        assert llm.evidence.upnp_friendly_name == "Office Vault"
        assert llm.evidence.upnp_server_header == "Linux UPnP/1.0"

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
    async def test_ha_enrichment_preserves_other_fingerprint_signals(
        self,
        device_manager: DeviceManager,
    ) -> None:
        from squirrelops_home_sensor.integrations.home_assistant import (
            HAArea,
            HADevice,
        )

        await device_manager.process_scan_result(ScanResult(
            ip_address="192.168.1.1",
            mac_address="AA:BB:CC:DD:EE:01",
            mdns_hostname="device.local.",
            dhcp_options=[1, 3, 6, 15],
            connections=[("1.1.1.1", 443)],
            open_ports=[22],
        ))
        before = device_manager.get_known_devices()[0].fingerprint

        await device_manager.enrich_device_ha(
            [HADevice(
                id="ha-dev-1",
                name="Living Room Device",
                manufacturer="Example",
                model="Model 1",
                mac_addresses=frozenset({"aa:bb:cc:dd:ee:01"}),
                area_id="area-1",
            )],
            [HAArea(id="area-1", name="Living Room")],
        )

        after = device_manager.get_known_devices()[0].fingerprint
        assert after.mdns_hostname == before.mdns_hostname
        assert after.dhcp_fingerprint_hash == before.dhcp_fingerprint_hash
        assert after.connection_pattern_hash == before.connection_pattern_hash
        assert after.open_ports_hash == before.open_ports_hash

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
