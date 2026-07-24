"""Device manager: orchestrates the discovery-to-event pipeline.

Pipeline stages:
1. Receive scan result
2. Compute composite fingerprint
3. Match against known devices
4. Classify if new (local DB -> LLM -> fallback)
5. Store fingerprint and device in database
6. Publish events (device.new, device.updated, device.verification_needed, device.mac_changed)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from squirrelops_home_sensor.devices.classifier import DeviceClassifier
from squirrelops_home_sensor.devices.decoy_filter import DECOY_DEVICE_FILTER, is_decoy_device_ip
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.types import EventType
from squirrelops_home_sensor.fingerprint.composite import (
    CompositeFingerprint,
    compute_fingerprint,
)
from squirrelops_home_sensor.fingerprint.matcher import (
    DEFAULT_WEIGHTS,
    KnownDevice,
    match_device,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Confidence thresholds (matching the spec defaults)
# ---------------------------------------------------------------------------

AUTO_APPROVE_THRESHOLD = 0.75
VERIFY_THRESHOLD = 0.20


# ---------------------------------------------------------------------------
# Scan result input
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanResult:
    """Raw scan result from the network scanner.

    This is the input to the device manager pipeline. All fields
    except ip_address are optional -- the pipeline handles partial data.
    """

    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    mdns_hostname: str | None = None
    open_ports: list[int] | None = None
    dhcp_options: list[int] | None = None
    connections: list[tuple[str, int]] | None = None


# ---------------------------------------------------------------------------
# Internal tracked device
# ---------------------------------------------------------------------------

@dataclass
class TrackedDevice:
    """Internal representation of a known device."""

    device_id: int
    ip_address: str
    mac_address: str | None
    hostname: str | None
    vendor: str | None
    device_type: str | None
    fingerprint: CompositeFingerprint
    connection_destinations: frozenset[str]
    open_ports: frozenset[int]
    first_seen: datetime
    last_seen: datetime
    is_online: bool = True
    model_name: str | None = None
    area: str | None = None


# ---------------------------------------------------------------------------
# Device manager
# ---------------------------------------------------------------------------

class DeviceManager:
    """Orchestrates the full device identification pipeline.

    Parameters
    ----------
    db:
        Open aiosqlite connection with schema applied.
    event_bus:
        Event bus for publishing device events.
    classifier:
        Device classifier for new device identification.
    """

    def __init__(
        self,
        db: aiosqlite.Connection,
        event_bus: EventBus,
        classifier: DeviceClassifier,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._db = db
        self._bus = event_bus
        self._classifier = classifier
        self._config = config
        self._known_devices: list[TrackedDevice] = []

    def _fingerprint_config(self) -> dict[str, Any]:
        if self._config is None:
            return {}
        fingerprint = self._config.get("fingerprint", {})
        return fingerprint if isinstance(fingerprint, dict) else {}

    @staticmethod
    def _float_config(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _auto_approve_threshold(self) -> float:
        return self._float_config(
            self._fingerprint_config().get("auto_approve_threshold"),
            AUTO_APPROVE_THRESHOLD,
        )

    def _verify_threshold(self) -> float:
        return self._float_config(
            self._fingerprint_config().get("verify_threshold"),
            VERIFY_THRESHOLD,
        )

    def _signal_weights(self) -> dict[str, float]:
        configured = self._fingerprint_config().get("signal_weights", {})
        if not isinstance(configured, dict):
            return DEFAULT_WEIGHTS

        weights = dict(DEFAULT_WEIGHTS)
        for signal, default in DEFAULT_WEIGHTS.items():
            weights[signal] = self._float_config(configured.get(signal), default)
        return weights

    async def _build_device_payload(
        self, tracked: TrackedDevice, now_iso: str
    ) -> dict[str, Any]:
        """Build a full device summary dict for WebSocket event payloads.

        Reads trust_status and custom_name from the database so event
        payloads always reflect the current persisted state.
        """
        # Trust status from device_trust table
        trust_status = "unknown"
        cursor = await self._db.execute(
            "SELECT status FROM device_trust WHERE device_id = ?",
            (tracked.device_id,),
        )
        row = await cursor.fetchone()
        if row:
            trust_status = row[0]

        # Custom name from devices table
        custom_name = None
        cursor = await self._db.execute(
            "SELECT custom_name FROM devices WHERE id = ?",
            (tracked.device_id,),
        )
        row = await cursor.fetchone()
        if row and row[0]:
            custom_name = row[0]

        return {
            "id": tracked.device_id,
            "ip_address": tracked.ip_address,
            "mac_address": tracked.mac_address,
            "hostname": tracked.hostname,
            "vendor": tracked.vendor,
            "device_type": tracked.device_type or "unknown",
            "model_name": tracked.model_name,
            "custom_name": custom_name,
            "area": tracked.area,
            "trust_status": trust_status,
            "is_online": tracked.is_online,
            "first_seen": tracked.first_seen.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "last_seen": now_iso,
        }

    async def load_known_devices(self) -> None:
        """Load previously-discovered devices from the database.

        Populates ``_known_devices`` so the fingerprint matcher can
        recognise returning devices across sensor restarts. Should be
        called once at startup before the first scan.

        Uses bulk queries instead of per-device lookups to avoid N+1.
        """
        cursor = await self._db.execute(
            "SELECT d.id, d.ip_address, d.mac_address, d.hostname, "
            "d.vendor, d.device_type, d.model_name, d.first_seen, d.last_seen, "
            "fp.mdns_hostname, fp.dhcp_fingerprint_hash, "
            "fp.connection_pattern_hash, fp.open_ports_hash, d.area, d.is_online "
            "FROM devices d "
            "LEFT JOIN device_fingerprints fp ON fp.device_id = d.id "
            "AND fp.id = (SELECT MAX(fp2.id) FROM device_fingerprints fp2 "
            "WHERE fp2.device_id = d.id) "
            f"WHERE {DECOY_DEVICE_FILTER}"
        )
        rows = await cursor.fetchall()

        # Batch-load connection baselines and open ports to avoid N+1 queries
        device_ids = [row[0] for row in rows]

        # Build {device_id: frozenset("ip:port", ...)} lookup
        baselines_by_device: dict[int, frozenset[str]] = {}
        if device_ids:
            placeholders = ",".join("?" * len(device_ids))
            bl_cursor = await self._db.execute(
                f"SELECT device_id, dest_ip, dest_port FROM connection_baselines "
                f"WHERE device_id IN ({placeholders})",
                device_ids,
            )
            mutable_baselines: dict[int, set[str]] = {}
            for bl_row in await bl_cursor.fetchall():
                did = bl_row[0]
                entry = f"{bl_row[1]}:{bl_row[2]}"
                mutable_baselines.setdefault(did, set()).add(entry)
            baselines_by_device = {
                did: frozenset(dests)
                for did, dests in mutable_baselines.items()
            }

        # Build {device_id: frozenset(port, ...)} lookup
        ports_by_device: dict[int, frozenset[int]] = {}
        if device_ids:
            placeholders = ",".join("?" * len(device_ids))
            port_cursor = await self._db.execute(
                f"SELECT device_id, port FROM device_open_ports "
                f"WHERE device_id IN ({placeholders})",
                device_ids,
            )
            mutable_ports: dict[int, set[int]] = {}
            for port_row in await port_cursor.fetchall():
                mutable_ports.setdefault(port_row[0], set()).add(port_row[1])
            ports_by_device = {
                did: frozenset(ports)
                for did, ports in mutable_ports.items()
            }

        loaded: list[TrackedDevice] = []
        for row in rows:
            device_id = row[0]

            # Build composite fingerprint from latest DB snapshot
            fp = CompositeFingerprint(
                mac_address=row[2],       # d.mac_address
                mdns_hostname=row[9],     # fp.mdns_hostname
                dhcp_fingerprint_hash=row[10],
                connection_pattern_hash=row[11],
                open_ports_hash=row[12],
            )

            # Parse timestamps
            first_seen = datetime.fromisoformat(row[7].replace("Z", "+00:00"))
            last_seen = datetime.fromisoformat(row[8].replace("Z", "+00:00"))

            loaded.append(TrackedDevice(
                device_id=device_id,
                ip_address=row[1],
                mac_address=row[2],
                hostname=row[3],
                vendor=row[4],
                device_type=row[5],
                model_name=row[6],
                fingerprint=fp,
                connection_destinations=baselines_by_device.get(device_id, frozenset()),
                open_ports=ports_by_device.get(device_id, frozenset()),
                first_seen=first_seen,
                last_seen=last_seen,
                is_online=bool(row[14]),
                area=row[13],
            ))

        self._known_devices = loaded
        logger.info("Loaded %d known devices from database", len(loaded))

        # Reclassify devices with Unknown vendor (may now resolve via bulk OUI DB)
        reclassified = 0
        for td in self._known_devices:
            if td.vendor == "Unknown" and td.mac_address is not None:
                fp = CompositeFingerprint(mac_address=td.mac_address)
                classification = await self._classifier.classify(fp)
                if classification.manufacturer != "Unknown":
                    await self._db.execute(
                        "UPDATE devices SET vendor = ?, device_type = ? WHERE id = ?",
                        (classification.manufacturer, classification.device_type, td.device_id),
                    )
                    td.vendor = classification.manufacturer
                    td.device_type = classification.device_type
                    reclassified += 1
        if reclassified > 0:
            await self._db.commit()
            logger.info("Reclassified %d devices with updated OUI database", reclassified)

    async def is_system_decoy_ip(self, ip_address: str) -> bool:
        """Return whether an address is currently reserved for a virtual decoy."""
        return await is_decoy_device_ip(self._db, ip_address)

    async def reconcile_online_state(self, seen_device_ids: set[int]) -> None:
        """Make a successful ARP snapshot authoritative for online status."""
        transitions: list[tuple[TrackedDevice, bool]] = []
        for tracked in self._known_devices:
            now_online = tracked.device_id in seen_device_ids
            if tracked.is_online != now_online:
                transitions.append((tracked, now_online))

        if seen_device_ids:
            ordered_ids = sorted(seen_device_ids)
            placeholders = ",".join("?" for _ in ordered_ids)
            await self._db.execute(
                f"""UPDATE devices
                    SET is_online = CASE
                        WHEN id IN ({placeholders}) THEN 1
                        ELSE 0
                    END""",
                ordered_ids,
            )
        else:
            await self._db.execute("UPDATE devices SET is_online = 0")
        await self._db.commit()

        for tracked, is_online in transitions:
            await self._bus.publish(
                EventType.DEVICE_ONLINE if is_online else EventType.DEVICE_OFFLINE,
                {"device_id": tracked.device_id},
                source_id=str(tracked.device_id),
            )
            tracked.is_online = is_online

    async def process_scan_result(self, scan: ScanResult) -> int | None:
        """Process a single scan result through the full pipeline.

        Parameters
        ----------
        scan:
            Raw scan result from the network scanner.
        """
        now = datetime.now(UTC)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if await self.is_system_decoy_ip(scan.ip_address):
            self._known_devices = [
                td for td in self._known_devices if td.ip_address != scan.ip_address
            ]
            logger.debug(
                "Ignoring system-created decoy IP in device scan: %s",
                scan.ip_address,
            )
            return None

        # Stage 1: Compute composite fingerprint
        fp = compute_fingerprint(
            mac=scan.mac_address,
            mdns_hostname=scan.mdns_hostname,
            dhcp_options=scan.dhcp_options,
            connections=scan.connections,
            open_ports=scan.open_ports,
        )

        # Build set representations for Jaccard comparison
        conn_dests = (
            frozenset(f"{ip}:{port}" for ip, port in scan.connections)
            if scan.connections is not None
            else None
        )
        ports_set = (
            frozenset(scan.open_ports)
            if scan.open_ports is not None
            else None
        )

        # Stage 2: Match against known devices
        # Fast path: direct MAC lookup (handles ARP-only scans where the
        # multi-signal matcher has no non-MAC signals to work with)
        matched_id: int | None = None
        confidence: float = 0.0

        if fp.mac_address is not None:
            mac_match = next(
                (td for td in self._known_devices
                 if td.mac_address == fp.mac_address),
                None,
            )
            if mac_match is not None:
                matched_id = mac_match.device_id
                confidence = self._auto_approve_threshold()

        # Full multi-signal matching (for devices without MAC or when
        # MAC didn't match -- e.g. MAC randomisation)
        if matched_id is None:
            known_for_match = [
                KnownDevice(
                    device_id=td.device_id,
                    fingerprint=td.fingerprint,
                    connection_destinations=td.connection_destinations,
                    open_ports=td.open_ports,
                )
                for td in self._known_devices
            ]

            matched_id, confidence = match_device(
                fp,
                known_for_match,
                connection_destinations=conn_dests or frozenset(),
                open_ports=ports_set or frozenset(),
                weights=self._signal_weights(),
            )

        if matched_id is not None:
            # Found a match -- update existing device
            return await self._handle_matched_device(
                matched_id, confidence, scan, fp, conn_dests, ports_set, now, now_iso
            )

        # New device
        return await self._handle_new_device(
            scan,
            fp,
            conn_dests or frozenset(),
            ports_set or frozenset(),
            now,
            now_iso,
        )

    async def _handle_new_device(
        self,
        scan: ScanResult,
        fp: CompositeFingerprint,
        conn_dests: frozenset[str],
        ports_set: frozenset[int],
        now: datetime,
        now_iso: str,
    ) -> int:
        """Handle a newly-discovered device."""
        # Classify
        classification = await self._classifier.classify(fp)

        # Store in database — let SQLite auto-assign the ID
        cursor = await self._db.execute(
            "INSERT INTO devices (ip_address, mac_address, hostname, vendor, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan.ip_address, fp.mac_address, scan.hostname,
             classification.manufacturer, now_iso, now_iso),
        )
        device_id = cursor.lastrowid
        if device_id is None:
            raise RuntimeError("SQLite did not return a device id")

        await self._db.execute(
            "INSERT INTO device_fingerprints "
            "(device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash, "
            "connection_pattern_hash, open_ports_hash, composite_hash, "
            "signal_count, confidence, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (device_id, fp.mac_address, fp.mdns_hostname,
             fp.dhcp_fingerprint_hash, fp.connection_pattern_hash,
             fp.open_ports_hash, fp.composite_hash, fp.signal_count,
             classification.confidence, now_iso, now_iso),
        )
        await self._db.commit()

        # Track in memory
        tracked = TrackedDevice(
            device_id=device_id,
            ip_address=scan.ip_address,
            mac_address=fp.mac_address,
            hostname=scan.hostname,
            vendor=classification.manufacturer,
            device_type=classification.device_type,
            fingerprint=fp,
            connection_destinations=conn_dests,
            open_ports=ports_set,
            first_seen=now,
            last_seen=now,
            is_online=True,
        )
        self._known_devices.append(tracked)

        # Publish event with full device summary for WebSocket clients
        await self._bus.publish(
            "device.new",
            await self._build_device_payload(tracked, now_iso),
            source_id=str(device_id),
        )
        return device_id

    async def _handle_matched_device(
        self,
        matched_id: int,
        confidence: float,
        scan: ScanResult,
        fp: CompositeFingerprint,
        conn_dests: frozenset[str] | None,
        ports_set: frozenset[int] | None,
        now: datetime,
        now_iso: str,
    ) -> int:
        """Handle a returning device that matched a known device."""
        # Find the tracked device
        tracked = next(
            (td for td in self._known_devices if td.device_id == matched_id), None
        )
        if tracked is None:
            raise RuntimeError(f"Matched device {matched_id} is not loaded")
        was_online = tracked.is_online

        merged_fp = CompositeFingerprint(
            mac_address=fp.mac_address or tracked.fingerprint.mac_address,
            mdns_hostname=(
                fp.mdns_hostname
                if scan.mdns_hostname is not None
                else tracked.fingerprint.mdns_hostname
            ),
            dhcp_fingerprint_hash=(
                fp.dhcp_fingerprint_hash
                if scan.dhcp_options is not None
                else tracked.fingerprint.dhcp_fingerprint_hash
            ),
            connection_pattern_hash=(
                fp.connection_pattern_hash
                if scan.connections is not None
                else tracked.fingerprint.connection_pattern_hash
            ),
            open_ports_hash=(
                fp.open_ports_hash
                if scan.open_ports is not None
                else tracked.fingerprint.open_ports_hash
            ),
        )

        old_mac = tracked.mac_address
        new_mac = merged_fp.mac_address

        # Update tracked device state
        tracked.ip_address = scan.ip_address
        if scan.hostname is not None:
            tracked.hostname = scan.hostname
        tracked.fingerprint = merged_fp
        if conn_dests is not None:
            tracked.connection_destinations = conn_dests
        if ports_set is not None:
            tracked.open_ports = ports_set
        tracked.last_seen = now
        if new_mac is not None:
            tracked.mac_address = new_mac

        # Update database — only overwrite hostname if scan provided one
        if scan.hostname is not None:
            await self._db.execute(
                "UPDATE devices SET ip_address = ?, mac_address = ?, hostname = ?, "
                "last_seen = ?, is_online = 1 "
                "WHERE id = ?",
                (scan.ip_address, merged_fp.mac_address, scan.hostname, now_iso, matched_id),
            )
        else:
            await self._db.execute(
                "UPDATE devices SET ip_address = ?, mac_address = ?, last_seen = ?, "
                "is_online = 1 "
                "WHERE id = ?",
                (scan.ip_address, merged_fp.mac_address, now_iso, matched_id),
            )

        await self._db.execute(
            "INSERT INTO device_fingerprints "
            "(device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash, "
            "connection_pattern_hash, open_ports_hash, composite_hash, "
            "signal_count, confidence, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (matched_id, merged_fp.mac_address, merged_fp.mdns_hostname,
             merged_fp.dhcp_fingerprint_hash, merged_fp.connection_pattern_hash,
             merged_fp.open_ports_hash, merged_fp.composite_hash, merged_fp.signal_count,
             confidence, now_iso, now_iso),
        )
        auto_approve_threshold = self._auto_approve_threshold()
        verify_threshold = self._verify_threshold()
        if confidence >= auto_approve_threshold:
            await self._auto_approve_device_if_unknown(matched_id, now_iso)

        await self._db.commit()
        if not was_online:
            await self._bus.publish(
                EventType.DEVICE_ONLINE,
                {"device_id": matched_id},
                source_id=str(matched_id),
            )
        tracked.is_online = True

        # Determine which events to emit
        # MAC changed?
        if old_mac is not None and new_mac is not None and old_mac != new_mac:
            await self._bus.publish(
                "device.mac_changed",
                {
                    "device_id": matched_id,
                    "old_mac": old_mac,
                    "new_mac": new_mac,
                    "confidence": confidence,
                },
                source_id=str(matched_id),
            )

        # Build full device summary for WebSocket clients
        device_payload = await self._build_device_payload(tracked, now_iso)

        # Confidence-based events
        if confidence >= auto_approve_threshold:
            # High confidence -- silent update
            await self._bus.publish(
                "device.updated",
                device_payload,
                source_id=str(matched_id),
            )
        elif confidence >= verify_threshold:
            # Medium confidence -- verification needed
            await self._bus.publish(
                "device.verification_needed",
                device_payload,
                source_id=str(matched_id),
            )
        else:
            # Low confidence -- treated as updated but flagged
            await self._bus.publish(
                "device.updated",
                {**device_payload, "low_confidence": True},
                source_id=str(matched_id),
            )
        return matched_id

    async def _auto_approve_device_if_unknown(self, device_id: int, now_iso: str) -> None:
        cursor = await self._db.execute(
            "SELECT status FROM device_trust WHERE device_id = ?",
            (device_id,),
        )
        row = await cursor.fetchone()
        if row is not None and row[0] != "unknown":
            return

        if row is None:
            await self._db.execute(
                "INSERT INTO device_trust (device_id, status, approved_by, updated_at) "
                "VALUES (?, 'approved', 'auto', ?)",
                (device_id, now_iso),
            )
        else:
            await self._db.execute(
                "UPDATE device_trust SET status = 'approved', approved_by = 'auto', "
                "updated_at = ? WHERE device_id = ?",
                (now_iso, device_id),
            )

    def get_known_devices(self) -> list[TrackedDevice]:
        """Return the list of all known tracked devices."""
        return list(self._known_devices)

    async def _persist_open_ports(
        self, device_id: int, port_results: list[Any]
    ) -> None:
        """Persist individual open port numbers with service metadata to the database.

        Accepts either a list of PortResult objects (with service_name/banner)
        or a frozenset/list of plain ints (backward compatible).
        """
        from squirrelops_home_sensor.scanner.port_scanner import PortResult

        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        normalized: list[tuple[int, str | None, str | None]] = []
        for item in port_results:
            if isinstance(item, PortResult):
                port, svc, banner = item.port, item.service_name, item.banner
            else:
                port, svc, banner = int(item), None, None
            normalized.append((port, svc, banner))

        current_ports = sorted({port for port, _, _ in normalized})
        if current_ports:
            placeholders = ",".join("?" for _ in current_ports)
            await self._db.execute(
                f"""DELETE FROM device_open_ports
                    WHERE device_id = ? AND port NOT IN ({placeholders})""",
                (device_id, *current_ports),
            )
        else:
            await self._db.execute(
                "DELETE FROM device_open_ports WHERE device_id = ?",
                (device_id,),
            )

        for port, svc, banner in normalized:
            await self._db.execute(
                """INSERT INTO device_open_ports
                   (device_id, port, protocol, service_name, banner, first_seen, last_seen)
                   VALUES (?, ?, 'tcp', ?, ?, ?, ?)
                   ON CONFLICT(device_id, port, protocol)
                   DO UPDATE SET
                       last_seen = excluded.last_seen,
                       service_name = COALESCE(excluded.service_name, device_open_ports.service_name),
                       banner = COALESCE(excluded.banner, device_open_ports.banner)""",
                (device_id, port, svc, banner, now, now),
            )
        await self._db.commit()

    async def enrich_device_ports(
        self,
        ip_address: str,
        port_data: list[Any],
        *,
        device_id: int | None = None,
    ) -> None:
        """Enrich a known device with open port data from a port scan.

        This is called in Phase 2 of the scan loop, after devices have
        already been created from ARP results in Phase 1. If the IP is
        not associated with a known device, this is a no-op.

        Accepts either a list of PortResult objects (with service/banner
        metadata) or a list of plain ints (backward compatible).

        Parameters
        ----------
        ip_address:
            IP address of the device to enrich.
        port_data:
            List of PortResult objects or plain port numbers.
        """
        from squirrelops_home_sensor.scanner.port_scanner import PortResult

        candidates = [
            td for td in self._known_devices
            if td.ip_address == ip_address
            and (device_id is None or td.device_id == device_id)
        ]
        tracked = (
            max(candidates, key=lambda td: (td.last_seen, td.device_id))
            if candidates
            else None
        )
        if tracked is None:
            return

        # Extract port numbers for fingerprinting
        port_numbers = [
            r.port if isinstance(r, PortResult) else int(r)
            for r in port_data
        ]
        ports_set = frozenset(port_numbers)
        if ports_set == tracked.open_ports:
            # Even if port set unchanged, persist to update service_name/banner
            await self._persist_open_ports(tracked.device_id, port_data)
            return

        tracked.open_ports = ports_set
        now = datetime.now(UTC)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        tracked.last_seen = now

        # Recompute fingerprint with port data
        refreshed_port_fp = compute_fingerprint(
            mac=tracked.mac_address,
            mdns_hostname=tracked.fingerprint.mdns_hostname,
            dhcp_options=None,
            connections=None,
            open_ports=port_numbers,
        )
        fp = CompositeFingerprint(
            mac_address=refreshed_port_fp.mac_address,
            mdns_hostname=tracked.fingerprint.mdns_hostname,
            dhcp_fingerprint_hash=tracked.fingerprint.dhcp_fingerprint_hash,
            connection_pattern_hash=tracked.fingerprint.connection_pattern_hash,
            open_ports_hash=refreshed_port_fp.open_ports_hash,
        )
        tracked.fingerprint = fp

        # Update fingerprint in DB
        await self._db.execute(
            "INSERT INTO device_fingerprints "
            "(device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash, "
            "connection_pattern_hash, open_ports_hash, composite_hash, "
            "signal_count, confidence, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tracked.device_id, fp.mac_address, fp.mdns_hostname,
             fp.dhcp_fingerprint_hash, fp.connection_pattern_hash,
             fp.open_ports_hash, fp.composite_hash, fp.signal_count,
             None, now_iso, now_iso),
        )
        await self._db.execute(
            "UPDATE devices SET last_seen = ? WHERE id = ?",
            (now_iso, tracked.device_id),
        )
        await self._db.commit()

        # Persist individual port numbers with service metadata
        await self._persist_open_ports(tracked.device_id, port_data)

        # Publish device.updated with full summary
        await self._bus.publish(
            "device.updated",
            await self._build_device_payload(tracked, now_iso),
            source_id=str(tracked.device_id),
        )

    async def enrich_device_discovery(
        self,
        ip_address: str,
        mdns_hostname: str | None = None,
        upnp_friendly_name: str | None = None,
        upnp_manufacturer: str | None = None,
        upnp_model_name: str | None = None,
        *,
        device_id: int | None = None,
    ) -> None:
        """Enrich a known device with mDNS/SSDP discovery data.

        Called in Phase 3 of the scan loop after mDNS browse and SSDP
        M-SEARCH results are collected. If the IP is not associated with
        a known device, this is a no-op.

        Priority rules:
        - mDNS hostname wins over UPnP friendly name for hostname
        - UPnP manufacturer only overwrites vendor if current is "Unknown"
        - custom_name is never overwritten
        - Enrichment is additive — never removes data
        """
        candidates = [
            td for td in self._known_devices
            if td.ip_address == ip_address
            and (device_id is None or td.device_id == device_id)
        ]
        tracked = (
            max(candidates, key=lambda td: (td.last_seen, td.device_id))
            if candidates
            else None
        )
        if tracked is None:
            return

        # Determine what changed
        changed = False
        now = datetime.now(UTC)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Hostname: mDNS wins over UPnP friendly name
        new_hostname = mdns_hostname or upnp_friendly_name
        if new_hostname and new_hostname != tracked.hostname:
            tracked.hostname = new_hostname
            changed = True

        # Model name from UPnP
        if upnp_model_name:
            tracked.model_name = upnp_model_name
            await self._db.execute(
                "UPDATE devices SET model_name = ? WHERE id = ?",
                (upnp_model_name, tracked.device_id),
            )
            changed = True

        # Vendor reclassification: only if currently Unknown
        if upnp_manufacturer and tracked.vendor == "Unknown":
            tracked.vendor = upnp_manufacturer
            await self._db.execute(
                "UPDATE devices SET vendor = ? WHERE id = ?",
                (upnp_manufacturer, tracked.device_id),
            )
            changed = True

        if not changed:
            return

        tracked.last_seen = now

        # Update hostname and last_seen in DB
        await self._db.execute(
            "UPDATE devices SET hostname = ?, last_seen = ? WHERE id = ?",
            (tracked.hostname, now_iso, tracked.device_id),
        )

        # Recompute fingerprint with mdns_hostname signal
        refreshed_discovery_fp = compute_fingerprint(
            mac=tracked.mac_address,
            mdns_hostname=mdns_hostname or tracked.fingerprint.mdns_hostname,
            dhcp_options=None,
            connections=None,
            open_ports=None,
        )
        fp = CompositeFingerprint(
            mac_address=refreshed_discovery_fp.mac_address,
            mdns_hostname=refreshed_discovery_fp.mdns_hostname,
            dhcp_fingerprint_hash=tracked.fingerprint.dhcp_fingerprint_hash,
            connection_pattern_hash=tracked.fingerprint.connection_pattern_hash,
            open_ports_hash=tracked.fingerprint.open_ports_hash,
        )
        tracked.fingerprint = fp

        await self._db.execute(
            "INSERT INTO device_fingerprints "
            "(device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash, "
            "connection_pattern_hash, open_ports_hash, composite_hash, "
            "signal_count, confidence, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tracked.device_id, fp.mac_address, fp.mdns_hostname,
             fp.dhcp_fingerprint_hash, fp.connection_pattern_hash,
             fp.open_ports_hash, fp.composite_hash, fp.signal_count,
             None, now_iso, now_iso),
        )
        await self._db.commit()

        # Publish device.updated with full summary (enrich_device_discovery)
        await self._bus.publish(
            "device.updated",
            await self._build_device_payload(tracked, now_iso),
            source_id=str(tracked.device_id),
        )

    async def enrich_device_ha(
        self,
        ha_devices: list[Any],
        ha_areas: list[Any],
    ) -> None:
        """Enrich tracked devices with Home Assistant device and area data.

        Matches tracked devices to HA devices by MAC address (case-insensitive).
        Updates hostname (unless custom_name is set), model_name, vendor
        (only if currently "Unknown"), and area.

        Parameters
        ----------
        ha_devices:
            List of HADevice objects from the HA device registry.
        ha_areas:
            List of HAArea objects from the HA area registry.
        """
        # Build lookup maps
        area_map: dict[str, str] = {area.id: area.name for area in ha_areas}
        mac_to_ha: dict[str, Any] = {
            mac.lower(): ha_dev
            for ha_dev in ha_devices
            for mac in ha_dev.mac_addresses
        }

        for tracked in self._known_devices:
            if tracked.mac_address is None:
                continue

            ha_dev = mac_to_ha.get(tracked.mac_address.lower())
            if ha_dev is None:
                continue

            # Check if device has a custom_name set by user
            cursor = await self._db.execute(
                "SELECT custom_name FROM devices WHERE id = ?",
                (tracked.device_id,),
            )
            row = await cursor.fetchone()
            has_custom_name = row is not None and row["custom_name"] is not None

            changed = False
            now = datetime.now(UTC)
            now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Hostname: only if HA has a name AND no custom_name is set
            if ha_dev.name and not has_custom_name:
                tracked.hostname = ha_dev.name
                changed = True

            # Model name from HA
            if ha_dev.model:
                tracked.model_name = ha_dev.model
                changed = True

            # Vendor: only if currently Unknown
            if ha_dev.manufacturer and tracked.vendor == "Unknown":
                tracked.vendor = ha_dev.manufacturer
                changed = True

            # Area from area_map lookup
            area_name = area_map.get(ha_dev.area_id) if ha_dev.area_id else None
            if area_name != tracked.area:
                tracked.area = area_name
                changed = True

            if not changed:
                continue

            tracked.last_seen = now

            # Update DB
            await self._db.execute(
                "UPDATE devices SET hostname = ?, model_name = ?, vendor = ?, "
                "area = ?, last_seen = ? WHERE id = ?",
                (tracked.hostname, tracked.model_name, tracked.vendor,
                 tracked.area, now_iso, tracked.device_id),
            )

            # Recompute fingerprint
            fp = tracked.fingerprint
            tracked.fingerprint = fp

            await self._db.execute(
                "INSERT INTO device_fingerprints "
                "(device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash, "
                "connection_pattern_hash, open_ports_hash, composite_hash, "
                "signal_count, confidence, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tracked.device_id, fp.mac_address, fp.mdns_hostname,
                 fp.dhcp_fingerprint_hash, fp.connection_pattern_hash,
                 fp.open_ports_hash, fp.composite_hash, fp.signal_count,
                 None, now_iso, now_iso),
            )
            await self._db.commit()

            # Publish device.updated with full summary
            await self._bus.publish(
                "device.updated",
                await self._build_device_payload(tracked, now_iso),
                source_id=str(tracked.device_id),
            )
