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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from squirrelops_home_sensor.devices.classifier import DeviceClassifier
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.fingerprint.composite import (
    CompositeFingerprint,
    compute_fingerprint,
)
from squirrelops_home_sensor.fingerprint.matcher import (
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
    ) -> None:
        self._db = db
        self._bus = event_bus
        self._classifier = classifier
        self._known_devices: list[TrackedDevice] = []

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
            "is_online": True,
            "first_seen": tracked.first_seen.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "last_seen": now_iso,
        }

    async def load_known_devices(self) -> None:
        """Load previously-discovered devices from the database.

        Populates ``_known_devices`` so the fingerprint matcher can
        recognise returning devices across sensor restarts. Should be
        called once at startup before the first scan.
        """
        cursor = await self._db.execute(
            "SELECT d.id, d.ip_address, d.mac_address, d.hostname, "
            "d.vendor, d.device_type, d.model_name, d.first_seen, d.last_seen, "
            "fp.mdns_hostname, fp.dhcp_fingerprint_hash, "
            "fp.connection_pattern_hash, fp.open_ports_hash, d.area "
            "FROM devices d "
            "LEFT JOIN device_fingerprints fp ON fp.device_id = d.id "
            "AND fp.id = (SELECT MAX(fp2.id) FROM device_fingerprints fp2 "
            "WHERE fp2.device_id = d.id)"
        )
        rows = await cursor.fetchall()

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

            # Load connection baselines for Jaccard comparison
            bl_cursor = await self._db.execute(
                "SELECT dest_ip, dest_port FROM connection_baselines "
                "WHERE device_id = ?",
                (device_id,),
            )
            bl_rows = await bl_cursor.fetchall()
            conn_dests = frozenset(
                f"{r[0]}:{r[1]}" for r in bl_rows
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
                connection_destinations=conn_dests,
                open_ports=frozenset(),  # Will load from DB below
                first_seen=first_seen,
                last_seen=last_seen,
                area=row[13],
            ))

        # Load persisted open ports for each device
        for td in loaded:
            port_cursor = await self._db.execute(
                "SELECT port FROM device_open_ports WHERE device_id = ?",
                (td.device_id,),
            )
            port_rows = await port_cursor.fetchall()
            if port_rows:
                td.open_ports = frozenset(r[0] for r in port_rows)

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

    async def process_scan_result(self, scan: ScanResult) -> None:
        """Process a single scan result through the full pipeline.

        Parameters
        ----------
        scan:
            Raw scan result from the network scanner.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Stage 1: Compute composite fingerprint
        fp = compute_fingerprint(
            mac=scan.mac_address,
            mdns_hostname=scan.mdns_hostname,
            dhcp_options=scan.dhcp_options,
            connections=scan.connections,
            open_ports=scan.open_ports,
        )

        # Build set representations for Jaccard comparison
        conn_dests = frozenset(
            f"{ip}:{port}" for ip, port in scan.connections
        ) if scan.connections else frozenset()
        ports_set = frozenset(scan.open_ports) if scan.open_ports else frozenset()

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
                confidence = AUTO_APPROVE_THRESHOLD

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
                connection_destinations=conn_dests,
                open_ports=ports_set,
            )

        if matched_id is not None:
            # Found a match -- update existing device
            await self._handle_matched_device(
                matched_id, confidence, scan, fp, conn_dests, ports_set, now, now_iso
            )
        else:
            # New device
            await self._handle_new_device(
                scan, fp, conn_dests, ports_set, now, now_iso
            )

    async def _handle_new_device(
        self,
        scan: ScanResult,
        fp: CompositeFingerprint,
        conn_dests: frozenset[str],
        ports_set: frozenset[int],
        now: datetime,
        now_iso: str,
    ) -> None:
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
        )
        self._known_devices.append(tracked)

        # Publish event with full device summary for WebSocket clients
        await self._bus.publish(
            "device.new",
            await self._build_device_payload(tracked, now_iso),
            source_id=str(device_id),
        )

    async def _handle_matched_device(
        self,
        matched_id: int,
        confidence: float,
        scan: ScanResult,
        fp: CompositeFingerprint,
        conn_dests: frozenset[str],
        ports_set: frozenset[int],
        now: datetime,
        now_iso: str,
    ) -> None:
        """Handle a returning device that matched a known device."""
        # Find the tracked device
        tracked = next(
            (td for td in self._known_devices if td.device_id == matched_id), None
        )
        if tracked is None:
            return

        old_mac = tracked.mac_address
        new_mac = fp.mac_address

        # Update tracked device state
        tracked.ip_address = scan.ip_address
        if scan.hostname is not None:
            tracked.hostname = scan.hostname
        tracked.fingerprint = fp
        tracked.connection_destinations = conn_dests
        tracked.open_ports = ports_set
        tracked.last_seen = now
        if new_mac is not None:
            tracked.mac_address = new_mac

        # Update database — only overwrite hostname if scan provided one
        if scan.hostname is not None:
            await self._db.execute(
                "UPDATE devices SET ip_address = ?, mac_address = ?, hostname = ?, last_seen = ? "
                "WHERE id = ?",
                (scan.ip_address, fp.mac_address, scan.hostname, now_iso, matched_id),
            )
        else:
            await self._db.execute(
                "UPDATE devices SET ip_address = ?, mac_address = ?, last_seen = ? "
                "WHERE id = ?",
                (scan.ip_address, fp.mac_address, now_iso, matched_id),
            )

        await self._db.execute(
            "INSERT INTO device_fingerprints "
            "(device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash, "
            "connection_pattern_hash, open_ports_hash, composite_hash, "
            "signal_count, confidence, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (matched_id, fp.mac_address, fp.mdns_hostname,
             fp.dhcp_fingerprint_hash, fp.connection_pattern_hash,
             fp.open_ports_hash, fp.composite_hash, fp.signal_count,
             confidence, now_iso, now_iso),
        )
        await self._db.commit()

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
        if confidence >= AUTO_APPROVE_THRESHOLD:
            # High confidence -- silent update
            await self._bus.publish(
                "device.updated",
                device_payload,
                source_id=str(matched_id),
            )
        elif confidence >= VERIFY_THRESHOLD:
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

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        for item in port_results:
            if isinstance(item, PortResult):
                port, svc, banner = item.port, item.service_name, item.banner
            else:
                port, svc, banner = int(item), None, None

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

    async def enrich_device_ports(self, ip_address: str, port_data: list[Any]) -> None:
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

        tracked = next(
            (td for td in self._known_devices if td.ip_address == ip_address),
            None,
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
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        tracked.last_seen = now

        # Recompute fingerprint with port data
        fp = compute_fingerprint(
            mac=tracked.mac_address,
            mdns_hostname=tracked.fingerprint.mdns_hostname,
            dhcp_options=None,
            connections=None,
            open_ports=port_numbers,
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
        tracked = next(
            (td for td in self._known_devices if td.ip_address == ip_address),
            None,
        )
        if tracked is None:
            return

        # Determine what changed
        changed = False
        now = datetime.now(timezone.utc)
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
        fp = compute_fingerprint(
            mac=tracked.mac_address,
            mdns_hostname=mdns_hostname or tracked.fingerprint.mdns_hostname,
            dhcp_options=None,
            connections=None,
            open_ports=list(tracked.open_ports) if tracked.open_ports else None,
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
            now = datetime.now(timezone.utc)
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
            fp = compute_fingerprint(
                mac=tracked.mac_address,
                mdns_hostname=tracked.fingerprint.mdns_hostname,
                dhcp_options=None,
                connections=None,
                open_ports=list(tracked.open_ports) if tracked.open_ports else None,
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

            # Publish device.updated with full summary
            await self._bus.publish(
                "device.updated",
                await self._build_device_payload(tracked, now_iso),
                source_id=str(tracked.device_id),
            )
