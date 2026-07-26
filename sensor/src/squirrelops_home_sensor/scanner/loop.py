"""Periodic scan loop that drives the device discovery pipeline.

Three-phase scan architecture:
  Phase 1: ARP scan discovers hosts -> devices created immediately
  Phase 2: Async TCP port scan -> enriches devices with open port data
  Phase 3: HA enrichment (if configured) or mDNS/SSDP discovery -> enriches with
           hostnames, model names, vendors, areas

Phase 2/3 failures never block device creation from Phase 1.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from squirrelops_home_sensor.devices.manager import DeviceManager, ScanResult
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.types import EventType
from squirrelops_home_sensor.fingerprint.signals import normalize_mac
from squirrelops_home_sensor.privileged.helper import PrivilegedOperations
from squirrelops_home_sensor.scanner.mdns_browser import MDNSBrowser
from squirrelops_home_sensor.scanner.port_scanner import PortScanner
from squirrelops_home_sensor.scanner.ssdp_scanner import SSDPScanner

logger = logging.getLogger(__name__)

# Default ports to scan for service detection
DEFAULT_SCAN_PORTS = [
    22, 53, 80, 443, 445, 548, 554, 631, 993, 995,
    3000, 3001, 3389, 5000, 5173, 5353, 5900,
    8000, 8080, 8123, 8443, 8888, 9090, 49152,
]


@dataclass(frozen=True)
class ARPIdentityConflict:
    """One ambiguous IP/MAC ownership claim from a single ARP snapshot."""

    kind: str
    ip_addresses: tuple[str, ...]
    mac_addresses: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ip_addresses": list(self.ip_addresses),
            "mac_addresses": list(self.mac_addresses),
        }


def _local_interface_macs() -> set[str]:
    """Return normalized MAC addresses assigned to this sensor host."""
    try:
        import psutil

        local_macs: set[str] = set()
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family == psutil.AF_LINK and address.address:
                    try:
                        local_macs.add(normalize_mac(address.address))
                    except ValueError:
                        continue
        return local_macs
    except Exception:
        logger.warning("Unable to enumerate local interface MAC addresses", exc_info=True)
        return set()


def _inventory_arp_results(
    arp_results: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], list[ARPIdentityConflict]]:
    """Normalize a raw ARP snapshot into unambiguous physical devices.

    Proxy-ARP creates duplicate rows that carry this sensor's own MAC. Those
    rows are useful to the virtual-IP conflict handler, but must never enter
    device inventory. Any IP claimed by several MACs or MAC observed at several
    IPs is quarantined from inventory and port scanning. Selecting one claim
    would let a forged lower address redirect an existing device row and erase
    its last verified ports.
    """
    local_macs: set[str] = set()
    for mac in _local_interface_macs():
        try:
            local_macs.add(normalize_mac(mac))
        except ValueError:
            continue

    macs_by_ip: dict[str, set[str]] = {}
    for ip, mac in arp_results:
        try:
            parsed_ip = str(ipaddress.IPv4Address(ip))
            normalized_mac = normalize_mac(mac)
        except ValueError:
            logger.warning("Ignoring invalid ARP result: ip=%r mac=%r", ip, mac)
            continue
        if normalized_mac in local_macs:
            continue
        macs_by_ip.setdefault(parsed_ip, set()).add(normalized_mac)

    conflicts: list[ARPIdentityConflict] = []
    unambiguous: list[tuple[str, str]] = []
    for ip, macs in macs_by_ip.items():
        if len(macs) != 1:
            conflict = ARPIdentityConflict(
                kind="ip_claimed_by_multiple_macs",
                ip_addresses=(ip,),
                mac_addresses=tuple(sorted(macs)),
            )
            conflicts.append(conflict)
            logger.warning(
                "Quarantining ambiguous ARP claim: ip=%s macs=%s",
                ip,
                ",".join(conflict.mac_addresses),
            )
            continue
        unambiguous.append((ip, next(iter(macs))))

    ips_by_mac: dict[str, set[str]] = {}
    for ip, mac in unambiguous:
        ips_by_mac.setdefault(mac, set()).add(ip)

    inventory: list[tuple[str, str]] = []
    for mac, ips in ips_by_mac.items():
        if len(ips) != 1:
            ordered_ips = tuple(
                sorted(ips, key=ipaddress.IPv4Address)
            )
            conflict = ARPIdentityConflict(
                kind="mac_observed_at_multiple_ips",
                ip_addresses=ordered_ips,
                mac_addresses=(mac,),
            )
            conflicts.append(conflict)
            logger.warning(
                "Quarantining ambiguous ARP identity: mac=%s ips=%s",
                mac,
                ",".join(ordered_ips),
            )
            continue
        inventory.append((next(iter(ips)), mac))

    return (
        sorted(inventory, key=lambda item: ipaddress.IPv4Address(item[0])),
        sorted(
            conflicts,
            key=lambda conflict: (
                conflict.kind,
                conflict.ip_addresses,
                conflict.mac_addresses,
            ),
        ),
    )


def _resolve_subnet(subnet: str) -> str:
    """Resolve 'auto' subnet to the local network CIDR, or validate the given CIDR."""
    if subnet.lower() != "auto":
        return subnet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        resolved = str(network)
        logger.info("Auto-detected subnet: %s (from local IP %s)", resolved, local_ip)
        return resolved
    except Exception:
        logger.warning("Subnet auto-detection failed, falling back to 192.168.1.0/24")
        return "192.168.1.0/24"


class ScanLoop:
    """Periodic network scan loop with three-phase architecture.

    Parameters
    ----------
    device_manager:
        Device manager for processing scan results.
    event_bus:
        Event bus for publishing scan events.
    privileged_ops:
        Privileged operations for ARP scanning (requires root).
    subnet:
        Network subnet to scan in CIDR notation (or "auto").
    scan_interval:
        Seconds between scan cycles.
    scan_ports:
        Ports to check during port scanning. Defaults to common ports.
    port_scanner:
        Optional PortScanner instance. Created with defaults if not provided.
    mdns_browser:
        Optional MDNSBrowser instance. Created with defaults if not provided.
    ssdp_scanner:
        Optional SSDPScanner instance. Created with defaults if not provided.
    ha_client:
        Optional HomeAssistantClient for HA device/area enrichment.
    ha_config:
        Optional dict with HA integration config (enabled, url, token).
    config:
        Optional reference to the top-level config dict so we can pick
        up HA config changes at runtime (e.g. from PUT /config).
    orchestrator:
        Optional DecoyOrchestrator for auto-deploying decoys based on
        discovered services after Phase 2.
    security_analyzer:
        Optional SecurityInsightAnalyzer for generating security alerts
        from port scan data after Phase 2.
    """

    def __init__(
        self,
        device_manager: DeviceManager,
        event_bus: EventBus,
        privileged_ops: PrivilegedOperations,
        subnet: str,
        scan_interval: int = 300,
        scan_ports: list[int] | None = None,
        port_scanner: PortScanner | None = None,
        mdns_browser: MDNSBrowser | None = None,
        ssdp_scanner: SSDPScanner | None = None,
        ha_client: Any | None = None,
        ha_config: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        orchestrator: Any | None = None,
        security_analyzer: Any | None = None,
    ) -> None:
        if scan_interval <= 0:
            raise ValueError("Scan interval must be greater than zero")
        self._manager = device_manager
        self._bus = event_bus
        self._ops = privileged_ops
        self._subnet = _resolve_subnet(subnet)
        self._scan_interval = scan_interval
        self._scan_ports = scan_ports or DEFAULT_SCAN_PORTS
        self._port_scanner = port_scanner or PortScanner()
        self._mdns_browser = mdns_browser or MDNSBrowser()
        self._ssdp_scanner = ssdp_scanner or SSDPScanner()
        self._ha_client = ha_client
        self._ha_config = ha_config or {}
        self._config = config
        self._orchestrator = orchestrator
        self._security_analyzer = security_analyzer
        self._reschedule = asyncio.Event()
        self._ip_conflict_handler: (
            Callable[[list[tuple[str, str]]], Awaitable[Any]] | None
        ) = None

    @property
    def scan_interval(self) -> int:
        """Return the configured scan interval in seconds."""
        return self._scan_interval

    def set_scan_interval(self, scan_interval: int) -> None:
        """Apply a new scan interval and interrupt the old sleep immediately."""
        if scan_interval <= 0:
            raise ValueError("Scan interval must be greater than zero")
        if scan_interval == self._scan_interval:
            return
        self._scan_interval = scan_interval
        self._reschedule.set()

    def set_ip_conflict_handler(
        self,
        handler: Callable[[list[tuple[str, str]]], Awaitable[Any]] | None,
    ) -> None:
        """Reconcile virtual-IP ownership from each scan's raw ARP results."""
        self._ip_conflict_handler = handler

    def _get_ha_client(self) -> Any | None:
        """Return an HA client, creating one lazily from live config if needed.

        This allows the scan loop to pick up HA settings that were changed
        at runtime via PUT /config (the app's Settings UI).
        """
        # Check the live top-level config for HA changes
        if self._config is not None:
            live_ha = self._config.get("home_assistant", {})
            if (
                live_ha.get("enabled")
                and live_ha.get("url")
                and live_ha.get("token")
            ):
                # If we don't have a client yet, or the URL/token changed, create one
                if (
                    self._ha_client is None
                    or self._ha_config.get("url") != live_ha.get("url")
                    or self._ha_config.get("token") != live_ha.get("token")
                ):
                    from squirrelops_home_sensor.integrations.home_assistant import (
                        HomeAssistantClient,
                    )
                    self._ha_client = HomeAssistantClient(
                        url=live_ha["url"], token=live_ha["token"]
                    )
                    self._ha_config = dict(live_ha)
                    logger.info("HA client created/updated from live config: %s", live_ha["url"])
                return self._ha_client
            else:
                # HA was disabled at runtime
                if self._ha_client is not None and not live_ha.get("enabled"):
                    self._ha_client = None
                    self._ha_config = {}
                return None

        # Fall back to constructor-provided client (only if enabled in static config)
        if (
            self._ha_client is not None
            and self._ha_config.get("enabled", False) is True
            and bool(self._ha_config.get("url", ""))
            and bool(self._ha_config.get("token", ""))
        ):
            return self._ha_client
        return None

    @property
    def _ha_enabled(self) -> bool:
        """Return True if HA enrichment is fully configured and available."""
        return self._get_ha_client() is not None

    async def run(self, shutdown_event: asyncio.Event) -> None:
        """Run the scan loop until the shutdown event is set."""
        # Load previously-discovered devices so the matcher can
        # recognise returning devices across sensor restarts.
        await self._manager.load_known_devices()

        logger.info(
            "Scan loop started: subnet=%s, interval=%ds, known_devices=%d",
            self._subnet,
            self._scan_interval,
            len(self._manager.get_known_devices()),
        )

        while not shutdown_event.is_set():
            try:
                await self.run_single_scan()
            except Exception:
                logger.exception("Scan cycle failed")

            shutdown_wait = asyncio.create_task(shutdown_event.wait())
            reschedule_wait = asyncio.create_task(self._reschedule.wait())
            _, pending = await asyncio.wait(
                {shutdown_wait, reschedule_wait},
                timeout=self._scan_interval,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if self._reschedule.is_set():
                self._reschedule.clear()

        logger.info("Scan loop stopped")

    async def run_single_scan(self) -> None:
        """Run a single three-phase scan cycle."""
        scan_start = datetime.now(UTC)
        logger.info("Starting scan cycle")

        # ---- Phase 1: ARP discovery + immediate device creation ----
        arp_results: list[tuple[str, str]] = []
        try:
            arp_results = await self._ops.arp_scan(self._subnet)
            logger.info("ARP scan found %d hosts", len(arp_results))
        except Exception:
            logger.exception("ARP scan failed")

        if not arp_results:
            await self._bus.publish(
                EventType.SYSTEM_SCAN_COMPLETE,
                {
                    "device_count": len(self._manager.get_known_devices()),
                    "scan_duration_ms": _elapsed_ms(scan_start),
                    "hosts_discovered": 0,
                    "arp_identity_conflicts": 0,
                },
            )
            return

        # Reconcile virtual aliases before DeviceManager applies its deliberate
        # decoy-IP filter. Otherwise a real host that claims a mimic address is
        # hidden from both inventory and conflict recovery.
        if self._ip_conflict_handler is not None:
            try:
                await self._ip_conflict_handler(arp_results)
            except Exception:
                logger.exception("Virtual IP conflict reconciliation failed")

        # Normalize after conflict handling so the ownership logic still sees
        # every raw claimant, including this host's proxy-ARP responses.
        inventory_results, arp_identity_conflicts = _inventory_arp_results(
            arp_results
        )
        if self._security_analyzer is not None:
            try:
                await self._security_analyzer.record_arp_conflicts(
                    [
                        conflict.as_dict()
                        for conflict in arp_identity_conflicts
                    ]
                )
            except Exception:
                logger.exception("Failed to record ARP identity conflicts")

        # Never feed active system decoys into discovery or the TCP scanner.
        real_arp_results: list[tuple[str, str]] = []
        for ip, mac in inventory_results:
            if await self._manager.is_system_decoy_ip(ip):
                logger.debug("Excluding system decoy IP from scan targets: %s", ip)
                continue
            real_arp_results.append((ip, mac))

        if not real_arp_results:
            await self._bus.publish(
                EventType.SYSTEM_SCAN_COMPLETE,
                {
                    "device_count": len(self._manager.get_known_devices()),
                    "scan_duration_ms": _elapsed_ms(scan_start),
                    "hosts_discovered": 0,
                    "arp_identity_conflicts": len(arp_identity_conflicts),
                },
            )
            return

        observed_device_ids: set[int] = set()
        observed_device_by_ip: dict[str, int] = {}
        # An ambiguous ARP snapshot is not authoritative for online/offline
        # reconciliation. Preserve the last trusted device addresses and ports.
        processing_succeeded = not arp_identity_conflicts
        for ip, mac in real_arp_results:
            scan_result = ScanResult(ip_address=ip, mac_address=mac)
            try:
                device_id = await self._manager.process_scan_result(scan_result)
                if device_id is not None:
                    observed_device_ids.add(device_id)
                    observed_device_by_ip[ip] = device_id
            except Exception:
                processing_succeeded = False
                logger.exception("Failed to process ARP result for %s", ip)

        if processing_succeeded and observed_device_ids:
            try:
                await self._manager.reconcile_online_state(observed_device_ids)
            except Exception:
                logger.exception("Failed to reconcile device online state")

        device_count_after_arp = len(self._manager.get_known_devices())
        logger.info(
            "Phase 1 complete: %d devices from ARP in %dms",
            device_count_after_arp,
            _elapsed_ms(scan_start),
        )

        # ---- Phase 2: Async TCP port scan with banner grabbing + enrichment ----
        target_ips = [
            ip for ip, _ in real_arp_results
            if ip in observed_device_by_ip
        ]
        port_results: dict[str, list] = {}
        port_scan_succeeded = False
        if target_ips:
            try:
                port_results = await self._port_scanner.scan_with_banners(
                    targets=target_ips,
                    ports=self._scan_ports,
                )
                port_scan_succeeded = True
                enriched_count = 0
                inconclusive_by_ip = getattr(
                    port_results,
                    "inconclusive_ports",
                    {},
                )
                for ip in target_ips:
                    results = port_results.get(ip, [])
                    await self._manager.enrich_device_ports(
                        ip,
                        results,
                        device_id=observed_device_by_ip[ip],
                        inconclusive_ports=inconclusive_by_ip.get(
                            ip,
                            frozenset(),
                        ),
                    )
                    if results:
                        enriched_count += 1
                logger.info(
                    "Phase 2 complete: enriched %d devices with port data",
                    enriched_count,
                )
            except Exception:
                logger.exception("Port scan failed, devices exist without port data")
                port_results = {}
                port_scan_succeeded = False

        # ---- Decoy auto-deploy (after Phase 2, if no decoys exist) ----
        if self._orchestrator is not None:
            try:
                discovered = [
                    {"ip": ip, "port": r.port, "protocol": "tcp"}
                    for ip, results in port_results.items()
                    for r in results
                ] if port_scan_succeeded else []
                deployed = await self._orchestrator.auto_deploy(discovered)
                if deployed:
                    logger.info("Auto-deployed %d decoys from scan results", deployed)
            except Exception:
                logger.exception("Decoy auto-deploy failed")

        # ---- Phase 2.5: Security insight analysis ----
        if self._security_analyzer is not None and port_scan_succeeded:
            try:
                devices_for_analysis = []
                current_device_ids = set(observed_device_by_ip.values())
                for td in self._manager.get_known_devices():
                    if td.device_id in current_device_ids:
                        devices_for_analysis.append({
                            "device_id": td.device_id,
                            "ip_address": td.ip_address,
                            "mac_address": td.mac_address,
                            "device_type": td.device_type or "unknown",
                            "open_ports": td.open_ports,
                            "display_name": td.hostname or td.ip_address,
                        })
                if devices_for_analysis:
                    new_alerts = await self._security_analyzer.analyze_all_devices(
                        devices_for_analysis
                    )
                    if new_alerts:
                        logger.info(
                            "Phase 2.5 complete: %d security insight alerts",
                            new_alerts,
                        )
            except Exception:
                logger.exception("Security insight analysis failed")

        # ---- Phase 3: HA enrichment (if configured) or mDNS/SSDP fallback ----
        ha_client = self._get_ha_client()
        if ha_client is not None:
            try:
                ha_devices, ha_areas = await asyncio.gather(
                    ha_client.get_devices(),
                    ha_client.get_areas(),
                )
                await self._manager.enrich_device_ha(ha_devices, ha_areas)
                logger.info(
                    "Phase 3 complete: enriched from HA (%d devices, %d areas)",
                    len(ha_devices),
                    len(ha_areas),
                )
            except Exception:
                logger.warning(
                    "HA enrichment failed, falling back to mDNS/SSDP",
                    exc_info=True,
                )
                await self._run_mdns_ssdp_enrichment(observed_device_by_ip)
        else:
            await self._run_mdns_ssdp_enrichment(observed_device_by_ip)

        try:
            classified = await self._manager.finalize_pending_classifications(
                observed_device_ids
            )
            if classified:
                logger.info(
                    "Optional AI classification enriched %d new devices",
                    classified,
                )
        except Exception:
            logger.exception("Optional AI device classification failed")

        # ---- Publish scan complete ----
        device_count = len(self._manager.get_known_devices())
        await self._bus.publish(
            EventType.SYSTEM_SCAN_COMPLETE,
            {
                "device_count": device_count,
                "scan_duration_ms": _elapsed_ms(scan_start),
                "hosts_discovered": len(real_arp_results),
                "arp_identity_conflicts": len(arp_identity_conflicts),
            },
        )

        logger.info(
            "Scan cycle complete: %d devices tracked in %dms",
            device_count,
            _elapsed_ms(scan_start),
        )

    async def _run_mdns_ssdp_enrichment(
        self,
        observed_device_by_ip: dict[str, int],
    ) -> None:
        """Run mDNS/SSDP discovery enrichment (Phase 3 fallback)."""
        try:
            mdns_results, ssdp_results = await asyncio.gather(
                self._mdns_browser.browse(),
                self._ssdp_scanner.scan(),
                return_exceptions=True,
            )

            # Handle individual failures gracefully
            if isinstance(mdns_results, BaseException):
                logger.warning("mDNS browse failed: %s", mdns_results)
                mdns_results = []
            if isinstance(ssdp_results, BaseException):
                logger.warning("SSDP scan failed: %s", ssdp_results)
                ssdp_results = []

            # Index results by IP for efficient lookup
            mdns_by_ip = {r.ip: r for r in mdns_results}
            ssdp_by_ip = {r.ip: r for r in ssdp_results}
            all_ips = set(mdns_by_ip.keys()) | set(ssdp_by_ip.keys())

            enriched_count = 0
            for ip in all_ips:
                device_id = observed_device_by_ip.get(ip)
                if device_id is None:
                    continue
                mdns = mdns_by_ip.get(ip)
                ssdp = ssdp_by_ip.get(ip)
                await self._manager.enrich_device_discovery(
                    ip_address=ip,
                    mdns_hostname=mdns.hostname if mdns else None,
                    mdns_service_types=mdns.service_types if mdns else frozenset(),
                    upnp_friendly_name=ssdp.friendly_name if ssdp else None,
                    upnp_manufacturer=ssdp.manufacturer if ssdp else None,
                    upnp_model_name=ssdp.model_name if ssdp else None,
                    upnp_server_header=ssdp.server_header if ssdp else None,
                    device_id=device_id,
                )
                enriched_count += 1
            logger.info(
                "Phase 3 complete: enriched %d devices with discovery data",
                enriched_count,
            )
        except Exception:
            logger.exception(
                "Discovery enrichment failed, devices exist without discovery data"
            )


def _elapsed_ms(start: datetime) -> int:
    """Return elapsed milliseconds since start."""
    delta = datetime.now(UTC) - start
    return int(delta.total_seconds() * 1000)
