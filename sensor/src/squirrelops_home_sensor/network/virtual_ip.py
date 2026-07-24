"""Virtual IP manager and IP allocator for mimic decoy deployment.

The IPAllocator finds unused IPs in the subnet (preferring .200-.250).
The VirtualIPManager wraps the privileged ops to add/remove ifconfig aliases,
persists state in the ``virtual_ips`` table, and provides a live set of
active virtual IPs for self-scan exclusion.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from datetime import UTC, datetime

import aiosqlite

from squirrelops_home_sensor.fingerprint.signals import normalize_mac
from squirrelops_home_sensor.privileged.helper import PrivilegedOperations

logger = logging.getLogger("squirrelops_home_sensor.network")

_UNKNOWN_MAC_OWNER = "unknown-mac"


class IPAllocator:
    """Finds unused IPs in the subnet for virtual decoy deployment.

    Allocation strategy: pick from the top of the subnet (.200-.250) since
    home DHCP typically assigns from the low end. Excludes: .0, .1 (gateway),
    .255 (broadcast), the sensor's own IP, all IPs seen in recent ARP scans,
    and all IPs already allocated as virtual.

    Parameters
    ----------
    subnet:
        CIDR notation (e.g. "192.168.1.0/24").
    gateway_ip:
        The subnet's gateway (typically .1), excluded from allocation.
    sensor_ip:
        The sensor's own IP, excluded from allocation.
    range_start:
        Start of the preferred allocation range (host octet, e.g. 200).
    range_end:
        End of the preferred allocation range (host octet, e.g. 250).
    """

    def __init__(
        self,
        subnet: str,
        gateway_ip: str,
        sensor_ip: str,
        range_start: int = 200,
        range_end: int = 250,
    ) -> None:
        self._network = ipaddress.IPv4Network(subnet, strict=False)
        self._gateway_ip = ipaddress.IPv4Address(gateway_ip)
        self._sensor_ip = ipaddress.IPv4Address(sensor_ip)
        self._range_start = range_start
        self._range_end = range_end
        self._active_ips: set[ipaddress.IPv4Address] = set()
        self._allocated: set[ipaddress.IPv4Address] = set()

    def set_active_ips(self, arp_results: list[tuple[str, str]]) -> None:
        """Update known-active IPs from latest ARP scan."""
        self._active_ips = {ipaddress.IPv4Address(ip) for ip, _ in arp_results}

    def mark_allocated(self, ip: str) -> None:
        """Mark an IP as allocated (e.g. loaded from DB at startup)."""
        self._allocated.add(ipaddress.IPv4Address(ip))

    def allocate(self, count: int) -> list[str]:
        """Allocate up to ``count`` unused IPs. Returns IP strings."""
        excluded = (
            self._active_ips
            | self._allocated
            | {self._gateway_ip, self._sensor_ip, self._network.network_address, self._network.broadcast_address}
        )

        # Build candidate pool from preferred range
        candidates: list[ipaddress.IPv4Address] = []
        base = int(self._network.network_address)
        for host_part in range(self._range_start, self._range_end + 1):
            candidate = ipaddress.IPv4Address(base + host_part)
            if candidate in self._network and candidate not in excluded:
                candidates.append(candidate)

        allocated: list[str] = []
        for candidate in candidates:
            if len(allocated) >= count:
                break
            self._allocated.add(candidate)
            allocated.append(str(candidate))

        return allocated

    def release(self, ip: str) -> None:
        """Return IP to available pool."""
        self._allocated.discard(ipaddress.IPv4Address(ip))

    @property
    def subnet(self) -> str:
        """Canonical CIDR scanned before allocating or checking conflicts."""
        return self._network.with_prefixlen


class VirtualIPManager:
    """Manages ifconfig aliases for decoy virtual IPs.

    Coordinates with the privileged ops layer to add/remove IP aliases
    on the host interface, and persists state to the ``virtual_ips`` table.

    Parameters
    ----------
    privileged_ops:
        Platform-specific privileged operations.
    allocator:
        IP allocator for finding unused IPs.
    db:
        Database connection for persistence.
    interface:
        Network interface for aliases (default "en0").
    """

    def __init__(
        self,
        privileged_ops: PrivilegedOperations,
        allocator: IPAllocator,
        db: aiosqlite.Connection,
        interface: str = "en0",
    ) -> None:
        self._ops = privileged_ops
        self._allocator = allocator
        self._db = db
        self._interface = interface
        self._active: set[str] = set()
        # ``_active`` is deliberately conservative and includes aliases whose
        # state is uncertain. Only this set means the helper positively
        # verified both the loopback alias and scoped proxy-ARP publication.
        self._verified_published: set[str] = set()
        self._owner_scan_lock = asyncio.Lock()
        self._owner_scan_cache: dict[str, str] | None = None
        self._owner_scan_cache_at = 0.0
        # A full /24 ownership probe is deliberately shared across a burst of
        # sequential mimic deployments. Conflict reconciliation bypasses this
        # cache, and callers can pass the just-completed scan directly.
        self._owner_scan_cache_ttl = 5.0

    @property
    def active_ips(self) -> set[str]:
        """Currently active virtual IPs (for scan loop exclusion)."""
        return set(self._active)

    @property
    def verified_ips(self) -> set[str]:
        """Virtual IPs whose complete OS publication is currently verified."""
        return set(self._verified_published)

    async def _load_online_device_owners(self) -> list[tuple[str, str]]:
        """Load currently-online physical owners from the device inventory.

        This primitive deliberately propagates read and row-validation failures.
        Security-critical callers need to distinguish a proven empty inventory
        from an inventory that could not be read.
        """
        cursor = await self._db.execute(
            """SELECT d.ip_address, d.mac_address
               FROM devices d
               WHERE d.is_online = 1
                 AND NOT EXISTS (
                     SELECT 1
                     FROM virtual_ips vip
                     WHERE vip.ip_address = d.ip_address
                       AND vip.released_at IS NULL
                 )"""
        )
        rows = await cursor.fetchall()
        owners = [(row["ip_address"], row["mac_address"] or "") for row in rows]
        # Validate addresses here so corrupt inventory rows also fail closed for
        # allocation/restoration instead of being silently treated as absent.
        for ip, _mac in owners:
            ipaddress.IPv4Address(ip)
        return owners

    async def _load_persisted_mimic_addresses(self) -> list[tuple[str, str]]:
        """Reserve every durable mimic binding from new allocation."""
        cursor = await self._db.execute(
            """SELECT DISTINCT bind_address
               FROM decoys
               WHERE decoy_type = 'mimic'
                 AND retired_at IS NULL
                 AND status IN ('active', 'stopped', 'degraded')"""
        )
        rows = await cursor.fetchall()
        reserved = [(row["bind_address"], "") for row in rows]
        for ip, _mac in reserved:
            ipaddress.IPv4Address(ip)
        return reserved

    async def refresh_active_ips(self) -> list[tuple[str, str]]:
        """Best-effort refresh of exclusions from currently-online devices.

        Without this, the allocator only excludes the gateway, sensor, and
        already-allocated virtual IPs, so it could hand a mimic a virtual IP
        already owned by a real statically-addressed host (NAS, NVR), causing an
        ARP/IP conflict. This public refresh remains best-effort for diagnostics
        and compatibility; allocation and restoration use the strict loader.
        """
        try:
            arp_like = await self._load_online_device_owners()
            self._allocator.set_active_ips(arp_like)
            return arp_like
        except Exception:
            logger.warning("Failed to refresh active IPs from devices", exc_info=True)
            self._allocator.set_active_ips([])
            return []

    @staticmethod
    def _local_interface_macs() -> set[str]:
        """Return normalized MAC addresses owned by this host.

        Proxy-ARP-backed virtual IPs legitimately appear in the ARP table with
        the physical interface's MAC.  Those entries are ours, not conflicts.
        """
        try:
            import psutil

            macs: set[str] = set()
            for addresses in psutil.net_if_addrs().values():
                for address in addresses:
                    if address.family == psutil.AF_LINK and address.address:
                        try:
                            macs.add(normalize_mac(address.address).lower())
                        except ValueError:
                            logger.warning(
                                "Ignoring invalid local interface MAC %r",
                                address.address,
                            )
            return macs
        except Exception:
            logger.warning("Failed to enumerate local interface MACs", exc_info=True)
            return set()

    def _real_ip_owners(
        self, results: list[tuple[str, str]]
    ) -> dict[str, str]:
        """Normalize ARP owners and remove this host's proxy-ARP records."""
        if not results:
            # Allocation must fail closed if the privileged probe silently
            # returns nothing; stale database rows are not proof an IP is free.
            raise RuntimeError(
                f"ARP ownership scan returned no results for {self._allocator.subnet}"
            )

        local_macs: set[str] = set()
        for mac in self._local_interface_macs():
            try:
                local_macs.add(normalize_mac(mac).lower())
            except ValueError:
                logger.warning("Ignoring invalid local interface MAC %r", mac)
        if not local_macs:
            raise RuntimeError(
                "Local interface MAC inventory is unavailable; "
                "ARP ownership cannot be classified safely"
            )
        owners: dict[str, str] = {}
        for ip, mac in results:
            if not mac:
                continue
            try:
                normalized_mac = normalize_mac(mac).lower()
            except ValueError:
                # Preserve the IP as occupied for allocation/restoration
                # without turning malformed telemetry into a destructive
                # routine conflict.
                logger.warning(
                    "Recording unknown MAC in ARP ownership result: "
                    "ip=%r mac=%r",
                    ip,
                    mac,
                )
                owners.setdefault(ip, _UNKNOWN_MAC_OWNER)
                continue
            # A local-MAC row is safe to discard only for an address this
            # manager already tracks as a live/possibly-live VIP. Other local
            # addresses can be legitimate secondary or alternate-interface
            # host addresses and must remain excluded from mimic allocation.
            if normalized_mac in local_macs and ip in self._active:
                continue
            owners[ip] = normalized_mac
        if not owners:
            raise RuntimeError(
                "ARP ownership scan contained no external owners after "
                "filtering this host's proxy aliases"
            )
        return owners

    async def _scan_real_ip_owners(
        self, *, force_refresh: bool = False
    ) -> dict[str, str]:
        """Return probed ARP owners, excluding this host's own MAC addresses."""
        async with self._owner_scan_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._owner_scan_cache is not None
                and now - self._owner_scan_cache_at <= self._owner_scan_cache_ttl
            ):
                return dict(self._owner_scan_cache)

            results = await self._ops.arp_scan(self._allocator.subnet)
            owners = self._real_ip_owners(results)
            self._owner_scan_cache = dict(owners)
            self._owner_scan_cache_at = time.monotonic()
            return owners

    async def snapshot_real_ip_owners(self) -> list[tuple[str, str]]:
        """Capture one fresh ownership snapshot for a deployment batch."""
        owners = await self._scan_real_ip_owners(force_refresh=True)
        return list(owners.items())

    async def allocate_verified(
        self,
        count: int,
        arp_results: list[tuple[str, str]] | None = None,
    ) -> list[str]:
        """Allocate only after a fresh privileged ARP ownership probe.

        The devices table deliberately filters virtual IPs, so it cannot detect
        a real device that later claims a decoy address.  A direct ARP scan is
        the authoritative pre-allocation check and closes that blind spot.
        ``arp_results`` may be supplied when the caller has just completed that
        scan, avoiding another full-subnet probe during reconciliation.
        """
        if count <= 0:
            return []

        try:
            db_owners = await self._load_online_device_owners()
            persisted_mimics = await self._load_persisted_mimic_addresses()
        except Exception:
            logger.exception(
                "Cannot safely allocate virtual IPs: durable address inventory "
                "read failed"
            )
            return []
        try:
            use_withdrawal_cache = (
                getattr(
                    self._ops,
                    "requires_active_alias_withdrawal_probe",
                    False,
                )
                is True
                and self._owner_scan_cache is not None
                and time.monotonic() - self._owner_scan_cache_at
                <= self._owner_scan_cache_ttl
            )
            if arp_results is None or use_withdrawal_cache:
                owners = await self._scan_real_ip_owners()
            else:
                owners = self._real_ip_owners(arp_results)
                self._owner_scan_cache = dict(owners)
                self._owner_scan_cache_at = time.monotonic()
        except Exception:
            logger.exception(
                "Cannot safely allocate virtual IPs: live ownership probe failed"
            )
            return []

        # Database discovery and the direct ownership probe cover different
        # failure modes. Never let one exclusion set replace the other.
        self._allocator.set_active_ips(
            [*db_owners, *persisted_mimics, *owners.items()]
        )
        return self._allocator.allocate(count)

    async def _find_conflicts_with_aliases_withdrawn(
        self,
        target_ips: set[str] | None = None,
    ) -> dict[str, str]:
        """Probe active proxy-ARP VIPs without letting our own MAC hide owners.

        The mimic PF quarantine remains installed throughout. Each alias and
        proxy-ARP entry is withdrawn, one real LAN sweep runs, and only
        addresses with no external owner are republished. Probe, withdrawal,
        or restore failures are treated as conflicts so the orchestrator
        evacuates the affected decoy while retaining PF isolation.
        """
        async with self._owner_scan_lock:
            if target_ips is None:
                active = sorted(self._active)
                conflicts: dict[str, str] = {}
            else:
                requested = set(target_ips)
                active = sorted(self._active.intersection(requested))
                conflicts = {
                    ip: "ownership-probe-alias-not-active"
                    for ip in sorted(requested.difference(self._active))
                }
            withdrawn: list[str] = []

            for ip in active:
                # Once mutation begins, the address is no longer verified
                # published until a successful helper restore proves both
                # halves are present again.
                self._verified_published.discard(ip)
                try:
                    removed = await self._ops.remove_ip_alias(
                        ip,
                        interface=self._interface,
                    )
                except Exception:
                    removed = False
                    logger.exception(
                        "Active virtual IP %s could not be withdrawn for "
                        "ownership probing",
                        ip,
                    )
                if removed:
                    withdrawn.append(ip)
                else:
                    conflicts[ip] = "ownership-probe-withdrawal-failed"

            if not withdrawn:
                return conflicts

            try:
                results = await self._ops.arp_scan(self._allocator.subnet)
                owners = self._real_ip_owners(results)
                self._owner_scan_cache = dict(owners)
                self._owner_scan_cache_at = time.monotonic()
            except Exception:
                # Fail closed. Leaving these aliases withdrawn lets conflict
                # cleanup converge DB/listener/PF state without briefly
                # republishing an address whose ownership is unknown.
                self._owner_scan_cache = None
                self._owner_scan_cache_at = 0.0
                logger.exception(
                    "Active virtual IP ownership probe failed; evacuating %d "
                    "withdrawn mimic address(es)",
                    len(withdrawn),
                )
                conflicts.update(
                    (ip, "ownership-probe-failed") for ip in withdrawn
                )
                return conflicts

            for ip in withdrawn:
                owner = owners.get(ip)
                if owner is not None:
                    conflicts[ip] = owner
                    continue

                try:
                    restored = await self._ops.add_ip_alias(
                        ip,
                        interface=self._interface,
                    )
                except Exception:
                    restored = False
                    logger.exception(
                        "Virtual IP %s could not be restored after ownership "
                        "probing",
                        ip,
                    )
                if not restored:
                    conflicts[ip] = "ownership-probe-restore-failed"
                else:
                    self._verified_published.add(ip)

            return conflicts

    async def verify_batch_ownership(
        self,
        ips: set[str],
    ) -> dict[str, str]:
        """Verify newly-published aliases with one post-deployment LAN sweep."""
        if not ips:
            return {}
        return await self._find_conflicts_with_aliases_withdrawn(set(ips))

    async def find_conflicts(
        self,
        arp_results: list[tuple[str, str]] | None = None,
    ) -> dict[str, str]:
        """Return active virtual IPs visibly claimed by another MAC.

        A caller performing the normal discovery sweep can pass its raw results
        so conflict handling does not launch a second ARP sweep. This routine
        check never withdraws active aliases: on macOS, doing that for every
        periodic scan makes every decoy unreachable for the duration of the
        subnet sweep. Proxy ARP can mask a competing response in this
        non-disruptive snapshot, so authoritative withdrawal probes remain
        limited to the pre-publish and post-deployment ownership gates.
        """
        if not self._active:
            return {}
        try:
            if arp_results is None:
                owners = await self._scan_real_ip_owners(force_refresh=True)
            else:
                owners = self._real_ip_owners(arp_results)
                self._owner_scan_cache = dict(owners)
                self._owner_scan_cache_at = time.monotonic()
        except Exception:
            # Routine reconciliation is non-authoritative telemetry. Treating
            # an unavailable snapshot as proof of conflict would make a helper
            # or scan failure evacuate every healthy decoy. Deployment and
            # restoration use separate fail-closed ownership gates.
            logger.warning(
                "Routine virtual IP ownership check failed; preserving active "
                "aliases until the next scan",
                exc_info=True,
            )
            return {}
        return {
            ip: owners[ip]
            for ip in sorted(self._active)
            if ip in owners and owners[ip] != _UNKNOWN_MAC_OWNER
        }

    async def is_verified_free(
        self,
        ip: str,
        arp_results: list[tuple[str, str]] | None = None,
    ) -> bool:
        """Fail closed unless both discovery sources show ``ip`` is unowned.

        This is used before restoring or resuming a persisted mimic. A decoy IP
        can be claimed by a real device while the sensor is stopped, so an old
        database reservation is not authority to reclaim it.
        """
        try:
            db_owners = await self._load_online_device_owners()
        except Exception:
            logger.exception(
                "Cannot verify ownership for virtual IP %s: "
                "device inventory read failed",
                ip,
            )
            return False
        try:
            if arp_results is None:
                # Restore/restart is a one-address safety decision with no
                # post-publish batch sweep. Never authorize it from the short
                # allocation-burst cache.
                owners = await self._scan_real_ip_owners(force_refresh=True)
            else:
                owners = self._real_ip_owners(arp_results)
                self._owner_scan_cache = dict(owners)
                self._owner_scan_cache_at = time.monotonic()
        except Exception:
            logger.exception("Cannot verify ownership for virtual IP %s", ip)
            return False

        database_ips = {owner_ip for owner_ip, _ in db_owners}
        return ip not in database_ips and ip not in owners

    def release_reservation(self, ip: str) -> None:
        """Release an allocation that failed before an alias became active."""
        self._verified_published.discard(ip)
        self._allocator.release(ip)

    def mark_possibly_active(self, ip: str) -> None:
        """Track an address whose startup OS state could not be verified."""
        self._verified_published.discard(ip)
        self._active.add(ip)
        self._allocator.mark_allocated(ip)

    async def is_available(self) -> bool:
        """Check if the privileged backend is available for IP alias operations."""
        return await self._ops.is_available()

    async def add_alias(self, ip: str) -> bool:
        """Add a virtual IP alias and persist to database."""
        # Enter conservative tracking before dispatching the privileged
        # mutation. Cancellation can arrive after the helper changed OS state
        # but before this coroutine receives its response; only a verified
        # remove operation may prove the address is no longer live.
        self.mark_possibly_active(ip)
        ok = await self._ops.add_ip_alias(ip, interface=self._interface)
        if not ok:
            # A helper failure is not proof that the OS transaction was rolled
            # back. The alias or proxy-ARP entry may have been created before a
            # cleanup command failed. Track it as possibly live so callers keep
            # PF isolation, shutdown retries removal, and the allocator cannot
            # hand the address to another mimic.
            logger.warning(
                "Failed to verify IP alias %s on %s; retaining conservative "
                "possibly-live state",
                ip,
                self._interface,
            )
            return False
        self._verified_published.add(ip)

        try:
            now = datetime.now(UTC).isoformat()
            await self._db.execute(
                """INSERT INTO virtual_ips (ip_address, interface, created_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(ip_address) DO UPDATE SET
                       interface = excluded.interface,
                       released_at = NULL,
                       created_at = excluded.created_at""",
                (ip, self._interface, now),
            )
            await self._db.commit()
        except Exception:
            try:
                await self._db.rollback()
            except Exception:
                logger.exception("Failed to roll back virtual IP database transaction")
            # Do not leave an untracked address on the host if persistence
            # fails.  An untracked alias would expose wildcard-bound services
            # without a mimic lifecycle capable of isolating or removing it.
            self._verified_published.discard(ip)
            rolled_back = await self._ops.remove_ip_alias(
                ip, interface=self._interface
            )
            if rolled_back:
                self._verified_published.discard(ip)
                self._active.discard(ip)
                self._allocator.release(ip)
            else:
                # The helper may have created the OS alias before persistence
                # failed. Track the address as live so shutdown retries removal
                # and callers know they must retain packet-filter isolation.
                self._active.add(ip)
                self._allocator.mark_allocated(ip)
            logger.exception(
                "Failed to persist virtual IP %s; OS alias rollback %s",
                ip,
                "succeeded" if rolled_back else "failed",
            )
            return False

        self._active.add(ip)
        self._allocator.mark_allocated(ip)
        logger.info("Added virtual IP alias %s on %s", ip, self._interface)
        return True

    async def remove_alias(self, ip: str) -> bool:
        """Remove a virtual IP alias and mark released in database."""
        # Callers retain PF while this method runs. Remove the OS address first
        # so a durable "released" row can never coexist with a live,
        # lifecycle-orphaned alias.
        self._verified_published.discard(ip)
        ok = await self._ops.remove_ip_alias(ip, interface=self._interface)
        if not ok:
            # Treat an unsuccessful helper operation as "possibly still live"
            # even when startup loaded only a durable reservation. This keeps
            # shutdown from flushing PF around an alias whose OS state could
            # not be verified.
            self._active.add(ip)
            self._allocator.mark_allocated(ip)
            logger.warning("Failed to remove IP alias %s", ip)
            return False

        now = datetime.now(UTC).isoformat()
        try:
            await self._db.execute(
                "UPDATE virtual_ips SET released_at = ? WHERE ip_address = ?",
                (now, ip),
            )
            await self._db.commit()
        except Exception:
            try:
                await self._db.rollback()
            except Exception:
                logger.exception("Failed to roll back virtual IP database transaction")

            # The durable row still reserves/restores this address. Recreate
            # the alias while PF remains in place so OS and database state
            # converge; regardless of the helper result, track it as possibly
            # live and force callers to retain isolation.
            restored = await self._ops.add_ip_alias(
                ip, interface=self._interface
            )
            if restored:
                self._verified_published.add(ip)
            try:
                await self._db.execute(
                    "UPDATE virtual_ips SET released_at = NULL WHERE ip_address = ?",
                    (ip,),
                )
                await self._db.commit()
            except Exception:
                logger.exception(
                    "Failed to restore active database state for virtual IP %s",
                    ip,
                )
            self._active.add(ip)
            self._allocator.mark_allocated(ip)
            logger.exception(
                "Failed to persist release for virtual IP %s; protected OS "
                "alias restoration %s",
                ip,
                "succeeded" if restored else "could not be confirmed",
            )
            return False

        self._active.discard(ip)
        self._allocator.release(ip)
        logger.info("Removed virtual IP alias %s", ip)
        return True

    async def remove_all(self) -> int:
        """Remove all active virtual IP aliases (shutdown cleanup)."""
        removed = 0
        for ip in list(self._active):
            if await self.remove_alias(ip):
                removed += 1
        return removed

    async def load_from_db(self, *, restore_aliases: bool = True) -> int:
        """Load active reservations, optionally restoring their OS aliases.

        Production startup passes ``restore_aliases=False`` so the mimic
        orchestrator can atomically quarantine every persisted endpoint in PF
        before any address is published. The default preserves the standalone
        manager API used by migrations and focused tests.
        """
        cursor = await self._db.execute(
            "SELECT ip_address, interface FROM virtual_ips WHERE released_at IS NULL"
        )
        rows = await cursor.fetchall()

        restored = 0
        for row in rows:
            ip = row["ip_address"]
            iface = row["interface"]
            self._allocator.mark_allocated(ip)
            if not restore_aliases:
                continue
            if not await self.is_verified_free(ip):
                # Keep the durable reservation so another mimic cannot claim
                # it, but never put a conflicting address back on the host.
                logger.error(
                    "Refusing to restore virtual IP %s: ownership is not verified free",
                    ip,
                )
                continue
            # Track before the helper request for the same cancellation safety
            # as add_alias(). Production startup reserves without publishing,
            # but standalone recovery must not leave a cancelled mutation
            # invisible to shutdown cleanup.
            self.mark_possibly_active(ip)
            ok = await self._ops.add_ip_alias(ip, interface=iface)
            if ok:
                self._verified_published.add(ip)
                restored += 1
                logger.info("Restored virtual IP alias %s on %s", ip, iface)
            else:
                # The helper may have mutated the OS before its verified
                # rollback failed. "Active" deliberately means possibly live,
                # not verified ownership, so shutdown must retry removal and
                # retain PF until absence is confirmed.
                logger.error(
                    "Failed to restore virtual IP %s; retaining possibly-live "
                    "reservation",
                    ip,
                )

        return restored
