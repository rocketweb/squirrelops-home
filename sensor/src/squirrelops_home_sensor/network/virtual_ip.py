"""Virtual IP manager and IP allocator for mimic decoy deployment.

The IPAllocator finds unused IPs in the subnet (preferring .200-.250).
The VirtualIPManager wraps the privileged ops to add/remove ifconfig aliases,
persists state in the ``virtual_ips`` table, and provides a live set of
active virtual IPs for self-scan exclusion.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

import aiosqlite

from squirrelops_home_sensor.privileged.helper import PrivilegedOperations

logger = logging.getLogger("squirrelops_home_sensor.network")


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

    @property
    def active_ips(self) -> set[str]:
        """Currently active virtual IPs (for scan loop exclusion)."""
        return set(self._active)

    async def add_alias(self, ip: str) -> bool:
        """Add a virtual IP alias and persist to database."""
        ok = await self._ops.add_ip_alias(ip, interface=self._interface)
        if not ok:
            logger.warning("Failed to add IP alias %s on %s", ip, self._interface)
            return False

        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            """INSERT INTO virtual_ips (ip_address, interface, created_at)
               VALUES (?, ?, ?)
               ON CONFLICT(ip_address) DO UPDATE SET
                   released_at = NULL,
                   created_at = excluded.created_at""",
            (ip, self._interface, now),
        )
        await self._db.commit()
        self._active.add(ip)
        logger.info("Added virtual IP alias %s on %s", ip, self._interface)
        return True

    async def remove_alias(self, ip: str) -> bool:
        """Remove a virtual IP alias and mark released in database."""
        ok = await self._ops.remove_ip_alias(ip, interface=self._interface)
        if not ok:
            logger.warning("Failed to remove IP alias %s", ip)

        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            "UPDATE virtual_ips SET released_at = ? WHERE ip_address = ?",
            (now, ip),
        )
        await self._db.commit()
        self._active.discard(ip)
        self._allocator.release(ip)
        logger.info("Removed virtual IP alias %s", ip)
        return True

    async def remove_all(self) -> int:
        """Remove all active virtual IP aliases (shutdown cleanup)."""
        removed = 0
        for ip in list(self._active):
            await self.remove_alias(ip)
            removed += 1
        return removed

    async def load_from_db(self) -> int:
        """Startup: re-add aliases for IPs still marked active in DB, or clean orphans."""
        cursor = await self._db.execute(
            "SELECT ip_address, interface FROM virtual_ips WHERE released_at IS NULL"
        )
        rows = await cursor.fetchall()

        restored = 0
        for row in rows:
            ip = row["ip_address"]
            iface = row["interface"]
            ok = await self._ops.add_ip_alias(ip, interface=iface)
            if ok:
                self._active.add(ip)
                self._allocator.mark_allocated(ip)
                restored += 1
                logger.info("Restored virtual IP alias %s on %s", ip, iface)
            else:
                # Clean up orphan — can't re-add, mark as released
                now = datetime.now(timezone.utc).isoformat()
                await self._db.execute(
                    "UPDATE virtual_ips SET released_at = ? WHERE ip_address = ?",
                    (now, ip),
                )
                await self._db.commit()
                logger.warning("Cleaned up orphaned virtual IP %s", ip)

        return restored
