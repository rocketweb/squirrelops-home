"""Tests for the IP allocator and virtual IP manager."""
from __future__ import annotations

from unittest.mock import AsyncMock

import aiosqlite
import pytest

from squirrelops_home_sensor.network.virtual_ip import IPAllocator, VirtualIPManager

_SCHEMA = """
CREATE TABLE IF NOT EXISTS virtual_ips (
    id INTEGER PRIMARY KEY,
    ip_address TEXT NOT NULL UNIQUE,
    interface TEXT NOT NULL DEFAULT 'en0',
    decoy_id INTEGER,
    created_at TEXT NOT NULL,
    released_at TEXT
);
"""


@pytest.fixture
async def db():
    """In-memory test database with virtual_ips schema."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.executescript(_SCHEMA)
        yield conn


class TestIPAllocator:
    """Verify IP allocation strategy and exclusion rules."""

    def test_allocate_returns_ips_in_range(self) -> None:
        """Allocated IPs should be in .200-.250 range."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
        )
        ips = alloc.allocate(3)
        assert len(ips) == 3
        for ip in ips:
            last_octet = int(ip.split(".")[-1])
            assert 200 <= last_octet <= 250

    def test_allocate_returns_requested_count(self) -> None:
        """Should return exactly the requested number of IPs."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
        )
        ips = alloc.allocate(5)
        assert len(ips) == 5

    def test_allocate_excludes_gateway(self) -> None:
        """Gateway IP should never be allocated, even if in range."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.200",
            sensor_ip="192.168.1.50",
        )
        ips = alloc.allocate(51)
        assert "192.168.1.200" not in ips

    def test_allocate_excludes_sensor_ip(self) -> None:
        """Sensor IP should never be allocated, even if in range."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.210",
        )
        ips = alloc.allocate(51)
        assert "192.168.1.210" not in ips

    def test_allocate_excludes_active_ips(self) -> None:
        """IPs seen in ARP scans should be excluded."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
        )
        alloc.set_active_ips([
            ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
            ("192.168.1.201", "aa:bb:cc:dd:ee:00"),
        ])
        ips = alloc.allocate(3)
        assert "192.168.1.200" not in ips
        assert "192.168.1.201" not in ips

    def test_allocate_excludes_already_allocated(self) -> None:
        """Previously allocated IPs should not be re-allocated."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
        )
        first = alloc.allocate(2)
        second = alloc.allocate(2)
        assert len(set(first) & set(second)) == 0

    def test_allocate_returns_empty_when_exhausted(self) -> None:
        """Should return empty list when all IPs are taken."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
            range_start=200,
            range_end=202,
        )
        first = alloc.allocate(3)
        assert len(first) == 3
        second = alloc.allocate(1)
        assert len(second) == 0

    def test_release_makes_ip_available(self) -> None:
        """Releasing an IP should allow it to be re-allocated."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
            range_start=200,
            range_end=200,
        )
        first = alloc.allocate(1)
        assert len(first) == 1
        ip = first[0]

        # Exhausted now
        assert alloc.allocate(1) == []

        # Release and re-allocate
        alloc.release(ip)
        second = alloc.allocate(1)
        assert second == [ip]

    def test_mark_allocated_prevents_reallocation(self) -> None:
        """mark_allocated should exclude IPs from future allocation."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
            range_start=200,
            range_end=201,
        )
        alloc.mark_allocated("192.168.1.200")
        ips = alloc.allocate(2)
        assert "192.168.1.200" not in ips
        assert len(ips) == 1
        assert ips[0] == "192.168.1.201"

    def test_custom_range(self) -> None:
        """Custom range_start/range_end should be respected."""
        alloc = IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.50",
            range_start=150,
            range_end=155,
        )
        ips = alloc.allocate(6)
        assert len(ips) == 6
        for ip in ips:
            last_octet = int(ip.split(".")[-1])
            assert 150 <= last_octet <= 155


class TestVirtualIPManager:
    """Verify VirtualIPManager add/remove/load operations."""

    @pytest.mark.asyncio
    async def test_add_alias_succeeds(self, db) -> None:
        """add_alias should call privileged ops and persist."""
        ops = AsyncMock()
        ops.add_ip_alias = AsyncMock(return_value=True)
        alloc = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.50")
        mgr = VirtualIPManager(ops, alloc, db)

        ok = await mgr.add_alias("192.168.1.200")
        assert ok is True
        assert "192.168.1.200" in mgr.active_ips
        ops.add_ip_alias.assert_awaited_once_with("192.168.1.200", interface="en0")

        # Check DB
        cursor = await db.execute("SELECT ip_address FROM virtual_ips WHERE released_at IS NULL")
        rows = await cursor.fetchall()
        assert len(rows) == 1
        assert rows[0]["ip_address"] == "192.168.1.200"

    @pytest.mark.asyncio
    async def test_add_alias_fails(self, db) -> None:
        """add_alias should return False if privileged ops fail."""
        ops = AsyncMock()
        ops.add_ip_alias = AsyncMock(return_value=False)
        alloc = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.50")
        mgr = VirtualIPManager(ops, alloc, db)

        ok = await mgr.add_alias("192.168.1.200")
        assert ok is False
        assert "192.168.1.200" not in mgr.active_ips

    @pytest.mark.asyncio
    async def test_remove_alias(self, db) -> None:
        """remove_alias should remove from active set and mark released in DB."""
        ops = AsyncMock()
        ops.add_ip_alias = AsyncMock(return_value=True)
        ops.remove_ip_alias = AsyncMock(return_value=True)
        alloc = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.50")
        mgr = VirtualIPManager(ops, alloc, db)

        await mgr.add_alias("192.168.1.200")
        await mgr.remove_alias("192.168.1.200")

        assert "192.168.1.200" not in mgr.active_ips

        cursor = await db.execute("SELECT released_at FROM virtual_ips WHERE ip_address = '192.168.1.200'")
        row = await cursor.fetchone()
        assert row["released_at"] is not None

    @pytest.mark.asyncio
    async def test_remove_all(self, db) -> None:
        """remove_all should stop all aliases."""
        ops = AsyncMock()
        ops.add_ip_alias = AsyncMock(return_value=True)
        ops.remove_ip_alias = AsyncMock(return_value=True)
        alloc = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.50")
        mgr = VirtualIPManager(ops, alloc, db)

        await mgr.add_alias("192.168.1.200")
        await mgr.add_alias("192.168.1.201")
        assert len(mgr.active_ips) == 2

        removed = await mgr.remove_all()
        assert removed == 2
        assert len(mgr.active_ips) == 0

    @pytest.mark.asyncio
    async def test_load_from_db_restores_active(self, db) -> None:
        """load_from_db should re-add aliases for non-released IPs."""
        # Pre-populate DB
        await db.execute(
            "INSERT INTO virtual_ips (ip_address, interface, created_at) "
            "VALUES ('192.168.1.220', 'en0', '2026-01-01T00:00:00Z')"
        )
        await db.execute(
            "INSERT INTO virtual_ips (ip_address, interface, created_at, released_at) "
            "VALUES ('192.168.1.221', 'en0', '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')"
        )
        await db.commit()

        ops = AsyncMock()
        ops.add_ip_alias = AsyncMock(return_value=True)
        alloc = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.50")
        mgr = VirtualIPManager(ops, alloc, db)

        restored = await mgr.load_from_db()
        assert restored == 1
        assert "192.168.1.220" in mgr.active_ips
        assert "192.168.1.221" not in mgr.active_ips

    @pytest.mark.asyncio
    async def test_load_from_db_cleans_orphans(self, db) -> None:
        """If re-adding fails, the orphan should be marked released."""
        await db.execute(
            "INSERT INTO virtual_ips (ip_address, interface, created_at) "
            "VALUES ('192.168.1.230', 'en0', '2026-01-01T00:00:00Z')"
        )
        await db.commit()

        ops = AsyncMock()
        ops.add_ip_alias = AsyncMock(return_value=False)
        alloc = IPAllocator("192.168.1.0/24", "192.168.1.1", "192.168.1.50")
        mgr = VirtualIPManager(ops, alloc, db)

        restored = await mgr.load_from_db()
        assert restored == 0
        assert "192.168.1.230" not in mgr.active_ips

        cursor = await db.execute("SELECT released_at FROM virtual_ips WHERE ip_address = '192.168.1.230'")
        row = await cursor.fetchone()
        assert row["released_at"] is not None
