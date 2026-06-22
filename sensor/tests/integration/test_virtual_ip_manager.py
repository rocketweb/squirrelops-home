"""Integration tests for VirtualIPManager.refresh_active_ips (F6)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from squirrelops_home_sensor.network.virtual_ip import IPAllocator, VirtualIPManager


async def _insert_device(db, ip: str, *, online: int = 1) -> None:
    await db.execute(
        """INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type,
           first_seen, last_seen, is_online)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ip, "AA:BB:CC:DD:EE:FF", "nas", "Synology", "nas",
         "2026-02-20T00:00:00Z", "2026-02-22T00:00:00Z", online),
    )
    await db.commit()


@pytest.mark.asyncio
async def test_refresh_excludes_online_devices_from_allocation(db):
    # A real device occupies an address in the preferred .200-.250 range.
    await _insert_device(db, "192.168.1.200", online=1)

    allocator = IPAllocator(
        subnet="192.168.1.0/24", gateway_ip="192.168.1.1", sensor_ip="192.168.1.2",
    )
    manager = VirtualIPManager(privileged_ops=AsyncMock(), allocator=allocator, db=db)

    await manager.refresh_active_ips()
    allocated = allocator.allocate(5)

    assert "192.168.1.200" not in allocated
    # Sanity: it still allocates other addresses in the range.
    assert len(allocated) == 5


@pytest.mark.asyncio
async def test_refresh_ignores_offline_devices(db):
    await _insert_device(db, "192.168.1.201", online=0)

    allocator = IPAllocator(
        subnet="192.168.1.0/24", gateway_ip="192.168.1.1", sensor_ip="192.168.1.2",
    )
    manager = VirtualIPManager(privileged_ops=AsyncMock(), allocator=allocator, db=db)

    await manager.refresh_active_ips()
    allocated = allocator.allocate(50)

    # Offline devices are not live, so their address remains allocatable.
    assert "192.168.1.201" in allocated
