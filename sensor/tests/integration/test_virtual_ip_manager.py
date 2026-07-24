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


@pytest.mark.asyncio
async def test_refresh_ignores_stale_self_scan_for_reserved_virtual_ip(db):
    # Older releases recorded their own physical-interface aliases as online
    # devices. That stale row must not prevent a persisted mimic address from
    # being verified and migrated to the isolated loopback/proxy-ARP form.
    await _insert_device(db, "192.168.1.200", online=1)
    await db.execute(
        """INSERT INTO virtual_ips (ip_address, interface, created_at)
           VALUES ('192.168.1.200', 'en0', '2026-02-22T00:00:00Z')"""
    )
    await db.commit()

    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=200,
    )
    manager = VirtualIPManager(
        privileged_ops=AsyncMock(),
        allocator=allocator,
        db=db,
    )

    assert await manager.refresh_active_ips() == []
    assert allocator.allocate(1) == ["192.168.1.200"]


@pytest.mark.asyncio
async def test_allocate_verified_excludes_fresh_arp_owner(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=201,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "38:42:0b:48:51:07"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == ["192.168.1.201"]
    ops.arp_scan.assert_awaited_once_with("192.168.1.0/24")


@pytest.mark.asyncio
async def test_allocate_verified_unions_database_and_fresh_arp_owners(db):
    await _insert_device(db, "192.168.1.200", online=1)
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=202,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.201", "38:42:0b:48:51:07"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == ["192.168.1.202"]


@pytest.mark.asyncio
async def test_allocate_verified_reserves_stopped_mimic_bind_address(db):
    await db.execute(
        """INSERT INTO decoys
           (name, decoy_type, bind_address, port, status, config,
            created_at, updated_at)
           VALUES ('stopped-mimic', 'mimic', '192.168.1.200', 8080,
                   'stopped', '{}', '2026-01-01T00:00:00Z',
                   '2026-01-01T00:00:00Z')"""
    )
    await db.commit()
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=201,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == ["192.168.1.201"]


@pytest.mark.asyncio
async def test_allocate_verified_reuses_supplied_fresh_arp_results(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=201,
    )
    ops = AsyncMock()
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    result = await manager.allocate_verified(
        1,
        arp_results=[
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "38:42:0b:48:51:07"),
        ],
    )

    assert result == ["192.168.1.201"]
    ops.arp_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_allocate_verified_shares_probe_across_deployment_burst(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=201,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == ["192.168.1.200"]
    assert await manager.allocate_verified(1) == ["192.168.1.201"]
    ops.arp_scan.assert_awaited_once_with("192.168.1.0/24")


@pytest.mark.asyncio
async def test_snapshot_real_ip_owners_forces_one_fresh_probe(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "38:42:0b:48:51:07"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}
    manager._owner_scan_cache = {"192.168.1.199": "66:55:44:33:22:11"}

    assert await manager.snapshot_real_ip_owners() == [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "38:42:0b:48:51:07"),
    ]
    ops.arp_scan.assert_awaited_once_with("192.168.1.0/24")


@pytest.mark.asyncio
async def test_allocate_verified_fails_closed_on_empty_probe(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = []
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)

    assert await manager.allocate_verified(1) == []


@pytest.mark.asyncio
async def test_allocate_verified_fails_closed_when_probe_only_sees_local_aliases(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=200,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == []


@pytest.mark.asyncio
async def test_allocate_verified_fails_closed_on_probe_error(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.arp_scan.side_effect = RuntimeError("helper unavailable")
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)

    assert await manager.allocate_verified(1) == []


@pytest.mark.asyncio
async def test_ownership_checks_fail_closed_when_device_inventory_is_unavailable():
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=200,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
    ]
    broken_db = AsyncMock()
    broken_db.execute.side_effect = RuntimeError("database unavailable")
    manager = VirtualIPManager(
        privileged_ops=ops,
        allocator=allocator,
        db=broken_db,
    )
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == []
    assert await manager.is_verified_free("192.168.1.200") is False
    ops.arp_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_untracked_local_address_is_not_free_for_mimic_ownership(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=200,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == []
    assert await manager.is_verified_free("192.168.1.200") is False


@pytest.mark.asyncio
async def test_restore_verification_does_not_reuse_cached_ownership_snapshot(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=200,
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "38:42:0b:48:51:07"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}
    manager._owner_scan_cache = {
        "192.168.1.1": "00:11:22:33:44:55",
    }
    manager._owner_scan_cache_at = float("inf")

    assert await manager.is_verified_free("192.168.1.200") is False
    ops.arp_scan.assert_awaited_once_with("192.168.1.0/24")


@pytest.mark.asyncio
async def test_verify_batch_ownership_withdraws_only_new_aliases_for_one_probe(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.remove_ip_alias.return_value = True
    ops.add_ip_alias.return_value = True
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.201", "38:42:0b:48:51:07"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.update(
        {"192.168.1.199", "192.168.1.200", "192.168.1.201"}
    )
    manager._verified_published.update(manager._active)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    conflicts = await manager.verify_batch_ownership(
        {"192.168.1.200", "192.168.1.201"}
    )

    assert conflicts == {"192.168.1.201": "38:42:0b:48:51:07"}
    assert manager.verified_ips == {"192.168.1.199", "192.168.1.200"}
    assert {
        call.args[0] for call in ops.remove_ip_alias.await_args_list
    } == {"192.168.1.200", "192.168.1.201"}
    ops.arp_scan.assert_awaited_once_with("192.168.1.0/24")
    ops.add_ip_alias.assert_awaited_once_with(
        "192.168.1.200",
        interface="en0",
    )


@pytest.mark.asyncio
async def test_verify_batch_ownership_stays_fail_closed_when_probe_fails(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.remove_ip_alias.return_value = True
    ops.arp_scan.side_effect = RuntimeError("helper scan failed")
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.update({"192.168.1.199", "192.168.1.200"})
    manager._verified_published.update(manager._active)

    conflicts = await manager.verify_batch_ownership({"192.168.1.200"})

    assert conflicts == {"192.168.1.200": "ownership-probe-failed"}
    assert manager.verified_ips == {"192.168.1.199"}
    ops.remove_ip_alias.assert_awaited_once_with(
        "192.168.1.200",
        interface="en0",
    )
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_find_conflicts_ignores_proxy_arp_owned_by_this_host(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.add("192.168.1.200")
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.find_conflicts() == {}

    ops.arp_scan.return_value = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", "38:42:0b:48:51:07"),
    ]
    assert await manager.find_conflicts() == {
        "192.168.1.200": "38:42:0b:48:51:07",
    }


@pytest.mark.asyncio
async def test_find_conflicts_canonicalizes_unpadded_macos_proxy_mac(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.update({"192.168.1.200", "192.168.1.201"})
    manager._local_interface_macs = lambda: {"1c:1d:d3:e0:7d:03"}

    conflicts = await manager.find_conflicts(
        arp_results=[
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "1c:1d:d3:e0:7d:3"),
            ("192.168.1.201", "1c:1d:d3:e0:7d:3"),
        ]
    )

    assert conflicts == {}
    ops.arp_scan.assert_not_awaited()
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_find_conflicts_ignores_malformed_mac_but_keeps_foreign_claim(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.update({"192.168.1.200", "192.168.1.201"})
    manager._local_interface_macs = lambda: {"1c:1d:d3:e0:7d:03"}

    conflicts = await manager.find_conflicts(
        arp_results=[
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "not-a-mac"),
            ("192.168.1.201", "38:42:b:48:51:7"),
        ]
    )

    assert conflicts == {"192.168.1.201": "38:42:0b:48:51:07"}
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_find_conflicts_preserves_alias_when_local_mac_inventory_fails(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.add("192.168.1.200")
    manager._local_interface_macs = lambda: set()

    conflicts = await manager.find_conflicts(
        arp_results=[
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "1c:1d:d3:e0:7d:3"),
        ]
    )

    assert conflicts == {}
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_allocate_verified_reserves_ip_with_malformed_mac_owner(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=201,
    )
    ops = AsyncMock()
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)

    allocated = await manager.allocate_verified(
        2,
        arp_results=[
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "not-a-mac"),
        ],
    )

    assert allocated == ["192.168.1.201"]


@pytest.mark.asyncio
async def test_find_conflicts_preserves_alias_when_probe_only_sees_local_aliases(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.arp_scan.return_value = [
        ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
    ]
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.add("192.168.1.200")
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.find_conflicts() == {}
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_find_conflicts_accepts_completed_discovery_scan(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.add("192.168.1.200")
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    conflicts = await manager.find_conflicts(
        arp_results=[
            ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
            ("192.168.1.200", "38:42:0b:48:51:07"),
        ]
    )

    assert conflicts == {"192.168.1.200": "38:42:0b:48:51:07"}
    ops.arp_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_macos_routine_conflict_probe_does_not_withdraw_active_aliases(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.requires_active_alias_withdrawal_probe = True
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.update({"192.168.1.200", "192.168.1.201"})
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    conflicts = await manager.find_conflicts(
        arp_results=[
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "aa:bb:cc:dd:ee:ff"),
            ("192.168.1.201", "aa:bb:cc:dd:ee:ff"),
        ]
    )

    assert conflicts == {}
    ops.arp_scan.assert_not_awaited()
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_macos_routine_conflict_probe_failure_does_not_mutate_aliases(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
    )
    ops = AsyncMock()
    ops.requires_active_alias_withdrawal_probe = True
    ops.arp_scan.side_effect = RuntimeError("helper scan failed")
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._active.update({"192.168.1.200", "192.168.1.201"})

    conflicts = await manager.find_conflicts()

    assert conflicts == {}
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_post_allocation_conflict_is_detected_by_fresh_probe(db):
    allocator = IPAllocator(
        subnet="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        sensor_ip="192.168.1.2",
        range_start=200,
        range_end=200,
    )
    ops = AsyncMock()
    ops.arp_scan.side_effect = [
        [("192.168.1.1", "00:11:22:33:44:55")],
        [
            ("192.168.1.1", "00:11:22:33:44:55"),
            ("192.168.1.200", "38:42:0b:48:51:07"),
        ],
    ]
    ops.add_ip_alias.return_value = True
    manager = VirtualIPManager(privileged_ops=ops, allocator=allocator, db=db)
    manager._local_interface_macs = lambda: {"aa:bb:cc:dd:ee:ff"}

    assert await manager.allocate_verified(1) == ["192.168.1.200"]
    assert await manager.add_alias("192.168.1.200") is True
    assert await manager.find_conflicts() == {
        "192.168.1.200": "38:42:0b:48:51:07",
    }
