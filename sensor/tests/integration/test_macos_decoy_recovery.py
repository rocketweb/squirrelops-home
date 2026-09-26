"""Regressions for the observed macOS 27 decoy creation failures."""

import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import psutil
import pytest

from squirrelops_home_sensor.decoys import orchestrator as classic
from squirrelops_home_sensor.network.virtual_ip import IPAllocator, VirtualIPManager
from squirrelops_home_sensor.privileged.xpc import MacOSPrivilegedOps
from squirrelops_home_sensor.scanner import loop as scanner

LOCAL_MAC = "1c:1d:d3:e0:7d:03"
REDACTED_MAC = "02:00:00:00:00:00"


@pytest.mark.asyncio
async def test_macos_identity_comes_from_helper_not_redacted_child_process(monkeypatch):
    from squirrelops_home_sensor.privileged.xpc import MacOSPrivilegedOps

    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {
        "en0": [SimpleNamespace(family=psutil.AF_LINK, address=REDACTED_MAC)],
    })
    helper = MacOSPrivilegedOps()
    helper._call = AsyncMock(return_value=[LOCAL_MAC])
    assert await helper.local_interface_macs() == {LOCAL_MAC.upper()}
    helper._call.assert_awaited_once_with("getLocalInterfaceMACs")


@pytest.fixture
def redacted_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {
        "en0": [SimpleNamespace(family=psutil.AF_LINK, address=REDACTED_MAC)],
    })
    run = Mock(return_value=subprocess.CompletedProcess(
        ["/sbin/ifconfig", "-a"], 0,
        stdout=f"en0: flags=8863\n\tether {REDACTED_MAC}\n\tinet 192.168.1.18 netmask 0xffffff00\n",
        stderr="",
    ))
    monkeypatch.setattr(subprocess, "run", run)
    helper = MacOSPrivilegedOps()
    helper._call = AsyncMock(return_value=[LOCAL_MAC])
    return helper


@pytest.mark.asyncio
async def test_mac_inventory_does_not_trust_redacted_psutil_value(db, redacted_macos):
    manager = VirtualIPManager(redacted_macos, IPAllocator(
        "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
    ), db)
    assert await manager._local_interface_macs() == {LOCAL_MAC}
    assert await scanner._local_interface_macs(redacted_macos) == {LOCAL_MAC.upper()}


@pytest.mark.asyncio
async def test_real_proxy_mac_is_not_a_conflict_but_foreign_owner_is(db, redacted_macos):
    ops = redacted_macos
    ops.remove_ip_alias = AsyncMock()
    manager = VirtualIPManager(ops, IPAllocator(
        "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
    ), db)
    manager._active.update({"192.168.1.200", "192.168.1.201"})
    assert await manager.find_conflicts([
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.200", LOCAL_MAC),
        ("192.168.1.201", "38:42:0b:48:51:07"),
    ]) == {"192.168.1.201": "38:42:0b:48:51:07"}
    ops.remove_ip_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_inventory_excludes_self_and_proxy_alias_without_false_warning(redacted_macos):
    inventory, conflicts = await scanner._inventory_arp_results([
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.18", LOCAL_MAC),
        ("192.168.1.200", LOCAL_MAC),
    ], redacted_macos)
    assert inventory == [("192.168.1.1", "00:11:22:33:44:55")]
    assert conflicts == []


@pytest.mark.parametrize("kind", ["deep", "host_without_services"])
@pytest.mark.asyncio
async def test_allocation_reserves_every_unretired_host_address(db, kind):
    await db.execute("""INSERT INTO decoy_hosts
        (id, hostname, bind_address, created_at, updated_at)
        VALUES (1, 'studio-mini.local', '192.168.1.200', '2026-09-25', '2026-09-25')""")
    if kind == "deep":
        await db.execute("""INSERT INTO decoys
            (name, decoy_type, bind_address, port, status, host_id, created_at, updated_at)
            VALUES ('Studio Build Mac', 'deep', '192.168.1.200', 445, 'stopped', 1,
                    '2026-09-25', '2026-09-25')""")
    await db.commit()
    ops = AsyncMock()
    ops.arp_scan.return_value = [("192.168.1.1", "00:11:22:33:44:55")]
    manager = VirtualIPManager(ops, IPAllocator(
        "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
    ), db)
    manager._local_interface_macs = AsyncMock(return_value={LOCAL_MAC})
    assert await manager.allocate_verified(1) == ["192.168.1.201"]
    row = await (await db.execute("SELECT * FROM decoy_hosts WHERE id=1")).fetchone()
    assert row["retired_at"] is None
    assert row["bind_address"] == "192.168.1.200"


def test_classic_listener_uses_selected_lan_not_vpn(monkeypatch):
    monkeypatch.setattr(classic, "_route_selected_ip", lambda: "100.96.4.79")
    monkeypatch.setattr(classic, "_interface_ipv4_addresses", lambda _: ["192.168.1.18"])
    assert classic._resolve_bind_address(
        interface="en0", excluded_ips=set(),
        virtual_ip_range_start=200, virtual_ip_range_end=250,
    ) == "192.168.1.18"


@pytest.mark.parametrize("result", [[], [REDACTED_MAC], ["invalid"], [None], {}, [LOCAL_MAC] * 257])
@pytest.mark.asyncio
async def test_unavailable_mac_inventory_does_not_invent_ownership(redacted_macos, result):
    redacted_macos._call.return_value = result
    with pytest.raises(RuntimeError, match="MAC inventory"):
        await redacted_macos.local_interface_macs()


@pytest.mark.asyncio
async def test_helper_identity_failure_blocks_allocation_but_preserves_active_host(db, redacted_macos):
    redacted_macos._call.side_effect = RuntimeError("helper unavailable")
    manager = VirtualIPManager(redacted_macos, IPAllocator(
        "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
    ), db)
    manager._active.add("192.168.1.200")
    arp = [("192.168.1.1", "00:11:22:33:44:55"), ("192.168.1.200", LOCAL_MAC)]
    assert await manager.allocate_verified(1, arp) == []
    assert await manager.find_conflicts(arp) == {}
    assert manager.active_ips == {"192.168.1.200"}


@pytest.mark.asyncio
async def test_retired_host_address_can_be_reused_without_deleting_history(db):
    await db.execute("""INSERT INTO decoy_hosts
        (id, hostname, bind_address, retired_at, created_at, updated_at)
        VALUES (1, 'old.local', '192.168.1.200', '2026-09-25', '2026-09-24', '2026-09-25')""")
    await db.commit()
    ops = AsyncMock()
    ops.arp_scan.return_value = [("192.168.1.1", "00:11:22:33:44:55")]
    manager = VirtualIPManager(ops, IPAllocator(
        "192.168.1.0/24", "192.168.1.1", "192.168.1.18",
    ), db)
    manager._local_interface_macs = AsyncMock(return_value={LOCAL_MAC})
    assert await manager.allocate_verified(1) == ["192.168.1.200"]
    assert await (await db.execute("SELECT 1 FROM decoy_hosts WHERE id=1")).fetchone()


def test_vpn_does_not_become_classic_fallback_if_lan_disappears(monkeypatch):
    monkeypatch.setattr(classic, "_route_selected_ip", lambda: "100.96.4.79")
    monkeypatch.setattr(classic, "_interface_ipv4_addresses", lambda _: [])
    assert classic._resolve_bind_address(
        interface="en0", excluded_ips=set(),
        virtual_ip_range_start=200, virtual_ip_range_end=250,
    ) is None


def test_linux_inventory_still_uses_interface_addresses(monkeypatch):
    from squirrelops_home_sensor.network import identity

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {
        "eth0": [SimpleNamespace(family=psutil.AF_LINK, address=LOCAL_MAC)],
        "lo": [SimpleNamespace(family=psutil.AF_LINK, address="00:00:00:00:00:00")],
    })
    run = Mock(side_effect=AssertionError("Linux must not invoke macOS ifconfig"))
    monkeypatch.setattr(subprocess, "run", run)
    assert identity.local_interface_macs() == {LOCAL_MAC.upper()}
    run.assert_not_called()
