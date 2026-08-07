"""Group B: decoy and mimic lifecycle.

Covers B-01 through B-07 and B-10 through B-15. B-08 and B-09 live in
test_known_defects.py because they reproduce KD-1.

Asserts the behavior the product should have. A failure is a finding.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from squirrelops_home_sensor.network.port_forward import PortForwardManager


def build_orchestrator(db, *, verified_ips=frozenset({"192.168.1.200"}), max_mimics=4):
    from squirrelops_home_sensor.scouts.orchestrator import MimicOrchestrator

    ip_manager = SimpleNamespace(
        verified_ips=set(verified_ips),
        is_available=AsyncMock(return_value=True),
        add_alias=AsyncMock(return_value=True),
        remove_alias=AsyncMock(return_value=True),
        release_reservation=lambda _: None,
    )
    return MimicOrchestrator(
        scout_engine=SimpleNamespace(),
        template_generator=SimpleNamespace(),
        ip_manager=ip_manager,
        event_bus=SimpleNamespace(publish=AsyncMock(return_value=1)),
        db=db,
        max_mimics=max_mimics,
        mdns_advertiser=SimpleNamespace(
            register=AsyncMock(return_value=True), unregister=AsyncMock()
        ),
        port_forward_manager=SimpleNamespace(
            add_forwards=AsyncMock(return_value=True),
            remove_forwards=AsyncMock(return_value=True),
            quarantine_endpoints=AsyncMock(return_value=True),
            clear_all=AsyncMock(return_value=True),
        ),
        sensor_hostnames={"sensor-box.local."},
    )


async def seed_host(db, *, hostname, ip, ports, host_id=None):
    """Insert a decoy_hosts row plus one decoy row per port.

    decoys.host_id references decoy_hosts(id), and hostname collision checks
    read decoy_hosts, so a mimic host is not represented by decoy rows alone.
    """
    if host_id is not None:
        await db.execute(
            """INSERT INTO decoy_hosts
               (id, hostname, bind_address, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (host_id, hostname, ip, "2026-08-07T00:00:00Z", "2026-08-07T00:00:00Z"),
        )
    ids = []
    for index, port in enumerate(ports):
        cursor = await db.execute(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config,
                created_at, updated_at, host_id, is_primary)
               VALUES (?, 'mimic', ?, ?, 'active', '{}', ?, ?, ?, ?)""",
            (
                hostname,
                ip,
                port,
                "2026-08-07T00:00:00Z",
                "2026-08-07T00:00:00Z",
                host_id,
                1 if index == 0 else 0,
            ),
        )
        ids.append(int(cursor.lastrowid))
    await db.commit()
    return ids


class TestB01OneRowPerPort:
    @pytest.mark.asyncio
    async def test_service_rows_group_by_host_with_one_primary(self, db):
        orch = build_orchestrator(db)
        ids = await seed_host(
            db, hostname="office.local", ip="192.168.1.200",
            ports=[22, 80, 443], host_id=1,
        )

        rows = await orch._service_rows_for_primary(ids[0])

        assert len(rows) == 3, "every advertised port needs its own row"
        assert sum(row["is_primary"] for row in rows) == 1
        assert {row["port"] for row in rows} == {22, 80, 443}


class TestB02DistinctBackendPorts:
    @pytest.mark.asyncio
    async def test_a_backend_port_equal_to_its_advertised_port_is_rejected(self):
        manager = PortForwardManager(SimpleNamespace(), interface="en0")
        with pytest.raises(ValueError, match="differ from advertised"):
            await manager.add_forwards(
                decoy_id=1, bind_ip="192.168.1.200", port_remaps={80: 80}
            )

    @pytest.mark.asyncio
    async def test_duplicate_backend_ports_are_rejected(self):
        manager = PortForwardManager(SimpleNamespace(), interface="en0")
        with pytest.raises(ValueError, match="unique"):
            await manager.add_forwards(
                decoy_id=1, bind_ip="192.168.1.200",
                port_remaps={80: 10080, 443: 10080},
            )

    @pytest.mark.asyncio
    async def test_a_backend_port_may_not_shadow_an_advertised_port(self):
        manager = PortForwardManager(SimpleNamespace(), interface="en0")
        with pytest.raises(ValueError, match="overlap"):
            await manager.add_forwards(
                decoy_id=1, bind_ip="192.168.1.200",
                port_remaps={80: 443, 443: 10443},
            )


class TestB04RemovalSoftRetires:
    @pytest.mark.asyncio
    async def test_rows_are_retired_not_deleted(self, db):
        orch = build_orchestrator(db)
        ids = await seed_host(
            db, hostname="office.local", ip="192.168.1.200",
            ports=[22, 80], host_id=1,
        )

        await orch._delete_mimic_records(
            decoy_id=ids[0], template_id=None,
            virtual_ip="192.168.1.200", retirement_reason="removed_by_user",
        )

        cursor = await db.execute("SELECT COUNT(*) FROM decoys WHERE id IN (?, ?)", ids)
        assert (await cursor.fetchone())[0] == 2, "forensic rows must survive"
        cursor = await db.execute(
            "SELECT status, retired_at, retirement_reason FROM decoys WHERE id = ?",
            (ids[0],),
        )
        row = await cursor.fetchone()
        assert row["status"] == "stopped"
        assert row["retired_at"] is not None
        assert row["retirement_reason"] == "removed_by_user"


class TestB05RetiredIsInvisible:
    def test_retired_decoy_is_absent_from_the_list(self, client, db):
        import asyncio

        async def setup():
            ids = await seed_host(
                db, hostname="gone.local", ip="192.168.1.201",
                ports=[22], host_id=2,
            )
            await db.execute(
                "UPDATE decoys SET retired_at = '2026-08-07T01:00:00Z' WHERE id = ?",
                (ids[0],),
            )
            await db.commit()
            return ids[0]

        retired_id = asyncio.get_event_loop().run_until_complete(setup())

        listed = {item["id"] for item in client.get("/decoys").json()["items"]}
        assert retired_id not in listed
        assert client.get(f"/decoys/{retired_id}").status_code == 404


class TestB06VirtualIPReleased:
    @pytest.mark.asyncio
    async def test_removal_frees_the_virtual_ip_row(self, db):
        orch = build_orchestrator(db)
        ids = await seed_host(
            db, hostname="office.local", ip="192.168.1.200",
            ports=[22], host_id=1,
        )
        await db.execute(
            "INSERT INTO virtual_ips (ip_address, decoy_id, created_at) "
            "VALUES ('192.168.1.200', ?, '2026-08-07T00:00:00Z')",
            (ids[0],),
        )
        await db.commit()

        await orch._delete_mimic_records(
            decoy_id=ids[0], template_id=None,
            virtual_ip="192.168.1.200", retirement_reason="removed_by_user",
        )

        cursor = await db.execute(
            "SELECT COUNT(*) FROM virtual_ips WHERE ip_address = '192.168.1.200'"
        )
        assert (await cursor.fetchone())[0] == 0, "the IP must be reusable"


class TestB10MdnsFailureDegradesTheHost:
    @pytest.mark.asyncio
    async def test_every_service_of_the_host_reports_degraded(self, db):
        orch = build_orchestrator(db)
        primary, siblings = 100, [101, 102]
        orch._active_mimics[primary] = SimpleNamespace(
            bind_address="192.168.1.200", name="office.local"
        )
        for service_id in [primary, *siblings]:
            orch._service_to_primary[service_id] = primary
        orch._mdns_degraded.add(primary)

        statuses = {
            sid: orch.effective_mimic_status(sid, "active")
            for sid in [primary, *siblings]
        }
        assert set(statuses.values()) == {"degraded"}, statuses


class TestB11StoppedIsLeftAlone:
    @pytest.mark.asyncio
    async def test_overlay_does_not_promote_a_stopped_row(self, db):
        orch = build_orchestrator(db)
        orch._active_mimics[100] = SimpleNamespace(
            bind_address="192.168.1.200", name="office.local"
        )
        orch._service_to_primary[100] = 100

        assert orch.effective_mimic_status(100, "stopped") == "stopped"

    @pytest.mark.asyncio
    async def test_unverified_ip_degrades_an_active_row(self, db):
        orch = build_orchestrator(db, verified_ips=set())
        orch._active_mimics[100] = SimpleNamespace(
            bind_address="192.168.1.200", name="office.local"
        )
        orch._service_to_primary[100] = 100

        assert orch.effective_mimic_status(100, "active") == "degraded"


class TestB13HostnameUniqueness:
    @pytest.mark.asyncio
    async def test_a_colliding_hostname_is_made_unique(self, db):
        orch = build_orchestrator(db)
        await seed_host(
            db, hostname="storage.local", ip="192.168.1.200",
            ports=[22], host_id=1,
        )

        generated = await orch._unique_generated_hostname("storage.local")

        assert generated != "storage.local"
        assert generated.endswith(".local")

    @pytest.mark.asyncio
    async def test_the_sensor_hostname_is_treated_as_taken(self, db):
        """The guard lives in _observed_real_hostnames, not in the generator."""
        orch = build_orchestrator(db)
        observed = await orch._observed_real_hostnames()
        assert "sensor-box.local." in observed


class TestB15StaleRemovalRefused:
    @pytest.mark.asyncio
    async def test_removing_an_unknown_decoy_reports_failure(self, db):
        orch = build_orchestrator(db)
        assert await orch.remove_mimic(999_999) is False
