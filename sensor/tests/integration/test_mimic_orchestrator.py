"""Regression coverage for mimic deployment and persistence lifecycle."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, call

import pytest

from squirrelops_home_sensor.network.virtual_ip import IPAllocator, VirtualIPManager
from squirrelops_home_sensor.scouts.engine import ServiceProfile
from squirrelops_home_sensor.scouts.orchestrator import (
    HelperUnavailableError,
    MimicCleanupError,
    MimicDeploymentError,
    MimicOrchestrator,
)
from squirrelops_home_sensor.scouts.templates import MimicTemplate


class FakeMimic:
    def __init__(
        self,
        *,
        decoy_id,
        name,
        bind_address,
        port_configs,
        server_header=None,
        planted_credentials=None,
        port_remaps=None,
        tls_cert_pem=None,
        tls_key_pem=None,
        credentials_by_port=None,
    ):
        self.decoy_id = decoy_id
        self.name = name
        self.bind_address = bind_address
        self.port = port_configs[0]["port"]
        self.port_configs = port_configs
        self.started = False
        self._configured_port_remaps = dict(port_remaps or {})
        self._port_remaps = dict(self._configured_port_remaps)
        self.tls_cert_pem = tls_cert_pem
        self.tls_key_pem = tls_key_pem
        self.credentials_by_port = dict(credentials_by_port or {})

    async def start(self):
        dynamic_ports = sorted(
            port for port, bind_port in self._configured_port_remaps.items()
            if bind_port == 0
        )
        for index, port in enumerate(dynamic_ports):
            self._port_remaps[port] = 50000 + index
        self.started = True

    async def stop(self):
        self.started = False
        self._port_remaps = dict(self._configured_port_remaps)

    @property
    def port_remaps(self):
        return dict(self._port_remaps)

    def rename_identity(
        self,
        hostname,
        *,
        cert_pem=None,
        key_pem=None,
    ):
        self.name = hostname
        if cert_pem is not None:
            self.tls_cert_pem = cert_pem
        if key_pem is not None:
            self.tls_key_pem = key_pem


@pytest.fixture
async def mimic_setup(db, monkeypatch):
    await db.execute(
        """INSERT INTO devices
           (id, ip_address, hostname, device_type, first_seen, last_seen, is_online)
           VALUES (1, '192.168.1.10', 'source', 'camera',
                   '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 1)"""
    )
    await db.commit()

    profile = ServiceProfile(
        device_id=1,
        ip_address="192.168.1.10",
        port=8080,
        http_status=200,
        http_headers={"server": "camera"},
        scouted_at="2026-01-01T00:00:00Z",
    )
    engine = SimpleNamespace(
        get_mimic_candidates=AsyncMock(return_value=[profile]),
        get_profiles_for_device=AsyncMock(return_value=[profile]),
    )
    template = MimicTemplate(
        source_device_id=1,
        source_ip="192.168.1.10",
        device_category="camera",
        routes=[{
            "path": "/",
            "method": "GET",
            "port": 8080,
            "status": 200,
            "headers": {},
            "body": "camera",
        }],
        credential_types=[],
        mdns_service_type="_http._tcp",
        ports=[8080],
    )
    template_generator = SimpleNamespace(generate=lambda *_: template)
    allocator = SimpleNamespace(mark_allocated=lambda _: None)
    ip_manager = SimpleNamespace(
        is_available=AsyncMock(return_value=True),
        find_conflicts=AsyncMock(return_value={}),
        snapshot_real_ip_owners=AsyncMock(
            return_value=[("192.168.1.1", "00:11:22:33:44:55")],
        ),
        allocate_verified=AsyncMock(return_value=["192.168.1.200"]),
        verify_batch_ownership=AsyncMock(return_value={}),
        is_verified_free=AsyncMock(return_value=True),
        add_alias=AsyncMock(return_value=True),
        remove_alias=AsyncMock(return_value=True),
        release_reservation=lambda _: None,
        mark_possibly_active=lambda ip: ip_manager.active_ips.add(ip),
        active_ips=set(),
        _allocator=allocator,
    )
    port_forward = SimpleNamespace(
        add_forwards=AsyncMock(return_value=True),
        quarantine_endpoints=AsyncMock(return_value=True),
        remove_forwards=AsyncMock(return_value=True),
        clear_all=AsyncMock(return_value=True),
    )
    mdns = SimpleNamespace(
        register=AsyncMock(return_value=True),
        unregister=AsyncMock(),
    )
    event_bus = SimpleNamespace(publish=AsyncMock(return_value=1))

    monkeypatch.setattr(
        "squirrelops_home_sensor.scouts.orchestrator.MimicDecoy",
        FakeMimic,
    )
    orchestrator = MimicOrchestrator(
        scout_engine=engine,
        template_generator=template_generator,
        ip_manager=ip_manager,
        event_bus=event_bus,
        db=db,
        max_mimics=1,
        mdns_advertiser=mdns,
        port_forward_manager=port_forward,
    )
    return SimpleNamespace(
        orchestrator=orchestrator,
        engine=engine,
        ip_manager=ip_manager,
        port_forward=port_forward,
        mdns=mdns,
    )


async def _insert_persisted_mimic(
    db,
    *,
    bind_address: str,
    status: str,
    with_virtual_ip: bool,
) -> tuple[int, int, int]:
    now = "2026-01-01T00:00:00Z"
    template_cursor = await db.execute(
        """INSERT INTO mimic_templates
           (source_device_id, source_ip, device_category, routes_json,
            server_header, credential_types_json, mdns_service_type,
            mdns_name, created_at, updated_at)
           VALUES (1, '192.168.1.10', 'camera', '[]', 'camera', '[]',
                   '_http._tcp', 'camera', ?, ?)""",
        (now, now),
    )
    template_id = template_cursor.lastrowid
    assert template_id is not None
    decoy_cursor = await db.execute(
        """INSERT INTO decoys
           (name, decoy_type, bind_address, port, status, config,
            created_at, updated_at)
           VALUES (?, 'mimic', ?, 8080, ?, ?, ?, ?)""",
        (
            f"camera-{template_id}.local",
            bind_address,
            status,
            f'{{"template_id": {template_id}}}',
            now,
            now,
        ),
    )
    decoy_id = decoy_cursor.lastrowid
    assert decoy_id is not None
    credential_cursor = await db.execute(
        """INSERT INTO planted_credentials
           (credential_type, credential_value, planted_location, decoy_id, created_at)
           VALUES ('password', 'cleanup-me', '/share/passwords.txt', ?, ?)""",
        (decoy_id, now),
    )
    credential_id = credential_cursor.lastrowid
    assert credential_id is not None
    if with_virtual_ip:
        await db.execute(
            """INSERT INTO virtual_ips
               (ip_address, interface, decoy_id, created_at)
               VALUES (?, 'en0', ?, ?)""",
            (bind_address, decoy_id, now),
        )
    await db.commit()
    return decoy_id, template_id, credential_id


async def _configure_distinct_sources(
    mimic_setup,
    db,
    count: int,
) -> list[ServiceProfile]:
    profiles = [
        ServiceProfile(
            device_id=device_id,
            ip_address=f"192.168.1.{9 + device_id}",
            port=8080,
            http_status=200,
            http_headers={"server": f"source-{device_id}"},
            scouted_at="2026-01-01T00:00:00Z",
        )
        for device_id in range(1, count + 1)
    ]
    for device_id in range(2, count + 1):
        await db.execute(
            """INSERT INTO devices
               (id, ip_address, hostname, device_type, first_seen, last_seen,
                is_online)
               VALUES (?, ?, ?, 'camera', '2026-01-01T00:00:00Z',
                       '2026-01-01T00:00:00Z', 1)""",
            (
                device_id,
                f"192.168.1.{9 + device_id}",
                f"source-{device_id}",
            ),
        )
    await db.commit()
    by_device = {
        profile.device_id: [profile]
        for profile in profiles
    }
    mimic_setup.engine.get_mimic_candidates.return_value = profiles
    mimic_setup.engine.get_profiles_for_device.side_effect = (
        lambda device_id: by_device.get(device_id, [])
    )
    return profiles


@pytest.mark.asyncio
async def test_full_profile_capacity_never_repeats_source_hosts(
    mimic_setup,
    db,
):
    await _configure_distinct_sources(mimic_setup, db, 2)
    mimic_setup.ip_manager.allocate_verified.side_effect = [
        ["192.168.1.200"],
        ["192.168.1.201"],
    ]
    mimic_setup.orchestrator.set_max_mimics(2)

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 2
    mimic_setup.orchestrator.set_max_mimics(30)
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 0
    assert mimic_setup.orchestrator.active_count == 2
    assert mimic_setup.ip_manager.add_alias.await_count == 2
    assert mimic_setup.port_forward.quarantine_endpoints.await_count == 2
    assert mimic_setup.port_forward.add_forwards.await_count == 2

    rows = list(await (
        await db.execute(
            """SELECT d.bind_address,
                      d.port,
                      json_extract(d.config, '$.mdns_hostname') AS mdns_hostname,
                      mt.source_device_id
               FROM decoys d
               JOIN mimic_templates mt
                 ON mt.id = CAST(
                     json_extract(d.config, '$.template_id') AS INTEGER
                 )
               WHERE d.status = 'active' AND d.decoy_type = 'mimic'
               ORDER BY d.id"""
        )
    ).fetchall())
    assert len(rows) == 2
    assert len({row["bind_address"] for row in rows}) == 2
    assert len({row["mdns_hostname"] for row in rows}) == 2
    assert len({(row["bind_address"], row["port"]) for row in rows}) == 2
    assert {row["source_device_id"] for row in rows} == {1, 2}


@pytest.mark.asyncio
async def test_full_capacity_uses_one_verified_owner_snapshot(mimic_setup, db):
    await _configure_distinct_sources(mimic_setup, db, 3)
    owner_snapshot = [
        ("192.168.1.1", "00:11:22:33:44:55"),
        ("192.168.1.202", "38:42:0b:48:51:07"),
    ]
    mimic_setup.ip_manager.snapshot_real_ip_owners.return_value = owner_snapshot
    mimic_setup.ip_manager.allocate_verified.side_effect = [
        ["192.168.1.203"],
        ["192.168.1.204"],
        ["192.168.1.205"],
    ]
    mimic_setup.orchestrator.set_max_mimics(3)

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 3

    mimic_setup.ip_manager.snapshot_real_ip_owners.assert_awaited_once_with()
    assert mimic_setup.ip_manager.allocate_verified.await_args_list == [
        call(1, owner_snapshot),
        call(1, owner_snapshot),
        call(1, owner_snapshot),
    ]
    mimic_setup.ip_manager.verify_batch_ownership.assert_awaited_once_with(
        {"192.168.1.203", "192.168.1.204", "192.168.1.205"}
    )


@pytest.mark.asyncio
async def test_batch_verification_evicts_claimant_that_arrives_after_snapshot(
    mimic_setup,
    db,
):
    await _configure_distinct_sources(mimic_setup, db, 3)
    mimic_setup.ip_manager.allocate_verified.side_effect = [
        ["192.168.1.200"],
        ["192.168.1.201"],
        ["192.168.1.202"],
    ]
    mimic_setup.ip_manager.verify_batch_ownership.return_value = {
        "192.168.1.201": "38:42:0b:48:51:07",
    }
    mimic_setup.orchestrator.set_max_mimics(3)

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 2

    mimic_setup.ip_manager.snapshot_real_ip_owners.assert_awaited_once_with()
    mimic_setup.ip_manager.verify_batch_ownership.assert_awaited_once_with(
        {"192.168.1.200", "192.168.1.201", "192.168.1.202"}
    )
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.201")
    rows = list(await (
        await db.execute(
            """SELECT bind_address
               FROM decoys
               WHERE status = 'active' AND decoy_type = 'mimic'
               ORDER BY bind_address"""
        )
    ).fetchall())
    assert [row["bind_address"] for row in rows] == [
        "192.168.1.200",
        "192.168.1.202",
    ]


@pytest.mark.asyncio
async def test_batch_verification_error_evicts_every_new_alias(
    mimic_setup,
    db,
):
    await _configure_distinct_sources(mimic_setup, db, 2)
    mimic_setup.ip_manager.allocate_verified.side_effect = [
        ["192.168.1.200"],
        ["192.168.1.201"],
    ]
    mimic_setup.ip_manager.verify_batch_ownership.side_effect = RuntimeError(
        "ownership probe unavailable"
    )
    mimic_setup.orchestrator.set_max_mimics(2)

    with pytest.raises(
        MimicDeploymentError,
        match="post-deployment ownership verification failed",
    ):
        await mimic_setup.orchestrator.evaluate_and_deploy()

    assert {
        call.args[0]
        for call in mimic_setup.ip_manager.remove_alias.await_args_list
    } == {"192.168.1.200", "192.168.1.201"}
    row = await (await db.execute(
        """SELECT COUNT(*) AS count
           FROM decoys
           WHERE status = 'active' AND decoy_type = 'mimic'"""
    )).fetchone()
    assert row["count"] == 0


@pytest.mark.asyncio
async def test_batch_conflict_cleanup_attempts_every_withdrawn_mimic(
    mimic_setup,
    db,
):
    await _configure_distinct_sources(mimic_setup, db, 3)
    ips = ["192.168.1.200", "192.168.1.201", "192.168.1.202"]
    mimic_setup.ip_manager.allocate_verified.side_effect = [
        [ip] for ip in ips
    ]
    mimic_setup.ip_manager.verify_batch_ownership.return_value = {
        ip: "ownership-probe-failed" for ip in ips
    }
    # Three successful deployment quarantines, then the first teardown cannot
    # confirm quarantine while the remaining two can still be cleaned.
    mimic_setup.port_forward.quarantine_endpoints.side_effect = [
        True,
        True,
        True,
        False,
        True,
        True,
    ]
    mimic_setup.orchestrator.set_max_mimics(3)

    with pytest.raises(
        MimicCleanupError,
        match="cleanup is incomplete for 192.168.1.200",
    ):
        await mimic_setup.orchestrator.evaluate_and_deploy()

    assert {
        call.args[0]
        for call in mimic_setup.ip_manager.remove_alias.await_args_list
    } == {"192.168.1.201", "192.168.1.202"}
    assert mimic_setup.port_forward.remove_forwards.await_count == 2
    assert set(mimic_setup.orchestrator._active_mimics) == {1}
    assert mimic_setup.orchestrator._network_ready is False

    rows = list(await (
        await db.execute(
            """SELECT id, bind_address, status, retired_at
               FROM decoys
               WHERE decoy_type = 'mimic'
               ORDER BY id"""
        )
    ).fetchall())
    assert [
        (
            row["id"],
            row["bind_address"],
            row["status"],
            row["retired_at"] is not None,
        )
        for row in rows
    ] == [
        (1, "192.168.1.200", "active", False),
        (2, "192.168.1.201", "stopped", True),
        (3, "192.168.1.202", "stopped", True),
    ]

    degraded_ips = {
        publish.args[1]["bind_address"]
        for publish in mimic_setup.orchestrator._event_bus.publish.await_args_list
        if publish.args[0] == "decoy.status_changed"
        and publish.args[1].get("status") == "degraded"
    }
    assert degraded_ips == set(ips)


@pytest.mark.asyncio
async def test_non_privileged_mimic_still_requires_host_isolation(mimic_setup):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1

    mimic_setup.port_forward.add_forwards.assert_awaited_once_with(
        1,
        "192.168.1.200",
        {8080: 50000},
        exposed_ports={8080},
    )


def test_port_configs_consolidate_duplicate_protocol_rows(mimic_setup):
    profile = mimic_setup.engine.get_mimic_candidates.return_value[0]
    duplicate_protocol = ServiceProfile(
        device_id=profile.device_id,
        ip_address=profile.ip_address,
        port=profile.port,
        protocol="udp",
        protocol_version="duplicate",
        scouted_at=profile.scouted_at,
    )
    template = mimic_setup.orchestrator._template_gen.generate([], "", "")

    configs = mimic_setup.orchestrator._build_port_configs(
        [profile, duplicate_protocol],
        template,
    )

    assert len(configs) == 1
    assert configs[0]["port"] == 8080


@pytest.mark.asyncio
async def test_isolation_failure_rolls_back_persisted_deployment(
    mimic_setup, db,
):
    mimic_setup.port_forward.add_forwards.return_value = False

    with pytest.raises(MimicDeploymentError):
        await mimic_setup.orchestrator.evaluate_and_deploy()
    retired = await (
        await db.execute("SELECT retired_at FROM decoys")
    ).fetchone()
    assert retired["retired_at"] is not None
    assert (
        await (await db.execute("SELECT COUNT(*) FROM mimic_templates")).fetchone()
    )[0] == 1
    mimic_setup.ip_manager.add_alias.assert_awaited_once_with("192.168.1.200")
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.200")


@pytest.mark.asyncio
async def test_failed_alias_verification_retains_quarantine_until_cleanup(
    mimic_setup,
    db,
):
    """An indeterminate helper rollback must never be followed by a PF flush."""
    mimic_setup.ip_manager.add_alias.return_value = False
    mimic_setup.ip_manager.remove_alias.return_value = False
    profile = mimic_setup.engine.get_mimic_candidates.return_value[0]

    with pytest.raises(MimicCleanupError, match="cleanup is incomplete"):
        await mimic_setup.orchestrator._deploy_mimic_for_device(
            1,
            [profile],
            arp_results=[],
        )

    assert mimic_setup.port_forward.quarantine_endpoints.await_count == 2
    assert (
        mimic_setup.port_forward.quarantine_endpoints.await_args_list
        == [call({1: "192.168.1.200"}), call({1: "192.168.1.200"})]
    )
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.200")
    mimic_setup.port_forward.remove_forwards.assert_not_awaited()
    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["status"] == "stopped"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_stage",
    ["quarantine", "alias", "advertise"],
)
async def test_incomplete_provisioning_rollback_raises_cleanup_error(
    mimic_setup,
    monkeypatch,
    failure_stage,
):
    rollback = AsyncMock(return_value=False)
    monkeypatch.setattr(
        mimic_setup.orchestrator,
        "_rollback_new_mimic",
        rollback,
    )
    if failure_stage == "quarantine":
        mimic_setup.port_forward.quarantine_endpoints.return_value = False
    elif failure_stage == "alias":
        mimic_setup.ip_manager.add_alias.return_value = False
    else:
        mimic_setup.port_forward.add_forwards.return_value = False

    profile = mimic_setup.engine.get_mimic_candidates.return_value[0]
    with pytest.raises(MimicCleanupError, match="cleanup is incomplete"):
        await mimic_setup.orchestrator._deploy_mimic_for_device(
            1,
            [profile],
            arp_results=[],
        )

    rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_evaluate_aborts_after_first_incomplete_rollback(
    mimic_setup,
    monkeypatch,
):
    deploy = AsyncMock(
        side_effect=MimicCleanupError(
            "Mimic 1 provisioning cleanup is incomplete"
        )
    )
    monkeypatch.setattr(
        mimic_setup.orchestrator,
        "_deploy_mimic_for_device",
        deploy,
    )
    mimic_setup.orchestrator.set_max_mimics(3)

    with pytest.raises(MimicCleanupError, match="cleanup is incomplete"):
        await mimic_setup.orchestrator.evaluate_and_deploy()

    deploy.assert_awaited_once()


@pytest.mark.asyncio
async def test_deploy_quarantines_before_alias_and_advertises_after_listener(
    mimic_setup,
    monkeypatch,
):
    calls: list[str] = []

    async def quarantine(_endpoints):
        calls.append("quarantine")
        return True

    original_start = FakeMimic.start

    async def start(mimic):
        calls.append("listener")
        await original_start(mimic)

    async def add_forwards(*_args, **_kwargs):
        calls.append("advertise")
        return True

    async def add_alias(_ip):
        calls.append("alias")
        return True

    monkeypatch.setattr(FakeMimic, "start", start)
    mimic_setup.port_forward.quarantine_endpoints.side_effect = quarantine
    mimic_setup.port_forward.add_forwards.side_effect = add_forwards
    mimic_setup.ip_manager.add_alias.side_effect = add_alias

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    assert calls == ["quarantine", "alias", "listener", "advertise"]


@pytest.mark.asyncio
async def test_concurrent_deploy_triggers_create_only_one_mimic(
    mimic_setup, db,
):
    mimic_setup.orchestrator.set_max_mimics(1)

    async def slow_add_forwards(*_args, **_kwargs):
        await asyncio.sleep(0.02)
        return True

    mimic_setup.port_forward.add_forwards.side_effect = slow_add_forwards

    results = await asyncio.gather(
        mimic_setup.orchestrator.evaluate_and_deploy(),
        mimic_setup.orchestrator.evaluate_and_deploy(),
    )

    assert sorted(results) == [0, 1]
    assert mimic_setup.orchestrator.active_count == 1
    assert (await (await db.execute("SELECT COUNT(*) FROM decoys")).fetchone())[0] == 1


@pytest.mark.asyncio
async def test_durable_host_identity_is_not_regenerated_from_stale_row_config(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await db.execute(
        """UPDATE decoys
           SET name = 'camera.local',
               config = '{"template_id": 1, "mdns_hostname": "camera"}'
           WHERE id = 1"""
    )
    await db.commit()
    template_row = await (
        await db.execute("SELECT * FROM mimic_templates WHERE id = 1")
    ).fetchone()

    name, hostname = await mimic_setup.orchestrator._normalize_mimic_identity(
        decoy_id=1,
        current_name="camera.local",
        config={"template_id": 1, "mdns_hostname": "camera"},
        template_row=template_row,
        bind_address="192.168.1.200",
    )

    assert hostname == "source-a6d6"
    assert name == "source-a6d6.local"
    row = await (
        await db.execute("SELECT name, config FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["name"] == "source-a6d6.local"
    assert '"mdns_hostname": "source-a6d6"' in row["config"]


@pytest.mark.asyncio
async def test_alias_removal_failure_retains_pf_and_durable_state(
    mimic_setup, db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.remove_alias.return_value = False
    mimic_setup.port_forward.remove_forwards.reset_mock()

    assert await mimic_setup.orchestrator.disable_mimic(1) is False

    mimic_setup.port_forward.remove_forwards.assert_not_awaited()
    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["status"] == "stopped"
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
async def test_alias_removal_exception_retains_pf_and_marks_stopped(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.remove_alias.side_effect = RuntimeError(
        "helper disconnected"
    )
    mimic_setup.port_forward.remove_forwards.reset_mock()

    assert await mimic_setup.orchestrator.disable_mimic(1) is False

    mimic_setup.port_forward.remove_forwards.assert_not_awaited()
    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["status"] == "stopped"
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
async def test_remove_reports_retryable_cleanup_failure(mimic_setup, db):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.remove_alias.return_value = False

    with pytest.raises(MimicCleanupError, match="PF isolation"):
        await mimic_setup.orchestrator.remove_mimic(1)

    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["status"] == "stopped"
    mimic_setup.port_forward.remove_forwards.assert_not_awaited()


@pytest.mark.asyncio
async def test_profile_reconfigure_restores_limit_but_keeps_unknown_alias_stopped(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    old_limit = mimic_setup.orchestrator.max_mimics
    mimic_setup.ip_manager.remove_alias.return_value = False

    with pytest.raises(RuntimeError, match="Could not safely apply mimic limit"):
        await mimic_setup.orchestrator.reconfigure(0)

    assert mimic_setup.orchestrator.max_mimics == old_limit
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
async def test_successful_removal_drops_alias_before_pf(mimic_setup):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    calls: list[str] = []

    async def quarantine(_endpoints):
        calls.append("quarantine")
        return True

    async def remove_alias(_ip):
        calls.append("alias")
        return True

    async def remove_forwards(_decoy_id):
        calls.append("pf")
        return True

    mimic_setup.port_forward.quarantine_endpoints.side_effect = quarantine
    mimic_setup.ip_manager.remove_alias.side_effect = remove_alias
    mimic_setup.port_forward.remove_forwards.side_effect = remove_forwards

    assert await mimic_setup.orchestrator.remove_mimic(1) is True
    assert calls == ["quarantine", "alias", "pf"]


@pytest.mark.asyncio
async def test_failed_teardown_quarantine_keeps_listener_and_alias_live(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    active = mimic_setup.orchestrator._active_mimics[1]
    mimic_setup.port_forward.quarantine_endpoints.return_value = False
    mimic_setup.ip_manager.remove_alias.reset_mock()
    mimic_setup.port_forward.remove_forwards.reset_mock()

    assert await mimic_setup.orchestrator.disable_mimic(1) is False

    assert active.started is True
    assert mimic_setup.orchestrator.active_count == 1
    mimic_setup.ip_manager.remove_alias.assert_not_awaited()
    mimic_setup.port_forward.remove_forwards.assert_not_awaited()
    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["status"] == "active"


@pytest.mark.asyncio
async def test_graceful_stop_preserves_mimic_for_next_start(mimic_setup, db):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.port_forward.quarantine_endpoints.reset_mock()

    await mimic_setup.orchestrator.stop_all()

    mimic_setup.port_forward.quarantine_endpoints.assert_awaited_once_with(
        {1: "192.168.1.200"}
    )
    row = await (await db.execute("SELECT status FROM decoys WHERE id = 1")).fetchone()
    assert row["status"] == "active"
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
async def test_graceful_stop_keeps_listeners_when_quarantine_fails(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    active = mimic_setup.orchestrator._active_mimics[1]
    mimic_setup.port_forward.quarantine_endpoints.return_value = False

    with pytest.raises(HelperUnavailableError, match="before listener shutdown"):
        await mimic_setup.orchestrator.stop_all()

    assert active.started is True
    assert mimic_setup.orchestrator.active_count == 1
    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = 1")
    ).fetchone()
    assert row["status"] == "active"


@pytest.mark.asyncio
async def test_resume_uses_durable_ports_after_source_profiles_disappear(
    mimic_setup,
    db,
):
    http_profile = mimic_setup.engine.get_mimic_candidates.return_value[0]
    ssh_profile = ServiceProfile(
        device_id=1,
        ip_address="192.168.1.10",
        port=22,
        protocol_version="SSH-2.0-OpenSSH_9.9",
        scouted_at="2026-01-01T00:00:00Z",
    )
    mimic_setup.engine.get_mimic_candidates.return_value = [
        ssh_profile,
        http_profile,
    ]
    mimic_setup.engine.get_profiles_for_device.return_value = []

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    persisted = await (
        await db.execute(
            """SELECT config FROM decoys
               WHERE host_id = (SELECT host_id FROM decoys WHERE id = 1)
                 AND retired_at IS NULL"""
        )
    ).fetchall()
    assert {
        config["port"]
        for row in persisted
        for config in json.loads(row["config"])["port_configs"]
    } == {22, 8080}

    await mimic_setup.orchestrator.stop_all()
    mimic_setup.engine.get_profiles_for_device.reset_mock()

    assert await mimic_setup.orchestrator.resume_active() == 1
    mimic_setup.engine.get_profiles_for_device.assert_not_awaited()
    active = mimic_setup.orchestrator._active_mimics[1]
    assert {config["port"] for config in active.port_configs} == {22, 8080}


@pytest.mark.asyncio
async def test_rescout_reconciles_services_without_replacing_host_identity(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    original = await (
        await db.execute(
            """SELECT d.id, d.host_id, d.name, d.bind_address, dh.hostname
               FROM decoys d
               JOIN decoy_hosts dh ON dh.id = d.host_id
               WHERE d.is_primary = 1"""
        )
    ).fetchone()
    await db.execute(
        """INSERT INTO virtual_ips
           (ip_address, interface, decoy_id, created_at)
           VALUES (?, 'en0', ?, '2026-01-01T00:00:00Z')""",
        (original["bind_address"], original["id"]),
    )
    await db.execute(
        """INSERT INTO decoy_connections
           (decoy_id, source_ip, port, timestamp)
           VALUES (?, '192.168.1.50', 8080, '2026-01-01T00:00:00Z')""",
        (original["id"],),
    )
    await db.execute(
        """INSERT INTO home_alerts
           (alert_type, severity, title, detail, decoy_id, created_at)
           VALUES ('decoy_trip', 'high', 'Original service hit', '{}', ?,
                   '2026-01-01T00:00:00Z')""",
        (original["id"],),
    )
    await db.commit()

    tls_profile = ServiceProfile(
        device_id=1,
        ip_address="192.168.1.10",
        port=443,
        service_name="https",
        http_status=200,
        http_body_snippet="fresh camera",
        tls_cn="real-camera.local",
        scouted_at="2026-01-02T00:00:00Z",
    )
    ssh_profile = ServiceProfile(
        device_id=1,
        ip_address="192.168.1.10",
        port=22,
        service_name="ssh",
        protocol_version="SSH-2.0-OpenSSH_9.9",
        scouted_at="2026-01-02T00:00:00Z",
    )
    mimic_setup.engine.get_profiles_for_device.return_value = [
        tls_profile,
        ssh_profile,
    ]

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 0

    rows = list(await (
        await db.execute(
            """SELECT id, host_id, name, bind_address, port, status, is_primary,
                      retired_at, retirement_reason
               FROM decoys
               WHERE host_id = ?
               ORDER BY id""",
            (original["host_id"],),
        )
    ).fetchall())
    assert len(rows) == 3
    old = next(row for row in rows if row["id"] == original["id"])
    assert old["port"] == 8080
    assert old["status"] == "stopped"
    assert old["is_primary"] == 0
    assert old["retired_at"] is not None
    assert old["retirement_reason"] == "source_service_removed"

    current = [row for row in rows if row["retired_at"] is None]
    assert {row["port"] for row in current} == {22, 443}
    assert all(row["host_id"] == original["host_id"] for row in current)
    assert all(row["name"] == original["name"] for row in current)
    assert all(
        row["bind_address"] == original["bind_address"]
        for row in current
    )
    promoted = next(row for row in current if row["is_primary"] == 1)
    assert promoted["port"] == 443
    assert set(mimic_setup.orchestrator._active_mimics) == {promoted["id"]}
    active = mimic_setup.orchestrator._active_mimics[promoted["id"]]
    assert {config["port"] for config in active.port_configs} == {22, 443}

    host = await (
        await db.execute(
            """SELECT hostname, tls_cert_pem, tls_key_pem
               FROM decoy_hosts WHERE id = ?""",
            (original["host_id"],),
        )
    ).fetchone()
    assert host["hostname"] == original["hostname"]
    assert host["tls_cert_pem"]
    assert host["tls_key_pem"]
    vip = await (
        await db.execute(
            "SELECT decoy_id FROM virtual_ips WHERE ip_address = ?",
            (original["bind_address"],),
        )
    ).fetchone()
    assert vip["decoy_id"] == promoted["id"]

    connection = await (
        await db.execute(
            "SELECT decoy_id FROM decoy_connections"
        )
    ).fetchone()
    alert = await (
        await db.execute("SELECT decoy_id FROM home_alerts")
    ).fetchone()
    assert connection["decoy_id"] == original["id"]
    assert alert["decoy_id"] == original["id"]

    await mimic_setup.orchestrator.stop_all()
    assert await mimic_setup.orchestrator.resume_active() == 1
    resumed = mimic_setup.orchestrator._active_mimics[promoted["id"]]
    assert {config["port"] for config in resumed.port_configs} == {22, 443}


@pytest.mark.asyncio
async def test_resume_backfills_legacy_ports_from_primary_port_and_routes(
    mimic_setup,
    db,
):
    http_profile = mimic_setup.engine.get_mimic_candidates.return_value[0]
    ssh_profile = ServiceProfile(
        device_id=1,
        ip_address="192.168.1.10",
        port=22,
        protocol_version="SSH-2.0-OpenSSH_9.9",
        scouted_at="2026-01-01T00:00:00Z",
    )
    mimic_setup.engine.get_mimic_candidates.return_value = [
        ssh_profile,
        http_profile,
    ]

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    await db.execute(
        """UPDATE decoys
           SET config = json_remove(config, '$.port_configs')
           WHERE id = 1"""
    )
    await db.commit()
    mimic_setup.engine.get_profiles_for_device.return_value = []
    mimic_setup.engine.get_profiles_for_device.reset_mock()

    assert await mimic_setup.orchestrator.resume_active() == 1
    mimic_setup.engine.get_profiles_for_device.assert_not_awaited()
    active = mimic_setup.orchestrator._active_mimics[1]
    assert {config["port"] for config in active.port_configs} == {22, 8080}
    persisted = await (
        await db.execute(
            """SELECT config FROM decoys
               WHERE host_id = (SELECT host_id FROM decoys WHERE id = 1)
                 AND retired_at IS NULL"""
        )
    ).fetchall()
    assert {
        config["port"]
        for row in persisted
        for config in json.loads(row["config"])["port_configs"]
    } == {22, 8080}


@pytest.mark.asyncio
async def test_unresumable_mimic_is_retired_before_same_cycle_replacement(
    mimic_setup,
    db,
):
    old_id, old_template_id, old_credential_id = await _insert_persisted_mimic(
        db,
        bind_address="192.168.1.200",
        status="active",
        with_virtual_ip=True,
    )
    await db.execute("UPDATE decoys SET port = 0 WHERE id = ?", (old_id,))
    await db.commit()
    mimic_setup.engine.get_profiles_for_device.return_value = []

    assert await mimic_setup.orchestrator.resume_active() == 0
    retired = await (
        await db.execute(
            "SELECT retired_at FROM decoys WHERE id = ?",
            (old_id,),
        )
    ).fetchone()
    assert retired["retired_at"] is not None
    assert await (
        await db.execute(
            "SELECT id FROM mimic_templates WHERE id = ?",
            (old_template_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM planted_credentials WHERE id = ?",
            (old_credential_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM virtual_ips WHERE ip_address = '192.168.1.200'"
        )
    ).fetchone() is None

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    duplicates = list(await (
        await db.execute(
            """SELECT bind_address, COUNT(*) AS n
               FROM decoys
               WHERE decoy_type = 'mimic' AND retired_at IS NULL
               GROUP BY bind_address
               HAVING COUNT(*) > 1"""
        )
    ).fetchall())
    assert duplicates == []
    rows = list(await (
        await db.execute(
            """SELECT id, bind_address, status
               FROM decoys
               WHERE decoy_type = 'mimic' AND retired_at IS NULL"""
        )
    ).fetchall())
    assert len(rows) == 1
    assert rows[0]["bind_address"] == "192.168.1.200"
    assert rows[0]["status"] == "active"


@pytest.mark.asyncio
async def test_unresumable_cleanup_failure_aborts_before_address_reuse(
    mimic_setup,
    db,
):
    decoy_id, _, _ = await _insert_persisted_mimic(
        db,
        bind_address="192.168.1.200",
        status="active",
        with_virtual_ip=True,
    )
    await db.execute("UPDATE decoys SET port = 0 WHERE id = ?", (decoy_id,))
    await db.commit()
    mimic_setup.engine.get_profiles_for_device.return_value = []
    mimic_setup.port_forward.remove_forwards.return_value = False
    mimic_setup.ip_manager.allocate_verified.reset_mock()

    with pytest.raises(MimicCleanupError, match="unresumable"):
        await mimic_setup.orchestrator.resume_active()

    mimic_setup.ip_manager.allocate_verified.assert_not_awaited()
    row = await (
        await db.execute("SELECT status FROM decoys WHERE id = ?", (decoy_id,))
    ).fetchone()
    assert row["status"] == "stopped"
    with pytest.raises(HelperUnavailableError, match="could not be quarantined"):
        await mimic_setup.orchestrator.evaluate_and_deploy()
    mimic_setup.ip_manager.allocate_verified.assert_not_awaited()


@pytest.mark.asyncio
async def test_resume_quarantines_and_verifies_before_republishing_alias(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    calls: list[str] = []

    async def quarantine(_endpoints):
        calls.append("quarantine")
        return True

    async def remove_alias(_ip):
        calls.append("withdraw")
        return True

    async def verify(_ip, _arp_results=None):
        calls.append("verify")
        return True

    async def add_forwards(*_args, **_kwargs):
        calls.append("advertise")
        return True

    async def add_alias(_ip):
        calls.append("add-alias")
        return True

    mimic_setup.port_forward.quarantine_endpoints.side_effect = quarantine
    mimic_setup.ip_manager.remove_alias.side_effect = remove_alias
    mimic_setup.ip_manager.is_verified_free.side_effect = verify
    mimic_setup.port_forward.add_forwards.side_effect = add_forwards
    mimic_setup.ip_manager.add_alias.side_effect = add_alias

    assert await mimic_setup.orchestrator.resume_active() == 1
    assert calls == [
        "quarantine",
        "withdraw",
        "verify",
        "add-alias",
        "advertise",
    ]


@pytest.mark.asyncio
async def test_startup_removes_stale_active_alias_under_quarantine_then_resumes(
    mimic_setup, db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    await db.execute(
        """INSERT INTO virtual_ips
           (ip_address, interface, decoy_id, created_at)
           VALUES ('192.168.1.200', 'en0', 1, '2026-01-01T00:00:00Z')"""
    )
    await db.commit()
    calls: list[str] = []

    async def quarantine(_endpoints):
        calls.append("quarantine")
        return True

    async def remove_alias(_ip):
        calls.append("remove-alias")
        return True

    async def add_forwards(*_args, **_kwargs):
        calls.append("pf")
        return True

    async def verify(_ip, _arp_results=None):
        calls.append("verify")
        return True

    async def add_alias(_ip):
        calls.append("add-alias")
        return True

    mimic_setup.port_forward.quarantine_endpoints.side_effect = quarantine
    mimic_setup.ip_manager.remove_alias.side_effect = remove_alias
    mimic_setup.ip_manager.is_verified_free.side_effect = verify
    mimic_setup.port_forward.add_forwards.side_effect = add_forwards
    mimic_setup.ip_manager.add_alias.side_effect = add_alias
    mimic_setup.port_forward.remove_forwards.reset_mock()

    assert await mimic_setup.orchestrator.prepare_persisted_network() == 0
    mimic_setup.port_forward.remove_forwards.assert_not_awaited()
    assert await mimic_setup.orchestrator.resume_active() == 1
    assert calls == [
        "quarantine",
        "remove-alias",
        "verify",
        "add-alias",
        "pf",
    ]


@pytest.mark.asyncio
async def test_full_profile_startup_resume_uses_one_scan_without_requarantine(
    mimic_setup,
    db,
):
    ips = [f"192.168.1.{octet}" for octet in range(200, 229)]
    await _configure_distinct_sources(mimic_setup, db, len(ips))
    mimic_setup.orchestrator.set_max_mimics(len(ips))
    mimic_setup.ip_manager.allocate_verified.side_effect = [[ip] for ip in ips]

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == len(ips)
    await mimic_setup.orchestrator.stop_all()
    assert await mimic_setup.orchestrator.prepare_persisted_network() == 0

    owner_snapshot = [("192.168.1.1", "00:11:22:33:44:55")]
    mimic_setup.ip_manager.snapshot_real_ip_owners.reset_mock()
    mimic_setup.ip_manager.snapshot_real_ip_owners.return_value = owner_snapshot
    mimic_setup.ip_manager.is_verified_free.reset_mock()
    mimic_setup.ip_manager.add_alias.reset_mock()
    mimic_setup.ip_manager.remove_alias.reset_mock()
    mimic_setup.ip_manager.verify_batch_ownership.reset_mock()
    mimic_setup.port_forward.quarantine_endpoints.reset_mock()
    mimic_setup.port_forward.add_forwards.reset_mock()

    assert await mimic_setup.orchestrator.resume_active() == len(ips)

    mimic_setup.ip_manager.snapshot_real_ip_owners.assert_awaited_once_with()
    assert mimic_setup.ip_manager.is_verified_free.await_args_list == [
        call(ip, owner_snapshot) for ip in ips
    ]
    mimic_setup.port_forward.quarantine_endpoints.assert_not_awaited()
    mimic_setup.ip_manager.remove_alias.assert_not_awaited()
    mimic_setup.ip_manager.verify_batch_ownership.assert_awaited_once_with(set(ips))


@pytest.mark.asyncio
async def test_full_profile_startup_registers_mdns_as_one_concurrent_batch(
    mimic_setup,
    db,
):
    ips = [f"192.168.1.{octet}" for octet in range(200, 204)]
    await _configure_distinct_sources(mimic_setup, db, len(ips))
    mimic_setup.orchestrator.set_max_mimics(len(ips))
    mimic_setup.ip_manager.allocate_verified.side_effect = [[ip] for ip in ips]

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == len(ips)
    await mimic_setup.orchestrator.stop_all()
    assert await mimic_setup.orchestrator.prepare_persisted_network() == 0

    started = 0
    all_started = asyncio.Event()
    release = asyncio.Event()

    async def delayed_register(**_kwargs):
        nonlocal started
        started += 1
        if started == len(ips):
            all_started.set()
        await release.wait()
        return True

    mimic_setup.mdns.register.reset_mock()
    mimic_setup.mdns.register.side_effect = delayed_register
    resume_task = asyncio.create_task(mimic_setup.orchestrator.resume_active())

    overlapped = False
    try:
        await asyncio.wait_for(all_started.wait(), timeout=1.0)
        overlapped = True
    except TimeoutError:
        pass
    finally:
        release.set()

    assert await resume_task == len(ips)
    assert overlapped, "mDNS registrations were awaited serially during startup"
    assert mimic_setup.mdns.register.await_count == len(ips)


@pytest.mark.asyncio
async def test_startup_resume_fails_closed_when_owner_snapshot_fails(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    assert await mimic_setup.orchestrator.prepare_persisted_network() == 0

    mimic_setup.ip_manager.snapshot_real_ip_owners.reset_mock()
    mimic_setup.ip_manager.snapshot_real_ip_owners.side_effect = RuntimeError(
        "ARP unavailable"
    )
    mimic_setup.ip_manager.add_alias.reset_mock()
    mimic_setup.port_forward.add_forwards.reset_mock()
    mimic_setup.port_forward.quarantine_endpoints.reset_mock()

    with pytest.raises(HelperUnavailableError, match="ownership snapshot"):
        await mimic_setup.orchestrator.resume_active()

    mimic_setup.ip_manager.snapshot_real_ip_owners.assert_awaited_once_with()
    mimic_setup.ip_manager.add_alias.assert_not_awaited()
    mimic_setup.port_forward.add_forwards.assert_not_awaited()
    mimic_setup.port_forward.quarantine_endpoints.assert_not_awaited()


@pytest.mark.asyncio
async def test_startup_resume_batch_verification_evacuates_late_conflict(
    mimic_setup,
    db,
):
    ips = ["192.168.1.200", "192.168.1.201"]
    await _configure_distinct_sources(mimic_setup, db, len(ips))
    mimic_setup.orchestrator.set_max_mimics(len(ips))
    mimic_setup.ip_manager.allocate_verified.side_effect = [[ip] for ip in ips]

    assert await mimic_setup.orchestrator.evaluate_and_deploy() == len(ips)
    await mimic_setup.orchestrator.stop_all()
    assert await mimic_setup.orchestrator.prepare_persisted_network() == 0

    mimic_setup.ip_manager.snapshot_real_ip_owners.reset_mock()
    mimic_setup.ip_manager.snapshot_real_ip_owners.return_value = []
    mimic_setup.ip_manager.verify_batch_ownership.reset_mock()
    mimic_setup.ip_manager.verify_batch_ownership.return_value = {
        "192.168.1.200": "38:42:0b:48:51:07",
    }

    assert await mimic_setup.orchestrator.resume_active() == 1

    mimic_setup.ip_manager.verify_batch_ownership.assert_awaited_once_with(set(ips))
    assert mimic_setup.orchestrator.active_count == 1
    active = await (
        await db.execute(
            """SELECT bind_address
               FROM decoys
               WHERE decoy_type = 'mimic' AND status = 'active'"""
        )
    ).fetchall()
    assert [row["bind_address"] for row in active] == ["192.168.1.201"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "removal_failure",
    [False, RuntimeError("alias withdrawal failed")],
    ids=["false-result", "exception"],
)
async def test_startup_alias_withdrawal_failure_cannot_resume_persisted_mimic(
    mimic_setup,
    db,
    removal_failure,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    await db.execute(
        """INSERT INTO virtual_ips
           (ip_address, interface, decoy_id, created_at)
           VALUES ('192.168.1.200', 'en0', 1, '2026-01-01T00:00:00Z')"""
    )
    await db.commit()

    # load_from_db(restore_aliases=False) records persisted addresses as
    # possibly active before startup quarantine reconciliation.
    mimic_setup.ip_manager.active_ips.add("192.168.1.200")
    mimic_setup.ip_manager.add_alias.reset_mock()
    mimic_setup.port_forward.add_forwards.reset_mock()
    if isinstance(removal_failure, Exception):
        mimic_setup.ip_manager.remove_alias.side_effect = removal_failure
    else:
        mimic_setup.ip_manager.remove_alias.return_value = removal_failure

    with pytest.raises(RuntimeError, match="alias"):
        await mimic_setup.orchestrator.prepare_persisted_network()

    with pytest.raises(HelperUnavailableError, match="could not be quarantined"):
        await mimic_setup.orchestrator.resume_active()
    mimic_setup.port_forward.add_forwards.assert_not_awaited()
    mimic_setup.ip_manager.add_alias.assert_not_awaited()
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "removal_failure",
    [False, RuntimeError("resume alias state is unknown")],
    ids=["false-result", "exception"],
)
async def test_resume_with_possibly_active_ip_cannot_replace_quarantine(
    mimic_setup,
    removal_failure,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    mimic_setup.ip_manager.active_ips.add("192.168.1.200")

    mimic_setup.ip_manager.remove_alias.reset_mock()
    mimic_setup.ip_manager.remove_alias.side_effect = None
    mimic_setup.ip_manager.remove_alias.return_value = True
    if isinstance(removal_failure, Exception):
        mimic_setup.ip_manager.remove_alias.side_effect = removal_failure
    else:
        mimic_setup.ip_manager.remove_alias.return_value = removal_failure
    mimic_setup.ip_manager.is_verified_free.reset_mock()
    mimic_setup.ip_manager.add_alias.reset_mock()
    mimic_setup.port_forward.quarantine_endpoints.reset_mock()
    mimic_setup.port_forward.add_forwards.reset_mock()

    with pytest.raises(HelperUnavailableError, match="withdraw"):
        await mimic_setup.orchestrator.resume_active()

    mimic_setup.port_forward.quarantine_endpoints.assert_awaited_once_with(
        {1: "192.168.1.200"}
    )
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.200")
    mimic_setup.ip_manager.is_verified_free.assert_not_awaited()
    mimic_setup.port_forward.add_forwards.assert_not_awaited()
    mimic_setup.ip_manager.add_alias.assert_not_awaited()
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
async def test_startup_quarantines_complete_persisted_set_before_orphan_cleanup(
    mimic_setup, db,
):
    await db.execute(
        """INSERT INTO virtual_ips
           (ip_address, interface, created_at)
           VALUES ('192.168.1.210', 'en0', '2026-01-01T00:00:00Z')"""
    )
    await db.execute(
        """INSERT INTO virtual_ips
           (ip_address, interface, created_at)
           VALUES ('192.168.1.211', 'en0', '2026-01-01T00:00:00Z')"""
    )
    await db.commit()
    calls: list[str] = []

    async def quarantine(endpoints):
        calls.append(f"quarantine:{len(endpoints)}")
        return True

    async def remove_alias(ip):
        calls.append(f"alias:{ip}")
        return True

    async def remove_forwards(_decoy_id):
        calls.append("pf")
        return True

    mimic_setup.port_forward.quarantine_endpoints.side_effect = quarantine
    mimic_setup.ip_manager.remove_alias.side_effect = remove_alias
    mimic_setup.port_forward.remove_forwards.side_effect = remove_forwards

    assert await mimic_setup.orchestrator.prepare_persisted_network() == 2
    assert calls[0] == "quarantine:2"
    assert calls[1:] == [
        "alias:192.168.1.210",
        "pf",
        "alias:192.168.1.211",
        "pf",
    ]


@pytest.mark.asyncio
async def test_startup_preserves_intentionally_stopped_mimic_after_cleanup(
    mimic_setup,
    db,
):
    decoy_id, template_id, credential_id = await _insert_persisted_mimic(
        db,
        bind_address="192.168.1.210",
        status="stopped",
        with_virtual_ip=False,
    )

    assert await mimic_setup.orchestrator.prepare_persisted_network() == 1

    mimic_setup.port_forward.quarantine_endpoints.assert_awaited_once_with(
        {decoy_id: "192.168.1.210"}
    )
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.210")
    mimic_setup.port_forward.remove_forwards.assert_awaited_once_with(decoy_id)
    stopped = await (
        await db.execute(
            "SELECT retired_at FROM decoys WHERE id = ?",
            (decoy_id,),
        )
    ).fetchone()
    assert stopped is not None
    assert stopped["retired_at"] is None
    assert await (
        await db.execute(
            "SELECT id FROM mimic_templates WHERE id = ?",
            (template_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM planted_credentials WHERE id = ?",
            (credential_id,),
        )
    ).fetchone() is not None


@pytest.mark.asyncio
async def test_startup_retains_stopped_records_until_pf_cleanup_succeeds(
    mimic_setup,
    db,
):
    decoy_id, template_id, credential_id = await _insert_persisted_mimic(
        db,
        bind_address="192.168.1.210",
        status="stopped",
        with_virtual_ip=True,
    )
    mimic_setup.port_forward.remove_forwards.return_value = False

    assert await mimic_setup.orchestrator.prepare_persisted_network() == 0

    assert await (
        await db.execute("SELECT id FROM decoys WHERE id = ?", (decoy_id,))
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM mimic_templates WHERE id = ?",
            (template_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM planted_credentials WHERE id = ?",
            (credential_id,),
        )
    ).fetchone() is not None


@pytest.mark.asyncio
async def test_startup_preserves_stopped_history_without_deleting_active_binding(
    mimic_setup,
    db,
):
    active_id, active_template_id, active_credential_id = (
        await _insert_persisted_mimic(
            db,
            bind_address="192.168.1.210",
            status="active",
            with_virtual_ip=False,
        )
    )
    stopped_id, stopped_template_id, stopped_credential_id = (
        await _insert_persisted_mimic(
            db,
            bind_address="192.168.1.210",
            status="stopped",
            with_virtual_ip=True,
        )
    )

    async def remove_alias(ip):
        await db.execute(
            """UPDATE virtual_ips
               SET released_at = '2026-01-01T00:01:00Z'
               WHERE ip_address = ?""",
            (ip,),
        )
        await db.commit()
        return True

    mimic_setup.ip_manager.remove_alias.side_effect = remove_alias

    assert await mimic_setup.orchestrator.prepare_persisted_network() == 1

    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.210")
    mimic_setup.port_forward.remove_forwards.assert_awaited_once_with(stopped_id)
    active = await (
        await db.execute("SELECT id FROM decoys WHERE id = ?", (active_id,))
    ).fetchone()
    assert active is not None
    assert await (
        await db.execute("SELECT id FROM decoys WHERE id = ?", (stopped_id,))
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM mimic_templates WHERE id = ?",
            (active_template_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM planted_credentials WHERE id = ?",
            (active_credential_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM mimic_templates WHERE id = ?",
            (stopped_template_id,),
        )
    ).fetchone() is not None
    assert await (
        await db.execute(
            "SELECT id FROM planted_credentials WHERE id = ?",
            (stopped_credential_id,),
        )
    ).fetchone() is not None
    virtual_ip = await (
        await db.execute(
            """SELECT decoy_id, released_at
               FROM virtual_ips
               WHERE ip_address = '192.168.1.210'"""
        )
    ).fetchone()
    assert virtual_ip["decoy_id"] == active_id
    assert virtual_ip["released_at"] is not None


@pytest.mark.asyncio
async def test_failed_startup_quarantine_blocks_new_aliases(mimic_setup, db):
    await db.execute(
        """INSERT INTO virtual_ips
           (ip_address, interface, created_at)
           VALUES ('192.168.1.210', 'en0', '2026-01-01T00:00:00Z')"""
    )
    await db.commit()
    mimic_setup.port_forward.quarantine_endpoints.return_value = False

    with pytest.raises(RuntimeError, match="startup quarantine"):
        await mimic_setup.orchestrator.prepare_persisted_network()

    assert mimic_setup.ip_manager.active_ips == {"192.168.1.210"}
    with pytest.raises(HelperUnavailableError, match="could not be quarantined"):
        await mimic_setup.orchestrator.evaluate_and_deploy()
    mimic_setup.ip_manager.add_alias.assert_not_awaited()


@pytest.mark.asyncio
async def test_restart_refuses_persisted_ip_now_owned_by_real_device(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    assert await mimic_setup.orchestrator.disable_mimic(1) is True
    mimic_setup.ip_manager.is_verified_free.return_value = False
    mimic_setup.ip_manager.add_alias.reset_mock()

    assert await mimic_setup.orchestrator.restart_mimic(1) is False
    mimic_setup.ip_manager.add_alias.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "removal_failure",
    [False, RuntimeError("alias removal failed")],
    ids=["false-result", "exception"],
)
async def test_restart_does_not_replace_isolation_when_alias_removal_fails(
    mimic_setup,
    removal_failure,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.add_alias.reset_mock()
    mimic_setup.port_forward.add_forwards.reset_mock()
    if isinstance(removal_failure, Exception):
        mimic_setup.ip_manager.remove_alias.side_effect = removal_failure
        assert await mimic_setup.orchestrator.restart_mimic(1) is False
    else:
        mimic_setup.ip_manager.remove_alias.return_value = removal_failure
        assert await mimic_setup.orchestrator.restart_mimic(1) is False

    mimic_setup.port_forward.add_forwards.assert_not_awaited()
    mimic_setup.ip_manager.add_alias.assert_not_awaited()
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "removal_failure",
    [False, RuntimeError("prior alias state is unknown")],
    ids=["false-result", "exception"],
)
async def test_stopped_restart_with_possibly_active_ip_stays_quarantined(
    mimic_setup,
    removal_failure,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1

    # A failed stop leaves a durable stopped row and marks the address as
    # possibly active. That state must never be mistaken for ownership proof.
    mimic_setup.ip_manager.remove_alias.return_value = False
    assert await mimic_setup.orchestrator.disable_mimic(1) is False
    mimic_setup.ip_manager.active_ips.add("192.168.1.200")

    mimic_setup.ip_manager.remove_alias.reset_mock()
    mimic_setup.ip_manager.remove_alias.side_effect = None
    mimic_setup.ip_manager.remove_alias.return_value = True
    if isinstance(removal_failure, Exception):
        mimic_setup.ip_manager.remove_alias.side_effect = removal_failure
    else:
        mimic_setup.ip_manager.remove_alias.return_value = removal_failure
    mimic_setup.ip_manager.is_verified_free.reset_mock()
    mimic_setup.ip_manager.add_alias.reset_mock()
    mimic_setup.port_forward.quarantine_endpoints.reset_mock()
    mimic_setup.port_forward.add_forwards.reset_mock()

    assert await mimic_setup.orchestrator.restart_mimic(1) is False

    mimic_setup.port_forward.quarantine_endpoints.assert_awaited_once_with(
        {1: "192.168.1.200"}
    )
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.200")
    mimic_setup.ip_manager.is_verified_free.assert_not_awaited()
    mimic_setup.port_forward.add_forwards.assert_not_awaited()
    mimic_setup.ip_manager.add_alias.assert_not_awaited()
    assert mimic_setup.orchestrator.active_count == 0


@pytest.mark.asyncio
async def test_stopped_restart_withdraws_and_verifies_before_republishing(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    assert await mimic_setup.orchestrator.disable_mimic(1) is True
    calls: list[str] = []

    async def quarantine(_endpoints):
        calls.append("quarantine")
        return True

    async def remove_alias(_ip):
        calls.append("withdraw")
        return True

    async def verify(_ip):
        calls.append("verify")
        return True

    async def add_alias(_ip):
        calls.append("add-alias")
        return True

    async def add_forwards(*_args, **_kwargs):
        calls.append("advertise")
        return True

    mimic_setup.port_forward.quarantine_endpoints.side_effect = quarantine
    mimic_setup.ip_manager.remove_alias.side_effect = remove_alias
    mimic_setup.ip_manager.is_verified_free.side_effect = verify
    mimic_setup.ip_manager.add_alias.side_effect = add_alias
    mimic_setup.port_forward.add_forwards.side_effect = add_forwards

    assert await mimic_setup.orchestrator.restart_mimic(1) is True
    assert calls == [
        "quarantine",
        "withdraw",
        "verify",
        "add-alias",
        "advertise",
    ]
    assert mimic_setup.orchestrator.active_count == 1


@pytest.mark.asyncio
async def test_resume_refuses_persisted_ip_now_owned_by_real_device(
    mimic_setup, db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    await mimic_setup.orchestrator.stop_all()
    mimic_setup.ip_manager.is_verified_free.return_value = False

    assert await mimic_setup.orchestrator.resume_active() == 0
    row = await (await db.execute("SELECT status FROM decoys WHERE id = 1")).fetchone()
    assert row["status"] == "stopped"


@pytest.mark.asyncio
async def test_conflict_evacuation_immediately_redeploys_on_new_address(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.find_conflicts.side_effect = [
        {"192.168.1.200": "38:42:0b:48:51:07"},
        {},
    ]
    mimic_setup.ip_manager.allocate_verified.return_value = ["192.168.1.203"]
    raw_arp = [("192.168.1.200", "38:42:0b:48:51:07")]

    assert await mimic_setup.orchestrator.reconcile_ip_conflicts(raw_arp) == 1

    assert mimic_setup.orchestrator.active_count == 1
    active = next(iter(mimic_setup.orchestrator._active_mimics.values()))
    assert active.bind_address == "192.168.1.203"
    mimic_setup.ip_manager.allocate_verified.assert_awaited_with(1, raw_arp)


@pytest.mark.asyncio
async def test_failed_routine_ownership_probe_preserves_active_mimic(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1

    ops = AsyncMock()
    ops.requires_active_alias_withdrawal_probe = True
    ops.arp_scan.side_effect = RuntimeError("helper scan failed")
    ops.remove_ip_alias.return_value = True
    live_ip_manager = VirtualIPManager(
        privileged_ops=ops,
        allocator=IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.2",
        ),
        db=db,
    )
    live_ip_manager._active.add("192.168.1.200")
    live_ip_manager._verified_published.add("192.168.1.200")
    mimic_setup.orchestrator._ip_manager = live_ip_manager
    mimic_setup.port_forward.remove_forwards.reset_mock()

    assert (
        await mimic_setup.orchestrator.reconcile_ip_conflicts(redeploy=False)
        == 0
    )
    assert mimic_setup.orchestrator.active_count == 1
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()
    mimic_setup.port_forward.remove_forwards.assert_not_awaited()


@pytest.mark.asyncio
async def test_unpadded_local_proxy_mac_does_not_evict_active_mimic(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1

    ops = AsyncMock()
    live_ip_manager = VirtualIPManager(
        privileged_ops=ops,
        allocator=IPAllocator(
            subnet="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            sensor_ip="192.168.1.2",
        ),
        db=db,
    )
    live_ip_manager._active.add("192.168.1.200")
    live_ip_manager._verified_published.add("192.168.1.200")
    live_ip_manager._local_interface_macs = lambda: {
        "1c:1d:d3:e0:7d:03",
    }
    mimic_setup.orchestrator._ip_manager = live_ip_manager
    mimic_setup.port_forward.remove_forwards.reset_mock()

    assert (
        await mimic_setup.orchestrator.reconcile_ip_conflicts(
            [
                ("192.168.1.1", "00:11:22:33:44:55"),
                ("192.168.1.200", "1c:1d:d3:e0:7d:3"),
            ],
            redeploy=False,
        )
        == 0
    )
    assert mimic_setup.orchestrator.active_count == 1
    ops.remove_ip_alias.assert_not_awaited()
    ops.add_ip_alias.assert_not_awaited()
    mimic_setup.port_forward.remove_forwards.assert_not_awaited()


@pytest.mark.asyncio
async def test_conflict_reconciliation_cleans_possibly_active_stopped_mimic(
    mimic_setup,
    db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.remove_alias.return_value = False
    assert await mimic_setup.orchestrator.disable_mimic(1) is False

    mimic_setup.ip_manager.remove_alias.reset_mock()
    mimic_setup.ip_manager.remove_alias.return_value = True
    mimic_setup.port_forward.remove_forwards.reset_mock()
    mimic_setup.ip_manager.find_conflicts.return_value = {
        "192.168.1.200": "38:42:0b:48:51:07",
    }

    assert (
        await mimic_setup.orchestrator.reconcile_ip_conflicts(redeploy=False)
        == 1
    )
    mimic_setup.ip_manager.remove_alias.assert_awaited_once_with("192.168.1.200")
    mimic_setup.port_forward.remove_forwards.assert_awaited_once_with(1)
    retired = await (
        await db.execute(
            "SELECT retired_at FROM decoys WHERE id = 1"
        )
    ).fetchone()
    assert retired["retired_at"] is not None


@pytest.mark.asyncio
async def test_conflict_reconciliation_surfaces_stopped_mimic_cleanup_failure(
    mimic_setup,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    mimic_setup.ip_manager.remove_alias.return_value = False
    assert await mimic_setup.orchestrator.disable_mimic(1) is False
    mimic_setup.ip_manager.find_conflicts.return_value = {
        "192.168.1.200": "38:42:0b:48:51:07",
    }

    with pytest.raises(MimicCleanupError, match="cleanup is incomplete"):
        await mimic_setup.orchestrator.reconcile_ip_conflicts(redeploy=False)


@pytest.mark.asyncio
async def test_remove_previously_hit_mimic_with_foreign_keys_enabled(
    mimic_setup, db,
):
    assert await mimic_setup.orchestrator.evaluate_and_deploy() == 1
    credential = await db.execute(
        """INSERT INTO planted_credentials
           (credential_type, credential_value, planted_location, decoy_id, created_at)
           VALUES ('password', 'secret', '/share/passwords.txt', 1,
                   '2026-01-01T00:00:00Z')"""
    )
    credential_id = credential.lastrowid
    await db.execute(
        """INSERT INTO decoy_connections
           (decoy_id, source_ip, port, credential_id, timestamp)
           VALUES (1, '192.168.1.50', 8080, ?, '2026-01-01T00:00:00Z')""",
        (credential_id,),
    )
    await db.execute(
        """INSERT INTO canary_observations
           (credential_id, canary_hostname, queried_by_ip, observed_at)
           VALUES (?, 'token.canary.local', '192.168.1.50',
                   '2026-01-01T00:00:00Z')""",
        (credential_id,),
    )
    await db.execute(
        """INSERT INTO home_alerts
           (alert_type, severity, title, detail, decoy_id, created_at)
           VALUES ('decoy_trip', 'high', 'Hit', '{}', 1,
                   '2026-01-01T00:00:00Z')"""
    )
    await db.commit()

    assert await mimic_setup.orchestrator.remove_mimic(1) is True

    retired = await (
        await db.execute("SELECT retired_at FROM decoys WHERE id = 1")
    ).fetchone()
    assert retired["retired_at"] is not None
    assert (
        await (await db.execute("SELECT COUNT(*) FROM decoy_connections")).fetchone()
    )[0] == 1
    assert (
        await (await db.execute("SELECT COUNT(*) FROM canary_observations")).fetchone()
    )[0] == 1
    alert = await (await db.execute("SELECT decoy_id FROM home_alerts")).fetchone()
    assert alert["decoy_id"] == 1
