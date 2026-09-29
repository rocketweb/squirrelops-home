"""Classic lifecycle operations must never adopt another orchestrator's rows."""

from unittest.mock import AsyncMock, Mock

import pytest

from squirrelops_home_sensor.decoys import orchestrator as classic

CLASSIC_TYPES = ("file_share", "dev_server", "home_assistant")
FOREIGN_TYPES = ("deep", "mimic", "future_guest")


async def _seed(db, decoy_type, status="active", port=445):
    cursor = await db.execute(
        """INSERT INTO decoys
           (name, decoy_type, bind_address, port, status, config,
            connection_count, credential_trip_count, created_at, updated_at)
           VALUES (?, ?, '192.0.2.240', ?, ?, '{}', 7, 2, 'before', 'before')""",
        (decoy_type, decoy_type, port, status),
    )
    await db.commit()
    return cursor.lastrowid


async def _snapshot(db, decoy_type):
    cursor = await db.execute(
        "SELECT * FROM decoys WHERE decoy_type = ? ORDER BY id", (decoy_type,),
    )
    return [dict(row) for row in await cursor.fetchall()]


@pytest.fixture
def manager(db):
    return classic.DecoyOrchestrator(
        event_bus=AsyncMock(), db=db, max_decoys=3, bind_address="192.0.2.115",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_type", FOREIGN_TYPES)
@pytest.mark.parametrize("operation", ["resume", "reconfigure", "recover"])
async def test_bulk_lifecycle_leaves_foreign_rows_untouched(
    db, manager, monkeypatch, foreign_type, operation,
):
    # Five guest services exceed the three-listener profile. Both adoption and
    # excess-row stopping used to corrupt a persisted Studio host on restart.
    for port in (445, 22, 11434, 1234, 8765):
        await _seed(db, foreign_type, "degraded" if operation == "recover" else "active", port)
    before = await _snapshot(db, foreign_type)
    factory = Mock(side_effect=AssertionError("Foreign row reached classic factory"))
    monkeypatch.setattr(classic, "_create_decoy_instance", factory)
    monkeypatch.setattr(manager, "select_decoys", Mock(return_value=[]))

    if operation == "resume":
        assert await manager.resume_active() == 0
    elif operation == "reconfigure":
        assert await manager.reconfigure(1) == []
    else:
        assert await manager.auto_deploy([]) == 0

    assert await _snapshot(db, foreign_type) == before
    factory.assert_not_called()
    manager._event_bus.publish.assert_not_awaited()
    assert manager._records == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_type", FOREIGN_TYPES)
@pytest.mark.parametrize("operation", ["enable_decoy", "disable_decoy", "restart_decoy"])
async def test_individual_lifecycle_declines_foreign_ids(
    db, manager, monkeypatch, foreign_type, operation,
):
    decoy_id = await _seed(db, foreign_type)
    before = await _snapshot(db, foreign_type)
    deploy = AsyncMock()
    monkeypatch.setattr(manager, "deploy_decoy", deploy)
    assert await getattr(manager, operation)(decoy_id) is False
    assert await _snapshot(db, foreign_type) == before
    deploy.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("classic_type", CLASSIC_TYPES)
@pytest.mark.parametrize("operation", ["resume", "enable", "auto_deploy"])
async def test_foreign_hosts_do_not_consume_classic_capacity(
    db, manager, monkeypatch, classic_type, operation,
):
    for foreign_type in FOREIGN_TYPES:
        await _seed(db, foreign_type)
    manager.set_max_decoys(1)
    # Use the real factory but never open sockets. Factory dispatch and persisted
    # status/count selection remain real; deployment is the external boundary.
    deploy = AsyncMock()
    monkeypatch.setattr(manager, "deploy_decoy", deploy)
    if operation == "auto_deploy":
        monkeypatch.setattr(manager, "select_decoys", Mock(return_value=[{"decoy_type": classic_type}]))
        assert await manager.auto_deploy([]) == 1
    else:
        decoy_id = await _seed(db, classic_type, "active" if operation == "resume" else "stopped", 9900)
        if operation == "resume":
            assert await manager.resume_active() == 1
        else:
            assert await manager.enable_decoy(decoy_id) is True
    deploy.assert_awaited_once()
    assert deploy.call_args.args[0].decoy_type == classic_type
    for foreign_type in FOREIGN_TYPES:
        assert (await _snapshot(db, foreign_type))[0]["updated_at"] == "before"


@pytest.mark.asyncio
async def test_profile_shrink_stops_only_excess_classic_rows(db, manager):
    foreign_id = await _seed(db, "deep")
    kept = await _seed(db, "file_share")
    stopped = await _seed(db, "dev_server")
    assert await manager.reconfigure(1) == [stopped]
    rows = await (await db.execute("SELECT id, status FROM decoys ORDER BY id")).fetchall()
    assert [(row["id"], row["status"]) for row in rows] == [
        (foreign_id, "active"), (kept, "active"), (stopped, "stopped"),
    ]


@pytest.mark.parametrize("foreign_type", FOREIGN_TYPES)
def test_factory_rejects_foreign_types_instead_of_falling_back_to_http(foreign_type):
    with pytest.raises(ValueError, match="Unsupported classic decoy type"):
        classic._create_decoy_instance(foreign_type, 1, "QA", 445, "192.0.2.240", [])


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_type", FOREIGN_TYPES)
async def test_creation_rejects_foreign_types_before_persisting_bait(db, manager, foreign_type):
    with pytest.raises(ValueError, match="Unsupported classic decoy type"):
        await manager._create_and_persist(foreign_type)
    assert (await (await db.execute("SELECT COUNT(*) FROM decoys")).fetchone())[0] == 0
    assert (await (await db.execute("SELECT COUNT(*) FROM planted_credentials")).fetchone())[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_type", FOREIGN_TYPES)
async def test_direct_deployment_rejects_foreign_types_before_start(manager, foreign_type):
    decoy = Mock(decoy_type=foreign_type, start=AsyncMock())
    with pytest.raises(ValueError, match="Unsupported classic decoy type"):
        await manager.deploy_decoy(decoy)
    decoy.start.assert_not_awaited()
    assert manager._records == {}
