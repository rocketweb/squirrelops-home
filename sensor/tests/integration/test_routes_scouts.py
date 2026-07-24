"""Integration tests for scout execution and automatic mimic fill."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from tests.integration.conftest import seed_decoys


def _override(app, dependency, value):
    async def provider():
        return value

    app.dependency_overrides[dependency] = provider


def test_run_scout_deploys_new_mimics(client, app):
    from squirrelops_home_sensor.api.routes_scouts import (
        get_mimic_orchestrator,
        get_scout_scheduler,
    )

    scheduler = SimpleNamespace(
        interval_minutes=30,
        run_now=AsyncMock(return_value=7),
        handles_mimic_deployment=False,
        last_mimics_deployed=0,
        last_deployment_error=None,
    )
    orchestrator = SimpleNamespace(evaluate_and_deploy=AsyncMock(return_value=3))
    _override(app, get_scout_scheduler, scheduler)
    _override(app, get_mimic_orchestrator, orchestrator)

    response = client.post("/scouts/run")

    assert response.status_code == 200
    assert response.json() == {
        "profiles_created": 7,
        "mimics_deployed": 3,
        "mimic_deployment_error": None,
    }
    orchestrator.evaluate_and_deploy.assert_awaited_once()


def test_run_scout_uses_scheduler_post_hook_result(client, app):
    from squirrelops_home_sensor.api.routes_scouts import (
        get_mimic_orchestrator,
        get_scout_scheduler,
    )

    scheduler = SimpleNamespace(
        interval_minutes=30,
        run_now=AsyncMock(return_value=4),
        handles_mimic_deployment=True,
        last_mimics_deployed=2,
        last_deployment_error=None,
    )
    orchestrator = SimpleNamespace(evaluate_and_deploy=AsyncMock(return_value=99))
    _override(app, get_scout_scheduler, scheduler)
    _override(app, get_mimic_orchestrator, orchestrator)

    response = client.post("/scouts/run")

    assert response.status_code == 200
    assert response.json()["mimics_deployed"] == 2
    orchestrator.evaluate_and_deploy.assert_not_awaited()


def test_lite_profile_disables_manual_scout(client, app):
    from squirrelops_home_sensor.api.routes_scouts import get_scout_scheduler

    scheduler = SimpleNamespace(interval_minutes=0)
    _override(app, get_scout_scheduler, scheduler)

    response = client.post("/scouts/run")

    assert response.status_code == 503


def test_remove_mimic_reports_preserved_cleanup_state(client, app):
    from squirrelops_home_sensor.api.routes_scouts import get_mimic_orchestrator
    from squirrelops_home_sensor.scouts.orchestrator import MimicCleanupError

    orchestrator = SimpleNamespace(
        remove_mimic=AsyncMock(
            side_effect=MimicCleanupError(
                "Persisted state and PF isolation were retained"
            )
        )
    )
    _override(app, get_mimic_orchestrator, orchestrator)

    response = client.delete("/scouts/mimics/42")

    assert response.status_code == 409
    assert "PF isolation" in response.json()["detail"]


def test_deploy_mimics_reports_preserved_cleanup_state(client, app):
    from squirrelops_home_sensor.api.routes_scouts import get_mimic_orchestrator
    from squirrelops_home_sensor.scouts.orchestrator import MimicCleanupError

    orchestrator = SimpleNamespace(
        evaluate_and_deploy=AsyncMock(
            side_effect=MimicCleanupError(
                "Mimic provisioning cleanup is incomplete"
            )
        )
    )
    _override(app, get_mimic_orchestrator, orchestrator)

    response = client.post("/scouts/mimics/deploy")

    assert response.status_code == 409
    assert "cleanup is incomplete" in response.json()["detail"]


def test_list_mimics_overlays_unpublished_runtime_as_degraded(
    client,
    app,
    db,
):
    from squirrelops_home_sensor.api.routes_scouts import get_mimic_orchestrator

    asyncio.get_event_loop().run_until_complete(seed_decoys(db, count=1))
    cursor = asyncio.get_event_loop().run_until_complete(
        db.execute("SELECT id FROM decoys ORDER BY id LIMIT 1")
    )
    decoy_id = asyncio.get_event_loop().run_until_complete(cursor.fetchone())[0]
    asyncio.get_event_loop().run_until_complete(
        db.execute(
            "UPDATE decoys SET decoy_type = 'mimic' WHERE id = ?",
            (decoy_id,),
        )
    )
    asyncio.get_event_loop().run_until_complete(db.commit())
    orchestrator = SimpleNamespace(
        effective_mimic_status=lambda current_id, persisted: (
            "degraded" if current_id == decoy_id else persisted
        )
    )
    _override(app, get_mimic_orchestrator, orchestrator)

    response = client.get("/scouts/mimics")

    assert response.status_code == 200
    assert response.json()[0]["status"] == "degraded"
