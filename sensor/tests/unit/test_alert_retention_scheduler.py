"""Lifecycle tests for the daily alert-retention scheduler."""

from __future__ import annotations

import asyncio

import pytest

from squirrelops_home_sensor.alerts.retention import (
    AlertRetentionScheduler,
    AlertRetentionService,
)


@pytest.mark.parametrize("retention_days", [0, -1, 3651])
def test_retention_service_rejects_destructive_day_bounds(
    retention_days: int,
    tmp_path,
) -> None:
    with pytest.raises(ValueError, match="between 1 and 3650"):
        AlertRetentionService(
            db=object(),  # type: ignore[arg-type]
            retention_days=retention_days,
        )
    with pytest.raises(ValueError, match="between 1 and 3650"):
        AlertRetentionScheduler(
            db_path=tmp_path / "squirrelops.db",
            retention_days=retention_days,
        )


@pytest.mark.asyncio
async def test_scheduler_runs_immediately_and_retries_after_a_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = AlertRetentionScheduler(
        db_path=tmp_path / "squirrelops.db",
        retention_days=90,
        interval_seconds=0.01,
    )
    calls = 0
    retried = asyncio.Event()

    async def fail_once_then_succeed() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary database contention")
        retried.set()

    monkeypatch.setattr(scheduler, "_purge_once", fail_once_then_succeed)

    await scheduler.start()
    await asyncio.wait_for(retried.wait(), timeout=1)
    await scheduler.stop()

    assert calls >= 2
    assert scheduler.is_running is False


@pytest.mark.asyncio
async def test_scheduler_stop_is_idempotent_before_start(tmp_path) -> None:
    scheduler = AlertRetentionScheduler(
        db_path=tmp_path / "squirrelops.db",
        retention_days=90,
    )

    await scheduler.stop()
    await scheduler.stop()

    assert scheduler.is_running is False
