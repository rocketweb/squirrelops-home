"""Regression tests for task shutdown and daemon credential hygiene."""

from __future__ import annotations

import asyncio
import io
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.mark.asyncio
async def test_scan_wrapper_cancels_task_that_misses_shutdown_deadline(
    monkeypatch,
) -> None:
    import squirrelops_home_sensor.__main__ as entry

    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def stuck_scan() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    wrapper = entry._ScanLoopWrapper(MagicMock())
    task = asyncio.create_task(stuck_scan())
    wrapper._task = task
    monkeypatch.setattr(entry, "SCAN_STOP_TIMEOUT_SECONDS", 0.01)
    await started.wait()

    await wrapper.stop()

    assert task.cancelled()
    assert cancelled.is_set()
    assert wrapper._task is None


@pytest.mark.asyncio
async def test_scan_wrapper_closes_replaced_and_active_llm_clients() -> None:
    import squirrelops_home_sensor.__main__ as entry

    class CloseableLLM:
        def __init__(self) -> None:
            self.closed = asyncio.Event()

        async def aclose(self) -> None:
            self.closed.set()

    class Classifier:
        def __init__(self, llm) -> None:
            self.llm = llm

        def set_llm(self, llm):
            previous = self.llm
            self.llm = llm
            return previous

    first = CloseableLLM()
    second = CloseableLLM()
    classifier = Classifier(first)
    loop = SimpleNamespace(
        _manager=SimpleNamespace(_classifier=classifier),
    )
    wrapper = entry._ScanLoopWrapper(loop, llm=first)
    naming_target = MagicMock()
    wrapper.set_hostname_advisor_target(naming_target)
    naming_target.set_hostname_advisor.assert_called_once_with(first)

    wrapper._replace_llm(second)
    naming_target.set_hostname_advisor.assert_called_with(second)
    await first.closed.wait()
    await wrapper.stop()

    assert second.closed.is_set()
    assert classifier.llm is None
    naming_target.set_hostname_advisor.assert_called_with(None)
    assert not wrapper._llm_close_tasks


@pytest.mark.asyncio
async def test_scout_scheduler_cancels_task_before_restart(
    monkeypatch,
) -> None:
    import squirrelops_home_sensor.scouts.scheduler as scheduler_module

    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def stuck_scout() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    scheduler = scheduler_module.ScoutScheduler(
        engine=MagicMock(),
        db=MagicMock(),
        event_bus=MagicMock(),
        interval_minutes=30,
    )
    task = asyncio.create_task(stuck_scout())
    scheduler._task = task
    monkeypatch.setattr(
        scheduler_module,
        "SCHEDULER_STOP_TIMEOUT_SECONDS",
        0.01,
    )
    await started.wait()

    await scheduler.stop()

    assert task.cancelled()
    assert cancelled.is_set()
    assert scheduler._task is None


class _DaemonStdout(io.StringIO):
    def isatty(self) -> bool:
        return False


def test_daemon_startup_never_prints_pairing_key(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import squirrelops_home_sensor.__main__ as entry

    captured = _DaemonStdout()
    monkeypatch.setattr(entry.sys, "stdout", captured)
    code = "ABCD-EFGH-JKMP-QRST-VWXY"
    config = {
        "sensor": {
            "name": "Test Sensor",
            "data_dir": str(tmp_path),
        }
    }

    entry._display_pairing_code(code, config)

    assert code not in captured.getvalue()
    key_file = tmp_path / "pairing-key"
    assert key_file.read_text(encoding="utf-8") == code + "\n"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
