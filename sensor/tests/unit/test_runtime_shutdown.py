"""Regression tests for task shutdown and daemon credential hygiene."""

from __future__ import annotations

import asyncio
import io
import os
import signal
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="Real Unix signal regression")
@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
def test_server_signal_cleans_runtime_before_uvicorn_replays_signal(
    tmp_path: Path, stop_signal: signal.Signals,
) -> None:
    # A real, isolated child is necessary: mocking signal.raise_signal hides the
    # process termination that skips an outer async finally on SIGTERM.
    program = textwrap.dedent("""
        import asyncio
        import os
        import signal
        import sys
        import uvicorn
        import squirrelops_home_sensor.__main__ as entry
        from squirrelops_home_sensor.__main__ import (
            _RuntimeResources, _RuntimeManagedServer, _cleanup_runtime,
        )
        print("SENSOR_MODULE=" + entry.__file__, flush=True)

        class Guest:
            async def stop_all(self):
                await asyncio.sleep(0.01)
                print("GUEST_STOPPED", flush=True)

        class Database:
            async def close(self):
                print("DATABASE_CLOSED", flush=True)

        async def app(scope, receive, send):
            raise RuntimeError("No client requests belong in this lifecycle test")

        async def main():
            runtime = _RuntimeResources({"sensor": {"data_dir": sys.argv[1]}})
            runtime.deep_orchestrator = Guest()
            runtime.deep_start_attempted = True
            runtime.db = Database()
            server = _RuntimeManagedServer(
                uvicorn.Config(app, host="127.0.0.1", port=0, lifespan="off", log_level="error"),
                runtime=runtime,
            )
            async def stop_after_start():
                while not server.started:
                    await asyncio.sleep(0.01)
                print("SERVER_STARTED", flush=True)
                os.kill(os.getpid(), int(sys.argv[2]))
            task = asyncio.create_task(stop_after_start())
            try:
                await server.serve()
            finally:
                await _cleanup_runtime(runtime)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            pass
    """)
    interpreter = os.environ.get("SQUIRRELOPS_TEST_SENSOR_PYTHON", sys.executable)
    result = subprocess.run(
        [interpreter, "-I", "-c", program, str(tmp_path), str(int(stop_signal))],
        capture_output=True, text=True, timeout=15,
    )
    assert "SERVER_STARTED" in result.stdout, result.stderr
    if "SQUIRRELOPS_TEST_SENSOR_PYTHON" in os.environ:
        module = next(line.removeprefix("SENSOR_MODULE=") for line in result.stdout.splitlines()
                      if line.startswith("SENSOR_MODULE="))
        assert Path(module).resolve().is_relative_to(Path(interpreter).resolve().parent.parent)
    assert result.stdout.count("GUEST_STOPPED") == 1, result.stdout + result.stderr
    assert result.stdout.count("DATABASE_CLOSED") == 1, result.stdout + result.stderr
    assert result.stdout.index("GUEST_STOPPED") < result.stdout.index("DATABASE_CLOSED")
    if stop_signal == signal.SIGTERM:
        assert result.returncode == -signal.SIGTERM
    else:
        assert result.returncode == 0, result.stderr


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, RuntimeError("startup failed"), asyncio.CancelledError()])
async def test_managed_server_always_cleans_runtime_once(monkeypatch, tmp_path, failure):
    import squirrelops_home_sensor.__main__ as entry

    serve = AsyncMock(side_effect=failure)
    monkeypatch.setattr(entry.uvicorn.Server, "_serve", serve)
    runtime = entry._RuntimeResources({"sensor": {"data_dir": str(tmp_path)}})
    runtime.db = SimpleNamespace(close=AsyncMock())
    server = entry._RuntimeManagedServer(entry.uvicorn.Config(MagicMock()), runtime=runtime)
    sockets = []

    if failure is None:
        await server._serve(sockets)
    else:
        with pytest.raises(type(failure)) as raised:
            await server._serve(sockets)
        assert raised.value is failure

    # The outer entry-point finally remains a fallback for earlier startup
    # failures, but must not close resources again after the server did so.
    assert await entry._cleanup_runtime(runtime) == []
    runtime.db.close.assert_awaited_once()
    serve.assert_awaited_once_with(sockets)


@pytest.mark.asyncio
@pytest.mark.parametrize("startup_failure", [None, RuntimeError("startup failed")])
async def test_managed_server_reports_cleanup_failure_without_hiding_startup_error(
    monkeypatch, tmp_path, startup_failure,
):
    import squirrelops_home_sensor.__main__ as entry

    monkeypatch.setattr(entry.uvicorn.Server, "_serve", AsyncMock(side_effect=startup_failure))
    runtime = entry._RuntimeResources({"sensor": {"data_dir": str(tmp_path)}})
    cleanup_failure = RuntimeError("guest cleanup failed")
    runtime.deep_orchestrator = SimpleNamespace(stop_all=AsyncMock(side_effect=cleanup_failure))
    runtime.deep_start_attempted = True
    runtime.db = SimpleNamespace(close=AsyncMock())
    server = entry._RuntimeManagedServer(entry.uvicorn.Config(MagicMock()), runtime=runtime)

    with pytest.raises(RuntimeError) as raised:
        await server._serve()
    if startup_failure is not None:
        assert raised.value is startup_failure
    else:
        assert str(raised.value) == "Sensor shutdown did not complete cleanly"
        assert raised.value.__cause__ is cleanup_failure
    runtime.deep_orchestrator.stop_all.assert_awaited_once()
    runtime.db.close.assert_awaited_once()


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
