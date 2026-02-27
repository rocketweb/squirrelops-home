"""Integration tests for the sensor entry point (__main__.py).

Every external subsystem is mocked so the test exercises the wiring and
startup/shutdown orchestration without requiring network access, a real
database, or a running uvicorn server.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    """Write a minimal YAML config to a temporary file."""
    config = {
        "sensor": {
            "port": 9443,
            "data_dir": str(tmp_path / "data"),
            "tls": {"enabled": False},
        },
        "scan": {
            "interval": 300,
            "subnet": "192.168.1.0/24",
        },
        "profile": "standard",
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.dump(config))
    return config_path


@pytest.fixture()
def mock_subsystems() -> dict[str, Any]:
    """Patch all subsystems and return the mocks for assertion."""
    mocks: dict[str, Any] = {}

    # Config loader
    mock_load_config = MagicMock()
    mock_load_config.return_value = {
        "sensor": {
            "port": 9443,
            "data_dir": "/tmp/squirrelops_test",
            "tls": {"enabled": False},
        },
        "scan": {"interval": 300, "subnet": "192.168.1.0/24"},
        "profile": "standard",
    }
    mocks["load_config"] = mock_load_config

    # Database
    mock_db = AsyncMock()
    mock_db.close = AsyncMock()
    mock_open_db = AsyncMock(return_value=mock_db)
    mocks["open_db"] = mock_open_db
    mocks["db"] = mock_db

    # Migrations
    mock_run_migrations = AsyncMock()
    mocks["run_migrations"] = mock_run_migrations

    # Event bus
    mock_event_bus = MagicMock()
    mock_event_bus.publish = AsyncMock(return_value=1)
    mocks["event_bus"] = mock_event_bus
    mock_create_event_bus = MagicMock(return_value=mock_event_bus)
    mocks["create_event_bus"] = mock_create_event_bus

    # Scan loop
    mock_scan_loop = AsyncMock()
    mock_scan_loop.start = AsyncMock()
    mock_scan_loop.stop = AsyncMock()
    mock_scan_loop.set_orchestrator = MagicMock()
    mock_create_scan_loop = MagicMock(return_value=mock_scan_loop)
    mocks["create_scan_loop"] = mock_create_scan_loop
    mocks["scan_loop"] = mock_scan_loop

    # Decoy orchestrator
    mock_orchestrator = AsyncMock()
    mock_orchestrator.start = AsyncMock()
    mock_orchestrator.stop = AsyncMock()
    mock_orchestrator.inner = MagicMock()  # .inner returns a plain mock for scan loop wiring
    mock_create_orchestrator = MagicMock(return_value=mock_orchestrator)
    mocks["create_orchestrator"] = mock_create_orchestrator
    mocks["orchestrator"] = mock_orchestrator

    # FastAPI app factory
    mock_app = MagicMock()
    mock_create_app = MagicMock(return_value=mock_app)
    mocks["create_app"] = mock_create_app
    mocks["app"] = mock_app

    # Uvicorn server
    mock_server = MagicMock()
    mock_server.serve = AsyncMock()
    mock_server_cls = MagicMock(return_value=mock_server)
    mocks["uvicorn_server_cls"] = mock_server_cls
    mocks["uvicorn_server"] = mock_server

    return mocks


@pytest.fixture()
def patched(mock_subsystems: dict[str, Any]):
    """Apply all subsystem patches for the duration of a test."""
    import contextlib

    with contextlib.ExitStack() as stack:
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.load_config",
                mock_subsystems["load_config"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.open_db",
                mock_subsystems["open_db"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.run_migrations",
                mock_subsystems["run_migrations"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.create_event_bus",
                mock_subsystems["create_event_bus"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.create_scan_loop",
                mock_subsystems["create_scan_loop"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.create_orchestrator",
                mock_subsystems["create_orchestrator"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.create_app",
                mock_subsystems["create_app"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.uvicorn.Server",
                mock_subsystems["uvicorn_server_cls"],
            )
        )
        yield


# ---------------------------------------------------------------------------
# Startup tests
# ---------------------------------------------------------------------------


class TestEntryPointStartup:
    """Sensor startup wires all components correctly."""

    @pytest.mark.asyncio
    async def test_loads_config_from_cli_arg(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """--config path is passed to the config loader."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["load_config"].assert_called_once_with(str(config_file))

    @pytest.mark.asyncio
    async def test_opens_database_and_runs_migrations(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["open_db"].assert_called_once()
        mock_subsystems["run_migrations"].assert_called_once_with(
            mock_subsystems["db"]
        )

    @pytest.mark.asyncio
    async def test_initializes_event_bus(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["create_event_bus"].assert_called_once_with(
            mock_subsystems["db"]
        )

    @pytest.mark.asyncio
    async def test_starts_scan_loop(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["scan_loop"].start.assert_called_once()

    @pytest.mark.asyncio
    async def test_starts_decoy_orchestrator(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["orchestrator"].start.assert_called_once()

    @pytest.mark.asyncio
    async def test_creates_fastapi_app_with_dependencies(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["create_app"].assert_called_once()
        call_kwargs = mock_subsystems["create_app"].call_args
        assert call_kwargs is not None

    @pytest.mark.asyncio
    async def test_starts_uvicorn_server(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["uvicorn_server_cls"].assert_called_once()
        mock_subsystems["uvicorn_server"].serve.assert_called_once()


# ---------------------------------------------------------------------------
# Shutdown tests
# ---------------------------------------------------------------------------


class TestEntryPointShutdown:
    """Graceful shutdown stops components in the correct order."""

    @pytest.mark.asyncio
    async def test_graceful_shutdown_on_cancelled_error(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """CancelledError (from SIGTERM/SIGINT) triggers ordered shutdown."""
        call_order: list[str] = []

        async def track_scan_stop() -> None:
            call_order.append("scan_loop.stop")

        async def track_orchestrator_stop() -> None:
            call_order.append("orchestrator.stop")

        async def track_db_close() -> None:
            call_order.append("db.close")

        mock_subsystems["scan_loop"].stop = AsyncMock(side_effect=track_scan_stop)
        mock_subsystems["orchestrator"].stop = AsyncMock(
            side_effect=track_orchestrator_stop
        )
        mock_subsystems["db"].close = AsyncMock(side_effect=track_db_close)

        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        # Verify all shutdown steps were called
        assert "scan_loop.stop" in call_order
        assert "orchestrator.stop" in call_order
        assert "db.close" in call_order

        # Verify order: scan loop and orchestrator stop before DB close
        assert call_order.index("scan_loop.stop") < call_order.index("db.close")
        assert call_order.index("orchestrator.stop") < call_order.index("db.close")

    @pytest.mark.asyncio
    async def test_shutdown_stops_scan_loop(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["scan_loop"].stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_stops_orchestrator(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["orchestrator"].stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_closes_database(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["db"].close.assert_called_once()


# ---------------------------------------------------------------------------
# CLI parsing tests
# ---------------------------------------------------------------------------


class TestCLIParsing:
    """The CLI argument parser handles all expected flags."""

    def test_default_args(self) -> None:
        from squirrelops_home_sensor.__main__ import parse_args

        args = parse_args([])
        assert args.config is None
        assert args.port == 8443
        assert args.no_tls is False

    def test_config_flag(self) -> None:
        from squirrelops_home_sensor.__main__ import parse_args

        args = parse_args(["--config", "/path/to/config.yaml"])
        assert args.config == "/path/to/config.yaml"

    def test_port_flag(self) -> None:
        from squirrelops_home_sensor.__main__ import parse_args

        args = parse_args(["--port", "9999"])
        assert args.port == 9999

    def test_no_tls_flag(self) -> None:
        from squirrelops_home_sensor.__main__ import parse_args

        args = parse_args(["--no-tls"])
        assert args.no_tls is True

    def test_all_flags_combined(self) -> None:
        from squirrelops_home_sensor.__main__ import parse_args

        args = parse_args(
            ["--config", "my.yaml", "--port", "7777", "--no-tls"]
        )
        assert args.config == "my.yaml"
        assert args.port == 7777
        assert args.no_tls is True
