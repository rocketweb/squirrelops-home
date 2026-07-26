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

    # Daily alert retention
    mock_retention_scheduler = AsyncMock()
    mock_retention_scheduler.start = AsyncMock()
    mock_retention_scheduler.stop = AsyncMock()
    mock_create_retention_scheduler = MagicMock(
        return_value=mock_retention_scheduler
    )
    mocks["create_retention_scheduler"] = mock_create_retention_scheduler
    mocks["retention_scheduler"] = mock_retention_scheduler

    # Event bus
    mock_event_bus = MagicMock()
    mock_event_bus.publish = AsyncMock(return_value=1)
    mock_event_bus._log = MagicMock()
    mock_event_bus._log.prune_orphaned_events = AsyncMock(return_value=0)
    mocks["event_bus"] = mock_event_bus
    mock_create_event_bus = MagicMock(return_value=mock_event_bus)
    mocks["create_event_bus"] = mock_create_event_bus

    # Scan loop
    mock_scan_loop = AsyncMock()
    mock_scan_loop.start = AsyncMock()
    mock_scan_loop.stop = AsyncMock()
    mock_scan_loop.set_orchestrator = MagicMock()
    mock_scan_loop.set_hostname_advisor_target = MagicMock()
    mock_scan_loop.set_ip_conflict_handler = MagicMock()
    mock_scan_loop.privileged_ops = MagicMock()
    mock_scan_loop.privileged_ops.is_available = AsyncMock(return_value=True)
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

    # Squirrel Scouts
    mock_scout_scheduler = AsyncMock()
    mock_scout_scheduler.start = AsyncMock()
    mock_scout_scheduler.stop = AsyncMock()
    mocks["scout_scheduler"] = mock_scout_scheduler

    mock_mimic_orchestrator = AsyncMock()
    mock_mimic_orchestrator.prepare_persisted_network = AsyncMock(return_value=0)
    mock_mimic_orchestrator.resume_active = AsyncMock(return_value=0)
    mock_mimic_orchestrator.stop_all = AsyncMock()
    mock_mimic_orchestrator.reconcile_ip_conflicts = AsyncMock()
    mocks["mimic_orchestrator"] = mock_mimic_orchestrator

    mock_ip_manager = AsyncMock()
    mock_ip_manager.load_from_db = AsyncMock(return_value=0)
    mock_ip_manager.remove_all = AsyncMock(return_value=0)
    mock_ip_manager.active_ips = set()
    mocks["ip_manager"] = mock_ip_manager

    mock_mimic_mdns = AsyncMock()
    mock_mimic_mdns.start = AsyncMock()
    mock_mimic_mdns.stop = AsyncMock()
    mocks["mimic_mdns"] = mock_mimic_mdns

    mock_port_fwd = AsyncMock()
    mock_port_fwd.clear_all = AsyncMock(return_value=True)
    mocks["port_fwd"] = mock_port_fwd

    mock_scouts = {
        "scheduler": mock_scout_scheduler,
        "mimic_orchestrator": mock_mimic_orchestrator,
        "ip_manager": mock_ip_manager,
        "mimic_mdns": mock_mimic_mdns,
        "port_forward_manager": mock_port_fwd,
    }
    mock_create_scouts = MagicMock(return_value=mock_scouts)
    mocks["create_scouts_subsystem"] = mock_create_scouts

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

    # API and mimic mDNS advertisers
    mock_mdns = AsyncMock()
    mock_mdns.start = AsyncMock()
    mock_mdns.stop = AsyncMock()
    mock_create_mdns = MagicMock(return_value=mock_mdns)
    mocks["create_mdns_advertiser"] = mock_create_mdns
    mocks["mdns"] = mock_mdns

    # Peer-verified local pairing socket
    mock_local_pairing = AsyncMock()
    mock_local_pairing.start = AsyncMock()
    mock_local_pairing.stop = AsyncMock()
    mock_local_pairing_cls = MagicMock(return_value=mock_local_pairing)
    mocks["local_pairing_cls"] = mock_local_pairing_cls
    mocks["local_pairing"] = mock_local_pairing

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
                "squirrelops_home_sensor.__main__.create_retention_scheduler",
                mock_subsystems["create_retention_scheduler"],
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
                "squirrelops_home_sensor.__main__.create_scouts_subsystem",
                mock_subsystems["create_scouts_subsystem"],
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
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.__main__.create_mdns_advertiser",
                mock_subsystems["create_mdns_advertiser"],
            )
        )
        stack.enter_context(
            patch(
                "squirrelops_home_sensor.api.local_pairing.LocalPairingServer",
                mock_subsystems["local_pairing_cls"],
            )
        )
        yield


# ---------------------------------------------------------------------------
# Startup tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_db_enables_foreign_key_enforcement(tmp_path: Path) -> None:
    """Production connections must enforce the relationships in the schema."""
    from squirrelops_home_sensor.__main__ import open_db

    db = await open_db(tmp_path / "sensor.db")
    try:
        cursor = await db.execute("PRAGMA foreign_keys")
        row = await cursor.fetchone()
        assert row[0] == 1
    finally:
        await db.close()


def test_full_profile_canonicalizes_stale_nested_runtime_limits() -> None:
    """A persisted Full label must reconstruct Full subsystems after restart."""
    from squirrelops_home_sensor.__main__ import _canonicalize_profile_runtime

    config = {
        "profile": "full",
        "network": {"scan_interval": 300},
        "decoys": {"max_decoys": 8},
        "classifier": {"mode": "cloud_llm"},
        "scouts": {
            "interval_minutes": 60,
            "max_mimic_decoys": 10,
            "max_virtual_ips": 10,
        },
    }

    _canonicalize_profile_runtime(config)

    assert config["network"]["scan_interval"] == 60
    assert config["decoys"]["max_decoys"] == 3
    assert config["classifier"]["mode"] == "local_llm"
    assert config["scouts"]["interval_minutes"] == 30
    assert config["scouts"]["max_mimic_decoys"] == 10
    assert config["scouts"]["max_virtual_ips"] == 10


@pytest.mark.parametrize(
    ("provider", "expected_endpoint"),
    [
        ("openrouter", "https://openrouter.ai/api/v1"),
        ("fireworks", "https://api.fireworks.ai/inference/v1"),
    ],
)
def test_cloud_provider_builds_openai_compatible_classifier(
    provider: str,
    expected_endpoint: str,
) -> None:
    from squirrelops_home_sensor.__main__ import _create_llm_classifier

    classifier = _create_llm_classifier({
        "classifier": {
            "mode": "cloud_llm",
            "llm_provider": provider,
            "llm_endpoint": "https://attacker.invalid/v1",
            "llm_model": "provider/model",
            "llm_api_key": "secret",
        },
    })

    assert classifier is not None
    assert classifier._endpoint == expected_endpoint


@pytest.mark.parametrize("provider", ["openrouter", "fireworks"])
def test_cloud_provider_without_key_is_disabled(provider: str) -> None:
    from squirrelops_home_sensor.__main__ import _create_llm_classifier

    classifier = _create_llm_classifier({
        "classifier": {
            "mode": "cloud_llm",
            "llm_provider": provider,
            "llm_model": "provider/model",
        },
    })

    assert classifier is None


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
        mock_subsystems["run_migrations"].assert_called_once_with(mock_subsystems["db"])

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

        mock_subsystems["create_event_bus"].assert_called_once_with(mock_subsystems["db"])

    @pytest.mark.asyncio
    async def test_starts_daily_alert_retention(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["create_retention_scheduler"].assert_called_once()
        mock_subsystems["retention_scheduler"].start.assert_awaited_once()

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
        mock_subsystems[
            "scan_loop"
        ].set_hostname_advisor_target.assert_called_once_with(
            mock_subsystems["mimic_orchestrator"]
        )

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
        uvicorn_config = mock_subsystems["uvicorn_server_cls"].call_args.args[0]
        assert uvicorn_config.proxy_headers is False

    @pytest.mark.asyncio
    async def test_packaged_defaults_do_not_start_setup_key_socket(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """Production requires administrator-assisted manual key entry."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError
        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        mock_subsystems["local_pairing_cls"].assert_not_called()

    @pytest.mark.asyncio
    async def test_disabled_tls_is_forced_to_loopback(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError
        await run_sensor(config_path=str(config_file), port=9443, no_tls=False)

        uvicorn_config = mock_subsystems["uvicorn_server_cls"].call_args.args[0]
        assert uvicorn_config.host == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_helper_capability_failure_aborts_before_mimic_start(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """The API cannot report healthy when privileged networking is unusable."""
        from squirrelops_home_sensor.__main__ import run_sensor

        privileged_ops = mock_subsystems["scan_loop"].privileged_ops
        privileged_ops.is_available.return_value = False

        with pytest.raises(RuntimeError, match="privileged helper"):
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )

        privileged_ops.is_available.assert_awaited_once()
        mock_subsystems["mimic_mdns"].start.assert_not_awaited()
        mock_subsystems["scan_loop"].start.assert_not_awaited()
        mock_subsystems["uvicorn_server"].serve.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_mimic_resume_failure_aborts_before_api_start(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """Persisted mimics are mandatory startup state, not best effort."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["mimic_orchestrator"].resume_active.side_effect = RuntimeError(
            "mimic resume failed"
        )

        with pytest.raises(RuntimeError, match="mimic resume failed"):
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )

        mock_subsystems["scout_scheduler"].start.assert_not_awaited()
        mock_subsystems["scan_loop"].start.assert_not_awaited()
        mock_subsystems["uvicorn_server"].serve.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_persisted_alias_withdrawal_failure_aborts_before_api_start(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """Startup quarantine must remain in place when an alias cannot be withdrawn."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems[
            "mimic_orchestrator"
        ].prepare_persisted_network.side_effect = RuntimeError(
            "persisted alias withdrawal failed"
        )

        with pytest.raises(RuntimeError, match="persisted alias withdrawal failed"):
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )

        mock_subsystems["mimic_orchestrator"].resume_active.assert_not_awaited()
        mock_subsystems["scout_scheduler"].start.assert_not_awaited()
        mock_subsystems["scan_loop"].start.assert_not_awaited()
        mock_subsystems["uvicorn_server"].serve.assert_not_awaited()


# ---------------------------------------------------------------------------
# Shutdown tests
# ---------------------------------------------------------------------------


class TestEntryPointShutdown:
    """Graceful shutdown stops components in the correct order."""

    @pytest.mark.asyncio
    async def test_startup_failure_after_network_and_scan_start_unwinds_all(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """A late startup failure cannot leak listeners, aliases, PF, or DB."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["mdns"].start.side_effect = RuntimeError("mDNS startup failed")

        with pytest.raises(RuntimeError, match="mDNS startup failed"):
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )

        mock_subsystems["orchestrator"].start.assert_awaited_once()
        mock_subsystems["mimic_orchestrator"].prepare_persisted_network.assert_awaited_once()
        mock_subsystems["scan_loop"].start.assert_awaited_once()
        mock_subsystems["mdns"].stop.assert_awaited_once()
        mock_subsystems["scan_loop"].stop.assert_awaited_once()
        mock_subsystems["scout_scheduler"].stop.assert_awaited_once()
        mock_subsystems["mimic_orchestrator"].stop_all.assert_awaited_once()
        mock_subsystems["mimic_mdns"].stop.assert_awaited_once()
        mock_subsystems["ip_manager"].remove_all.assert_awaited_once()
        mock_subsystems["port_fwd"].clear_all.assert_awaited_once()
        mock_subsystems["orchestrator"].stop.assert_awaited_once()
        mock_subsystems["db"].close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cleanup_failure_does_not_skip_later_critical_cleanup(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """One early stop error is reported only after all later cleanup."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["load_config"].return_value["pairing"] = {
            "allow_unsigned_local": True,
        }
        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError
        mock_subsystems["local_pairing"].stop.side_effect = RuntimeError(
            "local pairing stop failed"
        )

        with pytest.raises(
            RuntimeError,
            match="shutdown did not complete cleanly",
        ):
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )

        mock_subsystems["mdns"].stop.assert_awaited_once()
        mock_subsystems["scan_loop"].stop.assert_awaited_once()
        mock_subsystems["scout_scheduler"].stop.assert_awaited_once()
        mock_subsystems["mimic_orchestrator"].stop_all.assert_awaited_once()
        mock_subsystems["mimic_mdns"].stop.assert_awaited_once()
        mock_subsystems["ip_manager"].remove_all.assert_awaited_once()
        mock_subsystems["port_fwd"].clear_all.assert_awaited_once()
        mock_subsystems["orchestrator"].stop.assert_awaited_once()
        mock_subsystems["db"].close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unknown_persisted_alias_state_retains_packet_filter(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        """A failed DB reservation load must not make PF cleanup fail open."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["ip_manager"].load_from_db.side_effect = RuntimeError(
            "virtual IP load failed"
        )

        with pytest.raises(RuntimeError, match="virtual IP load failed"):
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )

        mock_subsystems["ip_manager"].remove_all.assert_awaited_once()
        assert mock_subsystems["ip_manager"].active_ips == set()
        mock_subsystems["port_fwd"].clear_all.assert_not_awaited()
        mock_subsystems["scan_loop"].start.assert_not_awaited()
        mock_subsystems["uvicorn_server"].serve.assert_not_awaited()
        mock_subsystems["orchestrator"].stop.assert_awaited_once()
        mock_subsystems["db"].close.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("remove_error", "active_ips"),
        [
            (RuntimeError("alias removal failed"), set()),
            (None, {"192.168.1.200"}),
        ],
    )
    async def test_alias_cleanup_failure_retains_packet_filter(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
        remove_error: RuntimeError | None,
        active_ips: set[str],
    ) -> None:
        """PF remains loaded unless virtual alias removal is confirmed."""
        from squirrelops_home_sensor.__main__ import run_sensor

        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError
        mock_subsystems["ip_manager"].active_ips = active_ips
        if remove_error is not None:
            mock_subsystems["ip_manager"].remove_all.side_effect = remove_error

        if remove_error is None:
            await run_sensor(
                config_path=str(config_file),
                port=9443,
                no_tls=True,
            )
        else:
            with pytest.raises(
                RuntimeError,
                match="shutdown did not complete cleanly",
            ):
                await run_sensor(
                    config_path=str(config_file),
                    port=9443,
                    no_tls=True,
                )

        mock_subsystems["port_fwd"].clear_all.assert_not_awaited()
        mock_subsystems["orchestrator"].stop.assert_awaited_once()
        mock_subsystems["db"].close.assert_awaited_once()

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
        mock_subsystems["orchestrator"].stop = AsyncMock(side_effect=track_orchestrator_stop)
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
    async def test_shutdown_stops_alert_retention_before_closing_database(
        self,
        config_file: Path,
        mock_subsystems: dict[str, Any],
        patched: None,
    ) -> None:
        from squirrelops_home_sensor.__main__ import run_sensor

        call_order: list[str] = []

        async def stop_retention() -> None:
            call_order.append("retention.stop")

        async def close_db() -> None:
            call_order.append("db.close")

        mock_subsystems["retention_scheduler"].stop.side_effect = stop_retention
        mock_subsystems["db"].close.side_effect = close_db
        mock_subsystems["uvicorn_server"].serve.side_effect = asyncio.CancelledError

        await run_sensor(config_path=str(config_file), port=9443, no_tls=True)

        assert call_order == ["retention.stop", "db.close"]

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
        assert args.port is None
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

        args = parse_args(["--config", "my.yaml", "--port", "7777", "--no-tls"])
        assert args.config == "my.yaml"
        assert args.port == 7777
        assert args.no_tls is True
