"""SquirrelOps Home Sensor -- entry point.

Usage::

    python -m squirrelops_home_sensor [--config PATH] [--port PORT] [--no-tls]

Startup sequence:
    1. Parse CLI arguments
    2. Load configuration from YAML (or defaults)
    3. Open SQLite database and run migrations
    4. Initialise the internal event bus
    5. Initialise the scan loop
    6. Initialise the decoy orchestrator
    7. Create the FastAPI application with dependency injection
    8. Start the uvicorn server
    9. On shutdown signal: stop scan loop, stop decoys, close database
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

import uvicorn

from squirrelops_home_sensor.app import create_app  # noqa: F401 -- patched in tests

logger = logging.getLogger("squirrelops_home_sensor")


# ---------------------------------------------------------------------------
# Integration seams -- thin wrappers around real subsystem constructors.
# These are module-level names so tests can patch them individually.
# ---------------------------------------------------------------------------


def load_config(config_path: str | None) -> dict[str, Any]:
    """Load configuration from a YAML file or return defaults.

    Wraps the real config loader, converting the pydantic Settings model
    into a plain dict for downstream consumption.
    """
    from squirrelops_home_sensor.config import load_settings

    path = Path(config_path) if config_path else None
    settings = load_settings(config_path=path)
    return settings.model_dump()


async def open_db(db_path: Path) -> Any:
    """Open the SQLite database."""
    import aiosqlite

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(db_path))
    db.row_factory = aiosqlite.Row
    return db


async def run_migrations(db: Any) -> None:
    """Apply pending database migrations."""
    from squirrelops_home_sensor.db.migrations import apply_migrations

    await apply_migrations(db)


def create_event_bus(db: Any) -> Any:
    """Create the event bus backed by the persistent event log."""
    from squirrelops_home_sensor.events.bus import EventBus
    from squirrelops_home_sensor.events.log import EventLog

    event_log = EventLog(db)
    return EventBus(event_log)


def create_scan_loop(config: dict[str, Any], db: Any, event_bus: Any) -> Any:
    """Create the periodic scan loop.

    Returns an object with async start() and stop() methods.
    """
    from squirrelops_home_sensor.devices.classifier import DeviceClassifier
    from squirrelops_home_sensor.devices.manager import DeviceManager
    from squirrelops_home_sensor.devices.signatures import SignatureDB
    from squirrelops_home_sensor.privileged.helper import create_privileged_ops
    from squirrelops_home_sensor.scanner.loop import ScanLoop
    from squirrelops_home_sensor.scanner.port_scanner import PortScanner

    # Build signature DB (load from file if available, otherwise empty)
    sig_file = Path(config.get("sensor", {}).get("data_dir", "./data")) / "device_signatures.json"
    if sig_file.exists():
        sig_db = SignatureDB.load(sig_file)
    else:
        sig_db = SignatureDB(oui_prefixes={}, dhcp_fingerprints={}, mdns_patterns=[])

    # Build optional LLM classifier
    llm = _create_llm_classifier(config)

    # Build device classifier with local DB + optional LLM
    classifier = DeviceClassifier(signature_db=sig_db, llm=llm)

    # Build the device manager
    device_manager = DeviceManager(
        db=db,
        event_bus=event_bus,
        classifier=classifier,
    )

    # Build privileged operations
    priv_ops = create_privileged_ops()

    # Build port scanner
    port_scanner = PortScanner(timeout_per_port=2.0, max_concurrent=100)

    network_cfg = config.get("network", {})
    subnet = network_cfg.get("subnet", "192.168.1.0/24")
    scan_interval = network_cfg.get("scan_interval", 300)

    # Build optional Home Assistant client
    ha_config = config.get("home_assistant", {})
    ha_client = None
    if ha_config.get("enabled") and ha_config.get("url") and ha_config.get("token"):
        from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient
        ha_client = HomeAssistantClient(url=ha_config["url"], token=ha_config["token"])
        logger.info("Home Assistant integration enabled: %s", ha_config["url"])

    # Build security insight analyzer
    from squirrelops_home_sensor.security.analyzer import SecurityInsightAnalyzer
    security_analyzer = SecurityInsightAnalyzer(db=db, event_bus=event_bus)

    # Orchestrator is attached later via set_orchestrator()
    wrapper = _ScanLoopWrapper(
        ScanLoop(
            device_manager=device_manager,
            event_bus=event_bus,
            privileged_ops=priv_ops,
            subnet=subnet,
            scan_interval=scan_interval,
            port_scanner=port_scanner,
            ha_client=ha_client,
            ha_config=ha_config,
            config=config,
            security_analyzer=security_analyzer,
        )
    )
    wrapper.privileged_ops = priv_ops
    return wrapper


def _create_llm_classifier(config: dict[str, Any]) -> Any:
    """Create the LLM classifier from config, or None if not configured."""
    classifier_cfg = config.get("classifier", {})
    endpoint = classifier_cfg.get("llm_endpoint")
    model = classifier_cfg.get("llm_model")

    if not endpoint or not model:
        return None

    from squirrelops_home_sensor.devices.llm_classifier import OpenAICompatibleClassifier

    logger.info("LLM classifier enabled: %s (model: %s)", endpoint, model)
    return OpenAICompatibleClassifier(
        endpoint=endpoint,
        model=model,
        api_key=classifier_cfg.get("llm_api_key"),
    )


class _ScanLoopWrapper:
    """Wraps ScanLoop to provide start()/stop() instead of run(event)."""

    def __init__(self, loop: Any) -> None:
        self._loop = loop
        self._shutdown = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def set_orchestrator(self, orchestrator: Any) -> None:
        """Attach a DecoyOrchestrator for auto-deploy after scans."""
        self._loop._orchestrator = orchestrator

    async def start(self) -> None:
        self._shutdown.clear()
        self._task = asyncio.create_task(self._loop.run(self._shutdown))

    async def stop(self) -> None:
        self._shutdown.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass


def create_secret_store(config: dict[str, Any]) -> Any:
    """Create the platform-appropriate secret store."""
    from squirrelops_home_sensor.secrets.encrypted_file import EncryptedFileStore
    data_dir = config.get("sensor", {}).get("data_dir", "./data")
    return EncryptedFileStore(
        file_path=Path(data_dir) / "secrets.enc",
        master_password=config.get("sensor", {}).get("secret_passphrase", "squirrelops-default"),
    )


def create_mdns_advertiser(config: dict[str, Any], port: int) -> Any:
    """Create the mDNS service advertiser."""
    from squirrelops_home_sensor.mdns import ServiceAdvertiser
    sensor_name = config.get("sensor_name", "SquirrelOps")
    return ServiceAdvertiser(name=sensor_name, port=port)


def create_orchestrator(config: dict[str, Any], db: Any, event_bus: Any) -> Any:
    """Create the decoy orchestrator.

    Returns an object with async start()/stop() methods.
    """
    from squirrelops_home_sensor.decoys.orchestrator import DecoyOrchestrator

    decoy_cfg = config.get("decoys", {})
    max_decoys = decoy_cfg.get("max_decoys", 8)

    return _OrchestratorWrapper(
        DecoyOrchestrator(
            event_bus=event_bus,
            db=db,
            max_decoys=max_decoys,
        )
    )


def create_scouts_subsystem(
    config: dict[str, Any], db: Any, event_bus: Any, priv_ops: Any,
) -> dict[str, Any] | None:
    """Create the Squirrel Scouts subsystem (scout engine, scheduler, IP manager, mimic orchestrator).

    Returns a dict with 'scheduler', 'mimic_orchestrator', 'ip_manager' keys,
    or None if scouts are disabled.
    """
    scouts_cfg = config.get("scouts", {})
    if not scouts_cfg.get("enabled", True):
        logger.info("Squirrel Scouts disabled in config")
        return None

    from squirrelops_home_sensor.network.port_forward import PortForwardManager
    from squirrelops_home_sensor.network.virtual_ip import IPAllocator, VirtualIPManager
    from squirrelops_home_sensor.scouts.engine import ScoutEngine
    from squirrelops_home_sensor.scouts.mdns import MimicMDNSAdvertiser
    from squirrelops_home_sensor.scouts.orchestrator import MimicOrchestrator
    from squirrelops_home_sensor.scouts.scheduler import ScoutScheduler
    from squirrelops_home_sensor.scouts.templates import MimicTemplateGenerator

    # Resolve subnet and sensor IP for IP allocation
    network_cfg = config.get("network", {})
    from squirrelops_home_sensor.scanner.loop import _resolve_subnet
    subnet = _resolve_subnet(network_cfg.get("subnet", "192.168.1.0/24"))

    import ipaddress
    network = ipaddress.IPv4Network(subnet, strict=False)
    # Gateway is typically .1
    gateway_ip = str(list(network.hosts())[0])
    # Sensor IP: detect from local socket
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        sensor_ip = s.getsockname()[0]
        s.close()
    except Exception:
        sensor_ip = str(list(network.hosts())[0])

    interface = network_cfg.get("interface", "en0")
    if interface == "auto":
        interface = "en0"

    # Build IP allocator
    allocator = IPAllocator(
        subnet=subnet,
        gateway_ip=gateway_ip,
        sensor_ip=sensor_ip,
        range_start=scouts_cfg.get("virtual_ip_range_start", 200),
        range_end=scouts_cfg.get("virtual_ip_range_end", 250),
    )

    # Build virtual IP manager
    ip_manager = VirtualIPManager(
        privileged_ops=priv_ops,
        allocator=allocator,
        db=db,
        interface=interface,
    )

    # Build scout engine
    scout_engine = ScoutEngine(
        db=db,
        max_concurrent=scouts_cfg.get("max_concurrent_probes", 20),
    )

    # Build scout scheduler
    interval = scouts_cfg.get("interval_minutes", 30)
    scheduler = ScoutScheduler(
        engine=scout_engine,
        db=db,
        event_bus=event_bus,
        interval_minutes=interval,
    )

    # Build mDNS advertiser for mimic hostnames
    mimic_mdns = MimicMDNSAdvertiser()

    # Build port forward manager for privileged port remapping
    port_fwd = PortForwardManager(privileged_ops=priv_ops, interface=interface)

    # Build mimic orchestrator
    template_gen = MimicTemplateGenerator()
    max_mimics = scouts_cfg.get("max_mimic_decoys", 10)
    mimic_orchestrator = MimicOrchestrator(
        scout_engine=scout_engine,
        template_generator=template_gen,
        ip_manager=ip_manager,
        event_bus=event_bus,
        db=db,
        max_mimics=max_mimics,
        mdns_advertiser=mimic_mdns,
        port_forward_manager=port_fwd,
    )

    logger.info(
        "Squirrel Scouts initialized: interval=%dm, max_mimics=%d, ip_range=.%d-.%d",
        interval, max_mimics,
        scouts_cfg.get("virtual_ip_range_start", 200),
        scouts_cfg.get("virtual_ip_range_end", 250),
    )

    return {
        "scheduler": scheduler,
        "mimic_orchestrator": mimic_orchestrator,
        "ip_manager": ip_manager,
        "mimic_mdns": mimic_mdns,
        "port_forward_manager": port_fwd,
    }


class _OrchestratorWrapper:
    """Wraps DecoyOrchestrator to provide simple start()/stop()."""

    def __init__(self, orchestrator: Any) -> None:
        self._orchestrator = orchestrator

    @property
    def inner(self) -> Any:
        return self._orchestrator

    async def start(self) -> None:
        """Resume any previously active decoys from the database."""
        try:
            resumed = await self._orchestrator.resume_active()
            if resumed:
                logger.info("Resumed %d decoys at startup", resumed)
        except Exception:
            logger.exception("Failed to resume decoys at startup")

    async def stop(self) -> None:
        await self._orchestrator.stop_all()


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Parameters
    ----------
    argv:
        Argument list.  Defaults to ``sys.argv[1:]`` when ``None``.
    """
    parser = argparse.ArgumentParser(
        prog="squirrelops_home_sensor",
        description="SquirrelOps Home network security sensor",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Port for the API server (default: 8443)",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        default=False,
        help="Disable TLS (development only)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Main run coroutine
# ---------------------------------------------------------------------------


async def run_sensor(
    config_path: str | None = None,
    port: int = 8443,
    no_tls: bool = False,
) -> None:
    """Start the sensor and run until cancelled.

    This is the top-level coroutine that wires all subsystems together.
    It is designed to be called from ``main()`` or directly in tests.
    """
    # 1. Load config
    config: dict[str, Any] = load_config(config_path)

    # Override port from CLI if provided
    config.setdefault("sensor", {})
    config["sensor"]["port"] = port
    if no_tls:
        config["sensor"].setdefault("tls", {})
        config["sensor"]["tls"]["enabled"] = False

    # 2. Open database
    data_dir = config.get("sensor", {}).get("data_dir", "./data")
    db = await open_db(Path(data_dir) / "squirrelops.db")

    # 3. Run migrations
    await run_migrations(db)

    # 3b. Init TLS certs (unless --no-tls)
    ca_key = None
    ca_cert = None
    ssl_certfile = None
    ssl_keyfile = None
    if not no_tls:
        from squirrelops_home_sensor.tls import ensure_tls_certs
        secret_store = create_secret_store(config)
        data_dir_path = Path(config.get("sensor", {}).get("data_dir", "./data"))
        sensor_name = config.get("sensor_name", "SquirrelOps")
        cert_path, key_path, ca_key, ca_cert = await ensure_tls_certs(
            secret_store, data_dir=data_dir_path, sensor_name=sensor_name
        )
        ssl_certfile = str(cert_path)
        ssl_keyfile = str(key_path)

    # 4. Init event bus
    event_bus = create_event_bus(db)

    # 5. Init scan loop
    scan_loop = create_scan_loop(config=config, db=db, event_bus=event_bus)

    # 6. Init decoy orchestrator
    orchestrator = create_orchestrator(config=config, db=db, event_bus=event_bus)

    # 6b. Init Squirrel Scouts subsystem (scout engine, scheduler, IP manager, mimics)
    priv_ops = scan_loop.privileged_ops
    scouts = create_scouts_subsystem(
        config=config, db=db, event_bus=event_bus, priv_ops=priv_ops,
    )
    scout_scheduler = scouts["scheduler"] if scouts else None
    mimic_orchestrator = scouts["mimic_orchestrator"] if scouts else None
    ip_manager = scouts["ip_manager"] if scouts else None
    mimic_mdns = scouts["mimic_mdns"] if scouts else None
    port_fwd = scouts["port_forward_manager"] if scouts else None

    # 7. Create FastAPI app
    app = create_app(config=config, ca_key=ca_key, ca_cert=ca_cert)

    # 7b. Wire up dependency overrides for production
    from squirrelops_home_sensor.api.deps import get_db as _get_db_dep, get_config as _get_config_dep, get_event_bus as _get_event_bus_dep, get_privileged_ops as _get_priv_ops_dep

    async def _prod_get_db():
        yield db

    async def _prod_get_config():
        return config

    async def _prod_get_event_bus():
        return event_bus

    async def _prod_get_priv_ops():
        return priv_ops

    app.dependency_overrides[_get_db_dep] = _prod_get_db
    app.dependency_overrides[_get_config_dep] = _prod_get_config
    app.dependency_overrides[_get_event_bus_dep] = _prod_get_event_bus
    app.dependency_overrides[_get_priv_ops_dep] = _prod_get_priv_ops

    # 7b2. Wire scouts API dependencies
    from squirrelops_home_sensor.api.routes_scouts import get_scout_scheduler as _get_sched_dep, get_mimic_orchestrator as _get_mimic_dep

    async def _prod_get_scout_scheduler():
        return scout_scheduler

    async def _prod_get_mimic_orchestrator():
        return mimic_orchestrator

    app.dependency_overrides[_get_sched_dep] = _prod_get_scout_scheduler
    app.dependency_overrides[_get_mimic_dep] = _prod_get_mimic_orchestrator

    # 7b3. Wire decoy orchestrator into decoy routes
    from squirrelops_home_sensor.api.routes_decoys import get_decoy_orchestrator as _get_decoy_orch_dep

    async def _prod_get_decoy_orchestrator():
        return orchestrator.inner

    app.dependency_overrides[_get_decoy_orch_dep] = _prod_get_decoy_orchestrator

    # 7c. Wire up live WebSocket broadcast from event bus
    from squirrelops_home_sensor.api.ws import broadcast_event

    async def _ws_broadcast(event: dict) -> None:
        await broadcast_event(
            seq=event["seq"],
            event_type=event["event_type"],
            payload=event["payload"],
        )

    event_bus.subscribe(["*"], _ws_broadcast)

    # 7d. Wire orchestrator into scan loop for auto-deploy
    scan_loop.set_orchestrator(orchestrator.inner)
    logger.info("Decoy orchestrator wired to scan loop for auto-deploy")

    # 8. Start subsystems (resume decoys first, then start scanning)
    await orchestrator.start()

    # 8b. Start scouts subsystem (restore virtual IPs, resume mimics, start scheduler)
    if scouts:
        # Start mDNS advertiser for mimic hostnames
        await mimic_mdns.start()

        try:
            restored = await ip_manager.load_from_db()
            if restored:
                logger.info("Restored %d virtual IP aliases", restored)
        except Exception:
            logger.exception("Failed to restore virtual IP aliases")

        try:
            resumed = await mimic_orchestrator.resume_active()
            if resumed:
                logger.info("Resumed %d mimic decoys", resumed)
        except Exception:
            logger.exception("Failed to resume mimic decoys")

        await scout_scheduler.start()

    await scan_loop.start()

    # 9. Configure and start uvicorn
    uvicorn_kwargs: dict[str, Any] = {}
    if ssl_certfile and ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile

    uvicorn_config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        **uvicorn_kwargs,
    )
    server = uvicorn.Server(uvicorn_config)

    # 10. Start mDNS advertisement
    mdns = create_mdns_advertiser(config, port)
    await mdns.start()

    # Generate pairing code at startup so it's visible before the app connects
    from squirrelops_home_sensor.api.routes_pairing import _init_pairing_state
    _init_pairing_state(app.state, config)

    try:
        await server.serve()
    except asyncio.CancelledError:
        logger.info("Shutdown signal received -- stopping sensor")
    finally:
        # Graceful shutdown: stop mDNS, scan loop, scouts, decoys, close DB
        logger.info("Stopping mDNS advertisement...")
        await mdns.stop()

        logger.info("Stopping scan loop...")
        await scan_loop.stop()

        if scouts:
            logger.info("Stopping scout scheduler...")
            await scout_scheduler.stop()

            logger.info("Stopping mimic orchestrator...")
            await mimic_orchestrator.stop_all()

            logger.info("Stopping mimic mDNS advertiser...")
            await mimic_mdns.stop()

            logger.info("Clearing port forwarding rules...")
            await port_fwd.clear_all()

            logger.info("Removing virtual IP aliases...")
            removed = await ip_manager.remove_all()
            if removed:
                logger.info("Removed %d virtual IP aliases", removed)

        logger.info("Stopping decoy orchestrator...")
        await orchestrator.stop()

        logger.info("Closing database...")
        await db.close()

        logger.info("Sensor shutdown complete")


# ---------------------------------------------------------------------------
# Script entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI args and run the sensor."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    args = parse_args()

    try:
        asyncio.run(
            run_sensor(
                config_path=args.config,
                port=args.port,
                no_tls=args.no_tls,
            )
        )
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
