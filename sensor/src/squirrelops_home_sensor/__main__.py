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
import inspect
import logging
import os
import ssl
import sys
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import uvicorn

from squirrelops_home_sensor.app import create_app  # noqa: F401 -- patched in tests

logger = logging.getLogger("squirrelops_home_sensor")
SCAN_STOP_TIMEOUT_SECONDS = 10.0


class _PrivateRotatingFileHandler(RotatingFileHandler):
    """Rotating log handler that keeps every newly created file private."""

    def _open(self):
        stream = super()._open()
        os.chmod(self.baseFilename, 0o600)
        return stream


def configure_logging(
    *,
    log_path: str | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    """Configure bounded private logs for the packaged daemon."""
    resolved_log_path = (
        log_path if log_path is not None else os.environ.get("SQUIRRELOPS_LOG_PATH", "").strip()
    )
    handler: logging.Handler
    if resolved_log_path:
        destination = Path(resolved_log_path).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        handler = _PrivateRotatingFileHandler(
            destination,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    else:
        handler = logging.StreamHandler()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[handler],
        force=True,
    )


# ---------------------------------------------------------------------------
# Integration seams -- thin wrappers around real subsystem constructors.
# These are module-level names so tests can patch them individually.
# ---------------------------------------------------------------------------


def _canonicalize_profile_runtime(config: dict[str, Any]) -> None:
    """Apply the selected profile to every startup runtime setting."""
    from squirrelops_home_sensor.profiles import PROFILE_SETTINGS, ResourceProfile

    try:
        profile = ResourceProfile(config.get("profile", ResourceProfile.STANDARD.value))
    except ValueError:
        logger.warning(
            "Unknown resource profile %r; using standard",
            config.get("profile"),
        )
        profile = ResourceProfile.STANDARD

    settings = PROFILE_SETTINGS[profile]
    config["profile"] = profile.value
    config["scan_interval_seconds"] = settings.scan_interval
    config["max_decoys"] = settings.max_decoys
    config.setdefault("network", {})["scan_interval"] = settings.scan_interval
    config.setdefault("decoys", {})["max_decoys"] = settings.max_decoys
    config.setdefault("classifier", {})["mode"] = settings.llm_mode.value
    scouts = config.setdefault("scouts", {})
    scouts["interval_minutes"] = settings.scout_interval_minutes
    scouts["max_mimic_decoys"] = settings.max_mimic_decoys
    scouts["max_virtual_ips"] = settings.max_virtual_ips


def load_config(config_path: str | None) -> dict[str, Any]:
    """Load configuration from a YAML file or return defaults.

    Wraps the real config loader, converting the pydantic Settings model
    into a plain dict for downstream consumption.
    """
    from squirrelops_home_sensor.config import load_settings

    path = Path(config_path) if config_path else None
    settings = load_settings(config_path=path)
    config = settings.model_dump()
    _canonicalize_profile_runtime(config)

    # Resolve relative data paths next to an explicit package/user config so
    # startup and persisted-config loading agree regardless of cwd.
    data_dir = Path(config["sensor"]["data_dir"]).expanduser()
    if not data_dir.is_absolute() and path is not None:
        data_dir = path.resolve().parent / data_dir
    else:
        data_dir = data_dir.resolve()
    config["sensor"]["data_dir"] = str(data_dir)

    # Sensor identity is generated once per installation and kept in a private
    # runtime file. A stable ID is required for pairing key derivation and app
    # credential labels; "unknown" must never become a shared identity.
    from squirrelops_home_sensor.secure_io import atomic_write_private_text

    sensor_id_path = data_dir / "sensor-id"
    sensor_id = str(config["sensor"].get("id", "")).strip()
    if not sensor_id and sensor_id_path.exists():
        sensor_id = sensor_id_path.read_text(encoding="utf-8").strip()
    if not sensor_id:
        sensor_id = str(uuid.uuid4())
        atomic_write_private_text(sensor_id_path, sensor_id + "\n")
    config["sensor"]["id"] = sensor_id

    # Keep the legacy flat runtime aliases while routes and integrations move
    # to the canonical nested sensor model.
    config["sensor_id"] = sensor_id
    config["sensor_name"] = config["sensor"]["name"]
    return config


def _detect_sensor_ip(fallback: str) -> str:
    """Return the IPv4 address selected by the active default route."""
    import socket as _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return str(sock.getsockname()[0])
    except OSError:
        return fallback
    finally:
        sock.close()


def _resolve_network_interface(configured: str, sensor_ip: str) -> str:
    """Resolve ``auto`` to the interface that owns the routed address."""
    if configured != "auto":
        return configured

    try:
        import psutil

        for name, addresses in psutil.net_if_addrs().items():
            if any(address.address == sensor_ip for address in addresses):
                return name
    except Exception:
        logger.warning(
            "Could not resolve interface for %s; using platform default",
            sensor_ip,
            exc_info=True,
        )
    return "en0" if sys.platform == "darwin" else "eth0"


async def open_db(db_path: Path) -> Any:
    """Open the SQLite database."""
    import aiosqlite

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(db_path))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON")
    return db


async def run_migrations(db: Any) -> None:
    """Apply pending database migrations."""
    from squirrelops_home_sensor.db.migrations import apply_migrations

    await apply_migrations(db)


def create_retention_scheduler(config: dict[str, Any]) -> Any:
    """Create the daily retention scheduler on its own SQLite connection."""
    from squirrelops_home_sensor.alerts.retention import AlertRetentionScheduler

    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    retention_days = int(config.get("alerts", {}).get("retention_days", 90))
    return AlertRetentionScheduler(
        db_path=data_dir / "squirrelops.db",
        retention_days=retention_days,
    )


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

    # Build signature DB. Runtime overrides in the data dir win, then the
    # packaged signatures bundled into Docker/wheels are used.
    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    signature_candidates = [
        data_dir / "device_signatures.json",
        Path.cwd() / "signatures" / "device_signatures.json",
        Path(__file__).resolve().parents[2] / "signatures" / "device_signatures.json",
    ]
    sig_file = next((path for path in signature_candidates if path.exists()), None)
    if sig_file is not None:
        logger.info("Loading device signatures from %s", sig_file)
        sig_db = SignatureDB.load(sig_file)
    else:
        logger.warning("No device signature database found; using empty signature DB")
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
        config=config,
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
        ),
        llm=llm,
    )
    wrapper.privileged_ops = priv_ops
    return wrapper


def _create_llm_classifier(config: dict[str, Any]) -> Any:
    """Create the LLM classifier from config, or None if not configured."""
    classifier_cfg = config.get("classifier", {})
    if classifier_cfg.get("mode") in {"local", "local_signatures", "none"}:
        return None
    from squirrelops_home_sensor.devices.llm_classifier import (
        CLOUD_LLM_PROVIDERS,
        OpenAICompatibleClassifier,
        resolve_llm_endpoint,
    )

    provider = str(classifier_cfg.get("llm_provider") or "").strip().lower()
    endpoint = resolve_llm_endpoint(
        provider,
        classifier_cfg.get("llm_endpoint"),
    )
    model = classifier_cfg.get("llm_model")
    api_key = classifier_cfg.get("llm_api_key")

    if not endpoint or not model:
        return None
    if provider in CLOUD_LLM_PROVIDERS and not api_key:
        logger.warning(
            "LLM classifier provider %s requires an API key; classifier disabled",
            provider,
        )
        return None

    logger.info(
        "LLM classifier enabled: %s at %s (model: %s)",
        provider or "custom",
        endpoint,
        model,
    )
    return OpenAICompatibleClassifier(
        endpoint=endpoint,
        model=model,
        api_key=api_key,
    )


class _ScanLoopWrapper:
    """Wraps ScanLoop to provide start()/stop() instead of run(event)."""

    def __init__(self, loop: Any, *, llm: Any = None) -> None:
        self._loop = loop
        self._llm = llm
        self._hostname_advisor_target: Any = None
        self._shutdown = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._llm_close_tasks: set[asyncio.Task[None]] = set()

    def set_orchestrator(self, orchestrator: Any) -> None:
        """Attach a DecoyOrchestrator for auto-deploy after scans."""
        self._loop._orchestrator = orchestrator

    def set_hostname_advisor_target(self, orchestrator: Any) -> None:
        """Share the live optional AI client with fake-host naming."""
        self._hostname_advisor_target = orchestrator
        setter = getattr(orchestrator, "set_hostname_advisor", None)
        if callable(setter):
            setter(self._llm)

    @property
    def scan_interval(self) -> int:
        """Current live scan interval."""
        return self._loop.scan_interval

    def set_scan_interval(self, scan_interval: int) -> None:
        """Apply a profile scan interval to the running loop."""
        self._loop.set_scan_interval(scan_interval)

    def set_classifier_mode(self, mode: str, config: dict[str, Any]) -> None:
        """Rebuild the optional LLM fallback for a live profile change."""
        classifier_config = dict(config.get("classifier", {}))
        classifier_config["mode"] = mode
        runtime_config = dict(config)
        runtime_config["classifier"] = classifier_config
        self._replace_llm(_create_llm_classifier(runtime_config))

    def set_classifier_config(self, config: dict[str, Any]) -> None:
        """Apply provider, endpoint, model, and key changes without a restart."""
        self._replace_llm(_create_llm_classifier(config))

    def _replace_llm(self, llm: Any) -> None:
        previous = self._loop._manager._classifier.set_llm(llm)
        self._llm = llm
        setter = getattr(
            self._hostname_advisor_target,
            "set_hostname_advisor",
            None,
        )
        if callable(setter):
            setter(llm)
        self._schedule_llm_close(previous)

    def _schedule_llm_close(self, llm: Any) -> None:
        if llm is None or not callable(getattr(llm, "aclose", None)):
            return
        task = asyncio.create_task(self._close_llm(llm))
        self._llm_close_tasks.add(task)
        task.add_done_callback(self._llm_close_tasks.discard)

    @staticmethod
    async def _close_llm(llm: Any) -> None:
        close = getattr(llm, "aclose", None)
        if not callable(close):
            return
        try:
            result = close()
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.warning("Failed to close LLM classifier client", exc_info=True)

    async def _close_classifier_clients(self) -> None:
        setter = getattr(
            self._hostname_advisor_target,
            "set_hostname_advisor",
            None,
        )
        if callable(setter):
            setter(None)
        self._llm = None
        manager = getattr(self._loop, "_manager", None)
        classifier = getattr(manager, "_classifier", None)
        set_llm = getattr(classifier, "set_llm", None)
        if callable(set_llm):
            await self._close_llm(set_llm(None))
        pending = tuple(self._llm_close_tasks)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
            self._llm_close_tasks.difference_update(pending)

    def set_ip_conflict_handler(self, handler: Any) -> None:
        """Attach raw-ARP virtual-IP conflict reconciliation."""
        self._loop.set_ip_conflict_handler(handler)

    async def start(self) -> None:
        self._shutdown.clear()
        self._task = asyncio.create_task(self._loop.run(self._shutdown))

    async def stop(self) -> None:
        self._shutdown.set()
        task = self._task
        self._task = None
        try:
            if task is not None:
                await asyncio.wait_for(
                    asyncio.shield(task),
                    timeout=SCAN_STOP_TIMEOUT_SECONDS,
                )
        except TimeoutError:
            logger.warning(
                "Scan loop did not stop in %.0fs; cancelling it",
                SCAN_STOP_TIMEOUT_SECONDS,
            )
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        except asyncio.CancelledError:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            raise
        finally:
            await self._close_classifier_clients()


def create_secret_store(config: dict[str, Any]) -> Any:
    """Create the platform-appropriate secret store.

    Passphrase resolution order:
    1. ``SQUIRRELOPS_SECRET_PASSPHRASE`` environment variable. Preferred for
       production: the key is injected at service start (launchd/systemd
       credential) and never written to the data directory beside the
       ciphertext it protects.
    2. Explicit ``sensor.secret_passphrase`` in config (if not the legacy default).
    3. Auto-generated passphrase file (``data_dir/.secret_passphrase``).
    4. Fresh install: generate a cryptographically random passphrase and persist it.
    5. Legacy install (secrets.enc exists but no passphrase file): the store is
       migrated off the old hardcoded default by re-encrypting it under a fresh
       random passphrase. If it cannot be decrypted with the legacy default, we
       fail closed rather than silently using a constant key.
    """
    import os as _os
    import secrets as _secrets

    from cryptography.fernet import InvalidToken

    from squirrelops_home_sensor.fsutil import write_text_atomic
    from squirrelops_home_sensor.secrets.encrypted_file import (
        EncryptedFileStore,
        reencrypt_store,
    )

    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    secrets_file = data_dir / "secrets.enc"
    passphrase_file = data_dir / ".secret_passphrase"

    env_passphrase = _os.environ.get("SQUIRRELOPS_SECRET_PASSPHRASE")
    explicit = config.get("sensor", {}).get("secret_passphrase")

    def _persist_passphrase(value: str) -> None:
        write_text_atomic(passphrase_file, value, mode=0o600)

    if env_passphrase:
        # Injected at runtime; do not persist it next to the ciphertext.
        passphrase = env_passphrase
    elif explicit and explicit != "squirrelops-default":
        # User provided an explicit passphrase — use it directly
        passphrase = explicit
    elif passphrase_file.exists():
        # Auto-generated passphrase from a previous run
        passphrase = passphrase_file.read_text().strip()
    elif not secrets_file.exists():
        # Fresh install — generate a strong passphrase and persist it
        passphrase = _secrets.token_urlsafe(32)
        _persist_passphrase(passphrase)
        logger.info("Generated new secret store passphrase at %s", passphrase_file)
    else:
        # Legacy install: secrets.enc exists but no passphrase file. Migrate it
        # off the old hardcoded default key onto a fresh random passphrase.
        new_passphrase = _secrets.token_urlsafe(32)
        try:
            reencrypt_store(
                secrets_file,
                old_password="squirrelops-default",
                new_password=new_passphrase,
            )
        except InvalidToken as exc:
            raise RuntimeError(
                f"Existing secret store at {secrets_file} cannot be decrypted "
                "and no passphrase is available. Set SQUIRRELOPS_SECRET_PASSPHRASE "
                "or sensor.secret_passphrase, or remove the file to re-pair."
            ) from exc
        _persist_passphrase(new_passphrase)
        passphrase = new_passphrase
        logger.warning(
            "Migrated legacy secret store at %s off the default passphrase onto "
            "a freshly generated one.",
            secrets_file,
        )

    return EncryptedFileStore(
        file_path=secrets_file,
        master_password=passphrase,
    )


def create_mdns_advertiser(config: dict[str, Any], port: int) -> Any:
    """Create the mDNS service advertiser."""
    from squirrelops_home_sensor.mdns import ServiceAdvertiser

    sensor_name = config.get("sensor", {}).get("name", "SquirrelOps")
    route_selected_ip = _detect_sensor_ip("")
    return ServiceAdvertiser(
        name=sensor_name,
        port=port,
        preferred_ip=route_selected_ip or None,
    )


def create_orchestrator(config: dict[str, Any], db: Any, event_bus: Any) -> Any:
    """Create the decoy orchestrator.

    Returns an object with async start()/stop() methods.
    """
    from squirrelops_home_sensor.decoys.orchestrator import DecoyOrchestrator

    decoy_cfg = config.get("decoys", {})
    max_decoys = decoy_cfg.get("max_decoys", 8)
    network_cfg = config.get("network", {})
    sensor_ip = _detect_sensor_ip("127.0.0.1")
    interface = _resolve_network_interface(
        network_cfg.get("interface", "auto"),
        sensor_ip,
    )
    scouts_cfg = config.get("scouts", {})
    from squirrelops_home_sensor.privileged.helper import create_privileged_ops

    network_publisher = create_privileged_ops()

    return _OrchestratorWrapper(
        DecoyOrchestrator(
            event_bus=event_bus,
            db=db,
            max_decoys=max_decoys,
            credential_filename=config.get("credential_filename", "passwords.txt"),
            interface=interface,
            virtual_ip_range_start=scouts_cfg.get("virtual_ip_range_start", 200),
            virtual_ip_range_end=scouts_cfg.get("virtual_ip_range_end", 250),
            network_publisher=network_publisher,
        )
    )


def create_scouts_subsystem(
    config: dict[str, Any],
    db: Any,
    event_bus: Any,
    priv_ops: Any,
) -> dict[str, Any] | None:
    """Create the Squirrel Scouts subsystem (scout engine, scheduler, IP manager, mimic orchestrator).

    Returns a dict with 'scheduler', 'mimic_orchestrator', 'ip_manager' keys,
    or None if scouts are disabled.
    """
    scouts_cfg = config.get("scouts", {})
    if not scouts_cfg.get("enabled", True):
        logger.info("Squirrel Scouts disabled in config")
        return None

    from squirrelops_home_sensor.mdns import _get_mdns_hostname
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
    # Gateway is typically .1.
    first_host = str(next(network.hosts()))
    gateway_ip = first_host
    sensor_ip = _detect_sensor_ip(first_host)
    interface = _resolve_network_interface(
        network_cfg.get("interface", "auto"),
        sensor_ip,
    )

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
    max_mimics = scouts_cfg.get("max_mimic_decoys", 5)
    import socket

    sensor_hostnames = {
        _get_mdns_hostname(),
        socket.gethostname(),
        socket.getfqdn(),
    }
    mimic_orchestrator = MimicOrchestrator(
        scout_engine=scout_engine,
        template_generator=template_gen,
        ip_manager=ip_manager,
        event_bus=event_bus,
        db=db,
        max_mimics=max_mimics,
        mdns_advertiser=mimic_mdns,
        port_forward_manager=port_fwd,
        sensor_hostnames=sensor_hostnames,
        backend_bind_address_for=priv_ops.listener_bind_address,
    )
    # Every scheduled or manual scout cycle also fills available mimic capacity.
    scheduler.set_post_scout_hook(mimic_orchestrator.evaluate_and_deploy)

    logger.info(
        "Squirrel Scouts initialized: interval=%dm, max_mimics=%d, ip_range=.%d-.%d",
        interval,
        max_mimics,
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
        default=None,
        help="Port for the API server (default: config/env value or 8443)",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        default=False,
        help="Disable TLS (development only)",
    )
    parser.add_argument(
        "--show-pairing-code",
        action="store_true",
        default=False,
        help="Print the current one-time setup key from a running sensor and exit",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Pairing setup-key display
# ---------------------------------------------------------------------------


def _pairing_key_file(config: dict[str, Any]) -> Path:
    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    return data_dir / "pairing-key"


def _local_pairing_socket(config: dict[str, Any]) -> Path:
    configured = config.get("pairing", {}).get("socket_path")
    if configured:
        return Path(configured).expanduser()
    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    return data_dir.parent / "run" / "pairing.sock"


def _local_enrollment_socket(config: dict[str, Any]) -> Path:
    data_dir = Path(config.get("sensor", {}).get("data_dir", "./data"))
    return data_dir.parent / "run" / "enrollment.sock"


def _display_pairing_code(code: str, config: dict[str, Any]) -> None:
    """Print the setup key and store a private recovery copy.

    The file is mode 0600 inside the private data directory for an administrator
    or service operator using ``--show-pairing-code``; no secret is written to
    a shared temporary directory. Production never serves this key over a local
    socket because a connected descriptor can outlive or be passed away from
    the process identity checked at accept time.
    """
    from squirrelops_home_sensor.secure_io import atomic_write_private_text

    sensor_name = config.get("sensor", {}).get("name", "SquirrelOps")

    banner = (
        "\n"
        "╔════════════════════════════════════════════════════════════╗\n"
        "║                                                            ║\n"
        f"║   🐿️  {sensor_name} Sensor Setup Key\n"
        "║                                                            ║\n"
        f"║       {code}\n"
        "║                                                            ║\n"
        "║   Enter this key in the SquirrelOps Home app to pair.      ║\n"
        "║   It expires after 10 minutes or after it is used.         ║\n"
        "║                                                            ║\n"
        "╚════════════════════════════════════════════════════════════╝\n"
    )
    # Only show the setup key in an interactive terminal. Packaged launchd
    # stdout is a log file and must never receive pairing credentials.
    if sys.stdout.isatty():
        print(banner, flush=True)

    # Also log it so it appears in structured logs / journald
    key_file = _pairing_key_file(config)
    atomic_write_private_text(key_file, code + "\n")
    logger.info("Pairing setup key stored privately at %s", key_file)


# ---------------------------------------------------------------------------
# Main run coroutine
# ---------------------------------------------------------------------------


class _RuntimeResources:
    """Mutable ownership record for partially started sensor resources."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.db: Any | None = None
        self.retention_scheduler: Any | None = None
        self.retention_start_attempted = False
        self.orchestrator: Any | None = None
        self.orchestrator_start_attempted = False
        self.scan_loop: Any | None = None
        self.scan_start_attempted = False
        self.scout_scheduler: Any | None = None
        self.scout_scheduler_start_attempted = False
        self.mimic_orchestrator: Any | None = None
        self.mimic_start_attempted = False
        self.ip_manager: Any | None = None
        self.mimic_network_attempted = False
        self.mimic_network_state_known = False
        self.mimic_mdns: Any | None = None
        self.mimic_mdns_start_attempted = False
        self.port_fwd: Any | None = None
        self.mdns: Any | None = None
        self.mdns_start_attempted = False
        self.local_pairing: Any | None = None
        self.local_pairing_start_attempted = False
        self.local_enrollment: Any | None = None
        self.local_enrollment_start_attempted = False
        self.cleaned = False


async def _cleanup_runtime(runtime: _RuntimeResources) -> list[BaseException]:
    """Unwind all attempted startup steps without skipping later cleanup."""
    if runtime.cleaned:
        return []
    runtime.cleaned = True
    errors: list[BaseException] = []

    async def stop_step(label: str, operation: Any) -> Any | None:
        logger.info("%s...", label)
        try:
            result = operation()
            if inspect.isawaitable(result):
                return await result
            return result
        except BaseException as exc:
            errors.append(exc)
            logger.exception("%s failed during sensor shutdown", label)
            return None

    if (
        runtime.retention_scheduler is not None
        and runtime.retention_start_attempted
    ):
        await stop_step(
            "Stopping alert retention scheduler",
            runtime.retention_scheduler.stop,
        )

    if runtime.local_pairing is not None and runtime.local_pairing_start_attempted:
        await stop_step(
            "Stopping local pairing socket",
            runtime.local_pairing.stop,
        )

    if runtime.local_enrollment is not None and runtime.local_enrollment_start_attempted:
        await stop_step(
            "Stopping local enrollment socket",
            runtime.local_enrollment.stop,
        )

    if runtime.mdns is not None and runtime.mdns_start_attempted:
        await stop_step("Stopping mDNS advertisement", runtime.mdns.stop)

    if runtime.scan_loop is not None and runtime.scan_start_attempted:
        await stop_step("Stopping scan loop", runtime.scan_loop.stop)

    if runtime.scout_scheduler is not None and runtime.scout_scheduler_start_attempted:
        await stop_step(
            "Stopping scout scheduler",
            runtime.scout_scheduler.stop,
        )

    if runtime.mimic_orchestrator is not None and (
        runtime.mimic_start_attempted or runtime.mimic_network_attempted
    ):
        await stop_step(
            "Stopping mimic orchestrator",
            runtime.mimic_orchestrator.stop_all,
        )

    if runtime.mimic_mdns is not None and runtime.mimic_mdns_start_attempted:
        await stop_step(
            "Stopping mimic mDNS advertiser",
            runtime.mimic_mdns.stop,
        )

    if runtime.ip_manager is not None and runtime.mimic_network_attempted:
        logger.info("Removing virtual IP aliases...")
        alias_state_known = True
        try:
            removed = await runtime.ip_manager.remove_all()
            if removed:
                logger.info("Removed %d virtual IP aliases", removed)
        except BaseException as exc:
            alias_state_known = False
            errors.append(exc)
            logger.exception("Removing virtual IP aliases failed during sensor shutdown")

        active_ips: set[str] = set()
        if alias_state_known:
            try:
                active_ips = set(runtime.ip_manager.active_ips)
            except BaseException as exc:
                alias_state_known = False
                errors.append(exc)
                logger.exception("Could not verify virtual IP alias state during shutdown")

        if not runtime.mimic_network_state_known:
            logger.critical(
                "Retaining packet-filter isolation because persisted virtual "
                "IP reconciliation did not complete"
            )
        elif not alias_state_known:
            logger.critical(
                "Retaining packet-filter isolation because virtual IP alias "
                "removal could not be verified"
            )
        elif active_ips:
            logger.critical(
                "Retaining packet-filter isolation because %d virtual IP "
                "alias(es) could not be removed: %s",
                len(active_ips),
                ", ".join(sorted(active_ips)),
            )
        elif runtime.port_fwd is not None:
            clear_result = await stop_step(
                "Clearing port forwarding rules",
                runtime.port_fwd.clear_all,
            )
            if clear_result is False:
                error = RuntimeError("Failed to clear port forwarding rules")
                errors.append(error)
                logger.error("%s", error)

    if runtime.orchestrator is not None and runtime.orchestrator_start_attempted:
        await stop_step(
            "Stopping decoy orchestrator",
            runtime.orchestrator.stop,
        )

    if runtime.db is not None:
        await stop_step("Closing database", runtime.db.close)

    try:
        _pairing_key_file(runtime.config).unlink(missing_ok=True)
    except OSError:
        logger.warning(
            "Could not remove the ephemeral pairing setup-key file",
            exc_info=True,
        )

    if not errors:
        logger.info("Sensor shutdown complete")
    else:
        logger.error(
            "Sensor shutdown completed with %d cleanup error(s)",
            len(errors),
        )
    return errors


async def run_sensor(
    config_path: str | None = None,
    port: int | None = None,
    no_tls: bool = False,
) -> None:
    """Start the sensor and run until cancelled.

    This is the top-level coroutine that wires all subsystems together.
    It is designed to be called from ``main()`` or directly in tests.
    """
    # 1. Load config
    config: dict[str, Any] = load_config(config_path)

    config.setdefault("sensor", {})
    if port is not None:
        config["sensor"]["port"] = port
    port = int(config.get("sensor", {}).get("port", 8443))
    no_tls = no_tls or not bool(config.get("sensor", {}).get("tls", {}).get("enabled", True))
    if no_tls:
        config["sensor"].setdefault("tls", {})
        config["sensor"]["tls"]["enabled"] = False

    runtime = _RuntimeResources(config)
    try:
        # Configuration credentials live in the encrypted store, not YAML.
        # Existing plaintext values are migrated before any subsystem reads
        # them, and the legacy YAML copy is scrubbed atomically.
        from squirrelops_home_sensor.config_vault import (
            hydrate_vaulted_config_secrets,
            scrub_persisted_config_file,
        )

        secret_store = create_secret_store(config)
        await hydrate_vaulted_config_secrets(config, secret_store)
        config_data_dir = Path(
            config.get("sensor", {}).get("data_dir", "./data")
        )
        if scrub_persisted_config_file(config_data_dir):
            logger.warning(
                "Migrated plaintext configuration credentials into encrypted storage"
            )

        # 2. Open database
        data_dir = config.get("sensor", {}).get("data_dir", "./data")
        db = await open_db(Path(data_dir) / "squirrelops.db")
        runtime.db = db

        # 3. Run migrations
        await run_migrations(db)

        # 3a. Start daily history retention only after the schema is current.
        # The scheduler uses a separate SQLite connection and runs once
        # immediately, then every 24 hours.
        retention_scheduler = create_retention_scheduler(config)
        runtime.retention_scheduler = retention_scheduler
        runtime.retention_start_attempted = True
        await retention_scheduler.start()

        # 3b. Init TLS certs (unless --no-tls)
        ca_key = None
        ca_cert = None
        ssl_certfile = None
        ssl_keyfile = None
        if not no_tls:
            from squirrelops_home_sensor.tls import ensure_tls_certs

            data_dir_path = Path(config.get("sensor", {}).get("data_dir", "./data"))
            sensor_name = config.get("sensor", {}).get(
                "name",
                "SquirrelOps",
            )
            cert_path, key_path, ca_key, ca_cert = await ensure_tls_certs(
                secret_store,
                data_dir=data_dir_path,
                sensor_name=sensor_name,
            )
            ssl_certfile = str(cert_path)
            ssl_keyfile = str(key_path)

        # 4. Init event bus
        event_bus = create_event_bus(db)

        # 4b. Prune orphaned events from the replay log to prevent phantom
        # decoys/alerts from appearing in the app after WebSocket replay.
        pruned = await event_bus._log.prune_orphaned_events()
        if pruned:
            logger.info("Pruned %d orphaned events at startup", pruned)

        # 5. Init scan loop
        scan_loop = create_scan_loop(
            config=config,
            db=db,
            event_bus=event_bus,
        )
        runtime.scan_loop = scan_loop

        # 6. Init decoy orchestrator
        orchestrator = create_orchestrator(
            config=config,
            db=db,
            event_bus=event_bus,
        )
        runtime.orchestrator = orchestrator

        # 6b. Init Squirrel Scouts subsystem (scout engine, scheduler, IP
        # manager, mimics).
        priv_ops = scan_loop.privileged_ops
        scouts = create_scouts_subsystem(
            config=config,
            db=db,
            event_bus=event_bus,
            priv_ops=priv_ops,
        )
        scout_scheduler = scouts["scheduler"] if scouts else None
        mimic_orchestrator = scouts["mimic_orchestrator"] if scouts else None
        ip_manager = scouts["ip_manager"] if scouts else None
        mimic_mdns = scouts["mimic_mdns"] if scouts else None
        port_fwd = scouts["port_forward_manager"] if scouts else None
        runtime.scout_scheduler = scout_scheduler
        runtime.mimic_orchestrator = mimic_orchestrator
        runtime.ip_manager = ip_manager
        runtime.mimic_mdns = mimic_mdns
        runtime.port_fwd = port_fwd
        if mimic_orchestrator is not None:
            scan_loop.set_hostname_advisor_target(mimic_orchestrator)
            # Reuse every regular scan's fresh ARP snapshot to evacuate
            # conflicts before virtual IPs are filtered from device inventory.
            conflict_hook_result = scan_loop.set_ip_conflict_handler(
                mimic_orchestrator.reconcile_ip_conflicts
            )
            if inspect.isawaitable(conflict_hook_result):
                await conflict_hook_result

        # 7. Create FastAPI app
        app = create_app(config=config, ca_key=ca_key, ca_cert=ca_cert)

        # 7b. Wire up dependency overrides for production
        from squirrelops_home_sensor.api.deps import (
            get_config as _get_config_dep,
        )
        from squirrelops_home_sensor.api.deps import get_db as _get_db_dep
        from squirrelops_home_sensor.api.deps import (
            get_event_bus as _get_event_bus_dep,
        )
        from squirrelops_home_sensor.api.deps import (
            get_privileged_ops as _get_priv_ops_dep,
        )
        from squirrelops_home_sensor.api.deps import (
            get_secret_store as _get_secret_store_dep,
        )
        from squirrelops_home_sensor.api.routes_system import (
            get_scan_loop as _get_scan_loop_dep,
        )

        async def _prod_get_db():
            yield db

        async def _prod_get_config():
            return config

        async def _prod_get_event_bus():
            return event_bus

        async def _prod_get_priv_ops():
            return priv_ops

        async def _prod_get_secret_store():
            return secret_store

        async def _prod_get_scan_loop():
            return scan_loop

        app.dependency_overrides[_get_db_dep] = _prod_get_db
        app.dependency_overrides[_get_config_dep] = _prod_get_config
        app.dependency_overrides[_get_event_bus_dep] = _prod_get_event_bus
        app.dependency_overrides[_get_priv_ops_dep] = _prod_get_priv_ops
        app.dependency_overrides[_get_secret_store_dep] = _prod_get_secret_store
        app.dependency_overrides[_get_scan_loop_dep] = _prod_get_scan_loop

        # 7b2. Wire scouts API dependencies
        from squirrelops_home_sensor.api.routes_scouts import (
            get_mimic_orchestrator as _get_mimic_dep,
        )
        from squirrelops_home_sensor.api.routes_scouts import (
            get_scout_scheduler as _get_sched_dep,
        )

        async def _prod_get_scout_scheduler():
            return scout_scheduler

        async def _prod_get_mimic_orchestrator():
            return mimic_orchestrator

        app.dependency_overrides[_get_sched_dep] = _prod_get_scout_scheduler
        app.dependency_overrides[_get_mimic_dep] = _prod_get_mimic_orchestrator

        # 7b3. Wire decoy orchestrator into decoy routes
        from squirrelops_home_sensor.api.routes_decoys import (
            get_decoy_orchestrator as _get_decoy_orch_dep,
        )

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

        # 7c2. Wire alert pipeline: decoy events → alerts → incidents →
        # dispatch.
        from squirrelops_home_sensor.alerts.decoy_handler import (
            DecoyAlertHandler,
        )
        from squirrelops_home_sensor.alerts.dispatcher import (
            ConfigurableAlertDispatcher,
        )
        from squirrelops_home_sensor.alerts.incidents import IncidentGrouper

        incident_grouper = IncidentGrouper(db=db, event_bus=event_bus)

        alert_dispatcher = ConfigurableAlertDispatcher(config)
        alert_dispatcher.subscribe_to(event_bus)

        decoy_alert_handler = DecoyAlertHandler(
            db=db,
            event_bus=event_bus,
            incident_grouper=incident_grouper,
        )
        decoy_alert_handler.subscribe_to(event_bus)

        # 7d. Wire orchestrator into scan loop for auto-deploy
        scan_loop.set_orchestrator(orchestrator.inner)
        logger.info("Decoy orchestrator wired to scan loop for auto-deploy")

        # 8. Start subsystems (resume decoys first, then start scanning).
        # Flags are set before awaiting start so a component that starts
        # partially and then raises is still asked to unwind.
        runtime.orchestrator_start_attempted = True
        await orchestrator.start()

        # 8b. Start scouts subsystem (restore virtual IPs, resume mimics,
        # start scheduler).
        if scouts:
            missing_components = [
                name
                for name, component in (
                    ("scheduler", scout_scheduler),
                    ("orchestrator", mimic_orchestrator),
                    ("IP manager", ip_manager),
                    ("mDNS advertiser", mimic_mdns),
                    ("port-forward manager", port_fwd),
                )
                if component is None
            ]
            if missing_components:
                raise RuntimeError(
                    "Squirrel Scouts initialization omitted: "
                    + ", ".join(missing_components)
                )
            if not await priv_ops.is_available():
                raise RuntimeError("Squirrel Scouts require a compatible privileged helper")

            runtime.mimic_mdns_start_attempted = True
            await mimic_mdns.start()

            runtime.mimic_network_attempted = True
            # Reserve durable addresses without publishing them. The
            # orchestrator first installs an atomic deny-all quarantine
            # for the complete persisted set, then resumes each listener.
            await ip_manager.load_from_db(restore_aliases=False)
            cleaned = await mimic_orchestrator.prepare_persisted_network()
            if cleaned:
                logger.info(
                    "Removed %d orphaned or stopped virtual IP aliases",
                    cleaned,
                )
            runtime.mimic_network_state_known = True

            runtime.mimic_start_attempted = True
            resumed = await mimic_orchestrator.resume_active()
            if resumed:
                logger.info("Resumed %d mimic decoys", resumed)
            runtime.scout_scheduler_start_attempted = True
            await scout_scheduler.start()

        runtime.scan_start_attempted = True
        await scan_loop.start()

        # 9. Configure and start uvicorn
        uvicorn_kwargs: dict[str, Any] = {}
        if ssl_certfile and ssl_keyfile:
            uvicorn_kwargs["ssl_certfile"] = ssl_certfile
            uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile
            uvicorn_kwargs["ssl_cert_reqs"] = ssl.CERT_OPTIONAL
            uvicorn_kwargs["ssl_ca_certs"] = str(Path(config["sensor"]["data_dir"]) / "ca.crt")

        from squirrelops_home_sensor.tls_client_auth import (
            ClientCertH11Protocol,
            ClientCertWebSocketProtocol,
        )

        bind_host = "127.0.0.1" if no_tls else "0.0.0.0"
        if no_tls:
            logger.warning(
                "TLS disabled for development; API restricted to %s",
                bind_host,
            )

        uvicorn_config = uvicorn.Config(
            app=app,
            host=bind_host,
            port=port,
            log_level="info",
            log_config=None,
            http=ClientCertH11Protocol,
            ws=ClientCertWebSocketProtocol,
            proxy_headers=False,
            **uvicorn_kwargs,
        )
        server = uvicorn.Server(uvicorn_config)

        # 10. Start mDNS advertisement
        mdns = create_mdns_advertiser(config, port)
        runtime.mdns = mdns
        runtime.mdns_start_attempted = True
        await mdns.start()

        # Generate the one-time setup key before the app connects.
        from squirrelops_home_sensor.api.routes_pairing import (
            _init_pairing_state,
            _maybe_regenerate_code,
        )

        pairing_state = _init_pairing_state(app.state, config)

        # Display the pairing setup key and store a private recovery copy.
        pairing_code = getattr(app.state, "pairing_code", None)
        if isinstance(pairing_code, str) and pairing_code:
            _display_pairing_code(pairing_code, config)

        local_enrollment_enabled = bool(
            config.get("pairing", {}).get(
                "local_enrollment_enabled",
                False,
            )
        )
        if local_enrollment_enabled:
            from squirrelops_home_sensor.api.local_enrollment import (
                LocalEnrollmentAuthority,
                LocalEnrollmentServer,
            )

            sensor_config = config.get("sensor", {})
            authority = LocalEnrollmentAuthority(
                db=db,
                ca_key=pairing_state["ca_key"],
                ca_cert=pairing_state["ca_cert"],
                sensor_id=str(
                    sensor_config.get("id")
                    or config.get("sensor_id")
                    or "squirrelops-local"
                ),
                sensor_name=str(
                    sensor_config.get("name")
                    or config.get("sensor_name")
                    or "SquirrelOps Home Sensor"
                ),
            )
            app.state.local_enrollment_authority = authority
            local_enrollment = LocalEnrollmentServer(
                str(_local_enrollment_socket(config)),
                authority,
            )
            runtime.local_enrollment = local_enrollment
            runtime.local_enrollment_start_attempted = True
            await local_enrollment.start()

        # The local socket is deliberately development-only. Kernel peer
        # identity authenticates the process that connected, not necessarily
        # the process that later reads or writes a passed descriptor. Production
        # pairing therefore requires the administrator-readable setup key.
        if bool(
            config.get("pairing", {}).get(
                "allow_unsigned_local",
                False,
            )
        ):
            from squirrelops_home_sensor.api.local_pairing import (
                LocalPairingServer,
            )

            def _get_local_pairing_code() -> str:
                state = _init_pairing_state(app.state, config)
                _maybe_regenerate_code(state)
                return state["code"]

            local_pairing = LocalPairingServer(
                str(_local_pairing_socket(config)),
                _get_local_pairing_code,
                allowed_app_requirement=None,
                allow_unsigned_local=True,
            )
            runtime.local_pairing = local_pairing
            runtime.local_pairing_start_attempted = True
            try:
                await local_pairing.start()
            except Exception:
                logger.warning(
                    "Failed to start development local pairing socket",
                    exc_info=True,
                )
        elif local_enrollment_enabled:
            logger.info(
                "Development setup-key socket disabled; signed-app local "
                "enrollment enabled"
            )
        else:
            logger.info(
                "Local enrollment disabled; retrieve the setup key "
                "with --show-pairing-code"
            )

        try:
            await server.serve()
        except asyncio.CancelledError:
            logger.info("Shutdown signal received -- stopping sensor")
    finally:
        startup_or_run_failed = sys.exc_info()[0] is not None
        cleanup_errors = await _cleanup_runtime(runtime)
        if cleanup_errors and not startup_or_run_failed:
            raise RuntimeError("Sensor shutdown did not complete cleanly") from cleanup_errors[0]


# ---------------------------------------------------------------------------
# Script entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI args and run the sensor."""
    configure_logging()

    args = parse_args()

    if args.show_pairing_code:
        config = load_config(args.config)
        key_file = _pairing_key_file(config)
        try:
            code = key_file.read_text(encoding="utf-8").strip()
            print(f"Current pairing setup key: {code}")
        except FileNotFoundError:
            print("No pairing setup key found. Is the sensor running?")
        except PermissionError:
            print(f"Permission denied reading {key_file}; run as the sensor service user or root.")
        sys.exit(0)

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
