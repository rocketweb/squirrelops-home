"""Decoy orchestrator — selection, deployment, health monitoring, and event handling.

The orchestrator is the central manager for all active decoys. It:
- Selects which decoy types to deploy based on discovered network services
- Auto-deploys decoys after the first scan if none exist
- Resumes previously active decoys from the database at startup
- Deploys and tracks decoy instances
- Monitors health and implements the ACTIVE -> RESTARTING -> DEGRADED state machine
- Processes connection events from decoys and publishes to the event bus
- Enforces resource profile limits on max active decoys
"""

from __future__ import annotations

import asyncio
import enum
import json as json_mod
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Protocol, runtime_checkable

from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEV_PORTS = {3000, 3001, 5173, 8000, 8080}
_HA_PORTS = {8123}
_FILE_SHARE_PORTS = {445, 548}
_HA_MDNS_SERVICE = "_home-assistant._tcp"
_MAX_FAILURES_BEFORE_DEGRADED = 3
_FAILURE_WINDOW = timedelta(minutes=5)
_DEGRADED_RETRY_INTERVAL = timedelta(minutes=30)

_DECOY_NAMES = {
    "file_share": "Network Share",
    "dev_server": "Dev Server",
    "home_assistant": "Smart Home",
}


# ---------------------------------------------------------------------------
# Health states
# ---------------------------------------------------------------------------

class DecoyHealth(enum.Enum):
    """Health states for a managed decoy."""

    ACTIVE = "active"
    RESTARTING = "restarting"
    DEGRADED = "degraded"
    STOPPED = "stopped"


# ---------------------------------------------------------------------------
# Decoy record
# ---------------------------------------------------------------------------

class DecoyRecord:
    """Internal tracking record for a deployed decoy.

    Attributes:
        decoy: The BaseDecoy instance.
        health: Current health state.
        failure_count: Number of consecutive restart failures.
        last_failure_at: When the most recent failure occurred.
        failure_window_start: Start of the current failure counting window.
    """

    def __init__(self, decoy: BaseDecoy) -> None:
        self.decoy = decoy
        self.health = DecoyHealth.ACTIVE
        self.failure_count: int = 0
        self.last_failure_at: Optional[datetime] = None
        self.failure_window_start: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------

@runtime_checkable
class EventBusProtocol(Protocol):
    async def publish(self, event_type: str, payload: dict) -> int: ...


@runtime_checkable
class DBProtocol(Protocol):
    """Minimal DB interface for the orchestrator."""
    ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_config(raw: Optional[str]) -> dict:
    """Parse a JSON config string from the DB, returning an empty dict on failure."""
    if not raw:
        return {}
    try:
        return json_mod.loads(raw)
    except (json_mod.JSONDecodeError, TypeError):
        return {}


def _generate_credentials(decoy_type: str) -> list:
    """Generate appropriate planted credentials for a decoy type."""
    from squirrelops_home_sensor.decoys.credentials import CredentialGenerator

    gen = CredentialGenerator()
    if decoy_type == "file_share":
        creds = gen.generate_passwords_file()
        creds.append(gen.generate_ssh_key())
        return creds
    elif decoy_type == "dev_server":
        return [gen.generate_env_file()]
    elif decoy_type == "home_assistant":
        return [gen.generate_ha_token()]
    else:
        return gen.generate_passwords_file()


def _create_decoy_instance(
    decoy_type: str,
    decoy_id: int,
    name: str,
    port: int,
    bind_address: str,
    credentials: list,
    config: Optional[dict] = None,
) -> BaseDecoy:
    """Factory for creating BaseDecoy subclass instances."""
    from squirrelops_home_sensor.decoys.types.dev_server import DevServerDecoy
    from squirrelops_home_sensor.decoys.types.file_share import FileShareDecoy
    from squirrelops_home_sensor.decoys.types.home_assistant import HomeAssistantDecoy

    if decoy_type == "dev_server":
        return DevServerDecoy(
            decoy_id=decoy_id, name=name, port=port,
            bind_address=bind_address, planted_credentials=credentials,
        )
    elif decoy_type == "home_assistant":
        return HomeAssistantDecoy(
            decoy_id=decoy_id, name=name, port=port,
            bind_address=bind_address, planted_credentials=credentials,
        )
    else:
        return FileShareDecoy(
            decoy_id=decoy_id, name=name, port=port,
            bind_address=bind_address, planted_credentials=credentials,
            config=config,
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class DecoyOrchestrator:
    """Central manager for decoy lifecycle and health.

    Args:
        event_bus: Event bus for publishing decoy events.
        db: Database interface for persisting decoy state.
        max_decoys: Maximum number of concurrent decoys (from resource profile).
    """

    def __init__(
        self,
        event_bus: EventBusProtocol,
        db: DBProtocol,
        max_decoys: int = 8,
    ) -> None:
        self._event_bus = event_bus
        self._db = db
        self._max_decoys = max_decoys
        self._records: dict[int, DecoyRecord] = {}

    # -----------------------------------------------------------------
    # Selection
    # -----------------------------------------------------------------

    def select_decoys(
        self,
        discovered_services: list[dict],
        mdns_services: set[str],
    ) -> list[dict]:
        """Select decoy types based on discovered network services.

        Examines open ports and mDNS services to decide which decoy types
        are appropriate for the network. Returns a list of candidate dicts
        with 'decoy_type' and suggested port info, trimmed to max_decoys.

        Args:
            discovered_services: List of dicts with 'ip', 'port', 'protocol'.
            mdns_services: Set of mDNS service type strings.

        Returns:
            List of candidate dicts: [{"decoy_type": str, ...}, ...]
        """
        if self._max_decoys == 0:
            return []

        candidates: list[dict] = []
        open_ports = {s["port"] for s in discovered_services}

        # Dev server decoy — if dev ports detected
        if open_ports & _DEV_PORTS:
            candidates.append({"decoy_type": "dev_server"})

        # Home Assistant decoy — if HA mDNS or port 8123
        if _HA_MDNS_SERVICE in mdns_services or (open_ports & _HA_PORTS):
            candidates.append({"decoy_type": "home_assistant"})

        # File share decoy — if SMB/AFP ports detected
        if open_ports & _FILE_SHARE_PORTS:
            candidates.append({"decoy_type": "file_share"})

        # Fallback: deploy a file share if nothing was detected
        if len(candidates) == 0:
            candidates.append({"decoy_type": "file_share"})

        return candidates[: self._max_decoys]

    # -----------------------------------------------------------------
    # Auto-deploy and resume
    # -----------------------------------------------------------------

    async def resume_active(self) -> int:
        """Load and start active decoys from the database.

        Called at startup to resume decoys that were running before the sensor
        was stopped. Returns the number of decoys resumed.
        """
        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE status = 'active' AND decoy_type != 'mimic'"
        )
        rows = await cursor.fetchall()
        if not rows:
            return 0

        resumed = 0
        for row in rows:
            try:
                creds = await self._load_credentials(row["id"])
                config = _parse_config(row["config"])
                decoy = _create_decoy_instance(
                    decoy_type=row["decoy_type"],
                    decoy_id=row["id"],
                    name=row["name"],
                    port=row["port"],
                    bind_address=row["bind_address"],
                    credentials=creds,
                    config=config,
                )
                await self.deploy_decoy(decoy)
                resumed += 1
            except Exception:
                logger.exception(
                    "Failed to resume decoy '%s' (id=%d)", row["name"], row["id"],
                )
                now = datetime.now(timezone.utc).isoformat()
                await self._db.execute(
                    "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                await self._db.commit()

        logger.info("Resumed %d active decoys from database", resumed)
        return resumed

    async def auto_deploy(
        self,
        discovered_services: list[dict],
        mdns_services: set[str] | None = None,
    ) -> int:
        """Auto-deploy decoys based on scan results if none exist.

        Called after each scan cycle. Checks if any decoys exist in the
        database. If none, selects decoy types based on discovered network
        services, creates instances with planted credentials, persists
        to the database, and starts the decoy servers.

        Returns the number of decoys deployed.
        """
        cursor = await self._db.execute("SELECT COUNT(*) FROM decoys")
        count = (await cursor.fetchone())[0]
        if count > 0:
            return 0

        candidates = self.select_decoys(discovered_services, mdns_services or set())
        if not candidates:
            return 0

        deployed = 0
        for candidate in candidates:
            decoy_type = candidate["decoy_type"]
            try:
                decoy, now = await self._create_and_persist(decoy_type)
                await self.deploy_decoy(decoy)

                # Update port in DB (may have been OS-assigned from port=0)
                await self._db.execute(
                    "UPDATE decoys SET port = ?, updated_at = ? WHERE id = ?",
                    (decoy.port, now, decoy.decoy_id),
                )
                await self._db.commit()

                # Publish full status for the app to pick up via WebSocket
                await self._event_bus.publish(
                    "decoy.status_changed",
                    {
                        "id": decoy.decoy_id,
                        "name": decoy.name,
                        "decoy_type": decoy.decoy_type,
                        "bind_address": decoy.bind_address,
                        "port": decoy.port,
                        "status": "active",
                        "connection_count": 0,
                        "credential_trip_count": 0,
                        "created_at": now,
                        "updated_at": now,
                    },
                )
                deployed += 1
            except Exception:
                logger.exception("Failed to auto-deploy %s decoy", decoy_type)

        logger.info("Auto-deployed %d decoys", deployed)
        return deployed

    async def _create_and_persist(self, decoy_type: str) -> tuple[BaseDecoy, str]:
        """Create a decoy instance, generate credentials, and persist to DB.

        Returns (decoy_instance, created_at_iso_string).
        """
        name = _DECOY_NAMES.get(decoy_type, decoy_type.replace("_", " ").title())
        now = datetime.now(timezone.utc).isoformat()
        creds = _generate_credentials(decoy_type)

        # Build default config per decoy type
        config: dict = {}
        if decoy_type == "file_share":
            config["password_filename"] = "passwords.txt"

        # Insert decoy row to get the ID
        cursor = await self._db.execute(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES (?, ?, '0.0.0.0', 0, 'active', ?, ?, ?)""",
            (name, decoy_type, json_mod.dumps(config), now, now),
        )
        await self._db.commit()
        decoy_id = cursor.lastrowid

        # Persist planted credentials
        for cred in creds:
            await self._db.execute(
                """INSERT INTO planted_credentials
                   (credential_type, credential_value, planted_location,
                    decoy_id, canary_hostname, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (cred.credential_type, cred.credential_value,
                 cred.planted_location, decoy_id, cred.canary_hostname, now),
            )
        await self._db.commit()

        decoy = _create_decoy_instance(
            decoy_type=decoy_type,
            decoy_id=decoy_id,
            name=name,
            port=0,
            bind_address="0.0.0.0",
            credentials=creds,
            config=config,
        )
        return decoy, now

    async def _load_credentials(self, decoy_id: int) -> list:
        """Load planted credentials for a decoy from the database."""
        from squirrelops_home_sensor.decoys.credentials import GeneratedCredential

        cursor = await self._db.execute(
            "SELECT * FROM planted_credentials WHERE decoy_id = ?",
            (decoy_id,),
        )
        rows = await cursor.fetchall()
        return [
            GeneratedCredential(
                credential_type=row["credential_type"],
                credential_value=row["credential_value"],
                planted_location=row["planted_location"],
                canary_hostname=row["canary_hostname"],
            )
            for row in rows
        ]

    # -----------------------------------------------------------------
    # Deployment
    # -----------------------------------------------------------------

    async def deploy_decoy(self, decoy: BaseDecoy) -> None:
        """Deploy a decoy: start it, register the connection callback, and track it.

        Args:
            decoy: The BaseDecoy instance to deploy.
        """
        # Register connection callback
        decoy.on_connection = self._handle_connection

        await decoy.start()

        record = DecoyRecord(decoy)
        self._records[decoy.decoy_id] = record

        await self._event_bus.publish(
            "decoy.health_changed",
            {
                "decoy_id": decoy.decoy_id,
                "name": decoy.name,
                "decoy_type": decoy.decoy_type,
                "health": DecoyHealth.ACTIVE.value,
                "port": decoy.port,
            },
        )

        logger.info(
            "Deployed decoy '%s' (id=%d) on port %d",
            decoy.name,
            decoy.decoy_id,
            decoy.port,
        )

    def get_decoy(self, decoy_id: int) -> Optional[DecoyRecord]:
        """Return the DecoyRecord for a given decoy ID, or None."""
        return self._records.get(decoy_id)

    async def stop_all(self) -> None:
        """Stop all deployed decoys."""
        for record in self._records.values():
            try:
                await record.decoy.stop()
                record.health = DecoyHealth.STOPPED
            except Exception:
                logger.exception("Error stopping decoy %d", record.decoy.decoy_id)

    # -----------------------------------------------------------------
    # Health monitoring
    # -----------------------------------------------------------------

    async def check_health(self) -> None:
        """Check health of all ACTIVE decoys and attempt restart on failure.

        State machine:
            ACTIVE -> crash detected -> attempt restart
            restart succeeds -> ACTIVE
            restart fails -> increment failure_count
            3 failures within 5 min -> DEGRADED
        """
        now = datetime.now(timezone.utc)

        for record in list(self._records.values()):
            if record.health in (DecoyHealth.DEGRADED, DecoyHealth.STOPPED):
                continue

            healthy = await record.decoy.health_check()
            if healthy:
                continue

            # Decoy is unhealthy — attempt restart
            logger.warning(
                "Decoy '%s' (id=%d) health check failed, attempting restart",
                record.decoy.name,
                record.decoy.decoy_id,
            )

            record.health = DecoyHealth.RESTARTING

            # Reset failure window if too old
            if (
                record.failure_window_start is None
                or (now - record.failure_window_start) > _FAILURE_WINDOW
            ):
                record.failure_count = 0
                record.failure_window_start = now

            try:
                await record.decoy.start()
                record.health = DecoyHealth.ACTIVE
                logger.info(
                    "Decoy '%s' (id=%d) restarted successfully",
                    record.decoy.name,
                    record.decoy.decoy_id,
                )
            except Exception:
                record.failure_count += 1
                record.last_failure_at = now
                logger.exception(
                    "Decoy '%s' (id=%d) restart failed (%d/%d)",
                    record.decoy.name,
                    record.decoy.decoy_id,
                    record.failure_count,
                    _MAX_FAILURES_BEFORE_DEGRADED,
                )

                if record.failure_count >= _MAX_FAILURES_BEFORE_DEGRADED:
                    record.health = DecoyHealth.DEGRADED
                    await self._event_bus.publish(
                        "decoy.health_changed",
                        {
                            "decoy_id": record.decoy.decoy_id,
                            "name": record.decoy.name,
                            "health": DecoyHealth.DEGRADED.value,
                            "failure_count": record.failure_count,
                        },
                    )
                    logger.error(
                        "Decoy '%s' (id=%d) degraded after %d failures",
                        record.decoy.name,
                        record.decoy.decoy_id,
                        record.failure_count,
                    )
                else:
                    record.health = DecoyHealth.ACTIVE  # Will retry next check

    async def check_degraded(self) -> None:
        """Attempt recovery of DEGRADED decoys past the retry interval.

        Called periodically (e.g. every 5 minutes). If a degraded decoy's
        last failure is older than 30 minutes, attempts a restart.
        """
        now = datetime.now(timezone.utc)

        for record in list(self._records.values()):
            if record.health != DecoyHealth.DEGRADED:
                continue

            if (
                record.last_failure_at is not None
                and (now - record.last_failure_at) < _DEGRADED_RETRY_INTERVAL
            ):
                continue

            logger.info(
                "Attempting recovery of degraded decoy '%s' (id=%d)",
                record.decoy.name,
                record.decoy.decoy_id,
            )

            try:
                await record.decoy.start()
                record.health = DecoyHealth.ACTIVE
                record.failure_count = 0
                record.failure_window_start = None

                await self._event_bus.publish(
                    "decoy.health_changed",
                    {
                        "decoy_id": record.decoy.decoy_id,
                        "name": record.decoy.name,
                        "health": DecoyHealth.ACTIVE.value,
                    },
                )
                logger.info(
                    "Degraded decoy '%s' (id=%d) recovered",
                    record.decoy.name,
                    record.decoy.decoy_id,
                )
            except Exception:
                record.last_failure_at = now
                logger.exception(
                    "Recovery of degraded decoy '%s' (id=%d) failed",
                    record.decoy.name,
                    record.decoy.decoy_id,
                )

    # -----------------------------------------------------------------
    # Manual restart
    # -----------------------------------------------------------------

    async def restart_decoy(self, decoy_id: int) -> None:
        """Manually restart a decoy, rebuilding from DB to pick up config changes.

        Args:
            decoy_id: ID of the decoy to restart.

        Raises:
            KeyError: If decoy_id is not tracked.
        """
        record = self._records.get(decoy_id)
        if record is None:
            raise KeyError(f"Decoy {decoy_id} not found")

        await record.decoy.stop()

        # Rebuild from DB to pick up any config changes
        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE id = ?", (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is not None:
            creds = await self._load_credentials(decoy_id)
            config = _parse_config(row["config"])
            new_decoy = _create_decoy_instance(
                decoy_type=row["decoy_type"],
                decoy_id=decoy_id,
                name=row["name"],
                port=record.decoy.port,
                bind_address=record.decoy.bind_address,
                credentials=creds,
                config=config,
            )
            new_decoy.on_connection = self._handle_connection
            await new_decoy.start()
            record.decoy = new_decoy
        else:
            await record.decoy.start()

        record.health = DecoyHealth.ACTIVE
        record.failure_count = 0
        record.failure_window_start = None

        await self._event_bus.publish(
            "decoy.health_changed",
            {
                "decoy_id": decoy_id,
                "name": record.decoy.name,
                "health": DecoyHealth.ACTIVE.value,
            },
        )

        logger.info("Decoy '%s' (id=%d) manually restarted", record.decoy.name, decoy_id)

    # -----------------------------------------------------------------
    # Connection handling
    # -----------------------------------------------------------------

    def _handle_connection(self, event: DecoyConnectionEvent) -> None:
        """Process a connection event from a decoy.

        Publishes decoy.trip for all connections, and additionally
        decoy.credential_trip if a planted credential was detected.
        Runs event publishing in a fire-and-forget task.
        """
        asyncio.get_event_loop().create_task(self._async_handle_connection(event))

    async def _async_handle_connection(self, event: DecoyConnectionEvent) -> None:
        """Async handler for connection events."""
        # Publish decoy.trip for every connection
        await self._event_bus.publish(
            "decoy.trip",
            {
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "request_path": event.request_path,
                "timestamp": event.timestamp.isoformat(),
            },
        )

        # If credential was detected, publish credential_trip
        if event.credential_used is not None:
            await self._event_bus.publish(
                "decoy.credential_trip",
                {
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "dest_port": event.dest_port,
                    "credential_used": event.credential_used,
                    "request_path": event.request_path,
                    "timestamp": event.timestamp.isoformat(),
                    "detection_method": "decoy_http",
                },
            )
