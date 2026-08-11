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
import ipaddress
import json as json_mod
import logging
import re
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent
from squirrelops_home_sensor.privileged.helper import PrivilegedOperations
from squirrelops_home_sensor.subprocess_security import trusted_executable

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


class _BindAddressUnavailableError(RuntimeError):
    """Raised when the host has no concrete LAN address for a classic decoy."""


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
        self.last_failure_at: datetime | None = None
        self.failure_window_start: datetime | None = None


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

def _parse_config(raw: str | None) -> dict:
    """Parse a JSON config string from the DB, returning an empty dict on failure."""
    if not raw:
        return {}
    try:
        return json_mod.loads(raw)
    except (json_mod.JSONDecodeError, TypeError):
        return {}


def _route_selected_ip() -> str | None:
    """Return the address selected by the default route, if available."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return str(ipaddress.IPv4Address(sock.getsockname()[0]))
    except (OSError, ValueError):
        return None
    finally:
        sock.close()


def _interface_ipv4_addresses(interface: str) -> list[str]:
    """Enumerate IPv4 addresses for one configured interface in OS order."""
    try:
        if sys.platform == "darwin":
            command = [trusted_executable("ifconfig"), interface]
        else:
            command = [
                trusted_executable("ip"),
                "-4", "-o", "addr", "show", "dev", interface,
            ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", result.stdout)


def _resolve_bind_address(
    *,
    interface: str,
    excluded_ips: set[str],
    virtual_ip_range_start: int,
    virtual_ip_range_end: int,
) -> str | None:
    """Return a concrete local address for classic decoy listeners.

    Binding classic decoys to ``0.0.0.0`` also exposed them on every mimic
    virtual-IP alias, making those aliases look exactly like the sensor host.
    The default-route address is authoritative while online. Offline, use the
    configured interface's primary non-virtual address. Active virtual IPs and
    the configured allocation range are excluded so a classic listener can
    never accidentally bind to a mimic alias.
    """
    def usable(candidate: str | None, *, exclude_virtual_range: bool) -> bool:
        if not candidate or candidate in excluded_ips:
            return False
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            return False
        if address.is_unspecified or address.is_loopback or address.is_link_local:
            return False
        host_octet = int(str(address).rsplit(".", 1)[-1])
        return not (
            exclude_virtual_range
            and virtual_ip_range_start <= host_octet <= virtual_ip_range_end
        )

    routed = _route_selected_ip()
    if usable(routed, exclude_virtual_range=False):
        return routed
    for candidate in _interface_ipv4_addresses(interface):
        if usable(candidate, exclude_virtual_range=True):
            return candidate
    return None


def _deferred_bind_marker(candidate: str) -> str:
    """Return a non-listening marker instead of preserving an unsafe address."""
    try:
        address = ipaddress.IPv4Address(candidate)
    except ValueError:
        return "0.0.0.0"
    if address.is_unspecified or address.is_loopback or address.is_link_local:
        return "0.0.0.0"
    return str(address)


def _generate_credentials(
    decoy_type: str,
    *,
    password_filename: str = "passwords.txt",
    canary_enabled: bool = False,
    canary_domain: str = "canary.local",
) -> list:
    """Generate appropriate planted credentials for a decoy type."""
    from squirrelops_home_sensor.decoys.credentials import CredentialGenerator

    gen = CredentialGenerator(
        password_filename=password_filename,
        canary_enabled=canary_enabled,
        canary_domain=canary_domain,
    )
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
    config: dict | None = None,
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
        canary_enabled: bool = False,
        canary_domain: str = "canary.local",
        credential_filename: str = "passwords.txt",
        bind_address: str | None = None,
        interface: str = "en0",
        virtual_ip_range_start: int = 200,
        virtual_ip_range_end: int = 250,
        network_publisher: PrivilegedOperations | None = None,
    ) -> None:
        self._event_bus = event_bus
        self._db = db
        self._max_decoys = max_decoys
        self._canary_enabled = canary_enabled
        self._canary_domain = canary_domain
        self._credential_filename = credential_filename or "passwords.txt"
        self._bind_address = bind_address
        self._interface = interface
        self._virtual_ip_range_start = virtual_ip_range_start
        self._virtual_ip_range_end = virtual_ip_range_end
        self._network_publisher = network_publisher
        self._records: dict[int, DecoyRecord] = {}
        # The event loop that owns this orchestrator. Captured on deploy (which
        # always runs on the loop) so connection callbacks raised on non-loop
        # threads (HTTP-emulator decoys use ThreadingHTTPServer) can schedule
        # the async handler back onto the loop thread-safely.
        self._loop: asyncio.AbstractEventLoop | None = None

    async def _get_bind_address(self) -> str:
        """Resolve a concrete non-mimic listener address or fail closed.

        Dynamic results are deliberately not cached. A sensor that starts
        without networking must retry resolution after the LAN returns, and a
        sensor moved between networks must not keep binding an obsolete host
        address.
        """
        if self._bind_address is not None:
            try:
                configured = ipaddress.IPv4Address(self._bind_address)
            except ValueError as exc:
                raise _BindAddressUnavailableError(
                    "Configured classic-decoy bind address is invalid"
                ) from exc
            if (
                configured.is_unspecified
                or configured.is_loopback
                or configured.is_link_local
            ):
                raise _BindAddressUnavailableError(
                    "Configured classic-decoy bind address is not a LAN address"
                )
            return str(configured)
        excluded: set[str] = set()
        try:
            cursor = await self._db.execute(
                "SELECT ip_address FROM virtual_ips WHERE released_at IS NULL"
            )
            excluded = {row["ip_address"] for row in await cursor.fetchall()}
        except Exception:
            logger.warning(
                "Could not load virtual-IP exclusions for decoy binding",
                exc_info=True,
            )
        bind_address = _resolve_bind_address(
            interface=self._interface,
            excluded_ips=excluded,
            virtual_ip_range_start=self._virtual_ip_range_start,
            virtual_ip_range_end=self._virtual_ip_range_end,
        )
        if bind_address is None:
            raise _BindAddressUnavailableError(
                f"No concrete LAN address is available on {self._interface}"
            )
        return bind_address

    async def _defer_bind(self, decoy_id: int, persisted_bind: str) -> None:
        """Keep active intent retryable without claiming an unreachable listener."""
        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            """UPDATE decoys
               SET status = 'degraded', bind_address = ?, updated_at = ?
               WHERE id = ?""",
            (_deferred_bind_marker(persisted_bind), now, decoy_id),
        )
        await self._db.commit()

    @property
    def max_decoys(self) -> int:
        """Current classic-decoy capacity."""
        return self._max_decoys

    def set_max_decoys(self, max_decoys: int) -> None:
        """Apply a resource-profile capacity to future deployments."""
        if max_decoys < 0:
            raise ValueError("Maximum decoy count cannot be negative")
        self._max_decoys = max_decoys

    async def reconfigure(self, max_decoys: int) -> list[int]:
        """Apply a live profile limit and return decoys stopped by the change."""
        old_max = self._max_decoys
        stopped: list[int] = []
        self.set_max_decoys(max_decoys)
        try:
            cursor = await self._db.execute(
                """SELECT id
                   FROM decoys
                   WHERE status IN ('active', 'degraded')
                     AND decoy_type != 'mimic'
                   ORDER BY id"""
            )
            rows = await cursor.fetchall()
            excess_ids = [row["id"] for row in rows[max_decoys:]]
            if not excess_ids:
                return stopped

            now = datetime.now(UTC).isoformat()
            for decoy_id in excess_ids:
                record = self._records.get(decoy_id)
                if record is not None:
                    if (
                        self._network_publisher is not None
                        and not await self._network_publisher.unpublish_listener(decoy_id)
                    ):
                        raise RuntimeError(
                            f"Could not withdraw classic decoy {decoy_id}"
                        )
                    await record.decoy.stop()
                    record.health = DecoyHealth.STOPPED
                await self._db.execute(
                    "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
                    (now, decoy_id),
                )
                stopped.append(decoy_id)
            await self._db.commit()
            return stopped
        except Exception:
            self._max_decoys = old_max
            for decoy_id in stopped:
                try:
                    await self.enable_decoy(decoy_id)
                except Exception:
                    logger.exception(
                        "Failed to roll back profile stop for decoy %d",
                        decoy_id,
                    )
            raise

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
            """SELECT *
               FROM decoys
               WHERE status IN ('active', 'degraded')
                 AND decoy_type != 'mimic'
               ORDER BY id"""
        )
        rows = await cursor.fetchall()
        if not rows:
            return 0

        resumable_rows = rows[: self._max_decoys]
        excess_rows = rows[self._max_decoys :]
        if excess_rows:
            now = datetime.now(UTC).isoformat()
            await self._db.executemany(
                "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
                [(now, row["id"]) for row in excess_rows],
            )
            await self._db.commit()
            logger.warning(
                "Stopped %d persisted classic decoys above the current profile limit of %d",
                len(excess_rows),
                self._max_decoys,
            )

        resumed = 0
        for row in resumable_rows:
            try:
                creds = await self._load_credentials(row["id"])
                config = _parse_config(row["config"])
                bind_address = await self._get_bind_address()
                decoy = _create_decoy_instance(
                    decoy_type=row["decoy_type"],
                    decoy_id=row["id"],
                    name=row["name"],
                    port=row["port"],
                    bind_address=bind_address,
                    credentials=creds,
                    config=config,
                )
                await self.deploy_decoy(decoy)
                now = datetime.now(UTC).isoformat()
                await self._db.execute(
                    """UPDATE decoys
                       SET status = 'active', bind_address = ?, port = ?,
                           failure_count = 0, last_failure_at = NULL, updated_at = ?
                       WHERE id = ?""",
                    (bind_address, decoy.port, now, row["id"]),
                )
                await self._db.commit()
                resumed += 1
            except _BindAddressUnavailableError as exc:
                await self._defer_bind(row["id"], row["bind_address"])
                logger.warning(
                    "Deferred classic decoy '%s' (id=%d): %s",
                    row["name"],
                    row["id"],
                    exc,
                )
            except Exception:
                logger.exception(
                    "Failed to resume decoy '%s' (id=%d)", row["name"], row["id"],
                )
                now = datetime.now(UTC).isoformat()
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

        Returns the number of decoys activated, including deferred listeners
        recovered after networking returns.
        """
        recovered = 0
        cursor = await self._db.execute(
            """SELECT id
               FROM decoys
               WHERE status = 'degraded' AND decoy_type != 'mimic'
               ORDER BY id"""
        )
        for row in await cursor.fetchall():
            if await self.enable_decoy(row["id"]):
                recovered += 1

        cursor = await self._db.execute(
            "SELECT decoy_type, status FROM decoys WHERE decoy_type != 'mimic'"
        )
        existing_rows = await cursor.fetchall()
        existing_types = {row["decoy_type"] for row in existing_rows}
        active_count = sum(1 for row in existing_rows if row["status"] == "active")
        remaining = self._max_decoys - active_count
        if remaining <= 0:
            return recovered

        candidates = self.select_decoys(discovered_services, mdns_services or set())
        candidates = [
            candidate
            for candidate in candidates
            if candidate["decoy_type"] not in existing_types
        ][:remaining]
        if not candidates:
            return recovered

        deployed = 0
        for candidate in candidates:
            decoy_type = candidate["decoy_type"]
            decoy: BaseDecoy | None = None
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
            except _BindAddressUnavailableError as exc:
                logger.warning("Deferred auto-deploy of %s decoy: %s", decoy_type, exc)
            except Exception:
                logger.exception("Failed to auto-deploy %s decoy", decoy_type)
                if decoy is not None:
                    now = datetime.now(UTC).isoformat()
                    await self._db.execute(
                        "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
                        (now, decoy.decoy_id),
                    )
                    await self._db.commit()

        logger.info(
            "Activated %d classic decoys (%d recovered, %d newly deployed)",
            recovered + deployed,
            recovered,
            deployed,
        )
        return recovered + deployed

    async def _create_and_persist(self, decoy_type: str) -> tuple[BaseDecoy, str]:
        """Create a decoy instance, generate credentials, and persist to DB.

        Returns (decoy_instance, created_at_iso_string).
        """
        name = _DECOY_NAMES.get(decoy_type, decoy_type.replace("_", " ").title())
        now = datetime.now(UTC).isoformat()
        bind_address = await self._get_bind_address()
        creds = _generate_credentials(
            decoy_type,
            password_filename=self._credential_filename,
            canary_enabled=self._canary_enabled,
            canary_domain=self._canary_domain,
        )

        # Build default config per decoy type
        config: dict = {}
        if decoy_type == "file_share":
            config["password_filename"] = self._credential_filename

        # Insert decoy row to get the ID
        cursor = await self._db.execute(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES (?, ?, ?, 0, 'active', ?, ?, ?)""",
            (name, decoy_type, bind_address, json_mod.dumps(config), now, now),
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
            bind_address=bind_address,
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
        # Capture the running loop so threaded decoy callbacks can reach it.
        self._loop = asyncio.get_running_loop()

        # Register connection callback (closure captures decoy identity)
        decoy.on_connection = lambda event, _did=decoy.decoy_id, _dname=decoy.name: self._handle_connection(event, decoy_id=_did, decoy_name=_dname)

        await decoy.start()
        if (
            self._network_publisher is not None
            and not await self._network_publisher.publish_listener(
                decoy.decoy_id,
                decoy.port,
            )
        ):
            await decoy.stop()
            raise RuntimeError(
                f"Could not publish classic decoy {decoy.decoy_id}"
            )

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

    def get_decoy(self, decoy_id: int) -> DecoyRecord | None:
        """Return the DecoyRecord for a given decoy ID, or None."""
        return self._records.get(decoy_id)

    async def stop_all(self) -> None:
        """Stop all deployed decoys."""
        for record in self._records.values():
            try:
                if self._network_publisher is not None:
                    await self._network_publisher.unpublish_listener(
                        record.decoy.decoy_id
                    )
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
        now = datetime.now(UTC)

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
        now = datetime.now(UTC)

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

    async def restart_decoy(self, decoy_id: int) -> bool:
        """Actually restart a classic decoy listener from persisted config."""
        record = self._records.get(decoy_id)
        if record is not None:
            try:
                if (
                    self._network_publisher is not None
                    and not await self._network_publisher.unpublish_listener(decoy_id)
                ):
                    return False
                await record.decoy.stop()
                record.health = DecoyHealth.STOPPED
            except Exception:
                logger.exception("Failed to stop decoy %d before restart", decoy_id)
                return False
        return await self.enable_decoy(decoy_id)

    async def enable_decoy(self, decoy_id: int) -> bool:
        """Start a classic decoy from its persisted row."""
        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE id = ? AND decoy_type != 'mimic'",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False

        record = self._records.get(decoy_id)
        if (
            record is not None
            and record.health == DecoyHealth.ACTIVE
            and record.decoy.is_running
        ):
            return True

        cursor = await self._db.execute(
            """SELECT COUNT(*)
               FROM decoys
               WHERE status = 'active' AND decoy_type != 'mimic' AND id != ?""",
            (decoy_id,),
        )
        active_count = (await cursor.fetchone())[0]
        if active_count >= self._max_decoys:
            logger.warning(
                "Cannot enable decoy %d: profile limit %d is reached",
                decoy_id,
                self._max_decoys,
            )
            return False

        try:
            bind_address = await self._get_bind_address()
        except _BindAddressUnavailableError as exc:
            if row["status"] in ("active", "degraded"):
                await self._defer_bind(decoy_id, row["bind_address"])
            logger.warning("Deferred enable of classic decoy %d: %s", decoy_id, exc)
            return False

        creds = await self._load_credentials(decoy_id)
        config = _parse_config(row["config"])
        decoy = _create_decoy_instance(
            decoy_type=row["decoy_type"],
            decoy_id=decoy_id,
            name=row["name"],
            port=row["port"],
            bind_address=bind_address,
            credentials=creds,
            config=config,
        )

        try:
            await self.deploy_decoy(decoy)
        except Exception:
            logger.exception("Failed to enable classic decoy %d", decoy_id)
            now = datetime.now(UTC).isoformat()
            await self._db.execute(
                "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
                (now, decoy_id),
            )
            await self._db.commit()
            return False

        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            """UPDATE decoys
               SET status = 'active', bind_address = ?, port = ?,
                   failure_count = 0, last_failure_at = NULL, updated_at = ?
               WHERE id = ?""",
            (bind_address, decoy.port, now, decoy_id),
        )
        await self._db.commit()
        return True

    async def disable_decoy(self, decoy_id: int) -> bool:
        """Stop a classic decoy listener and preserve it for later enable."""
        cursor = await self._db.execute(
            "SELECT id FROM decoys WHERE id = ? AND decoy_type != 'mimic'",
            (decoy_id,),
        )
        if await cursor.fetchone() is None:
            return False

        record = self._records.get(decoy_id)
        if record is not None:
            try:
                if (
                    self._network_publisher is not None
                    and not await self._network_publisher.unpublish_listener(decoy_id)
                ):
                    return False
                await record.decoy.stop()
            except Exception:
                logger.exception("Failed to stop classic decoy %d", decoy_id)
                return False
            record.health = DecoyHealth.STOPPED

        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
            (now, decoy_id),
        )
        await self._db.commit()
        return True

    # -----------------------------------------------------------------
    # Connection handling
    # -----------------------------------------------------------------

    def _handle_connection(self, event: DecoyConnectionEvent, *, decoy_id: int | None = None, decoy_name: str | None = None) -> None:
        """Process a connection event from a decoy.

        Publishes decoy.trip for all connections, and additionally
        decoy.credential_trip if a planted credential was detected.
        Runs event publishing in a fire-and-forget task.

        This is invoked synchronously from the decoy's connection callback,
        which for HTTP-emulator decoys runs on a ThreadingHTTPServer worker
        thread with no event loop. We therefore schedule the async handler
        onto the captured orchestrator loop with run_coroutine_threadsafe,
        which is safe to call from any thread (including the loop thread).
        """
        loop = self._loop
        if loop is None:
            logger.error(
                "Decoy connection received before orchestrator loop was captured; "
                "dropping trip (decoy_id=%s, decoy_name=%s)",
                decoy_id,
                decoy_name,
            )
            return
        asyncio.run_coroutine_threadsafe(
            self._async_handle_connection(event, decoy_id=decoy_id, decoy_name=decoy_name),
            loop,
        )

    async def _async_handle_connection(self, event: DecoyConnectionEvent, *, decoy_id: int | None = None, decoy_name: str | None = None) -> None:
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
                "credential_used": event.credential_used,
                "timestamp": event.timestamp.isoformat(),
                "decoy_id": decoy_id,
                "decoy_name": decoy_name,
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
                    "decoy_id": decoy_id,
                    "decoy_name": decoy_name,
                },
            )
