"""Lifecycle owner for the isolated Studio Mini deep-decoy host."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from squirrelops_home_sensor.decoys.deep.ai_workbench import AIWorkbenchDecoy
from squirrelops_home_sensor.decoys.deep.campaign_store import NarrativeStore
from squirrelops_home_sensor.decoys.deep.guest_runtime import (
    GuestConnectionTelemetry,
    GuestRuntimeController,
)
from squirrelops_home_sensor.decoys.deep.narrative import InteractionEvidence
from squirrelops_home_sensor.decoys.deep.persona import (
    StudioMiniPersona,
    build_studio_mini_persona,
)
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent

logger = logging.getLogger(__name__)

DEEP_SECRET_KEY = "decoys.deep.studio_mini_secret"
DEFAULT_RUNTIME_PATH = Path(
    "/Applications/SquirrelOps Home.app/Contents/Library/Helpers/"
    "com.squirrelops.deception-guest"
)
DEFAULT_GUEST_BUNDLE = Path(
    "/Applications/SquirrelOps Home.app/Contents/Resources/DeceptionGuest"
)

_SERVICES = (
    (445, "smb", "Time Machine and Office Shares", True),
    (22, "ssh", "Remote Login", False),
    (11434, "http", "Ollama", False),
    (1234, "http", "Local Inference API", False),
    (8765, "http", "Studio Build Tools MCP", False),
)
_AI_SURFACES = (
    (11434, "ollama"),
    (1234, "openai"),
    (8765, "mcp"),
)


async def load_or_create_deployment_secret(secret_store: Any) -> bytes:
    """Load the stable persona seed from encrypted storage, creating it once."""
    encoded = await secret_store.get(DEEP_SECRET_KEY)
    if encoded is not None:
        try:
            value = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError("Stored deep-decoy persona seed is invalid") from exc
        if len(value) != 32:
            raise RuntimeError("Stored deep-decoy persona seed has an invalid length")
        return value

    value = secrets.token_bytes(32)
    await secret_store.set(DEEP_SECRET_KEY, base64.urlsafe_b64encode(value).decode("ascii"))
    return value


@dataclass
class _ActiveDeepHost:
    primary_id: int
    host_id: int
    virtual_ip: str
    service_ids: dict[int, int]
    guest: Any
    ai_services: list[AIWorkbenchDecoy]
    backend_ports: dict[int, int]


class DeepDecoyOrchestrator:
    """Publish one coherent real-protocol host under a protected virtual IP."""

    def __init__(
        self,
        *,
        db: Any,
        event_bus: Any,
        ip_manager: Any,
        port_forward_manager: Any,
        mdns_advertiser: Any,
        backend_bind_address_for: Callable[[str], str],
        deployment_secret: bytes,
        runtime_path: Path = DEFAULT_RUNTIME_PATH,
        guest_bundle: Path = DEFAULT_GUEST_BUNDLE,
        state_dir: Path | None = None,
        trusted_uids: set[int] | None = None,
        guest_factory: Callable[..., Any] = GuestRuntimeController,
        ai_factory: Callable[..., AIWorkbenchDecoy] = AIWorkbenchDecoy,
    ) -> None:
        if len(deployment_secret) < 32:
            raise ValueError("Deep-decoy deployment secret must be at least 32 bytes")
        self._db = db
        self._event_bus = event_bus
        self._ip_manager = ip_manager
        self._port_forward = port_forward_manager
        self._mdns = mdns_advertiser
        self._backend_bind_address_for = backend_bind_address_for
        self._deployment_secret = deployment_secret
        self._runtime_path = runtime_path
        self._guest_bundle = guest_bundle
        self._state_dir = state_dir or (
            Path(os.environ.get("TMPDIR", "/tmp")) / "squirrelops-deception-guest"
        )
        self._trusted_uids = trusted_uids
        self._guest_factory = guest_factory
        self._ai_factory = ai_factory
        self._active: _ActiveDeepHost | None = None
        self._mdns_degraded = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lifecycle_lock = asyncio.Lock()

    @property
    def is_active(self) -> bool:
        return self._active is not None

    @property
    def active_virtual_ip(self) -> str | None:
        return None if self._active is None else self._active.virtual_ip

    @property
    def active_count(self) -> int:
        return 1 if self._active is not None else 0

    def effective_status(self, decoy_id: int, persisted_status: str) -> str:
        """Overlay runtime and Bonjour truth without changing restart intent."""
        active = self._active
        if persisted_status != "active":
            return persisted_status
        if active is None or decoy_id not in active.service_ids.values():
            return "degraded"
        if not active.guest.is_running:
            return "degraded"
        if any(not service.is_running for service in active.ai_services):
            return "degraded"
        if self._mdns_degraded:
            return "degraded"
        return persisted_status

    def _schedule(self, coroutine: Any) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            logger.error("Deep-decoy event arrived outside its lifecycle loop")
            coroutine.close()
            return
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if loop is running_loop:
            loop.create_task(coroutine)
        else:
            asyncio.run_coroutine_threadsafe(coroutine, loop)

    async def start(self) -> bool:
        """Resume an active host or provision the first Studio Mini."""
        async with self._lifecycle_lock:
            self._loop = asyncio.get_running_loop()
            cursor = await self._db.execute(
                """SELECT d.*, h.id AS deep_host_id
                   FROM decoys d
                   JOIN decoy_hosts h ON h.id = d.host_id
                   WHERE d.decoy_type = 'deep'
                     AND d.is_primary = 1
                     AND d.retired_at IS NULL
                   ORDER BY d.id
                   LIMIT 1"""
            )
            row = await cursor.fetchone()
            if row is None:
                return await self._provision()
            if row["status"] != "active":
                return False
            return await self._activate_existing(row)

    async def _provision(self) -> bool:
        allocated = await self._ip_manager.allocate_verified(1)
        if len(allocated) != 1:
            logger.warning("Deep decoy could not obtain a verified virtual IP")
            return False
        virtual_ip = allocated[0]
        created_at = datetime.now(UTC)
        persona = build_studio_mini_persona(self._deployment_secret, created_at)
        now = created_at.isoformat()
        service_ids: dict[int, int] = {}
        try:
            host_cursor = await self._db.execute(
                """INSERT INTO decoy_hosts
                       (hostname, bind_address, created_at, updated_at)
                   VALUES (?, ?, ?, ?)""",
                (persona.hostname, virtual_ip, now, now),
            )
            if host_cursor.lastrowid is None:
                raise RuntimeError("Deep-decoy host insert did not return an ID")
            host_id = int(host_cursor.lastrowid)
            for port, protocol, service_name, primary in _SERVICES:
                config = json.dumps(
                    {
                        "persona_id": persona.persona_id,
                        "persona_created_at": now,
                        "release": "2.1",
                    },
                    separators=(",", ":"),
                )
                cursor = await self._db.execute(
                    """INSERT INTO decoys
                           (name, decoy_type, bind_address, port, status, config,
                            created_at, updated_at, host_id, protocol,
                            service_name, is_primary)
                       VALUES (?, 'deep', ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        persona.display_name,
                        virtual_ip,
                        port,
                        config,
                        now,
                        now,
                        host_id,
                        protocol,
                        service_name,
                        1 if primary else 0,
                    ),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("Deep-decoy service insert did not return an ID")
                service_ids[port] = int(cursor.lastrowid)
            primary_id = service_ids[445]
            credentials = (
                (service_ids[22], "password", persona.login_password, "SSH buildbot login"),
                (service_ids[445], "password", persona.login_password, "SMB buildbot login"),
                (
                    service_ids[1234],
                    "api_key",
                    persona.openai_api_key,
                    "/Users/buildbot/Projects/fieldkit-ios/.env.local",
                ),
                (
                    service_ids[8765],
                    "source_token",
                    persona.source_token,
                    "/Users/buildbot/Projects/fieldkit-ios/.env.local",
                ),
            )
            for decoy_id, kind, value, location in credentials:
                await self._db.execute(
                    """INSERT INTO planted_credentials
                           (credential_type, credential_value, planted_location,
                            decoy_id, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (kind, value, location, decoy_id, now),
                )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            self._ip_manager.release_reservation(virtual_ip)
            raise

        row_cursor = await self._db.execute(
            "SELECT *, ? AS deep_host_id FROM decoys WHERE id = ?",
            (host_id, primary_id),
        )
        row = await row_cursor.fetchone()
        if row is None:
            raise RuntimeError("Deep-decoy provisioning row disappeared")
        return await self._activate_existing(
            row,
            persona=persona,
            freshly_allocated=True,
        )

    async def _service_ids(self, host_id: int) -> dict[int, int]:
        cursor = await self._db.execute(
            """SELECT id, port FROM decoys
               WHERE host_id = ? AND decoy_type = 'deep' AND retired_at IS NULL""",
            (host_id,),
        )
        return {int(row["port"]): int(row["id"]) for row in await cursor.fetchall()}

    async def _activate_existing(
        self,
        row: Any,
        *,
        persona: StudioMiniPersona | None = None,
        freshly_allocated: bool = False,
    ) -> bool:
        primary_id = int(row["id"])
        host_id = int(row["deep_host_id"])
        virtual_ip = str(row["bind_address"])
        service_ids = await self._service_ids(host_id)
        if set(service_ids) != {service[0] for service in _SERVICES}:
            logger.error("Deep-decoy service set is incomplete")
            return False
        if persona is None:
            try:
                config = json.loads(row["config"] or "{}")
                created_at = datetime.fromisoformat(config["persona_created_at"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                logger.exception("Deep-decoy persona state is invalid")
                return False
            persona = build_studio_mini_persona(self._deployment_secret, created_at)

        if not await self._port_forward.quarantine_endpoints({primary_id: virtual_ip}):
            logger.error("Deep-decoy endpoint quarantine could not be established")
            return False
        if not freshly_allocated:
            if not await self._ip_manager.remove_alias(virtual_ip):
                logger.error("Deep-decoy virtual IP could not be withdrawn safely")
                return False
            if not await self._ip_manager.is_verified_free(virtual_ip):
                logger.error("Deep-decoy virtual IP is no longer verified free")
                return False
        alias_created = await self._ip_manager.add_alias(virtual_ip)
        if not alias_created:
            logger.error("Deep-decoy virtual IP could not be published")
            return False

        try:
            await self._db.execute(
                "UPDATE virtual_ips SET decoy_id = ? WHERE ip_address = ?",
                (primary_id, virtual_ip),
            )
            await self._db.commit()
            active = await self._start_components(
                primary_id=primary_id,
                host_id=host_id,
                virtual_ip=virtual_ip,
                service_ids=service_ids,
                persona=persona,
            )
            if not await self._port_forward.add_forwards(
                primary_id,
                virtual_ip,
                active.backend_ports,
                exposed_ports=set(service_ids),
            ):
                raise RuntimeError("Deep-decoy port publication failed")
            self._active = active
            self._mdns_degraded = not await self._register_mdns(active)
            now = datetime.now(UTC).isoformat()
            await self._db.execute(
                "UPDATE decoys SET status = 'active', updated_at = ? WHERE host_id = ?",
                (now, host_id),
            )
            await self._db.execute(
                "UPDATE decoy_hosts SET updated_at = ? WHERE id = ?",
                (now, host_id),
            )
            await self._db.commit()
            await self._publish_status(active, "active", now)
            logger.info("Studio Mini deep decoy active at %s", virtual_ip)
            return True
        except BaseException:
            logger.exception("Deep-decoy activation failed")
            active = locals().get("active")
            if isinstance(active, _ActiveDeepHost):
                await self._stop_components(active)
            removed = await self._ip_manager.remove_alias(virtual_ip)
            if removed:
                await self._port_forward.remove_forwards(primary_id)
            return False

    async def _start_components(
        self,
        *,
        primary_id: int,
        host_id: int,
        virtual_ip: str,
        service_ids: dict[int, int],
        persona: StudioMiniPersona,
    ) -> _ActiveDeepHost:
        bind_address = self._backend_bind_address_for(virtual_ip)
        campaigns = NarrativeStore(self._db)
        guest_kwargs: dict[str, Any] = {
            "executable": self._runtime_path,
            "bundle_root": self._guest_bundle,
            "state_dir": self._state_dir,
            "bind_address": bind_address,
            "persona": persona,
            "on_connection": self._guest_connection_callback(primary_id, persona, campaigns),
            "on_exit": self._guest_exit_callback(primary_id),
        }
        if self._trusted_uids is not None:
            guest_kwargs["trusted_uids"] = self._trusted_uids
        guest = self._guest_factory(**guest_kwargs)
        guest_ports = await guest.start()
        ai_services: list[AIWorkbenchDecoy] = []
        try:
            for advertised_port, surface in _AI_SURFACES:
                decoy = self._ai_factory(
                    decoy_id=primary_id,
                    name=persona.hostname,
                    port=0,
                    advertised_port=advertised_port,
                    surface=surface,
                    bind_address=bind_address,
                    db=self._db,
                    deployment_secret=self._deployment_secret,
                    persona_created_at=persona.created_at,
                    campaign_store=campaigns,
                )
                decoy.on_connection = self._ai_connection_callback(service_ids)
                await decoy.start()
                ai_services.append(decoy)
        except BaseException:
            for service in reversed(ai_services):
                with suppress(Exception):
                    await service.stop()
            await guest.stop()
            raise

        backend_ports = dict(guest_ports)
        backend_ports.update(
            (advertised, service.port)
            for (advertised, _surface), service in zip(
                _AI_SURFACES,
                ai_services,
                strict=True,
            )
        )
        return _ActiveDeepHost(
            primary_id=primary_id,
            host_id=host_id,
            virtual_ip=virtual_ip,
            service_ids=service_ids,
            guest=guest,
            ai_services=ai_services,
            backend_ports=backend_ports,
        )

    def _guest_connection_callback(
        self,
        primary_id: int,
        persona: StudioMiniPersona,
        campaigns: NarrativeStore,
    ) -> Callable[[GuestConnectionTelemetry], None]:
        def callback(telemetry: GuestConnectionTelemetry) -> None:
            self._schedule(
                self._handle_guest_connection(primary_id, persona, campaigns, telemetry)
            )

        return callback

    def _ai_connection_callback(
        self,
        service_ids: dict[int, int],
    ) -> Callable[[DecoyConnectionEvent], None]:
        def callback(event: DecoyConnectionEvent) -> None:
            self._schedule(self._publish_trip(event, service_ids.get(event.dest_port)))

        return callback

    def _guest_exit_callback(self, primary_id: int) -> Callable[[int], None]:
        def callback(returncode: int) -> None:
            self._schedule(self._handle_guest_exit(primary_id, returncode))

        return callback

    async def _handle_guest_exit(self, primary_id: int, returncode: int) -> None:
        async with self._lifecycle_lock:
            active = self._active
            if active is None or active.primary_id != primary_id:
                return
            logger.error(
                "Deep-decoy runtime exited unexpectedly with status %d",
                returncode,
            )
            quarantined = await self._port_forward.quarantine_endpoints(
                {active.primary_id: active.virtual_ip}
            )
            if not quarantined:
                logger.critical("Deep-decoy quarantine failed after runtime exit")
            await self._stop_components(active)
            self._active = None
            removed = await self._ip_manager.remove_alias(active.virtual_ip)
            if removed:
                if not await self._port_forward.remove_forwards(active.primary_id):
                    logger.error("Deep-decoy forwarding cleanup failed after runtime exit")
            else:
                logger.error("Deep-decoy virtual IP cleanup failed after runtime exit")
            now = datetime.now(UTC).isoformat()
            await self._publish_status(active, "degraded", now)

    async def _handle_guest_connection(
        self,
        primary_id: int,
        persona: StudioMiniPersona,
        campaigns: NarrativeStore,
        telemetry: GuestConnectionTelemetry,
    ) -> None:
        campaign = await campaigns.observe(
            decoy_id=primary_id,
            source_ip=telemetry.source_ip,
            persona_id=persona.persona_id,
            evidence=InteractionEvidence(
                method="connect",
                path="",
                protocol="ssh" if telemetry.dest_port == 22 else "smb",
                operation=telemetry.interaction_type,
            ),
        )
        event = DecoyConnectionEvent(
            source_ip=telemetry.source_ip,
            source_port=telemetry.source_port,
            dest_port=telemetry.dest_port,
            protocol=telemetry.protocol,
            timestamp=telemetry.timestamp,
            intruder_intent=campaign.intent.value,
            narrative_stage=int(campaign.stage),
            interaction_type=telemetry.interaction_type,
        )
        active = self._active
        service_id = None if active is None else active.service_ids.get(event.dest_port)
        await self._publish_trip(event, service_id)

    async def _publish_trip(
        self,
        event: DecoyConnectionEvent,
        service_id: int | None,
    ) -> None:
        if service_id is None:
            logger.error(
                "Discarding deep-decoy telemetry for unknown service port %d",
                event.dest_port,
            )
            return
        await self._event_bus.publish(
            "decoy.trip",
            {
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "request_path": event.request_path,
                "credential_used": event.credential_used,
                "intruder_intent": event.intruder_intent,
                "narrative_stage": event.narrative_stage,
                "interaction_type": event.interaction_type,
                "timestamp": event.timestamp.isoformat(),
                "decoy_id": service_id,
                "decoy_name": "Studio Build Mac",
            },
        )
        if event.credential_used is not None:
            await self._event_bus.publish(
                "decoy.credential_trip",
                {
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "dest_port": event.dest_port,
                    "credential_used": event.credential_used,
                    "request_path": event.request_path,
                    "intruder_intent": event.intruder_intent,
                    "narrative_stage": event.narrative_stage,
                    "interaction_type": event.interaction_type,
                    "timestamp": event.timestamp.isoformat(),
                    "detection_method": "deep_decoy",
                    "decoy_id": service_id,
                    "decoy_name": "Studio Build Mac",
                },
            )

    async def _register_mdns(self, active: _ActiveDeepHost) -> bool:
        registrations = (
            (22, "_ssh._tcp", "Studio Build Mac"),
            (445, "_smb._tcp", "Studio Build Mac"),
            (11434, "_http._tcp", "Studio Mini Ollama"),
            (1234, "_http._tcp", "Studio Mini Inference"),
            (8765, "_http._tcp", "Studio Build Tools"),
        )
        all_registered = True
        for port, service_type, instance_name in registrations:
            registered = await self._mdns.register(
                active.primary_id,
                active.virtual_ip,
                port,
                service_type,
                "studio-mini",
                instance_name=instance_name,
            )
            if not registered:
                all_registered = False
                logger.warning("Deep-decoy mDNS registration failed for port %d", port)
        return all_registered

    async def _publish_status(
        self,
        active: _ActiveDeepHost,
        status: str,
        updated_at: str,
    ) -> None:
        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE host_id = ? ORDER BY port, id",
            (active.host_id,),
        )
        for row in await cursor.fetchall():
            await self._event_bus.publish(
                "decoy.status_changed",
                {
                    "id": row["id"],
                    "host_id": row["host_id"],
                    "hostname": "studio-mini.local",
                    "name": row["name"],
                    "decoy_type": "deep",
                    "bind_address": row["bind_address"],
                    "port": row["port"],
                    "protocol": row["protocol"],
                    "service_name": row["service_name"],
                    "status": status,
                    "connection_count": row["connection_count"],
                    "credential_trip_count": row["credential_trip_count"],
                    "created_at": row["created_at"],
                    "updated_at": updated_at,
                },
            )

    async def _stop_components(self, active: _ActiveDeepHost) -> None:
        await self._mdns.unregister(active.primary_id)
        self._mdns_degraded = False
        for service in reversed(active.ai_services):
            with suppress(Exception):
                await service.stop()
        with suppress(Exception):
            await active.guest.stop()

    async def stop_all(self) -> None:
        """Stop listeners under deny-all quarantine; shared cleanup removes IPs."""
        async with self._lifecycle_lock:
            active = self._active
            if active is None:
                return
            if not await self._port_forward.quarantine_endpoints(
                {active.primary_id: active.virtual_ip}
            ):
                raise RuntimeError("Deep-decoy quarantine failed during shutdown")
            await self._stop_components(active)
            self._active = None

    async def disable(self, decoy_id: int) -> bool:
        """Stop the grouped host and release its virtual network state."""
        async with self._lifecycle_lock:
            active = self._active
            if active is None or decoy_id not in active.service_ids.values():
                return False
            if not await self._port_forward.quarantine_endpoints(
                {active.primary_id: active.virtual_ip}
            ):
                return False
            await self._stop_components(active)
            self._active = None
            if not await self._ip_manager.remove_alias(active.virtual_ip):
                return False
            if not await self._port_forward.remove_forwards(active.primary_id):
                return False
            now = datetime.now(UTC).isoformat()
            await self._db.execute(
                "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE host_id = ?",
                (now, active.host_id),
            )
            await self._db.commit()
            await self._publish_status(active, "stopped", now)
            return True

    async def enable(self, decoy_id: int) -> bool:
        """Enable a stopped deep host through the same fail-closed start path."""
        async with self._lifecycle_lock:
            if self._active is not None:
                return decoy_id in self._active.service_ids.values()
            cursor = await self._db.execute(
                """SELECT d.*, h.id AS deep_host_id
                   FROM decoys d JOIN decoy_hosts h ON h.id = d.host_id
                   WHERE d.decoy_type = 'deep'
                     AND d.is_primary = 1
                     AND d.retired_at IS NULL
                     AND (d.id = ? OR d.host_id = (SELECT host_id FROM decoys WHERE id = ?))""",
                (decoy_id, decoy_id),
            )
            row = await cursor.fetchone()
            return False if row is None else await self._activate_existing(row)

    async def restart(self, decoy_id: int) -> bool:
        if self._active is not None:
            if not await self.disable(decoy_id):
                return False
        return await self.enable(decoy_id)

    async def handle_ip_conflict(self, ip: str) -> bool:
        """Stop the deep host if a real LAN device claims its address."""
        active = self._active
        if active is None or active.virtual_ip != ip:
            return False
        logger.error("Real device claimed deep-decoy address %s; stopping host", ip)
        return await self.disable(active.primary_id)
