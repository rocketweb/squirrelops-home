"""Mimic orchestrator — manages the scout-to-deploy pipeline.

After each scout cycle, evaluates candidates and deploys mimic decoys:
  1. Get best mimic candidates from scout profiles
  2. Generate MimicTemplate for each candidate
  3. Allocate virtual IPs
  4. Deploy lightweight async mimic servers
  5. Register mDNS services
  6. Persist to database
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from typing import Any

import aiosqlite

from squirrelops_home_sensor.decoys.credentials import CredentialGenerator, GeneratedCredential
from squirrelops_home_sensor.decoys.identity import (
    canonicalize_decoy_hostname,
    canonicalize_local_hostname,
    mdns_label,
)
from squirrelops_home_sensor.decoys.tls_identity import generate_host_tls_identity
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent
from squirrelops_home_sensor.decoys.types.mimic import MimicDecoy
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.network.port_forward import PortForwardManager
from squirrelops_home_sensor.network.virtual_ip import VirtualIPManager
from squirrelops_home_sensor.scanner.service_names import get_service_name
from squirrelops_home_sensor.scouts.engine import ScoutEngine
from squirrelops_home_sensor.scouts.mdns import (
    MimicMDNSAdvertiser,
    generate_mimic_hostname,
    mdns_service_type_for,
    mimic_display_name,
    network_uses_host_identifiers,
    should_refresh_mimic_name,
)
from squirrelops_home_sensor.scouts.templates import MimicTemplate, MimicTemplateGenerator

logger = logging.getLogger("squirrelops_home_sensor.scouts")


class _ReentrantAsyncLock:
    """Task-reentrant wrapper around one asyncio lifecycle lock."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._owner: asyncio.Task[Any] | None = None
        self._depth = 0

    async def __aenter__(self) -> _ReentrantAsyncLock:
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("Mimic lifecycle mutation requires an asyncio task")
        if self._owner is task:
            self._depth += 1
            return self
        await self._lock.acquire()
        self._owner = task
        self._depth = 1
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        task = asyncio.current_task()
        if self._owner is not task:
            raise RuntimeError("Mimic lifecycle lock released by a non-owner")
        self._depth -= 1
        if self._depth == 0:
            self._owner = None
            self._lock.release()

    def is_owned_by_another_task(self) -> bool:
        task = asyncio.current_task()
        return self._owner is not None and self._owner is not task

    @property
    def is_locked(self) -> bool:
        return self._owner is not None


def _serialized_lifecycle(method: Any) -> Any:
    """Serialize a lifecycle method while allowing its internal nesting."""

    @wraps(method)
    async def wrapped(self: MimicOrchestrator, *args: Any, **kwargs: Any) -> Any:
        async with self._lifecycle_lock:
            return await method(self, *args, **kwargs)

    return wrapped


def _serialized_user_lifecycle(method: Any) -> Any:
    """Reject user actions instead of queueing behind long Scout work."""

    @wraps(method)
    async def wrapped(self: MimicOrchestrator, *args: Any, **kwargs: Any) -> Any:
        if self._lifecycle_lock.is_owned_by_another_task():
            raise MimicLifecycleBusyError(
                "Fake host lifecycle is busy; wait for the current network update"
            )
        async with self._lifecycle_lock:
            return await method(self, *args, **kwargs)

    return wrapped


def _serialized_background_lifecycle(method: Any) -> Any:
    """Skip stale routine work instead of queueing it behind lifecycle work."""

    @wraps(method)
    async def wrapped(self: MimicOrchestrator, *args: Any, **kwargs: Any) -> Any:
        if self._lifecycle_lock.is_owned_by_another_task():
            logger.info(
                "Skipping routine mimic reconciliation while lifecycle work is active"
            )
            return 0
        async with self._lifecycle_lock:
            return await method(self, *args, **kwargs)

    return wrapped


class HelperUnavailableError(Exception):
    """Raised when the privileged helper is not available for virtual IP operations."""


class MimicDeploymentError(Exception):
    """Raised when eligible mimics exist but none can be safely deployed."""


class MimicCleanupError(Exception):
    """Raised when a mimic remains protected and persisted for cleanup retry."""


class MimicLifecycleBusyError(Exception):
    """Raised when a user action would wait behind long Scout lifecycle work."""


@dataclass(frozen=True, slots=True)
class _MimicRemovalTarget:
    """Generation identity captured before a removal waits for serialization."""

    requested_id: int
    primary_id: int
    host_id: int | None
    generation_created_at: str | None
    runtime: MimicDecoy | None


class MimicOrchestrator:
    """Manages the full mimic lifecycle: scout -> template -> deploy.

    Parameters
    ----------
    scout_engine:
        Scout engine for fetching service profiles.
    template_generator:
        Template generator for converting profiles to route configs.
    ip_manager:
        Virtual IP manager for allocating and managing IPs.
    event_bus:
        Event bus for publishing decoy events.
    db:
        Database connection.
    max_mimics:
        Maximum number of mimic decoys to deploy.
    """

    def __init__(
        self,
        scout_engine: ScoutEngine,
        template_generator: MimicTemplateGenerator,
        ip_manager: VirtualIPManager,
        event_bus: EventBus,
        db: aiosqlite.Connection,
        max_mimics: int = 10,
        mdns_advertiser: MimicMDNSAdvertiser | None = None,
        port_forward_manager: PortForwardManager | None = None,
        sensor_hostnames: set[str] | None = None,
        canary_enabled: bool = False,
        canary_domain: str = "canary.local",
        backend_bind_address_for: Callable[[str], str] | None = None,
        hostname_advisor: Any | None = None,
    ) -> None:
        self._engine = scout_engine
        self._template_gen = template_generator
        self._ip_manager = ip_manager
        self._event_bus = event_bus
        self._db = db
        self._max_mimics = max_mimics
        self._active_mimics: dict[int, MimicDecoy] = {}  # decoy_id -> MimicDecoy
        # One runtime object owns every service row for a virtual host. Values
        # map stable service IDs to that primary/runtime-owner decoy ID.
        self._service_to_primary: dict[int, int] = {}
        self._mdns_degraded: set[int] = set()
        self._cred_gen = CredentialGenerator(
            canary_enabled=canary_enabled,
            canary_domain=canary_domain,
        )
        self._mdns = mdns_advertiser
        self._port_fwd = port_forward_manager
        self._sensor_hostnames = frozenset(sensor_hostnames or ())
        self._hostname_advisor = hostname_advisor
        self._network_ready = True
        self._backend_bind_address_for = backend_bind_address_for or (lambda ip: ip)
        self._startup_resume_endpoints: dict[int, str] | None = None
        self._lifecycle_lock = _ReentrantAsyncLock()

    @property
    def active_count(self) -> int:
        """Number of operational mimics with verified network publication."""
        return sum(
            self.is_mimic_operational(decoy_id)
            for decoy_id in self._active_mimics
        )

    @property
    def lifecycle_busy(self) -> bool:
        """Whether protected fake-host lifecycle work currently owns the lock."""
        return self._lifecycle_lock.is_locked

    def is_mimic_operational(self, decoy_id: int) -> bool:
        """Whether a listener also has a positively verified virtual IP."""
        primary_id = self._service_to_primary.get(decoy_id, decoy_id)
        mimic = self._active_mimics.get(primary_id)
        if mimic is None:
            return False
        verified_ips = getattr(self._ip_manager, "verified_ips", None)
        if verified_ips is None:
            # Lightweight test doubles and non-network backends predate the
            # verified-publication signal. Runtime VirtualIPManager always
            # exposes it.
            return True
        return mimic.bind_address in verified_ips

    def _backend_bind_kwargs(self, advertised_ip: str) -> dict[str, str]:
        """Pass a separate backend address only for namespace-separated Linux."""
        backend_ip = self._backend_bind_address_for(advertised_ip)
        if backend_ip == advertised_ip:
            return {}
        return {"backend_bind_address": backend_ip}

    async def _resolve_primary_id(self, decoy_id: int) -> int:
        """Resolve any service row to its virtual host's runtime owner."""
        cursor = await self._db.execute(
            """SELECT COALESCE(primary_row.id, requested.id) AS primary_id
               FROM decoys requested
               LEFT JOIN decoys primary_row
                 ON primary_row.host_id = requested.host_id
                AND primary_row.is_primary = 1
               WHERE requested.id = ? AND requested.decoy_type = 'mimic'
               LIMIT 1""",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        return int(row["primary_id"]) if row is not None else decoy_id

    async def _service_rows_for_primary(self, primary_id: int) -> list[Any]:
        """Load every stable service row owned by one mimic runtime."""
        cursor = await self._db.execute(
            """SELECT service.*
               FROM decoys primary_row
               JOIN decoys service
                 ON (
                     primary_row.host_id IS NOT NULL
                     AND service.host_id = primary_row.host_id
                 )
                 OR (
                     primary_row.host_id IS NULL
                     AND service.id = primary_row.id
               )
               WHERE primary_row.id = ?
                 AND service.retired_at IS NULL
               ORDER BY service.is_primary DESC, service.port, service.id""",
            (primary_id,),
        )
        return list(await cursor.fetchall())

    async def _refresh_service_mapping(self, primary_id: int) -> list[Any]:
        """Refresh in-memory service ownership and return the service rows."""
        rows = await self._service_rows_for_primary(primary_id)
        for row in rows:
            self._service_to_primary[int(row["id"])] = primary_id
        return rows

    async def _unique_generated_hostname(
        self,
        hostname: str,
        *,
        allow_identifiers: bool = False,
    ) -> str:
        """Resolve durable-name and shared mDNS-label collisions."""
        canonical = canonicalize_local_hostname(hostname)
        label = mdns_label(canonical)
        modifiers = ("main", "shared", "office", "home", "central")
        candidates = [canonical]
        candidates.extend(
            canonicalize_local_hostname(
                f"{modifier}-{label[: 62 - len(modifier)].rstrip('-')}"
            )
            for modifier in modifiers
        )
        if allow_identifiers:
            candidates.extend(
                canonicalize_local_hostname(
                    f"{label[: 63 - len(str(suffix)) - 1].rstrip('-')}"
                    f"-{suffix}"
                )
                for suffix in range(2, 100)
            )
        for candidate in candidates:
            cursor = await self._db.execute(
                """SELECT hostname FROM decoy_hosts
                   WHERE retired_at IS NULL""",
            )
            existing = list(await cursor.fetchall())
            if not any(
                mdns_label(str(row["hostname"])) == mdns_label(candidate)
                for row in existing
            ):
                return candidate
        raise ValueError("No collision-free durable fake-host name is available")

    async def _observed_real_hostnames(self) -> list[str]:
        """Return bounded hostname values observed from real devices."""
        cursor = await self._db.execute(
            """SELECT hostname
               FROM devices
               WHERE hostname IS NOT NULL
               UNION ALL
               SELECT mdns_hostname AS hostname
               FROM device_fingerprints
               WHERE mdns_hostname IS NOT NULL"""
        )
        candidates = [
            str(row["hostname"])
            for row in await cursor.fetchall()
        ]
        candidates.extend(self._sensor_hostnames)
        return list(dict.fromkeys(candidates))[:128]

    async def _observed_real_hostname_labels(self) -> set[str]:
        """Return normalized labels owned by real devices or the sensor host."""
        labels: set[str] = set()
        for candidate in await self._observed_real_hostnames():
            try:
                labels.add(mdns_label(candidate))
            except ValueError:
                # Friendly names and unrelated DNS domains do not claim the
                # single-label ``.local`` identity used by mimic advertising.
                continue
        return labels

    def effective_mimic_status(
        self,
        decoy_id: int,
        persisted_status: str,
    ) -> str:
        """Overlay volatile network truth without changing restart intent."""
        if persisted_status == "active" and not self.is_mimic_operational(decoy_id):
            return "degraded"
        primary_id = self._service_to_primary.get(decoy_id, decoy_id)
        if persisted_status == "active" and primary_id in self._mdns_degraded:
            return "degraded"
        return persisted_status

    @property
    def max_mimics(self) -> int:
        return self._max_mimics

    def set_max_mimics(self, max_mimics: int) -> None:
        """Apply a resource-profile capacity to future deployments."""
        if max_mimics < 0:
            raise ValueError("Maximum mimic count cannot be negative")
        self._max_mimics = max_mimics

    def set_hostname_advisor(self, advisor: Any | None) -> None:
        """Apply the optional AI advisor used only for future fake hosts."""
        self._hostname_advisor = advisor

    @_serialized_lifecycle
    async def reconfigure(self, max_mimics: int) -> list[int]:
        """Apply a live profile limit and return mimics stopped by the change."""
        old_max = self._max_mimics
        stopped: list[int] = []
        self.set_max_mimics(max_mimics)
        try:
            active_ids = sorted(self._active_mimics)
            for decoy_id in active_ids[max_mimics:]:
                mimic = self._active_mimics.get(decoy_id)
                if mimic is not None:
                    deactivated = await self._deactivate_failed_mimic(
                        decoy_id=decoy_id,
                        bind_address=mimic.bind_address,
                        mimic=mimic,
                    )
                    stopped.append(decoy_id)
                    if not deactivated:
                        raise RuntimeError(
                            f"Could not safely apply mimic limit while "
                            f"stopping decoy {decoy_id}"
                        )
            return stopped
        except Exception:
            self._max_mimics = old_max
            for decoy_id in stopped:
                try:
                    await self.enable_mimic(decoy_id)
                except Exception:
                    logger.exception(
                        "Failed to roll back profile stop for mimic %d",
                        decoy_id,
                    )
            raise

    @_serialized_lifecycle
    async def evaluate_and_deploy(
        self,
        arp_results: list[tuple[str, str]] | None = None,
    ) -> int:
        """After scouting, pick best candidates and deploy mimics.

        Returns the number of new mimics deployed.

        Raises
        ------
        HelperUnavailableError:
            If the privileged helper is not available for virtual IP operations.
        """
        if not self._network_ready:
            raise HelperUnavailableError(
                "Persisted virtual IPs could not be quarantined safely"
            )
        await self.reconcile_ip_conflicts(arp_results, redeploy=False)
        if self._max_mimics <= 0:
            return 0

        # Check helper availability before attempting any deployment
        if not await self._ip_manager.is_available():
            raise HelperUnavailableError(
                "Privileged helper is not running — cannot create virtual IPs for "
                "mimic decoys. Install and start the SquirrelOps Helper."
            )

        reconciled = await self._reconcile_existing_mimic_services()
        slots = self._max_mimics - len(self._active_mimics)
        if slots <= 0:
            logger.info(
                "Max fake hosts reached (%d); reconciled %d existing host(s)",
                self._max_mimics,
                reconciled,
            )
            return 0

        # Capacity is a ceiling on believable fake hosts, not a target that
        # justifies cloning the same source repeatedly. One source device can
        # have at most one active virtual host; its services become individual
        # rows within that shared host identity.
        mimicked_devices = await self._get_mimicked_device_ids()
        candidates = await self._engine.get_mimic_candidates(
            count=self._max_mimics,
            exclude_device_ids=mimicked_devices,
        )
        if not candidates:
            logger.info("No mimic candidates — run scouts first to discover services")
            return 0

        # Group profiles by device
        device_profiles: dict[int, list] = {}
        for profile in candidates:
            device_profiles.setdefault(profile.device_id, []).append(profile)

        ordered_profiles = [
            (device_id, profiles)
            for device_id, profiles in device_profiles.items()
            if device_id not in mimicked_devices
        ]
        if not ordered_profiles:
            logger.info("Every eligible source device already has an active mimic")
            return 0

        batch_size = min(slots, len(ordered_profiles))
        real_hostnames = await self._observed_real_hostnames()
        allow_identifiers = network_uses_host_identifiers(real_hostnames)
        ai_suggestions: list[str] = []
        if self._hostname_advisor is not None and batch_size > 0:
            suggestion_count = (batch_size + 1) // 2
            try:
                ai_suggestions = await (
                    self._hostname_advisor.suggest_decoy_hostnames(
                        existing_hostnames=real_hostnames,
                        count=suggestion_count,
                        allow_identifiers=allow_identifiers,
                    )
                )
            except Exception:
                logger.warning(
                    "AI decoy naming failed; using deterministic names",
                    exc_info=True,
                )
                ai_suggestions = []

        if arp_results is None:
            try:
                arp_results = await self._ip_manager.snapshot_real_ip_owners()
            except Exception as exc:
                raise MimicDeploymentError(
                    "Could not verify free virtual addresses for mimic deployment"
                ) from exc

        logger.info(
            "Filling %d mimic slot(s) from %d eligible source device(s) "
            "(%d already represented)",
            slots,
            len(device_profiles),
            len(mimicked_devices),
        )

        deployed = 0
        batch_ips: set[str] = set()
        for index, (device_id, profiles) in enumerate(ordered_profiles[:slots]):
            try:
                active_before = set(self._active_mimics)
                ok = await self._deploy_mimic_for_device(
                    device_id,
                    profiles,
                    arp_results=arp_results,
                    suggested_hostname=(
                        ai_suggestions[index]
                        if index < len(ai_suggestions)
                        else None
                    ),
                    allow_identifiers=allow_identifiers,
                )
                if ok:
                    deployed += 1
                    batch_ips.update(
                        mimic.bind_address
                        for decoy_id, mimic in self._active_mimics.items()
                        if decoy_id not in active_before
                    )
            except MimicCleanupError:
                raise
            except Exception:
                logger.exception("Failed to deploy mimic for device %d", device_id)

        if deployed > 0:
            verification_error: Exception | None = None
            try:
                conflicts = await self._ip_manager.verify_batch_ownership(batch_ips)
            except Exception as exc:
                verification_error = exc
                conflicts = {
                    ip: "ownership-probe-failed"
                    for ip in batch_ips
                }
                logger.exception(
                    "Post-deployment ownership verification failed; "
                    "evacuating every new decoy"
                )
            deployed = max(0, deployed - len(conflicts))
            await self._evacuate_verified_conflicts(
                conflicts,
                context="Post-deployment ownership verification",
            )
            if verification_error is not None:
                raise MimicDeploymentError(
                    "Mimic post-deployment ownership verification failed"
                ) from verification_error

        if deployed > 0:
            logger.info("Deployed %d new mimic decoys", deployed)
        else:
            raise MimicDeploymentError(
                "Could not deploy any of "
                f"{len(device_profiles)} eligible mimic device(s). "
                "No verified-free isolated virtual address could be created."
            )
        return deployed

    async def _reconcile_existing_mimic_services(self) -> int:
        """Refresh per-port service rows without replacing host identity."""
        cursor = await self._db.execute(
            """SELECT primary_row.id, host.source_device_id
               FROM decoy_hosts host
               JOIN decoys primary_row
                 ON primary_row.host_id = host.id
                AND primary_row.is_primary = 1
               WHERE host.retired_at IS NULL
                 AND host.source_device_id IS NOT NULL
                 AND primary_row.status = 'active'
               ORDER BY primary_row.id"""
        )
        existing_hosts = list(await cursor.fetchall())
        changed_hosts = 0
        for host_row in existing_hosts:
            device_id = int(host_row["source_device_id"])
            profiles = await self._engine.get_profiles_for_device(device_id)
            if not profiles:
                # Do not erase a whole host on one empty/transient scout. Port
                # removal is reconciled whenever at least one authoritative
                # service remains for the source.
                continue
            try:
                if await self._reconcile_mimic_service_rows(
                    int(host_row["id"]),
                    device_id,
                    profiles,
                ):
                    changed_hosts += 1
            except Exception:
                # All service-row/template mutations before the explicit
                # commit are one SQLite transaction. Never leave a half-split
                # host behind when any statement fails.
                await self._db.rollback()
                raise
        return changed_hosts

    async def _reconcile_mimic_service_rows(
        self,
        primary_id: int,
        device_id: int,
        profiles: list,
    ) -> bool:
        """Add, refresh, or retire services while preserving stable IDs."""
        device_cursor = await self._db.execute(
            "SELECT device_type, hostname FROM devices WHERE id = ?",
            (device_id,),
        )
        device = await device_cursor.fetchone()
        if device is None:
            return False
        template = self._template_gen.generate(
            profiles,
            device["device_type"],
            device["hostname"],
        )
        fresh_configs = self._build_port_configs(profiles, template)
        if not fresh_configs:
            return False

        identity_cursor = await self._db.execute(
            """SELECT primary_row.*, host.id AS durable_host_id,
                      host.hostname, host.template_id,
                      host.tls_cert_pem, host.tls_key_pem
               FROM decoys primary_row
               JOIN decoy_hosts host ON host.id = primary_row.host_id
               WHERE primary_row.id = ?
                 AND host.retired_at IS NULL""",
            (primary_id,),
        )
        primary = await identity_cursor.fetchone()
        if primary is None:
            return False
        host_id = int(primary["durable_host_id"])
        hostname = str(primary["hostname"])
        bind_address = str(primary["bind_address"])
        template_id = primary["template_id"]

        credential_cursor = await self._db.execute(
            """SELECT pc.*
               FROM planted_credentials pc
               JOIN decoys service ON service.id = pc.decoy_id
               WHERE service.host_id = ?
               ORDER BY pc.id""",
            (host_id,),
        )
        credential_rows = list(await credential_cursor.fetchall())
        credentials = [
            GeneratedCredential(
                credential_type=row["credential_type"],
                credential_value=row["credential_value"],
                planted_location=row["planted_location"],
                canary_hostname=row["canary_hostname"],
            )
            for row in credential_rows
        ]
        _, credentials_by_port = self._plant_http_credentials(
            credentials,
            fresh_configs,
        )

        service_cursor = await self._db.execute(
            """SELECT * FROM decoys
               WHERE host_id = ?
               ORDER BY is_primary DESC, id""",
            (host_id,),
        )
        existing_rows = list(await service_cursor.fetchall())
        existing_by_key = {
            (
                int(row["port"]),
                str(row["protocol"] or "tcp").lower(),
            ): row
            for row in existing_rows
        }
        fresh_by_key = {
            (
                int(config["port"]),
                str(config.get("protocol") or "tcp").lower(),
            ): config
            for config in fresh_configs
        }
        primary_key = (
            int(primary["port"]),
            str(primary["protocol"] or "tcp").lower(),
        )
        primary_removed = primary_key not in fresh_by_key
        if primary_removed:
            active_mimic = self._active_mimics.get(primary_id)
            if active_mimic is not None:
                deactivated = await self._deactivate_failed_mimic(
                    decoy_id=primary_id,
                    bind_address=bind_address,
                    mimic=active_mimic,
                )
                if not deactivated:
                    raise MimicCleanupError(
                        f"Could not safely stop mimic {primary_id} before "
                        "promoting its replacement primary service"
                    )
        now = datetime.now(UTC).isoformat()
        changed = False
        active_ids_by_port: dict[int, int] = {}
        active_ids_by_key: dict[tuple[int, str], int] = {}
        retired_service_rows: list[Any] = []
        service_status = "stopped" if primary_removed else "active"

        if template_id is not None:
            await self._db.execute(
                """UPDATE mimic_templates
                   SET source_ip = ?, device_category = ?, routes_json = ?,
                       server_header = ?, credential_types_json = ?,
                       mdns_service_type = ?, mdns_name = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    template.source_ip,
                    template.device_category,
                    json.dumps(template.routes),
                    template.server_header,
                    json.dumps(template.credential_types),
                    template.mdns_service_type,
                    template.mdns_name,
                    now,
                    template_id,
                ),
            )

        for key, config in fresh_by_key.items():
            port, protocol = key
            service_name = str(config.get("service_name") or f"Port {port}")
            durable_config = {
                "template_id": template_id,
                "mdns_hostname": mdns_label(hostname),
                "port_configs": [config],
            }
            encoded_config = json.dumps(durable_config)
            existing = existing_by_key.get(key)
            if existing is None:
                insert_cursor = await self._db.execute(
                    """INSERT INTO decoys
                       (name, decoy_type, bind_address, port, status, config,
                        created_at, updated_at, host_id, protocol,
                        service_name, is_primary)
                       VALUES (?, 'mimic', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                    (
                        hostname,
                        bind_address,
                        port,
                        service_status,
                        encoded_config,
                        now,
                        now,
                        host_id,
                        protocol,
                        service_name,
                    ),
                )
                if insert_cursor.lastrowid is None:
                    raise RuntimeError("Reconciled service insert returned no ID")
                service_id = int(insert_cursor.lastrowid)
                changed = True
            else:
                service_id = int(existing["id"])
                if (
                    existing["config"] != encoded_config
                    or existing["service_name"] != service_name
                    or existing["status"] != service_status
                    or existing["retired_at"] is not None
                ):
                    await self._db.execute(
                        """UPDATE decoys
                           SET name = ?, status = ?, config = ?,
                               service_name = ?, retired_at = NULL,
                               retirement_reason = NULL, updated_at = ?
                           WHERE id = ?""",
                        (
                            hostname,
                            service_status,
                            encoded_config,
                            service_name,
                            now,
                            service_id,
                        ),
                    )
                    changed = True
            active_ids_by_port.setdefault(port, service_id)
            active_ids_by_key[key] = service_id

        for key, existing in existing_by_key.items():
            if key in fresh_by_key:
                continue
            if existing["retired_at"] is None:
                retired_service_rows.append(existing)
                await self._db.execute(
                    """UPDATE decoys
                       SET status = 'stopped',
                           retired_at = ?,
                           retirement_reason = 'source_service_removed',
                           updated_at = ?
                       WHERE id = ?""",
                    (now, now, existing["id"]),
                )
                changed = True

        restart_id = primary_id
        if primary_removed:
            first_key = next(iter(fresh_by_key))
            restart_id = active_ids_by_key[first_key]
            await self._db.execute(
                "UPDATE decoys SET is_primary = 0 WHERE host_id = ?",
                (host_id,),
            )
            await self._db.execute(
                "UPDATE decoys SET is_primary = 1 WHERE id = ?",
                (restart_id,),
            )
            await self._db.execute(
                "UPDATE virtual_ips SET decoy_id = ? WHERE decoy_id = ?",
                (restart_id, primary_id),
            )
            changed = True

        for credential_row in credential_rows:
            owner_port = next(iter(credentials_by_port), None)
            if owner_port is None:
                continue
            target_id = active_ids_by_port.get(owner_port)
            if (
                target_id is not None
                and int(credential_row["decoy_id"]) != target_id
            ):
                await self._db.execute(
                    "UPDATE planted_credentials SET decoy_id = ? WHERE id = ?",
                    (target_id, credential_row["id"]),
                )
                changed = True

        if (
            any(config.get("tls") for config in fresh_configs)
            and (not primary["tls_cert_pem"] or not primary["tls_key_pem"])
        ):
            cert_pem, key_pem = generate_host_tls_identity(
                hostname,
                bind_address,
            )
            await self._db.execute(
                """UPDATE decoy_hosts
                   SET tls_cert_pem = ?, tls_key_pem = ?, updated_at = ?
                   WHERE id = ?""",
                (cert_pem, key_pem, now, host_id),
            )
            changed = True

        await self._db.commit()
        if not changed:
            return False
        restarted = await self.restart_mimic(restart_id)
        if not restarted:
            raise MimicDeploymentError(
                f"Updated services for mimic host {primary_id}, but its "
                "listener could not be restarted"
            )
        if retired_service_rows:
            await self._publish_group_status(
                restart_id,
                "removed",
                hostname=hostname,
                rows=retired_service_rows,
            )
        return True

    async def _publish_effective_mimic_status(
        self,
        ip: str,
        status: str,
    ) -> None:
        """Best-effort live status overlay for a network-degraded mimic."""
        match = next(
            (
                (decoy_id, mimic)
                for decoy_id, mimic in self._active_mimics.items()
                if mimic.bind_address == ip
            ),
            None,
        )
        if match is None:
            return
        decoy_id, mimic = match
        try:
            await self._publish_group_status(
                decoy_id,
                status,
                hostname=mimic.name,
            )
        except Exception:
            logger.exception(
                "Could not publish effective %s status for mimic %d",
                status,
                decoy_id,
            )

    async def _service_status_rows(self, primary_id: int) -> list[Any]:
        cursor = await self._db.execute(
            """SELECT service.*, dh.hostname
               FROM decoys primary_row
               JOIN decoys service
                 ON (
                     primary_row.host_id IS NOT NULL
                     AND service.host_id = primary_row.host_id
                 )
                 OR (
                     primary_row.host_id IS NULL
                     AND service.id = primary_row.id
                 )
               LEFT JOIN decoy_hosts dh ON dh.id = service.host_id
               WHERE primary_row.id = ?
                 AND service.retired_at IS NULL
               ORDER BY service.is_primary DESC, service.port, service.id""",
            (primary_id,),
        )
        return list(await cursor.fetchall())

    async def _publish_group_status(
        self,
        primary_id: int,
        status: str,
        *,
        hostname: str | None = None,
        rows: list[Any] | None = None,
    ) -> None:
        """Publish one compatible status event for every host service row."""
        service_rows = (
            rows
            if rows is not None
            else await self._service_status_rows(primary_id)
        )
        updated_at = datetime.now(UTC).isoformat()
        for row in service_rows:
            row_hostname = hostname
            if row_hostname is None:
                try:
                    row_hostname = row["hostname"]
                except (IndexError, KeyError):
                    row_hostname = None
            await self._event_bus.publish(
                "decoy.status_changed",
                {
                    "id": int(row["id"]),
                    "host_id": row["host_id"],
                    "hostname": row_hostname,
                    "name": row_hostname or row["name"],
                    "decoy_type": "mimic",
                    "bind_address": row["bind_address"],
                    "port": int(row["port"]),
                    "protocol": row["protocol"] or "tcp",
                    "service_name": row["service_name"],
                    "status": status,
                    "connection_count": int(row["connection_count"] or 0),
                    "credential_trip_count": int(
                        row["credential_trip_count"] or 0
                    ),
                    "created_at": row["created_at"],
                    "updated_at": updated_at,
                },
            )

    async def _evacuate_verified_conflicts(
        self,
        conflicts: dict[str, str],
        *,
        context: str,
    ) -> None:
        """Attempt every conflicted teardown before reporting aggregate failure."""
        if not conflicts:
            return

        # Batch verification may already have withdrawn every listed address.
        # Tell live clients before teardown so the first cleanup failure cannot
        # leave later withdrawn mimics displayed as active.
        for ip in sorted(conflicts):
            await self._publish_effective_mimic_status(ip, "degraded")

        failures: list[str] = []
        for ip in sorted(conflicts):
            mac = conflicts[ip]
            logger.error(
                "%s found %s at %s; evacuating mimic",
                context,
                mac,
                ip,
            )
            try:
                removed = await self.handle_ip_conflict(ip)
            except Exception:
                failures.append(ip)
                logger.exception(
                    "%s cleanup failed for %s; continuing remaining "
                    "conflicted mimics",
                    context,
                    ip,
                )
                continue
            if not removed:
                failures.append(ip)
                logger.error("%s cleanup was incomplete for %s", context, ip)

        if failures:
            # Do not deploy or reuse anything after an unconfirmed teardown.
            # Existing PF state and runtime objects remain available for a
            # protected retry or restart reconciliation.
            self._network_ready = False
            raise MimicCleanupError(
                f"{context} cleanup is incomplete for "
                + ", ".join(sorted(failures))
            )

    @_serialized_background_lifecycle
    async def reconcile_ip_conflicts(
        self,
        arp_results: list[tuple[str, str]] | None = None,
        *,
        redeploy: bool = True,
    ) -> int:
        """Evacuate conflicts and immediately refill on a verified-free IP."""
        if not self._network_ready:
            return 0
        conflicts = await self._ip_manager.find_conflicts(arp_results)
        evacuated = 0
        for ip, mac in conflicts.items():
            logger.error(
                "Real device %s claimed mimic address %s; evacuating decoy",
                mac,
                ip,
            )
            if await self.handle_ip_conflict(ip):
                evacuated += 1
        if evacuated and redeploy:
            await self.evaluate_and_deploy(arp_results)
        return evacuated

    @_serialized_lifecycle
    async def _deploy_mimic_for_device(
        self,
        device_id: int,
        profiles: list,
        *,
        arp_results: list[tuple[str, str]] | None = None,
        suggested_hostname: str | None = None,
        allow_identifiers: bool = False,
    ) -> bool:
        """Deploy a mimic decoy for a specific device."""
        # Look up device info
        cursor = await self._db.execute(
            "SELECT device_type, hostname FROM devices WHERE id = ?",
            (device_id,),
        )
        device_row = await cursor.fetchone()
        if not device_row:
            logger.warning("Device %d not found in database, skipping mimic deploy", device_id)
            return False

        device_type = device_row["device_type"]
        hostname = device_row["hostname"]

        # Generate template
        template = self._template_gen.generate(profiles, device_type, hostname)
        if not template.routes and not any(p.protocol_version for p in profiles):
            logger.info("No HTTP routes or banners for device %d, skipping mimic", device_id)
            return False

        # Verify ownership directly on the LAN before aliasing. Database-only
        # exclusions can hide conflicts because virtual IP rows are filtered
        # from normal device discovery.
        ips = await self._ip_manager.allocate_verified(1, arp_results)
        if not ips:
            logger.warning("No verified-free virtual IPs available for mimic deployment")
            return False
        virtual_ip = ips[0]

        # Build port configs for the mimic decoy
        port_configs = self._build_port_configs(profiles, template)
        if not port_configs:
            self._ip_manager.release_reservation(virtual_ip)
            logger.warning("No usable ports for mimic device %d", device_id)
            return False
        credentials, credentials_by_port = self._plant_http_credentials(
            self._generate_credentials(template.credential_types),
            port_configs,
        )

        # Persist template to DB
        now = datetime.now(UTC).isoformat()
        template_id: int | None = None
        decoy_id: int | None = None
        host_id: int | None = None
        service_ids: list[int] = []
        try:
            template_cursor = await self._db.execute(
                """INSERT INTO mimic_templates
                   (source_device_id, source_ip, device_category, routes_json,
                    server_header, credential_types_json, mdns_service_type,
                    mdns_name, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device_id, template.source_ip, template.device_category,
                    json.dumps(template.routes), template.server_header,
                    json.dumps(template.credential_types), template.mdns_service_type,
                    template.mdns_name, now, now,
                ),
            )
            template_id = template_cursor.lastrowid

            # Generate mDNS hostname for this mimic
            existing_cursor = await self._db.execute(
                """SELECT hostname
                   FROM decoy_hosts
                   WHERE retired_at IS NULL"""
            )
            existing_hostnames = await self._observed_real_hostnames()
            existing_hostnames.extend(
                str(row["hostname"])
                for row in await existing_cursor.fetchall()
            )
            mdns_hostname = generate_mimic_hostname(
                mdns_name=hostname or template.mdns_name,
                device_category=template.device_category,
                virtual_ip=virtual_ip,
                existing_hostnames=existing_hostnames,
                suggested_names=(
                    [suggested_hostname]
                    if suggested_hostname is not None
                    else []
                ),
                allow_identifiers=allow_identifiers,
            )
            durable_hostname = await self._unique_generated_hostname(
                mdns_hostname,
                allow_identifiers=allow_identifiers,
            )
            mdns_hostname = mdns_label(durable_hostname)

            # Keep the durable row stopped until PF, the alias, and the listener
            # are all live. The dashboard must never advertise a partially
            # provisioned mimic as active.
            mimic_name = durable_hostname
            tls_cert_pem: str | None = None
            tls_key_pem: str | None = None
            if any(config.get("tls") for config in port_configs):
                tls_cert_pem, tls_key_pem = generate_host_tls_identity(
                    mimic_name,
                    virtual_ip,
                )
            host_cursor = await self._db.execute(
                """INSERT INTO decoy_hosts
                   (hostname, bind_address, source_device_id, template_id,
                    tls_cert_pem, tls_key_pem, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    mimic_name,
                    virtual_ip,
                    device_id,
                    template_id,
                    tls_cert_pem,
                    tls_key_pem,
                    now,
                    now,
                ),
            )
            host_id = host_cursor.lastrowid
            if host_id is None:
                raise RuntimeError("Mimic host insert did not return an ID")

            # Scout profiles are a live inventory and are reconciled away when
            # a source service disappears. Persist one exact service behavior
            # per stable decoy row so every advertised port has its own ID.
            for index, port_config in enumerate(port_configs):
                decoy_config = {
                    "template_id": template_id,
                    "mdns_hostname": mdns_hostname,
                    "port_configs": [port_config],
                }
                decoy_cursor = await self._db.execute(
                    """INSERT INTO decoys
                       (name, decoy_type, bind_address, port, status, config,
                        created_at, updated_at, host_id, protocol,
                        service_name, is_primary)
                       VALUES (?, 'mimic', ?, ?, 'stopped', ?, ?, ?, ?, ?,
                               ?, ?)""",
                    (
                        mimic_name,
                        virtual_ip,
                        port_config["port"],
                        json.dumps(decoy_config),
                        now,
                        now,
                        host_id,
                        port_config.get("protocol", "tcp"),
                        port_config.get("service_name")
                        or get_service_name(int(port_config["port"]))
                        or f"Port {port_config['port']}",
                        1 if index == 0 else 0,
                    ),
                )
                if decoy_cursor.lastrowid is None:
                    raise RuntimeError("Mimic service insert did not return an ID")
                service_ids.append(int(decoy_cursor.lastrowid))
            decoy_id = service_ids[0]

            service_ids_by_port = {
                int(port_config["port"]): service_id
                for service_id, port_config in zip(
                    service_ids,
                    port_configs,
                    strict=True,
                )
            }
            for cred in credentials:
                owner_port = next(
                    (
                        port
                        for port, scoped in credentials_by_port.items()
                        if cred in scoped
                    ),
                    int(port_configs[0]["port"]),
                )
                await self._db.execute(
                    """INSERT INTO planted_credentials
                       (credential_type, credential_value, planted_location,
                        decoy_id, canary_hostname, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        cred.credential_type, cred.credential_value,
                        cred.planted_location,
                        service_ids_by_port[owner_port],
                        cred.canary_hostname,
                        now,
                    ),
                )
            await self._db.commit()
        except Exception:
            await self._db.rollback()
            self._ip_manager.release_reservation(virtual_ip)
            logger.exception(
                "Failed to persist provisioning state for mimic device %d",
                device_id,
            )
            return False
        assert template_id is not None
        assert decoy_id is not None
        assert host_id is not None

        # Request a private backend for every advertised port.
        port_remaps = self._compute_port_remaps(port_configs)

        # Create and start the mimic decoy
        mimic = MimicDecoy(
            decoy_id=decoy_id,
            name=mimic_name,
            bind_address=virtual_ip,
            port_configs=port_configs,
            server_header=template.server_header,
            planted_credentials=credentials,
            port_remaps=port_remaps,
            tls_cert_pem=tls_cert_pem,
            tls_key_pem=tls_key_pem,
            credentials_by_port=credentials_by_port,
            **self._backend_bind_kwargs(virtual_ip),
        )
        mimic.on_connection = lambda event, _did=decoy_id: self._handle_connection(
            event,
            decoy_id=_did,
        )

        # Install deny-all isolation before the address exists on the host.
        # Listeners then bind OS-assigned private ports while quarantine stays
        # active; only the final atomic PF replacement advertises them.
        exposed_ports = {config["port"] for config in port_configs}
        quarantined = (
            self._port_fwd is not None
            and await self._port_fwd.quarantine_endpoints(
                {decoy_id: virtual_ip}
            )
        )
        if not quarantined:
            logger.error(
                "Network quarantine setup failed for mimic %d; refusing to "
                "create its virtual address",
                decoy_id,
            )
            await self._rollback_failed_provisioning(
                decoy_id=decoy_id,
                template_id=template_id,
                virtual_ip=virtual_ip,
                mimic=mimic,
                alias_created=False,
            )
            return False

        # Only expose the IP after PF has committed a default-deny rule.
        alias_created = await self._ip_manager.add_alias(virtual_ip)
        if not alias_created:
            logger.error(
                "Failed to create protected virtual IP %s for mimic %d",
                virtual_ip,
                decoy_id,
            )
            await self._rollback_failed_provisioning(
                decoy_id=decoy_id,
                template_id=template_id,
                virtual_ip=virtual_ip,
                mimic=mimic,
                # A failed helper/database operation can leave the OS alias in
                # an indeterminate state. Attempt removal while PF stays live.
                alias_created=True,
            )
            return False

        try:
            await self._db.execute(
                "UPDATE virtual_ips SET decoy_id = ? WHERE ip_address = ?",
                (decoy_id, virtual_ip),
            )
            await self._db.commit()
            await mimic.start()

            assert self._port_fwd is not None
            isolated = await self._port_fwd.add_forwards(
                decoy_id,
                virtual_ip,
                mimic.port_remaps,
                exposed_ports=exposed_ports,
            )
            if not isolated:
                raise RuntimeError(
                    f"Could not advertise isolated ports for mimic {decoy_id}"
                )

            active_at = datetime.now(UTC).isoformat()
            await self._db.execute(
                """UPDATE decoys
                   SET status = 'active', updated_at = ?
                   WHERE host_id = ?""",
                (active_at, host_id),
            )
            await self._db.execute(
                "UPDATE decoy_hosts SET updated_at = ? WHERE id = ?",
                (active_at, host_id),
            )
            await self._db.commit()
        except Exception:
            await self._db.rollback()
            logger.exception("Failed to finish provisioning mimic decoy %d", decoy_id)
            await self._rollback_failed_provisioning(
                decoy_id=decoy_id,
                template_id=template_id,
                virtual_ip=virtual_ip,
                mimic=mimic,
                alias_created=True,
            )
            return False

        # Map every service to its primary BEFORE publishing the mimic. A
        # status read that observes _active_mimics without the mapping resolves
        # a sibling to itself, misses the dict, and reports a running host as
        # degraded.
        for service_id in service_ids:
            self._service_to_primary[service_id] = decoy_id
        self._active_mimics[decoy_id] = mimic

        # Register every credible service under the shared host identity.
        if self._mdns is not None:
            mdns_ready = await self._register_mdns_batch(
                self._mdns_registration_specs(
                    decoy_id=decoy_id,
                    virtual_ip=virtual_ip,
                    port_configs=port_configs,
                    configured_type=template.mdns_service_type,
                    hostname=mdns_hostname,
                )
            )
            if mdns_ready:
                self._mdns_degraded.discard(decoy_id)
            else:
                self._mdns_degraded.add(decoy_id)

        for service_id, port_config in zip(service_ids, port_configs, strict=True):
            try:
                await self._event_bus.publish(
                    "decoy.status_changed",
                    {
                        "id": service_id,
                        "host_id": host_id,
                        "hostname": mimic_name,
                        "name": mimic_name,
                        "decoy_type": "mimic",
                        "bind_address": virtual_ip,
                        "port": int(port_config["port"]),
                        "protocol": port_config.get("protocol", "tcp"),
                        "service_name": port_config.get("service_name"),
                        "status": self.effective_mimic_status(
                            service_id,
                            "active",
                        ),
                        "connection_count": 0,
                        "credential_trip_count": 0,
                        "created_at": now,
                        "updated_at": active_at,
                    },
                )
            except Exception:
                logger.exception(
                    "Mimic service %d is active but its status event could "
                    "not be published",
                    service_id,
                )

        logger.info(
            "Deployed mimic '%s' on %s as '%s' (device %d, %d ports)",
            mimic_name, virtual_ip, mdns_hostname, device_id, len(port_configs),
        )
        return True

    async def _rollback_failed_provisioning(
        self,
        *,
        decoy_id: int,
        template_id: int | None,
        virtual_ip: str,
        mimic: MimicDecoy,
        alias_created: bool,
    ) -> None:
        """Require a failed deployment to reach a fully cleaned state."""
        cleaned = await self._rollback_new_mimic(
            decoy_id=decoy_id,
            template_id=template_id,
            virtual_ip=virtual_ip,
            mimic=mimic,
            alias_created=alias_created,
        )
        if not cleaned:
            raise MimicCleanupError(
                f"Mimic {decoy_id} provisioning cleanup is incomplete; "
                "its stopped state and PF isolation were retained"
            )

    @_serialized_lifecycle
    async def _rollback_new_mimic(
        self,
        *,
        decoy_id: int,
        template_id: int | None,
        virtual_ip: str,
        mimic: MimicDecoy,
        alias_created: bool = True,
    ) -> bool:
        """Undo a failed deployment without ever exposing a host alias.

        PF protection is deliberately removed last. If the address or PF rule
        cannot be removed, the stopped durable row is retained so the cleanup
        can be retried and the dashboard does not lie about runtime state.
        """
        if alias_created:
            deactivated = await self._deactivate_failed_mimic(
                decoy_id=decoy_id,
                bind_address=virtual_ip,
                mimic=mimic,
            )
            if not deactivated:
                return False
        else:
            try:
                await mimic.stop()
            except Exception:
                logger.exception("Failed to stop unaliased mimic %d", decoy_id)
            if self._port_fwd is not None:
                if not await self._port_fwd.remove_forwards(decoy_id):
                    await self._set_mimic_status(decoy_id, "stopped")
                    return False
            self._ip_manager.release_reservation(virtual_ip)

        await self._delete_mimic_records(
            decoy_id=decoy_id,
            template_id=template_id,
            virtual_ip=virtual_ip,
            retirement_reason="provisioning_failed",
        )
        return True

    async def _delete_mimic_records(
        self,
        *,
        decoy_id: int,
        template_id: int | None,
        virtual_ip: str,
        delete_virtual_ip: bool = True,
        retirement_reason: str = "removed",
    ) -> None:
        """Retire a deactivated mimic without destroying forensic evidence."""
        service_rows = await self._service_rows_for_primary(decoy_id)
        service_ids = [int(row["id"]) for row in service_rows] or [decoy_id]
        host_id = (
            int(service_rows[0]["host_id"])
            if service_rows and service_rows[0]["host_id"] is not None
            else None
        )
        placeholders = ",".join("?" for _ in service_ids)
        retired_at = datetime.now(UTC).isoformat()
        await self._db.execute(
            f"""UPDATE decoys
                SET status = 'stopped',
                    retired_at = ?,
                    retirement_reason = ?,
                    updated_at = ?
                WHERE id IN ({placeholders})""",
            (retired_at, retirement_reason, retired_at, *service_ids),
        )
        if delete_virtual_ip:
            await self._db.execute(
                "DELETE FROM virtual_ips WHERE ip_address = ?",
                (virtual_ip,),
            )
        if host_id is not None:
            await self._db.execute(
                """UPDATE decoy_hosts
                   SET retired_at = ?, retirement_reason = ?, updated_at = ?
                   WHERE id = ?""",
                (retired_at, retirement_reason, retired_at, host_id),
            )
        await self._db.commit()

    async def _discard_unresumable_mimic(
        self,
        *,
        row: Any,
        template_id: int | None,
        reason: str,
        already_quarantined_and_withdrawn: bool,
    ) -> None:
        """Delete an invalid persisted mimic only after network cleanup."""
        decoy_id = int(row["id"])
        bind_address = row["bind_address"]
        logger.error(
            "Persisted mimic %d is unresumable (%s); retiring it before "
            "capacity can reuse %s",
            decoy_id,
            reason,
            bind_address,
        )

        cleaned = False
        if already_quarantined_and_withdrawn:
            if self._port_fwd is not None:
                try:
                    cleaned = await self._port_fwd.remove_forwards(decoy_id)
                except Exception:
                    logger.exception(
                        "Could not remove startup quarantine for unresumable "
                        "mimic %d",
                        decoy_id,
                    )
        else:
            cleaned = await self._deactivate_failed_mimic(
                decoy_id=decoy_id,
                bind_address=bind_address,
                mimic=None,
            )

        if not cleaned:
            # A retained row must not still claim to be active while no runtime
            # listener exists. Block all further allocation until the next
            # startup reconciliation retries the protected cleanup.
            await self._set_mimic_status(decoy_id, "stopped")
            self._network_ready = False
            raise MimicCleanupError(
                f"Persisted mimic {decoy_id} is unresumable and its network "
                "cleanup is incomplete; capacity fill was blocked"
            )

        try:
            await self._delete_mimic_records(
                decoy_id=decoy_id,
                template_id=template_id,
                virtual_ip=bind_address,
                retirement_reason=f"unresumable: {reason}",
            )
            await self._db.execute(
                "DELETE FROM events WHERE event_type = 'decoy.status_changed' "
                "AND json_extract(payload, '$.id') = ? "
                "AND NOT EXISTS ("
                "    SELECT 1 FROM home_alerts ha WHERE ha.event_seq = events.seq"
                ")",
                (decoy_id,),
            )
            await self._db.commit()
        except Exception as exc:
            self._network_ready = False
            raise MimicCleanupError(
                f"Persisted mimic {decoy_id} is unresumable and its durable "
                "cleanup is incomplete; capacity fill was blocked"
            ) from exc

        try:
            await self._event_bus.publish(
                "decoy.status_changed",
                {
                    "id": decoy_id,
                    "name": row["name"],
                    "decoy_type": "mimic",
                    "bind_address": bind_address,
                    "port": row["port"],
                    "status": "removed",
                },
            )
        except Exception:
            logger.exception(
                "Unresumable mimic %d was retired but its removal event "
                "could not be published",
                decoy_id,
            )

    async def _set_mimic_status(self, decoy_id: int, status: str) -> None:
        """Persist the best-known mimic runtime state."""
        now = datetime.now(UTC).isoformat()
        await self._db.execute(
            """UPDATE decoys
               SET status = ?, updated_at = ?
               WHERE (
                   id = ? OR host_id = (
                       SELECT host_id FROM decoys WHERE id = ?
                   )
               )
               AND retired_at IS NULL""",
            (status, now, decoy_id, decoy_id),
        )
        await self._db.commit()

    @_serialized_lifecycle
    async def _deactivate_failed_mimic(
        self,
        *,
        decoy_id: int,
        bind_address: str,
        mimic: MimicDecoy | None,
    ) -> bool:
        """Stop a mimic while retaining isolation until its alias is gone."""
        if self._port_fwd is None:
            logger.error(
                "Cannot safely deactivate mimic %d without packet-filter isolation",
                decoy_id,
            )
            return False

        # Replace every redirect with deny-all before freeing a dynamic backend
        # port. Otherwise a failed alias withdrawal would leave ``rdr pass``
        # pointing at a now-unbound port on a still-published VIP. A host daemon
        # that later acquired that port could then answer through the stale
        # redirect and make the mimic reflect the real host.
        try:
            quarantined = await self._port_fwd.quarantine_endpoints(
                {decoy_id: bind_address}
            )
        except Exception:
            logger.exception(
                "Could not quarantine mimic %d before listener shutdown",
                decoy_id,
            )
            return False
        if not quarantined:
            logger.error(
                "Could not quarantine mimic %d before listener shutdown",
                decoy_id,
            )
            return False

        if self._mdns is not None:
            try:
                await self._mdns.unregister(decoy_id)
            except Exception:
                logger.exception("Failed to unregister mDNS for mimic %d", decoy_id)
        if mimic is not None:
            try:
                await mimic.stop()
            except Exception:
                logger.exception("Failed to stop broken mimic %d", decoy_id)
                await self._set_mimic_status(decoy_id, "degraded")
                return False

        self._active_mimics.pop(decoy_id, None)
        self._mdns_degraded.discard(decoy_id)
        for service_id, primary_id in list(self._service_to_primary.items()):
            if primary_id == decoy_id:
                self._service_to_primary.pop(service_id, None)
        try:
            alias_removed = await self._ip_manager.remove_alias(bind_address)
        except Exception:
            # The listener is down and PF is deny-all, so report the runtime
            # truth while retaining both the durable row and quarantine for a
            # later cleanup retry.
            await self._set_mimic_status(decoy_id, "stopped")
            logger.exception(
                "Could not remove virtual IP %s for mimic %d; retaining PF "
                "isolation and persisted state for retry",
                bind_address,
                decoy_id,
            )
            return False
        if not alias_removed:
            # The listener is down, but the host still owns (or may own) the
            # address. Keep its default-deny PF rule and durable records.
            await self._set_mimic_status(decoy_id, "stopped")
            logger.error(
                "Could not remove virtual IP %s for mimic %d; retaining PF "
                "isolation and persisted state for retry",
                bind_address,
                decoy_id,
            )
            return False

        forwards_removed = await self._port_fwd.remove_forwards(decoy_id)
        if not forwards_removed:
            # The alias is already gone, so stale PF state is harmless.
            # Preserve the row so an explicit retry can finish cleanup.
            await self._set_mimic_status(decoy_id, "stopped")
            logger.error(
                "Could not remove PF state for mimic %d; persisted state "
                "was retained for retry",
                decoy_id,
            )
            return False

        await self._set_mimic_status(decoy_id, "stopped")
        return True

    async def _restore_alias_under_quarantine(
        self,
        *,
        decoy_id: int,
        bind_address: str,
        ownership_snapshot: list[tuple[str, str]] | None = None,
        already_quarantined_and_withdrawn: bool = False,
    ) -> bool:
        """Withdraw, verify, and restore a dormant mimic address safely.

        ``VirtualIPManager.active_ips`` includes addresses whose removal could
        not be verified, so membership can never authorize reuse. A confirmed
        deny-all rule remains installed throughout withdrawal and ownership
        verification. Alias-state uncertainty raises so startup cannot proceed;
        a confirmed ownership conflict returns ``False`` without exposure.
        Startup may pass the one fresh ownership snapshot taken after
        :meth:`prepare_persisted_network` withdrew the complete alias set.
        """
        if self._port_fwd is None:
            raise HelperUnavailableError(
                f"Cannot quarantine mimic {decoy_id} without packet-filter isolation"
            )
        if not already_quarantined_and_withdrawn:
            try:
                quarantined = await self._port_fwd.quarantine_endpoints(
                    {decoy_id: bind_address}
                )
            except Exception as exc:
                raise HelperUnavailableError(
                    f"Could not quarantine mimic {decoy_id} before alias withdrawal"
                ) from exc
            if not quarantined:
                raise HelperUnavailableError(
                    f"Could not confirm quarantine for mimic {decoy_id} "
                    "before alias withdrawal"
                )

            try:
                alias_removed = await self._ip_manager.remove_alias(bind_address)
            except Exception as exc:
                raise HelperUnavailableError(
                    f"Could not withdraw alias {bind_address} for mimic {decoy_id}"
                ) from exc
            if not alias_removed:
                raise HelperUnavailableError(
                    f"Could not withdraw alias {bind_address} for mimic {decoy_id}"
                )

        try:
            if ownership_snapshot is None:
                verified_free = await self._ip_manager.is_verified_free(
                    bind_address
                )
            else:
                verified_free = await self._ip_manager.is_verified_free(
                    bind_address,
                    ownership_snapshot,
                )
        except Exception:
            logger.exception(
                "Could not verify ownership of %s for mimic %d",
                bind_address,
                decoy_id,
            )
            return False
        if not verified_free:
            logger.error(
                "Cannot restore mimic %d: %s is owned or could not be verified",
                decoy_id,
                bind_address,
            )
            return False

        try:
            alias_added = await self._ip_manager.add_alias(bind_address)
        except Exception:
            logger.exception(
                "Could not restore quarantined IP %s for mimic %d",
                bind_address,
                decoy_id,
            )
            return False
        if not alias_added:
            logger.error(
                "Failed to restore quarantined IP %s for mimic %d",
                bind_address,
                decoy_id,
            )
            return False
        return True

    @staticmethod
    def _compute_port_remaps(port_configs: list[dict]) -> dict[int, int]:
        """Request an OS-assigned private backend for every advertised port."""
        return {int(config["port"]): 0 for config in port_configs}

    async def _normalize_mimic_identity(
        self,
        *,
        decoy_id: int,
        current_name: str,
        config: dict[str, Any],
        template_row: aiosqlite.Row,
        bind_address: str,
    ) -> tuple[str, str]:
        """Load the durable host identity, backfilling legacy mimic names."""
        identity_cursor = await self._db.execute(
            """SELECT dh.id, dh.hostname
               FROM decoys d
               JOIN decoy_hosts dh ON dh.id = d.host_id
               WHERE d.id = ?""",
            (decoy_id,),
        )
        identity_row = await identity_cursor.fetchone()
        if identity_row is not None:
            mimic_name = str(identity_row["hostname"])
            mdns_hostname = mdns_label(mimic_name)
            service_rows = await self._service_rows_for_primary(decoy_id)
            changed = False
            for service_row in service_rows:
                try:
                    decoded_config = json.loads(service_row["config"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    decoded_config = {}
                service_config = (
                    dict(decoded_config)
                    if isinstance(decoded_config, dict)
                    else {}
                )
                original_config = dict(service_config)
                if service_config.get("mdns_hostname") != mdns_hostname:
                    service_config["mdns_hostname"] = mdns_hostname
                    changed = True
                if (
                    service_row["name"] != mimic_name
                    or service_config != original_config
                ):
                    await self._db.execute(
                        """UPDATE decoys
                           SET name = ?, config = ?
                           WHERE id = ?""",
                        (
                            mimic_name,
                            json.dumps(service_config),
                            service_row["id"],
                        ),
                    )
                    changed = True
            if changed:
                await self._db.commit()
            return mimic_name, mdns_hostname

        device_category = template_row["device_category"] or "generic"
        mdns_hostname = generate_mimic_hostname(
            mdns_name=None,
            device_category=device_category,
            virtual_ip=bind_address,
        )
        mimic_name = current_name
        existing_hostname = config.get("mdns_hostname")

        update_config = existing_hostname != mdns_hostname
        if update_config:
            config["mdns_hostname"] = mdns_hostname

        previous_display_name = (
            mimic_display_name(existing_hostname)
            if isinstance(existing_hostname, str) and existing_hostname
            else None
        )
        if (
            should_refresh_mimic_name(current_name, existing_hostname)
            or current_name == previous_display_name
        ):
            mimic_name = mimic_display_name(mdns_hostname)

        if update_config or mimic_name != current_name:
            await self._db.execute(
                "UPDATE decoys SET name = ?, config = ? WHERE id = ?",
                (mimic_name, json.dumps(config), decoy_id),
            )
            await self._db.commit()

        return mimic_name, mdns_hostname

    async def _register_mdns_batch(
        self,
        registrations: list[tuple[int, str, int, str, str, str]],
    ) -> bool:
        """Register independent mimic identities concurrently.

        Zeroconf performs an approximately one-second uniqueness probe for
        every service registration. Awaiting those probes one-by-one makes a
        Full-profile startup exceed the package health deadline even though
        every listener and PF rule is already ready. The generated service
        names are unique per virtual IP, so their independent probes can run
        together without weakening collision detection.
        """
        mdns = self._mdns
        if mdns is None:
            return True
        if not registrations:
            return True

        async def register_one(
            registration: tuple[int, str, int, str, str, str],
        ) -> bool:
            (
                decoy_id,
                virtual_ip,
                port,
                service_type,
                hostname,
                instance_name,
            ) = registration
            try:
                registered = await mdns.register(
                    decoy_id=decoy_id,
                    virtual_ip=virtual_ip,
                    port=port,
                    service_type=service_type,
                    hostname=hostname,
                    instance_name=instance_name,
                )
                return registered is not False
            except Exception:
                logger.exception(
                    "Failed to register mDNS for mimic %d",
                    decoy_id,
                )
                return False

        results = await asyncio.gather(
            *(register_one(item) for item in registrations)
        )
        return all(results)

    @staticmethod
    def _mdns_registration_specs(
        *,
        decoy_id: int,
        virtual_ip: str,
        port_configs: list[dict[str, Any]],
        configured_type: str | None,
        hostname: str,
    ) -> list[tuple[int, str, int, str, str, str]]:
        """Build one credible Bonjour registration per emulated service."""
        typed: list[tuple[dict[str, Any], str]] = []
        for config in port_configs:
            service_type = mdns_service_type_for(
                port=int(config["port"]),
                service_name=config.get("service_name"),
                configured_type=configured_type,
            )
            if service_type is not None:
                typed.append((config, service_type))

        type_counts: dict[str, int] = {}
        for _config, service_type in typed:
            type_counts[service_type] = type_counts.get(service_type, 0) + 1

        return [
            (
                decoy_id,
                virtual_ip,
                int(config["port"]),
                service_type,
                hostname,
                (
                    f"{hostname}-{config['port']}"
                    if type_counts[service_type] > 1
                    else hostname
                ),
            )
            for config, service_type in typed
        ]

    @_serialized_lifecycle
    async def update_mimic_hostname(
        self,
        decoy_id: int,
        hostname: str,
    ) -> dict[str, Any]:
        """Atomically rename one virtual host and all of its service rows."""
        canonical = canonicalize_decoy_hostname(hostname)
        new_label = mdns_label(canonical)
        primary_id = await self._resolve_primary_id(decoy_id)
        cursor = await self._db.execute(
            """SELECT primary_row.*, dh.hostname, dh.id AS durable_host_id,
                      dh.tls_cert_pem, dh.tls_key_pem,
                      mt.mdns_service_type
               FROM decoys primary_row
               JOIN decoy_hosts dh ON dh.id = primary_row.host_id
               LEFT JOIN mimic_templates mt ON mt.id = dh.template_id
               WHERE primary_row.id = ?
                 AND primary_row.decoy_type = 'mimic'
                 AND primary_row.is_primary = 1""",
            (primary_id,),
        )
        primary_row = await cursor.fetchone()
        if primary_row is None:
            raise ValueError("Decoy does not have a durable virtual-host identity")

        host_id = int(primary_row["durable_host_id"])
        bind_address = str(primary_row["bind_address"])
        old_hostname = canonicalize_decoy_hostname(primary_row["hostname"])
        old_label = mdns_label(old_hostname)
        if old_hostname == canonical:
            service_rows = await self._service_rows_for_primary(primary_id)
            return {
                "host_id": host_id,
                "hostname": canonical,
                "bind_address": bind_address,
                "decoy_ids": [int(row["id"]) for row in service_rows],
            }

        if (
            new_label != old_label
            and new_label in await self._observed_real_hostname_labels()
        ):
            raise RuntimeError(
                f"Hostname label {new_label} is already used by a real device "
                "or the sensor host"
            )

        collision_cursor = await self._db.execute(
            """SELECT hostname
               FROM decoy_hosts
               WHERE id != ?
                 AND retired_at IS NULL
               ORDER BY id""",
            (host_id,),
        )
        collisions = list(await collision_cursor.fetchall())
        if any(
            mdns_label(str(row["hostname"])) == new_label
            for row in collisions
        ):
            raise RuntimeError(
                f"Hostname label {new_label} is already assigned to another "
                "fake host"
            )
        service_rows = await self._service_rows_for_primary(primary_id)

        try:
            primary_config = json.loads(primary_row["config"] or "{}")
        except (TypeError, json.JSONDecodeError):
            primary_config = {}
        if not isinstance(primary_config, dict):
            primary_config = {}
        template_id = primary_config.get("template_id")
        template_cursor = await self._db.execute(
            "SELECT routes_json FROM mimic_templates WHERE id = ?",
            (template_id,),
        )
        template_row = await template_cursor.fetchone()
        routes: Any = []
        if template_row is not None:
            try:
                routes = json.loads(template_row["routes_json"] or "[]")
            except (TypeError, json.JSONDecodeError):
                routes = []
        port_configs = await self._load_persisted_port_configs(
            decoy_id=primary_id,
            config=primary_config,
            routes=routes,
            primary_port=primary_row["port"],
        )
        configured_type = primary_row["mdns_service_type"]
        active_mimic = self._active_mimics.get(primary_id)
        tls_cert_pem: str | None = None
        tls_key_pem: str | None = None
        if any(bool(config.get("tls")) for config in port_configs):
            tls_cert_pem, tls_key_pem = generate_host_tls_identity(
                canonical,
                bind_address,
            )

        mdns_label_changed = old_label != new_label
        if (
            mdns_label_changed
            and active_mimic is not None
            and self._mdns is not None
        ):
            await self._mdns.unregister(primary_id)
            registered = await self._register_mdns_batch(
                self._mdns_registration_specs(
                    decoy_id=primary_id,
                    virtual_ip=bind_address,
                    port_configs=port_configs,
                    configured_type=configured_type,
                    hostname=new_label,
                )
            )
            if not registered:
                await self._mdns.unregister(primary_id)
                restored = await self._register_mdns_batch(
                    self._mdns_registration_specs(
                        decoy_id=primary_id,
                        virtual_ip=bind_address,
                        port_configs=port_configs,
                        configured_type=configured_type,
                        hostname=old_label,
                    )
                )
                if not restored:
                    raise RuntimeError(
                        "New hostname could not be advertised and the previous "
                        "mDNS registration could not be restored"
                    )
                raise RuntimeError(
                    "New hostname could not be advertised; previous hostname "
                    "was restored"
                )

        updated_at = datetime.now(UTC).isoformat()
        await self._db.execute("SAVEPOINT mimic_hostname_update")
        try:
            await self._db.execute(
                """UPDATE decoy_hosts
                   SET hostname = ?,
                       tls_cert_pem = COALESCE(?, tls_cert_pem),
                       tls_key_pem = COALESCE(?, tls_key_pem),
                       updated_at = ?
                   WHERE id = ?""",
                (
                    canonical,
                    tls_cert_pem,
                    tls_key_pem,
                    updated_at,
                    host_id,
                ),
            )
            for row in service_rows:
                try:
                    config = json.loads(row["config"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    config = {}
                if not isinstance(config, dict):
                    config = {}
                config["mdns_hostname"] = new_label
                await self._db.execute(
                    """UPDATE decoys
                       SET name = ?, config = ?, updated_at = ?
                       WHERE id = ?""",
                    (
                        canonical,
                        json.dumps(config),
                        updated_at,
                        row["id"],
                    ),
                )
            await self._db.execute("RELEASE SAVEPOINT mimic_hostname_update")
            await self._db.commit()
        except Exception:
            await self._db.execute("ROLLBACK TO SAVEPOINT mimic_hostname_update")
            await self._db.execute("RELEASE SAVEPOINT mimic_hostname_update")
            if (
                mdns_label_changed
                and active_mimic is not None
                and self._mdns is not None
            ):
                await self._mdns.unregister(primary_id)
                await self._register_mdns_batch(
                    self._mdns_registration_specs(
                        decoy_id=primary_id,
                        virtual_ip=bind_address,
                        port_configs=port_configs,
                        configured_type=configured_type,
                        hostname=old_label,
                    )
                )
            raise

        if active_mimic is not None:
            active_mimic.rename_identity(
                canonical,
                cert_pem=tls_cert_pem,
                key_pem=tls_key_pem,
            )

        decoy_ids = [int(row["id"]) for row in service_rows]
        try:
            await self._event_bus.publish(
                "decoy.hostname_changed",
                {
                    "host_id": host_id,
                    "hostname": canonical,
                    "bind_address": bind_address,
                    "decoy_ids": decoy_ids,
                    "updated_at": updated_at,
                },
            )
        except Exception:
            logger.exception(
                "Hostname for mimic host %d was saved but its live event "
                "could not be published",
                host_id,
            )

        return {
            "host_id": host_id,
            "hostname": canonical,
            "bind_address": bind_address,
            "decoy_ids": decoy_ids,
        }

    def _build_port_configs(
        self, profiles: list, template: MimicTemplate,
    ) -> list[dict]:
        """Build port configs for MimicDecoy from profiles and template."""
        return self._port_configs_for_profiles(profiles, template.routes)

    @staticmethod
    def _port_configs_for_profiles(
        profiles: list,
        routes: list,
    ) -> list[dict[str, Any]]:
        """Build one TCP listener configuration per advertised port."""
        configs: list[dict] = []
        routes_by_port: dict[int, list[dict[str, Any]]] = {}
        for route in routes:
            if not isinstance(route, dict) or "port" not in route:
                continue
            try:
                route_port = int(route["port"])
            except (TypeError, ValueError):
                continue
            routes_by_port.setdefault(route_port, []).append(dict(route))
        seen_ports: set[int] = set()

        for profile in profiles:
            port = int(profile.port)
            if (
                str(profile.protocol).lower() != "tcp"
                or not 1 <= port <= 65535
                or port in seen_ports
            ):
                continue
            seen_ports.add(port)
            protocol = str(profile.protocol or "tcp").lower()
            config: dict[str, Any] = {
                "port": port,
                "protocol": protocol,
                "service_name": (
                    profile.service_name
                    or get_service_name(port)
                    or f"Port {port}"
                ),
            }
            if profile.http_server_header:
                config["server_header"] = profile.http_server_header
            if profile.tls_cn or port in {443, 8443, 993, 995, 8883}:
                config["tls"] = True

            if port in routes_by_port:
                config["routes"] = routes_by_port[port]
            elif profile.http_status is not None:
                config["routes"] = [{
                    "path": "/",
                    "method": "GET",
                    "status": profile.http_status,
                    "headers": profile.http_headers or {},
                    "body": profile.http_body_snippet or "",
                }]
            elif profile.protocol_version:
                config["protocol_banner"] = profile.protocol_version
            else:
                config["protocol_banner"] = ""

            configs.append(config)

        return configs

    @staticmethod
    def _normalize_persisted_port_configs(value: Any) -> list[dict[str, Any]]:
        """Validate the durable endpoint shape before binding listeners."""
        if not isinstance(value, list):
            return []

        configs: list[dict[str, Any]] = []
        seen_ports: set[int] = set()
        for raw_config in value:
            if not isinstance(raw_config, dict):
                continue
            raw_port = raw_config.get("port")
            if (
                isinstance(raw_port, bool)
                or not isinstance(raw_port, (int, str))
            ):
                continue
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535 or port in seen_ports:
                continue

            config: dict[str, Any] = {"port": port}
            protocol = str(raw_config.get("protocol") or "tcp").lower()
            config["protocol"] = protocol if protocol in {"tcp", "udp"} else "tcp"
            config["service_name"] = str(
                raw_config.get("service_name")
                or get_service_name(port)
                or f"Port {port}"
            )
            server_header = raw_config.get("server_header")
            if isinstance(server_header, str) and server_header:
                config["server_header"] = server_header
            if bool(raw_config.get("tls")) or port in {
                443,
                8443,
                993,
                995,
                8883,
            }:
                config["tls"] = True
            routes = raw_config.get("routes")
            if isinstance(routes, list):
                valid_routes = [
                    dict(route) for route in routes if isinstance(route, dict)
                ]
                if valid_routes:
                    config["routes"] = valid_routes
            banner = raw_config.get("protocol_banner")
            if "routes" not in config and isinstance(banner, str):
                config["protocol_banner"] = banner
            if "routes" not in config and "protocol_banner" not in config:
                config["protocol_banner"] = ""

            configs.append(config)
            seen_ports.add(port)

        return configs

    @classmethod
    def _legacy_port_configs(
        cls,
        routes: Any,
        primary_port: Any,
    ) -> list[dict[str, Any]]:
        """Recover pre-durable-config mimics from the data they did persist."""
        by_port: dict[int, dict[str, Any]] = {}

        if (
            not isinstance(primary_port, bool)
            and isinstance(primary_port, (int, str))
        ):
            try:
                port = int(primary_port)
            except (TypeError, ValueError):
                port = 0
            if 1 <= port <= 65535:
                by_port[port] = {
                    "port": port,
                    "protocol": "tcp",
                    "service_name": get_service_name(port) or f"Port {port}",
                    "protocol_banner": "",
                }

        if isinstance(routes, list):
            for raw_route in routes:
                if not isinstance(raw_route, dict):
                    continue
                raw_port = raw_route.get("port")
                if (
                    isinstance(raw_port, bool)
                    or not isinstance(raw_port, (int, str))
                ):
                    continue
                try:
                    port = int(raw_port)
                except (TypeError, ValueError):
                    continue
                if not 1 <= port <= 65535:
                    continue
                config = by_port.setdefault(
                    port,
                    {
                        "port": port,
                        "protocol": "tcp",
                        "service_name": get_service_name(port) or f"Port {port}",
                    },
                )
                config.pop("protocol_banner", None)
                config.setdefault("routes", []).append(dict(raw_route))

        return cls._normalize_persisted_port_configs(
            [by_port[port] for port in sorted(by_port)]
        )

    async def _load_persisted_port_configs(
        self,
        *,
        decoy_id: int,
        config: dict[str, Any],
        routes: Any,
        primary_port: Any,
    ) -> list[dict[str, Any]]:
        """Load exact durable endpoints, backfilling records from older builds."""
        group_cursor = await self._db.execute(
            """SELECT service.id, service.port, service.protocol,
                      service.service_name, service.config
               FROM decoys requested
               JOIN decoys service
                ON requested.host_id IS NOT NULL
                AND service.host_id = requested.host_id
               WHERE requested.id = ?
                 AND service.retired_at IS NULL
               ORDER BY service.is_primary DESC, service.port, service.id""",
            (decoy_id,),
        )
        group_rows = list(await group_cursor.fetchall())
        if group_rows:
            combined: list[dict[str, Any]] = []
            seen: set[tuple[int, str]] = set()
            backfilled = False
            for row in group_rows:
                try:
                    service_config = json.loads(row["config"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    service_config = {}
                if not isinstance(service_config, dict):
                    service_config = {}
                normalized = self._normalize_persisted_port_configs(
                    service_config.get("port_configs")
                )
                if not normalized:
                    normalized = [{
                        "port": int(row["port"]),
                        "protocol": row["protocol"] or "tcp",
                        "service_name": (
                            row["service_name"]
                            or get_service_name(int(row["port"]))
                            or f"Port {row['port']}"
                        ),
                        "protocol_banner": "",
                    }]
                    service_config["port_configs"] = normalized
                    await self._db.execute(
                        "UPDATE decoys SET config = ? WHERE id = ?",
                        (json.dumps(service_config), row["id"]),
                    )
                    backfilled = True
                service = normalized[0]
                key = (
                    int(service["port"]),
                    str(service.get("protocol") or "tcp"),
                )
                if key not in seen:
                    combined.append(service)
                    seen.add(key)
            if backfilled:
                await self._db.commit()
            return combined

        stored = self._normalize_persisted_port_configs(
            config.get("port_configs")
        )
        port_configs = stored or self._legacy_port_configs(routes, primary_port)
        if port_configs and config.get("port_configs") != port_configs:
            config["port_configs"] = port_configs
            await self._db.execute(
                "UPDATE decoys SET config = ? WHERE id = ?",
                (json.dumps(config), decoy_id),
            )
            await self._db.commit()
        return port_configs

    async def _load_or_create_tls_identity(
        self,
        *,
        decoy_id: int,
        hostname: str,
        bind_address: str,
        port_configs: list[dict[str, Any]],
    ) -> tuple[str | None, str | None]:
        """Return the durable TLS identity required by this fake host."""
        if not any(bool(config.get("tls")) for config in port_configs):
            return None, None

        cursor = await self._db.execute(
            """SELECT dh.id, dh.tls_cert_pem, dh.tls_key_pem
               FROM decoys d
               LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
               WHERE d.id = ?""",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if (
            row is not None
            and row["tls_cert_pem"]
            and row["tls_key_pem"]
        ):
            return str(row["tls_cert_pem"]), str(row["tls_key_pem"])

        cert_pem, key_pem = generate_host_tls_identity(
            hostname,
            bind_address,
        )
        if row is not None and row["id"] is not None:
            await self._db.execute(
                """UPDATE decoy_hosts
                   SET tls_cert_pem = ?, tls_key_pem = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    cert_pem,
                    key_pem,
                    datetime.now(UTC).isoformat(),
                    row["id"],
                ),
            )
            await self._db.commit()
        return cert_pem, key_pem

    def _generate_credentials(self, credential_types: list[str]) -> list[GeneratedCredential]:
        """Generate credentials based on template strategy."""
        creds: list[GeneratedCredential] = []
        for cred_type in credential_types:
            if cred_type == "ha_token":
                creds.append(self._cred_gen.generate_ha_token())
            elif cred_type == "ssh_key":
                creds.append(self._cred_gen.generate_ssh_key())
            elif cred_type == "env_file":
                creds.append(self._cred_gen.generate_env_file())
            elif cred_type == "password":
                creds.extend(self._cred_gen.generate_passwords_file())
        return creds

    @staticmethod
    def _plant_http_credentials(
        credentials: list[GeneratedCredential],
        port_configs: list[dict[str, Any]],
    ) -> tuple[
        list[GeneratedCredential],
        dict[int, list[GeneratedCredential]],
    ]:
        """Expose bait only on one credible HTTP service and scope detection."""
        owner = next(
            (
                config
                for config in port_configs
                if isinstance(config.get("routes"), list)
                and config["routes"]
            ),
            None,
        )
        if owner is None or not credentials:
            return [], {}

        by_location: dict[str, list[GeneratedCredential]] = {}
        for credential in credentials:
            by_location.setdefault(
                credential.planted_location,
                [],
            ).append(credential)

        routes = list(owner.get("routes", []))
        existing_paths = {
            str(route.get("path"))
            for route in routes
            if isinstance(route, dict)
        }
        for location, planted in by_location.items():
            path = "/" + location.lstrip("/")
            if path in existing_paths:
                continue
            routes.append(
                {
                    "path": path,
                    "method": "GET",
                    "status": 200,
                    "headers": {
                        "Content-Type": "text/plain; charset=utf-8",
                    },
                    "body": "\n".join(
                        credential.credential_value
                        for credential in planted
                    )
                    + "\n",
                }
            )
        owner["routes"] = routes
        owner_port = int(owner["port"])
        return credentials, {owner_port: credentials}

    async def _get_mimicked_device_ids(self) -> set[int]:
        """Get device IDs that already have active mimic decoys."""
        cursor = await self._db.execute(
            """SELECT DISTINCT
                      COALESCE(dh.source_device_id, mt.source_device_id)
                          AS source_device_id
               FROM decoys d
               LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
               LEFT JOIN mimic_templates mt
                 ON mt.id = CASE
                     WHEN json_valid(d.config) THEN CAST(
                         json_extract(d.config, '$.template_id') AS INTEGER
                     )
                     ELSE NULL
                 END
               WHERE d.status = 'active'
                 AND d.decoy_type = 'mimic'
                 AND d.retired_at IS NULL
                 AND (d.host_id IS NULL OR dh.retired_at IS NULL)
                 AND (d.host_id IS NULL OR d.is_primary = 1)"""
        )
        rows = list(await cursor.fetchall())
        return {row[0] for row in rows if row[0] is not None}

    async def _capture_mimic_removal_target(
        self,
        decoy_id: int,
    ) -> _MimicRemovalTarget | None:
        """Bind a remove request to the host generation visible at entry."""
        mapped_primary_id = self._service_to_primary.get(decoy_id, decoy_id)
        runtime = self._active_mimics.get(mapped_primary_id)
        rows = list(
            await self._db.execute_fetchall(
                """SELECT requested.id AS requested_id,
                      CASE
                          WHEN requested.host_id IS NULL THEN requested.id
                          ELSE primary_row.id
                      END AS primary_id,
                      requested.host_id AS host_id,
                      COALESCE(
                          host_row.created_at,
                          requested.created_at
                      ) AS generation_created_at,
                      requested.bind_address
               FROM decoys requested
               LEFT JOIN decoy_hosts host_row
                 ON host_row.id = requested.host_id
               LEFT JOIN decoys primary_row
                 ON primary_row.host_id = requested.host_id
                AND primary_row.is_primary = 1
                AND primary_row.decoy_type = 'mimic'
                AND primary_row.retired_at IS NULL
               WHERE requested.id = ?
                 AND requested.decoy_type = 'mimic'
                 AND requested.retired_at IS NULL
                 AND (
                     requested.host_id IS NULL
                     OR (
                         host_row.retired_at IS NULL
                         AND primary_row.id IS NOT NULL
                     )
                 )
                   LIMIT 1""",
                (decoy_id,),
            )
        )
        if not rows:
            if runtime is None:
                return None
            return _MimicRemovalTarget(
                requested_id=decoy_id,
                primary_id=mapped_primary_id,
                host_id=None,
                generation_created_at=None,
                runtime=runtime,
            )

        row = rows[0]
        primary_id = int(row["primary_id"])
        if runtime is not None and (
            mapped_primary_id != primary_id
            or runtime.bind_address != row["bind_address"]
        ):
            logger.warning(
                "Mimic %d changed identity while its removal target was "
                "being captured",
                decoy_id,
            )
            return None
        return _MimicRemovalTarget(
            requested_id=int(row["requested_id"]),
            primary_id=primary_id,
            host_id=(
                int(row["host_id"])
                if row["host_id"] is not None
                else None
            ),
            generation_created_at=str(row["generation_created_at"]),
            runtime=runtime,
        )

    async def _revalidate_mimic_removal_target(
        self,
        target: _MimicRemovalTarget,
    ) -> tuple[int, Any | None, MimicDecoy | None] | None:
        """Resolve a captured generation without following a recycled ID."""
        if target.generation_created_at is None:
            current = self._active_mimics.get(target.primary_id)
            if current is not target.runtime:
                return None
            rows = await self._db.execute_fetchall(
                "SELECT 1 FROM decoys WHERE id = ? LIMIT 1",
                (target.primary_id,),
            )
            if rows:
                return None
            return target.primary_id, None, current

        if target.host_id is not None:
            rows = list(
                await self._db.execute_fetchall(
                    """SELECT primary_row.*
                   FROM decoy_hosts host_row
                   JOIN decoys primary_row
                     ON primary_row.host_id = host_row.id
                    AND primary_row.is_primary = 1
                    AND primary_row.decoy_type = 'mimic'
                    AND primary_row.retired_at IS NULL
                   WHERE host_row.id = ?
                     AND host_row.created_at = ?
                     AND host_row.retired_at IS NULL
                       LIMIT 1""",
                    (target.host_id, target.generation_created_at),
                )
            )
        else:
            rows = list(
                await self._db.execute_fetchall(
                    """SELECT *
                   FROM decoys
                   WHERE id = ?
                     AND decoy_type = 'mimic'
                     AND host_id IS NULL
                     AND created_at = ?
                     AND retired_at IS NULL
                       LIMIT 1""",
                    (target.primary_id, target.generation_created_at),
                )
            )
        if not rows:
            return None

        row = rows[0]
        primary_id = int(row["id"])
        current = self._active_mimics.get(primary_id)
        if target.runtime is not None and current is not target.runtime:
            return None
        return primary_id, row, current

    async def remove_mimic(self, decoy_id: int) -> bool:
        """Stop the captured mimic generation and release its virtual IP."""
        if self._lifecycle_lock.is_owned_by_another_task():
            raise MimicLifecycleBusyError(
                "Fake host lifecycle is busy; wait for the current network update"
            )
        target = await self._capture_mimic_removal_target(decoy_id)
        if target is None:
            return False
        if self._lifecycle_lock.is_owned_by_another_task():
            raise MimicLifecycleBusyError(
                "Fake host lifecycle is busy; wait for the current network update"
            )
        async with self._lifecycle_lock:
            resolved = await self._revalidate_mimic_removal_target(target)
            if resolved is None:
                logger.info(
                    "Skipped stale removal for mimic %d because its host "
                    "generation changed while the request was queued",
                    decoy_id,
                )
                return False
            primary_id, row, mimic = resolved
            return await self._remove_bound_mimic(primary_id, row, mimic)

    async def _remove_bound_mimic(
        self,
        decoy_id: int,
        row: Any | None,
        mimic: MimicDecoy | None,
    ) -> bool:
        """Remove one already revalidated host generation."""
        if row is None and mimic is None:
            return False
        if row is None:
            assert mimic is not None
            logger.error(
                "Mimic %d exists in runtime without a durable row; cleaning "
                "network state before forgetting it",
                decoy_id,
            )
            if await self._deactivate_failed_mimic(
                decoy_id=decoy_id,
                bind_address=mimic.bind_address,
                mimic=mimic,
            ):
                return True
            raise MimicCleanupError(
                f"Mimic {decoy_id} network cleanup is incomplete; "
                "PF isolation was retained"
            )

        bind_address = row["bind_address"]
        config = json.loads(row["config"]) if row["config"] else {}
        template_id = config.get("template_id")
        status_rows = await self._service_status_rows(decoy_id)

        # Stop the listener first, remove the address second, and only then
        # remove PF. A failed alias operation therefore remains isolated.
        if not await self._deactivate_failed_mimic(
            decoy_id=decoy_id,
            bind_address=bind_address,
            mimic=mimic,
        ):
            raise MimicCleanupError(
                f"Mimic {decoy_id} network cleanup is incomplete; "
                "its persisted state and PF isolation were retained"
            )

        await self._delete_mimic_records(
            decoy_id=decoy_id,
            template_id=template_id,
            virtual_ip=bind_address,
            retirement_reason="removed_by_user",
        )
        # Clean up stale status events only when no preserved alert points
        # at the event sequence.
        service_ids = [int(item["id"]) for item in status_rows]
        placeholders = ",".join("?" for _ in service_ids)
        await self._db.execute(
            "DELETE FROM events WHERE event_type = 'decoy.status_changed' "
            f"AND json_extract(payload, '$.id') IN ({placeholders}) "
            "AND NOT EXISTS ("
            "    SELECT 1 FROM home_alerts ha WHERE ha.event_seq = events.seq"
            ")",
            service_ids,
        )
        await self._db.commit()

        name = mimic.name if mimic else row["name"]
        await self._publish_group_status(
            decoy_id,
            "removed",
            hostname=name,
            rows=status_rows,
        )

        logger.info("Removed mimic decoy '%s' (id=%d)", name, decoy_id)

        return True

    @_serialized_user_lifecycle
    async def restart_mimic(self, decoy_id: int) -> bool:
        """Restart a stopped mimic decoy."""
        if not self._network_ready:
            return False
        decoy_id = await self._resolve_primary_id(decoy_id)
        # A restart must cycle a live listener rather than reporting success
        # after doing nothing.
        active = self._active_mimics.get(decoy_id)
        if active is None and len(self._active_mimics) >= self._max_mimics:
            return False
        if active is None:
            duplicate_cursor = await self._db.execute(
                """SELECT 1
                   FROM decoys target
                   JOIN decoy_hosts target_host ON target_host.id = target.host_id
                   JOIN decoy_hosts active_host
                     ON active_host.source_device_id =
                        target_host.source_device_id
                    AND active_host.id != target_host.id
                   JOIN decoys active_primary
                     ON active_primary.host_id = active_host.id
                    AND active_primary.is_primary = 1
                    AND active_primary.status = 'active'
                   WHERE target.id = ?
                     AND target_host.source_device_id IS NOT NULL
                   LIMIT 1""",
                (decoy_id,),
            )
            if await duplicate_cursor.fetchone() is not None:
                return False
        if active is not None:
            deactivated = await self._deactivate_failed_mimic(
                decoy_id=decoy_id,
                bind_address=active.bind_address,
                mimic=active,
            )
            if not deactivated:
                return False

        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE id = ? AND decoy_type = 'mimic'",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False

        bind_address = row["bind_address"]
        mimic: MimicDecoy | None = None
        try:
            config = json.loads(row["config"]) if row["config"] else {}
            if not isinstance(config, dict):
                return False
            template_id = config.get("template_id")
            if not template_id:
                return False

            # Load template
            tmpl_cursor = await self._db.execute(
                "SELECT * FROM mimic_templates WHERE id = ?", (template_id,),
            )
            tmpl_row = await tmpl_cursor.fetchone()
            if not tmpl_row:
                await self._deactivate_failed_mimic(
                    decoy_id=decoy_id,
                    bind_address=bind_address,
                    mimic=None,
                )
                return False

            try:
                routes = json.loads(tmpl_row["routes_json"])
            except (TypeError, json.JSONDecodeError):
                routes = []
            server_header = tmpl_row["server_header"]

            # Load credentials
            cred_cursor = await self._db.execute(
                """SELECT pc.*, credential_owner.port AS owner_port
                   FROM planted_credentials pc
                   JOIN decoys credential_owner ON credential_owner.id = pc.decoy_id
                   JOIN decoys primary_row
                     ON (
                         primary_row.host_id IS NOT NULL
                         AND credential_owner.host_id = primary_row.host_id
                     )
                     OR credential_owner.id = primary_row.id
                   WHERE primary_row.id = ?""",
                (decoy_id,),
            )
            cred_rows = await cred_cursor.fetchall()
            credentials = [
                GeneratedCredential(
                    credential_type=cr["credential_type"],
                    credential_value=cr["credential_value"],
                    planted_location=cr["planted_location"],
                    canary_hostname=cr["canary_hostname"],
                )
                for cr in cred_rows
            ]
            credentials_by_port: dict[int, list[GeneratedCredential]] = {}
            for credential, credential_row in zip(
                credentials,
                cred_rows,
                strict=True,
            ):
                credentials_by_port.setdefault(
                    int(credential_row["owner_port"]),
                    [],
                ).append(credential)

            port_configs = await self._load_persisted_port_configs(
                decoy_id=decoy_id,
                config=config,
                routes=routes,
                primary_port=row["port"],
            )

            if not port_configs:
                await self._deactivate_failed_mimic(
                    decoy_id=decoy_id,
                    bind_address=bind_address,
                    mimic=None,
                )
                return False

            mimic_name, mdns_hostname = await self._normalize_mimic_identity(
                decoy_id=decoy_id,
                current_name=row["name"],
                config=config,
                template_row=tmpl_row,
                bind_address=bind_address,
            )
            tls_cert_pem, tls_key_pem = (
                await self._load_or_create_tls_identity(
                    decoy_id=decoy_id,
                    hostname=mimic_name,
                    bind_address=bind_address,
                    port_configs=port_configs,
                )
            )
            port_remaps = self._compute_port_remaps(port_configs)

            mimic = MimicDecoy(
                decoy_id=decoy_id,
                name=mimic_name,
                bind_address=bind_address,
                port_configs=port_configs,
                server_header=server_header,
                planted_credentials=credentials,
                port_remaps=port_remaps,
                tls_cert_pem=tls_cert_pem,
                tls_key_pem=tls_key_pem,
                credentials_by_port=credentials_by_port,
                **self._backend_bind_kwargs(bind_address),
            )
            mimic.on_connection = lambda event, _did=decoy_id: self._handle_connection(
                event,
                decoy_id=_did,
            )

            # A stopped row can still have an alias whose removal previously
            # failed. ``active_ips`` therefore means "possibly live", not
            # "safe to reuse". Establish deny-all isolation first, withdraw
            # the address unconditionally, and prove it is free before
            # republishing it.
            try:
                alias_restored = await self._restore_alias_under_quarantine(
                    decoy_id=decoy_id,
                    bind_address=bind_address,
                )
            except HelperUnavailableError as exc:
                logger.error(
                    "Cannot safely restart mimic %d: %s",
                    decoy_id,
                    exc,
                )
                raise
            if not alias_restored:
                return False

            # Start the listener while the address is still deny-all, then
            # replace only this endpoint's quarantine with its advertised
            # ports. Other active/quarantined endpoints remain in the atomic
            # packet-filter ruleset.
            await mimic.start()

            exposed_ports = {config["port"] for config in port_configs}
            assert self._port_fwd is not None
            isolated = await self._port_fwd.add_forwards(
                decoy_id,
                bind_address,
                mimic.port_remaps,
                exposed_ports=exposed_ports,
            )
            if not isolated:
                logger.error(
                    "Network isolation setup failed while restarting mimic %d",
                    decoy_id,
                )
                await self._deactivate_failed_mimic(
                    decoy_id=decoy_id,
                    bind_address=bind_address,
                    mimic=mimic,
                )
                return False

            # Resolve and install the mapping first. This awaits a DB query,
            # so publishing the mimic before it leaves a window in which a
            # concurrent status read reports the host's siblings as degraded.
            service_rows = await self._refresh_service_mapping(decoy_id)
            self._active_mimics[decoy_id] = mimic

            # Re-register every credible service under the shared hostname.
            if self._mdns is not None:
                if mdns_hostname:
                    mdns_ready = await self._register_mdns_batch(
                        self._mdns_registration_specs(
                            decoy_id=decoy_id,
                            virtual_ip=bind_address,
                            port_configs=port_configs,
                            configured_type=tmpl_row["mdns_service_type"],
                            hostname=mdns_hostname,
                        )
                    )
                    if mdns_ready:
                        self._mdns_degraded.discard(decoy_id)
                    else:
                        self._mdns_degraded.add(decoy_id)

            now = datetime.now(UTC).isoformat()
            await self._db.execute(
                """UPDATE decoys
                   SET status = 'active', updated_at = ?
                   WHERE (
                       id = ? OR host_id = (
                           SELECT host_id FROM decoys WHERE id = ?
                       )
                   )
                   AND retired_at IS NULL""",
                (now, decoy_id, decoy_id),
            )
            await self._db.commit()

            for service_row in service_rows:
                await self._event_bus.publish(
                    "decoy.status_changed",
                    {
                        "id": service_row["id"],
                        "host_id": service_row["host_id"],
                        "hostname": mimic_name,
                        "name": mimic_name,
                        "decoy_type": "mimic",
                        "bind_address": bind_address,
                        "port": service_row["port"],
                        "protocol": service_row["protocol"],
                        "service_name": service_row["service_name"],
                        "status": self.effective_mimic_status(
                            int(service_row["id"]),
                            "active",
                        ),
                        "connection_count": service_row["connection_count"],
                        "credential_trip_count": service_row[
                            "credential_trip_count"
                        ],
                        "created_at": service_row["created_at"],
                        "updated_at": now,
                    },
                )

            logger.info("Restarted mimic decoy '%s' (id=%d)", mimic_name, decoy_id)
            return True

        except HelperUnavailableError:
            raise
        except Exception:
            logger.exception("Failed to restart mimic decoy %d", decoy_id)
            await self._deactivate_failed_mimic(
                decoy_id=decoy_id,
                bind_address=bind_address,
                mimic=mimic,
            )
            return False

    @_serialized_lifecycle
    async def enable_mimic(self, decoy_id: int) -> bool:
        """Enable a persisted mimic, restoring its IP and forwarding rules."""
        decoy_id = await self._resolve_primary_id(decoy_id)
        if decoy_id in self._active_mimics:
            return True
        duplicate_cursor = await self._db.execute(
            """SELECT 1
               FROM decoys target
               JOIN decoy_hosts target_host ON target_host.id = target.host_id
               JOIN decoy_hosts active_host
                 ON active_host.source_device_id = target_host.source_device_id
                AND active_host.id != target_host.id
               JOIN decoys active_primary
                 ON active_primary.host_id = active_host.id
                AND active_primary.is_primary = 1
                AND active_primary.status = 'active'
               WHERE target.id = ?
                 AND target_host.source_device_id IS NOT NULL
               LIMIT 1""",
            (decoy_id,),
        )
        if await duplicate_cursor.fetchone() is not None:
            logger.warning(
                "Cannot enable mimic %d: its source device already has an "
                "active fake host",
                decoy_id,
            )
            return False
        if len(self._active_mimics) >= self._max_mimics:
            logger.warning(
                "Cannot enable mimic %d: profile limit %d is reached",
                decoy_id,
                self._max_mimics,
            )
            return False
        return await self.restart_mimic(decoy_id)

    @_serialized_lifecycle
    async def disable_mimic(self, decoy_id: int) -> bool:
        """Stop a mimic and release runtime network state without deleting it."""
        decoy_id = await self._resolve_primary_id(decoy_id)
        cursor = await self._db.execute(
            "SELECT bind_address FROM decoys WHERE id = ? AND decoy_type = 'mimic'",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False

        mimic = self._active_mimics.get(decoy_id)
        disabled = await self._deactivate_failed_mimic(
            decoy_id=decoy_id,
            bind_address=row["bind_address"],
            mimic=mimic,
        )
        if disabled:
            try:
                await self._publish_group_status(decoy_id, "stopped")
            except Exception:
                logger.exception(
                    "Mimic %d stopped but its grouped status event failed",
                    decoy_id,
                )
        return disabled

    @_serialized_lifecycle
    async def handle_ip_conflict(self, ip: str) -> bool:
        """Withdraw any live or possibly-live mimic endpoint at ``ip``."""
        # Find the mimic using this IP
        for decoy_id, mimic in list(self._active_mimics.items()):
            if mimic.bind_address == ip:
                logger.warning(
                    "IP conflict: real device at %s, evacuating mimic '%s'",
                    ip, mimic.name,
                )
                return await self.remove_mimic(decoy_id)

        # A failed stop or rollback deliberately removes the listener from the
        # runtime map while retaining its durable row, alias reservation, and
        # deny-all PF rule. Conflict reconciliation must still withdraw that
        # possibly-live address instead of silently ignoring it.
        cursor = await self._db.execute(
            """SELECT id
               FROM decoys
               WHERE decoy_type = 'mimic'
                 AND bind_address = ?
                 AND retired_at IS NULL
                 AND (host_id IS NULL OR is_primary = 1)
               ORDER BY id
               LIMIT 1""",
            (ip,),
        )
        row = await cursor.fetchone()
        if row is not None:
            logger.warning(
                "IP conflict at possibly-active stopped mimic %d (%s); "
                "retrying protected cleanup",
                row["id"],
                ip,
            )
            return await self.remove_mimic(row["id"])

        # A persistence failure can theoretically leave an address tracked by
        # VirtualIPManager without a decoy row. There is no listener to stop;
        # withdraw the address directly while leaving unknown PF state intact.
        if await self._ip_manager.remove_alias(ip):
            logger.warning(
                "Withdrew conflicted orphan virtual IP %s; retained any stale "
                "packet-filter isolation",
                ip,
            )
            return True
        raise MimicCleanupError(
            f"Conflicted virtual IP {ip} has no persisted mimic and could not "
            "be withdrawn; PF isolation was retained"
        )

    @_serialized_lifecycle
    async def prepare_persisted_network(self) -> int:
        """Quarantine every persisted alias before startup reconciliation.

        PF's anchor is replaced atomically. Seeding all recorded endpoints in
        one call prevents resuming the first mimic from exposing the remaining
        aliases left by a crash. Orphaned and stopped aliases are removed while
        their quarantine rule is still present.
        """
        self._startup_resume_endpoints = None
        cursor = await self._db.execute(
            """SELECT vip.ip_address,
                      vip.decoy_id,
                      d.id AS persisted_decoy_id,
                      d.decoy_type,
                      d.status,
                      dh.source_device_id,
                      CAST(
                          json_extract(d.config, '$.template_id') AS INTEGER
                      ) AS template_id
               FROM virtual_ips vip
               LEFT JOIN decoys d ON d.id = vip.decoy_id
               LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
               WHERE vip.released_at IS NULL
                 AND (
                     d.id IS NULL
                     OR (d.host_id IS NULL AND d.retired_at IS NULL)
                     OR (d.host_id IS NOT NULL AND dh.retired_at IS NULL)
                 )
               UNION ALL
               SELECT d.bind_address AS ip_address,
                      d.id AS decoy_id,
                      d.id AS persisted_decoy_id,
                      d.decoy_type,
                      d.status,
                      dh.source_device_id,
                      CAST(
                          json_extract(d.config, '$.template_id') AS INTEGER
                      ) AS template_id
               FROM decoys d
               LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
               WHERE d.decoy_type = 'mimic'
                 AND d.status IN ('active', 'stopped')
                 AND (
                     (d.host_id IS NULL AND d.retired_at IS NULL)
                     OR (d.host_id IS NOT NULL AND dh.retired_at IS NULL)
                 )
                 AND (d.host_id IS NULL OR d.is_primary = 1)
                 AND NOT EXISTS (
                     SELECT 1
                     FROM virtual_ips vip
                     WHERE vip.decoy_id = d.id
                       AND vip.released_at IS NULL
                 )
               ORDER BY ip_address, persisted_decoy_id"""
        )
        rows = list(await cursor.fetchall())
        if not rows:
            self._network_ready = True
            self._startup_resume_endpoints = {}
            return 0
        self._network_ready = False
        if self._port_fwd is None:
            raise RuntimeError(
                "Cannot safely reconcile persisted virtual IPs without "
                "packet-filter isolation"
            )

        protected: dict[int, str] = {}
        row_keys: list[tuple[Any, int]] = []
        next_orphan_key = -1
        for row in rows:
            decoy_id = row["persisted_decoy_id"]
            if decoy_id is None:
                decoy_id = row["decoy_id"]
            if (
                isinstance(decoy_id, int)
                and decoy_id not in protected
            ):
                key = decoy_id
            else:
                while next_orphan_key in protected:
                    next_orphan_key -= 1
                key = next_orphan_key
                next_orphan_key -= 1
            protected[key] = row["ip_address"]
            row_keys.append((row, key))

        if not await self._port_fwd.quarantine_endpoints(protected):
            for row in rows:
                self._ip_manager.mark_possibly_active(row["ip_address"])
            raise RuntimeError(
                "Could not install startup quarantine for persisted virtual IPs"
            )

        rows_by_ip: dict[str, list[tuple[Any, int]]] = {}
        for row, key in row_keys:
            rows_by_ip.setdefault(row["ip_address"], []).append((row, key))

        # Keep one canonical active fake host per real source. All candidates
        # are already under deny-all quarantine; safely withdrawn inactive
        # hosts are retired below while their forensic rows remain intact.
        active_by_source: dict[int, list[tuple[Any, int]]] = {}
        for row, key in row_keys:
            source_device_id = row["source_device_id"]
            if (
                source_device_id is not None
                and row["persisted_decoy_id"] is not None
                and row["decoy_type"] == "mimic"
                and row["status"] == "active"
            ):
                active_by_source.setdefault(int(source_device_id), []).append(
                    (row, key)
                )
        duplicate_keys: set[int] = set()
        for entries in active_by_source.values():
            ordered = sorted(
                entries,
                key=lambda item: int(item[0]["persisted_decoy_id"]),
            )
            duplicate_keys.update(key for _row, key in ordered[1:])

        cleaned = 0
        startup_resume_endpoints: dict[int, str] = {}
        for ip, entries in rows_by_ip.items():
            active_entries = [
                (row, key)
                for row, key in entries
                if (
                    key not in duplicate_keys
                    and
                    row["persisted_decoy_id"] is not None
                    and row["decoy_type"] == "mimic"
                    and row["status"] == "active"
                )
            ]
            active_keys = {key for _, key in active_entries}
            stale_entries = [
                (row, key)
                for row, key in entries
                if key not in active_keys
            ]
            try:
                alias_removed = await self._ip_manager.remove_alias(ip)
            except Exception as exc:
                logger.exception(
                    "Could not verify withdrawal of persisted virtual IP %s; "
                    "retaining startup quarantine",
                    ip,
                )
                raise RuntimeError(
                    f"Could not withdraw persisted virtual IP alias {ip}"
                ) from exc
            if not alias_removed:
                logger.error(
                    "Retaining startup quarantine for virtual IP %s because "
                    "alias removal failed",
                    ip,
                )
                raise RuntimeError(
                    f"Could not withdraw persisted virtual IP alias {ip}"
                )

            cleanup_complete = True
            for _row, key in stale_entries:
                if await self._port_fwd.remove_forwards(key):
                    continue
                cleanup_complete = False
                logger.error(
                    "Alias %s was removed, but stale startup quarantine for "
                    "decoy key %d could not be cleared",
                    ip,
                    key,
                )
            if not cleanup_complete:
                if active_entries:
                    raise RuntimeError(
                        f"Could not clear stale packet-filter state for {ip}"
                    )
                continue

            for row, _key in stale_entries:
                if (
                    row["persisted_decoy_id"] is None
                    or row["decoy_type"] != "mimic"
                    or row["status"] != "stopped"
                ):
                    continue
                await self._delete_mimic_records(
                    decoy_id=int(row["persisted_decoy_id"]),
                    template_id=row["template_id"],
                    virtual_ip=ip,
                    delete_virtual_ip=False,
                    retirement_reason="stopped_after_network_cleanup",
                )
                logger.info(
                    "Retired stopped mimic host %d after verified startup "
                    "network cleanup; preserved its alert and connection evidence",
                    row["persisted_decoy_id"],
                )

            retired_duplicate = False
            for row, key in entries:
                if key not in duplicate_keys:
                    continue
                retired_duplicate = True
                await self._delete_mimic_records(
                    decoy_id=int(row["persisted_decoy_id"]),
                    template_id=row["template_id"],
                    virtual_ip=ip,
                    retirement_reason="duplicate_source_host",
                )
                logger.warning(
                    "Retired duplicate mimic host %d for source device %d; "
                    "preserved its alert and connection evidence",
                    row["persisted_decoy_id"],
                    row["source_device_id"],
                )

            active_id = (
                int(active_entries[0][0]["persisted_decoy_id"])
                if active_entries
                else None
            )
            for row, _key in active_entries:
                startup_resume_endpoints[
                    int(row["persisted_decoy_id"])
                ] = ip
            if active_id is not None:
                # The VIP row may point at a failed stopped deployment even
                # though a durable active mimic owns the same binding. Reassign
                # it before deleting the stopped duplicate so the active mimic
                # can republish the address during resume.
                await self._db.execute(
                    """UPDATE virtual_ips
                       SET decoy_id = ?
                       WHERE ip_address = ?""",
                    (active_id, ip),
                )

            if active_id is None:
                await self._db.execute(
                    "DELETE FROM virtual_ips WHERE ip_address = ?",
                    (ip,),
                )
            await self._db.commit()

            if stale_entries or retired_duplicate:
                cleaned += 1

        self._network_ready = True
        self._startup_resume_endpoints = startup_resume_endpoints
        return cleaned

    @_serialized_lifecycle
    async def resume_active(self) -> int:
        """Resume mimic decoys from DB on startup.

        Ensures virtual IP aliases exist before starting each mimic.
        Mimics whose virtual IPs cannot be restored are marked as stopped.
        """
        if not self._network_ready:
            raise HelperUnavailableError(
                "Persisted virtual IPs could not be quarantined safely"
            )
        cursor = await self._db.execute(
            """SELECT d.*
               FROM decoys d
               LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
               WHERE d.status = 'active'
                 AND d.decoy_type = 'mimic'
                 AND (
                     (d.host_id IS NULL AND d.retired_at IS NULL)
                     OR (d.host_id IS NOT NULL AND dh.retired_at IS NULL)
                 )
                 AND (d.host_id IS NULL OR d.is_primary = 1)
               ORDER BY d.created_at, d.id"""
        )
        rows = list(await cursor.fetchall())
        if not rows:
            self._startup_resume_endpoints = None
            return 0

        logger.info("Found %d mimic decoys to resume", len(rows))

        prepared_endpoints = self._startup_resume_endpoints
        reuse_startup_quarantine = (
            prepared_endpoints is not None
            and all(
                prepared_endpoints.get(int(row["id"])) == row["bind_address"]
                for row in rows
            )
        )
        ownership_snapshot: list[tuple[str, str]] | None = None
        if reuse_startup_quarantine:
            try:
                ownership_snapshot = (
                    await self._ip_manager.snapshot_real_ip_owners()
                )
                if not isinstance(ownership_snapshot, list):
                    raise TypeError("ownership snapshot is not a list")
            except Exception as exc:
                raise HelperUnavailableError(
                    "Could not obtain a fresh ownership snapshot after "
                    "withdrawing persisted mimic aliases"
                ) from exc
        # Once any alias is republished, the prepared withdrawn-state proof
        # cannot authorize a later resume attempt.
        self._startup_resume_endpoints = None

        resumed = 0
        resumed_ips: set[str] = set()
        mdns_registrations: dict[
            int,
            list[tuple[int, str, int, str, str, str]],
        ] = {}
        for row in rows:
            decoy_id = row["id"]
            bind_address = row["bind_address"]
            mimic: MimicDecoy | None = None
            try:
                if resumed >= self._max_mimics:
                    deactivated = await self._deactivate_failed_mimic(
                        decoy_id=decoy_id,
                        bind_address=bind_address,
                        mimic=None,
                    )
                    if not deactivated:
                        self._network_ready = False
                        raise MimicCleanupError(
                            f"Mimic {decoy_id} exceeds the active profile limit "
                            "and could not be safely stopped"
                        )
                    continue

                # Load template
                try:
                    config = json.loads(row["config"]) if row["config"] else {}
                except (TypeError, json.JSONDecodeError):
                    config = None
                if not isinstance(config, dict):
                    await self._discard_unresumable_mimic(
                        row=row,
                        template_id=None,
                        reason="invalid durable configuration",
                        already_quarantined_and_withdrawn=reuse_startup_quarantine,
                    )
                    continue
                template_id = config.get("template_id")
                if not template_id:
                    await self._discard_unresumable_mimic(
                        row=row,
                        template_id=None,
                        reason="missing template reference",
                        already_quarantined_and_withdrawn=reuse_startup_quarantine,
                    )
                    continue

                template_cursor = await self._db.execute(
                    "SELECT * FROM mimic_templates WHERE id = ?", (template_id,)
                )
                tmpl_row = await template_cursor.fetchone()
                if not tmpl_row:
                    await self._discard_unresumable_mimic(
                        row=row,
                        template_id=template_id,
                        reason="missing template",
                        already_quarantined_and_withdrawn=reuse_startup_quarantine,
                    )
                    continue

                try:
                    routes = json.loads(tmpl_row["routes_json"])
                except (TypeError, json.JSONDecodeError):
                    routes = []
                server_header = tmpl_row["server_header"]

                # Load credentials
                cred_cursor = await self._db.execute(
                    """SELECT pc.*, credential_owner.port AS owner_port
                       FROM planted_credentials pc
                       JOIN decoys credential_owner
                         ON credential_owner.id = pc.decoy_id
                       JOIN decoys primary_row
                         ON (
                             primary_row.host_id IS NOT NULL
                             AND credential_owner.host_id = primary_row.host_id
                         )
                         OR credential_owner.id = primary_row.id
                       WHERE primary_row.id = ?""",
                    (decoy_id,),
                )
                cred_rows = await cred_cursor.fetchall()
                credentials = [
                    GeneratedCredential(
                        credential_type=cr["credential_type"],
                        credential_value=cr["credential_value"],
                        planted_location=cr["planted_location"],
                        canary_hostname=cr["canary_hostname"],
                    )
                    for cr in cred_rows
                ]
                credentials_by_port: dict[
                    int,
                    list[GeneratedCredential],
                ] = {}
                for credential, credential_row in zip(
                    credentials,
                    cred_rows,
                    strict=True,
                ):
                    credentials_by_port.setdefault(
                        int(credential_row["owner_port"]),
                        [],
                    ).append(credential)

                port_configs = await self._load_persisted_port_configs(
                    decoy_id=decoy_id,
                    config=config,
                    routes=routes,
                    primary_port=row["port"],
                )

                if not port_configs:
                    await self._discard_unresumable_mimic(
                        row=row,
                        template_id=template_id,
                        reason="no valid durable endpoints",
                        already_quarantined_and_withdrawn=reuse_startup_quarantine,
                    )
                    continue

                mimic_name, mdns_hostname = await self._normalize_mimic_identity(
                    decoy_id=decoy_id,
                    current_name=row["name"],
                    config=config,
                    template_row=tmpl_row,
                    bind_address=bind_address,
                )
                tls_cert_pem, tls_key_pem = (
                    await self._load_or_create_tls_identity(
                        decoy_id=decoy_id,
                        hostname=mimic_name,
                        bind_address=bind_address,
                        port_configs=port_configs,
                    )
                )
                port_remaps = self._compute_port_remaps(port_configs)

                mimic = MimicDecoy(
                    decoy_id=decoy_id,
                    name=mimic_name,
                    bind_address=bind_address,
                    port_configs=port_configs,
                    server_header=server_header,
                    planted_credentials=credentials,
                    port_remaps=port_remaps,
                    tls_cert_pem=tls_cert_pem,
                    tls_key_pem=tls_key_pem,
                    credentials_by_port=credentials_by_port,
                    **self._backend_bind_kwargs(bind_address),
                )
                mimic.on_connection = lambda event, _did=decoy_id: self._handle_connection(
                    event,
                    decoy_id=_did,
                )

                # Do not trust ``active_ips`` here. It includes aliases whose
                # prior removal could not be confirmed. Re-establish
                # quarantine and prove ownership from a withdrawn state on
                # every resume, including in-process resumes after stop_all().
                alias_restored = await self._restore_alias_under_quarantine(
                    decoy_id=decoy_id,
                    bind_address=bind_address,
                    ownership_snapshot=ownership_snapshot,
                    already_quarantined_and_withdrawn=reuse_startup_quarantine,
                )
                if not alias_restored:
                    deactivated = await self._deactivate_failed_mimic(
                        decoy_id=decoy_id,
                        bind_address=bind_address,
                        mimic=mimic,
                    )
                    if not deactivated:
                        self._network_ready = False
                        raise MimicCleanupError(
                            f"Mimic {decoy_id} could not restore its alias and "
                            "cleanup is incomplete"
                        )
                    continue

                # The listener becomes ready while deny-all remains active.
                # Only then is this endpoint changed to its advertised ports.
                await mimic.start()
                exposed_ports = {config["port"] for config in port_configs}
                assert self._port_fwd is not None
                isolated = await self._port_fwd.add_forwards(
                    decoy_id,
                    bind_address,
                    mimic.port_remaps,
                    exposed_ports=exposed_ports,
                )
                if not isolated:
                    logger.error(
                        "Network isolation setup failed while resuming mimic %d",
                        decoy_id,
                    )
                    deactivated = await self._deactivate_failed_mimic(
                        decoy_id=decoy_id,
                        bind_address=bind_address,
                        mimic=mimic,
                    )
                    if not deactivated:
                        self._network_ready = False
                        raise MimicCleanupError(
                            f"Mimic {decoy_id} isolation failed and cleanup is "
                            "incomplete"
                        )
                    continue

                # Mapping first, for the same reason as the restart path.
                await self._refresh_service_mapping(decoy_id)
                self._active_mimics[decoy_id] = mimic
                resumed_ips.add(bind_address)

                # Re-register every credible service.
                if self._mdns is not None:
                    mdns_registrations[decoy_id] = (
                        self._mdns_registration_specs(
                            decoy_id=decoy_id,
                            virtual_ip=bind_address,
                            port_configs=port_configs,
                            configured_type=tmpl_row["mdns_service_type"],
                            hostname=mdns_hostname,
                        )
                    )

                resumed += 1

            except (HelperUnavailableError, MimicCleanupError):
                # Startup must not become healthy when alias withdrawal or
                # quarantine could not be confirmed.
                raise
            except Exception as exc:
                logger.exception("Failed to resume mimic decoy %d", decoy_id)
                deactivated = await self._deactivate_failed_mimic(
                    decoy_id=decoy_id,
                    bind_address=bind_address,
                    mimic=mimic,
                )
                if not deactivated:
                    self._network_ready = False
                    raise MimicCleanupError(
                        f"Mimic {decoy_id} failed to resume and cleanup is "
                        "incomplete"
                    ) from exc

        if mdns_registrations:
            mdns_results = await asyncio.gather(
                *(
                    self._register_mdns_batch(registrations)
                    for registrations in mdns_registrations.values()
                )
            )
            for decoy_id, mdns_ready in zip(
                mdns_registrations,
                mdns_results,
                strict=True,
            ):
                if mdns_ready:
                    self._mdns_degraded.discard(decoy_id)
                else:
                    self._mdns_degraded.add(decoy_id)

        if resumed_ips:
            verification_error: Exception | None = None
            try:
                conflicts = await self._ip_manager.verify_batch_ownership(
                    resumed_ips
                )
            except Exception as exc:
                verification_error = exc
                conflicts = {
                    ip: "ownership-probe-failed"
                    for ip in resumed_ips
                }
                logger.exception(
                    "Post-resume ownership verification failed; evacuating "
                    "every resumed mimic"
                )
            resumed = max(0, resumed - len(conflicts))
            await self._evacuate_verified_conflicts(
                conflicts,
                context="Post-resume ownership verification",
            )
            if verification_error is not None:
                raise HelperUnavailableError(
                    "Mimic post-resume ownership verification failed"
                ) from verification_error

        if resumed:
            logger.info("Resumed %d mimic decoys", resumed)
        elif rows:
            logger.warning(
                "Found %d mimic decoys in DB but could not resume any — "
                "check helper status and virtual IP availability",
                len(rows),
            )
        return resumed

    @_serialized_lifecycle
    async def stop_all(self) -> None:
        """Stop runtime services without deleting persistent mimic records.

        This is the graceful-shutdown path. Explicit user deletion goes
        through :meth:`remove_mimic`; treating shutdown as deletion made every
        upgrade erase all scout-created decoys and templates.
        """
        if self._active_mimics:
            if self._port_fwd is None:
                raise HelperUnavailableError(
                    "Cannot safely stop mimics without packet-filter isolation"
                )
            endpoints = {
                decoy_id: mimic.bind_address
                for decoy_id, mimic in self._active_mimics.items()
            }
            # Atomically withdraw every redirect before any dynamic backend
            # listener is closed. Shutdown removes aliases next and clears PF
            # only after their withdrawal is confirmed; if an alias survives,
            # this deny-all state is the protection that must remain behind.
            if not await self._port_fwd.quarantine_endpoints(endpoints):
                raise HelperUnavailableError(
                    "Could not quarantine mimics before listener shutdown"
                )

        for decoy_id, mimic in list(self._active_mimics.items()):
            if self._mdns is not None:
                try:
                    await self._mdns.unregister(decoy_id)
                except Exception:
                    logger.exception(
                        "Failed to unregister mDNS for mimic %d during shutdown",
                        decoy_id,
                    )
            try:
                await mimic.stop()
            except Exception:
                logger.exception("Failed to stop mimic decoy %d", decoy_id)
        self._active_mimics.clear()

        # PF is intentionally retained here. The application removes virtual
        # aliases next and clears PF only after every alias removal succeeds.

    def _handle_connection(self, event: DecoyConnectionEvent, *, decoy_id: int | None = None, decoy_name: str | None = None) -> None:
        """Connection callback for mimic decoys."""
        asyncio.get_event_loop().create_task(self._async_handle_connection(event, decoy_id=decoy_id, decoy_name=decoy_name))

    async def _async_handle_connection(self, event: DecoyConnectionEvent, *, decoy_id: int | None = None, decoy_name: str | None = None) -> None:
        """Async handler for connection events from mimic decoys."""
        if decoy_id is not None:
            primary_id = await self._resolve_primary_id(decoy_id)
            service_cursor = await self._db.execute(
                """SELECT service.id, service.name
                   FROM decoys primary_row
                   JOIN decoys service
                     ON (
                         primary_row.host_id IS NOT NULL
                         AND service.host_id = primary_row.host_id
                     )
                     OR (
                         primary_row.host_id IS NULL
                         AND service.id = primary_row.id
                     )
                   WHERE primary_row.id = ?
                     AND service.port = ?
                     AND lower(COALESCE(service.protocol, 'tcp')) =
                         lower(COALESCE(?, 'tcp'))
                   ORDER BY service.is_primary DESC, service.id
                   LIMIT 1""",
                (primary_id, event.dest_port, event.protocol),
            )
            service_row = await service_cursor.fetchone()
            if service_row is not None:
                decoy_id = int(service_row["id"])
                decoy_name = str(service_row["name"])

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
                    "detection_method": "mimic_decoy",
                    "decoy_id": decoy_id,
                    "decoy_name": decoy_name,
                },
            )
