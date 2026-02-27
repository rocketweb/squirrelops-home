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
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from squirrelops_home_sensor.decoys.credentials import CredentialGenerator, GeneratedCredential
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent
from squirrelops_home_sensor.decoys.types.mimic import MimicDecoy
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.network.port_forward import PortForwardManager, needs_remap, remap_port
from squirrelops_home_sensor.network.virtual_ip import VirtualIPManager
from squirrelops_home_sensor.scouts.engine import ScoutEngine
from squirrelops_home_sensor.scouts.mdns import MimicMDNSAdvertiser, generate_mimic_hostname
from squirrelops_home_sensor.scouts.templates import MimicTemplate, MimicTemplateGenerator

logger = logging.getLogger("squirrelops_home_sensor.scouts")


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
    ) -> None:
        self._engine = scout_engine
        self._template_gen = template_generator
        self._ip_manager = ip_manager
        self._event_bus = event_bus
        self._db = db
        self._max_mimics = max_mimics
        self._active_mimics: dict[int, MimicDecoy] = {}  # decoy_id -> MimicDecoy
        self._cred_gen = CredentialGenerator()
        self._mdns = mdns_advertiser
        self._port_fwd = port_forward_manager

    @property
    def active_count(self) -> int:
        """Number of currently active mimic decoys."""
        return len(self._active_mimics)

    @property
    def max_mimics(self) -> int:
        return self._max_mimics

    async def evaluate_and_deploy(self) -> int:
        """After scouting, pick best candidates and deploy mimics.

        Returns the number of new mimics deployed.
        """
        if self._max_mimics <= 0:
            return 0

        slots = self._max_mimics - len(self._active_mimics)
        if slots <= 0:
            logger.debug("Max mimics reached (%d), skipping deploy", self._max_mimics)
            return 0

        # Get best candidates from scout data
        candidates = await self._engine.get_mimic_candidates(count=slots)
        if not candidates:
            logger.debug("No mimic candidates available")
            return 0

        # Group profiles by device
        device_profiles: dict[int, list] = {}
        for profile in candidates:
            device_profiles.setdefault(profile.device_id, []).append(profile)

        # Filter out devices already mimicked
        mimicked_devices = await self._get_mimicked_device_ids()
        new_devices = {
            did: profiles
            for did, profiles in device_profiles.items()
            if did not in mimicked_devices
        }

        if not new_devices:
            logger.debug("All candidate devices already mimicked")
            return 0

        deployed = 0
        for device_id, profiles in new_devices.items():
            if deployed >= slots:
                break

            try:
                ok = await self._deploy_mimic_for_device(device_id, profiles)
                if ok:
                    deployed += 1
            except Exception:
                logger.exception("Failed to deploy mimic for device %d", device_id)

        if deployed > 0:
            logger.info("Deployed %d new mimic decoys", deployed)
        return deployed

    async def _deploy_mimic_for_device(
        self, device_id: int, profiles: list,
    ) -> bool:
        """Deploy a mimic decoy for a specific device."""
        # Look up device info
        cursor = await self._db.execute(
            "SELECT device_type, hostname FROM devices WHERE id = ?",
            (device_id,),
        )
        device_row = await cursor.fetchone()
        if not device_row:
            return False

        device_type = device_row["device_type"]
        hostname = device_row["hostname"]

        # Generate template
        template = self._template_gen.generate(profiles, device_type, hostname)
        if not template.routes and not any(p.protocol_version for p in profiles):
            logger.debug("No HTTP routes or banners for device %d, skipping", device_id)
            return False

        # Allocate virtual IP
        ips = self._ip_manager._allocator.allocate(1)
        if not ips:
            logger.warning("No virtual IPs available for mimic deployment")
            return False
        virtual_ip = ips[0]

        # Add IP alias
        ok = await self._ip_manager.add_alias(virtual_ip)
        if not ok:
            self._ip_manager._allocator.release(virtual_ip)
            return False

        # Generate credentials
        credentials = self._generate_credentials(template.credential_types)

        # Build port configs for the mimic decoy
        port_configs = self._build_port_configs(profiles, template)

        # Persist template to DB
        now = datetime.now(timezone.utc).isoformat()
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
        await self._db.commit()

        # Generate mDNS hostname for this mimic
        mdns_hostname = generate_mimic_hostname(
            mdns_name=template.mdns_name,
            device_category=template.device_category,
            virtual_ip=virtual_ip,
        )

        # Create decoy record in DB
        mimic_name = f"Mimic: {hostname or template.source_ip}"
        decoy_config = {
            "template_id": template_cursor.lastrowid,
            "mdns_hostname": mdns_hostname,
        }
        decoy_cursor = await self._db.execute(
            """INSERT INTO decoys
               (name, decoy_type, bind_address, port, status, config, created_at, updated_at)
               VALUES (?, 'mimic', ?, ?, 'active', ?, ?, ?)""",
            (
                mimic_name, virtual_ip, port_configs[0]["port"] if port_configs else 0,
                json.dumps(decoy_config),
                now, now,
            ),
        )
        await self._db.commit()
        decoy_id = decoy_cursor.lastrowid

        # Link virtual IP to decoy
        await self._db.execute(
            "UPDATE virtual_ips SET decoy_id = ? WHERE ip_address = ?",
            (decoy_id, virtual_ip),
        )

        # Persist credentials
        for cred in credentials:
            await self._db.execute(
                """INSERT INTO planted_credentials
                   (credential_type, credential_value, planted_location,
                    decoy_id, canary_hostname, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    cred.credential_type, cred.credential_value,
                    cred.planted_location, decoy_id, cred.canary_hostname, now,
                ),
            )
        await self._db.commit()

        # Compute port remaps for privileged ports
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
        )
        mimic.on_connection = self._handle_connection

        try:
            await mimic.start()
        except Exception:
            logger.exception("Failed to start mimic decoy %d", decoy_id)
            await self._ip_manager.remove_alias(virtual_ip)
            await self._db.execute("DELETE FROM decoys WHERE id = ?", (decoy_id,))
            await self._db.commit()
            return False

        self._active_mimics[decoy_id] = mimic

        # Set up pfctl/iptables port forwarding for privileged ports
        if port_remaps and self._port_fwd is not None:
            ok = await self._port_fwd.add_forwards(decoy_id, virtual_ip, port_remaps)
            if not ok:
                logger.warning(
                    "Port forwarding setup failed for mimic %d — "
                    "privileged ports may be unreachable",
                    decoy_id,
                )

        # Register mDNS service with custom hostname
        if self._mdns is not None:
            await self._mdns.register(
                decoy_id=decoy_id,
                virtual_ip=virtual_ip,
                port=port_configs[0]["port"] if port_configs else 80,
                service_type=template.mdns_service_type,
                hostname=mdns_hostname,
            )

        await self._event_bus.publish(
            "decoy.status_changed",
            {
                "id": decoy_id,
                "name": mimic_name,
                "decoy_type": "mimic",
                "bind_address": virtual_ip,
                "port": mimic.port,
                "status": "active",
                "connection_count": 0,
                "credential_trip_count": 0,
                "created_at": now,
                "updated_at": now,
            },
        )

        logger.info(
            "Deployed mimic '%s' on %s as '%s' (device %d, %d ports)",
            mimic_name, virtual_ip, mdns_hostname, device_id, len(port_configs),
        )
        return True

    @staticmethod
    def _compute_port_remaps(port_configs: list[dict]) -> dict[int, int]:
        """Compute port remappings for privileged ports.

        Returns a dict of ``{original_port: high_port}`` for ports < 1024.
        """
        remaps: dict[int, int] = {}
        for config in port_configs:
            port = config["port"]
            if needs_remap(port):
                remaps[port] = remap_port(port)
        return remaps

    def _build_port_configs(
        self, profiles: list, template: MimicTemplate,
    ) -> list[dict]:
        """Build port configs for MimicDecoy from profiles and template."""
        configs: list[dict] = []
        route_by_port: dict[int, dict] = {
            r["port"]: r for r in template.routes if "port" in r
        }

        for profile in profiles:
            config: dict[str, Any] = {"port": profile.port}

            if profile.port in route_by_port:
                route = route_by_port[profile.port]
                config["routes"] = [route]
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

    async def _get_mimicked_device_ids(self) -> set[int]:
        """Get device IDs that already have active mimic decoys."""
        cursor = await self._db.execute(
            """SELECT DISTINCT mt.source_device_id
               FROM mimic_templates mt
               JOIN decoys d ON d.config LIKE '%' || mt.id || '%'
               WHERE d.status = 'active' AND d.decoy_type = 'mimic'"""
        )
        rows = await cursor.fetchall()
        return {row[0] for row in rows if row[0] is not None}

    async def remove_mimic(self, decoy_id: int) -> bool:
        """Stop and remove a mimic decoy, releasing its virtual IP."""
        mimic = self._active_mimics.get(decoy_id)

        # Remove port forwarding rules
        if self._port_fwd is not None:
            await self._port_fwd.remove_forwards(decoy_id)

        # Unregister mDNS services
        if self._mdns is not None:
            await self._mdns.unregister(decoy_id)

        if mimic is not None:
            # Active mimic — stop it and release IP
            await mimic.stop()
            del self._active_mimics[decoy_id]
            await self._ip_manager.remove_alias(mimic.bind_address)

        # Clean up DB record (works for both active and stopped mimics)
        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE id = ? AND decoy_type = 'mimic'",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is None and mimic is None:
            return False

        if row is not None:
            bind_address = row["bind_address"]
            # Release virtual IP if it wasn't already released above
            if mimic is None:
                await self._ip_manager.remove_alias(bind_address)

            # Delete related records
            await self._db.execute(
                "DELETE FROM planted_credentials WHERE decoy_id = ?", (decoy_id,),
            )
            await self._db.execute(
                "DELETE FROM virtual_ips WHERE decoy_id = ?", (decoy_id,),
            )
            await self._db.execute(
                "DELETE FROM decoys WHERE id = ?", (decoy_id,),
            )
            await self._db.commit()

            name = mimic.name if mimic else row["name"]
            await self._event_bus.publish(
                "decoy.status_changed",
                {
                    "id": decoy_id,
                    "name": name,
                    "decoy_type": "mimic",
                    "bind_address": bind_address,
                    "port": row["port"],
                    "status": "removed",
                },
            )

            logger.info("Removed mimic decoy '%s' (id=%d)", name, decoy_id)

        return True

    async def restart_mimic(self, decoy_id: int) -> bool:
        """Restart a stopped mimic decoy."""
        # If already active, nothing to do
        if decoy_id in self._active_mimics:
            return True

        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE id = ? AND decoy_type = 'mimic'",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False

        try:
            bind_address = row["bind_address"]
            config = json.loads(row["config"]) if row["config"] else {}
            template_id = config.get("template_id")
            if not template_id:
                return False

            # Re-add IP alias
            ok = await self._ip_manager.add_alias(bind_address)
            if not ok:
                logger.warning("Failed to re-add IP alias %s for mimic %d", bind_address, decoy_id)
                return False

            # Load template
            tmpl_cursor = await self._db.execute(
                "SELECT * FROM mimic_templates WHERE id = ?", (template_id,),
            )
            tmpl_row = await tmpl_cursor.fetchone()
            if not tmpl_row:
                return False

            routes = json.loads(tmpl_row["routes_json"])
            server_header = tmpl_row["server_header"]

            # Load credentials
            cred_cursor = await self._db.execute(
                "SELECT * FROM planted_credentials WHERE decoy_id = ?", (decoy_id,),
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

            # Build port configs from profiles
            source_device_id = tmpl_row["source_device_id"]
            profiles = await self._engine.get_profiles_for_device(source_device_id)

            port_configs: list[dict[str, Any]] = []
            route_by_port = {r.get("port", 0): r for r in routes if isinstance(r, dict)}
            for profile in profiles:
                pc: dict[str, Any] = {"port": profile.port}
                if profile.port in route_by_port:
                    pc["routes"] = [route_by_port[profile.port]]
                elif profile.http_status is not None:
                    pc["routes"] = [{
                        "path": "/",
                        "method": "GET",
                        "status": profile.http_status,
                        "headers": profile.http_headers or {},
                        "body": profile.http_body_snippet or "",
                    }]
                elif profile.protocol_version:
                    pc["protocol_banner"] = profile.protocol_version
                else:
                    pc["protocol_banner"] = ""
                port_configs.append(pc)

            if not port_configs:
                return False

            port_remaps = self._compute_port_remaps(port_configs)

            mimic = MimicDecoy(
                decoy_id=decoy_id,
                name=row["name"],
                bind_address=bind_address,
                port_configs=port_configs,
                server_header=server_header,
                planted_credentials=credentials,
                port_remaps=port_remaps,
            )
            mimic.on_connection = self._handle_connection
            await mimic.start()
            self._active_mimics[decoy_id] = mimic

            # Set up port forwarding for privileged ports
            if port_remaps and self._port_fwd is not None:
                await self._port_fwd.add_forwards(decoy_id, bind_address, port_remaps)

            # Re-register mDNS service
            if self._mdns is not None:
                mdns_hostname = config.get("mdns_hostname")
                if mdns_hostname:
                    primary_port = port_configs[0]["port"] if port_configs else 80
                    mdns_svc_type = tmpl_row["mdns_service_type"]
                    await self._mdns.register(
                        decoy_id=decoy_id,
                        virtual_ip=bind_address,
                        port=primary_port,
                        service_type=mdns_svc_type,
                        hostname=mdns_hostname,
                    )

            now = datetime.now(timezone.utc).isoformat()
            await self._db.execute(
                "UPDATE decoys SET status = 'active', updated_at = ? WHERE id = ?",
                (now, decoy_id),
            )
            await self._db.commit()

            await self._event_bus.publish(
                "decoy.status_changed",
                {
                    "id": decoy_id,
                    "name": row["name"],
                    "decoy_type": "mimic",
                    "bind_address": bind_address,
                    "port": row["port"],
                    "status": "active",
                    "connection_count": row["connection_count"],
                    "credential_trip_count": row["credential_trip_count"],
                    "created_at": row["created_at"],
                    "updated_at": now,
                },
            )

            logger.info("Restarted mimic decoy '%s' (id=%d)", row["name"], decoy_id)
            return True

        except Exception:
            logger.exception("Failed to restart mimic decoy %d", decoy_id)
            return False

    async def handle_ip_conflict(self, ip: str) -> None:
        """Real device appeared at our virtual IP — evacuate and redeploy."""
        # Find the mimic using this IP
        for decoy_id, mimic in list(self._active_mimics.items()):
            if mimic.bind_address == ip:
                logger.warning(
                    "IP conflict: real device at %s, evacuating mimic '%s'",
                    ip, mimic.name,
                )
                await self.remove_mimic(decoy_id)
                return

    async def resume_active(self) -> int:
        """Resume mimic decoys from DB on startup."""
        cursor = await self._db.execute(
            "SELECT * FROM decoys WHERE status = 'active' AND decoy_type = 'mimic'"
        )
        rows = await cursor.fetchall()
        if not rows:
            return 0

        resumed = 0
        for row in rows:
            try:
                decoy_id = row["id"]
                bind_address = row["bind_address"]

                # Load template
                config = json.loads(row["config"]) if row["config"] else {}
                template_id = config.get("template_id")
                if not template_id:
                    continue

                template_cursor = await self._db.execute(
                    "SELECT * FROM mimic_templates WHERE id = ?", (template_id,)
                )
                tmpl_row = await template_cursor.fetchone()
                if not tmpl_row:
                    continue

                routes = json.loads(tmpl_row["routes_json"])
                server_header = tmpl_row["server_header"]

                # Load credentials
                cred_cursor = await self._db.execute(
                    "SELECT * FROM planted_credentials WHERE decoy_id = ?", (decoy_id,)
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

                # Load profiles for this device to build port configs
                source_device_id = tmpl_row["source_device_id"]
                profiles = await self._engine.get_profiles_for_device(source_device_id)

                port_configs = []
                route_by_port = {r.get("port", 0): r for r in routes if isinstance(r, dict)}
                for profile in profiles:
                    pc: dict[str, Any] = {"port": profile.port}
                    if profile.port in route_by_port:
                        pc["routes"] = [route_by_port[profile.port]]
                    elif profile.http_status is not None:
                        pc["routes"] = [{
                            "path": "/",
                            "method": "GET",
                            "status": profile.http_status,
                            "headers": profile.http_headers or {},
                            "body": profile.http_body_snippet or "",
                        }]
                    elif profile.protocol_version:
                        pc["protocol_banner"] = profile.protocol_version
                    else:
                        pc["protocol_banner"] = ""
                    port_configs.append(pc)

                if not port_configs:
                    continue

                port_remaps = self._compute_port_remaps(port_configs)

                mimic = MimicDecoy(
                    decoy_id=decoy_id,
                    name=row["name"],
                    bind_address=bind_address,
                    port_configs=port_configs,
                    server_header=server_header,
                    planted_credentials=credentials,
                    port_remaps=port_remaps,
                )
                mimic.on_connection = self._handle_connection
                await mimic.start()
                self._active_mimics[decoy_id] = mimic

                # Set up port forwarding for privileged ports
                if port_remaps and self._port_fwd is not None:
                    await self._port_fwd.add_forwards(decoy_id, bind_address, port_remaps)

                # Re-register mDNS service
                if self._mdns is not None:
                    mdns_hostname = config.get("mdns_hostname")
                    if not mdns_hostname:
                        # Backfill for mimics deployed before mDNS support
                        device_category = tmpl_row["device_category"] or "generic"
                        mdns_hostname = generate_mimic_hostname(
                            mdns_name=tmpl_row["mdns_name"],
                            device_category=device_category,
                            virtual_ip=bind_address,
                        )
                        config["mdns_hostname"] = mdns_hostname
                        await self._db.execute(
                            "UPDATE decoys SET config = ? WHERE id = ?",
                            (json.dumps(config), decoy_id),
                        )
                        await self._db.commit()

                    primary_port = port_configs[0]["port"] if port_configs else 80
                    mdns_svc_type = tmpl_row["mdns_service_type"]
                    await self._mdns.register(
                        decoy_id=decoy_id,
                        virtual_ip=bind_address,
                        port=primary_port,
                        service_type=mdns_svc_type,
                        hostname=mdns_hostname,
                    )

                resumed += 1

            except Exception:
                logger.exception("Failed to resume mimic decoy %d", row["id"])
                now = datetime.now(timezone.utc).isoformat()
                await self._db.execute(
                    "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                await self._db.commit()

        if resumed:
            logger.info("Resumed %d mimic decoys", resumed)
        return resumed

    async def stop_all(self) -> None:
        """Stop all mimics, remove virtual IPs, clear port forwards."""
        for decoy_id in list(self._active_mimics.keys()):
            await self.remove_mimic(decoy_id)

        # Final cleanup: clear any stale port forward rules
        if self._port_fwd is not None:
            await self._port_fwd.clear_all()

    def _handle_connection(self, event: DecoyConnectionEvent) -> None:
        """Connection callback for mimic decoys."""
        asyncio.get_event_loop().create_task(self._async_handle_connection(event))

    async def _async_handle_connection(self, event: DecoyConnectionEvent) -> None:
        """Async handler for connection events from mimic decoys."""
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
                },
            )
