"""Schema version tracking and migration runner.

Checks the current schema version in the database and applies any pending
migrations in order. Version 0 means no schema exists yet.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime

import aiosqlite

from squirrelops_home_sensor.db.schema import SCHEMA_V1_SQL, SCHEMA_VERSION

logger = logging.getLogger(__name__)


async def _get_current_version(db: aiosqlite.Connection) -> int:
    """Return the current schema version, or 0 if the table does not exist."""
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    row = await cursor.fetchone()
    if row is None:
        return 0
    cursor = await db.execute("SELECT MAX(version) FROM schema_version")
    row = await cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


async def _apply_v1(db: aiosqlite.Connection) -> None:
    """Apply schema version 1: create all initial tables and indexes."""
    await db.executescript(SCHEMA_V1_SQL)
    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
        (1, now),
    )
    await db.commit()


async def _column_exists(db: aiosqlite.Connection, table: str, column: str) -> bool:
    """Check whether a column already exists in a table."""
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return any(row[1] == column for row in rows)


async def _apply_v2(db: aiosqlite.Connection) -> None:
    """Apply schema version 2: add model_name column to devices."""
    if not await _column_exists(db, "devices", "model_name"):
        await db.execute("ALTER TABLE devices ADD COLUMN model_name TEXT")
    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
        (2, now),
    )
    await db.commit()


async def _apply_v3(db: aiosqlite.Connection) -> None:
    """V3: Add area column to devices table."""
    if not await _column_exists(db, "devices", "area"):
        await db.execute("ALTER TABLE devices ADD COLUMN area TEXT")
    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (3, now),
    )
    await db.commit()


async def _table_exists(db: aiosqlite.Connection, table: str) -> bool:
    """Check whether a table already exists in the database."""
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    )
    return await cursor.fetchone() is not None


async def _apply_v4(db: aiosqlite.Connection) -> None:
    """V4: Add device_open_ports and security_insight_state tables."""
    if not await _table_exists(db, "device_open_ports"):
        await db.executescript("""
            CREATE TABLE device_open_ports (
                id          INTEGER PRIMARY KEY,
                device_id   INTEGER NOT NULL REFERENCES devices(id),
                port        INTEGER NOT NULL,
                protocol    TEXT NOT NULL DEFAULT 'tcp',
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                UNIQUE(device_id, port, protocol)
            );
            CREATE INDEX idx_device_ports_device ON device_open_ports(device_id);
            CREATE INDEX idx_device_ports_port ON device_open_ports(port);
        """)

    if not await _table_exists(db, "security_insight_state"):
        await db.executescript("""
            CREATE TABLE security_insight_state (
                id          INTEGER PRIMARY KEY,
                device_id   INTEGER NOT NULL REFERENCES devices(id),
                insight_key TEXT NOT NULL,
                alert_id    INTEGER REFERENCES home_alerts(id),
                dismissed   INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                resolved_at TEXT,
                UNIQUE(device_id, insight_key)
            );
            CREATE INDEX idx_insight_state_device ON security_insight_state(device_id);
            CREATE INDEX idx_insight_state_key ON security_insight_state(insight_key);
        """)

    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (4, now),
    )
    await db.commit()


async def _apply_v5(db: aiosqlite.Connection) -> None:
    """V5: Add service_name and banner columns to device_open_ports."""
    if not await _column_exists(db, "device_open_ports", "service_name"):
        await db.execute("ALTER TABLE device_open_ports ADD COLUMN service_name TEXT")
    if not await _column_exists(db, "device_open_ports", "banner"):
        await db.execute("ALTER TABLE device_open_ports ADD COLUMN banner TEXT")

    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (5, now),
    )
    await db.commit()


async def _apply_v6(db: aiosqlite.Connection) -> None:
    """V6: Add Squirrel Scouts tables -- service profiles, virtual IPs, mimic templates."""
    if not await _table_exists(db, "service_profiles"):
        await db.executescript("""
            CREATE TABLE service_profiles (
                id INTEGER PRIMARY KEY,
                device_id INTEGER NOT NULL REFERENCES devices(id),
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service_name TEXT,
                http_status INTEGER,
                http_headers TEXT,
                http_body_snippet TEXT,
                http_server_header TEXT,
                favicon_hash TEXT,
                tls_cn TEXT,
                tls_issuer TEXT,
                tls_not_after TEXT,
                protocol_version TEXT,
                scouted_at TEXT NOT NULL,
                UNIQUE(device_id, port, protocol)
            );
            CREATE INDEX idx_svc_profiles_device ON service_profiles(device_id);
        """)

    if not await _table_exists(db, "virtual_ips"):
        await db.executescript("""
            CREATE TABLE virtual_ips (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL UNIQUE,
                interface TEXT NOT NULL DEFAULT 'en0',
                decoy_id INTEGER REFERENCES decoys(id),
                created_at TEXT NOT NULL,
                released_at TEXT
            );
        """)

    if not await _table_exists(db, "mimic_templates"):
        await db.executescript("""
            CREATE TABLE mimic_templates (
                id INTEGER PRIMARY KEY,
                source_device_id INTEGER REFERENCES devices(id),
                source_ip TEXT NOT NULL,
                device_category TEXT NOT NULL,
                routes_json TEXT NOT NULL,
                server_header TEXT,
                credential_types_json TEXT,
                mdns_service_type TEXT,
                mdns_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (6, now),
    )
    await db.commit()


async def _apply_v7(db: aiosqlite.Connection) -> None:
    """V7: Deduplicate historical security alerts.

    Before the security_insight_state dedup table was introduced (V4), the
    analyzer created a new alert for every scan cycle that found the same open
    port on the same device.  This migration removes those historical duplicates,
    keeping only the latest alert per unique (device_id, alert_type, title)
    combination.  Insight state entries already point to the latest alert so
    they remain valid after the cleanup.
    """
    # Step 1: Count duplicates so we can log useful info
    cursor = await db.execute("""
        SELECT COUNT(*) FROM home_alerts
        WHERE incident_id IS NULL
        AND id NOT IN (
            SELECT MAX(id) FROM home_alerts
            WHERE incident_id IS NULL
            GROUP BY device_id, alert_type, title
        )
    """)
    row = await cursor.fetchone()
    dup_count = row[0] if row else 0

    if dup_count > 0:
        # Step 2: Delete duplicate standalone alerts, keeping only the latest
        await db.execute("""
            DELETE FROM home_alerts
            WHERE incident_id IS NULL
            AND id NOT IN (
                SELECT MAX(id) FROM home_alerts
                WHERE incident_id IS NULL
                GROUP BY device_id, alert_type, title
            )
        """)

        # Step 3: Clean up any orphaned insight_state entries that may reference
        # deleted alerts (shouldn't happen since we keep the MAX id, but be safe)
        await db.execute("""
            DELETE FROM security_insight_state
            WHERE alert_id IS NOT NULL
            AND alert_id NOT IN (SELECT id FROM home_alerts)
        """)

        logger.info(
            "V7 migration: removed %d duplicate alerts, keeping latest per condition",
            dup_count,
        )

    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (7, now),
    )
    await db.commit()


async def _apply_v8(db: aiosqlite.Connection) -> None:
    """V8: Alert grouping by issue type.

    Adds columns for grouped alerts (issue_key, affected_devices, device_count,
    risk_description, remediation) and consolidates existing per-device
    security.port_risk alerts into one grouped alert per issue type.
    """
    import json

    # -- Schema additions --
    if not await _column_exists(db, "home_alerts", "issue_key"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN issue_key TEXT")
    if not await _column_exists(db, "home_alerts", "affected_devices"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN affected_devices TEXT")
    if not await _column_exists(db, "home_alerts", "device_count"):
        await db.execute(
            "ALTER TABLE home_alerts ADD COLUMN device_count INTEGER DEFAULT 1"
        )
    if not await _column_exists(db, "home_alerts", "risk_description"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN risk_description TEXT")
    if not await _column_exists(db, "home_alerts", "remediation"):
        await db.execute("ALTER TABLE home_alerts ADD COLUMN remediation TEXT")

    # Index for fast issue_key lookups
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_issue_key "
        "ON home_alerts(issue_key) WHERE issue_key IS NOT NULL"
    )
    await db.commit()

    # -- Data migration: consolidate per-device alerts into grouped alerts --
    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE alert_type = 'security.port_risk' "
        "AND issue_key IS NULL ORDER BY created_at DESC"
    )
    rows = await cursor.fetchall()

    if rows:
        # Group alerts by (port, service_name) extracted from detail JSON
        groups: dict[str, list[dict]] = {}
        for row in rows:
            detail = row["detail"]
            if isinstance(detail, str):
                try:
                    detail = json.loads(detail)
                except (json.JSONDecodeError, TypeError):
                    detail = {}
            if not isinstance(detail, dict):
                detail = {}

            port = detail.get("port")
            service_name = detail.get("service_name", "")

            # Build issue key matching the new logic
            service_slug = service_name.lower().replace(" ", "_")
            if "unencrypted" in service_slug:
                issue_key = "port_risk:unencrypted_admin"
            elif port is not None:
                issue_key = f"port_risk:{service_slug}:{port}"
            else:
                continue

            groups.setdefault(issue_key, []).append(dict(row))

        for issue_key, alert_rows in groups.items():
            # First row is the latest (ORDER BY created_at DESC)
            winner = alert_rows[0]
            winner_id = winner["id"]

            # Build affected_devices from all alerts in this group
            affected = []
            seen_device_ids: set[int] = set()
            for a in alert_rows:
                detail = a["detail"]
                if isinstance(detail, str):
                    try:
                        detail = json.loads(detail)
                    except (json.JSONDecodeError, TypeError):
                        detail = {}
                did = a.get("device_id") or detail.get("device_id")
                if did and did not in seen_device_ids:
                    seen_device_ids.add(did)
                    svc = detail.get("service_name", "")
                    title_str = a.get("title", "")
                    display = title_str.replace(f"{svc} open on ", "") if svc else title_str
                    affected.append({
                        "device_id": did,
                        "ip_address": a.get("source_ip", ""),
                        "mac_address": a.get("source_mac"),
                        "display_name": display,
                        "port": detail.get("port", 0),
                    })

            # Extract risk info from winner's detail
            winner_detail = winner["detail"]
            if isinstance(winner_detail, str):
                try:
                    winner_detail = json.loads(winner_detail)
                except (json.JSONDecodeError, TypeError):
                    winner_detail = {}
            risk_desc = winner_detail.get("risk_description", "")
            remediation_text = winner_detail.get("remediation_steps", "")

            # Compute new title
            service_name = winner_detail.get("service_name", "Unknown")
            n = len(affected)
            new_title = f"{service_name} open on {n} device{'s' if n > 1 else ''}"

            # Update the winner alert with grouped data
            await db.execute(
                "UPDATE home_alerts SET "
                "issue_key = ?, affected_devices = ?, device_count = ?, "
                "risk_description = ?, remediation = ?, title = ?, "
                "source_ip = NULL, source_mac = NULL, device_id = NULL "
                "WHERE id = ?",
                (
                    issue_key,
                    json.dumps(affected),
                    n,
                    risk_desc,
                    remediation_text,
                    new_title,
                    winner_id,
                ),
            )

            # Delete non-winner alerts and update insight_state references
            non_winner_ids = [a["id"] for a in alert_rows if a["id"] != winner_id]
            if non_winner_ids:
                placeholders = ",".join("?" * len(non_winner_ids))
                await db.execute(
                    f"DELETE FROM home_alerts WHERE id IN ({placeholders})",
                    non_winner_ids,
                )
                await db.execute(
                    f"UPDATE security_insight_state SET alert_id = ? "
                    f"WHERE alert_id IN ({placeholders})",
                    [winner_id] + non_winner_ids,
                )

        await db.commit()
        logger.info(
            "V8 migration: consolidated %d per-device alerts into %d grouped alerts",
            len(rows),
            len(groups),
        )

    # -- Clean stale alert events from the events replay table --
    # Old alert.new/alert.updated events referencing deleted alerts would
    # cause the app to re-add per-device alerts during WebSocket replay.
    await db.execute(
        "DELETE FROM events WHERE event_type IN ('alert.new', 'alert.updated') "
        "AND json_extract(payload, '$.id') NOT IN (SELECT id FROM home_alerts)"
    )
    await db.commit()

    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
        (8, now),
    )
    await db.commit()


def _v9_hostname(raw: object, bind_address: str) -> str:
    """Return a durable, canonical ``.local`` hostname for a mimic host."""
    import re

    candidate = str(raw or "").strip().rstrip(".")
    if candidate.lower().endswith(".local"):
        candidate = candidate[:-6].rstrip(".")
    candidate = candidate.lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", candidate):
        suffix = bind_address.rsplit(".", 1)[-1]
        candidate = f"decoy-{suffix}" if suffix.isdigit() else "decoy-host"
    return f"{candidate}.local"


def _v9_unique_hostname(
    hostname: str,
    bind_address: str,
    used: set[str],
) -> str:
    """Return a deterministic collision-free canonical migration hostname."""
    canonical = hostname.lower()
    if canonical not in used:
        used.add(canonical)
        return hostname

    label = hostname.removesuffix(".local")
    address_suffix = bind_address.rsplit(".", 1)[-1]
    suffix = f"-{address_suffix}" if address_suffix.isdigit() else "-2"
    candidate = f"{label[: 63 - len(suffix)].rstrip('-')}{suffix}.local"
    counter = 2
    while candidate.lower() in used:
        suffix = f"-{counter}"
        candidate = f"{label[: 63 - len(suffix)].rstrip('-')}{suffix}.local"
        counter += 1
    used.add(candidate.lower())
    return candidate


def _v9_latest_failure_at(
    current: object,
    candidate: object,
) -> str | None:
    """Return the chronologically latest meaningful legacy failure time."""
    values = [
        str(value).strip()
        for value in (current, candidate)
        if value is not None and str(value).strip()
    ]
    if not values:
        return None

    parsed: list[tuple[datetime, str]] = []
    for value in values:
        normalized = (
            f"{value[:-1]}+00:00"
            if value.upper().endswith("Z")
            else value
        )
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            continue
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        parsed.append((timestamp.astimezone(UTC), value))
    if parsed:
        return max(parsed, key=lambda item: (item[0], item[1]))[1]
    return max(values)


def _v9_service_config(
    raw_config: object,
    *,
    fallback_port: int,
) -> list[dict]:
    """Normalize the legacy multi-port config without discarding behavior."""
    import json

    from squirrelops_home_sensor.scanner.service_names import get_service_name

    config: dict = {}
    if isinstance(raw_config, str):
        try:
            decoded = json.loads(raw_config)
        except (TypeError, json.JSONDecodeError):
            decoded = {}
        if isinstance(decoded, dict):
            config = decoded
    elif isinstance(raw_config, dict):
        config = dict(raw_config)

    raw_services = config.get("port_configs")
    if not isinstance(raw_services, list):
        raw_services = [{"port": fallback_port}]

    services: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for raw_service in raw_services:
        if not isinstance(raw_service, dict):
            continue
        try:
            port = int(raw_service.get("port", fallback_port))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        protocol = str(raw_service.get("protocol") or "tcp").strip().lower()
        if protocol not in {"tcp", "udp"}:
            protocol = "tcp"
        key = (port, protocol)
        if key in seen:
            continue
        service = dict(raw_service)
        service["port"] = port
        service["protocol"] = protocol
        if bool(service.get("tls")) or port in {443, 8443, 993, 995, 8883}:
            service["tls"] = True
        service_name = str(
            service.get("service_name") or get_service_name(port) or f"Port {port}"
        ).strip()
        service["service_name"] = service_name
        services.append(service)
        seen.add(key)

    if not services and 1 <= fallback_port <= 65535:
        services.append(
            {
                "port": fallback_port,
                "protocol": "tcp",
                "service_name": get_service_name(fallback_port)
                or f"Port {fallback_port}",
                "protocol_banner": "",
            }
        )
    return services


async def _apply_v9(db: aiosqlite.Connection) -> None:
    """V9: Persist host identities and one stable decoy row per service.

    Older mimic rows represented a complete virtual host and hid all but the
    first advertised port in ``config.port_configs``.  V9 preserves the
    original row as the runtime owner/primary service and creates stable rows
    for the remaining services.  Every service on one virtual IP references
    the same durable ``decoy_hosts`` identity.
    """
    import json

    await db.execute("SAVEPOINT squirrelops_v9")
    try:
        await db.execute(
            """CREATE TABLE IF NOT EXISTS decoy_hosts (
                   id INTEGER PRIMARY KEY,
                   hostname TEXT NOT NULL,
                   bind_address TEXT NOT NULL,
                   source_device_id INTEGER REFERENCES devices(id),
                   template_id INTEGER REFERENCES mimic_templates(id),
                   tls_cert_pem TEXT,
                   tls_key_pem TEXT,
                   retired_at TEXT,
                   retirement_reason TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL
               )"""
        )
        if not await _column_exists(db, "decoys", "host_id"):
            await db.execute(
                "ALTER TABLE decoys ADD COLUMN "
                "host_id INTEGER REFERENCES decoy_hosts(id)"
            )
        if not await _column_exists(db, "decoys", "protocol"):
            await db.execute("ALTER TABLE decoys ADD COLUMN protocol TEXT")
        if not await _column_exists(db, "decoys", "service_name"):
            await db.execute("ALTER TABLE decoys ADD COLUMN service_name TEXT")
        if not await _column_exists(db, "decoys", "is_primary"):
            await db.execute(
                "ALTER TABLE decoys ADD COLUMN "
                "is_primary INTEGER NOT NULL DEFAULT 0"
            )
        if not await _column_exists(db, "decoys", "retired_at"):
            await db.execute("ALTER TABLE decoys ADD COLUMN retired_at TEXT")
        if not await _column_exists(db, "decoys", "retirement_reason"):
            await db.execute(
                "ALTER TABLE decoys ADD COLUMN retirement_reason TEXT"
            )
        if not await _column_exists(db, "service_profiles", "favicon_body"):
            await db.execute(
                "ALTER TABLE service_profiles ADD COLUMN favicon_body BLOB"
            )

        cursor = await db.execute(
            """SELECT *
               FROM decoys
               WHERE decoy_type = 'mimic'
               ORDER BY bind_address,
                        CASE status WHEN 'active' THEN 0 ELSE 1 END,
                        id"""
        )
        mimic_rows = list(await cursor.fetchall())
        rows_by_address: dict[str, list[aiosqlite.Row]] = {}
        for row in mimic_rows:
            rows_by_address.setdefault(row["bind_address"], []).append(row)

        used_hostnames: set[str] = set()
        for bind_address, rows in rows_by_address.items():
            try:
                parsed_bind_address = ipaddress.ip_address(bind_address)
                invalid_binding = (
                    parsed_bind_address.version != 4
                    or parsed_bind_address.is_unspecified
                    or parsed_bind_address.is_loopback
                    or parsed_bind_address.is_link_local
                    or parsed_bind_address.is_multicast
                    or not parsed_bind_address.is_private
                )
            except ValueError:
                invalid_binding = True
            primary_row = rows[0]
            primary_config: dict = {}
            try:
                decoded = json.loads(primary_row["config"] or "{}")
                if isinstance(decoded, dict):
                    primary_config = decoded
            except (TypeError, json.JSONDecodeError):
                pass
            raw_hostname = (
                primary_config.get("mdns_hostname")
                or primary_row["name"]
            )
            template_id = primary_config.get("template_id")
            source_device_id = None
            source_ip = None
            source_hostname = None
            template_routes: list[dict] = []
            if isinstance(template_id, int) and not isinstance(template_id, bool):
                source_cursor = await db.execute(
                    """SELECT source_device_id, source_ip, mdns_name,
                              routes_json
                       FROM mimic_templates WHERE id = ?""",
                    (template_id,),
                )
                source_row = await source_cursor.fetchone()
                if source_row is not None:
                    source_device_id = source_row[0]
                    source_ip = source_row[1]
                    source_hostname = source_row[2]
                    try:
                        decoded_routes = json.loads(source_row[3] or "[]")
                    except (TypeError, json.JSONDecodeError):
                        decoded_routes = []
                    if isinstance(decoded_routes, list):
                        template_routes = [
                            dict(route)
                            for route in decoded_routes
                            if isinstance(route, dict)
                        ]
            hostname = _v9_unique_hostname(
                _v9_hostname(raw_hostname, bind_address),
                bind_address,
                used_hostnames,
            )
            legacy_services = [
                service
                for row in rows
                for service in _v9_service_config(
                    row["config"],
                    fallback_port=int(row["port"]),
                )
            ]
            routes_by_port: dict[int, list[dict]] = {}
            for route in template_routes:
                try:
                    route_port = int(route.get("port"))
                except (TypeError, ValueError):
                    continue
                routes_by_port.setdefault(route_port, []).append(route)
            enriched_services: dict[tuple[int, str], dict] = {}
            for service in legacy_services:
                enriched = dict(service)
                routes = enriched.get("routes")
                if not isinstance(routes, list) or not routes:
                    routes = routes_by_port.get(int(enriched["port"]), [])
                if routes:
                    enriched_routes: list[dict] = []
                    for route in routes:
                        if not isinstance(route, dict):
                            continue
                        enriched_route = dict(route)
                        if source_ip:
                            enriched_route.setdefault("_source_ip", source_ip)
                        if source_hostname:
                            enriched_route.setdefault(
                                "_source_hostname",
                                source_hostname,
                            )
                        enriched_routes.append(enriched_route)
                    enriched["routes"] = enriched_routes
                    enriched.pop("protocol_banner", None)
                enriched_services[
                    (int(enriched["port"]), str(enriched["protocol"]))
                ] = enriched
            legacy_services = list(enriched_services.values())
            tls_cert_pem = None
            tls_key_pem = None
            if any(
                bool(service.get("tls"))
                or int(service["port"]) in {443, 8443, 993, 995, 8883}
                for service in legacy_services
            ):
                from squirrelops_home_sensor.decoys.tls_identity import (
                    generate_host_tls_identity,
                )

                tls_cert_pem, tls_key_pem = generate_host_tls_identity(
                    hostname,
                    bind_address,
                )
            now = primary_row["updated_at"] or datetime.now(UTC).isoformat()
            created_at = primary_row["created_at"] or now
            retired_at = now if invalid_binding else None
            retirement_reason = (
                "invalid_legacy_bind_address"
                if invalid_binding
                else None
            )
            await db.execute(
                """INSERT INTO decoy_hosts
                   (hostname, bind_address, source_device_id, template_id,
                    tls_cert_pem, tls_key_pem, retired_at,
                    retirement_reason, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    hostname,
                    bind_address,
                    source_device_id,
                    template_id,
                    tls_cert_pem,
                    tls_key_pem,
                    retired_at,
                    retirement_reason,
                    created_at,
                    now,
                ),
            )
            host_cursor = await db.execute(
                "SELECT id FROM decoy_hosts WHERE bind_address = ?",
                (bind_address,),
            )
            host_row = await host_cursor.fetchone()
            if host_row is None:
                raise RuntimeError(
                    f"Could not create host identity for {bind_address}"
                )
            host_id = int(host_row[0])

            # Existing duplicate host rows are retained when they describe a
            # distinct port. The first row remains the runtime owner.
            used_services: set[tuple[int, str]] = set()
            primary_id = int(primary_row["id"])
            for source_index, row in enumerate(rows):
                source_id = int(row["id"])
                services = _v9_service_config(
                    row["config"],
                    fallback_port=int(row["port"]),
                )
                services = [
                    dict(
                        enriched_services.get(
                            (
                                int(service["port"]),
                                str(service["protocol"]),
                            ),
                            service,
                        )
                    )
                    for service in services
                ]
                if not services:
                    continue

                try:
                    base_config = json.loads(row["config"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    base_config = {}
                if not isinstance(base_config, dict):
                    base_config = {}
                label = hostname.removesuffix(".local")

                protocols_by_port: dict[int, set[str]] = {}
                for port, protocol in used_services:
                    protocols_by_port.setdefault(port, set()).add(protocol)
                for service in services:
                    protocols_by_port.setdefault(
                        int(service["port"]),
                        set(),
                    ).add(str(service["protocol"]))
                available = [
                    service
                    for service in services
                    if (service["port"], service["protocol"]) not in used_services
                ]
                duplicate_services = [
                    service
                    for service in services
                    if (service["port"], service["protocol"]) in used_services
                ]
                if not available:
                    # A corrupt legacy duplicate must not violate the new
                    # service identity. Dispatch exact evidence to each
                    # retained service; only ambiguous evidence and aggregate
                    # residuals belong on the primary service.
                    service_targets: dict[tuple[int, str], int] = {}
                    for service in services:
                        port = int(service["port"])
                        protocol = str(service["protocol"])
                        target_cursor = await db.execute(
                            """SELECT id FROM decoys
                               WHERE host_id = ? AND port = ?
                                 AND protocol = ?
                               ORDER BY is_primary DESC, id LIMIT 1""",
                            (host_id, port, protocol),
                        )
                        target = await target_cursor.fetchone()
                        if target is None:
                            raise RuntimeError(
                                "Missing V9 service merge target"
                            )
                        service_targets[(port, protocol)] = int(target[0])

                    retained_ids = list(
                        dict.fromkeys(
                            [primary_id, *service_targets.values()]
                        )
                    )
                    retained_placeholders = ",".join(
                        "?" for _ in retained_ids
                    )
                    retained_cursor = await db.execute(
                        f"""SELECT d.id, d.connection_count,
                                   d.credential_trip_count,
                                   COUNT(c.id) AS evidence_connections,
                                   SUM(
                                       CASE
                                           WHEN c.credential_used IS NOT NULL
                                             OR c.credential_id IS NOT NULL
                                           THEN 1 ELSE 0
                                       END
                                   ) AS evidence_trips
                            FROM decoys d
                            LEFT JOIN decoy_connections c
                              ON c.decoy_id = d.id
                            WHERE d.id IN ({retained_placeholders})
                            GROUP BY d.id""",
                        retained_ids,
                    )
                    retained_residuals = {
                        int(item["id"]): (
                            max(
                                0,
                                int(item["connection_count"] or 0)
                                - int(item["evidence_connections"] or 0),
                            ),
                            max(
                                0,
                                int(item["credential_trip_count"] or 0)
                                - int(item["evidence_trips"] or 0),
                            ),
                        )
                        for item in await retained_cursor.fetchall()
                    }
                    source_evidence_cursor = await db.execute(
                        """SELECT COUNT(*) AS connection_count,
                                  SUM(
                                      CASE
                                          WHEN credential_used IS NOT NULL
                                            OR credential_id IS NOT NULL
                                          THEN 1 ELSE 0
                                      END
                                  ) AS credential_trip_count
                           FROM decoy_connections
                           WHERE decoy_id = ?""",
                        (source_id,),
                    )
                    source_evidence = await source_evidence_cursor.fetchone()
                    source_connection_residual = max(
                        0,
                        int(row["connection_count"] or 0)
                        - int(source_evidence["connection_count"] or 0),
                    )
                    source_trip_residual = max(
                        0,
                        int(row["credential_trip_count"] or 0)
                        - int(
                            source_evidence["credential_trip_count"] or 0
                        ),
                    )

                    for (
                        port,
                        protocol,
                    ), target_id in service_targets.items():
                        owns_legacy_null = (
                            len(protocols_by_port[port]) == 1
                        )
                        await db.execute(
                            """UPDATE decoy_connections
                               SET decoy_id = ?
                               WHERE decoy_id = ? AND port = ?
                                 AND (
                                     lower(protocol) = ?
                                     OR (protocol IS NULL AND ?)
                                 )""",
                            (
                                target_id,
                                source_id,
                                port,
                                protocol,
                                1 if owns_legacy_null else 0,
                            ),
                        )
                        await db.execute(
                            """UPDATE home_alerts
                               SET decoy_id = ?
                               WHERE decoy_id = ?
                                 AND CASE
                                     WHEN NOT json_valid(detail) THEN 0
                                     WHEN json_type(
                                         detail,
                                         '$.dest_port'
                                     ) = 'integer'
                                     THEN json_extract(
                                         detail,
                                         '$.dest_port'
                                     ) = ?
                                     WHEN (
                                         json_type(
                                             detail,
                                             '$.dest_port'
                                         ) IS NULL
                                         OR json_type(
                                             detail,
                                             '$.dest_port'
                                         ) = 'null'
                                     )
                                     AND json_type(
                                         detail,
                                         '$.port'
                                     ) = 'integer'
                                     THEN json_extract(
                                         detail,
                                         '$.port'
                                     ) = ?
                                     ELSE 0
                                 END
                                 AND (
                                     lower(
                                         json_extract(
                                             detail,
                                             '$.protocol'
                                         )
                                     ) = ?
                                     OR (
                                         json_extract(
                                             detail,
                                             '$.protocol'
                                         ) IS NULL
                                         AND ?
                                     )
                                 )""",
                            (
                                target_id,
                                source_id,
                                port,
                                port,
                                protocol,
                                1 if owns_legacy_null else 0,
                            ),
                        )

                    # Anything not attributable to an advertised service stays
                    # attached to the durable primary row.
                    await db.execute(
                        "UPDATE home_alerts SET decoy_id = ? WHERE decoy_id = ?",
                        (primary_id, source_id),
                    )
                    await db.execute(
                        "UPDATE planted_credentials SET decoy_id = ? "
                        "WHERE decoy_id = ?",
                        (primary_id, source_id),
                    )
                    await db.execute(
                        "UPDATE decoy_connections SET decoy_id = ? "
                        "WHERE decoy_id = ?",
                        (primary_id, source_id),
                    )
                    await db.execute(
                        "UPDATE virtual_ips SET decoy_id = ? WHERE decoy_id = ?",
                        (primary_id, source_id),
                    )
                    primary_metadata_cursor = await db.execute(
                        """SELECT status, failure_count, last_failure_at
                           FROM decoys WHERE id = ?""",
                        (primary_id,),
                    )
                    primary_metadata = await primary_metadata_cursor.fetchone()
                    if primary_metadata is None:
                        raise RuntimeError(
                            "Missing V9 primary service merge target"
                        )
                    # Failure history is cumulative. A degraded duplicate is
                    # actionable, but its stopped lifecycle state must not
                    # disable an otherwise healthy retained host.
                    primary_status = str(primary_metadata["status"])
                    duplicate_status = str(row["status"])
                    merged_status = (
                        "degraded"
                        if primary_status == "active"
                        and duplicate_status == "degraded"
                        else primary_status
                    )
                    merged_failure_count = max(
                        0,
                        int(primary_metadata["failure_count"] or 0),
                    ) + max(0, int(row["failure_count"] or 0))
                    merged_last_failure_at = _v9_latest_failure_at(
                        primary_metadata["last_failure_at"],
                        row["last_failure_at"],
                    )
                    await db.execute(
                        """UPDATE decoys
                           SET status = ?, failure_count = ?,
                               last_failure_at = ?
                           WHERE id = ?""",
                        (
                            merged_status,
                            merged_failure_count,
                            merged_last_failure_at,
                            primary_id,
                        ),
                    )
                    await db.execute("DELETE FROM decoys WHERE id = ?", (source_id,))

                    evidence_cursor = await db.execute(
                        f"""SELECT decoy_id,
                                   COUNT(*) AS connection_count,
                                   SUM(
                                       CASE
                                           WHEN credential_used IS NOT NULL
                                             OR credential_id IS NOT NULL
                                           THEN 1 ELSE 0
                                       END
                                   ) AS credential_trip_count
                            FROM decoy_connections
                            WHERE decoy_id IN ({retained_placeholders})
                            GROUP BY decoy_id""",
                        retained_ids,
                    )
                    evidence = {
                        int(item["decoy_id"]): (
                            int(item["connection_count"] or 0),
                            int(item["credential_trip_count"] or 0),
                        )
                        for item in await evidence_cursor.fetchall()
                    }
                    for retained_id in retained_ids:
                        known_connections, known_trips = evidence.get(
                            retained_id,
                            (0, 0),
                        )
                        prior_connection_residual, prior_trip_residual = (
                            retained_residuals.get(retained_id, (0, 0))
                        )
                        await db.execute(
                            """UPDATE decoys
                               SET connection_count = ?,
                                   credential_trip_count = ?
                               WHERE id = ?""",
                            (
                                known_connections
                                + prior_connection_residual
                                + (
                                    source_connection_residual
                                    if retained_id == primary_id
                                    else 0
                                ),
                                known_trips
                                + prior_trip_residual
                                + (
                                    source_trip_residual
                                    if retained_id == primary_id
                                    else 0
                                ),
                                retained_id,
                            ),
                        )
                    continue

                duplicate_moved_connections = 0
                duplicate_moved_trips = 0
                for duplicate in duplicate_services:
                    duplicate_port = int(duplicate["port"])
                    duplicate_protocol = str(duplicate["protocol"])
                    owns_legacy_null = (
                        len(protocols_by_port[duplicate_port]) == 1
                    )
                    target_cursor = await db.execute(
                        """SELECT id FROM decoys
                           WHERE host_id = ? AND port = ? AND protocol = ?
                           ORDER BY is_primary DESC, id LIMIT 1""",
                        (host_id, duplicate_port, duplicate_protocol),
                    )
                    target = await target_cursor.fetchone()
                    if target is None:
                        raise RuntimeError(
                            "Missing V9 partial-overlap service target"
                        )
                    target_id = int(target[0])
                    evidence_cursor = await db.execute(
                        """SELECT COUNT(*) AS connection_count,
                                  SUM(
                                      CASE
                                          WHEN credential_used IS NOT NULL
                                            OR credential_id IS NOT NULL
                                          THEN 1 ELSE 0
                                      END
                                  ) AS credential_trip_count
                           FROM decoy_connections
                           WHERE decoy_id = ? AND port = ?
                             AND (
                                 lower(protocol) = ?
                                 OR (protocol IS NULL AND ?)
                             )""",
                        (
                            source_id,
                            duplicate_port,
                            duplicate_protocol,
                            1 if owns_legacy_null else 0,
                        ),
                    )
                    duplicate_evidence = await evidence_cursor.fetchone()
                    moved_connections = int(
                        duplicate_evidence["connection_count"] or 0
                    )
                    moved_trips = int(
                        duplicate_evidence["credential_trip_count"] or 0
                    )
                    duplicate_moved_connections += moved_connections
                    duplicate_moved_trips += moved_trips
                    await db.execute(
                        """UPDATE decoy_connections
                           SET decoy_id = ?
                           WHERE decoy_id = ? AND port = ?
                             AND (
                                 lower(protocol) = ?
                                 OR (protocol IS NULL AND ?)
                             )""",
                        (
                            target_id,
                            source_id,
                            duplicate_port,
                            duplicate_protocol,
                            1 if owns_legacy_null else 0,
                        ),
                    )
                    await db.execute(
                        """UPDATE home_alerts
                           SET decoy_id = ?
                           WHERE decoy_id = ?
                             AND CASE
                                 WHEN NOT json_valid(detail) THEN 0
                                 WHEN json_type(
                                     detail,
                                     '$.dest_port'
                                 ) = 'integer'
                                 THEN json_extract(
                                     detail,
                                     '$.dest_port'
                                 ) = ?
                                 AND (
                                     lower(
                                         json_extract(
                                             detail,
                                             '$.protocol'
                                         )
                                     ) = ?
                                     OR (
                                         json_extract(
                                             detail,
                                             '$.protocol'
                                         ) IS NULL
                                         AND ?
                                     )
                                 )
                                 WHEN (
                                     json_type(
                                         detail,
                                         '$.dest_port'
                                     ) IS NULL
                                     OR json_type(
                                         detail,
                                         '$.dest_port'
                                     ) = 'null'
                                 )
                                 AND json_type(
                                     detail,
                                     '$.port'
                                 ) = 'integer'
                                 THEN json_extract(
                                     detail,
                                     '$.port'
                                 ) = ?
                                 AND (
                                     lower(
                                         json_extract(
                                             detail,
                                             '$.protocol'
                                         )
                                     ) = ?
                                     OR (
                                         json_extract(
                                             detail,
                                             '$.protocol'
                                         ) IS NULL
                                         AND ?
                                     )
                                 )
                                 ELSE 0
                             END""",
                        (
                            target_id,
                            source_id,
                            duplicate_port,
                            duplicate_protocol,
                            1 if owns_legacy_null else 0,
                            duplicate_port,
                            duplicate_protocol,
                            1 if owns_legacy_null else 0,
                        ),
                    )
                    await db.execute(
                        """UPDATE decoys
                           SET connection_count = connection_count + ?,
                               credential_trip_count =
                                   credential_trip_count + ?
                           WHERE id = ?""",
                        (moved_connections, moved_trips, target_id),
                    )
                if duplicate_services:
                    await db.execute(
                        """UPDATE planted_credentials
                           SET decoy_id = ?
                           WHERE decoy_id = ?""",
                        (primary_id, source_id),
                    )
                    await db.execute(
                        """UPDATE home_alerts
                           SET decoy_id = ?
                           WHERE decoy_id = ?
                             AND CASE
                                 WHEN NOT json_valid(detail) THEN 1
                                 WHEN json_type(
                                     detail,
                                     '$.dest_port'
                                 ) = 'integer'
                                 THEN 0
                                 WHEN (
                                     json_type(
                                         detail,
                                         '$.dest_port'
                                     ) IS NULL
                                     OR json_type(
                                         detail,
                                         '$.dest_port'
                                     ) = 'null'
                                 )
                                 AND json_type(
                                     detail,
                                     '$.port'
                                 ) = 'integer'
                                 THEN 0
                                 ELSE 1
                             END""",
                        (primary_id, source_id),
                    )

                if source_id != primary_id:
                    for ambiguous_port, protocols in protocols_by_port.items():
                        if len(protocols) <= 1:
                            continue
                        ambiguous_cursor = await db.execute(
                            """SELECT COUNT(*) AS connection_count,
                                      SUM(
                                          CASE
                                              WHEN credential_used IS NOT NULL
                                                OR credential_id IS NOT NULL
                                              THEN 1 ELSE 0
                                          END
                                      ) AS credential_trip_count
                               FROM decoy_connections
                               WHERE decoy_id = ? AND port = ?
                                 AND protocol IS NULL""",
                            (source_id, ambiguous_port),
                        )
                        ambiguous = await ambiguous_cursor.fetchone()
                        ambiguous_connections = int(
                            ambiguous["connection_count"] or 0
                        )
                        ambiguous_trips = int(
                            ambiguous["credential_trip_count"] or 0
                        )
                        duplicate_moved_connections += ambiguous_connections
                        duplicate_moved_trips += ambiguous_trips
                        await db.execute(
                            """UPDATE decoy_connections
                               SET decoy_id = ?
                               WHERE decoy_id = ? AND port = ?
                                 AND protocol IS NULL""",
                            (primary_id, source_id, ambiguous_port),
                        )
                        await db.execute(
                            """UPDATE home_alerts
                               SET decoy_id = ?
                               WHERE decoy_id = ?
                                 AND CASE
                                     WHEN NOT json_valid(detail) THEN 0
                                     WHEN json_type(
                                         detail,
                                         '$.dest_port'
                                     ) = 'integer'
                                     THEN json_extract(
                                         detail,
                                         '$.dest_port'
                                     ) = ?
                                     WHEN (
                                         json_type(
                                             detail,
                                             '$.dest_port'
                                         ) IS NULL
                                         OR json_type(
                                             detail,
                                             '$.dest_port'
                                         ) = 'null'
                                     )
                                     AND json_type(
                                         detail,
                                         '$.port'
                                     ) = 'integer'
                                     THEN json_extract(
                                         detail,
                                         '$.port'
                                     ) = ?
                                     ELSE 0
                                 END
                                 AND json_extract(
                                     detail,
                                     '$.protocol'
                                 ) IS NULL""",
                            (
                                primary_id,
                                source_id,
                                ambiguous_port,
                                ambiguous_port,
                            ),
                        )
                        await db.execute(
                            """UPDATE decoys
                               SET connection_count = connection_count + ?,
                                   credential_trip_count =
                                       credential_trip_count + ?
                               WHERE id = ?""",
                            (
                                ambiguous_connections,
                                ambiguous_trips,
                                primary_id,
                            ),
                        )

                service_ids: dict[tuple[int, str], int] = {}
                known_cursor = await db.execute(
                    """SELECT port, COUNT(*) AS count
                       FROM decoy_connections
                       WHERE decoy_id = ?
                       GROUP BY port""",
                    (source_id,),
                )
                known_counts = {
                    int(item["port"]): int(item["count"])
                    for item in await known_cursor.fetchall()
                }
                non_primary_known = sum(
                    known_counts.get(int(service["port"]), 0)
                    for service in available[1:]
                )
                primary_count = max(
                    known_counts.get(int(available[0]["port"]), 0),
                    int(row["connection_count"] or 0)
                    - duplicate_moved_connections
                    - non_primary_known,
                )

                for service_index, service in enumerate(available):
                    service_config = dict(base_config)
                    service_config["mdns_hostname"] = label
                    service_config["port_configs"] = [service]
                    service_name = service["service_name"]
                    protocol = service["protocol"]
                    port = int(service["port"])
                    connection_count = (
                        primary_count
                        if service_index == 0
                        else known_counts.get(port, 0)
                    )
                    if service_index == 0:
                        service_id = source_id
                        await db.execute(
                            """UPDATE decoys
                               SET name = ?, host_id = ?, port = ?,
                                   protocol = ?, service_name = ?,
                                   is_primary = ?, config = ?,
                                   connection_count = ?
                               WHERE id = ?""",
                            (
                                hostname,
                                host_id,
                                port,
                                protocol,
                                service_name,
                                1 if source_index == 0 else 0,
                                json.dumps(service_config),
                                connection_count,
                                service_id,
                            ),
                        )
                    else:
                        insert_cursor = await db.execute(
                            """INSERT INTO decoys
                               (name, decoy_type, bind_address, port, status,
                                config, connection_count,
                                credential_trip_count, failure_count,
                                last_failure_at, created_at, updated_at,
                                host_id, protocol, service_name, is_primary)
                               VALUES (?, 'mimic', ?, ?, ?, ?, ?, 0, ?, ?,
                                       ?, ?, ?, ?, ?, 0)""",
                            (
                                hostname,
                                bind_address,
                                port,
                                row["status"],
                                json.dumps(service_config),
                                connection_count,
                                row["failure_count"],
                                row["last_failure_at"],
                                row["created_at"],
                                row["updated_at"],
                                host_id,
                                protocol,
                                service_name,
                            ),
                        )
                        if insert_cursor.lastrowid is None:
                            raise RuntimeError("V9 service insert returned no ID")
                        service_id = int(insert_cursor.lastrowid)
                    service_ids[(port, protocol)] = service_id
                    used_services.add((port, protocol))

                # Historical connection rows already contain the advertised
                # port, so move each record to its now-stable service identity.
                for (port, protocol), service_id in service_ids.items():
                    owns_legacy_null = (
                        len(protocols_by_port[port]) == 1
                    )
                    await db.execute(
                        """UPDATE decoy_connections
                           SET decoy_id = ?
                           WHERE decoy_id = ?
                             AND port = ?
                             AND (
                                 lower(protocol) = ?
                                 OR (protocol IS NULL AND ?)
                             )""",
                        (
                            service_id,
                            source_id,
                            port,
                            protocol,
                            1 if owns_legacy_null else 0,
                        ),
                    )
                    await db.execute(
                        """UPDATE home_alerts
                           SET decoy_id = ?
                           WHERE decoy_id = ?
                             AND CASE
                                 WHEN NOT json_valid(detail) THEN 0
                                 WHEN json_type(
                                     detail,
                                     '$.dest_port'
                                 ) = 'integer'
                                 THEN json_extract(
                                     detail,
                                     '$.dest_port'
                                 ) = ?
                                 WHEN (
                                     json_type(
                                         detail,
                                         '$.dest_port'
                                     ) IS NULL
                                     OR json_type(
                                         detail,
                                         '$.dest_port'
                                     ) = 'null'
                                 )
                                 AND json_type(
                                     detail,
                                     '$.port'
                                 ) = 'integer'
                                 THEN json_extract(
                                     detail,
                                     '$.port'
                                 ) = ?
                                 ELSE 0
                             END
                             AND (
                                 lower(json_extract(
                                     detail,
                                     '$.protocol'
                                 )) = ?
                                 OR (
                                     json_extract(
                                         detail,
                                         '$.protocol'
                                     ) IS NULL
                                     AND ?
                                 )
                             )""",
                        (
                            service_id,
                            source_id,
                            port,
                            port,
                            protocol,
                            1 if owns_legacy_null else 0,
                        ),
                    )

                # Recompute split counters from exact evidence. Any legacy
                # aggregate residual that predates connection logging remains
                # on the original/primary service so totals never decrease.
                split_ids = list(service_ids.values())
                split_placeholders = ",".join("?" for _ in split_ids)
                evidence_cursor = await db.execute(
                    f"""SELECT decoy_id,
                               COUNT(*) AS connection_count,
                               SUM(
                                   CASE
                                       WHEN credential_used IS NOT NULL
                                         OR credential_id IS NOT NULL
                                       THEN 1 ELSE 0
                                   END
                               ) AS credential_trip_count
                        FROM decoy_connections
                        WHERE decoy_id IN ({split_placeholders})
                        GROUP BY decoy_id""",
                    split_ids,
                )
                evidence = {
                    int(item["decoy_id"]): (
                        int(item["connection_count"] or 0),
                        int(item["credential_trip_count"] or 0),
                    )
                    for item in await evidence_cursor.fetchall()
                }
                primary_service_id = service_ids[
                    (
                        int(available[0]["port"]),
                        str(available[0]["protocol"]),
                    )
                ]
                total_known_connections = sum(
                    counts[0] for counts in evidence.values()
                )
                total_known_trips = sum(
                    counts[1] for counts in evidence.values()
                )
                connection_residual = max(
                    0,
                    int(row["connection_count"] or 0)
                    - duplicate_moved_connections
                    - total_known_connections,
                )
                trip_residual = max(
                    0,
                    int(row["credential_trip_count"] or 0)
                    - duplicate_moved_trips
                    - total_known_trips,
                )
                for service_id in split_ids:
                    known_connections, known_trips = evidence.get(
                        service_id,
                        (0, 0),
                    )
                    await db.execute(
                        """UPDATE decoys
                           SET connection_count = ?,
                               credential_trip_count = ?
                           WHERE id = ?""",
                        (
                            known_connections
                            + (
                                connection_residual
                                if service_id == primary_service_id
                                else 0
                            ),
                            known_trips
                            + (
                                trip_residual
                                if service_id == primary_service_id
                                else 0
                            ),
                            service_id,
                        ),
                    )

            await db.execute(
                """UPDATE decoys
                   SET is_primary = CASE WHEN id = ? THEN 1 ELSE 0 END
                   WHERE host_id = ?""",
                (primary_id, host_id),
            )
            await db.execute(
                "UPDATE virtual_ips SET decoy_id = ? WHERE ip_address = ?",
                (primary_id, bind_address),
            )
            if invalid_binding:
                await db.execute(
                    """UPDATE decoys
                       SET status = 'stopped',
                           retired_at = ?,
                           retirement_reason = ?
                       WHERE host_id = ?""",
                    (retired_at, retirement_reason, host_id),
                )
                await db.execute(
                    "DELETE FROM virtual_ips WHERE ip_address = ?",
                    (bind_address,),
                )

        # Classic decoys are already one service per row. Add descriptive
        # metadata without assigning them a virtual-host identity.
        classic_cursor = await db.execute(
            "SELECT id, port FROM decoys WHERE decoy_type != 'mimic'"
        )
        from squirrelops_home_sensor.scanner.service_names import get_service_name

        for row in await classic_cursor.fetchall():
            port = int(row["port"])
            await db.execute(
                """UPDATE decoys
                   SET protocol = COALESCE(protocol, 'tcp'),
                       service_name = COALESCE(service_name, ?)
                   WHERE id = ?""",
                (get_service_name(port) or f"Port {port}", row["id"]),
            )

        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_decoys_host ON decoys(host_id)"
        )
        await db.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS
               idx_decoy_hosts_hostname_nocase
               ON decoy_hosts(hostname COLLATE NOCASE)
               WHERE retired_at IS NULL"""
        )
        await db.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS
               idx_decoy_hosts_active_bind_address
               ON decoy_hosts(bind_address)
               WHERE retired_at IS NULL"""
        )
        await db.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_decoys_host_service
               ON decoys(host_id, port, protocol)
               WHERE host_id IS NOT NULL"""
        )
        await db.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_decoys_host_primary
               ON decoys(host_id)
               WHERE host_id IS NOT NULL AND is_primary = 1"""
        )
        now = datetime.now(UTC).isoformat()
        await db.execute(
            "INSERT OR IGNORE INTO schema_version (version, applied_at) "
            "VALUES (?, ?)",
            (9, now),
        )
        await db.execute("RELEASE SAVEPOINT squirrelops_v9")
        await db.commit()
    except Exception:
        await db.execute("ROLLBACK TO SAVEPOINT squirrelops_v9")
        await db.execute("RELEASE SAVEPOINT squirrelops_v9")
        raise


# Ordered list of migration functions. Index 0 = migration to version 1.
_MIGRATIONS: list[tuple[int, callable]] = [
    (1, _apply_v1),
    (2, _apply_v2),
    (3, _apply_v3),
    (4, _apply_v4),
    (5, _apply_v5),
    (6, _apply_v6),
    (7, _apply_v7),
    (8, _apply_v8),
    (9, _apply_v9),
]


async def apply_migrations(db: aiosqlite.Connection) -> None:
    """Apply all pending migrations to bring the database to the current version.

    Safe to call multiple times -- skips already-applied migrations.
    """
    current = await _get_current_version(db)

    if current >= SCHEMA_VERSION:
        return

    for target_version, migrate_fn in _MIGRATIONS:
        if current < target_version:
            await migrate_fn(db)
            current = target_version
