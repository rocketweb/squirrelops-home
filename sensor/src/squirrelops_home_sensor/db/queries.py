"""Typed async query helpers for all SquirrelOps Home Sensor tables.

Every function takes an ``aiosqlite.Connection`` as its first argument and
returns plain dicts (row_factory = aiosqlite.Row) or scalar values. This
module provides the data-access layer used by the API routes and internal
components.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

import aiosqlite


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _fetchone(
    db: aiosqlite.Connection, sql: str, params: tuple = ()
) -> dict[str, Any] | None:
    cursor = await db.execute(sql, params)
    row = await cursor.fetchone()
    if row is None:
        return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


async def _fetchall(
    db: aiosqlite.Connection, sql: str, params: tuple = ()
) -> list[dict[str, Any]]:
    cursor = await db.execute(sql, params)
    rows = await cursor.fetchall()
    if not rows:
        return []
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]


# ---------------------------------------------------------------------------
# Device fingerprint queries
# ---------------------------------------------------------------------------

async def insert_device_fingerprint(
    db: aiosqlite.Connection,
    *,
    device_id: int | None = None,
    mac_address: str | None = None,
    mdns_hostname: str | None = None,
    dhcp_fingerprint_hash: str | None = None,
    connection_pattern_hash: str | None = None,
    open_ports_hash: str | None = None,
    composite_hash: str | None = None,
    signal_count: int,
    confidence: float | None = None,
    first_seen: str,
    last_seen: str,
) -> int:
    """Insert a device fingerprint record and return its id."""
    cursor = await db.execute(
        """INSERT INTO device_fingerprints
           (device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash,
            connection_pattern_hash, open_ports_hash, composite_hash,
            signal_count, confidence, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (device_id, mac_address, mdns_hostname, dhcp_fingerprint_hash,
         connection_pattern_hash, open_ports_hash, composite_hash,
         signal_count, confidence, first_seen, last_seen),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def get_device_fingerprints(
    db: aiosqlite.Connection,
    device_id: int | None = None,
) -> list[dict[str, Any]]:
    """List fingerprints, optionally filtered by device_id."""
    if device_id is not None:
        return await _fetchall(
            db,
            "SELECT * FROM device_fingerprints WHERE device_id = ? ORDER BY last_seen DESC",
            (device_id,),
        )
    return await _fetchall(
        db, "SELECT * FROM device_fingerprints ORDER BY last_seen DESC"
    )


# ---------------------------------------------------------------------------
# Device trust queries
# ---------------------------------------------------------------------------

async def set_device_trust(
    db: aiosqlite.Connection,
    *,
    device_id: int,
    status: str,
    approved_by: str | None = None,
    updated_at: str,
) -> None:
    """Insert or update device trust status (upsert)."""
    await db.execute(
        """INSERT INTO device_trust (device_id, status, approved_by, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(device_id)
           DO UPDATE SET status = excluded.status,
                         approved_by = excluded.approved_by,
                         updated_at = excluded.updated_at""",
        (device_id, status, approved_by, updated_at),
    )
    await db.commit()


async def get_device_trust(
    db: aiosqlite.Connection, device_id: int
) -> dict[str, Any] | None:
    """Get trust status for a device."""
    return await _fetchone(
        db, "SELECT * FROM device_trust WHERE device_id = ?", (device_id,)
    )


# ---------------------------------------------------------------------------
# Alert queries
# ---------------------------------------------------------------------------

async def insert_alert(
    db: aiosqlite.Connection,
    *,
    alert_type: str,
    severity: str,
    title: str,
    detail: str,
    created_at: str,
    incident_id: int | None = None,
    source_ip: str | None = None,
    source_mac: str | None = None,
    device_id: int | None = None,
    decoy_id: int | None = None,
    event_seq: int | None = None,
) -> int:
    """Insert an alert and return its id."""
    cursor = await db.execute(
        """INSERT INTO home_alerts
           (incident_id, alert_type, severity, title, detail, source_ip,
            source_mac, device_id, decoy_id, event_seq, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (incident_id, alert_type, severity, title, detail, source_ip,
         source_mac, device_id, decoy_id, event_seq, created_at),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def get_alert(
    db: aiosqlite.Connection, alert_id: int
) -> dict[str, Any] | None:
    """Get a single alert by id."""
    return await _fetchone(
        db, "SELECT * FROM home_alerts WHERE id = ?", (alert_id,)
    )


async def list_alerts(
    db: aiosqlite.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    alert_type: str | None = None,
    unread_only: bool = False,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """List alerts with optional filters, pagination, and date range."""
    conditions: list[str] = []
    params: list[Any] = []

    if severity is not None:
        conditions.append("severity = ?")
        params.append(severity)
    if alert_type is not None:
        conditions.append("alert_type = ?")
        params.append(alert_type)
    if unread_only:
        conditions.append("read_at IS NULL")
    if date_from is not None:
        conditions.append("created_at >= ?")
        params.append(date_from)
    if date_to is not None:
        conditions.append("created_at <= ?")
        params.append(date_to)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    sql = f"SELECT * FROM home_alerts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return await _fetchall(db, sql, tuple(params))


async def mark_alert_read(
    db: aiosqlite.Connection, alert_id: int, *, read_at: str
) -> None:
    """Mark an alert as read."""
    await db.execute(
        "UPDATE home_alerts SET read_at = ? WHERE id = ?", (read_at, alert_id)
    )
    await db.commit()


async def mark_alert_actioned(
    db: aiosqlite.Connection, alert_id: int, *, actioned_at: str
) -> None:
    """Mark an alert as actioned."""
    await db.execute(
        "UPDATE home_alerts SET actioned_at = ? WHERE id = ?",
        (actioned_at, alert_id),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Incident queries
# ---------------------------------------------------------------------------

async def insert_incident(
    db: aiosqlite.Connection,
    *,
    source_ip: str,
    severity: str,
    first_alert_at: str,
    last_alert_at: str,
    source_mac: str | None = None,
    summary: str | None = None,
) -> int:
    """Insert an incident and return its id."""
    cursor = await db.execute(
        """INSERT INTO incidents
           (source_ip, source_mac, severity, first_alert_at, last_alert_at, summary)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (source_ip, source_mac, severity, first_alert_at, last_alert_at, summary),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def get_incident(
    db: aiosqlite.Connection, incident_id: int
) -> dict[str, Any] | None:
    """Get a single incident by id."""
    return await _fetchone(
        db, "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    )


async def get_active_incident_for_source(
    db: aiosqlite.Connection,
    *,
    source_ip: str,
    window_minutes: int = 15,
) -> dict[str, Any] | None:
    """Find an active incident from the same source within the time window.

    Returns the most recent active incident whose ``last_alert_at`` is
    within ``window_minutes`` of now, or None if no match.
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return await _fetchone(
        db,
        """SELECT * FROM incidents
           WHERE source_ip = ? AND status = 'active' AND last_alert_at >= ?
           ORDER BY last_alert_at DESC LIMIT 1""",
        (source_ip, cutoff),
    )


async def update_incident(
    db: aiosqlite.Connection,
    incident_id: int,
    *,
    alert_count: int | None = None,
    severity: str | None = None,
    last_alert_at: str | None = None,
    summary: str | None = None,
) -> None:
    """Update selected fields on an incident."""
    sets: list[str] = []
    params: list[Any] = []
    if alert_count is not None:
        sets.append("alert_count = ?")
        params.append(alert_count)
    if severity is not None:
        sets.append("severity = ?")
        params.append(severity)
    if last_alert_at is not None:
        sets.append("last_alert_at = ?")
        params.append(last_alert_at)
    if summary is not None:
        sets.append("summary = ?")
        params.append(summary)
    if not sets:
        return
    params.append(incident_id)
    sql = f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?"
    await db.execute(sql, tuple(params))
    await db.commit()


async def close_incident(
    db: aiosqlite.Connection, incident_id: int, *, closed_at: str
) -> None:
    """Close an incident."""
    await db.execute(
        "UPDATE incidents SET status = 'closed', closed_at = ? WHERE id = ?",
        (closed_at, incident_id),
    )
    await db.commit()


async def list_incidents(
    db: aiosqlite.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """List incidents with optional status filter."""
    if status is not None:
        return await _fetchall(
            db,
            "SELECT * FROM incidents WHERE status = ? ORDER BY last_alert_at DESC LIMIT ? OFFSET ?",
            (status, limit, offset),
        )
    return await _fetchall(
        db,
        "SELECT * FROM incidents ORDER BY last_alert_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )


# ---------------------------------------------------------------------------
# Decoy queries
# ---------------------------------------------------------------------------

async def insert_decoy(
    db: aiosqlite.Connection,
    *,
    name: str,
    decoy_type: str,
    bind_address: str,
    port: int,
    created_at: str,
    updated_at: str,
    config: str | None = None,
) -> int:
    """Insert a decoy and return its id."""
    cursor = await db.execute(
        """INSERT INTO decoys
           (name, decoy_type, bind_address, port, config, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (name, decoy_type, bind_address, port, config, created_at, updated_at),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def get_decoy(
    db: aiosqlite.Connection, decoy_id: int
) -> dict[str, Any] | None:
    """Get a single decoy by id."""
    return await _fetchone(
        db, "SELECT * FROM decoys WHERE id = ?", (decoy_id,)
    )


async def list_decoys(
    db: aiosqlite.Connection,
    *,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """List all decoys, optionally filtered by status."""
    if status is not None:
        return await _fetchall(
            db, "SELECT * FROM decoys WHERE status = ? ORDER BY name", (status,)
        )
    return await _fetchall(db, "SELECT * FROM decoys ORDER BY name")


async def update_decoy_status(
    db: aiosqlite.Connection,
    decoy_id: int,
    *,
    status: str,
    updated_at: str,
) -> None:
    """Update a decoy's status."""
    await db.execute(
        "UPDATE decoys SET status = ?, updated_at = ? WHERE id = ?",
        (status, updated_at, decoy_id),
    )
    await db.commit()


async def increment_decoy_connection_count(
    db: aiosqlite.Connection, decoy_id: int
) -> None:
    """Increment the connection count for a decoy by 1."""
    await db.execute(
        "UPDATE decoys SET connection_count = connection_count + 1 WHERE id = ?",
        (decoy_id,),
    )
    await db.commit()


async def increment_decoy_credential_trip_count(
    db: aiosqlite.Connection, decoy_id: int
) -> None:
    """Increment the credential trip count for a decoy by 1."""
    await db.execute(
        "UPDATE decoys SET credential_trip_count = credential_trip_count + 1 WHERE id = ?",
        (decoy_id,),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Decoy connection queries
# ---------------------------------------------------------------------------

async def insert_decoy_connection(
    db: aiosqlite.Connection,
    *,
    decoy_id: int,
    source_ip: str,
    port: int,
    timestamp: str,
    source_mac: str | None = None,
    protocol: str | None = None,
    request_path: str | None = None,
    credential_used: str | None = None,
    credential_id: int | None = None,
    event_seq: int | None = None,
) -> int:
    """Insert a decoy connection record and return its id."""
    cursor = await db.execute(
        """INSERT INTO decoy_connections
           (decoy_id, source_ip, source_mac, port, protocol, request_path,
            credential_used, credential_id, event_seq, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (decoy_id, source_ip, source_mac, port, protocol, request_path,
         credential_used, credential_id, event_seq, timestamp),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def list_decoy_connections(
    db: aiosqlite.Connection,
    *,
    decoy_id: int | None = None,
    source_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List decoy connections with optional filters."""
    conditions: list[str] = []
    params: list[Any] = []
    if decoy_id is not None:
        conditions.append("decoy_id = ?")
        params.append(decoy_id)
    if source_ip is not None:
        conditions.append("source_ip = ?")
        params.append(source_ip)
    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)
    sql = f"SELECT * FROM decoy_connections {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return await _fetchall(db, sql, tuple(params))


# ---------------------------------------------------------------------------
# Planted credential queries
# ---------------------------------------------------------------------------

async def insert_planted_credential(
    db: aiosqlite.Connection,
    *,
    credential_type: str,
    credential_value: str,
    planted_location: str,
    created_at: str,
    canary_hostname: str | None = None,
    decoy_id: int | None = None,
) -> int:
    """Insert a planted credential and return its id."""
    cursor = await db.execute(
        """INSERT INTO planted_credentials
           (credential_type, credential_value, canary_hostname,
            planted_location, decoy_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (credential_type, credential_value, canary_hostname,
         planted_location, decoy_id, created_at),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def get_planted_credential(
    db: aiosqlite.Connection, credential_id: int
) -> dict[str, Any] | None:
    """Get a single planted credential by id."""
    return await _fetchone(
        db, "SELECT * FROM planted_credentials WHERE id = ?", (credential_id,)
    )


async def list_planted_credentials(
    db: aiosqlite.Connection,
    *,
    decoy_id: int | None = None,
) -> list[dict[str, Any]]:
    """List planted credentials, optionally filtered by decoy_id."""
    if decoy_id is not None:
        return await _fetchall(
            db,
            "SELECT * FROM planted_credentials WHERE decoy_id = ? ORDER BY created_at DESC",
            (decoy_id,),
        )
    return await _fetchall(
        db, "SELECT * FROM planted_credentials ORDER BY created_at DESC"
    )


async def mark_credential_tripped(
    db: aiosqlite.Connection, credential_id: int, *, tripped_at: str
) -> None:
    """Mark a planted credential as tripped."""
    await db.execute(
        """UPDATE planted_credentials
           SET tripped = 1, first_tripped_at = COALESCE(first_tripped_at, ?)
           WHERE id = ?""",
        (tripped_at, credential_id),
    )
    await db.commit()


async def get_credential_by_value(
    db: aiosqlite.Connection, credential_value: str
) -> dict[str, Any] | None:
    """Look up a planted credential by its value (for decoy trip detection)."""
    return await _fetchone(
        db,
        "SELECT * FROM planted_credentials WHERE credential_value = ?",
        (credential_value,),
    )


async def get_credential_by_canary_hostname(
    db: aiosqlite.Connection, canary_hostname: str
) -> dict[str, Any] | None:
    """Look up a planted credential by its canary hostname (for DNS detection)."""
    return await _fetchone(
        db,
        "SELECT * FROM planted_credentials WHERE canary_hostname = ?",
        (canary_hostname,),
    )


# ---------------------------------------------------------------------------
# Canary observation queries
# ---------------------------------------------------------------------------

async def insert_canary_observation(
    db: aiosqlite.Connection,
    *,
    credential_id: int,
    canary_hostname: str,
    queried_by_ip: str,
    observed_at: str,
    queried_by_mac: str | None = None,
    event_seq: int | None = None,
) -> int:
    """Insert a canary observation and return its id."""
    cursor = await db.execute(
        """INSERT INTO canary_observations
           (credential_id, canary_hostname, queried_by_ip,
            queried_by_mac, event_seq, observed_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (credential_id, canary_hostname, queried_by_ip,
         queried_by_mac, event_seq, observed_at),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def list_canary_observations(
    db: aiosqlite.Connection,
    *,
    credential_id: int | None = None,
    canary_hostname: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List canary observations with optional filters."""
    conditions: list[str] = []
    params: list[Any] = []
    if credential_id is not None:
        conditions.append("credential_id = ?")
        params.append(credential_id)
    if canary_hostname is not None:
        conditions.append("canary_hostname = ?")
        params.append(canary_hostname)
    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)
    sql = f"SELECT * FROM canary_observations {where} ORDER BY observed_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return await _fetchall(db, sql, tuple(params))


# ---------------------------------------------------------------------------
# Pairing queries
# ---------------------------------------------------------------------------

async def insert_pairing(
    db: aiosqlite.Connection,
    *,
    client_name: str,
    client_cert_fingerprint: str,
    paired_at: str,
    is_local: bool = False,
) -> int:
    """Insert a pairing record and return its id."""
    cursor = await db.execute(
        """INSERT INTO pairing
           (client_name, client_cert_fingerprint, is_local, paired_at)
           VALUES (?, ?, ?, ?)""",
        (client_name, client_cert_fingerprint, int(is_local), paired_at),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def get_pairing(
    db: aiosqlite.Connection, pairing_id: int
) -> dict[str, Any] | None:
    """Get a single pairing by id."""
    return await _fetchone(
        db, "SELECT * FROM pairing WHERE id = ?", (pairing_id,)
    )


async def list_pairings(
    db: aiosqlite.Connection,
) -> list[dict[str, Any]]:
    """List all pairings."""
    return await _fetchall(db, "SELECT * FROM pairing ORDER BY paired_at DESC")


async def delete_pairing(
    db: aiosqlite.Connection, pairing_id: int
) -> None:
    """Delete a pairing by id."""
    await db.execute("DELETE FROM pairing WHERE id = ?", (pairing_id,))
    await db.commit()


async def update_pairing_last_connected(
    db: aiosqlite.Connection,
    pairing_id: int,
    *,
    last_connected_at: str,
) -> None:
    """Update the last_connected_at timestamp for a pairing."""
    await db.execute(
        "UPDATE pairing SET last_connected_at = ? WHERE id = ?",
        (last_connected_at, pairing_id),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Connection baseline queries
# ---------------------------------------------------------------------------

async def upsert_baseline_connection(
    db: aiosqlite.Connection,
    *,
    device_id: int,
    dest_ip: str,
    dest_port: int,
    seen_at: str,
) -> None:
    """Insert or update a connection baseline entry.

    On conflict (same device_id, dest_ip, dest_port), increments hit_count
    and updates last_seen.
    """
    await db.execute(
        """INSERT INTO connection_baselines
           (device_id, dest_ip, dest_port, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(device_id, dest_ip, dest_port)
           DO UPDATE SET hit_count = hit_count + 1,
                         last_seen = excluded.last_seen""",
        (device_id, dest_ip, dest_port, seen_at, seen_at),
    )
    await db.commit()


async def get_device_baseline(
    db: aiosqlite.Connection, device_id: int
) -> set[tuple[str, int]]:
    """Return the set of (dest_ip, dest_port) pairs in the baseline for a device."""
    rows = await _fetchall(
        db,
        "SELECT dest_ip, dest_port FROM connection_baselines WHERE device_id = ?",
        (device_id,),
    )
    return {(row["dest_ip"], row["dest_port"]) for row in rows}


async def has_baseline(
    db: aiosqlite.Connection, device_id: int
) -> bool:
    """Return True if the device has at least one baseline entry."""
    row = await _fetchone(
        db,
        "SELECT 1 FROM connection_baselines WHERE device_id = ? LIMIT 1",
        (device_id,),
    )
    return row is not None


# ---------------------------------------------------------------------------
# Retention / purge
# ---------------------------------------------------------------------------

async def purge_old_records(
    db: aiosqlite.Connection,
    *,
    days: int = 90,
) -> dict[str, int]:
    """Purge records older than the specified number of days.

    Returns a dict with counts of purged records per table.
    Preserves alerts linked to active (unclosed) incidents.
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=days)
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    counts: dict[str, int] = {}

    # Purge alerts not linked to active incidents
    cursor = await db.execute(
        """DELETE FROM home_alerts
           WHERE created_at < ?
           AND (incident_id IS NULL
                OR incident_id IN (
                    SELECT id FROM incidents WHERE status = 'closed'
                ))""",
        (cutoff,),
    )
    counts["alerts"] = cursor.rowcount

    # Purge closed incidents
    cursor = await db.execute(
        "DELETE FROM incidents WHERE status = 'closed' AND closed_at < ?",
        (cutoff,),
    )
    counts["incidents"] = cursor.rowcount

    # Purge old events
    cursor = await db.execute(
        "DELETE FROM events WHERE created_at < ?", (cutoff,)
    )
    counts["events"] = cursor.rowcount

    # Purge old decoy connections
    cursor = await db.execute(
        "DELETE FROM decoy_connections WHERE timestamp < ?", (cutoff,)
    )
    counts["decoy_connections"] = cursor.rowcount

    # Purge old canary observations
    cursor = await db.execute(
        "DELETE FROM canary_observations WHERE observed_at < ?", (cutoff,)
    )
    counts["canary_observations"] = cursor.rowcount

    await db.commit()
    return counts
