"""Decoy routes: list, get, restart, update config, connections."""
from __future__ import annotations

import json as json_mod
from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, verify_client_cert

router = APIRouter(prefix="/decoys", tags=["decoys"])


# ---------- Dependency stubs ----------


async def get_decoy_orchestrator():
    """Return the DecoyOrchestrator instance. Overridden in production."""
    return None


# ---------- Request/Response models ----------


class DecoySummary(BaseModel):
    id: int
    name: str
    decoy_type: str
    bind_address: str
    port: int
    status: str
    connection_count: int
    credential_trip_count: int
    created_at: str
    updated_at: str


class DecoyListResponse(BaseModel):
    items: list[DecoySummary]


class DecoyDetail(BaseModel):
    id: int
    name: str
    decoy_type: str
    bind_address: str
    port: int
    status: str
    config: Any  # JSON object
    connection_count: int
    credential_trip_count: int
    failure_count: int
    last_failure_at: Optional[str] = None
    created_at: str
    updated_at: str


class ConnectionEntry(BaseModel):
    id: int
    decoy_id: int
    source_ip: str
    source_mac: Optional[str] = None
    port: int
    protocol: Optional[str] = None
    request_path: Optional[str] = None
    credential_used: Optional[str] = None
    timestamp: str


class PaginatedConnections(BaseModel):
    items: list[ConnectionEntry]
    total: int
    limit: int
    offset: int


class CredentialEntry(BaseModel):
    id: int
    credential_type: str
    planted_location: str
    tripped: bool
    first_tripped_at: Optional[str] = None
    created_at: str


# ---------- Helpers ----------


def _parse_config(raw: Optional[str]) -> Any:
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            return json_mod.loads(raw)
        except (json_mod.JSONDecodeError, TypeError):
            return {}
    return raw


async def _get_decoy_or_404(db: aiosqlite.Connection, decoy_id: int) -> aiosqlite.Row:
    cursor = await db.execute("SELECT * FROM decoys WHERE id = ?", (decoy_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decoy not found")
    return row


def _decoy_detail(row: aiosqlite.Row) -> DecoyDetail:
    return DecoyDetail(
        id=row["id"],
        name=row["name"],
        decoy_type=row["decoy_type"],
        bind_address=row["bind_address"],
        port=row["port"],
        status=row["status"],
        config=_parse_config(row["config"]),
        connection_count=row["connection_count"],
        credential_trip_count=row["credential_trip_count"],
        failure_count=row["failure_count"],
        last_failure_at=row["last_failure_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# ---------- Routes ----------


@router.get("", response_model=DecoyListResponse)
async def list_decoys(
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """List all decoys with status and connection counts."""
    cursor = await db.execute(
        "SELECT * FROM decoys WHERE decoy_type != 'mimic' ORDER BY created_at"
    )
    rows = await cursor.fetchall()

    items = [
        DecoySummary(
            id=row["id"],
            name=row["name"],
            decoy_type=row["decoy_type"],
            bind_address=row["bind_address"],
            port=row["port"],
            status=row["status"],
            connection_count=row["connection_count"],
            credential_trip_count=row["credential_trip_count"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]

    return DecoyListResponse(items=items)


@router.get("/{decoy_id}", response_model=DecoyDetail)
async def get_decoy(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get decoy detail including config and connection log summary."""
    row = await _get_decoy_or_404(db, decoy_id)
    return _decoy_detail(row)


@router.post("/{decoy_id}/restart", response_model=DecoyDetail)
async def restart_decoy(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Restart a decoy service. Resets failure count and sets status to active."""
    await _get_decoy_or_404(db, decoy_id)
    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        """UPDATE decoys SET status = 'active', failure_count = 0,
           last_failure_at = NULL, updated_at = ?
           WHERE id = ?""",
        (now, decoy_id),
    )
    await db.commit()

    cursor = await db.execute("SELECT * FROM decoys WHERE id = ?", (decoy_id,))
    row = await cursor.fetchone()
    return _decoy_detail(row)


@router.post("/{decoy_id}/enable", response_model=DecoyDetail)
async def enable_decoy(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Enable a stopped decoy. No-op if already active."""
    await _get_decoy_or_404(db, decoy_id)
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """UPDATE decoys SET status = 'active', failure_count = 0,
           last_failure_at = NULL, updated_at = ?
           WHERE id = ?""",
        (now, decoy_id),
    )
    await db.commit()
    cursor = await db.execute("SELECT * FROM decoys WHERE id = ?", (decoy_id,))
    row = await cursor.fetchone()
    return _decoy_detail(row)


@router.post("/{decoy_id}/disable", response_model=DecoyDetail)
async def disable_decoy(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Disable an active decoy. No-op if already stopped."""
    await _get_decoy_or_404(db, decoy_id)
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE decoys SET status = 'stopped', updated_at = ? WHERE id = ?",
        (now, decoy_id),
    )
    await db.commit()
    cursor = await db.execute("SELECT * FROM decoys WHERE id = ?", (decoy_id,))
    row = await cursor.fetchone()
    return _decoy_detail(row)


@router.put("/{decoy_id}/config", response_model=DecoyDetail)
async def update_decoy_config(
    decoy_id: int,
    body: dict,
    db: aiosqlite.Connection = Depends(get_db),
    orchestrator=Depends(get_decoy_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Update decoy-specific configuration. Merges with existing config, restarts decoy."""
    row = await _get_decoy_or_404(db, decoy_id)
    existing_config = _parse_config(row["config"])

    # Merge: new keys overwrite, existing keys preserved
    merged = {**existing_config, **body}
    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        "UPDATE decoys SET config = ?, updated_at = ? WHERE id = ?",
        (json_mod.dumps(merged), now, decoy_id),
    )
    await db.commit()

    # Restart the decoy so the new config takes effect
    if orchestrator is not None:
        try:
            await orchestrator.restart_decoy(decoy_id)
        except KeyError:
            pass  # Decoy not currently tracked (e.g. stopped)

    cursor = await db.execute("SELECT * FROM decoys WHERE id = ?", (decoy_id,))
    row = await cursor.fetchone()
    return _decoy_detail(row)


@router.get("/{decoy_id}/credentials", response_model=list[CredentialEntry])
async def get_decoy_credentials(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """List planted credentials for a decoy."""
    await _get_decoy_or_404(db, decoy_id)
    cursor = await db.execute(
        "SELECT * FROM planted_credentials WHERE decoy_id = ? ORDER BY id",
        (decoy_id,),
    )
    rows = await cursor.fetchall()
    return [
        CredentialEntry(
            id=row["id"],
            credential_type=row["credential_type"],
            planted_location=row["planted_location"],
            tripped=bool(row["tripped"]),
            first_tripped_at=row["first_tripped_at"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


@router.get("/{decoy_id}/connections", response_model=PaginatedConnections)
async def get_decoy_connections(
    decoy_id: int,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get paginated connection log for a decoy, ordered by timestamp descending."""
    await _get_decoy_or_404(db, decoy_id)

    cursor = await db.execute(
        "SELECT COUNT(*) FROM decoy_connections WHERE decoy_id = ?", (decoy_id,)
    )
    total = (await cursor.fetchone())[0]

    cursor = await db.execute(
        """SELECT * FROM decoy_connections
           WHERE decoy_id = ?
           ORDER BY timestamp DESC
           LIMIT ? OFFSET ?""",
        (decoy_id, limit, offset),
    )
    rows = await cursor.fetchall()

    items = [
        ConnectionEntry(
            id=row["id"],
            decoy_id=row["decoy_id"],
            source_ip=row["source_ip"],
            source_mac=row["source_mac"],
            port=row["port"],
            protocol=row["protocol"],
            request_path=row["request_path"],
            credential_used=row["credential_used"],
            timestamp=row["timestamp"],
        )
        for row in rows
    ]

    return PaginatedConnections(items=items, total=total, limit=limit, offset=offset)
