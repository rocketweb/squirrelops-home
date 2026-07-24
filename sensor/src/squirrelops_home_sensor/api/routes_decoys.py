"""Decoy routes: list, get, restart, update config, connections."""
from __future__ import annotations

import json as json_mod
from datetime import UTC, datetime
from typing import Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, verify_client_cert
from squirrelops_home_sensor.api.routes_scouts import get_mimic_orchestrator

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
    host_id: int | None = None
    hostname: str | None = None
    protocol: str | None = None
    service_name: str | None = None


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
    last_failure_at: str | None = None
    created_at: str
    updated_at: str
    host_id: int | None = None
    hostname: str | None = None
    protocol: str | None = None
    service_name: str | None = None


class DecoyHostnameUpdate(BaseModel):
    hostname: str


class DecoyHostnameUpdateResponse(BaseModel):
    host_id: int
    hostname: str
    bind_address: str
    decoy_ids: list[int]
    services: list[DecoySummary]


class ConnectionEntry(BaseModel):
    id: int
    decoy_id: int
    source_ip: str
    source_mac: str | None = None
    port: int
    protocol: str | None = None
    request_path: str | None = None
    credential_used: str | None = None
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
    first_tripped_at: str | None = None
    created_at: str


# ---------- Helpers ----------


def _parse_config(raw: str | None) -> Any:
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            return json_mod.loads(raw)
        except (json_mod.JSONDecodeError, TypeError):
            return {}
    return raw


async def _get_decoy_or_404(db: aiosqlite.Connection, decoy_id: int) -> aiosqlite.Row:
    cursor = await db.execute(
        """SELECT d.*, dh.hostname AS hostname
           FROM decoys d
           LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
           WHERE d.id = ? AND d.retired_at IS NULL""",
        (decoy_id,),
    )
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
        host_id=row["host_id"],
        hostname=row["hostname"],
        protocol=row["protocol"],
        service_name=row["service_name"],
    )


def _decoy_summary(
    row: aiosqlite.Row,
    *,
    effective_status: str | None = None,
) -> DecoySummary:
    return DecoySummary(
        id=row["id"],
        name=row["name"],
        decoy_type=row["decoy_type"],
        bind_address=row["bind_address"],
        port=row["port"],
        status=effective_status or row["status"],
        connection_count=row["connection_count"],
        credential_trip_count=row["credential_trip_count"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        host_id=row["host_id"],
        hostname=row["hostname"],
        protocol=row["protocol"],
        service_name=row["service_name"],
    )


# ---------- Routes ----------


@router.get("", response_model=DecoyListResponse)
async def list_decoys(
    db: aiosqlite.Connection = Depends(get_db),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """List all decoys (including mimics) with status and connection counts."""
    cursor = await db.execute(
        """SELECT d.*, dh.hostname AS hostname
           FROM decoys d
           LEFT JOIN decoy_hosts dh ON dh.id = d.host_id
           WHERE d.retired_at IS NULL
           ORDER BY d.created_at, d.id"""
    )
    rows = await cursor.fetchall()

    items = [
        _decoy_summary(
            row,
            effective_status=(
                mimic_orchestrator.effective_mimic_status(
                    row["id"],
                    row["status"],
                )
                if row["decoy_type"] == "mimic"
                and mimic_orchestrator is not None
                else row["status"]
            ),
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
    orchestrator=Depends(get_decoy_orchestrator),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Restart the live listener and report failure instead of faking state."""
    existing = await _get_decoy_or_404(db, decoy_id)
    if existing["decoy_type"] == "mimic":
        if mimic_orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Mimic orchestrator is unavailable",
            )
        succeeded = await mimic_orchestrator.restart_mimic(decoy_id)
    else:
        if orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Decoy orchestrator is unavailable",
            )
        succeeded = await orchestrator.restart_decoy(decoy_id)

    if not succeeded:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Decoy could not be restarted; its persisted state was preserved",
        )

    row = await _get_decoy_or_404(db, decoy_id)
    return _decoy_detail(row)


@router.post("/{decoy_id}/enable", response_model=DecoyDetail)
async def enable_decoy(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    orchestrator=Depends(get_decoy_orchestrator),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Start a stopped decoy and only mark it active after it is reachable."""
    existing = await _get_decoy_or_404(db, decoy_id)
    if existing["decoy_type"] == "mimic":
        if mimic_orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Mimic orchestrator is unavailable",
            )
        succeeded = await mimic_orchestrator.enable_mimic(decoy_id)
    else:
        if orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Decoy orchestrator is unavailable",
            )
        succeeded = await orchestrator.enable_decoy(decoy_id)

    if not succeeded:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Decoy could not be enabled; its persisted state was preserved",
        )

    row = await _get_decoy_or_404(db, decoy_id)
    return _decoy_detail(row)


@router.post("/{decoy_id}/disable", response_model=DecoyDetail)
async def disable_decoy(
    decoy_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    orchestrator=Depends(get_decoy_orchestrator),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Stop the live listener before reporting the decoy as stopped."""
    existing = await _get_decoy_or_404(db, decoy_id)
    if existing["decoy_type"] == "mimic":
        if mimic_orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Mimic orchestrator is unavailable",
            )
        succeeded = await mimic_orchestrator.disable_mimic(decoy_id)
    else:
        if orchestrator is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Decoy orchestrator is unavailable",
            )
        succeeded = await orchestrator.disable_decoy(decoy_id)

    if not succeeded:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Decoy could not be disabled; its persisted state was preserved",
        )

    row = await _get_decoy_or_404(db, decoy_id)
    return _decoy_detail(row)


@router.put("/{decoy_id}/config", response_model=DecoyDetail)
async def update_decoy_config(
    decoy_id: int,
    body: dict,
    db: aiosqlite.Connection = Depends(get_db),
    orchestrator=Depends(get_decoy_orchestrator),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Update decoy-specific configuration. Merges with existing config, restarts decoy."""
    row = await _get_decoy_or_404(db, decoy_id)
    existing_config = _parse_config(row["config"])

    # Merge: new keys overwrite, existing keys preserved
    merged = {**existing_config, **body}
    now = datetime.now(UTC).isoformat()

    await db.execute(
        "UPDATE decoys SET config = ?, updated_at = ? WHERE id = ?",
        (json_mod.dumps(merged), now, decoy_id),
    )
    await db.commit()

    # Restart the decoy so the new config takes effect
    if row["status"] == "active":
        if row["decoy_type"] == "mimic":
            if mimic_orchestrator is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Mimic orchestrator is unavailable",
                )
            restarted = await mimic_orchestrator.restart_mimic(decoy_id)
        else:
            if orchestrator is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Decoy orchestrator is unavailable",
                )
            restarted = await orchestrator.restart_decoy(decoy_id)
        if not restarted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Configuration was saved, but the decoy could not be restarted",
            )

    row = await _get_decoy_or_404(db, decoy_id)
    return _decoy_detail(row)


@router.put(
    "/{decoy_id}/hostname",
    response_model=DecoyHostnameUpdateResponse,
)
async def update_decoy_hostname(
    decoy_id: int,
    body: DecoyHostnameUpdate,
    db: aiosqlite.Connection = Depends(get_db),
    mimic_orchestrator=Depends(get_mimic_orchestrator),
    _auth: dict = Depends(verify_client_cert),
):
    """Rename one virtual host and every service sharing its identity."""
    existing = await _get_decoy_or_404(db, decoy_id)
    if existing["decoy_type"] != "mimic" or existing["host_id"] is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only virtual mimic hostnames can be changed",
        )
    if mimic_orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mimic orchestrator is unavailable",
        )

    try:
        result = await mimic_orchestrator.update_mimic_hostname(
            decoy_id,
            body.hostname,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    cursor = await db.execute(
        """SELECT d.*, dh.hostname AS hostname
           FROM decoys d
           JOIN decoy_hosts dh ON dh.id = d.host_id
           WHERE d.host_id = ?
             AND d.retired_at IS NULL
           ORDER BY d.port, d.id""",
        (result["host_id"],),
    )
    rows = list(await cursor.fetchall())
    services = [
        _decoy_summary(
            row,
            effective_status=(
                mimic_orchestrator.effective_mimic_status(
                    row["id"],
                    row["status"],
                )
            ),
        )
        for row in rows
    ]
    return DecoyHostnameUpdateResponse(
        host_id=result["host_id"],
        hostname=result["hostname"],
        bind_address=result["bind_address"],
        decoy_ids=[item.id for item in services],
        services=services,
    )


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
