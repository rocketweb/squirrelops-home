"""Alert routes: list, get, incident detail, mark read/actioned, export."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, verify_client_cert

router = APIRouter(tags=["alerts"])


# ---------- Request/Response models ----------


class AlertSummary(BaseModel):
    id: int
    incident_id: Optional[int] = None
    alert_type: str
    severity: str
    title: str
    source_ip: Optional[str] = None
    read_at: Optional[str] = None
    actioned_at: Optional[str] = None
    created_at: str
    alert_count: Optional[int] = None  # present when this represents an incident


class PaginatedAlerts(BaseModel):
    items: list[AlertSummary]
    total: int
    limit: int
    offset: int


class AlertDetail(BaseModel):
    id: int
    incident_id: Optional[int] = None
    alert_type: str
    severity: str
    title: str
    detail: Any  # JSON object
    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    device_id: Optional[int] = None
    decoy_id: Optional[int] = None
    read_at: Optional[str] = None
    actioned_at: Optional[str] = None
    action_note: Optional[str] = None
    created_at: str


class IncidentDetail(BaseModel):
    id: int
    source_ip: str
    source_mac: Optional[str] = None
    status: str
    severity: str
    alert_count: int
    first_alert_at: str
    last_alert_at: str
    closed_at: Optional[str] = None
    summary: Optional[str] = None
    alerts: list[AlertDetail]


class ActionRequest(BaseModel):
    note: Optional[str] = None


class AlertReadResponse(BaseModel):
    id: int
    read_at: str


class IncidentReadResponse(BaseModel):
    id: int
    read_at: str
    alerts_marked: int


class ExportResponse(BaseModel):
    alerts: list[AlertDetail]
    incidents: list[IncidentDetail] = []
    exported_at: str


# ---------- Helpers ----------


def _parse_alert_row(row: aiosqlite.Row) -> AlertDetail:
    detail = row["detail"]
    if isinstance(detail, str):
        import json
        try:
            detail = json.loads(detail)
        except (json.JSONDecodeError, TypeError):
            pass

    return AlertDetail(
        id=row["id"],
        incident_id=row["incident_id"],
        alert_type=row["alert_type"],
        severity=row["severity"],
        title=row["title"],
        detail=detail,
        source_ip=row["source_ip"],
        source_mac=row["source_mac"],
        device_id=row["device_id"],
        decoy_id=row["decoy_id"],
        read_at=row["read_at"],
        actioned_at=row["actioned_at"],
        action_note=row["action_note"] if "action_note" in row.keys() else None,
        created_at=row["created_at"],
    )


# ---------- Alert routes ----------


@router.get("/alerts", response_model=PaginatedAlerts)
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    unread: Optional[bool] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """List alerts with pagination and filters.

    Alerts belonging to an incident are collapsed: each incident appears as a
    single item with alert_count > 1. Standalone alerts have alert_count = None.
    """
    where_clauses: list[str] = []
    params: list = []

    if severity:
        where_clauses.append("a.severity = ?")
        params.append(severity)

    if alert_type:
        where_clauses.append("a.alert_type = ?")
        params.append(alert_type)

    if unread is True:
        where_clauses.append("a.read_at IS NULL")
    elif unread is False:
        where_clauses.append("a.read_at IS NOT NULL")

    if date_from:
        where_clauses.append("a.created_at >= ?")
        params.append(date_from)

    if date_to:
        where_clauses.append("a.created_at <= ?")
        params.append(date_to)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # Count total items (standalone + distinct incidents)
    standalone_where = where_sql + (" AND" if where_clauses else "WHERE") + " a.incident_id IS NULL"
    incident_where = where_sql + (" AND" if where_clauses else "WHERE") + " a.incident_id IS NOT NULL"

    count_sql = f"""
        SELECT (
            SELECT COUNT(*) FROM home_alerts a
            {standalone_where}
        ) + (
            SELECT COUNT(DISTINCT a.incident_id) FROM home_alerts a
            {incident_where}
        )
    """
    cursor = await db.execute(count_sql, params + params)
    total = (await cursor.fetchone())[0]

    # Fetch: standalone alerts
    standalone_sql = f"""
        SELECT a.*, NULL as alert_count FROM home_alerts a
        {standalone_where}
    """

    # Fetch: one representative per incident (latest alert), with incident's alert_count
    incident_sql = f"""
        SELECT a.*, i.alert_count FROM home_alerts a
        INNER JOIN incidents i ON i.id = a.incident_id
        {incident_where}
        AND a.id = (
            SELECT MAX(a2.id) FROM home_alerts a2 WHERE a2.incident_id = a.incident_id
        )
    """

    combined_sql = f"""
        SELECT * FROM (
            {standalone_sql}
            UNION ALL
            {incident_sql}
        ) ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """
    cursor = await db.execute(combined_sql, params + params + [limit, offset])
    rows = await cursor.fetchall()

    items = []
    for row in rows:
        items.append(
            AlertSummary(
                id=row["id"],
                incident_id=row["incident_id"],
                alert_type=row["alert_type"],
                severity=row["severity"],
                title=row["title"],
                source_ip=row["source_ip"],
                read_at=row["read_at"],
                actioned_at=row["actioned_at"],
                created_at=row["created_at"],
                alert_count=row["alert_count"],
            )
        )

    return PaginatedAlerts(items=items, total=total, limit=limit, offset=offset)


@router.get("/alerts/export", response_model=ExportResponse)
async def export_alerts(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Export all alerts and incidents as JSON, optionally filtered by date range."""
    where_clauses: list[str] = []
    params: list = []

    if date_from:
        where_clauses.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("created_at <= ?")
        params.append(date_to)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    cursor = await db.execute(f"SELECT * FROM home_alerts {where_sql} ORDER BY created_at", params)
    rows = await cursor.fetchall()
    alerts = [_parse_alert_row(row) for row in rows]

    # Fetch incidents that have alerts in the date range
    incident_ids = {a.incident_id for a in alerts if a.incident_id is not None}
    incidents = []
    for iid in incident_ids:
        cursor = await db.execute("SELECT * FROM incidents WHERE id = ?", (iid,))
        inc_row = await cursor.fetchone()
        if inc_row:
            child_alerts = [a for a in alerts if a.incident_id == iid]
            incidents.append(
                IncidentDetail(
                    id=inc_row["id"],
                    source_ip=inc_row["source_ip"],
                    source_mac=inc_row["source_mac"],
                    status=inc_row["status"],
                    severity=inc_row["severity"],
                    alert_count=inc_row["alert_count"],
                    first_alert_at=inc_row["first_alert_at"],
                    last_alert_at=inc_row["last_alert_at"],
                    closed_at=inc_row["closed_at"],
                    summary=inc_row["summary"],
                    alerts=child_alerts,
                )
            )

    return ExportResponse(
        alerts=alerts,
        incidents=incidents,
        exported_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert(
    alert_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get a single alert by ID."""
    cursor = await db.execute("SELECT * FROM home_alerts WHERE id = ?", (alert_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return _parse_alert_row(row)


@router.put("/alerts/{alert_id}/read", response_model=AlertReadResponse)
async def mark_alert_read(
    alert_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Mark a single alert as read."""
    cursor = await db.execute("SELECT id, read_at FROM home_alerts WHERE id = ?", (alert_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    now = datetime.now(timezone.utc).isoformat()
    if row["read_at"] is None:
        await db.execute(
            "UPDATE home_alerts SET read_at = ? WHERE id = ?", (now, alert_id)
        )
        await db.commit()
    else:
        now = row["read_at"]

    return AlertReadResponse(id=alert_id, read_at=now)


@router.put("/alerts/{alert_id}/action", response_model=AlertDetail)
async def mark_alert_actioned(
    alert_id: int,
    body: ActionRequest,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Mark an alert as actioned with an optional note."""
    cursor = await db.execute("SELECT * FROM home_alerts WHERE id = ?", (alert_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        "UPDATE home_alerts SET actioned_at = ?, action_note = ? WHERE id = ?",
        (now, body.note, alert_id),
    )
    await db.commit()

    # Re-fetch and return
    cursor = await db.execute("SELECT * FROM home_alerts WHERE id = ?", (alert_id,))
    row = await cursor.fetchone()
    return _parse_alert_row(row)


# ---------- Incident routes ----------


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get an incident with all child alerts in chronological order."""
    cursor = await db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    inc_row = await cursor.fetchone()
    if not inc_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    cursor = await db.execute(
        "SELECT * FROM home_alerts WHERE incident_id = ? ORDER BY created_at ASC",
        (incident_id,),
    )
    alert_rows = await cursor.fetchall()
    alerts = [_parse_alert_row(row) for row in alert_rows]

    return IncidentDetail(
        id=inc_row["id"],
        source_ip=inc_row["source_ip"],
        source_mac=inc_row["source_mac"],
        status=inc_row["status"],
        severity=inc_row["severity"],
        alert_count=inc_row["alert_count"],
        first_alert_at=inc_row["first_alert_at"],
        last_alert_at=inc_row["last_alert_at"],
        closed_at=inc_row["closed_at"],
        summary=inc_row["summary"],
        alerts=alerts,
    )


@router.put("/incidents/{incident_id}/read", response_model=IncidentReadResponse)
async def mark_incident_read(
    incident_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Mark an incident and all its child alerts as read."""
    cursor = await db.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    now = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        "UPDATE home_alerts SET read_at = ? WHERE incident_id = ? AND read_at IS NULL",
        (now, incident_id),
    )
    alerts_marked = cursor.rowcount
    await db.commit()

    return IncidentReadResponse(id=incident_id, read_at=now, alerts_marked=alerts_marked)
