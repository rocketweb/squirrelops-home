"""Device routes: list, get, update, trust actions, fingerprint history."""
from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, verify_client_cert
from squirrelops_home_sensor.devices.decoy_filter import DECOY_DEVICE_FILTER

router = APIRouter(prefix="/devices", tags=["devices"])


# ---------- Request/Response models ----------


class DeviceSummary(BaseModel):
    id: int
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str
    model_name: str | None = None
    area: str | None = None
    custom_name: str | None = None
    trust_status: str
    is_online: bool
    first_seen: str
    last_seen: str


class PaginatedDevices(BaseModel):
    items: list[DeviceSummary]
    total: int
    limit: int
    offset: int


class FingerprintEntry(BaseModel):
    id: int
    mac_address: str | None = None
    mdns_hostname: str | None = None
    dhcp_fingerprint_hash: str | None = None
    connection_pattern_hash: str | None = None
    open_ports_hash: str | None = None
    composite_hash: str | None = None
    signal_count: int
    confidence: float | None = None
    first_seen: str
    last_seen: str


class DeviceDetail(BaseModel):
    id: int
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str
    model_name: str | None = None
    area: str | None = None
    custom_name: str | None = None
    notes: str | None = None
    trust_status: str
    trust_updated_at: str | None = None
    is_online: bool
    first_seen: str
    last_seen: str
    latest_fingerprint: FingerprintEntry | None = None


class DeviceUpdateRequest(BaseModel):
    custom_name: str | None = None
    notes: str | None = None
    device_type: str | None = None


class TrustActionResponse(BaseModel):
    id: int
    trust_status: str
    trust_updated_at: str
    verification_requested: bool = False


class PaginatedFingerprints(BaseModel):
    items: list[FingerprintEntry]


# ---------- Helpers ----------


async def _get_device_or_404(db: aiosqlite.Connection, device_id: int) -> aiosqlite.Row:
    cursor = await db.execute(
        f"SELECT * FROM devices d WHERE d.id = ? AND {DECOY_DEVICE_FILTER}",
        (device_id,),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return row


async def _get_trust(db: aiosqlite.Connection, device_id: int) -> tuple[str, str | None]:
    cursor = await db.execute(
        "SELECT status, updated_at FROM device_trust WHERE device_id = ?", (device_id,)
    )
    row = await cursor.fetchone()
    if row:
        return row["status"], row["updated_at"]
    return "unknown", None


async def _get_latest_fingerprint(
    db: aiosqlite.Connection, device_id: int
) -> FingerprintEntry | None:
    cursor = await db.execute(
        """SELECT * FROM device_fingerprints
           WHERE device_id = ?
           ORDER BY last_seen DESC LIMIT 1""",
        (device_id,),
    )
    row = await cursor.fetchone()
    if not row:
        return None
    return FingerprintEntry(
        id=row["id"],
        mac_address=row["mac_address"],
        mdns_hostname=row["mdns_hostname"],
        dhcp_fingerprint_hash=row["dhcp_fingerprint_hash"],
        connection_pattern_hash=row["connection_pattern_hash"],
        open_ports_hash=row["open_ports_hash"],
        composite_hash=row["composite_hash"],
        signal_count=row["signal_count"],
        confidence=row["confidence"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )


# ---------- Routes ----------


@router.get("", response_model=PaginatedDevices)
async def list_devices(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    trust_status: str | None = Query(None),
    category: str | None = Query(None),
    online: bool | None = Query(None),
    search: str | None = Query(None),
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """List devices with pagination, filters, and search."""
    where_clauses = [DECOY_DEVICE_FILTER]
    params: list = []

    if trust_status:
        where_clauses.append("dt.status = ?")
        params.append(trust_status)

    if category:
        where_clauses.append("d.device_type = ?")
        params.append(category)

    if online is not None:
        where_clauses.append("d.is_online = ?")
        params.append(1 if online else 0)

    if search:
        where_clauses.append(
            "(d.hostname LIKE ? OR d.ip_address LIKE ? OR d.mac_address LIKE ? "
            "OR d.custom_name LIKE ?)"
        )
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern, pattern])

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # Count total
    count_sql = f"""
        SELECT COUNT(*) FROM devices d
        LEFT JOIN device_trust dt ON dt.device_id = d.id
        {where_sql}
    """
    cursor = await db.execute(count_sql, params)
    total = (await cursor.fetchone())[0]

    # Fetch page
    query_sql = f"""
        SELECT d.*, dt.status as trust_status FROM devices d
        LEFT JOIN device_trust dt ON dt.device_id = d.id
        {where_sql}
        ORDER BY d.last_seen DESC
        LIMIT ? OFFSET ?
    """
    cursor = await db.execute(query_sql, params + [limit, offset])
    rows = await cursor.fetchall()

    items = [
        DeviceSummary(
            id=row["id"],
            ip_address=row["ip_address"],
            mac_address=row["mac_address"],
            hostname=row["hostname"],
            vendor=row["vendor"],
            device_type=row["device_type"],
            model_name=row["model_name"] if "model_name" in row.keys() else None,
            area=row["area"] if "area" in row.keys() else None,
            custom_name=row["custom_name"] if "custom_name" in row.keys() else None,
            trust_status=row["trust_status"] or "unknown",
            is_online=bool(row["is_online"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
        for row in rows
    ]

    return PaginatedDevices(items=items, total=total, limit=limit, offset=offset)


@router.get("/{device_id}", response_model=DeviceDetail)
async def get_device(
    device_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get device detail with latest fingerprint and trust status."""
    device = await _get_device_or_404(db, device_id)
    trust_status, trust_updated_at = await _get_trust(db, device_id)
    latest_fp = await _get_latest_fingerprint(db, device_id)

    return DeviceDetail(
        id=device["id"],
        ip_address=device["ip_address"],
        mac_address=device["mac_address"],
        hostname=device["hostname"],
        vendor=device["vendor"],
        device_type=device["device_type"],
        model_name=device["model_name"] if "model_name" in device.keys() else None,
        area=device["area"] if "area" in device.keys() else None,
        custom_name=device["custom_name"] if "custom_name" in device.keys() else None,
        notes=device["notes"] if "notes" in device.keys() else None,
        trust_status=trust_status,
        trust_updated_at=trust_updated_at,
        is_online=bool(device["is_online"]),
        first_seen=device["first_seen"],
        last_seen=device["last_seen"],
        latest_fingerprint=latest_fp,
    )


@router.put("/{device_id}", response_model=DeviceDetail)
async def update_device(
    device_id: int,
    body: DeviceUpdateRequest,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Update device custom name and/or notes."""
    await _get_device_or_404(db, device_id)

    updates = []
    params = []
    if body.custom_name is not None:
        updates.append("custom_name = ?")
        params.append(body.custom_name)
    if body.notes is not None:
        updates.append("notes = ?")
        params.append(body.notes)
    if body.device_type is not None:
        updates.append("device_type = ?")
        params.append(body.device_type)

    if updates:
        params.append(device_id)
        await db.execute(
            f"UPDATE devices SET {', '.join(updates)} WHERE id = ?", params
        )
        await db.commit()

    return await get_device(device_id, db=db, _auth=None)


@router.post("/{device_id}/approve", response_model=TrustActionResponse)
async def approve_device(
    device_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Approve a device as trusted."""
    return await _set_trust(db, device_id, "approved")


@router.post("/{device_id}/reject", response_model=TrustActionResponse)
async def reject_device(
    device_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Reject a device as untrusted."""
    return await _set_trust(db, device_id, "rejected")


@router.post("/{device_id}/ignore", response_model=TrustActionResponse)
async def ignore_device(
    device_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Reset device trust to unknown (ignore)."""
    return await _set_trust(db, device_id, "unknown")


@router.post("/{device_id}/verify", response_model=TrustActionResponse)
async def verify_device(
    device_id: int,
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Request re-verification of device identity."""
    await _get_device_or_404(db, device_id)
    trust_status, _ = await _get_trust(db, device_id)
    now = datetime.now(UTC).isoformat()

    # Update the timestamp to signal re-verification was requested
    await db.execute(
        "UPDATE device_trust SET updated_at = ? WHERE device_id = ?",
        (now, device_id),
    )
    await db.commit()

    return TrustActionResponse(
        id=device_id,
        trust_status=trust_status,
        trust_updated_at=now,
        verification_requested=True,
    )


async def _set_trust(
    db: aiosqlite.Connection, device_id: int, new_status: str
) -> TrustActionResponse:
    await _get_device_or_404(db, device_id)
    now = datetime.now(UTC).isoformat()
    await db.execute(
        """INSERT INTO device_trust (device_id, status, approved_by, updated_at)
           VALUES (?, ?, 'user', ?)
           ON CONFLICT(device_id) DO UPDATE SET status = ?, approved_by = 'user', updated_at = ?""",
        (device_id, new_status, now, new_status, now),
    )
    await db.commit()
    return TrustActionResponse(
        id=device_id,
        trust_status=new_status,
        trust_updated_at=now,
    )


@router.get("/{device_id}/fingerprints", response_model=PaginatedFingerprints)
async def get_fingerprint_history(
    device_id: int,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get fingerprint history for a device, ordered by last_seen descending."""
    await _get_device_or_404(db, device_id)

    cursor = await db.execute(
        """SELECT * FROM device_fingerprints
           WHERE device_id = ?
           ORDER BY last_seen DESC
           LIMIT ? OFFSET ?""",
        (device_id, limit, offset),
    )
    rows = await cursor.fetchall()

    items = [
        FingerprintEntry(
            id=row["id"],
            mac_address=row["mac_address"],
            mdns_hostname=row["mdns_hostname"],
            dhcp_fingerprint_hash=row["dhcp_fingerprint_hash"],
            connection_pattern_hash=row["connection_pattern_hash"],
            open_ports_hash=row["open_ports_hash"],
            composite_hash=row["composite_hash"],
            signal_count=row["signal_count"],
            confidence=row["confidence"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
        for row in rows
    ]

    return PaginatedFingerprints(items=items)


# ---------- Open ports ----------


class OpenPortEntry(BaseModel):
    port: int
    protocol: str
    service_name: str | None = None
    banner: str | None = None
    first_seen: str
    last_seen: str


class DeviceOpenPortsResponse(BaseModel):
    items: list[OpenPortEntry]


@router.get("/{device_id}/ports", response_model=DeviceOpenPortsResponse)
async def get_device_ports(
    device_id: int,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get open ports for a device."""
    await _get_device_or_404(db, device_id)
    cursor = await db.execute(
        "SELECT port, protocol, service_name, banner, first_seen, last_seen "
        "FROM device_open_ports WHERE device_id = ? ORDER BY port "
        "LIMIT ? OFFSET ?",
        (device_id, limit, offset),
    )
    rows = await cursor.fetchall()
    items = [
        OpenPortEntry(
            port=row["port"],
            protocol=row["protocol"],
            service_name=row["service_name"],
            banner=row["banner"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
        for row in rows
    ]
    return DeviceOpenPortsResponse(items=items)
