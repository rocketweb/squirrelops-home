"""Port routes: network-wide port view and on-demand service probing."""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from squirrelops_home_sensor.api.deps import get_db, get_privileged_ops, verify_client_cert
from squirrelops_home_sensor.scanner.service_names import get_service_name

router = APIRouter(prefix="/ports", tags=["ports"])


# ---------- Response models ----------


class NetworkPortDevice(BaseModel):
    device_id: int
    ip_address: str
    hostname: Optional[str] = None
    custom_name: Optional[str] = None
    device_type: str
    banner: Optional[str] = None


class NetworkPortEntry(BaseModel):
    port: int
    protocol: str
    service_name: Optional[str] = None
    device_count: int
    devices: list[NetworkPortDevice]


class NetworkPortsResponse(BaseModel):
    items: list[NetworkPortEntry]
    total_ports: int
    total_devices: int


class ProbeRequest(BaseModel):
    ip_address: str
    ports: list[int]


class ProbeResult(BaseModel):
    ip: str
    port: int
    service_name: Optional[str] = None
    banner: Optional[str] = None


# ---------- Routes ----------


@router.get("/network", response_model=NetworkPortsResponse)
async def get_network_ports(
    db: aiosqlite.Connection = Depends(get_db),
    _auth: dict = Depends(verify_client_cert),
):
    """Get all open ports across all devices, grouped by port number."""
    cursor = await db.execute(
        """SELECT p.port, p.protocol, p.service_name, p.banner,
                  d.id as device_id, d.ip_address, d.hostname,
                  d.custom_name, d.device_type
           FROM device_open_ports p
           JOIN devices d ON d.id = p.device_id
           ORDER BY p.port, d.ip_address"""
    )
    rows = await cursor.fetchall()

    # Group by port
    port_groups: dict[tuple[int, str], list] = defaultdict(list)
    port_service: dict[tuple[int, str], str | None] = {}
    device_ids: set[int] = set()

    for row in rows:
        key = (row["port"], row["protocol"])
        port_groups[key].append(row)
        device_ids.add(row["device_id"])
        # Prefer DB-stored service name, fall back to IANA lookup
        if key not in port_service or port_service[key] is None:
            port_service[key] = row["service_name"] or get_service_name(row["port"])

    items = []
    for (port, protocol), group_rows in sorted(port_groups.items()):
        devices = [
            NetworkPortDevice(
                device_id=r["device_id"],
                ip_address=r["ip_address"],
                hostname=r["hostname"],
                custom_name=r["custom_name"],
                device_type=r["device_type"],
                banner=r["banner"],
            )
            for r in group_rows
        ]
        items.append(NetworkPortEntry(
            port=port,
            protocol=protocol,
            service_name=port_service.get((port, protocol)),
            device_count=len(devices),
            devices=devices,
        ))

    return NetworkPortsResponse(
        items=items,
        total_ports=len(items),
        total_devices=len(device_ids),
    )


@router.post("/probe", response_model=list[ProbeResult])
async def probe_ports(
    body: ProbeRequest,
    db: aiosqlite.Connection = Depends(get_db),
    priv_ops=Depends(get_privileged_ops),
    _auth: dict = Depends(verify_client_cert),
):
    """Probe specific ports on a device for service detection.

    Uses the privileged operations layer (nmap -sV on Linux, Swift helper
    on macOS) for deep service/version detection. Results are persisted
    back to device_open_ports for caching.
    """
    if not body.ports:
        return []

    if len(body.ports) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 ports per probe request",
        )

    results = await priv_ops.service_scan(
        targets=[body.ip_address],
        ports=body.ports,
    )

    probe_results = []
    for sr in results:
        svc_name = get_service_name(sr.port)
        probe_results.append(ProbeResult(
            ip=sr.ip,
            port=sr.port,
            service_name=svc_name,
            banner=sr.banner,
        ))

        # Persist results back to device_open_ports
        await db.execute(
            """UPDATE device_open_ports
               SET service_name = COALESCE(?, device_open_ports.service_name),
                   banner = COALESCE(?, device_open_ports.banner)
               WHERE port = ? AND device_id IN (
                   SELECT id FROM devices WHERE ip_address = ?
               )""",
            (svc_name, sr.banner, sr.port, sr.ip),
        )

    await db.commit()
    return probe_results
