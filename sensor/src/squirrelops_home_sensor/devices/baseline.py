"""Connection baseline collection and anomaly detection."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from squirrelops_home_sensor.alerts.types import AlertType, severity_for_alert_type
from squirrelops_home_sensor.db.queries import (
    get_device_baseline,
    has_baseline,
    insert_alert,
    insert_incident,
    upsert_baseline_connection,
)

logger = logging.getLogger(__name__)


class BaselineCollector:
    """Records device connection destinations during learning mode."""

    def __init__(self, *, db: aiosqlite.Connection) -> None:
        self._db = db

    async def record_connections(
        self,
        device_id: int,
        destinations: list[tuple[str, int]],
    ) -> int:
        """Record observed connection destinations for a device. Returns count."""
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for dest_ip, dest_port in destinations:
            await upsert_baseline_connection(
                self._db,
                device_id=device_id,
                dest_ip=dest_ip,
                dest_port=dest_port,
                seen_at=now,
            )
            count += 1
        return count


class AnomalyDetector:
    """Detects new connection destinations not seen during learning."""

    def __init__(self, *, db: aiosqlite.Connection) -> None:
        self._db = db

    async def check_device(
        self,
        device_id: int,
        destinations: list[tuple[str, int]],
        source_ip: str = "",
        source_mac: str | None = None,
    ) -> list[dict[str, Any]]:
        """Check observed destinations against baseline. Returns anomaly list.
        Only checks devices that have a baseline (learned during learning mode).
        """
        if not await has_baseline(self._db, device_id):
            return []

        baseline = await get_device_baseline(self._db, device_id)
        anomalies: list[dict[str, Any]] = []

        for dest_ip, dest_port in destinations:
            if (dest_ip, dest_port) not in baseline:
                now = datetime.now(timezone.utc).isoformat()
                severity = severity_for_alert_type(AlertType.BEHAVIORAL_ANOMALY)

                incident_id = await insert_incident(
                    self._db,
                    source_ip=source_ip,
                    severity=severity.value,
                    first_alert_at=now,
                    last_alert_at=now,
                    source_mac=source_mac,
                    summary=f"New destination {dest_ip}:{dest_port}",
                )

                alert_id = await insert_alert(
                    self._db,
                    alert_type=AlertType.BEHAVIORAL_ANOMALY.value,
                    severity=severity.value,
                    title=f"New connection destination: {dest_ip}:{dest_port}",
                    detail=f"Device contacted {dest_ip}:{dest_port} which was not observed during the learning period.",
                    created_at=now,
                    incident_id=incident_id,
                    source_ip=source_ip,
                    source_mac=source_mac,
                    device_id=device_id,
                )

                anomalies.append({
                    "alert_id": alert_id,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "device_id": device_id,
                })
                logger.info(
                    "Anomaly detected: device %d -> %s:%d (not in baseline)",
                    device_id, dest_ip, dest_port,
                )

        return anomalies
