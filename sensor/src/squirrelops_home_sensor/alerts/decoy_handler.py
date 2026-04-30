"""Decoy alert handler -- converts decoy events into alerts.

Subscribes to ``decoy.trip`` and ``decoy.credential_trip`` events on the
event bus. For each event it:

1. Inserts a ``home_alerts`` row.
2. Groups the alert into an incident via ``IncidentGrouper``.
3. Publishes ``alert.new`` so the ``AlertDispatcher`` can deliver
   notifications (Slack, APNS, log).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, Protocol

import aiosqlite

from squirrelops_home_sensor.alerts.types import (
    AlertType,
    severity_for_alert_type,
)

logger = logging.getLogger(__name__)


# -- Protocols for dependency injection ------------------------------------

class EventBusProtocol(Protocol):
    async def publish(self, event_type: str, payload: dict[str, Any], source_id: str | None = None) -> int: ...
    def subscribe(self, event_types: list[str], callback: Any) -> Any: ...


class IncidentGrouperProtocol(Protocol):
    async def process_alert(self, alert_id: int) -> None: ...


# -- Handler ---------------------------------------------------------------

class DecoyAlertHandler:
    """Converts decoy trip events into persisted alerts.

    Parameters
    ----------
    db:
        Open aiosqlite connection.
    event_bus:
        The sensor event bus for subscribing and publishing.
    incident_grouper:
        Groups alerts by source IP into incidents.  May be ``None`` to
        skip incident grouping.
    """

    def __init__(
        self,
        *,
        db: aiosqlite.Connection,
        event_bus: EventBusProtocol,
        incident_grouper: IncidentGrouperProtocol | None = None,
    ) -> None:
        self._db = db
        self._event_bus = event_bus
        self._incident_grouper = incident_grouper

    def subscribe_to(self, event_bus: EventBusProtocol) -> None:
        """Subscribe to decoy events on the given event bus."""
        event_bus.subscribe(
            ["decoy.trip", "decoy.credential_trip"],
            self._on_decoy_event,
        )

    async def _on_decoy_event(self, event: dict[str, Any]) -> None:
        """Event bus callback for decoy trip events."""
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        try:
            if event_type == "decoy.credential_trip":
                alert_id = await self._create_alert(
                    AlertType.DECOY_CREDENTIAL_TRIP, payload
                )
            elif event_type == "decoy.trip":
                alert_id = await self._create_alert(
                    AlertType.DECOY_TRIP, payload
                )
            else:
                return

            if self._incident_grouper is not None:
                await self._incident_grouper.process_alert(alert_id)

        except Exception:
            logger.exception("Failed to create alert for %s event", event_type)

    async def _lookup_device(self, source_ip: str) -> dict[str, Any] | None:
        """Look up a device record by IP address. Returns dict or None."""
        async with self._db.execute(
            "SELECT id, mac_address, hostname, vendor FROM devices WHERE ip_address = ?",
            (source_ip,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return {
            "device_id": row["id"],
            "mac_address": row["mac_address"],
            "hostname": row["hostname"],
            "vendor": row["vendor"],
        }

    async def _create_alert(
        self,
        alert_type: AlertType,
        payload: dict[str, Any],
    ) -> int:
        """Insert a home_alerts row and publish alert.new."""
        severity = severity_for_alert_type(alert_type)
        source_ip = payload.get("source_ip", "unknown")
        dest_port = payload.get("dest_port", "?")
        decoy_id = payload.get("decoy_id")
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Look up device to enrich with MAC, hostname, vendor
        device = await self._lookup_device(source_ip)
        source_mac = device["mac_address"] if device else None
        device_id = device["device_id"] if device else None

        if alert_type == AlertType.DECOY_CREDENTIAL_TRIP:
            title = f"Credential stolen from {source_ip} on port {dest_port}"
        else:
            title = f"Decoy connection from {source_ip} on port {dest_port}"

        detail_obj: dict[str, Any] = {
            "dest_port": dest_port,
            "protocol": payload.get("protocol", "tcp"),
        }
        if payload.get("request_path"):
            detail_obj["request_path"] = payload["request_path"]
        if payload.get("credential_used"):
            detail_obj["credential_used"] = payload["credential_used"]
        if payload.get("detection_method"):
            detail_obj["detection_method"] = payload["detection_method"]
        if payload.get("decoy_name"):
            detail_obj["decoy_name"] = payload["decoy_name"]
        # Add device info to detail JSON so the app can display it
        if device:
            if device["hostname"]:
                detail_obj["hostname"] = device["hostname"]
            if device["vendor"]:
                detail_obj["vendor"] = device["vendor"]

        detail_json = json.dumps(detail_obj)

        cursor = await self._db.execute(
            """INSERT INTO home_alerts
               (alert_type, severity, title, detail, source_ip, source_mac,
                device_id, decoy_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_type.value,
                severity.value,
                title,
                detail_json,
                source_ip,
                source_mac,
                device_id,
                decoy_id,
                now,
            ),
        )
        alert_id = cursor.lastrowid
        await self._db.commit()

        await self._event_bus.publish(
            "alert.new",
            {
                "id": alert_id,
                "alert_type": alert_type.value,
                "severity": severity.value,
                "title": title,
                "source_ip": source_ip,
                "source_mac": source_mac,
                "created_at": now,
                "incident_id": None,
                "read_at": None,
                "actioned_at": None,
                "alert_count": None,
            },
            source_id=source_ip,
        )

        logger.info(
            "Created %s alert (id=%d) for %s on port %s",
            severity.value, alert_id, source_ip, dest_port,
        )
        return alert_id
