"""Decoy alert handler -- converts decoy events into alerts.

Subscribes to ``decoy.trip`` and ``decoy.credential_trip`` events on the
event bus. For actionable events it:

1. Inserts a ``home_alerts`` row.
2. Groups the alert into an incident via ``IncidentGrouper``.
3. Publishes ``alert.new`` so the ``AlertDispatcher`` can deliver
   notifications (Slack, APNS, log).

Every connection is still written to ``decoy_connections`` and reflected in
the service counter. Protocol-defined automatic discovery traffic is kept as
forensic evidence without being promoted to an intrusion alert.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any, Protocol

import aiosqlite

from squirrelops_home_sensor.alerts.types import (
    AlertType,
    severity_for_alert_type,
)
from squirrelops_home_sensor.db.queries import (
    get_credential_by_value,
    increment_decoy_connection_count,
    increment_decoy_credential_trip_count,
    insert_decoy_connection,
    mark_credential_tripped,
)

logger = logging.getLogger(__name__)

_IPP_DISCOVERY_PATHS = frozenset({"/ipp/print"})


# -- Protocols for dependency injection ------------------------------------

class EventBusProtocol(Protocol):
    async def publish(self, event_type: str, payload: dict[str, Any], source_id: str | None = None) -> int: ...
    def subscribe(self, event_types: list[str], callback: Any) -> Any: ...


class IncidentGrouperProtocol(Protocol):
    async def process_alert(
        self,
        alert_id: int,
        *,
        source_event_seq: int,
    ) -> None: ...


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
        # EventBus schedules subscriber callbacks independently. Serialize the
        # read-modify-write alert path so a fast port scan cannot race several
        # "first" alerts into the database.
        self._event_lock = asyncio.Lock()

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
        if not isinstance(payload, dict):
            logger.error("Ignored %s callback with an invalid payload", event_type)
            return
        source_event_seq = event.get("seq")
        if (
            not isinstance(source_event_seq, int)
            or isinstance(source_event_seq, bool)
            or source_event_seq <= 0
        ):
            logger.error(
                "Ignored %s callback without a valid source event sequence",
                event_type,
            )
            return

        async with self._event_lock:
            try:
                is_new_alert = False
                if event_type == "decoy.credential_trip":
                    alert_id = await self._create_alert(
                        AlertType.DECOY_CREDENTIAL_TRIP,
                        payload,
                        source_event_seq=source_event_seq,
                    )
                    is_new_alert = alert_id is not None
                elif event_type == "decoy.trip":
                    if self._is_discovery_probe(payload):
                        alert_id = None
                        logger.debug(
                            "Recorded automatic service discovery from %s "
                            "on port %s without raising an alert",
                            payload.get("source_ip", "unknown"),
                            payload.get("dest_port", "?"),
                        )
                    elif payload.get("credential_used"):
                        # The matching credential event is critical and carries
                        # the same connection. Avoid a redundant high alert.
                        alert_id = None
                        logger.debug(
                            "Deferred credential-bearing decoy trip to its "
                            "critical credential alert"
                        )
                    else:
                        alert_id, is_new_alert = (
                            await self._create_or_update_trip_alert(
                                payload,
                                source_event_seq=source_event_seq,
                            )
                        )
                else:
                    return

                if (
                    alert_id is None
                    and not self._is_discovery_probe(payload)
                    and not payload.get("credential_used")
                ):
                    logger.info(
                        "Ignored pre-clear %s event at sequence %d",
                        event_type,
                        source_event_seq,
                    )
                elif (
                    alert_id is not None
                    and is_new_alert
                    and self._incident_grouper is not None
                ):
                    await self._incident_grouper.process_alert(
                        alert_id,
                        source_event_seq=source_event_seq,
                    )

            except Exception:
                logger.exception("Failed to create alert for %s event", event_type)

            # Persist the forensic connection record and counters independently,
            # so an alert failure cannot discard the underlying evidence.
            try:
                await self._persist_event(event_type, payload)
            except Exception:
                logger.exception("Failed to persist decoy %s record", event_type)

    @staticmethod
    def _is_discovery_probe(payload: dict[str, Any]) -> bool:
        """Recognize protocol-defined client discovery that we solicited.

        A printer-profile mimic advertises ``rp=ipp/print`` over Bonjour.
        Normal print clients then POST Get-Printer-Attributes to that exact
        resource without user interaction. It is useful forensic activity, but
        not evidence of an intrusion. A connect-only scan, a request to another
        path, or any credential use remains actionable.
        """
        if payload.get("credential_used"):
            return False
        raw_port = payload.get("dest_port")
        if isinstance(raw_port, bool) or not isinstance(raw_port, (int, str)):
            return False
        try:
            port = int(raw_port)
        except ValueError:
            return False
        if port != 631:
            return False

        raw_path = payload.get("request_path")
        if not isinstance(raw_path, str):
            return False
        path = raw_path.partition("?")[0].rstrip("/") or "/"
        return path.casefold() in _IPP_DISCOVERY_PATHS

    async def _create_or_update_trip_alert(
        self,
        payload: dict[str, Any],
        *,
        source_event_seq: int,
    ) -> tuple[int | None, bool]:
        """Create one unread alert per source and fold its scan burst into it.

        ``decoy_connections`` remains the one-row-per-connection forensic log.
        ``home_alerts`` is the human attention surface, so repeated hits from
        one source update the same unread alert instead of producing hundreds
        of indistinguishable high-severity rows.
        """
        source_ip = str(payload.get("source_ip") or "unknown")
        cursor = await self._db.execute(
            """SELECT alert.*, incident.status AS incident_status
               FROM home_alerts alert
               LEFT JOIN incidents incident ON incident.id = alert.incident_id
               WHERE alert.alert_type = ?
                 AND alert.source_ip = ?
                 AND alert.read_at IS NULL
                 AND alert.actioned_at IS NULL
                 AND (
                     alert.incident_id IS NULL
                     OR incident.status = 'active'
                 )
               ORDER BY alert.id DESC
               LIMIT 1""",
            (AlertType.DECOY_TRIP.value, source_ip),
        )
        existing = await cursor.fetchone()
        if existing is None:
            alert_id = await self._create_alert(
                AlertType.DECOY_TRIP,
                payload,
                source_event_seq=source_event_seq,
            )
            return alert_id, alert_id is not None

        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        detail = self._merged_trip_detail(existing, payload, observed_at=now)
        endpoint_count = len(detail["endpoints"])
        title = (
            f"Port scan detected from {source_ip}"
            if endpoint_count >= 2
            else str(existing["title"])
        )
        detail_json = json.dumps(detail)

        update_cursor = await self._db.execute(
            """UPDATE home_alerts
               SET title = ?, detail = ?
               WHERE id = ?
                 AND read_at IS NULL
                 AND actioned_at IS NULL
                 AND NOT EXISTS (
                     SELECT 1
                     FROM events
                     WHERE event_type = 'alerts.history_cleared'
                       AND seq >= ?
                 )""",
            (
                title,
                detail_json,
                int(existing["id"]),
                source_event_seq,
            ),
        )
        if update_cursor.rowcount != 1:
            await self._db.commit()
            alert_id = await self._create_alert(
                AlertType.DECOY_TRIP,
                payload,
                source_event_seq=source_event_seq,
            )
            return alert_id, alert_id is not None

        incident_id = existing["incident_id"]
        if incident_id is not None:
            await self._db.execute(
                """UPDATE incidents
                   SET last_alert_at = ?,
                       summary = ?
                   WHERE id = ? AND status = 'active'""",
                (
                    now,
                    self._scan_summary(
                        source_ip=source_ip,
                        connection_count=int(detail["connection_count"]),
                        endpoint_count=endpoint_count,
                    ),
                    int(incident_id),
                ),
            )
        await self._db.commit()

        await self._event_bus.publish(
            "alert.updated",
            {
                "id": int(existing["id"]),
                "alert_type": AlertType.DECOY_TRIP.value,
                "severity": existing["severity"],
                "title": title,
                "source_ip": source_ip,
                "source_mac": existing["source_mac"],
                "created_at": existing["created_at"],
                "incident_id": incident_id,
                "read_at": None,
                "actioned_at": None,
                # Keep this stable. The app uses visible summary fields as the
                # modal revision; forensic connection_count lives in detail.
                "alert_count": None,
                "source_event_seq": source_event_seq,
            },
            source_id=source_ip,
        )
        logger.info(
            "Updated decoy activity alert %d for %s (%d connections, "
            "%d endpoints)",
            int(existing["id"]),
            source_ip,
            int(detail["connection_count"]),
            endpoint_count,
        )
        return int(existing["id"]), False

    @staticmethod
    def _merged_trip_detail(
        existing: aiosqlite.Row,
        payload: dict[str, Any],
        *,
        observed_at: str,
    ) -> dict[str, Any]:
        try:
            decoded = json.loads(existing["detail"])
        except (json.JSONDecodeError, TypeError, ValueError):
            decoded = {}
        detail = decoded if isinstance(decoded, dict) else {}

        ports: set[int] = set()
        raw_ports = detail.get("ports", [])
        if isinstance(raw_ports, list):
            for raw_port in raw_ports:
                port = DecoyAlertHandler._coerce_int(raw_port)
                if port is not None:
                    ports.add(port)
        for raw_port in (detail.get("dest_port"), payload.get("dest_port")):
            port = DecoyAlertHandler._coerce_int(raw_port)
            if port is not None:
                ports.add(port)

        decoy_ids: set[int] = set()
        raw_decoy_ids = detail.get("decoy_ids", [])
        if isinstance(raw_decoy_ids, list):
            for raw_decoy_id in raw_decoy_ids:
                decoy_id = DecoyAlertHandler._coerce_int(raw_decoy_id)
                if decoy_id is not None:
                    decoy_ids.add(decoy_id)
        for raw_decoy_id in (existing["decoy_id"], payload.get("decoy_id")):
            decoy_id = DecoyAlertHandler._coerce_int(raw_decoy_id)
            if decoy_id is not None:
                decoy_ids.add(decoy_id)

        endpoints: set[str] = set()
        raw_endpoints = detail.get("endpoints", [])
        if isinstance(raw_endpoints, list):
            endpoints.update(
                endpoint
                for endpoint in raw_endpoints
                if isinstance(endpoint, str)
            )
        existing_port = detail.get("dest_port")
        if existing_port is not None:
            endpoints.add(
                f"{existing['decoy_id'] or 'unknown'}:{existing_port}"
            )
        raw_port = payload.get("dest_port")
        raw_decoy_id = payload.get("decoy_id")
        if raw_port is not None:
            endpoints.add(f"{raw_decoy_id or 'unknown'}:{raw_port}")
        if not endpoints:
            endpoints.update(f"unknown:{port}" for port in ports)

        raw_connection_count = detail.get("connection_count", 1)
        try:
            connection_count = max(1, int(raw_connection_count)) + 1
        except (TypeError, ValueError):
            connection_count = 2

        detail.update(
            {
                "dest_port": payload.get("dest_port", detail.get("dest_port")),
                "protocol": payload.get(
                    "protocol",
                    detail.get("protocol", "tcp"),
                ),
                "ports": sorted(ports),
                "decoy_ids": sorted(decoy_ids),
                "endpoints": sorted(endpoints),
                "connection_count": connection_count,
                "first_seen": detail.get("first_seen") or existing["created_at"],
                "last_seen": observed_at,
            }
        )
        if len(endpoints) >= 2:
            detail["detection_method"] = "decoy_port_scan"
        if payload.get("request_path"):
            detail["latest_request_path"] = payload["request_path"]
        if payload.get("decoy_name"):
            detail["latest_decoy_name"] = payload["decoy_name"]
        return detail

    @staticmethod
    def _coerce_int(value: object) -> int | None:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _scan_summary(
        *,
        source_ip: str,
        connection_count: int,
        endpoint_count: int,
    ) -> str:
        if endpoint_count >= 2:
            return (
                f"Port scan from {source_ip}: {connection_count} connections "
                f"across {endpoint_count} decoy services"
            )
        return f"{connection_count} decoy connections from {source_ip}"

    async def _persist_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Record decoy hits in decoy_connections and update trip counters.

        A ``decoy.trip`` records one connection row and increments the decoy's
        connection_count. A ``decoy.credential_trip`` increments the credential
        trip count and marks the matching planted credential as tripped. For
        HTTP decoys both events fire for a single connection; only ``decoy.trip``
        writes the connection row so there is no duplicate.
        """
        decoy_id = payload.get("decoy_id")
        credential_used = payload.get("credential_used")
        timestamp = payload.get("timestamp") or datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )

        if event_type == "decoy.trip":
            if decoy_id is None:
                return
            source_ip = payload.get("source_ip", "unknown")
            device = await self._lookup_device(source_ip)
            source_mac = device["mac_address"] if device else None
            credential_id = None
            if credential_used:
                cred = await get_credential_by_value(self._db, credential_used)
                if cred:
                    credential_id = cred["id"]
            await insert_decoy_connection(
                self._db,
                decoy_id=decoy_id,
                source_ip=source_ip,
                port=int(payload.get("dest_port") or 0),
                timestamp=timestamp,
                source_mac=source_mac,
                protocol=payload.get("protocol"),
                request_path=payload.get("request_path"),
                credential_used=credential_used,
                credential_id=credential_id,
            )
            await increment_decoy_connection_count(self._db, decoy_id)
            await self._publish_count_changed(decoy_id)

        elif event_type == "decoy.credential_trip":
            if decoy_id is not None:
                await increment_decoy_credential_trip_count(self._db, decoy_id)
                await self._publish_count_changed(decoy_id)
            if credential_used:
                cred = await get_credential_by_value(self._db, credential_used)
                if cred:
                    await mark_credential_tripped(
                        self._db, cred["id"], tripped_at=timestamp
                    )

    async def _publish_count_changed(self, decoy_id: int) -> None:
        """Publish authoritative per-service counters after persistence."""
        updated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        await self._db.execute(
            "UPDATE decoys SET updated_at = ? WHERE id = ?",
            (updated_at, decoy_id),
        )
        await self._db.commit()
        cursor = await self._db.execute(
            """SELECT id, host_id, bind_address, port,
                      connection_count, credential_trip_count
               FROM decoys
               WHERE id = ?""",
            (decoy_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return
        await self._event_bus.publish(
            "decoy.connection_count_changed",
            {
                "id": int(row["id"]),
                "decoy_id": int(row["id"]),
                "host_id": row["host_id"],
                "bind_address": row["bind_address"],
                "port": int(row["port"]),
                "connection_count": int(row["connection_count"]),
                "credential_trip_count": int(row["credential_trip_count"]),
                "updated_at": updated_at,
            },
        )

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
        *,
        source_event_seq: int,
    ) -> int | None:
        """Insert an alert unless its source event predates a history clear."""
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
               SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
               WHERE NOT EXISTS (
                   SELECT 1
                   FROM events
                   WHERE event_type = 'alerts.history_cleared'
                     AND seq >= ?
               )""",
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
                source_event_seq,
            ),
        )
        await self._db.commit()
        if cursor.rowcount != 1:
            return None

        alert_id = cursor.lastrowid
        if alert_id is None:
            raise RuntimeError("Alert insert did not return an ID")

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
                "source_event_seq": source_event_seq,
            },
            source_id=source_ip,
        )

        logger.info(
            "Created %s alert (id=%d) for %s on port %s",
            severity.value, alert_id, source_ip, dest_port,
        )
        return alert_id
