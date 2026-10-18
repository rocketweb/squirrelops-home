"""Turn device lifecycle events into alert rows.

Subscribes to ``device.new``, ``device.mac_changed``, and
``device.verification_needed``. The device manager has published these since
the inventory was written; nothing consumed them, so a rogue host joining the
LAN appeared in the device list and nowhere an operator would be told.

Trust is the gate. A device the operator or the fingerprint matcher has
already approved is not news when it appears or needs verification, so those
two events alert only for ``unknown`` or ``rejected`` trust. A MAC change is
different: an approved identity suddenly answering from a different hardware
address is the spoofing signal, so it alerts regardless of trust and
reactivates a dismissed alert on every further change.

One alert per device per kind, keyed through ``issue_key``, so a flapping
device cannot page repeatedly. Device alerts do not join incidents: an
incident is an attack session against decoys from one source, and a device
joining the network is not that.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from squirrelops_home_sensor.alerts.types import (
    AlertType,
    Severity,
    severity_for_alert_type,
)

logger = logging.getLogger(__name__)

_MAX_RECENT_CHANGES = 10
_ALERTING_TRUST = frozenset({"unknown", "rejected"})


class EventBusProtocol:
    async def publish(
        self, event_type: str, payload: dict[str, Any], source_id: str | None = None
    ) -> int: ...
    def subscribe(self, event_types: list[str], callback: Any) -> Any: ...


class DeviceAlertHandler:
    """Create and refresh alert rows for device lifecycle events."""

    def __init__(self, *, db: aiosqlite.Connection, event_bus: Any) -> None:
        self._db = db
        self._event_bus = event_bus
        self._event_lock = asyncio.Lock()

    def subscribe_to(self, event_bus: Any) -> None:
        event_bus.subscribe(
            ["device.new", "device.mac_changed", "device.verification_needed"],
            self._on_device_event,
        )

    # -- Event entry -----------------------------------------------------

    async def _on_device_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("event_type", "")
        payload = event.get("payload")
        seq = event.get("seq")
        if not isinstance(payload, dict):
            logger.error("Ignored %s with a non-object payload", event_type)
            return
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            logger.error("Ignored %s without a valid source event sequence", event_type)
            return
        async with self._event_lock:
            try:
                if event_type == "device.new":
                    await self._on_new_device(payload, seq)
                elif event_type == "device.verification_needed":
                    await self._on_verification_needed(payload, seq)
                elif event_type == "device.mac_changed":
                    await self._on_mac_changed(payload, seq)
            except Exception:
                logger.exception("Failed to create alert for %s event", event_type)

    # -- device.new / device.verification_needed -------------------------

    async def _on_new_device(self, payload: dict[str, Any], seq: int) -> None:
        device_id = _coerce_id(payload.get("id"))
        if device_id is None:
            logger.error("Ignored device.new without a device id")
            return
        if payload.get("trust_status") not in _ALERTING_TRUST:
            return
        issue_key = f"device:new:{device_id}"
        # A device is new once. If an alert ever existed for it, even a
        # dismissed one, there is nothing to say again.
        if await self._existing(issue_key) is not None:
            return
        await self._insert(
            AlertType.DEVICE_NEW,
            title=f"New device: {_display_name(payload)} ({payload.get('ip_address', '?')})",
            detail=_device_detail(payload),
            device_id=device_id,
            source_ip=_text(payload.get("ip_address")),
            source_mac=_text(payload.get("mac_address")),
            issue_key=issue_key,
            seq=seq,
        )

    async def _on_verification_needed(self, payload: dict[str, Any], seq: int) -> None:
        device_id = _coerce_id(payload.get("id"))
        if device_id is None:
            logger.error("Ignored device.verification_needed without a device id")
            return
        if payload.get("trust_status") not in _ALERTING_TRUST:
            return
        issue_key = f"device:verify:{device_id}"
        existing = await self._existing(issue_key)
        if existing is not None:
            if existing["read_at"] is None:
                return
            # Dismissed, and the matcher is unsure again: bring it back
            # rather than opening a second row for the same question.
            await self._reactivate(existing, detail=_device_detail(payload))
            return
        await self._insert(
            AlertType.DEVICE_VERIFICATION_NEEDED,
            title=(
                f"Device needs verification: {_display_name(payload)} "
                f"({payload.get('ip_address', '?')})"
            ),
            detail=_device_detail(payload),
            device_id=device_id,
            source_ip=_text(payload.get("ip_address")),
            source_mac=_text(payload.get("mac_address")),
            issue_key=issue_key,
            seq=seq,
        )

    # -- device.mac_changed ----------------------------------------------

    async def _on_mac_changed(self, payload: dict[str, Any], seq: int) -> None:
        device_id = _coerce_id(payload.get("device_id"))
        old_mac = _text(payload.get("old_mac"))
        new_mac = _text(payload.get("new_mac"))
        if device_id is None or not old_mac or not new_mac:
            logger.error("Ignored device.mac_changed with an incomplete payload")
            return
        device = await self._device_row(device_id)
        if device is None:
            logger.error("Ignored device.mac_changed for unknown device %d", device_id)
            return
        confidence = payload.get("confidence")
        change = {
            "old_mac": old_mac,
            "new_mac": new_mac,
            "confidence": confidence if isinstance(confidence, (int, float)) else None,
            "observed_at": _now(),
        }
        issue_key = f"device:mac_changed:{device_id}"
        existing = await self._existing(issue_key)
        if existing is not None:
            detail = _load_detail(existing["detail"])
            recent = detail.get("recent_changes")
            recent = list(recent) if isinstance(recent, list) else []
            recent.append(change)
            detail.update(
                {
                    "old_mac": old_mac,
                    "new_mac": new_mac,
                    "confidence": change["confidence"],
                    "change_count": int(detail.get("change_count") or 0) + 1,
                    "last_changed": change["observed_at"],
                    "recent_changes": recent[-_MAX_RECENT_CHANGES:],
                }
            )
            await self._reactivate(existing, detail=detail, source_mac=new_mac)
            return
        name = _display_name(device)
        await self._insert(
            AlertType.DEVICE_MAC_CHANGED,
            title=f"MAC address changed for {name} ({device['ip_address']})",
            detail={
                "device_name": name,
                "ip_address": device["ip_address"],
                "hostname": device["hostname"],
                "vendor": device["vendor"],
                "old_mac": old_mac,
                "new_mac": new_mac,
                "confidence": change["confidence"],
                "change_count": 1,
                "first_changed": change["observed_at"],
                "last_changed": change["observed_at"],
                "recent_changes": [change],
            },
            device_id=device_id,
            source_ip=device["ip_address"],
            source_mac=new_mac,
            issue_key=issue_key,
            seq=seq,
        )

    # -- Persistence -----------------------------------------------------

    async def _existing(self, issue_key: str) -> aiosqlite.Row | None:
        async with self._db.execute(
            "SELECT * FROM home_alerts WHERE issue_key = ? ORDER BY id DESC LIMIT 1",
            (issue_key,),
        ) as cursor:
            return await cursor.fetchone()

    async def _device_row(self, device_id: int) -> aiosqlite.Row | None:
        async with self._db.execute(
            "SELECT id, ip_address, mac_address, hostname, vendor, custom_name "
            "FROM devices WHERE id = ?",
            (device_id,),
        ) as cursor:
            return await cursor.fetchone()

    async def _insert(
        self,
        alert_type: AlertType,
        *,
        title: str,
        detail: dict[str, Any],
        device_id: int,
        source_ip: str | None,
        source_mac: str | None,
        issue_key: str,
        seq: int,
    ) -> None:
        severity: Severity = severity_for_alert_type(alert_type)
        now = _now()
        detail_json = json.dumps(detail, sort_keys=True)
        # Same guard as the decoy handler: an event that predates a history
        # clear must not resurrect a row the operator just removed.
        cursor = await self._db.execute(
            """INSERT INTO home_alerts
               (alert_type, severity, title, detail, source_ip, source_mac,
                device_id, issue_key, device_count, created_at)
               SELECT ?, ?, ?, ?, ?, ?, ?, ?, 1, ?
               WHERE NOT EXISTS (
                   SELECT 1 FROM events
                   WHERE event_type = 'alerts.history_cleared' AND seq >= ?
               )""",
            (
                alert_type.value, severity.value, title, detail_json,
                source_ip, source_mac, device_id, issue_key, now, seq,
            ),
        )
        await self._db.commit()
        if cursor.rowcount != 1:
            logger.info("Ignored pre-clear %s event at sequence %d", alert_type.value, seq)
            return
        alert_id = cursor.lastrowid
        if alert_id is None:
            raise RuntimeError("Device alert insert did not return an ID")
        await self._event_bus.publish(
            "alert.new",
            {
                "id": alert_id,
                "alert_type": alert_type.value,
                "severity": severity.value,
                "title": title,
                "source_ip": source_ip,
                "source_mac": source_mac,
                "device_id": device_id,
                "created_at": now,
                "incident_id": None,
                "read_at": None,
                "actioned_at": None,
                "summary": _summary(detail),
                "issue_key": issue_key,
                "alert_count": None,
                "device_count": 1,
                "source_event_seq": seq,
            },
            source_id=f"device:{device_id}",
        )

    async def _reactivate(
        self,
        existing: aiosqlite.Row,
        *,
        detail: dict[str, Any],
        source_mac: str | None = None,
    ) -> None:
        detail_json = json.dumps(detail, sort_keys=True)
        await self._db.execute(
            """UPDATE home_alerts
               SET detail = ?,
                   source_mac = COALESCE(?, source_mac),
                   read_at = NULL,
                   actioned_at = NULL
               WHERE id = ?""",
            (detail_json, source_mac, existing["id"]),
        )
        await self._db.commit()
        await self._event_bus.publish(
            "alert.updated",
            {
                "id": existing["id"],
                "alert_type": existing["alert_type"],
                "severity": existing["severity"],
                "title": existing["title"],
                "source_ip": existing["source_ip"],
                "source_mac": source_mac or existing["source_mac"],
                "device_id": existing["device_id"],
                "created_at": existing["created_at"],
                "incident_id": existing["incident_id"],
                "read_at": None,
                "actioned_at": None,
                "summary": _summary(detail),
                "issue_key": existing["issue_key"],
                "alert_count": None,
                "device_count": 1,
            },
            source_id=f"device:{existing['device_id']}",
        )


# -- Helpers -------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _coerce_id(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _text(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value[:128]
    return None


def _display_name(fields: Any) -> str:
    """Operator name, then hostname, then the hardware address."""
    for key in ("custom_name", "hostname", "mac_address"):
        value = _text(fields[key] if not isinstance(fields, dict) else fields.get(key))
        if value:
            return value
    return "unknown device"


def _device_detail(payload: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "ip_address", "mac_address", "hostname", "vendor", "device_type",
        "model_name", "custom_name", "area", "trust_status", "first_seen", "last_seen",
    )
    return {key: payload.get(key) for key in keys if payload.get(key) is not None}


def _summary(detail: dict[str, Any]) -> str:
    """One line for Slack and push, built from what the detail actually holds.

    Outbound handlers render a string; the detail dict is for the app and the
    row. Sending the dict would reach an operator as a Python repr.
    """
    parts: list[str] = []
    vendor = detail.get("vendor")
    device_type = detail.get("device_type")
    if vendor or (device_type and device_type != "unknown"):
        parts.append(" ".join(str(x) for x in (vendor, device_type) if x))
    if detail.get("new_mac"):
        parts.append(f"MAC {detail.get('old_mac')} to {detail['new_mac']}")
        count = detail.get("change_count")
        if isinstance(count, int) and count > 1:
            parts.append(f"{count} changes")
    elif detail.get("mac_address"):
        parts.append(f"MAC {detail['mac_address']}")
    if detail.get("trust_status"):
        parts.append(f"trust {detail['trust_status']}")
    return ", ".join(parts)


def _load_detail(raw: object) -> dict[str, Any]:
    try:
        decoded = json.loads(raw) if isinstance(raw, str) else None
    except (json.JSONDecodeError, TypeError, ValueError):
        decoded = None
    return decoded if isinstance(decoded, dict) else {}
