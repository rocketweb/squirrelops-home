"""Security insight analyzer -- generates alerts from port scan data.

Called after Phase 2 of each scan cycle. For each device with open ports,
evaluates the port risk knowledge base and creates/updates alerts via the
existing alert system. Deduplicates across scans so the same port/device
combination only ever produces a single alert -- even if the device goes
offline and comes back.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from squirrelops_home_sensor.alerts.types import AlertType, Severity
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.security.port_risks import PortRisk, evaluate_device_ports

logger = logging.getLogger(__name__)


class SecurityInsightAnalyzer:
    """Generates security insight alerts from device port scan data.

    Parameters
    ----------
    db:
        Open aiosqlite connection with schema applied (V4+).
    event_bus:
        Event bus for publishing alert.new events.
    """

    def __init__(self, db: aiosqlite.Connection, event_bus: EventBus) -> None:
        self._db = db
        self._bus = event_bus

    async def analyze_device(
        self,
        device_id: int,
        ip_address: str,
        mac_address: str | None,
        device_type: str,
        open_ports: frozenset[int],
        display_name: str,
    ) -> int:
        """Analyze a single device's ports and generate/update alerts.

        Returns the number of new alerts created.
        """
        if not open_ports:
            await self._resolve_stale_insights(device_id, set())
            return 0

        findings = evaluate_device_ports(open_ports, device_type)
        if not findings:
            await self._resolve_stale_insights(device_id, set())
            return 0

        new_count = 0
        active_keys: set[str] = set()

        for finding in findings:
            insight_key = f"risky_port:{finding.port}"
            active_keys.add(insight_key)

            # Check deduplication -- once alerted, never re-alert for the
            # same device+port even if the device goes offline and comes back.
            existing = await self._get_insight_state(device_id, insight_key)
            if existing is not None:
                # Clear resolved_at so the insight is considered active again
                # (device came back online) without creating a duplicate alert.
                if existing["resolved_at"] is not None:
                    await self._reactivate_insight_state(
                        device_id, insight_key
                    )
                continue

            # Create alert
            alert_id = await self._create_alert(
                device_id=device_id,
                ip_address=ip_address,
                mac_address=mac_address,
                display_name=display_name,
                finding=finding,
            )

            # Record insight state for deduplication
            await self._insert_insight_state(device_id, insight_key, alert_id)
            new_count += 1

        # Resolve insights for ports that are no longer open
        await self._resolve_stale_insights(device_id, active_keys)

        return new_count

    async def analyze_all_devices(
        self,
        devices: list[dict[str, Any]],
    ) -> int:
        """Analyze all devices after a scan cycle.

        Parameters
        ----------
        devices:
            List of dicts with keys: device_id, ip_address, mac_address,
            device_type, open_ports (frozenset[int]), display_name.

        Returns the total number of new alerts created.
        """
        total = 0
        for dev in devices:
            count = await self.analyze_device(
                device_id=dev["device_id"],
                ip_address=dev["ip_address"],
                mac_address=dev["mac_address"],
                device_type=dev["device_type"],
                open_ports=dev["open_ports"],
                display_name=dev["display_name"],
            )
            total += count
        if total > 0:
            logger.info("Security analysis generated %d new alerts", total)
        return total

    # -- Private helpers ------------------------------------------------------

    async def _get_insight_state(
        self, device_id: int, insight_key: str
    ) -> dict[str, Any] | None:
        cursor = await self._db.execute(
            "SELECT * FROM security_insight_state "
            "WHERE device_id = ? AND insight_key = ?",
            (device_id, insight_key),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def _insert_insight_state(
        self, device_id: int, insight_key: str, alert_id: int
    ) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        await self._db.execute(
            "INSERT INTO security_insight_state "
            "(device_id, insight_key, alert_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (device_id, insight_key, alert_id, now),
        )
        await self._db.commit()

    async def _reactivate_insight_state(
        self, device_id: int, insight_key: str
    ) -> None:
        """Clear resolved_at so a returning port is tracked as active again
        without creating a duplicate alert."""
        await self._db.execute(
            "UPDATE security_insight_state SET resolved_at = NULL "
            "WHERE device_id = ? AND insight_key = ?",
            (device_id, insight_key),
        )
        await self._db.commit()

    async def _resolve_stale_insights(
        self, device_id: int, active_keys: set[str]
    ) -> None:
        """Mark insights as resolved when their port is no longer open."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        cursor = await self._db.execute(
            "SELECT id, insight_key FROM security_insight_state "
            "WHERE device_id = ? AND resolved_at IS NULL",
            (device_id,),
        )
        rows = await cursor.fetchall()
        resolved = False
        for row in rows:
            if row["insight_key"] not in active_keys:
                await self._db.execute(
                    "UPDATE security_insight_state SET resolved_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                resolved = True
        if resolved:
            await self._db.commit()

    async def _create_alert(
        self,
        device_id: int,
        ip_address: str,
        mac_address: str | None,
        display_name: str,
        finding: PortRisk,
    ) -> int:
        """Create an alert and publish it to the event bus."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        title = f"{finding.service_name} open on {display_name}"

        detail_obj = {
            "device_id": device_id,
            "port": finding.port,
            "service_name": finding.service_name,
            "risk_description": finding.risk_description,
            "remediation_steps": finding.remediation,
        }
        detail_json = json.dumps(detail_obj)

        cursor = await self._db.execute(
            """INSERT INTO home_alerts
               (alert_type, severity, title, detail, source_ip,
                source_mac, device_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                AlertType.SECURITY_PORT_RISK.value,
                finding.severity.value,
                title,
                detail_json,
                ip_address,
                mac_address,
                device_id,
                now,
            ),
        )
        alert_id = cursor.lastrowid
        await self._db.commit()

        # Publish for real-time WebSocket delivery
        await self._bus.publish(
            "alert.new",
            {
                "id": alert_id,
                "alert_type": AlertType.SECURITY_PORT_RISK.value,
                "severity": finding.severity.value,
                "title": title,
                "source_ip": ip_address,
                "created_at": now,
                "incident_id": None,
                "read_at": None,
                "actioned_at": None,
                "alert_count": None,
            },
            source_id=str(device_id),
        )

        return alert_id
