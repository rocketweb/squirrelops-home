"""Security insight analyzer -- generates grouped alerts from port scan data.

Called after Phase 2 of each scan cycle. Evaluates all devices' open ports
against the port risk knowledge base and produces ONE alert per issue type
(e.g., "SSH open") listing all affected devices, rather than one alert per
device+port. Deduplicates across scans using security_insight_state and the
issue_key column on grouped alerts.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from squirrelops_home_sensor.alerts.types import AlertType
from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.security.port_risks import (
    PortRisk,
    evaluate_device_ports,
    issue_key_for_port_risk,
)

logger = logging.getLogger(__name__)


class SecurityInsightAnalyzer:
    """Generates security insight alerts grouped by issue type.

    Parameters
    ----------
    db:
        Open aiosqlite connection with schema V8+.
    event_bus:
        Event bus for publishing alert.new / alert.updated events.
    """

    def __init__(self, db: aiosqlite.Connection, event_bus: EventBus) -> None:
        self._db = db
        self._bus = event_bus

    async def analyze_all_devices(
        self,
        devices: list[dict[str, Any]],
    ) -> int:
        """Analyze all devices after a scan cycle.

        Produces at most one alert per issue type.  Returns the number of *new*
        grouped alerts created (does not count updates to existing alerts).

        Parameters
        ----------
        devices:
            List of dicts with keys: device_id, ip_address, mac_address,
            device_type, open_ports (frozenset[int]), display_name.
        """
        # Step 1: Collect findings across all devices, grouped by issue_key.
        groups: dict[str, dict[str, Any]] = {}

        # Track which (device_id, insight_key) pairs are currently active
        # so we can resolve stale insight_state entries.
        all_active_per_device: dict[int, set[str]] = defaultdict(set)

        for dev in devices:
            findings = evaluate_device_ports(
                dev["open_ports"], dev["device_type"]
            )
            for finding in findings:
                ik = issue_key_for_port_risk(finding)
                insight_key = f"risky_port:{finding.port}"
                all_active_per_device[dev["device_id"]].add(insight_key)

                if ik not in groups:
                    groups[ik] = {"finding": finding, "devices": []}
                groups[ik]["devices"].append({
                    "device_id": dev["device_id"],
                    "ip_address": dev["ip_address"],
                    "mac_address": dev.get("mac_address"),
                    "display_name": dev["display_name"],
                    "port": finding.port,
                })

        # Step 2: For each issue_key, create or update the grouped alert.
        new_count = 0

        for issue_key, group in groups.items():
            finding: PortRisk = group["finding"]
            affected: list[dict] = group["devices"]

            existing = await self._get_grouped_alert(issue_key)

            if existing is None:
                # Create new grouped alert
                alert_id = await self._create_grouped_alert(
                    issue_key, finding, affected
                )
                # Record insight state for each device in the group
                for dev_info in affected:
                    insight_key = f"risky_port:{dev_info['port']}"
                    await self._upsert_insight_state(
                        dev_info["device_id"], insight_key, alert_id
                    )
                new_count += 1
            else:
                # Existing grouped alert -- check if devices changed
                alert_id = existing["id"]
                old_devices = self._parse_affected_devices(
                    existing["affected_devices"]
                )
                old_device_ids = {d["device_id"] for d in old_devices}
                new_device_ids = {d["device_id"] for d in affected}

                added_ids = new_device_ids - old_device_ids

                if added_ids:
                    # Merge new devices into the existing list
                    merged = list(old_devices)
                    for dev_info in affected:
                        if dev_info["device_id"] in added_ids:
                            merged.append(dev_info)

                    # Un-acknowledge if new devices appeared
                    was_acknowledged = existing["read_at"] is not None
                    await self._update_grouped_alert(
                        alert_id,
                        finding,
                        merged,
                        clear_read=was_acknowledged,
                    )

                    # Record insight state for new devices
                    for dev_info in affected:
                        if dev_info["device_id"] in added_ids:
                            insight_key = f"risky_port:{dev_info['port']}"
                            await self._upsert_insight_state(
                                dev_info["device_id"], insight_key, alert_id
                            )
                else:
                    # Update IPs in case of DHCP reassignment (silent update)
                    old_ips = {d["ip_address"] for d in old_devices}
                    new_ips = {d["ip_address"] for d in affected}
                    if old_ips != new_ips:
                        await self._update_grouped_alert(
                            alert_id, finding, affected, clear_read=False,
                            silent=True,
                        )

        # Step 3: Handle device removal from groups.
        await self._prune_removed_devices(groups)

        # Step 4: Resolve stale per-device insight states.
        await self._resolve_stale_insights_batch(all_active_per_device)

        if new_count > 0:
            logger.info("Security analysis generated %d new grouped alerts", new_count)
        return new_count

    # -- Private helpers --------------------------------------------------------

    async def _get_grouped_alert(
        self, issue_key: str
    ) -> dict[str, Any] | None:
        """Find the active grouped alert for an issue key."""
        cursor = await self._db.execute(
            "SELECT * FROM home_alerts "
            "WHERE issue_key = ? ORDER BY created_at DESC LIMIT 1",
            (issue_key,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    @staticmethod
    def _parse_affected_devices(raw: str | None) -> list[dict]:
        """Parse the affected_devices JSON column."""
        if not raw:
            return []
        try:
            result = json.loads(raw)
            return result if isinstance(result, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    async def _create_grouped_alert(
        self,
        issue_key: str,
        finding: PortRisk,
        affected: list[dict],
    ) -> int:
        """Create a new grouped alert and publish alert.new event."""
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        n = len(affected)
        title = f"{finding.service_name} open on {n} device{'s' if n > 1 else ''}"

        detail_obj = {
            "issue_key": issue_key,
            "port": finding.port,
            "service_name": finding.service_name,
        }

        cursor = await self._db.execute(
            """INSERT INTO home_alerts
               (alert_type, severity, title, detail, issue_key,
                affected_devices, device_count, risk_description, remediation,
                created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                AlertType.SECURITY_PORT_RISK.value,
                finding.severity.value,
                title,
                json.dumps(detail_obj),
                issue_key,
                json.dumps(affected),
                n,
                finding.risk_description,
                finding.remediation,
                now,
            ),
        )
        alert_id = cursor.lastrowid
        await self._db.commit()

        await self._bus.publish(
            "alert.new",
            {
                "id": alert_id,
                "alert_type": AlertType.SECURITY_PORT_RISK.value,
                "severity": finding.severity.value,
                "title": title,
                "source_ip": None,
                "created_at": now,
                "incident_id": None,
                "read_at": None,
                "actioned_at": None,
                "alert_count": None,
                "device_count": n,
                "issue_key": issue_key,
            },
            source_id=f"issue:{issue_key}",
        )

        return alert_id

    async def _update_grouped_alert(
        self,
        alert_id: int,
        finding: PortRisk,
        affected: list[dict],
        *,
        clear_read: bool = False,
        silent: bool = False,
    ) -> None:
        """Update an existing grouped alert's device list."""
        n = len(affected)
        title = f"{finding.service_name} open on {n} device{'s' if n > 1 else ''}"

        if clear_read:
            await self._db.execute(
                "UPDATE home_alerts SET "
                "affected_devices = ?, device_count = ?, title = ?, read_at = NULL "
                "WHERE id = ?",
                (json.dumps(affected), n, title, alert_id),
            )
        else:
            await self._db.execute(
                "UPDATE home_alerts SET "
                "affected_devices = ?, device_count = ?, title = ? "
                "WHERE id = ?",
                (json.dumps(affected), n, title, alert_id),
            )
        await self._db.commit()

        if not silent:
            cursor = await self._db.execute(
                "SELECT * FROM home_alerts WHERE id = ?", (alert_id,)
            )
            row = await cursor.fetchone()
            if row:
                await self._bus.publish(
                    "alert.updated",
                    {
                        "id": alert_id,
                        "alert_type": row["alert_type"],
                        "severity": row["severity"],
                        "title": title,
                        "source_ip": None,
                        "created_at": row["created_at"],
                        "incident_id": None,
                        "read_at": row["read_at"],
                        "actioned_at": row["actioned_at"],
                        "alert_count": None,
                        "device_count": n,
                        "issue_key": row["issue_key"],
                    },
                    source_id=f"issue:{row['issue_key']}",
                )

    async def _prune_removed_devices(
        self, current_groups: dict[str, dict[str, Any]]
    ) -> None:
        """Remove devices from grouped alerts when their port closes."""
        cursor = await self._db.execute(
            "SELECT * FROM home_alerts "
            "WHERE issue_key IS NOT NULL AND device_count > 0"
        )
        rows = await cursor.fetchall()

        for row in rows:
            issue_key = row["issue_key"]
            old_devices = self._parse_affected_devices(row["affected_devices"])
            if not old_devices:
                continue

            if issue_key in current_groups:
                current_device_ids = {
                    d["device_id"] for d in current_groups[issue_key]["devices"]
                }
            else:
                current_device_ids = set()

            pruned = [d for d in old_devices if d["device_id"] in current_device_ids]

            if len(pruned) < len(old_devices):
                n = len(pruned)
                detail = row["detail"]
                if isinstance(detail, str):
                    try:
                        detail = json.loads(detail)
                    except (json.JSONDecodeError, TypeError):
                        detail = {}
                svc = detail.get("service_name", "Unknown") if isinstance(detail, dict) else "Unknown"
                title = (
                    f"{svc} open on {n} device{'s' if n > 1 else ''}"
                    if n > 0
                    else row["title"]
                )

                await self._db.execute(
                    "UPDATE home_alerts SET "
                    "affected_devices = ?, device_count = ?, title = ? "
                    "WHERE id = ?",
                    (json.dumps(pruned), n, title, row["id"]),
                )
                await self._db.commit()

    async def _upsert_insight_state(
        self, device_id: int, insight_key: str, alert_id: int
    ) -> None:
        """Insert or update insight_state for a device+port."""
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        cursor = await self._db.execute(
            "SELECT id, resolved_at FROM security_insight_state "
            "WHERE device_id = ? AND insight_key = ?",
            (device_id, insight_key),
        )
        existing = await cursor.fetchone()

        if existing is None:
            await self._db.execute(
                "INSERT INTO security_insight_state "
                "(device_id, insight_key, alert_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (device_id, insight_key, alert_id, now),
            )
        else:
            await self._db.execute(
                "UPDATE security_insight_state "
                "SET alert_id = ?, resolved_at = NULL "
                "WHERE device_id = ? AND insight_key = ?",
                (alert_id, device_id, insight_key),
            )
        await self._db.commit()

    async def _resolve_stale_insights_batch(
        self, active_per_device: dict[int, set[str]]
    ) -> None:
        """Resolve insight_state entries for ports no longer open."""
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        cursor = await self._db.execute(
            "SELECT id, device_id, insight_key FROM security_insight_state "
            "WHERE resolved_at IS NULL"
        )
        rows = await cursor.fetchall()

        resolved = False
        for row in rows:
            active_keys = active_per_device.get(row["device_id"], set())
            if row["insight_key"] not in active_keys:
                await self._db.execute(
                    "UPDATE security_insight_state SET resolved_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                resolved = True

        if resolved:
            await self._db.commit()
