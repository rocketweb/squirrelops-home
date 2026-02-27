"""Session-based incident grouping.

Groups alerts from the same source_ip within a configurable time window
into parent incidents. Each incident tracks alert count, maximum severity,
and a template-generated summary.

Lifecycle:
  ACTIVE  -- receiving new alerts within the window
  CLOSED  -- no new alerts for ``incident_close_window_minutes``

Closed incidents are immutable. New alerts from the same source after
closure create a new incident.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

import aiosqlite

from squirrelops_home_sensor.alerts.types import Severity


# -- Protocols for dependency injection ------------------------------

class EventBusProtocol(Protocol):
    async def publish(self, event_type: str, payload: dict[str, Any]) -> int: ...
    def subscribe(self, event_types: list[str], callback: Any) -> None: ...


# -- Incident Grouper ------------------------------------------------

class IncidentGrouper:
    """Watches for new alerts and groups them into incidents by source_ip.

    Parameters
    ----------
    db:
        An open aiosqlite connection with the incidents and home_alerts
        tables.
    event_bus:
        Event bus for publishing incident.new / incident.updated events.
    incident_window_minutes:
        Maximum gap between alerts in the same incident (default 15).
    incident_close_window_minutes:
        How long after the last alert before an incident is closed
        (default 30).
    """

    def __init__(
        self,
        *,
        db: aiosqlite.Connection,
        event_bus: EventBusProtocol,
        incident_window_minutes: int = 15,
        incident_close_window_minutes: int = 30,
    ) -> None:
        self._db = db
        self._event_bus = event_bus
        self._incident_window = timedelta(minutes=incident_window_minutes)
        self._close_window = timedelta(minutes=incident_close_window_minutes)

    # -- Public API --------------------------------------------------

    async def process_alert(self, alert_id: int) -> None:
        """Process a newly inserted alert: attach to an existing incident
        or create a new one.

        The alert must already exist in ``home_alerts``. This method
        updates ``incident_id`` on the alert row and creates/updates
        the parent incident.
        """
        alert = await self._fetch_alert(alert_id)
        if alert is None:
            return

        source_ip: str | None = alert["source_ip"]
        if source_ip is None:
            # System alerts -- no grouping
            return

        alert_time = _parse_iso(alert["created_at"])
        alert_severity = Severity(alert["severity"])

        # Find active incident for this source_ip within the window
        incident = await self._find_active_incident(source_ip, alert_time)

        if incident is not None:
            await self._attach_to_incident(alert, incident, alert_severity, alert_time)
        else:
            await self._create_incident(alert, alert_severity, alert_time)

    async def close_stale_incidents(self) -> int:
        """Close active incidents whose last alert is older than the
        close window. Returns the number of incidents closed."""
        cutoff = datetime.now(timezone.utc) - self._close_window
        cutoff_str = _format_iso(cutoff)

        cursor = await self._db.execute(
            """UPDATE incidents
               SET status = 'closed', closed_at = ?
               WHERE status = 'active' AND last_alert_at < ?""",
            (_format_iso(datetime.now(timezone.utc)), cutoff_str),
        )
        await self._db.commit()
        return cursor.rowcount

    # -- Private helpers ---------------------------------------------

    async def _fetch_alert(self, alert_id: int) -> aiosqlite.Row | None:
        async with self._db.execute(
            "SELECT * FROM home_alerts WHERE id = ?", (alert_id,)
        ) as cur:
            return await cur.fetchone()

    async def _find_active_incident(
        self, source_ip: str, alert_time: datetime
    ) -> aiosqlite.Row | None:
        """Find an active incident for ``source_ip`` whose last_alert_at
        is within the incident window of ``alert_time``."""
        window_start = alert_time - self._incident_window
        window_start_str = _format_iso(window_start)

        async with self._db.execute(
            """SELECT * FROM incidents
               WHERE source_ip = ? AND status = 'active'
                 AND last_alert_at >= ?
               ORDER BY last_alert_at DESC
               LIMIT 1""",
            (source_ip, window_start_str),
        ) as cur:
            return await cur.fetchone()

    async def _attach_to_incident(
        self,
        alert: aiosqlite.Row,
        incident: aiosqlite.Row,
        alert_severity: Severity,
        alert_time: datetime,
    ) -> None:
        """Attach an alert to an existing incident, escalate severity,
        regenerate summary."""
        incident_id = incident["id"]
        current_severity = Severity(incident["severity"])
        new_severity = max(current_severity, alert_severity)
        new_count = incident["alert_count"] + 1

        # Link alert to incident
        await self._db.execute(
            "UPDATE home_alerts SET incident_id = ? WHERE id = ?",
            (incident_id, alert["id"]),
        )

        # Update incident
        await self._db.execute(
            """UPDATE incidents
               SET alert_count = ?,
                   last_alert_at = ?,
                   severity = ?
               WHERE id = ?""",
            (new_count, _format_iso(alert_time), new_severity.value, incident_id),
        )
        await self._db.commit()

        # Regenerate summary
        summary = await self._generate_summary(incident_id)
        await self._db.execute(
            "UPDATE incidents SET summary = ? WHERE id = ?",
            (summary, incident_id),
        )
        await self._db.commit()

        await self._event_bus.publish(
            "incident.updated",
            {
                "incident_id": incident_id,
                "alert_count": new_count,
                "severity": new_severity.value,
            },
        )

    async def _create_incident(
        self,
        alert: aiosqlite.Row,
        alert_severity: Severity,
        alert_time: datetime,
    ) -> None:
        """Create a new incident with this alert as the first child."""
        time_str = _format_iso(alert_time)

        cursor = await self._db.execute(
            """INSERT INTO incidents
               (source_ip, source_mac, status, severity, alert_count,
                first_alert_at, last_alert_at)
               VALUES (?, ?, 'active', ?, 1, ?, ?)""",
            (
                alert["source_ip"],
                alert["source_mac"],
                alert_severity.value,
                time_str,
                time_str,
            ),
        )
        incident_id = cursor.lastrowid
        await self._db.commit()

        # Link alert to incident
        await self._db.execute(
            "UPDATE home_alerts SET incident_id = ? WHERE id = ?",
            (incident_id, alert["id"]),
        )
        await self._db.commit()

        # Generate initial summary
        summary = await self._generate_summary(incident_id)
        await self._db.execute(
            "UPDATE incidents SET summary = ? WHERE id = ?",
            (summary, incident_id),
        )
        await self._db.commit()

        await self._event_bus.publish(
            "incident.new",
            {
                "incident_id": incident_id,
                "source_ip": alert["source_ip"],
                "severity": alert_severity.value,
            },
        )

    async def _generate_summary(self, incident_id: int) -> str:
        """Generate a template-based summary for an incident.

        Pattern: "{count} event(s) from {source_ip} over {duration}: {alert_type_list}"
        """
        async with self._db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ) as cur:
            incident = await cur.fetchone()

        if incident is None:
            return ""

        count = incident["alert_count"]
        source_ip = incident["source_ip"]

        # Get child alert types in chronological order
        async with self._db.execute(
            """SELECT alert_type FROM home_alerts
               WHERE incident_id = ?
               ORDER BY created_at ASC""",
            (incident_id,),
        ) as cur:
            alert_rows = await cur.fetchall()

        alert_types = [row["alert_type"] for row in alert_rows]

        # Calculate duration
        first = _parse_iso(incident["first_alert_at"])
        last = _parse_iso(incident["last_alert_at"])
        duration = last - first

        # Format duration
        duration_str = _format_duration(duration)

        # Collapse consecutive duplicates with counts
        type_sequence = _collapse_consecutive(alert_types)

        event_word = "event" if count == 1 else "events"
        type_list = " \u2192 ".join(type_sequence)

        if duration.total_seconds() < 1:
            return f"{count} {event_word} from {source_ip}: {type_list}"
        return f"{count} {event_word} from {source_ip} over {duration_str}: {type_list}"


# -- Utility functions -----------------------------------------------

def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 timestamp string to a timezone-aware datetime."""
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def _format_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _format_duration(delta: timedelta) -> str:
    """Format a timedelta as a human-readable string."""
    total_seconds = int(delta.total_seconds())
    if total_seconds < 60:
        return f"{total_seconds} second{'s' if total_seconds != 1 else ''}"
    minutes = total_seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    remaining_min = minutes % 60
    if remaining_min == 0:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return (
        f"{hours} hour{'s' if hours != 1 else ''} "
        f"{remaining_min} minute{'s' if remaining_min != 1 else ''}"
    )


def _collapse_consecutive(items: list[str]) -> list[str]:
    """Collapse consecutive duplicate items with counts.

    ["decoy.trip", "decoy.trip", "decoy.trip", "decoy.credential_trip"]
    becomes ["decoy.trip (x3)", "decoy.credential_trip"]
    """
    if not items:
        return []

    result: list[str] = []
    current = items[0]
    count = 1

    for item in items[1:]:
        if item == current:
            count += 1
        else:
            result.append(current if count == 1 else f"{current} (\u00d7{count})")
            current = item
            count = 1

    result.append(current if count == 1 else f"{current} (\u00d7{count})")
    return result
