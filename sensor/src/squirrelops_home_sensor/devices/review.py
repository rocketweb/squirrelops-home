"""Device review reminders -- creates alerts for uncategorized devices.

Runs as a periodic background task. Checks for devices that have been
in "unknown" trust status for more than 24 hours and creates a
low-severity reminder alert for each one.

Idempotent: only one reminder per device. Safe to run multiple times.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import aiosqlite

from squirrelops_home_sensor.alerts.types import AlertType, Severity

logger = logging.getLogger(__name__)

REVIEW_THRESHOLD_HOURS = 24


class DeviceReviewService:
    """Creates reminder alerts for devices that remain uncategorized.

    Parameters
    ----------
    db:
        An open aiosqlite connection with schema applied.
    review_threshold_hours:
        Hours after first_seen before creating a reminder (default 24).
    """

    def __init__(
        self,
        *,
        db: aiosqlite.Connection,
        review_threshold_hours: int = REVIEW_THRESHOLD_HOURS,
    ) -> None:
        self._db = db
        self._threshold_hours = review_threshold_hours

    async def check_for_reviews(self) -> int:
        """Check for devices needing review and create reminder alerts.

        Returns the number of new reminders created.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self._threshold_hours)
        cutoff_str = _format_iso(cutoff)
        now_str = _format_iso(datetime.now(timezone.utc))

        # Find devices that:
        # 1. Were first seen before the cutoff
        # 2. Have no trust row OR trust status is 'unknown'
        # 3. Don't already have a review reminder alert
        cursor = await self._db.execute(
            """SELECT d.id, d.ip_address, d.hostname, d.mac_address
               FROM devices d
               LEFT JOIN device_trust dt ON dt.device_id = d.id
               WHERE d.first_seen < ?
                 AND (dt.device_id IS NULL OR dt.status = 'unknown')
                 AND d.id NOT IN (
                     SELECT device_id FROM home_alerts
                     WHERE alert_type = ?
                       AND device_id IS NOT NULL
                 )""",
            (cutoff_str, AlertType.DEVICE_REVIEW_REMINDER.value),
        )
        rows = await cursor.fetchall()

        count = 0
        for row in rows:
            device_id = row["id"]
            ip = row["ip_address"]
            hostname = row["hostname"]

            name = hostname or ip
            title = f"Device '{name}' needs review"
            detail = (
                f"Device at {ip} was discovered over "
                f"{self._threshold_hours} hours ago and has not been "
                f"approved or rejected."
            )

            await self._db.execute(
                """INSERT INTO home_alerts
                   (alert_type, severity, title, detail, source_ip,
                    source_mac, device_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    AlertType.DEVICE_REVIEW_REMINDER.value,
                    Severity.LOW.value,
                    title,
                    detail,
                    ip,
                    row["mac_address"],
                    device_id,
                    now_str,
                ),
            )
            count += 1

        if count > 0:
            await self._db.commit()
            logger.info("Created %d device review reminder(s)", count)

        return count


def _format_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
