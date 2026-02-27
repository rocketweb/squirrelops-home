"""Alert retention -- 90-day rolling purge of aged-out records.

Runs as a daily background task. Purges:
  - ``home_alerts`` older than retention period (preserves alerts in active incidents)
  - ``events`` older than retention period
  - ``decoy_connections`` older than retention period
  - ``canary_observations`` older than retention period
  - ``incidents`` that are closed and older than retention period

Active incidents and their linked alerts are always preserved regardless
of age. Sequence numbers (events.seq) are never reused because the
table uses AUTOINCREMENT.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import aiosqlite


logger = logging.getLogger(__name__)


@dataclass
class PurgeResult:
    """Summary of a single purge run."""

    alerts_purged: int = 0
    events_purged: int = 0
    decoy_connections_purged: int = 0
    canary_observations_purged: int = 0
    incidents_purged: int = 0

    @property
    def total_purged(self) -> int:
        return (
            self.alerts_purged
            + self.events_purged
            + self.decoy_connections_purged
            + self.canary_observations_purged
            + self.incidents_purged
        )


class AlertRetentionService:
    """Purges aged-out records from the database.

    Parameters
    ----------
    db:
        An open aiosqlite connection.
    retention_days:
        Number of days to retain records (default 90).
    """

    def __init__(
        self,
        *,
        db: aiosqlite.Connection,
        retention_days: int = 90,
    ) -> None:
        self._db = db
        self._retention_days = retention_days

    async def purge(self) -> PurgeResult:
        """Execute the retention purge. Returns a summary of purged counts.

        Order of operations matters -- alerts are purged before incidents
        to respect foreign key relationships.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        cutoff_str = _format_iso(cutoff)

        result = PurgeResult()

        result.alerts_purged = await self._purge_alerts(cutoff_str)
        result.incidents_purged = await self._purge_incidents(cutoff_str)
        result.events_purged = await self._purge_events(cutoff_str)
        result.decoy_connections_purged = await self._purge_decoy_connections(cutoff_str)
        result.canary_observations_purged = await self._purge_canary_observations(
            cutoff_str
        )

        if result.total_purged > 0:
            logger.info(
                "Retention purge complete: %d total records purged "
                "(alerts=%d, events=%d, connections=%d, observations=%d, incidents=%d)",
                result.total_purged,
                result.alerts_purged,
                result.events_purged,
                result.decoy_connections_purged,
                result.canary_observations_purged,
                result.incidents_purged,
            )

        return result

    async def _purge_alerts(self, cutoff_str: str) -> int:
        """Purge alerts older than cutoff, preserving those linked to
        active incidents."""
        cursor = await self._db.execute(
            """DELETE FROM home_alerts
               WHERE created_at < ?
                 AND (
                     incident_id IS NULL
                     OR incident_id NOT IN (
                         SELECT id FROM incidents WHERE status = 'active'
                     )
                 )""",
            (cutoff_str,),
        )
        await self._db.commit()
        return cursor.rowcount

    async def _purge_incidents(self, cutoff_str: str) -> int:
        """Purge closed incidents older than cutoff.

        Active incidents are never purged regardless of age.
        Child alerts must be purged first (handled by _purge_alerts).
        """
        cursor = await self._db.execute(
            """DELETE FROM incidents
               WHERE status = 'closed'
                 AND closed_at < ?""",
            (cutoff_str,),
        )
        await self._db.commit()
        return cursor.rowcount

    async def _purge_events(self, cutoff_str: str) -> int:
        """Purge events older than cutoff.

        Sequence numbers are never reused (AUTOINCREMENT).
        """
        cursor = await self._db.execute(
            "DELETE FROM events WHERE created_at < ?",
            (cutoff_str,),
        )
        await self._db.commit()
        return cursor.rowcount

    async def _purge_decoy_connections(self, cutoff_str: str) -> int:
        """Purge decoy connection records older than cutoff."""
        cursor = await self._db.execute(
            "DELETE FROM decoy_connections WHERE timestamp < ?",
            (cutoff_str,),
        )
        await self._db.commit()
        return cursor.rowcount

    async def _purge_canary_observations(self, cutoff_str: str) -> int:
        """Purge canary observation records older than cutoff."""
        cursor = await self._db.execute(
            "DELETE FROM canary_observations WHERE observed_at < ?",
            (cutoff_str,),
        )
        await self._db.commit()
        return cursor.rowcount


def _format_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
