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

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)
_DAILY_INTERVAL_SECONDS = 24 * 60 * 60


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
        if not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        self._db = db
        self._retention_days = retention_days

    async def purge(self) -> PurgeResult:
        """Execute the retention purge. Returns a summary of purged counts.

        Order of operations matters -- alerts are purged before incidents
        to respect foreign key relationships.
        """
        cutoff = datetime.now(UTC) - timedelta(days=self._retention_days)
        cutoff_str = _format_iso(cutoff)

        result = PurgeResult()
        await self._db.execute("SAVEPOINT alert_retention")
        try:
            result.alerts_purged = await self._purge_alerts(cutoff_str)
            result.incidents_purged = await self._purge_incidents(cutoff_str)
            result.decoy_connections_purged = await self._purge_decoy_connections(
                cutoff_str
            )
            result.canary_observations_purged = (
                await self._purge_canary_observations(cutoff_str)
            )
            await self._detach_old_event_references(cutoff_str)
            result.events_purged = await self._purge_events(cutoff_str)
        except BaseException:
            await self._db.execute("ROLLBACK TO SAVEPOINT alert_retention")
            await self._db.execute("RELEASE SAVEPOINT alert_retention")
            raise
        await self._db.execute("RELEASE SAVEPOINT alert_retention")
        await self._db.commit()

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
        await self._db.execute(
            """UPDATE security_insight_state
               SET alert_id = NULL
               WHERE alert_id IN (
                   SELECT id
                   FROM home_alerts
                   WHERE created_at < ?
                     AND (
                         incident_id IS NULL
                         OR incident_id NOT IN (
                             SELECT id FROM incidents WHERE status = 'active'
                         )
                     )
               )""",
            (cutoff_str,),
        )
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
        return cursor.rowcount

    async def _purge_events(self, cutoff_str: str) -> int:
        """Purge events older than cutoff.

        Referencing child history is purged or detached first. Sequence
        numbers are never reused (AUTOINCREMENT).
        """
        cursor = await self._db.execute(
            "DELETE FROM events WHERE created_at < ?",
            (cutoff_str,),
        )
        return cursor.rowcount

    async def _detach_old_event_references(self, cutoff_str: str) -> None:
        """Detach retained records from events that are about to age out.

        These references are optional provenance. A recent record or an alert
        preserved by an active incident may outlive the event it references.
        Clearing the nullable foreign keys preserves that retained record
        while allowing the event retention boundary to be enforced.
        """
        for table in (
            "home_alerts",
            "decoy_connections",
            "canary_observations",
        ):
            await self._db.execute(
                f"""UPDATE {table}
                    SET event_seq = NULL
                    WHERE event_seq IN (
                        SELECT seq FROM events WHERE created_at < ?
                    )""",
                (cutoff_str,),
            )

    async def _purge_decoy_connections(self, cutoff_str: str) -> int:
        """Purge decoy connection records older than cutoff."""
        cursor = await self._db.execute(
            "DELETE FROM decoy_connections WHERE timestamp < ?",
            (cutoff_str,),
        )
        return cursor.rowcount

    async def _purge_canary_observations(self, cutoff_str: str) -> int:
        """Purge canary observation records older than cutoff."""
        cursor = await self._db.execute(
            "DELETE FROM canary_observations WHERE observed_at < ?",
            (cutoff_str,),
        )
        return cursor.rowcount


class AlertRetentionScheduler:
    """Run retention immediately at startup and once per day thereafter.

    Each purge uses a dedicated SQLite connection so its savepoint cannot
    accidentally include work from another coroutine sharing the sensor's
    primary connection.
    """

    def __init__(
        self,
        *,
        db_path: Path,
        retention_days: int = 90,
        interval_seconds: float = _DAILY_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        self._db_path = Path(db_path)
        self._retention_days = retention_days
        self._interval_seconds = interval_seconds
        self._shutdown = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def is_running(self) -> bool:
        """Whether the scheduler currently owns a live task."""
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start the scheduler once; repeated calls are harmless."""
        if self.is_running:
            return
        self._shutdown.clear()
        self._task = asyncio.create_task(
            self._run(),
            name="alert-retention",
        )

    async def stop(self) -> None:
        """Wake and join the scheduler before its database can be removed."""
        task = self._task
        if task is None:
            return
        self._shutdown.set()
        try:
            await task
        finally:
            self._task = None

    async def _run(self) -> None:
        while not self._shutdown.is_set():
            try:
                await self._purge_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "Alert retention purge failed; retrying at the next interval"
                )

            try:
                await asyncio.wait_for(
                    self._shutdown.wait(),
                    timeout=self._interval_seconds,
                )
            except TimeoutError:
                continue

    async def _purge_once(self) -> PurgeResult:
        db = await aiosqlite.connect(str(self._db_path))
        try:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON")
            await db.execute("PRAGMA busy_timeout = 30000")
            service = AlertRetentionService(
                db=db,
                retention_days=self._retention_days,
            )
            return await service.purge()
        finally:
            await db.close()


def _format_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
