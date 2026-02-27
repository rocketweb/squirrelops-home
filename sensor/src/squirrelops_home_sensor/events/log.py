"""Persistent event log backed by SQLite.

Every event published through the event bus is persisted here with a
monotonic sequence number (AUTOINCREMENT). The WebSocket replay endpoint
reads from this log to catch clients up after reconnection.
"""

from __future__ import annotations

import json
from typing import Any

import aiosqlite


class EventLog:
    """Persistent, append-only event log stored in SQLite.

    Parameters
    ----------
    db:
        An open ``aiosqlite.Connection`` with the schema already applied.
    """

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        source_id: str | None = None,
    ) -> int:
        """Append an event and return its sequence number."""
        payload_json = json.dumps(payload)
        cursor = await self._db.execute(
            "INSERT INTO events (event_type, payload, source_id) VALUES (?, ?, ?)",
            (event_type, payload_json, source_id),
        )
        await self._db.commit()
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    async def replay(self, since_seq: int) -> list[dict[str, Any]]:
        """Return all events with seq > since_seq, ordered by seq ascending.

        Parameters
        ----------
        since_seq:
            The last sequence number the caller has seen. Pass 0 to get
            all events from the beginning.
        """
        cursor = await self._db.execute(
            "SELECT seq, event_type, payload, source_id, created_at "
            "FROM events WHERE seq > ? ORDER BY seq ASC",
            (since_seq,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "seq": row[0],
                "event_type": row[1],
                "payload": json.loads(row[2]),
                "source_id": row[3],
                "created_at": row[4],
            }
            for row in rows
        ]

    async def get_latest_seq(self) -> int:
        """Return the highest sequence number, or 0 if the log is empty."""
        cursor = await self._db.execute("SELECT MAX(seq) FROM events")
        row = await cursor.fetchone()
        return row[0] if row and row[0] is not None else 0
