"""Async event bus with persistent storage.

The event bus is the central nervous system of the sensor. Components
publish events (device discoveries, decoy trips, alerts), and subscribers
(WebSocket, incident grouper, alert dispatcher) receive them.

Every published event is first persisted to the EventLog (SQLite), then
delivered to matching subscribers asynchronously.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from squirrelops_home_sensor.events.log import EventLog

logger = logging.getLogger(__name__)

# Type alias for subscriber callbacks
EventCallback = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class Subscription:
    """Represents an active event subscription."""

    id: str = field(default_factory=lambda: uuid4().hex)
    event_types: list[str] = field(default_factory=list)
    callback: EventCallback | None = None


class EventBus:
    """Async pub/sub event bus backed by a persistent EventLog.

    Parameters
    ----------
    event_log:
        The persistent event log for storage and replay.
    """

    def __init__(self, event_log: EventLog) -> None:
        self._log = event_log
        self._subscriptions: list[Subscription] = []
        self._lock = asyncio.Lock()

    async def publish(
        self,
        event_type: str,
        payload: dict[str, Any],
        source_id: str | None = None,
    ) -> int:
        """Persist an event and notify subscribers. Returns the sequence number."""
        async with self._lock:
            return await self._publish_serialized(
                event_type,
                payload,
                source_id=source_id,
            )

    async def _publish_serialized(
        self,
        event_type: str,
        payload: dict[str, Any],
        source_id: str | None = None,
    ) -> int:
        """Publish while the caller owns the event-ordering lock."""
        if not await self._log.entity_exists_for_event(event_type, payload):
            logger.info(
                "Suppressed orphaned %s event for cleared entity %r",
                event_type,
                payload.get("id"),
            )
            return 0

        seq = await self._log.append(event_type, payload, source_id=source_id)
        self._broadcast(seq, event_type, payload, source_id)
        return seq

    def _broadcast(
        self,
        seq: int,
        event_type: str,
        payload: dict[str, Any],
        source_id: str | None,
    ) -> None:
        """Schedule delivery of one already-persisted event."""
        event = {
            "seq": seq,
            "event_type": event_type,
            "payload": payload,
            "source_id": source_id,
        }

        # Notify matching subscribers
        for sub in list(self._subscriptions):
            if "*" in sub.event_types or event_type in sub.event_types:
                if sub.callback is not None:
                    try:
                        asyncio.ensure_future(sub.callback(event))
                    except Exception:
                        logger.exception(
                            "Error scheduling callback for subscription %s", sub.id
                        )

    @asynccontextmanager
    async def serialized(self):
        """Hold event ordering across a related database transaction."""
        async with self._lock:
            yield

    async def broadcast_persisted(
        self,
        *,
        seq: int,
        event_type: str,
        payload: dict[str, Any],
        source_id: str | None = None,
    ) -> None:
        """Broadcast an event inserted by a serialized database transaction."""
        if not self._lock.locked():
            raise RuntimeError("broadcast_persisted requires serialized()")
        self._broadcast(seq, event_type, payload, source_id)

    def subscribe(
        self,
        event_types: list[str],
        callback: EventCallback,
    ) -> Subscription:
        """Register a callback for the given event types.

        Use ``["*"]`` to subscribe to all events.

        Returns a ``Subscription`` that can be passed to ``unsubscribe()``.
        """
        sub = Subscription(event_types=event_types, callback=callback)
        self._subscriptions.append(sub)
        return sub

    def unsubscribe(self, subscription: Subscription) -> None:
        """Remove a subscription."""
        self._subscriptions = [
            s for s in self._subscriptions if s.id != subscription.id
        ]

    async def replay(self, since_seq: int) -> list[dict[str, Any]]:
        """Replay events from the persistent log since the given sequence number."""
        return await self._log.replay(since_seq)
