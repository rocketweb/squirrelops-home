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
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable
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
            seq = await self._log.append(event_type, payload, source_id=source_id)

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

        return seq

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
