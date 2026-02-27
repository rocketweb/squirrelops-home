"""Base decoy class and connection event dataclass.

All decoy types (dev server, Home Assistant, file share) inherit from BaseDecoy
and implement its abstract lifecycle methods. Connection events flow through the
_notify_connection callback to the orchestrator for logging and alert generation.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable, Optional


@dataclasses.dataclass(frozen=True)
class DecoyConnectionEvent:
    """Immutable record of a single connection to a decoy service.

    Attributes:
        source_ip: IP address of the connecting client.
        source_port: Ephemeral port of the connecting client.
        dest_port: Port on the decoy that received the connection.
        protocol: Transport protocol (e.g. "tcp", "udp").
        timestamp: When the connection was observed (UTC).
        request_path: HTTP request path, if applicable.
        credential_used: Value of a planted credential detected in the request, if any.
    """

    source_ip: str
    source_port: int
    dest_port: int
    protocol: str
    timestamp: datetime
    request_path: Optional[str] = None
    credential_used: Optional[str] = None


class BaseDecoy(ABC):
    """Abstract base class for all decoy service types.

    Subclasses must implement:
        - start(): Launch the decoy service (may spawn threads).
        - stop(): Gracefully shut down the decoy service.
        - health_check(): Return True if the decoy is operational.
        - is_running (property): Whether the decoy is currently serving.

    The orchestrator registers a connection callback via the on_connection
    property. Subclasses call _notify_connection(event) when a client connects.
    """

    def __init__(
        self,
        decoy_id: int,
        name: str,
        port: int,
        bind_address: str = "127.0.0.1",
        decoy_type: str = "unknown",
    ) -> None:
        self.decoy_id = decoy_id
        self.name = name
        self.port = port
        self.bind_address = bind_address
        self.decoy_type = decoy_type
        self._on_connection: Optional[Callable[[DecoyConnectionEvent], None]] = None

    @property
    def on_connection(self) -> Optional[Callable[[DecoyConnectionEvent], None]]:
        """Get the registered connection callback."""
        return self._on_connection

    @on_connection.setter
    def on_connection(self, callback: Optional[Callable[[DecoyConnectionEvent], None]]) -> None:
        """Set the connection callback invoked on every client connection."""
        self._on_connection = callback

    def _notify_connection(self, event: DecoyConnectionEvent) -> None:
        """Invoke the registered connection callback, if any.

        Subclasses call this method from their request handlers whenever a
        client connects to the decoy service.
        """
        if self._on_connection is not None:
            self._on_connection(event)

    @abstractmethod
    async def start(self) -> None:
        """Start the decoy service. May spawn background threads."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the decoy service and release resources."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the decoy is healthy and accepting connections."""
        ...

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether the decoy service is currently running."""
        ...
