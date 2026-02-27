"""Abstract base class for agent module plugins.

Every plugin must subclass ``BaseAgentModule`` and implement the four
lifecycle methods: ``setup``, ``start``, ``stop``, and ``health_check``.
Plugins must also declare class-level ``name`` and ``version`` attributes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseAgentModule(ABC):
    """Base class that all SquirrelOps agent modules must extend.

    Class attributes:
        name:    Short identifier for the plugin (e.g. ``"ghostcrew"``).
        version: SemVer string (e.g. ``"1.2.0"``).
    """

    name: str
    version: str

    @abstractmethod
    async def setup(
        self,
        config: dict[str, Any],
        db: Any,
        event_bus: Any,
    ) -> None:
        """Initialise the plugin with shared resources.

        Called once after the plugin is loaded but before ``start()``.
        """

    @abstractmethod
    async def start(self) -> None:
        """Begin the plugin's background work (scans, listeners, etc.)."""

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully shut down; release resources."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return ``True`` if the plugin is operating normally."""
