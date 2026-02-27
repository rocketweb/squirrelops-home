"""Abstract interface for secret storage."""

from __future__ import annotations

from abc import ABC, abstractmethod


class SecretStore(ABC):
    """Abstract secret store. Implementations provide platform-specific storage.

    All methods are async to support both I/O-bound backends (file, network)
    and subprocess-based backends (macOS Keychain CLI).
    """

    @abstractmethod
    async def get(self, key: str) -> str | None:
        """Retrieve a secret by key. Returns None if not found."""

    @abstractmethod
    async def set(self, key: str, value: str) -> None:
        """Store or update a secret."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a secret. Does not raise if the key does not exist."""

    @abstractmethod
    async def list_keys(self) -> list[str]:
        """Return a list of all stored secret keys."""
