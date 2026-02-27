"""DNS canary manager — tracks canary hostnames and records observations.

Canary hostnames are embedded in planted credentials. When an attacker
uses a stolen credential that triggers a DNS lookup (AWS keys, GitHub
PATs, HA tokens), the DNS query for the canary hostname is detected
by the DNSMonitor and matched here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class CanaryManager:
    """Manages canary hostnames and matches DNS queries against them.

    Canary hostnames are loaded at startup and can be dynamically added/removed.
    Each hostname maps to a credential_id for tracing back to the planted
    credential that was compromised.

    Args:
        hostnames: Initial set of known canary hostnames.
    """

    def __init__(self, hostnames: set[str]) -> None:
        # Store lowercased for case-insensitive matching
        self._hostnames: set[str] = {h.lower() for h in hostnames}
        self._credential_map: dict[str, int] = {}

    @property
    def hostnames(self) -> set[str]:
        """Return the current set of tracked canary hostnames."""
        return set(self._hostnames)

    def add_hostname(self, hostname: str) -> None:
        """Add a canary hostname to the tracking set."""
        self._hostnames.add(hostname.lower())

    def remove_hostname(self, hostname: str) -> None:
        """Remove a canary hostname from the tracking set."""
        self._hostnames.discard(hostname.lower())

    def register_credential(self, hostname: str, credential_id: int) -> None:
        """Map a canary hostname to its planted credential ID.

        This enables tracing a DNS canary hit back to the specific
        credential that was compromised.
        """
        normalized = hostname.lower().rstrip(".")
        self._hostnames.add(normalized)
        self._credential_map[normalized] = credential_id

    def get_credential_id(self, hostname: str) -> Optional[int]:
        """Return the credential ID for a canary hostname, or None."""
        normalized = hostname.lower().rstrip(".")
        return self._credential_map.get(normalized)

    def check_query(self, query_name: str) -> bool:
        """Check if a DNS query name matches a known canary hostname.

        Strips trailing dots (common in DNS wire format) and performs
        case-insensitive comparison.

        Args:
            query_name: The DNS query name to check.

        Returns:
            True if the query matches a known canary hostname.
        """
        normalized = query_name.lower().rstrip(".")
        return normalized in self._hostnames

    def record_observation(
        self,
        hostname: str,
        queried_by_ip: str,
        queried_by_mac: Optional[str] = None,
    ) -> dict:
        """Record a canary DNS observation.

        Returns an observation dict suitable for persisting to
        the canary_observations table and including in event payloads.

        Args:
            hostname: The canary hostname that was queried.
            queried_by_ip: IP address of the host that made the DNS query.
            queried_by_mac: MAC address, if known.

        Returns:
            Dict with observation details.
        """
        normalized = hostname.lower().rstrip(".")
        now = datetime.now(timezone.utc)
        credential_id = self.get_credential_id(normalized)

        observation = {
            "hostname": normalized,
            "queried_by_ip": queried_by_ip,
            "queried_by_mac": queried_by_mac,
            "credential_id": credential_id,
            "observed_at": now,
        }

        logger.warning(
            "Canary DNS hit: %s queried by %s (credential_id=%s)",
            normalized,
            queried_by_ip,
            credential_id,
        )

        return observation
