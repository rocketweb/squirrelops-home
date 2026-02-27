"""Composite fingerprint computation from individual signals.

A composite fingerprint aggregates all available signals for a device
into a single structure with a combined hash. The composite_hash is
used for quick exact-match lookups, while individual signals support
fuzzy matching via the matcher module.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from squirrelops_home_sensor.fingerprint.signals import (
    normalize_mac,
    normalize_mdns,
    hash_dhcp_options,
    hash_connection_pattern,
    hash_open_ports,
)


@dataclass(frozen=True)
class CompositeFingerprint:
    """Aggregated device fingerprint from all available signals.

    All signal fields are optional -- a fingerprint is valid with any
    subset of signals present. The ``signal_count`` and ``composite_hash``
    properties are derived from whichever signals are non-null.
    """

    mac_address: str | None = None
    mdns_hostname: str | None = None
    dhcp_fingerprint_hash: str | None = None
    connection_pattern_hash: str | None = None
    open_ports_hash: str | None = None

    @property
    def signal_count(self) -> int:
        """Return the number of non-null signals."""
        return sum(
            1
            for val in (
                self.mac_address,
                self.mdns_hostname,
                self.dhcp_fingerprint_hash,
                self.connection_pattern_hash,
                self.open_ports_hash,
            )
            if val is not None
        )

    @property
    def composite_hash(self) -> str | None:
        """Return SHA-256 of all non-null signal values concatenated in field order.

        Returns None if no signals are present.
        """
        parts = [
            val
            for val in (
                self.mac_address,
                self.mdns_hostname,
                self.dhcp_fingerprint_hash,
                self.connection_pattern_hash,
                self.open_ports_hash,
            )
            if val is not None
        ]
        if not parts:
            return None
        concat = "".join(parts)
        return hashlib.sha256(concat.encode()).hexdigest()


def compute_fingerprint(
    mac: str | None,
    mdns_hostname: str | None,
    dhcp_options: list[int] | None,
    connections: list[tuple[str, int]] | None,
    open_ports: list[int] | None,
) -> CompositeFingerprint:
    """Compute a composite fingerprint from raw signal data.

    Normalizes each signal using the appropriate extractor from
    ``signals.py`` and assembles a ``CompositeFingerprint``.

    Parameters
    ----------
    mac:
        Raw MAC address string, or None if unavailable.
    mdns_hostname:
        Raw mDNS hostname, or None if unavailable.
    dhcp_options:
        List of DHCP option numbers, or None if unavailable.
    connections:
        List of (ip, port) tuples for outbound connections, or None.
    open_ports:
        List of open port numbers, or None.

    Returns
    -------
    CompositeFingerprint:
        The assembled fingerprint with normalized signals and hashes.
    """
    normalized_mac = normalize_mac(mac) if mac is not None else None
    normalized_mdns = normalize_mdns(mdns_hostname) if mdns_hostname is not None else None
    dhcp_hash = hash_dhcp_options(dhcp_options) if dhcp_options is not None else None
    conn_hash = hash_connection_pattern(connections) if connections is not None else None
    ports_hash = hash_open_ports(open_ports) if open_ports is not None else None

    return CompositeFingerprint(
        mac_address=normalized_mac,
        mdns_hostname=normalized_mdns,
        dhcp_fingerprint_hash=dhcp_hash,
        connection_pattern_hash=conn_hash,
        open_ports_hash=ports_hash,
    )
