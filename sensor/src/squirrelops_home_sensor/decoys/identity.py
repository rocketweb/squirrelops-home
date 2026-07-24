"""Validation helpers for durable virtual decoy host identities."""

from __future__ import annotations

import re

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def canonicalize_local_hostname(value: str) -> str:
    """Validate one DNS label and return its canonical ``.local`` hostname."""
    if not isinstance(value, str):
        raise ValueError("Hostname must be a string")
    hostname = value.strip().rstrip(".").lower()
    if hostname.endswith(".local"):
        hostname = hostname[:-6].rstrip(".")
    if not hostname:
        raise ValueError("Hostname is required")
    if "." in hostname:
        raise ValueError("Hostname must be a single label with optional .local")
    if not _DNS_LABEL.fullmatch(hostname):
        raise ValueError(
            "Hostname must be 1-63 letters, numbers, or hyphens and cannot "
            "start or end with a hyphen"
        )
    return f"{hostname}.local"


def mdns_label(hostname: str) -> str:
    """Return the service-advertisement label for a canonical hostname."""
    return canonicalize_local_hostname(hostname).removesuffix(".local")
