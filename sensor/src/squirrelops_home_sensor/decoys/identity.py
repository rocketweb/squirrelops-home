"""Validation helpers for durable virtual decoy host identities."""

from __future__ import annotations

import re

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ALLOWED_SUFFIXES = (".localdomain", ".local")


def _validated_label_and_suffix(value: str) -> tuple[str, str]:
    """Return one valid DNS label and its supported optional suffix."""
    if not isinstance(value, str):
        raise ValueError("Hostname must be a string")

    hostname = value.strip().rstrip(".").lower()
    suffix = ""
    for candidate in _ALLOWED_SUFFIXES:
        if hostname.endswith(candidate):
            hostname = hostname[: -len(candidate)].rstrip(".")
            suffix = candidate
            break

    if not hostname:
        raise ValueError("Hostname is required")
    if "." in hostname:
        raise ValueError(
            "Hostname must be a single label, optionally followed by "
            ".local or .localdomain"
        )
    if not _DNS_LABEL.fullmatch(hostname):
        raise ValueError(
            "Hostname must be 1-63 letters, numbers, or hyphens and cannot "
            "start or end with a hyphen"
        )
    return hostname, suffix


def canonicalize_decoy_hostname(value: str) -> str:
    """Validate and preserve a bare, ``.local``, or ``.localdomain`` name."""
    label, suffix = _validated_label_and_suffix(value)
    return f"{label}{suffix}"


def canonicalize_local_hostname(value: str) -> str:
    """Return the mDNS-style ``.local`` form used for generated identities."""
    label, _suffix = _validated_label_and_suffix(value)
    return f"{label}.local"


def mdns_label(hostname: str) -> str:
    """Return the one-label mDNS identity for any supported durable hostname."""
    label, _suffix = _validated_label_and_suffix(hostname)
    return label
