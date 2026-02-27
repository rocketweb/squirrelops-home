"""Signal extractors for device fingerprinting.

Each function extracts and normalizes a single signal from raw network
scan data. These signals feed into the composite fingerprinter.
"""

from __future__ import annotations

import hashlib
import re


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to uppercase colon-separated format.

    Accepts colon, dash, dot (Cisco), or no-separator formats.

    Parameters
    ----------
    mac:
        Raw MAC address string.

    Returns
    -------
    str:
        Normalized MAC in ``AA:BB:CC:DD:EE:FF`` format.

    Raises
    ------
    ValueError:
        If the input cannot be parsed as a valid MAC address.
    """
    mac = mac.strip()

    # Determine separator and split into octets
    if ":" in mac:
        parts = mac.split(":")
    elif "-" in mac:
        parts = mac.split("-")
    elif "." in mac:
        # Cisco format: aaaa.bbbb.cccc -> split into 3 groups of 4 hex chars
        groups = mac.split(".")
        if len(groups) == 3 and all(len(g) == 4 for g in groups):
            flat = "".join(groups).upper()
            if re.fullmatch(r"[0-9A-F]{12}", flat):
                return ":".join(flat[i : i + 2] for i in range(0, 12, 2))
        raise ValueError(f"Invalid MAC address: {mac!r}")
    else:
        # No separator — must be exactly 12 hex chars
        flat = mac.upper()
        if len(flat) != 12 or not re.fullmatch(r"[0-9A-F]{12}", flat):
            raise ValueError(f"Invalid MAC address: {mac!r}")
        return ":".join(flat[i : i + 2] for i in range(0, 12, 2))

    # Validate and zero-pad each octet (handles e.g. "a" -> "0A")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address: {mac!r}")

    padded = []
    for part in parts:
        if not part or len(part) > 2 or not re.fullmatch(r"[0-9A-Fa-f]+", part):
            raise ValueError(f"Invalid MAC address: {mac!r}")
        padded.append(part.upper().zfill(2))

    return ":".join(padded)


def normalize_mdns(hostname: str) -> str:
    """Normalize an mDNS hostname for fingerprint comparison.

    - Strips whitespace
    - Lowercases
    - Strips ``.local`` and ``.local.`` suffixes
    - Collapses consecutive hyphens into a single hyphen

    Parameters
    ----------
    hostname:
        Raw mDNS hostname string.

    Returns
    -------
    str:
        Normalized hostname.
    """
    hostname = hostname.strip().lower()

    # Strip .local. or .local suffix
    if hostname.endswith(".local."):
        hostname = hostname[: -len(".local.")]
    elif hostname.endswith(".local"):
        hostname = hostname[: -len(".local")]

    # Collapse consecutive hyphens
    hostname = re.sub(r"-{2,}", "-", hostname)

    return hostname


def hash_dhcp_options(options: list[int]) -> str:
    """Compute SHA-256 hash of a DHCP option set.

    Options are sorted numerically and joined with commas before hashing.
    This produces a stable hash regardless of the order options were observed.

    Parameters
    ----------
    options:
        List of DHCP option numbers.

    Returns
    -------
    str:
        Hex-encoded SHA-256 hash.
    """
    sorted_opts = sorted(options)
    data = ",".join(str(o) for o in sorted_opts)
    return hashlib.sha256(data.encode()).hexdigest()


def hash_connection_pattern(conns: list[tuple[str, int]]) -> str:
    """Compute SHA-256 hash of a connection pattern.

    Connections are formatted as ``ip:port``, sorted lexicographically,
    and joined with commas before hashing.

    Parameters
    ----------
    conns:
        List of (ip_address, port) tuples representing outbound connections
        observed during the first 120 seconds after device appearance.

    Returns
    -------
    str:
        Hex-encoded SHA-256 hash.
    """
    sorted_conns = sorted(f"{ip}:{port}" for ip, port in conns)
    data = ",".join(sorted_conns)
    return hashlib.sha256(data.encode()).hexdigest()


def hash_open_ports(ports: list[int]) -> str:
    """Compute SHA-256 hash of an open port set.

    Ports are sorted numerically and joined with commas before hashing.

    Parameters
    ----------
    ports:
        List of open port numbers.

    Returns
    -------
    str:
        Hex-encoded SHA-256 hash.
    """
    sorted_ports = sorted(ports)
    data = ",".join(str(p) for p in sorted_ports)
    return hashlib.sha256(data.encode()).hexdigest()
