"""Fingerprint matcher with tiered matching and confidence scoring.

Implements the matching algorithm from the spec: min 2 non-MAC signal
agreement for a strong match, 1-signal match capped at 0.50, and a
MAC shortcut for exact MAC + any 1 other signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

# Signal weights (must sum to 1.0)
DEFAULT_WEIGHTS: dict[str, float] = {
    "mdns": 0.30,
    "dhcp": 0.25,
    "connections": 0.25,
    "mac": 0.10,
    "ports": 0.10,
}

# Minimum similarity for a signal to count as a "strong match"
SIGNAL_THRESHOLD = 0.70


# ---------------------------------------------------------------------------
# Known device container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KnownDevice:
    """Represents a previously-identified device with its latest fingerprint.

    Parameters
    ----------
    device_id:
        Unique device identifier from the database.
    fingerprint:
        The latest composite fingerprint for this device.
    connection_destinations:
        Set of "ip:port" strings for Jaccard comparison of connection patterns.
    open_ports:
        Set of port numbers for Jaccard comparison of open ports.
    """

    device_id: int
    fingerprint: CompositeFingerprint
    connection_destinations: frozenset[str] = field(default_factory=frozenset)
    open_ports: frozenset[int] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Similarity functions
# ---------------------------------------------------------------------------

def levenshtein_similarity(a: str, b: str) -> float:
    """Compute normalized Levenshtein similarity between two strings.

    Returns a value in [0.0, 1.0] where 1.0 means identical strings.
    Uses the standard dynamic programming algorithm.
    """
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0

    len_a = len(a)
    len_b = len(b)

    # Build DP matrix
    # prev and curr rows of the edit distance matrix
    prev = list(range(len_b + 1))
    curr = [0] * (len_b + 1)

    for i in range(1, len_a + 1):
        curr[0] = i
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,      # deletion
                curr[j - 1] + 1,  # insertion
                prev[j - 1] + cost,  # substitution
            )
        prev, curr = curr, [0] * (len_b + 1)

    distance = prev[len_b]
    max_len = max(len_a, len_b)
    return 1.0 - (distance / max_len)


def jaccard_similarity(set_a: set | frozenset, set_b: set | frozenset) -> float:
    """Compute Jaccard similarity between two sets.

    Returns |A intersection B| / |A union B|, or 0.0 if both sets are empty.
    """
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


# ---------------------------------------------------------------------------
# Matching algorithm
# ---------------------------------------------------------------------------

def match_device(
    new_fp: CompositeFingerprint,
    known_devices: list[KnownDevice],
    connection_destinations: frozenset[str] | None = None,
    open_ports: frozenset[int] | None = None,
    weights: dict[str, float] | None = None,
    signal_threshold: float = SIGNAL_THRESHOLD,
) -> tuple[int | None, float]:
    """Match a new fingerprint against known devices.

    Implements tiered matching:
    - 2+ non-MAC signals above threshold -> strong match (full confidence)
    - 1 non-MAC signal above threshold -> capped at 0.50
    - MAC shortcut: exact MAC + any 1 other signal above threshold -> auto-approve (>= 0.75)
    - No matches -> (None, 0.0)

    Parameters
    ----------
    new_fp:
        The fingerprint of the newly-observed device.
    known_devices:
        List of previously-identified devices with their fingerprints.
    connection_destinations:
        Set of "ip:port" strings for the new device's connection pattern.
    open_ports:
        Set of port numbers for the new device's open ports.
    weights:
        Signal weight overrides. Defaults to ``DEFAULT_WEIGHTS``.
    signal_threshold:
        Minimum similarity for a signal to count as a strong match.

    Returns
    -------
    tuple[int | None, float]:
        (device_id, confidence) or (None, 0.0) if no match.
    """
    if not known_devices:
        return (None, 0.0)

    w = weights or DEFAULT_WEIGHTS
    conn_dests = connection_destinations or frozenset()
    new_ports = open_ports or frozenset()

    candidates: list[tuple[int, float]] = []

    for known in known_devices:
        signal_scores: dict[str, float] = {}
        kfp = known.fingerprint

        # MAC comparison (exact match: 0 or 1)
        if new_fp.mac_address is not None and kfp.mac_address is not None:
            signal_scores["mac"] = 1.0 if new_fp.mac_address == kfp.mac_address else 0.0

        # mDNS comparison (normalized Levenshtein)
        if new_fp.mdns_hostname is not None and kfp.mdns_hostname is not None:
            signal_scores["mdns"] = levenshtein_similarity(
                new_fp.mdns_hostname, kfp.mdns_hostname
            )

        # DHCP comparison (exact hash match: 0 or 1)
        if new_fp.dhcp_fingerprint_hash is not None and kfp.dhcp_fingerprint_hash is not None:
            signal_scores["dhcp"] = (
                1.0 if new_fp.dhcp_fingerprint_hash == kfp.dhcp_fingerprint_hash else 0.0
            )

        # Connection pattern comparison (Jaccard similarity)
        if new_fp.connection_pattern_hash is not None and kfp.connection_pattern_hash is not None:
            signal_scores["connections"] = jaccard_similarity(
                conn_dests, known.connection_destinations
            )

        # Open ports comparison (Jaccard similarity)
        if new_fp.open_ports_hash is not None and kfp.open_ports_hash is not None:
            signal_scores["ports"] = jaccard_similarity(new_ports, known.open_ports)

        if not signal_scores:
            continue

        # Count strong non-MAC matches
        strong_non_mac = sum(
            1
            for signal, score in signal_scores.items()
            if signal != "mac" and score >= signal_threshold
        )

        # Check MAC shortcut: exact MAC + any 1 other signal above threshold
        mac_exact = signal_scores.get("mac", 0.0) == 1.0
        has_other_strong = strong_non_mac >= 1

        if mac_exact and has_other_strong:
            # MAC shortcut: auto-approve with high confidence
            confidence = _weighted_average(signal_scores, w)
            confidence = max(confidence, 0.75)  # Floor at auto-approve threshold
            candidates.append((known.device_id, confidence))
        elif strong_non_mac >= 2:
            # Strong match: 2+ non-MAC signals agree
            confidence = _weighted_average(signal_scores, w)
            candidates.append((known.device_id, confidence))
        elif strong_non_mac == 1:
            # Weak match: only 1 non-MAC signal -- cap at 0.50
            confidence = min(_weighted_average(signal_scores, w), 0.50)
            candidates.append((known.device_id, confidence))
        # else: no strong matches at all -> skip this known device

    if not candidates:
        return (None, 0.0)

    # Tie-breaking: pick highest confidence
    best = max(candidates, key=lambda c: c[1])
    return best


def _weighted_average(
    signal_scores: dict[str, float],
    weights: dict[str, float],
) -> float:
    """Compute weighted average of signal scores.

    Only signals present in ``signal_scores`` contribute. Weights are
    re-normalized to sum to 1.0 over the available signals.
    """
    total_weight = 0.0
    weighted_sum = 0.0

    for signal, score in signal_scores.items():
        w = weights.get(signal, 0.0)
        weighted_sum += score * w
        total_weight += w

    if total_weight == 0.0:
        return 0.0

    return weighted_sum / total_weight
