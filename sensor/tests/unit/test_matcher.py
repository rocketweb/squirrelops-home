"""Unit tests for fingerprint matcher with tiered matching."""

from __future__ import annotations

import pytest

from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint
from squirrelops_home_sensor.fingerprint.matcher import (
    match_device,
    levenshtein_similarity,
    jaccard_similarity,
    KnownDevice,
)


# ---------------------------------------------------------------------------
# Similarity function tests
# ---------------------------------------------------------------------------

class TestLevenshteinSimilarity:
    """Normalized Levenshtein similarity for mDNS hostname comparison."""

    def test_identical_strings(self) -> None:
        assert levenshtein_similarity("macbook-pro", "macbook-pro") == 1.0

    def test_completely_different(self) -> None:
        result = levenshtein_similarity("aaa", "zzz")
        assert result == 0.0

    def test_similar_strings(self) -> None:
        # "macbook-pro" vs "macbook-pro-2" -- edit distance 2, max len 13
        result = levenshtein_similarity("macbook-pro", "macbook-pro-2")
        assert 0.8 <= result <= 0.9

    def test_empty_strings(self) -> None:
        assert levenshtein_similarity("", "") == 1.0

    def test_one_empty(self) -> None:
        assert levenshtein_similarity("abc", "") == 0.0

    def test_case_matters(self) -> None:
        # Inputs should be pre-normalized, but similarity is case-sensitive
        result = levenshtein_similarity("abc", "ABC")
        assert result == 0.0

    def test_suffix_change(self) -> None:
        # sarahs-iphone vs sarahs-iphone-2
        result = levenshtein_similarity("sarahs-iphone", "sarahs-iphone-2")
        assert result >= 0.85


class TestJaccardSimilarity:
    """Jaccard similarity for set-based signal comparison."""

    def test_identical_sets(self) -> None:
        assert jaccard_similarity({"a", "b", "c"}, {"a", "b", "c"}) == 1.0

    def test_disjoint_sets(self) -> None:
        assert jaccard_similarity({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self) -> None:
        # {a,b,c} intersection {b,c,d} = {b,c}, union = {a,b,c,d} -> 2/4 = 0.5
        assert jaccard_similarity({"a", "b", "c"}, {"b", "c", "d"}) == 0.5

    def test_empty_sets(self) -> None:
        assert jaccard_similarity(set(), set()) == 0.0

    def test_one_empty(self) -> None:
        assert jaccard_similarity({"a"}, set()) == 0.0

    def test_subset(self) -> None:
        # {a,b} intersection {a,b,c} = {a,b}, union = {a,b,c} -> 2/3
        result = jaccard_similarity({"a", "b"}, {"a", "b", "c"})
        assert abs(result - 2 / 3) < 1e-9


# ---------------------------------------------------------------------------
# match_device tests
# ---------------------------------------------------------------------------

class TestMatchDeviceExactMatch:
    """Test exact composite hash match (fast path)."""

    def test_exact_composite_hash_match(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
            connection_pattern_hash="conn456",
            open_ports_hash="ports789",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=fp,
                connection_destinations=frozenset({"8.8.8.8:443", "1.1.1.1:53"}),
                open_ports=frozenset({80, 443}),
            ),
        ]
        device_id, confidence = match_device(
            fp,
            known,
            connection_destinations=frozenset({"8.8.8.8:443", "1.1.1.1:53"}),
            open_ports=frozenset({80, 443}),
        )
        assert device_id == 1
        assert confidence >= 0.75


class TestMatchDeviceTwoSignalMatch:
    """Two non-MAC signals above threshold produces a strong match."""

    def test_mdns_and_dhcp_match(self) -> None:
        new_fp = CompositeFingerprint(
            mac_address="11:22:33:44:55:66",  # Different MAC
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
        )
        known_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset(),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        assert device_id == 1
        # 2 strong matches (mDNS + DHCP) -- confidence not capped at 0.50
        assert confidence > 0.50


class TestMatchDeviceOneSignalCapped:
    """One non-MAC signal match caps confidence at 0.50."""

    def test_single_mdns_match(self) -> None:
        new_fp = CompositeFingerprint(
            mac_address="11:22:33:44:55:66",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="different_dhcp",
        )
        known_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset(),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        assert device_id == 1
        assert confidence <= 0.50


class TestMatchDeviceNoMatch:
    """No signals match -- returns None."""

    def test_completely_different(self) -> None:
        new_fp = CompositeFingerprint(
            mac_address="11:22:33:44:55:66",
            mdns_hostname="totally-different",
            dhcp_fingerprint_hash="different_dhcp",
        )
        known_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset(),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        assert device_id is None
        assert confidence == 0.0


class TestMatchDeviceTieBreaking:
    """When multiple devices match, pick highest confidence."""

    def test_picks_highest_confidence(self) -> None:
        new_fp = CompositeFingerprint(
            mac_address="11:22:33:44:55:66",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
            open_ports_hash="ports789",
        )
        known1_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:01",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp123",
            open_ports_hash="ports789",
        )
        # known2 only matches on mDNS (weaker)
        known2_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:02",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="other_dhcp",
            open_ports_hash="other_ports",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known1_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset({80, 443, 22}),
            ),
            KnownDevice(
                device_id=2,
                fingerprint=known2_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset({8080}),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset({80, 443, 22}),
        )
        assert device_id == 1


class TestMatchDeviceMacShortcut:
    """Exact MAC + any 1 other signal = auto-approve."""

    def test_mac_plus_mdns(self) -> None:
        new_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
        )
        known_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset(),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        assert device_id == 1
        assert confidence >= 0.75

    def test_mac_plus_dhcp(self) -> None:
        new_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            dhcp_fingerprint_hash="dhcp123",
        )
        known_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            dhcp_fingerprint_hash="dhcp123",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset(),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        assert device_id == 1
        assert confidence >= 0.75

    def test_mac_only_no_shortcut(self) -> None:
        """MAC alone without any other matching signal does not trigger shortcut."""
        new_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
        )
        known_fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
        )
        known = [
            KnownDevice(
                device_id=1,
                fingerprint=known_fp,
                connection_destinations=frozenset(),
                open_ports=frozenset(),
            ),
        ]
        device_id, confidence = match_device(
            new_fp,
            known,
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        # MAC only -> 1 signal (MAC itself), capped at 0.50
        assert confidence <= 0.50


class TestMatchDeviceEmptyKnown:
    """Empty known devices list returns no match."""

    def test_no_known_devices(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
        )
        device_id, confidence = match_device(
            fp,
            [],
            connection_destinations=frozenset(),
            open_ports=frozenset(),
        )
        assert device_id is None
        assert confidence == 0.0
