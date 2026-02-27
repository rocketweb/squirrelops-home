"""Unit tests for fingerprint signal extractors."""

from __future__ import annotations

import hashlib

import pytest

from squirrelops_home_sensor.fingerprint.signals import (
    normalize_mac,
    normalize_mdns,
    hash_dhcp_options,
    hash_connection_pattern,
    hash_open_ports,
)


# ---------------------------------------------------------------------------
# MAC normalization
# ---------------------------------------------------------------------------

class TestNormalizeMac:
    """normalize_mac must produce uppercase, colon-separated format."""

    def test_already_normalized(self) -> None:
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_lowercase_input(self) -> None:
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_mixed_case(self) -> None:
        assert normalize_mac("aA:Bb:cC:Dd:eE:fF") == "AA:BB:CC:DD:EE:FF"

    def test_dash_separated(self) -> None:
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator(self) -> None:
        assert normalize_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    def test_dot_separated_cisco(self) -> None:
        assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

    def test_whitespace_stripped(self) -> None:
        assert normalize_mac("  aa:bb:cc:dd:ee:ff  ") == "AA:BB:CC:DD:EE:FF"

    def test_invalid_mac_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("not-a-mac")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("")

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("AA:BB:CC")

    def test_unpadded_octets(self) -> None:
        """ARP scanners may return single-digit hex octets like 'a' instead of '0a'."""
        assert normalize_mac("ae:29:a:e5:cc:c5") == "AE:29:0A:E5:CC:C5"

    def test_unpadded_leading_zeros(self) -> None:
        """MACs with leading zero octets like '0:8:9b:ce:b6:fd'."""
        assert normalize_mac("0:8:9b:ce:b6:fd") == "00:08:9B:CE:B6:FD"

    def test_unpadded_mixed(self) -> None:
        """Mix of padded and unpadded octets."""
        assert normalize_mac("60:c4:18:7:67:f3") == "60:C4:18:07:67:F3"


# ---------------------------------------------------------------------------
# mDNS hostname normalization
# ---------------------------------------------------------------------------

class TestNormalizeMdns:
    """normalize_mdns must lowercase, strip .local, collapse hyphens."""

    def test_simple_hostname(self) -> None:
        assert normalize_mdns("macbook-pro") == "macbook-pro"

    def test_strips_dot_local(self) -> None:
        assert normalize_mdns("macbook-pro.local") == "macbook-pro"

    def test_strips_dot_local_trailing_dot(self) -> None:
        assert normalize_mdns("macbook-pro.local.") == "macbook-pro"

    def test_lowercases(self) -> None:
        assert normalize_mdns("MacBook-Pro.local") == "macbook-pro"

    def test_collapses_consecutive_hyphens(self) -> None:
        assert normalize_mdns("sarah---iphone.local") == "sarah-iphone"

    def test_combined_normalization(self) -> None:
        assert normalize_mdns("Sarah's--iPhone.local.") == "sarah's-iphone"

    def test_already_normalized(self) -> None:
        assert normalize_mdns("mydevice") == "mydevice"

    def test_whitespace_stripped(self) -> None:
        assert normalize_mdns("  mydevice.local  ") == "mydevice"

    def test_empty_after_stripping(self) -> None:
        assert normalize_mdns(".local") == ""

    def test_preserves_numbers(self) -> None:
        assert normalize_mdns("iPhone-14-2.local") == "iphone-14-2"


# ---------------------------------------------------------------------------
# DHCP fingerprint hash
# ---------------------------------------------------------------------------

class TestHashDhcpOptions:
    """hash_dhcp_options must SHA-256 sorted comma-joined option integers."""

    def test_sorted_options(self) -> None:
        result = hash_dhcp_options([53, 1, 3, 6, 15, 28, 51])
        expected_input = "1,3,6,15,28,51,53"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_already_sorted(self) -> None:
        result = hash_dhcp_options([1, 3, 6])
        expected_input = "1,3,6"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_single_option(self) -> None:
        result = hash_dhcp_options([53])
        expected_input = "53"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_empty_options(self) -> None:
        result = hash_dhcp_options([])
        expected_input = ""
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_duplicate_options_preserved(self) -> None:
        # Duplicates in DHCP options are unusual but should be handled
        result = hash_dhcp_options([53, 53, 1])
        expected_input = "1,53,53"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_deterministic(self) -> None:
        r1 = hash_dhcp_options([6, 3, 1])
        r2 = hash_dhcp_options([1, 6, 3])
        assert r1 == r2


# ---------------------------------------------------------------------------
# Connection pattern hash
# ---------------------------------------------------------------------------

class TestHashConnectionPattern:
    """hash_connection_pattern must SHA-256 sorted ip:port strings."""

    def test_basic_connections(self) -> None:
        conns = [("8.8.8.8", 443), ("1.1.1.1", 53)]
        result = hash_connection_pattern(conns)
        expected_input = "1.1.1.1:53,8.8.8.8:443"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_single_connection(self) -> None:
        conns = [("192.168.1.1", 80)]
        result = hash_connection_pattern(conns)
        expected_input = "192.168.1.1:80"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_empty_connections(self) -> None:
        result = hash_connection_pattern([])
        expected_input = ""
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_deterministic_regardless_of_order(self) -> None:
        r1 = hash_connection_pattern([("8.8.8.8", 443), ("1.1.1.1", 53)])
        r2 = hash_connection_pattern([("1.1.1.1", 53), ("8.8.8.8", 443)])
        assert r1 == r2

    def test_different_ports_different_hash(self) -> None:
        r1 = hash_connection_pattern([("8.8.8.8", 443)])
        r2 = hash_connection_pattern([("8.8.8.8", 80)])
        assert r1 != r2


# ---------------------------------------------------------------------------
# Open ports hash
# ---------------------------------------------------------------------------

class TestHashOpenPorts:
    """hash_open_ports must SHA-256 sorted comma-joined port integers."""

    def test_basic_ports(self) -> None:
        result = hash_open_ports([443, 80, 22])
        expected_input = "22,80,443"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_single_port(self) -> None:
        result = hash_open_ports([8080])
        expected_input = "8080"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_empty_ports(self) -> None:
        result = hash_open_ports([])
        expected_input = ""
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected

    def test_deterministic_regardless_of_order(self) -> None:
        r1 = hash_open_ports([443, 80, 22])
        r2 = hash_open_ports([22, 443, 80])
        assert r1 == r2

    def test_duplicate_ports_preserved(self) -> None:
        result = hash_open_ports([80, 80, 443])
        expected_input = "80,80,443"
        expected = hashlib.sha256(expected_input.encode()).hexdigest()
        assert result == expected
