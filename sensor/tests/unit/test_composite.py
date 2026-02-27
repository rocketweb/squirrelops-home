"""Unit tests for composite fingerprint computation."""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from squirrelops_home_sensor.fingerprint.composite import (
    CompositeFingerprint,
    compute_fingerprint,
)


# ---------------------------------------------------------------------------
# CompositeFingerprint dataclass tests
# ---------------------------------------------------------------------------

class TestCompositeFingerprintDataclass:
    """Verify the CompositeFingerprint dataclass structure."""

    def test_is_dataclass(self) -> None:
        assert dataclasses.is_dataclass(CompositeFingerprint)

    def test_all_fields_present(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="abc123",
            connection_pattern_hash="def456",
            open_ports_hash="ghi789",
        )
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.mdns_hostname == "macbook-pro"
        assert fp.dhcp_fingerprint_hash == "abc123"
        assert fp.connection_pattern_hash == "def456"
        assert fp.open_ports_hash == "ghi789"

    def test_fields_default_to_none(self) -> None:
        fp = CompositeFingerprint()
        assert fp.mac_address is None
        assert fp.mdns_hostname is None
        assert fp.dhcp_fingerprint_hash is None
        assert fp.connection_pattern_hash is None
        assert fp.open_ports_hash is None

    def test_frozen(self) -> None:
        fp = CompositeFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        with pytest.raises(dataclasses.FrozenInstanceError):
            fp.mac_address = "changed"


# ---------------------------------------------------------------------------
# signal_count tests
# ---------------------------------------------------------------------------

class TestSignalCount:
    """Verify signal_count returns the number of non-null signals."""

    def test_all_signals(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="abc",
            connection_pattern_hash="def",
            open_ports_hash="ghi",
        )
        assert fp.signal_count == 5

    def test_partial_signals(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
        )
        assert fp.signal_count == 2

    def test_single_signal(self) -> None:
        fp = CompositeFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        assert fp.signal_count == 1

    def test_no_signals(self) -> None:
        fp = CompositeFingerprint()
        assert fp.signal_count == 0


# ---------------------------------------------------------------------------
# composite_hash tests
# ---------------------------------------------------------------------------

class TestCompositeHash:
    """Verify composite_hash is SHA-256 of concatenated non-null signal values."""

    def test_all_signals_hash(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            mdns_hostname="macbook-pro",
            dhcp_fingerprint_hash="dhcp_hash",
            connection_pattern_hash="conn_hash",
            open_ports_hash="ports_hash",
        )
        # Concatenate all non-null values in field order
        concat = "AA:BB:CC:DD:EE:FF" + "macbook-pro" + "dhcp_hash" + "conn_hash" + "ports_hash"
        expected = hashlib.sha256(concat.encode()).hexdigest()
        assert fp.composite_hash == expected

    def test_partial_signals_hash(self) -> None:
        fp = CompositeFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            dhcp_fingerprint_hash="dhcp_hash",
        )
        concat = "AA:BB:CC:DD:EE:FF" + "dhcp_hash"
        expected = hashlib.sha256(concat.encode()).hexdigest()
        assert fp.composite_hash == expected

    def test_single_signal_hash(self) -> None:
        fp = CompositeFingerprint(mdns_hostname="macbook-pro")
        concat = "macbook-pro"
        expected = hashlib.sha256(concat.encode()).hexdigest()
        assert fp.composite_hash == expected

    def test_no_signals_hash_is_none(self) -> None:
        fp = CompositeFingerprint()
        assert fp.composite_hash is None

    def test_hash_is_deterministic(self) -> None:
        fp1 = CompositeFingerprint(mac_address="AA:BB:CC:DD:EE:FF", mdns_hostname="test")
        fp2 = CompositeFingerprint(mac_address="AA:BB:CC:DD:EE:FF", mdns_hostname="test")
        assert fp1.composite_hash == fp2.composite_hash

    def test_different_signals_different_hash(self) -> None:
        fp1 = CompositeFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        fp2 = CompositeFingerprint(mac_address="11:22:33:44:55:66")
        assert fp1.composite_hash != fp2.composite_hash


# ---------------------------------------------------------------------------
# compute_fingerprint helper tests
# ---------------------------------------------------------------------------

class TestComputeFingerprint:
    """Verify the compute_fingerprint helper produces correct composites."""

    def test_full_signals(self) -> None:
        fp = compute_fingerprint(
            mac="aa:bb:cc:dd:ee:ff",
            mdns_hostname="MacBook-Pro.local",
            dhcp_options=[53, 1, 3, 6, 15],
            connections=[("8.8.8.8", 443), ("1.1.1.1", 53)],
            open_ports=[443, 80, 22],
        )
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.mdns_hostname == "macbook-pro"
        assert fp.dhcp_fingerprint_hash is not None
        assert fp.connection_pattern_hash is not None
        assert fp.open_ports_hash is not None
        assert fp.signal_count == 5

    def test_partial_signals(self) -> None:
        fp = compute_fingerprint(
            mac="aa:bb:cc:dd:ee:ff",
            mdns_hostname=None,
            dhcp_options=None,
            connections=None,
            open_ports=[80, 443],
        )
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.mdns_hostname is None
        assert fp.dhcp_fingerprint_hash is None
        assert fp.connection_pattern_hash is None
        assert fp.open_ports_hash is not None
        assert fp.signal_count == 2

    def test_single_signal_mac_only(self) -> None:
        fp = compute_fingerprint(
            mac="aa:bb:cc:dd:ee:ff",
            mdns_hostname=None,
            dhcp_options=None,
            connections=None,
            open_ports=None,
        )
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.signal_count == 1

    def test_no_mac(self) -> None:
        fp = compute_fingerprint(
            mac=None,
            mdns_hostname="my-device.local",
            dhcp_options=[1, 3, 6],
            connections=None,
            open_ports=None,
        )
        assert fp.mac_address is None
        assert fp.mdns_hostname == "my-device"
        assert fp.dhcp_fingerprint_hash is not None
        assert fp.signal_count == 2

    def test_all_none(self) -> None:
        fp = compute_fingerprint(
            mac=None,
            mdns_hostname=None,
            dhcp_options=None,
            connections=None,
            open_ports=None,
        )
        assert fp.signal_count == 0
        assert fp.composite_hash is None
