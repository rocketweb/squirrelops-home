"""Unit tests for device signature database (OUI, DHCP, mDNS patterns)."""

from __future__ import annotations

import json
import pathlib

import pytest

from squirrelops_home_sensor.devices.signatures import (
    SignatureDB,
    DeviceClassification,
)


SENSOR_ROOT = pathlib.Path(__file__).resolve().parents[2]
SIGNATURES_PATH = SENSOR_ROOT / "signatures" / "device_signatures.json"


# ---------------------------------------------------------------------------
# Signature DB loading
# ---------------------------------------------------------------------------

class TestSignatureDBLoading:
    """Verify the signature database loads and validates correctly."""

    def test_loads_from_default_path(self) -> None:
        db = SignatureDB.load(SIGNATURES_PATH)
        assert db is not None

    def test_loads_from_explicit_path(self, tmp_path: pathlib.Path) -> None:
        sig_file = tmp_path / "sigs.json"
        sig_file.write_text(json.dumps({
            "oui_prefixes": {"AA:BB:CC": {"manufacturer": "TestCo", "device_type": "router"}},
            "dhcp_fingerprints": {},
            "mdns_patterns": [],
        }))
        db = SignatureDB.load(sig_file)
        assert db is not None

    def test_signature_file_exists(self) -> None:
        assert SIGNATURES_PATH.exists(), "signatures/device_signatures.json must exist"

    def test_signature_file_is_valid_json(self) -> None:
        data = json.loads(SIGNATURES_PATH.read_text())
        assert "oui_prefixes" in data
        assert "dhcp_fingerprints" in data
        assert "mdns_patterns" in data


# ---------------------------------------------------------------------------
# OUI lookup
# ---------------------------------------------------------------------------

class TestOUILookup:
    """Verify OUI prefix-based manufacturer/device type lookup."""

    @pytest.fixture
    def db(self) -> SignatureDB:
        return SignatureDB.load(SIGNATURES_PATH)

    def test_apple_oui(self, db: SignatureDB) -> None:
        result = db.lookup_oui("A4:83:E7:11:22:33")  # Apple OUI
        assert result is not None
        assert result.manufacturer == "Apple"

    def test_unknown_oui(self, db: SignatureDB) -> None:
        result = db.lookup_oui("02:00:00:00:00:00")  # Locally administered
        assert result is None

    def test_case_insensitive(self, db: SignatureDB) -> None:
        result = db.lookup_oui("a4:83:e7:11:22:33")
        assert result is not None
        assert result.manufacturer == "Apple"

    def test_returns_device_type(self, db: SignatureDB) -> None:
        result = db.lookup_oui("A4:83:E7:11:22:33")
        assert result is not None
        assert result.device_type is not None

    def test_confidence_between_0_and_1(self, db: SignatureDB) -> None:
        result = db.lookup_oui("A4:83:E7:11:22:33")
        assert result is not None
        assert 0.0 < result.confidence <= 1.0


# ---------------------------------------------------------------------------
# DHCP fingerprint matching
# ---------------------------------------------------------------------------

class TestDHCPMatch:
    """Verify DHCP fingerprint hash matching."""

    @pytest.fixture
    def db(self) -> SignatureDB:
        return SignatureDB.load(SIGNATURES_PATH)

    def test_known_dhcp_fingerprint(self, db: SignatureDB) -> None:
        # Use a fingerprint hash from the signature file
        data = json.loads(SIGNATURES_PATH.read_text())
        if data["dhcp_fingerprints"]:
            first_hash = next(iter(data["dhcp_fingerprints"]))
            result = db.match_dhcp(first_hash)
            assert result is not None
            assert result.manufacturer is not None

    def test_unknown_dhcp_fingerprint(self, db: SignatureDB) -> None:
        result = db.match_dhcp("0000000000000000000000000000000000000000000000000000000000000000")
        assert result is None

    def test_dhcp_match_has_confidence(self, db: SignatureDB) -> None:
        data = json.loads(SIGNATURES_PATH.read_text())
        if data["dhcp_fingerprints"]:
            first_hash = next(iter(data["dhcp_fingerprints"]))
            result = db.match_dhcp(first_hash)
            assert result is not None
            assert 0.0 < result.confidence <= 1.0


# ---------------------------------------------------------------------------
# mDNS pattern matching
# ---------------------------------------------------------------------------

class TestMDNSPatternMatch:
    """Verify mDNS hostname regex pattern matching."""

    @pytest.fixture
    def db(self) -> SignatureDB:
        return SignatureDB.load(SIGNATURES_PATH)

    def test_apple_iphone_pattern(self, db: SignatureDB) -> None:
        result = db.match_mdns("sarahs-iphone")
        assert result is not None
        assert result.manufacturer == "Apple"
        assert "phone" in result.device_type.lower() or "iphone" in result.device_type.lower()

    def test_apple_macbook_pattern(self, db: SignatureDB) -> None:
        result = db.match_mdns("matts-macbook-pro")
        assert result is not None
        assert result.manufacturer == "Apple"

    def test_no_match(self, db: SignatureDB) -> None:
        result = db.match_mdns("xyzzy-unknown-device-12345")
        assert result is None

    def test_mdns_match_has_confidence(self, db: SignatureDB) -> None:
        result = db.match_mdns("sarahs-iphone")
        assert result is not None
        assert 0.0 < result.confidence <= 1.0

    def test_raspberry_pi_pattern(self, db: SignatureDB) -> None:
        result = db.match_mdns("raspberrypi")
        assert result is not None
        assert result.manufacturer == "Raspberry Pi"


# ---------------------------------------------------------------------------
# DeviceClassification dataclass
# ---------------------------------------------------------------------------

class TestDeviceClassification:
    """Verify the classification result structure."""

    def test_fields(self) -> None:
        c = DeviceClassification(
            manufacturer="Apple",
            device_type="smartphone",
            model="iPhone",
            confidence=0.85,
            source="oui",
        )
        assert c.manufacturer == "Apple"
        assert c.device_type == "smartphone"
        assert c.model == "iPhone"
        assert c.confidence == 0.85
        assert c.source == "oui"

    def test_optional_model(self) -> None:
        c = DeviceClassification(
            manufacturer="Unknown",
            device_type="unknown",
            confidence=0.10,
            source="fallback",
        )
        assert c.model is None


# ---------------------------------------------------------------------------
# Two-layer OUI lookup (hand-curated + bulk IEEE OUI_DB fallback)
# ---------------------------------------------------------------------------

class TestTwoLayerOUILookup:
    """Verify two-layer OUI lookup: hand-curated first, then bulk OUI_DB fallback."""

    @pytest.fixture
    def db(self) -> SignatureDB:
        return SignatureDB.load(SIGNATURES_PATH)

    def test_hand_curated_still_works(self, db: SignatureDB) -> None:
        result = db.lookup_oui("A4:83:E7:11:22:33")  # Apple in hand-curated
        assert result is not None
        assert result.manufacturer == "Apple"
        assert result.confidence >= 0.50

    def test_hand_curated_wins_over_bulk(self, db: SignatureDB) -> None:
        result = db.lookup_oui("A4:83:E7:11:22:33")
        assert result is not None
        assert result.confidence >= 0.50  # Hand-curated confidence, not 0.40-0.45

    def test_bulk_fallback_resolves_unknown_prefix(self, db: SignatureDB) -> None:
        # 00:50:F2 is Microsoft — should be in IEEE OUI_DB but NOT in our 35-entry hand-curated list
        result = db.lookup_oui("00:50:F2:11:22:33")
        assert result is not None
        assert result.source == "oui"
        assert result.manufacturer != "Unknown"

    def test_bulk_fallback_has_lower_confidence(self, db: SignatureDB) -> None:
        result = db.lookup_oui("00:50:F2:11:22:33")
        assert result is not None
        assert result.confidence <= 0.45

    def test_truly_unknown_returns_none(self, db: SignatureDB) -> None:
        result = db.lookup_oui("02:00:00:00:00:00")  # Locally-administered
        assert result is None

    def test_bulk_with_known_type_gets_higher_confidence(self, db: SignatureDB) -> None:
        # Find a prefix in OUI_DB whose manufacturer is in MANUFACTURER_TYPES
        from squirrelops_home_sensor.devices.oui_db import OUI_DB, MANUFACTURER_TYPES
        test_prefix = None
        for prefix, mfr in OUI_DB.items():
            if mfr in MANUFACTURER_TYPES and prefix not in db._oui_prefixes:
                test_prefix = prefix
                break
        assert test_prefix is not None, "Should find a bulk OUI with known type"
        result = db.lookup_oui(f"{test_prefix}:11:22:33")
        assert result is not None
        assert result.confidence == 0.45
        assert result.device_type != "unknown"

    def test_bulk_with_unknown_type_gets_lower_confidence(self, db: SignatureDB) -> None:
        from squirrelops_home_sensor.devices.oui_db import OUI_DB, MANUFACTURER_TYPES
        test_prefix = None
        for prefix, mfr in OUI_DB.items():
            if mfr not in MANUFACTURER_TYPES and prefix not in db._oui_prefixes:
                test_prefix = prefix
                break
        assert test_prefix is not None, "Should find a bulk OUI with unknown type"
        result = db.lookup_oui(f"{test_prefix}:11:22:33")
        assert result is not None
        assert result.confidence == 0.40
        assert result.device_type == "unknown"
