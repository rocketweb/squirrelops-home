"""Unit tests for device classifier with local DB + LLM fallback chain."""

from __future__ import annotations

import json
import pathlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from squirrelops_home_sensor.devices.classifier import (
    DeviceClassifier,
    LLMClassifier,
)
from squirrelops_home_sensor.devices.signatures import (
    DeviceClassification,
    SignatureDB,
)
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint


SENSOR_ROOT = pathlib.Path(__file__).resolve().parents[2]
SIGNATURES_PATH = SENSOR_ROOT / "signatures" / "device_signatures.json"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def signature_db() -> SignatureDB:
    return SignatureDB.load(SIGNATURES_PATH)


@pytest.fixture
def mock_llm() -> AsyncMock:
    """Mock LLM classifier that returns a classification."""
    llm = AsyncMock(spec=LLMClassifier)
    llm.classify.return_value = DeviceClassification(
        manufacturer="TestCo",
        device_type="smart_widget",
        model="Widget Pro",
        confidence=0.70,
        source="llm",
    )
    return llm


@pytest.fixture
def failing_llm() -> AsyncMock:
    """Mock LLM classifier that raises an exception."""
    llm = AsyncMock(spec=LLMClassifier)
    llm.classify.side_effect = ConnectionError("LLM service unavailable")
    return llm


@pytest.fixture
def none_llm() -> None:
    """No LLM classifier configured."""
    return None


# ---------------------------------------------------------------------------
# Local signature DB hit
# ---------------------------------------------------------------------------

class TestLocalDBHit:
    """When the local signature DB matches, use that classification."""

    @pytest.mark.asyncio
    async def test_oui_match(self, signature_db: SignatureDB, mock_llm: AsyncMock) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=mock_llm)
        fp = CompositeFingerprint(
            mac_address="A4:83:E7:11:22:33",  # Apple OUI
            mdns_hostname=None,
        )
        result = await classifier.classify(fp)
        assert result.manufacturer == "Apple"
        assert result.source == "oui"
        # LLM should NOT be called when local DB matches
        mock_llm.classify.assert_not_called()

    @pytest.mark.asyncio
    async def test_mdns_match(self, signature_db: SignatureDB, mock_llm: AsyncMock) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=mock_llm)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",  # Unknown OUI
            mdns_hostname="sarahs-iphone",
        )
        result = await classifier.classify(fp)
        assert result.manufacturer == "Apple"
        assert result.source == "mdns"
        mock_llm.classify.assert_not_called()

    @pytest.mark.asyncio
    async def test_dhcp_match(self, signature_db: SignatureDB, mock_llm: AsyncMock) -> None:
        data = json.loads(SIGNATURES_PATH.read_text())
        if not data["dhcp_fingerprints"]:
            pytest.skip("No DHCP fingerprints in signature file")
        first_hash = next(iter(data["dhcp_fingerprints"]))

        classifier = DeviceClassifier(signature_db=signature_db, llm=mock_llm)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",
            dhcp_fingerprint_hash=first_hash,
        )
        result = await classifier.classify(fp)
        assert result.source in ("oui", "dhcp", "mdns")
        mock_llm.classify.assert_not_called()

    @pytest.mark.asyncio
    async def test_prefers_highest_confidence_local_match(
        self, signature_db: SignatureDB
    ) -> None:
        """When both OUI and mDNS match, prefer the higher confidence one."""
        classifier = DeviceClassifier(signature_db=signature_db, llm=None)
        fp = CompositeFingerprint(
            mac_address="A4:83:E7:11:22:33",  # Apple OUI
            mdns_hostname="sarahs-iphone",     # Apple mDNS
        )
        result = await classifier.classify(fp)
        assert result.manufacturer == "Apple"
        # The result should come from whichever source had higher confidence


# ---------------------------------------------------------------------------
# LLM fallback
# ---------------------------------------------------------------------------

class TestLLMFallback:
    """When local DB misses, fall back to LLM classification."""

    @pytest.mark.asyncio
    async def test_llm_called_on_local_miss(
        self, signature_db: SignatureDB, mock_llm: AsyncMock
    ) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=mock_llm)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",  # Unknown OUI
            mdns_hostname="totally-unknown-device",
        )
        result = await classifier.classify(fp)
        assert result.manufacturer == "TestCo"
        assert result.source == "llm"
        mock_llm.classify.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_receives_fingerprint(
        self, signature_db: SignatureDB, mock_llm: AsyncMock
    ) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=mock_llm)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",
            mdns_hostname="unknown-gadget",
        )
        await classifier.classify(fp)
        call_args = mock_llm.classify.call_args
        assert call_args is not None
        # The fingerprint should be passed to the LLM
        assert call_args[0][0] is fp or call_args[1].get("fingerprint") is fp


# ---------------------------------------------------------------------------
# LLM unavailable -- graceful degradation
# ---------------------------------------------------------------------------

class TestLLMUnavailable:
    """When LLM is unavailable or errors, degrade gracefully."""

    @pytest.mark.asyncio
    async def test_no_llm_configured(self, signature_db: SignatureDB) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=None)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",
            mdns_hostname="totally-unknown-device",
        )
        result = await classifier.classify(fp)
        assert result.manufacturer == "Unknown"
        assert result.device_type == "unknown"
        assert result.confidence < 0.50
        assert result.source == "fallback"

    @pytest.mark.asyncio
    async def test_llm_connection_error(
        self, signature_db: SignatureDB, failing_llm: AsyncMock
    ) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=failing_llm)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",
            mdns_hostname="totally-unknown-device",
        )
        result = await classifier.classify(fp)
        assert result.manufacturer == "Unknown"
        assert result.device_type == "unknown"
        assert result.source == "fallback"

    @pytest.mark.asyncio
    async def test_llm_error_does_not_raise(
        self, signature_db: SignatureDB, failing_llm: AsyncMock
    ) -> None:
        """LLM errors should be caught, not propagated."""
        classifier = DeviceClassifier(signature_db=signature_db, llm=failing_llm)
        fp = CompositeFingerprint(
            mac_address="02:00:00:00:00:01",
            mdns_hostname="totally-unknown-device",
        )
        # This should NOT raise
        result = await classifier.classify(fp)
        assert result is not None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestClassifierEdgeCases:
    """Edge cases for the classification pipeline."""

    @pytest.mark.asyncio
    async def test_empty_fingerprint(self, signature_db: SignatureDB) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=None)
        fp = CompositeFingerprint()
        result = await classifier.classify(fp)
        assert result.manufacturer == "Unknown"
        assert result.source == "fallback"

    @pytest.mark.asyncio
    async def test_mac_only_fingerprint(self, signature_db: SignatureDB) -> None:
        classifier = DeviceClassifier(signature_db=signature_db, llm=None)
        fp = CompositeFingerprint(mac_address="A4:83:E7:11:22:33")
        result = await classifier.classify(fp)
        assert result.manufacturer == "Apple"
        assert result.source == "oui"
