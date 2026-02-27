"""Device classifier with local signature DB and optional LLM fallback.

Classification chain:
1. Local signature DB (OUI, mDNS patterns, DHCP fingerprints)
2. LLM fallback (cloud or local, via mockable async interface)
3. "Unknown" with low confidence (graceful degradation)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from squirrelops_home_sensor.devices.signatures import (
    DeviceClassification,
    SignatureDB,
)
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint

logger = logging.getLogger(__name__)


class LLMClassifier(ABC):
    """Abstract interface for LLM-based device classification.

    Implementations connect to cloud LLM APIs (Standard profile) or
    local LLM servers like LM Studio/Ollama (Full profile).
    """

    @abstractmethod
    async def classify(self, fingerprint: CompositeFingerprint) -> DeviceClassification:
        """Classify a device based on its fingerprint signals.

        Parameters
        ----------
        fingerprint:
            The composite fingerprint with all available signals.

        Returns
        -------
        DeviceClassification:
            The LLM's best classification with confidence score.
        """


_FALLBACK_CLASSIFICATION = DeviceClassification(
    manufacturer="Unknown",
    device_type="unknown",
    model=None,
    confidence=0.10,
    source="fallback",
)


class DeviceClassifier:
    """Device classification pipeline: local DB -> LLM -> fallback.

    Parameters
    ----------
    signature_db:
        The local device signature database for OUI/DHCP/mDNS matching.
    llm:
        Optional LLM classifier for fallback. None if not configured.
    """

    def __init__(
        self,
        signature_db: SignatureDB,
        llm: LLMClassifier | None = None,
    ) -> None:
        self._sig_db = signature_db
        self._llm = llm

    async def classify(self, fingerprint: CompositeFingerprint) -> DeviceClassification:
        """Classify a device using the full classification chain.

        Parameters
        ----------
        fingerprint:
            The composite fingerprint for the device.

        Returns
        -------
        DeviceClassification:
            The best classification found, or a fallback "Unknown" result.
        """
        # Stage 1: Local signature database
        local_result = self._classify_local(fingerprint)
        if local_result is not None:
            return local_result

        # Stage 2: LLM fallback
        if self._llm is not None:
            try:
                llm_result = await self._llm.classify(fingerprint)
                return llm_result
            except Exception:
                logger.warning(
                    "LLM classification failed for fingerprint, falling back to unknown",
                    exc_info=True,
                )

        # Stage 3: Graceful degradation
        return _FALLBACK_CLASSIFICATION

    def _classify_local(
        self, fingerprint: CompositeFingerprint
    ) -> DeviceClassification | None:
        """Attempt classification using the local signature database.

        Tries OUI, mDNS, and DHCP matching in parallel and returns the
        highest-confidence result.
        """
        candidates: list[DeviceClassification] = []

        # OUI lookup
        if fingerprint.mac_address is not None:
            oui_result = self._sig_db.lookup_oui(fingerprint.mac_address)
            if oui_result is not None:
                candidates.append(oui_result)

        # mDNS pattern matching
        if fingerprint.mdns_hostname is not None:
            mdns_result = self._sig_db.match_mdns(fingerprint.mdns_hostname)
            if mdns_result is not None:
                candidates.append(mdns_result)

        # DHCP fingerprint matching
        if fingerprint.dhcp_fingerprint_hash is not None:
            dhcp_result = self._sig_db.match_dhcp(fingerprint.dhcp_fingerprint_hash)
            if dhcp_result is not None:
                candidates.append(dhcp_result)

        if not candidates:
            return None

        # Return highest confidence match
        return max(candidates, key=lambda c: c.confidence)
