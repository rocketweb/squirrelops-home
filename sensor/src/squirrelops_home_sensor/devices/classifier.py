"""Device classifier with local signature DB and optional LLM fallback.

Classification chain:
1. Local signature DB (OUI, mDNS patterns, DHCP fingerprints)
2. LLM fallback (cloud or local, via mockable async interface)
3. "Unknown" with low confidence (graceful degradation)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from squirrelops_home_sensor.devices.signatures import (
    DeviceClassification,
    SignatureDB,
)
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeviceClassificationEvidence:
    """Interpretable, privacy-bounded signals that may be sent to an LLM.

    Fingerprint hashes and connection destinations deliberately do not belong
    here. They remain useful for local matching but provide no classification
    value to a language model. ``mac_oui`` contains at most the first three
    octets, never a device's complete MAC address.
    """

    mac_oui: str | None = None
    dns_hostname: str | None = None
    mdns_hostname: str | None = None
    open_ports: tuple[int, ...] = ()
    detected_services: tuple[str, ...] = ()
    dhcp_options: tuple[int, ...] = ()
    mdns_service_types: tuple[str, ...] = ()
    upnp_friendly_name: str | None = None
    upnp_manufacturer: str | None = None
    upnp_model_name: str | None = None
    upnp_server_header: str | None = None

    @classmethod
    def from_fingerprint(
        cls,
        fingerprint: CompositeFingerprint,
    ) -> DeviceClassificationEvidence:
        """Build the only safe evidence recoverable from a fingerprint."""
        mac_oui = (
            fingerprint.mac_address[:8]
            if fingerprint.mac_address is not None
            else None
        )
        return cls(
            mac_oui=mac_oui,
            mdns_hostname=fingerprint.mdns_hostname,
        )


class LLMClassifier(ABC):
    """Abstract interface for LLM-based device classification.

    Implementations connect to cloud LLM APIs (Standard profile) or
    local LLM servers like LM Studio/Ollama (Full profile).
    """

    @abstractmethod
    async def classify(
        self,
        fingerprint: CompositeFingerprint,
        evidence: DeviceClassificationEvidence | None = None,
    ) -> DeviceClassification:
        """Classify a device using privacy-bounded, interpretable evidence.

        Parameters
        ----------
        fingerprint:
            The local composite fingerprint. Implementations must not send its
            opaque hashes or complete MAC address to a provider.
        evidence:
            Sanitized source metadata that is useful for classification.

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

    def set_llm(self, llm: LLMClassifier | None) -> LLMClassifier | None:
        """Replace the live LLM fallback and return the previous instance."""
        previous = self._llm
        self._llm = llm
        return previous

    @property
    def has_llm(self) -> bool:
        """Return whether an optional LLM fallback is currently configured."""
        return self._llm is not None

    async def classify(
        self,
        fingerprint: CompositeFingerprint,
        evidence: DeviceClassificationEvidence | None = None,
        *,
        allow_llm: bool = True,
        allow_local: bool = True,
    ) -> DeviceClassification:
        """Classify a device using the full classification chain.

        Parameters
        ----------
        fingerprint:
            The composite fingerprint for the device.
        evidence:
            Interpretable evidence for the optional LLM fallback.
        allow_llm:
            False while a scan is still gathering port and discovery metadata.
        allow_local:
            False when enriching an incomplete local result with the LLM.

        Returns
        -------
        DeviceClassification:
            The best classification found, or a fallback "Unknown" result.
        """
        # Stage 1: Local signature database
        if allow_local:
            local_result = self._classify_local(fingerprint)
            if local_result is not None:
                return local_result

        # Stage 2: LLM fallback
        if allow_llm and self._llm is not None:
            try:
                llm_result = await self._llm.classify(fingerprint, evidence)
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
