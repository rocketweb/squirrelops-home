"""Local device signature database for OUI, DHCP, and mDNS pattern matching.

Loads a JSON file containing:
- OUI prefixes (first 3 octets -> manufacturer + device type)
- DHCP fingerprint hashes -> OS/device identification
- mDNS hostname regex patterns -> device identification

Used as the first stage in the device classification chain, before
any LLM fallback.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceClassification:
    """Result of a device classification lookup.

    Parameters
    ----------
    manufacturer:
        Device manufacturer name (e.g., "Apple", "Google").
    device_type:
        General device category (e.g., "smartphone", "nas", "smart_speaker").
    model:
        Specific model if identifiable, or None.
    confidence:
        Classification confidence in [0.0, 1.0].
    source:
        Which method produced this classification ("oui", "dhcp", "mdns", "llm", "fallback").
    """

    manufacturer: str
    device_type: str
    model: str | None = None
    confidence: float = 0.0
    source: str = "unknown"


class SignatureDB:
    """Local device signature database.

    Provides OUI prefix lookup, DHCP fingerprint hash matching, and
    mDNS hostname pattern matching against a JSON signature file.
    """

    def __init__(
        self,
        oui_prefixes: dict[str, dict],
        dhcp_fingerprints: dict[str, dict],
        mdns_patterns: list[dict],
    ) -> None:
        self._oui_prefixes = oui_prefixes
        self._dhcp_fingerprints = dhcp_fingerprints
        self._mdns_patterns = [
            {
                **entry,
                "_compiled": re.compile(entry["pattern"], re.IGNORECASE),
            }
            for entry in mdns_patterns
        ]

    @classmethod
    def load(cls, path: pathlib.Path) -> SignatureDB:
        """Load signature database from a JSON file.

        Parameters
        ----------
        path:
            Path to the device_signatures.json file.

        Returns
        -------
        SignatureDB:
            Loaded and ready-to-query signature database.
        """
        data = json.loads(path.read_text())
        return cls(
            oui_prefixes=data.get("oui_prefixes", {}),
            dhcp_fingerprints=data.get("dhcp_fingerprints", {}),
            mdns_patterns=data.get("mdns_patterns", []),
        )

    def lookup_oui(self, mac_address: str) -> DeviceClassification | None:
        """Look up a MAC address by its OUI prefix (first 3 octets).

        Two-layer lookup:
        1. Hand-curated oui_prefixes (high confidence, device_type + model)
        2. Bulk IEEE OUI_DB fallback (manufacturer only, lower confidence)

        Parameters
        ----------
        mac_address:
            Full MAC address in any common format.

        Returns
        -------
        DeviceClassification | None:
            Classification if the OUI prefix is known, else None.
        """
        # Normalize to uppercase colon-separated
        flat = mac_address.strip().replace(":", "").replace("-", "").replace(".", "").upper()
        if len(flat) != 12:
            return None
        prefix = f"{flat[0:2]}:{flat[2:4]}:{flat[4:6]}"

        # Layer 1: Hand-curated (higher confidence, device_type + model)
        entry = self._oui_prefixes.get(prefix)
        if entry is not None:
            return DeviceClassification(
                manufacturer=entry["manufacturer"],
                device_type=entry.get("device_type", "unknown"),
                model=entry.get("model"),
                confidence=entry.get("confidence", 0.50),
                source="oui",
            )

        # Layer 2: Bulk IEEE OUI database fallback
        from squirrelops_home_sensor.devices.oui_db import MANUFACTURER_TYPES, OUI_DB

        manufacturer = OUI_DB.get(prefix)
        if manufacturer is not None:
            device_type = MANUFACTURER_TYPES.get(manufacturer, "unknown")
            confidence = 0.45 if device_type != "unknown" else 0.40
            return DeviceClassification(
                manufacturer=manufacturer,
                device_type=device_type,
                model=None,
                confidence=confidence,
                source="oui",
            )

        return None

    def match_dhcp(self, dhcp_hash: str) -> DeviceClassification | None:
        """Match a DHCP fingerprint hash against known fingerprints.

        Parameters
        ----------
        dhcp_hash:
            SHA-256 hex digest of the sorted DHCP option set.

        Returns
        -------
        DeviceClassification | None:
            Classification if the DHCP hash is known, else None.
        """
        entry = self._dhcp_fingerprints.get(dhcp_hash)
        if entry is None:
            return None

        return DeviceClassification(
            manufacturer=entry["manufacturer"],
            device_type=entry.get("device_type", "unknown"),
            model=entry.get("model"),
            confidence=entry.get("confidence", 0.70),
            source="dhcp",
        )

    def match_mdns(self, hostname: str) -> DeviceClassification | None:
        """Match an mDNS hostname against known regex patterns.

        Patterns are tested in order; the first match wins.

        Parameters
        ----------
        hostname:
            Normalized mDNS hostname (lowercase, no .local suffix).

        Returns
        -------
        DeviceClassification | None:
            Classification if a pattern matches, else None.
        """
        for entry in self._mdns_patterns:
            compiled: re.Pattern = entry["_compiled"]
            if compiled.fullmatch(hostname):
                return DeviceClassification(
                    manufacturer=entry["manufacturer"],
                    device_type=entry.get("device_type", "unknown"),
                    model=entry.get("model"),
                    confidence=entry.get("confidence", 0.60),
                    source="mdns",
                )
        return None
