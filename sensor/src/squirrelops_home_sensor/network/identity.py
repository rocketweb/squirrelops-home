"""Read host link identities without treating privacy placeholders as MACs."""

from __future__ import annotations

import logging

from squirrelops_home_sensor.fingerprint.signals import normalize_mac

logger = logging.getLogger(__name__)
_UNUSABLE_MACS = {"00:00:00:00:00:00", "02:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def normalize_local_macs(candidates: list[str]) -> set[str]:
    """Normalize observed link identities, excluding unknown placeholders."""
    observed: set[str] = set()
    for candidate in candidates:
        try:
            mac = normalize_mac(candidate)
        except ValueError:
            continue
        if mac not in _UNUSABLE_MACS:
            observed.add(mac)
    return observed


def local_interface_macs() -> set[str]:
    """Read local link identities for direct/Linux operations.

    macOS operations override this with an authenticated helper observation:
    both psutil and subprocesses launched by Python can be privacy-redacted.
    """
    try:
        import psutil

        return normalize_local_macs([
            address.address
            for addresses in psutil.net_if_addrs().values()
            for address in addresses
            if address.family == psutil.AF_LINK and address.address
        ])
    except Exception:
        logger.warning("Unable to observe local interface MAC addresses", exc_info=True)
        return set()
