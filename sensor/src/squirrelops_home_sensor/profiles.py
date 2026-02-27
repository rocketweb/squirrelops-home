"""Resource profile detection and enforcement.

Three resource profiles control scan frequency, decoy limits, and LLM
classification mode. The sensor auto-detects an appropriate profile on
startup based on available system resources (RAM, CPU cores), but the
user may override it at any time.

Profiles:
    Lite     -- 15-min scans, <=3 decoys, local signature DB only
    Standard -- 5-min scans,  <=8 decoys, cloud LLM (user's API key)
    Full     -- 1-min scans,  <=16 decoys, local LLM (LM Studio/Ollama)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)

# Try to import psutil; it is optional.
try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ResourceProfile(StrEnum):
    """Available resource profiles."""

    LITE = "lite"
    STANDARD = "standard"
    FULL = "full"


class LLMMode(StrEnum):
    """LLM classification modes corresponding to each profile."""

    LOCAL_SIGNATURES = "local_signatures"
    CLOUD_LLM = "cloud_llm"
    LOCAL_LLM = "local_llm"


# ---------------------------------------------------------------------------
# Profile settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProfileSettings:
    """Immutable settings for a single resource profile."""

    scan_interval: int  # seconds between active scans
    max_decoys: int  # maximum concurrent decoy services
    llm_mode: LLMMode  # classification strategy
    scout_interval_minutes: int = 30  # 0 = disabled
    max_mimic_decoys: int = 10
    max_virtual_ips: int = 15


PROFILE_SETTINGS: dict[ResourceProfile, ProfileSettings] = {
    ResourceProfile.LITE: ProfileSettings(
        scan_interval=900,
        max_decoys=3,
        llm_mode=LLMMode.LOCAL_SIGNATURES,
        scout_interval_minutes=0,
        max_mimic_decoys=0,
        max_virtual_ips=0,
    ),
    ResourceProfile.STANDARD: ProfileSettings(
        scan_interval=300,
        max_decoys=8,
        llm_mode=LLMMode.CLOUD_LLM,
        scout_interval_minutes=60,
        max_mimic_decoys=10,
        max_virtual_ips=10,
    ),
    ResourceProfile.FULL: ProfileSettings(
        scan_interval=60,
        max_decoys=16,
        llm_mode=LLMMode.LOCAL_LLM,
        scout_interval_minutes=30,
        max_mimic_decoys=30,
        max_virtual_ips=30,
    ),
}


# ---------------------------------------------------------------------------
# Detection thresholds (bytes / count)
# ---------------------------------------------------------------------------

_FULL_MIN_RAM = 16 * 1024 * 1024 * 1024  # 16 GB
_FULL_MIN_CPUS = 8
_STANDARD_MIN_RAM = 4 * 1024 * 1024 * 1024  # 4 GB
_STANDARD_MIN_CPUS = 2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_profile() -> ResourceProfile:
    """Auto-detect the best resource profile for this machine.

    Detection rules:
        >= 16 GB RAM **and** >= 8 CPU cores  -> FULL
        >=  4 GB RAM **and** >= 2 CPU cores  -> STANDARD
        Otherwise                             -> LITE

    Falls back to STANDARD if *psutil* is not installed or raises an
    exception (conservative default -- not the lowest tier).
    """
    if psutil is None:
        logger.info("psutil not available; defaulting to STANDARD profile")
        return ResourceProfile.STANDARD

    try:
        total_ram: int = psutil.virtual_memory().total
        cpu_count: int = psutil.cpu_count() or 1
    except Exception:
        logger.warning(
            "Failed to query system resources; defaulting to STANDARD profile",
            exc_info=True,
        )
        return ResourceProfile.STANDARD

    if total_ram >= _FULL_MIN_RAM and cpu_count >= _FULL_MIN_CPUS:
        return ResourceProfile.FULL

    if total_ram >= _STANDARD_MIN_RAM and cpu_count >= _STANDARD_MIN_CPUS:
        return ResourceProfile.STANDARD

    return ResourceProfile.LITE


def get_profile_limits(profile: ResourceProfile) -> dict[str, object]:
    """Return the numeric limits for *profile* as a plain dict.

    Keys: ``scan_interval``, ``max_decoys``, ``llm_mode``.
    """
    settings = PROFILE_SETTINGS[profile]
    return {
        "scan_interval": settings.scan_interval,
        "max_decoys": settings.max_decoys,
        "llm_mode": settings.llm_mode.value,
    }


def apply_profile(
    config: dict[str, object],
    profile: ResourceProfile,
) -> dict[str, object]:
    """Return a **copy** of *config* with *profile* settings applied.

    Overwrites ``scan_interval``, ``max_decoys``, ``llm_mode``, and
    ``profile`` keys. All other keys are preserved unchanged.
    """
    merged = dict(config)
    limits = get_profile_limits(profile)
    merged.update(limits)
    merged["profile"] = profile.value
    return merged
