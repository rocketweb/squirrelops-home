"""Alert type definitions and severity mapping.

Each alert type has a fixed severity. Severity supports ordering so that
incident grouping can escalate to max(current, new).
"""

from __future__ import annotations

import enum
import functools


@functools.total_ordering
class Severity(enum.Enum):
    """Alert severity levels with ordering support.

    CRITICAL > HIGH > MEDIUM > LOW.
    Uses an internal numeric rank for comparison -- the .value is always the
    lowercase string stored in SQLite.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def _rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank < other._rank

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank == other._rank

    def __hash__(self) -> int:
        return hash(self.value)


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class AlertType(enum.Enum):
    """All alert types emitted by the sensor."""

    DECOY_CREDENTIAL_TRIP = "decoy.credential_trip"
    DECOY_TRIP = "decoy.trip"
    DEVICE_NEW = "device.new"
    DEVICE_VERIFICATION_NEEDED = "device.verification_needed"
    DEVICE_MAC_CHANGED = "device.mac_changed"
    SYSTEM_SENSOR_OFFLINE = "system.sensor_offline"
    SYSTEM_LEARNING_COMPLETE = "system.learning_complete"
    DEVICE_REVIEW_REMINDER = "device.review_reminder"
    BEHAVIORAL_ANOMALY = "behavioral.anomaly"
    SECURITY_PORT_RISK = "security.port_risk"
    SECURITY_VENDOR_ADVISORY = "security.vendor_advisory"


# -- Severity mapping ------------------------------------------------

ALERT_SEVERITY_MAP: dict[AlertType, Severity] = {
    AlertType.DECOY_CREDENTIAL_TRIP: Severity.CRITICAL,
    AlertType.DECOY_TRIP: Severity.HIGH,
    AlertType.DEVICE_NEW: Severity.MEDIUM,
    AlertType.DEVICE_VERIFICATION_NEEDED: Severity.MEDIUM,
    AlertType.DEVICE_MAC_CHANGED: Severity.HIGH,
    AlertType.SYSTEM_SENSOR_OFFLINE: Severity.LOW,
    AlertType.SYSTEM_LEARNING_COMPLETE: Severity.LOW,
    AlertType.DEVICE_REVIEW_REMINDER: Severity.LOW,
    AlertType.BEHAVIORAL_ANOMALY: Severity.MEDIUM,
    AlertType.SECURITY_PORT_RISK: Severity.MEDIUM,
    AlertType.SECURITY_VENDOR_ADVISORY: Severity.MEDIUM,
}


def severity_for_alert_type(alert_type: AlertType) -> Severity:
    """Return the severity for a given alert type.

    Raises ``KeyError`` if the alert type has no mapping (indicates a
    programming error -- every AlertType must have an entry in
    ``ALERT_SEVERITY_MAP``).
    """
    return ALERT_SEVERITY_MAP[alert_type]


# -- Category helpers ------------------------------------------------

def is_decoy_alert(alert_type: AlertType) -> bool:
    """Return True if the alert type belongs to the decoy category."""
    return alert_type.value.startswith("decoy.")


def is_device_alert(alert_type: AlertType) -> bool:
    """Return True if the alert type belongs to the device category."""
    return alert_type.value.startswith("device.")


def is_system_alert(alert_type: AlertType) -> bool:
    """Return True if the alert type belongs to the system category."""
    return alert_type.value.startswith("system.")


def is_security_alert(alert_type: AlertType) -> bool:
    """Return True if the alert type belongs to the security category."""
    return alert_type.value.startswith("security.")


# -- Display helpers -------------------------------------------------

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "\U0001f534",  # red circle
    Severity.HIGH: "\U0001f7e0",      # orange circle
    Severity.MEDIUM: "\U0001f7e1",    # yellow circle
    Severity.LOW: "\U0001f535",       # blue circle
}


def severity_emoji(severity: Severity) -> str:
    """Return a colored circle emoji for the given severity level."""
    return _SEVERITY_EMOJI[severity]
