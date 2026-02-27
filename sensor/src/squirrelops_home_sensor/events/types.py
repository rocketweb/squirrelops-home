"""Event type constants for the SquirrelOps Home Sensor event bus.

These constants define the canonical event type strings used throughout
the system. Components publish events using these types, and subscribers
filter on them.
"""

from __future__ import annotations


class EventType:
    """Namespace for event type string constants."""

    # Device events
    DEVICE_DISCOVERED = "device.discovered"
    DEVICE_UPDATED = "device.updated"
    DEVICE_ONLINE = "device.online"
    DEVICE_OFFLINE = "device.offline"

    # Decoy events
    DECOY_TRIP = "decoy.trip"
    DECOY_CREDENTIAL_TRIP = "decoy.credential_trip"
    DECOY_HEALTH_CHANGED = "decoy.health_changed"
    DECOY_STATUS_CHANGED = "decoy.status_changed"

    # Alert events
    ALERT_NEW = "alert.new"
    ALERT_UPDATED = "alert.updated"

    # Incident events
    INCIDENT_NEW = "incident.new"
    INCIDENT_UPDATED = "incident.updated"

    # Scout events
    SCOUT_CYCLE_COMPLETE = "scout.cycle_complete"
    MIMIC_DEPLOYED = "mimic.deployed"
    MIMIC_REMOVED = "mimic.removed"

    # System events
    SYSTEM_SCAN_COMPLETE = "system.scan_complete"
    SYSTEM_PROFILE_CHANGED = "system.profile_changed"
    SYSTEM_LEARNING_PROGRESS = "system.learning_progress"
