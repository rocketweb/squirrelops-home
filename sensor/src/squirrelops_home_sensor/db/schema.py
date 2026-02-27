"""SQLite schema definitions for SquirrelOps Home Sensor.

Extends Pingting's existing tables with 11 new tables for device fingerprints,
trust management, incidents, alerts, decoys, credentials, pairing, canary
observations, and event logging.
"""

from __future__ import annotations

# Current schema version -- increment when adding migrations
SCHEMA_VERSION = 6

# All table names managed by this schema (does NOT include Pingting's tables)
_TABLE_NAMES: list[str] = [
    "events",
    "devices",
    "device_fingerprints",
    "device_trust",
    "incidents",
    "home_alerts",
    "decoys",
    "planted_credentials",
    "decoy_connections",
    "pairing",
    "canary_observations",
    "connection_baselines",
    "device_open_ports",
    "security_insight_state",
    "service_profiles",
    "virtual_ips",
    "mimic_templates",
    "schema_version",
]


def get_all_table_names() -> list[str]:
    """Return the list of all table names managed by this schema."""
    return list(_TABLE_NAMES)


async def create_all_tables(db) -> None:
    """Apply the full V1 schema to the database.

    Convenience wrapper for tests and fresh databases. For production
    use, prefer ``apply_migrations()`` from the migrations module.
    """
    await db.executescript(SCHEMA_V1_SQL)
    await db.commit()


# ---------------------------------------------------------------------------
# SQL statements for schema version 1
# ---------------------------------------------------------------------------

SCHEMA_V1_SQL = """
-- Monotonic event log (WebSocket replay + audit trail)
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    source_id TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

-- Discovered devices
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    model_name TEXT,
    area TEXT,
    custom_name TEXT,
    notes TEXT,
    is_online INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);

-- Composite device fingerprints
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id INTEGER PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id),
    mac_address TEXT,
    mdns_hostname TEXT,
    dhcp_fingerprint_hash TEXT,
    connection_pattern_hash TEXT,
    open_ports_hash TEXT,
    composite_hash TEXT,
    signal_count INTEGER NOT NULL,
    confidence REAL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fp_device ON device_fingerprints(device_id);
CREATE INDEX IF NOT EXISTS idx_fp_composite ON device_fingerprints(composite_hash);

-- Device trust status
CREATE TABLE IF NOT EXISTS device_trust (
    device_id INTEGER PRIMARY KEY REFERENCES devices(id),
    status TEXT NOT NULL CHECK(status IN ('approved', 'rejected', 'unknown')),
    approved_by TEXT,
    updated_at TEXT NOT NULL
);

-- Incident grouping (session-based alert correlation)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    source_ip TEXT NOT NULL,
    source_mac TEXT,
    status TEXT NOT NULL CHECK(status IN ('active', 'closed')) DEFAULT 'active',
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    alert_count INTEGER NOT NULL DEFAULT 1,
    first_alert_at TEXT NOT NULL,
    last_alert_at TEXT NOT NULL,
    closed_at TEXT,
    summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_active ON incidents(status) WHERE status = 'active';

-- Home-specific alerts
CREATE TABLE IF NOT EXISTS home_alerts (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id),
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    source_ip TEXT,
    source_mac TEXT,
    device_id INTEGER REFERENCES devices(id),
    decoy_id INTEGER REFERENCES decoys(id),
    read_at TEXT,
    actioned_at TEXT,
    action_note TEXT,
    event_seq INTEGER REFERENCES events(seq),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON home_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON home_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON home_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON home_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_unread ON home_alerts(read_at) WHERE read_at IS NULL;

-- Active decoys
CREATE TABLE IF NOT EXISTS decoys (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    decoy_type TEXT NOT NULL,
    bind_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'degraded', 'stopped')) DEFAULT 'active',
    config TEXT,
    connection_count INTEGER NOT NULL DEFAULT 0,
    credential_trip_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_failure_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Planted credentials
CREATE TABLE IF NOT EXISTS planted_credentials (
    id INTEGER PRIMARY KEY,
    credential_type TEXT NOT NULL,
    credential_value TEXT NOT NULL,
    canary_hostname TEXT,
    planted_location TEXT NOT NULL,
    decoy_id INTEGER REFERENCES decoys(id),
    tripped INTEGER NOT NULL DEFAULT 0,
    first_tripped_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_creds_canary ON planted_credentials(canary_hostname) WHERE canary_hostname IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_creds_value ON planted_credentials(credential_value);

-- Decoy connection log
CREATE TABLE IF NOT EXISTS decoy_connections (
    id INTEGER PRIMARY KEY,
    decoy_id INTEGER NOT NULL REFERENCES decoys(id),
    source_ip TEXT NOT NULL,
    source_mac TEXT,
    port INTEGER NOT NULL,
    protocol TEXT,
    request_path TEXT,
    credential_used TEXT,
    credential_id INTEGER REFERENCES planted_credentials(id),
    event_seq INTEGER REFERENCES events(seq),
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conn_decoy ON decoy_connections(decoy_id);
CREATE INDEX IF NOT EXISTS idx_conn_source ON decoy_connections(source_ip);

-- Paired clients
CREATE TABLE IF NOT EXISTS pairing (
    id INTEGER PRIMARY KEY,
    client_name TEXT NOT NULL,
    client_cert_fingerprint TEXT NOT NULL,
    is_local INTEGER NOT NULL DEFAULT 0,
    paired_at TEXT NOT NULL,
    last_connected_at TEXT
);

-- DNS canary observations
CREATE TABLE IF NOT EXISTS canary_observations (
    id INTEGER PRIMARY KEY,
    credential_id INTEGER NOT NULL REFERENCES planted_credentials(id),
    canary_hostname TEXT NOT NULL,
    queried_by_ip TEXT NOT NULL,
    queried_by_mac TEXT,
    event_seq INTEGER REFERENCES events(seq),
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_canary_hostname ON canary_observations(canary_hostname);

-- Connection baselines (learned device destinations)
CREATE TABLE IF NOT EXISTS connection_baselines (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    dest_ip     TEXT    NOT NULL,
    dest_port   INTEGER NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 1,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    UNIQUE(device_id, dest_ip, dest_port)
);
CREATE INDEX IF NOT EXISTS idx_baseline_device ON connection_baselines(device_id);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""
