"""Tests for the scout engine — deep service fingerprinting."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from squirrelops_home_sensor.scouts.engine import (
    ScoutEngine,
    ServiceProfile,
    _HTTP_PORTS,
    _PROTOCOL_PORTS,
    _TLS_PORTS,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_profiles (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT,
    http_status INTEGER,
    http_headers TEXT,
    http_body_snippet TEXT,
    http_server_header TEXT,
    favicon_hash TEXT,
    tls_cn TEXT,
    tls_issuer TEXT,
    tls_not_after TEXT,
    protocol_version TEXT,
    scouted_at TEXT NOT NULL,
    UNIQUE(device_id, port, protocol)
);
"""


@pytest.fixture
async def db():
    """In-memory test database with scout schema."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.executescript(_SCHEMA)
        await conn.execute(
            "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) "
            "VALUES (1, '192.168.1.100', 'smart_home', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        await conn.execute(
            "INSERT INTO devices (id, ip_address, device_type, first_seen, last_seen) "
            "VALUES (2, '192.168.1.101', 'camera', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
        )
        await conn.commit()
        yield conn


class TestServiceProfile:
    """Verify ServiceProfile dataclass defaults."""

    def test_default_protocol_is_tcp(self) -> None:
        """Default protocol should be tcp."""
        p = ServiceProfile(device_id=1, ip_address="10.0.0.1", port=80)
        assert p.protocol == "tcp"

    def test_http_fields_default_none(self) -> None:
        """HTTP fields should default to None."""
        p = ServiceProfile(device_id=1, ip_address="10.0.0.1", port=80)
        assert p.http_status is None
        assert p.http_headers is None
        assert p.http_body_snippet is None
        assert p.http_server_header is None
        assert p.favicon_hash is None

    def test_tls_fields_default_none(self) -> None:
        """TLS fields should default to None."""
        p = ServiceProfile(device_id=1, ip_address="10.0.0.1", port=443)
        assert p.tls_cn is None
        assert p.tls_issuer is None
        assert p.tls_not_after is None

    def test_protocol_version_default_none(self) -> None:
        """Protocol version should default to None."""
        p = ServiceProfile(device_id=1, ip_address="10.0.0.1", port=22)
        assert p.protocol_version is None


class TestScoutEngineProbes:
    """Verify probe dispatch and HTTP/protocol capture."""

    @pytest.mark.asyncio
    async def test_scout_device_returns_profiles(self, db) -> None:
        """scout_device should return a profile for each port."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        # Mock all probes to avoid real network calls
        with patch.object(engine, "_probe_http", new_callable=AsyncMock), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", new_callable=AsyncMock):
            profiles = await engine.scout_device(1, "192.168.1.100", [80, 22])
        assert len(profiles) == 2
        assert {p.port for p in profiles} == {80, 22}

    @pytest.mark.asyncio
    async def test_scout_device_handles_probe_exception(self, db) -> None:
        """If a probe raises, the port is skipped gracefully."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        async def fail_probe(*args, **kwargs):
            raise ConnectionRefusedError("refused")

        with patch.object(engine, "_probe_http", side_effect=fail_probe), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", new_callable=AsyncMock):
            profiles = await engine.scout_device(1, "192.168.1.100", [80])
        # Should still get a profile even if probe fails (profile is created before probes)
        assert len(profiles) == 1

    @pytest.mark.asyncio
    async def test_http_port_triggers_http_probe(self, db) -> None:
        """Port 8123 (in _HTTP_PORTS) should trigger _probe_http."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        http_mock = AsyncMock()
        proto_mock = AsyncMock()
        with patch.object(engine, "_probe_http", http_mock), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", proto_mock):
            await engine.scout_device(1, "192.168.1.100", [8123])
        http_mock.assert_awaited_once()
        proto_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ssh_port_triggers_protocol_probe(self, db) -> None:
        """Port 22 (in _PROTOCOL_PORTS) should trigger _probe_protocol."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        http_mock = AsyncMock()
        proto_mock = AsyncMock()
        with patch.object(engine, "_probe_http", http_mock), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", proto_mock):
            await engine.scout_device(1, "192.168.1.100", [22])
        http_mock.assert_not_awaited()
        proto_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_tls_port_triggers_tls_probe(self, db) -> None:
        """Port 443 should trigger both HTTP and TLS probes."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        http_mock = AsyncMock()
        tls_mock = AsyncMock()
        with patch.object(engine, "_probe_http", http_mock), \
             patch.object(engine, "_probe_tls", tls_mock), \
             patch.object(engine, "_probe_protocol", new_callable=AsyncMock):
            await engine.scout_device(1, "192.168.1.100", [443])
        http_mock.assert_awaited_once()
        tls_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unknown_port_triggers_generic_banner(self, db) -> None:
        """An unknown port (not HTTP/TLS/protocol) should still probe for a banner."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        proto_mock = AsyncMock()
        with patch.object(engine, "_probe_http", new_callable=AsyncMock) as http_mock, \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", proto_mock):
            await engine.scout_device(1, "192.168.1.100", [9999])
        http_mock.assert_not_awaited()
        proto_mock.assert_awaited_once()


class TestScoutEnginePersistence:
    """Verify profile persistence and retrieval."""

    @pytest.mark.asyncio
    async def test_scout_all_persists_profiles(self, db) -> None:
        """scout_all should persist profiles to the database."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        with patch.object(engine, "_probe_http", new_callable=AsyncMock), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", new_callable=AsyncMock):
            count = await engine.scout_all({(1, "192.168.1.100"): [80, 22]})
        assert count == 2

        cursor = await db.execute("SELECT COUNT(*) FROM service_profiles")
        row = await cursor.fetchone()
        assert row[0] == 2

    @pytest.mark.asyncio
    async def test_persist_profile_upserts(self, db) -> None:
        """Re-scouting the same port should update, not duplicate."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        profile = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=80,
            http_status=200, http_server_header="nginx",
            scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(profile)

        # Update with new data
        profile2 = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=80,
            http_status=301, http_server_header="apache",
            scouted_at="2026-01-01T01:00:00Z",
        )
        await engine._persist_profile(profile2)

        cursor = await db.execute("SELECT COUNT(*) FROM service_profiles WHERE device_id = 1 AND port = 80")
        row = await cursor.fetchone()
        assert row[0] == 1

        cursor = await db.execute("SELECT http_status, http_server_header FROM service_profiles WHERE device_id = 1 AND port = 80")
        row = await cursor.fetchone()
        assert row["http_status"] == 301
        assert row["http_server_header"] == "apache"

    @pytest.mark.asyncio
    async def test_coalesce_preserves_old_data(self, db) -> None:
        """COALESCE upsert should keep old data when new probe returns None."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        profile = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=80,
            http_status=200, http_server_header="nginx", tls_cn="example.com",
            scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(profile)

        # New profile with None tls_cn — old value should be preserved
        profile2 = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=80,
            http_status=200, tls_cn=None,
            scouted_at="2026-01-01T01:00:00Z",
        )
        await engine._persist_profile(profile2)

        cursor = await db.execute("SELECT tls_cn FROM service_profiles WHERE device_id = 1 AND port = 80")
        row = await cursor.fetchone()
        assert row["tls_cn"] == "example.com"

    @pytest.mark.asyncio
    async def test_get_profiles_for_device(self, db) -> None:
        """get_profiles_for_device should return stored profiles."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        profile = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=80,
            http_status=200, http_server_header="gunicorn",
            scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(profile)

        profiles = await engine.get_profiles_for_device(1)
        assert len(profiles) == 1
        assert profiles[0].port == 80
        assert profiles[0].http_status == 200
        assert profiles[0].http_server_header == "gunicorn"

    @pytest.mark.asyncio
    async def test_get_mimic_candidates_prioritizes_smart_home(self, db) -> None:
        """Mimic candidates should prioritize smart_home devices."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        # Camera device profile
        p1 = ServiceProfile(
            device_id=2, ip_address="192.168.1.101", port=80,
            http_status=200, scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(p1)

        # Smart home device profile
        p2 = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=8123,
            http_status=200, scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(p2)

        candidates = await engine.get_mimic_candidates(count=5)
        assert len(candidates) == 2
        # Smart home should come first
        assert candidates[0].device_id == 1
        assert candidates[1].device_id == 2

    @pytest.mark.asyncio
    async def test_get_mimic_candidates_only_http(self, db) -> None:
        """Mimic candidates require http_status to be set."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        # Profile without HTTP data — should not be a candidate
        p = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=22,
            protocol_version="SSH-2.0-OpenSSH_8.9p1",
            scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(p)

        candidates = await engine.get_mimic_candidates(count=5)
        assert len(candidates) == 0
