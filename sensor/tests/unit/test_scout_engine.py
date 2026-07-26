"""Tests for the scout engine — deep service fingerprinting."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import httpx
import pytest

from squirrelops_home_sensor.scouts.engine import (
    ScoutEngine,
    ServiceProfile,
)
from squirrelops_home_sensor.scouts.scheduler import ScoutScheduler

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    is_online INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_open_ports (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(device_id, port, protocol)
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
    favicon_body BLOB,
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

    @pytest.mark.parametrize("max_concurrent", [0, 65, True])
    def test_rejects_unbounded_concurrency(self, max_concurrent) -> None:
        with pytest.raises(ValueError, match="max_concurrent"):
            ScoutEngine(db=MagicMock(), max_concurrent=max_concurrent)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("http_timeout", 0),
            ("http_timeout", float("inf")),
            ("probe_deadline", 0),
            ("probe_deadline", float("nan")),
            ("probe_deadline", 61),
        ],
    )
    def test_rejects_invalid_probe_deadlines(self, field, value) -> None:
        kwargs = {field: value}
        with pytest.raises(ValueError):
            ScoutEngine(db=MagicMock(), **kwargs)

    @pytest.mark.asyncio
    async def test_complete_port_probe_has_an_absolute_deadline(self, db) -> None:
        engine = ScoutEngine(
            db=db,
            max_concurrent=1,
            probe_deadline=0.05,
        )
        never = asyncio.Event()

        async def hang(*_args, **_kwargs) -> None:
            await never.wait()

        loop = asyncio.get_running_loop()
        started = loop.time()
        with patch.object(engine, "_probe_http", side_effect=hang), \
             patch.object(engine, "_probe_tls", side_effect=hang):
            profiles = await asyncio.wait_for(
                engine.scout_device(1, "192.168.1.100", [443]),
                timeout=0.5,
            )

        assert len(profiles) == 1
        assert loop.time() - started < 0.25

    @pytest.mark.asyncio
    async def test_device_probe_respects_connection_cap(self, db) -> None:
        engine = ScoutEngine(db=db, max_concurrent=2)
        active = 0
        maximum = 0

        async def tracked_probe(*_args, **_kwargs) -> None:
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            try:
                await asyncio.sleep(0.02)
            finally:
                active -= 1

        with patch.object(engine, "_probe_protocol", side_effect=tracked_probe):
            profiles = await engine.scout_device(
                1,
                "192.168.1.100",
                [9001, 9002, 9003, 9004],
            )

        assert len(profiles) == 4
        assert maximum == 2

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

    @pytest.mark.asyncio
    async def test_http_probe_stops_reading_after_bounded_body_snippet(
        self,
        db,
    ) -> None:
        """A hostile response cannot make the scout consume the complete body."""

        class ExplodingBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(3):
                    yield b"a" * 1024
                raise AssertionError("probe read beyond its body limit")

        body_stream = ExplodingBody()

        def handle_request(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    headers={
                        "Content-Type": "text/plain; charset=utf-8",
                        # A hostile service may ignore Accept-Encoding:
                        # identity. The probe must cap raw bytes without
                        # invoking an attacker-controlled decompression step.
                        "Content-Encoding": "gzip",
                        "Server": "test-device",
                    },
                    stream=body_stream,
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handle_request)
        async_client_class = httpx.AsyncClient

        def make_client(**kwargs):
            return async_client_class(transport=transport, **kwargs)

        engine = ScoutEngine(db=db, max_concurrent=5)
        profile = ServiceProfile(
            device_id=1,
            ip_address="192.168.1.100",
            port=80,
        )
        with patch(
            "squirrelops_home_sensor.scouts.engine.httpx.AsyncClient",
            side_effect=make_client,
        ):
            await engine._probe_http(profile, "192.168.1.100", 80)

        assert profile.http_status == 200
        assert profile.http_server_header == "test-device"
        assert profile.http_body_snippet == "a" * 2048

    @pytest.mark.asyncio
    async def test_http_probe_does_not_decode_encoded_favicon(
        self,
        db,
    ) -> None:
        """A favicon response cannot trigger attacker-controlled expansion."""

        class EncodedBody(httpx.AsyncByteStream):
            was_read = False

            async def __aiter__(self):
                self.was_read = True
                yield b"compressed bytes are intentionally not decoded"

        class PlainBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"device"

        favicon_stream = EncodedBody()

        def handle_request(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, stream=PlainBody())
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                stream=favicon_stream,
            )

        transport = httpx.MockTransport(handle_request)
        async_client_class = httpx.AsyncClient

        def make_client(**kwargs):
            return async_client_class(transport=transport, **kwargs)

        engine = ScoutEngine(db=db, max_concurrent=5)
        profile = ServiceProfile(
            device_id=1,
            ip_address="192.168.1.100",
            port=80,
        )
        with patch(
            "squirrelops_home_sensor.scouts.engine.httpx.AsyncClient",
            side_effect=make_client,
        ):
            await engine._probe_http(profile, "192.168.1.100", 80)

        assert favicon_stream.was_read is False
        assert profile.favicon_body is None
        assert profile.favicon_hash is None

    @pytest.mark.asyncio
    async def test_http_probe_enforces_absolute_stream_deadline(
        self,
        db,
    ) -> None:
        """A byte-drip response cannot monopolize a scout semaphore slot."""

        class DripBody(httpx.AsyncByteStream):
            iterations = 0

            async def __aiter__(self):
                while True:
                    await asyncio.sleep(0.03)
                    self.iterations += 1
                    yield b"x"

        body_stream = DripBody()

        def handle_request(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, stream=body_stream)

        transport = httpx.MockTransport(handle_request)
        async_client_class = httpx.AsyncClient

        def make_client(**kwargs):
            return async_client_class(transport=transport, **kwargs)

        engine = ScoutEngine(db=db, max_concurrent=1, http_timeout=0.07)
        profile = ServiceProfile(
            device_id=1,
            ip_address="192.168.1.100",
            port=80,
        )
        loop = asyncio.get_running_loop()
        started = loop.time()
        with patch(
            "squirrelops_home_sensor.scouts.engine.httpx.AsyncClient",
            side_effect=make_client,
        ):
            await asyncio.wait_for(
                engine._probe_http(profile, "192.168.1.100", 80),
                timeout=0.5,
            )

        assert loop.time() - started < 0.25
        assert body_stream.iterations < 5


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
    async def test_scout_all_removes_profile_for_closed_port(self, db) -> None:
        """A successful inventory replaces, rather than accumulates, open ports."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        with patch.object(engine, "_probe_http", new_callable=AsyncMock), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", new_callable=AsyncMock):
            await engine.scout_all({(1, "192.168.1.100"): [22, 80]})
            await engine.scout_all({(1, "192.168.1.100"): [80]})

        cursor = await db.execute(
            "SELECT port FROM service_profiles WHERE device_id = 1 ORDER BY port"
        )
        assert [row["port"] for row in await cursor.fetchall()] == [80]

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
    async def test_failed_reprobe_clears_stale_nullable_identity(self, db) -> None:
        """A current empty probe must not retain a service identity from the past."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        profile = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=80,
            service_name="http", http_status=200,
            http_headers={"server": "nginx"},
            http_body_snippet="old body",
            http_server_header="nginx",
            favicon_hash="old-favicon",
            tls_cn="example.com",
            tls_issuer="Example CA",
            tls_not_after="2030-01-01",
            protocol_version="old-banner",
            scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(profile)

        async def fail_probe(*_args, **_kwargs) -> None:
            raise ConnectionError("probe failed")

        with patch.object(engine, "_probe_http", side_effect=fail_probe), \
             patch.object(engine, "_probe_tls", new_callable=AsyncMock), \
             patch.object(engine, "_probe_protocol", new_callable=AsyncMock):
            await engine.scout_all({(1, "192.168.1.100"): [80]})

        cursor = await db.execute(
            """SELECT service_name, http_status, http_headers, http_body_snippet,
                      http_server_header, favicon_hash, tls_cn, tls_issuer,
                      tls_not_after, protocol_version
               FROM service_profiles
               WHERE device_id = 1 AND port = 80"""
        )
        row = await cursor.fetchone()
        assert row is not None
        assert all(value is None for value in row)

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
    async def test_get_mimic_candidates_excludes_offline_devices(self, db) -> None:
        """Historical profiles from an offline source are not deployable."""
        engine = ScoutEngine(db=db, max_concurrent=5)
        await engine._persist_profile(ServiceProfile(
            device_id=1,
            ip_address="192.168.1.100",
            port=80,
            http_status=200,
            scouted_at="2026-01-01T00:00:00Z",
        ))
        await db.execute("UPDATE devices SET is_online = 0 WHERE id = 1")
        await db.commit()

        assert await engine.get_mimic_candidates(count=5) == []

    @pytest.mark.asyncio
    async def test_get_mimic_candidates_include_protocol_banners(self, db) -> None:
        """Banner-only services are valid mimic candidates."""
        engine = ScoutEngine(db=db, max_concurrent=5)

        # A captured SSH banner can be replayed without HTTP metadata.
        p = ServiceProfile(
            device_id=1, ip_address="192.168.1.100", port=22,
            protocol_version="SSH-2.0-OpenSSH_8.9p1",
            scouted_at="2026-01-01T00:00:00Z",
        )
        await engine._persist_profile(p)

        candidates = await engine.get_mimic_candidates(count=5)
        assert len(candidates) == 1
        assert candidates[0].protocol_version == "SSH-2.0-OpenSSH_8.9p1"

    @pytest.mark.asyncio
    async def test_mimic_candidate_limit_counts_devices_not_profile_rows(
        self, db,
    ) -> None:
        engine = ScoutEngine(db=db, max_concurrent=5)
        for port in (80, 8080):
            await engine._persist_profile(ServiceProfile(
                device_id=1,
                ip_address="192.168.1.100",
                port=port,
                http_status=200,
                scouted_at="2026-01-01T00:00:00Z",
            ))
        await engine._persist_profile(ServiceProfile(
            device_id=2,
            ip_address="192.168.1.101",
            port=80,
            http_status=200,
            scouted_at="2026-01-01T00:00:00Z",
        ))

        candidates = await engine.get_mimic_candidates(count=1)

        assert [profile.device_id for profile in candidates] == [1, 1]
        assert {profile.port for profile in candidates} == {80, 8080}

    @pytest.mark.asyncio
    async def test_mimic_candidates_exclude_already_deployed_sources(
        self, db,
    ) -> None:
        engine = ScoutEngine(db=db, max_concurrent=5)
        for device_id in (1, 2):
            await engine._persist_profile(ServiceProfile(
                device_id=device_id,
                ip_address=f"192.168.1.{99 + device_id}",
                port=80,
                http_status=200,
                scouted_at="2026-01-01T00:00:00Z",
            ))

        candidates = await engine.get_mimic_candidates(
            count=1,
            exclude_device_ids={1},
        )

        assert [profile.device_id for profile in candidates] == [2]


class TestScoutSchedulerInventory:
    """Verify scheduler authority boundaries around inventory reconciliation."""

    @pytest.mark.asyncio
    async def test_successful_empty_inventory_removes_stale_profiles(self, db) -> None:
        engine = ScoutEngine(db=db, max_concurrent=5)
        await engine._persist_profile(ServiceProfile(
            device_id=1,
            ip_address="192.168.1.100",
            port=80,
            http_status=200,
            scouted_at="2026-01-01T00:00:00Z",
        ))
        await db.execute("UPDATE devices SET is_online = 0 WHERE id = 1")
        await db.commit()
        scheduler = ScoutScheduler(
            engine=engine,
            db=db,
            event_bus=MagicMock(),
            interval_minutes=30,
        )

        assert await scheduler._execute_scout_cycle() == 0
        cursor = await db.execute("SELECT COUNT(*) FROM service_profiles")
        assert (await cursor.fetchone())[0] == 0

    @pytest.mark.asyncio
    async def test_inventory_read_failure_does_not_reconcile_profiles(self, db) -> None:
        engine = MagicMock(spec=ScoutEngine)
        engine.scout_all = AsyncMock()
        scheduler = ScoutScheduler(
            engine=engine,
            db=db,
            event_bus=MagicMock(),
            interval_minutes=30,
        )
        scheduler._get_device_ports = AsyncMock(
            side_effect=RuntimeError("inventory unavailable")
        )

        with pytest.raises(RuntimeError, match="inventory unavailable"):
            await scheduler._execute_scout_cycle()

        engine.scout_all.assert_not_awaited()
