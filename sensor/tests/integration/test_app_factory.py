"""Integration tests for FastAPI app factory, DI, and auth middleware."""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from squirrelops_home_sensor import __version__
from squirrelops_home_sensor.app import create_app
from squirrelops_home_sensor.api.deps import get_db, get_event_bus, get_config, verify_client_cert


class TestAppFactory:
    """Test that create_app produces a working FastAPI application."""

    def test_create_app_returns_fastapi_instance(self, sensor_config):
        app = create_app(sensor_config)
        assert isinstance(app, FastAPI)

    def test_app_has_title_and_version(self, sensor_config):
        app = create_app(sensor_config)
        assert app.title == "SquirrelOps Home Sensor"
        assert app.version == __version__

    def test_app_includes_all_routers(self, sensor_config):
        app = create_app(sensor_config)
        route_paths = [route.path for route in app.routes]
        assert "/system/health" in route_paths
        assert "/ws/events" in route_paths

    def test_health_endpoint_no_auth_required(self, client):
        """Health endpoint must work without authentication."""
        response = client.get("/system/health")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "sensor_id" in data
        assert "uptime_seconds" in data


class TestDependencyInjection:
    """Test that FastAPI dependency injection is wired correctly."""

    def test_get_db_dependency_is_overridable(self, app):
        assert get_db in app.dependency_overrides

    def test_get_event_bus_dependency_is_overridable(self, app):
        assert get_event_bus in app.dependency_overrides

    def test_get_config_dependency_is_overridable(self, app):
        assert get_config in app.dependency_overrides

    def test_verify_client_cert_dependency_is_overridable(self, app):
        assert verify_client_cert in app.dependency_overrides


class TestAuthMiddleware:
    """Test TLS client cert verification."""

    def test_authenticated_route_returns_200_with_valid_auth(self, client, db):
        """Routes requiring auth should succeed when auth dependency is overridden."""
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                """INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type,
                   first_seen, last_seen, is_online)
                   VALUES ('192.168.1.1', 'AA:BB:CC:DD:EE:01', 'test', 'Test', 'unknown',
                   '2026-02-22T00:00:00Z', '2026-02-22T00:00:00Z', 1)"""
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        response = client.get("/devices")
        assert response.status_code == 200

    def test_unauthenticated_route_returns_403(self, sensor_config):
        """Without auth override, protected routes should return 403."""
        app = create_app(sensor_config)
        import aiosqlite
        from squirrelops_home_sensor.db.schema import create_all_tables

        _db = None

        async def setup_db():
            nonlocal _db
            _db = await aiosqlite.connect(":memory:")
            _db.row_factory = aiosqlite.Row
            await _db.execute("PRAGMA foreign_keys = ON")
            await create_all_tables(_db)

        asyncio.get_event_loop().run_until_complete(setup_db())

        async def override_db():
            yield _db

        async def override_event_bus():
            from squirrelops_home_sensor.events.log import EventLog
            from squirrelops_home_sensor.events.bus import EventBus
            return EventBus(EventLog(_db))

        async def override_config():
            return sensor_config

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_event_bus] = override_event_bus
        app.dependency_overrides[get_config] = override_config
        # verify_client_cert is NOT overridden — it should reject

        client = TestClient(app)
        response = client.get("/devices")
        assert response.status_code == 403

        asyncio.get_event_loop().run_until_complete(_db.close())

    def test_pairing_routes_skip_auth(self, sensor_config):
        """Pairing routes must be accessible without client cert auth."""
        app = create_app(sensor_config)

        import aiosqlite
        from squirrelops_home_sensor.db.schema import create_all_tables

        _db = None

        async def setup_db():
            nonlocal _db
            _db = await aiosqlite.connect(":memory:")
            _db.row_factory = aiosqlite.Row
            await _db.execute("PRAGMA foreign_keys = ON")
            await create_all_tables(_db)

        asyncio.get_event_loop().run_until_complete(setup_db())

        async def override_db():
            yield _db

        async def override_event_bus():
            from squirrelops_home_sensor.events.log import EventLog
            from squirrelops_home_sensor.events.bus import EventBus
            return EventBus(EventLog(_db))

        async def override_config():
            return sensor_config

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_event_bus] = override_event_bus
        app.dependency_overrides[get_config] = override_config

        client = TestClient(app)
        response = client.get("/pairing/code/challenge")
        # Should not be 403 — pairing routes do not require client cert auth
        assert response.status_code != 403

        asyncio.get_event_loop().run_until_complete(_db.close())
