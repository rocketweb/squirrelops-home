"""FastAPI application factory for the SquirrelOps Home Sensor."""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from squirrelops_home_sensor.api.routes_system import router as system_router
from squirrelops_home_sensor.api.routes_devices import router as devices_router
from squirrelops_home_sensor.api.routes_alerts import router as alerts_router
from squirrelops_home_sensor.api.routes_decoys import router as decoys_router
from squirrelops_home_sensor.api.routes_config import router as config_router
from squirrelops_home_sensor.api.routes_pairing import router as pairing_router
from squirrelops_home_sensor.api.routes_ports import router as ports_router
from squirrelops_home_sensor.api.routes_scouts import router as scouts_router
from squirrelops_home_sensor.api.ws import router as ws_router


def create_app(config: dict, ca_key=None, ca_cert=None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Sensor configuration dictionary.
        ca_key: Optional CA private key from TLS startup.
        ca_cert: Optional CA certificate from TLS startup.

    Returns:
        Configured FastAPI application instance.
    """
    start_time = time.time()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # Store startup time and config on app state for access by routes
        app.state.start_time = start_time
        app.state.config = config
        app.state.ca_key = ca_key
        app.state.ca_cert = ca_cert
        yield

    app = FastAPI(
        title="SquirrelOps Home Sensor",
        version=config.get("version", "0.0.0"),
        lifespan=lifespan,
    )

    # Store config and start_time directly for access outside lifespan
    app.state.start_time = start_time
    app.state.config = config
    app.state.ca_key = ca_key
    app.state.ca_cert = ca_cert

    # Include routers -- pairing and system/health do NOT require auth
    app.include_router(system_router)
    app.include_router(devices_router)
    app.include_router(alerts_router)
    app.include_router(decoys_router)
    app.include_router(config_router)
    app.include_router(pairing_router)
    app.include_router(ports_router)
    app.include_router(scouts_router)
    app.include_router(ws_router)

    return app
