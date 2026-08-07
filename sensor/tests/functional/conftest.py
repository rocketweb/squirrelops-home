"""Fixtures for the functional suite.

Reuses the integration fixtures rather than duplicating them, so the functional
cases exercise the same wiring the integration suite does.
"""

from tests.integration.conftest import (  # noqa: F401
    app,
    client,
    db,
    event_bus,
    sensor_config,
)
