"""Scout scheduler — runs deep service fingerprinting on a background timer.

Scouting is heavier than port scanning (probes HTTP, TLS, and protocol
banners on every open port), so it runs on its own timer rather than
in the scan loop. Subscribes to ``system.scan_complete`` events to
pick up fresh port data, then scouts after a configurable delay.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from squirrelops_home_sensor.events.bus import EventBus
from squirrelops_home_sensor.events.types import EventType
from squirrelops_home_sensor.scouts.engine import ScoutEngine

logger = logging.getLogger("squirrelops_home_sensor.scouts")


class ScoutScheduler:
    """Manages periodic scouting of all discovered devices.

    Parameters
    ----------
    engine:
        The ScoutEngine that performs the actual probing.
    db:
        Database connection for querying device/port data.
    event_bus:
        Event bus for subscribing to scan-complete events.
    interval_minutes:
        Minutes between scout cycles. Set to 0 to disable automatic scouting.
    initial_delay_seconds:
        Seconds to wait after first scan-complete before scouting.
    """

    def __init__(
        self,
        engine: ScoutEngine,
        db: aiosqlite.Connection,
        event_bus: EventBus,
        interval_minutes: int = 30,
        initial_delay_seconds: float = 30.0,
    ) -> None:
        self._engine = engine
        self._db = db
        self._event_bus = event_bus
        self._interval_minutes = interval_minutes
        self._initial_delay = initial_delay_seconds
        self._task: asyncio.Task[None] | None = None
        self._shutdown = asyncio.Event()
        self._run_now_event = asyncio.Event()
        self._first_scan_received = asyncio.Event()
        self._subscription = None
        self._last_scout_at: datetime | None = None
        self._last_scout_duration_ms: int | None = None
        self._total_profiles: int = 0

    @property
    def last_scout_at(self) -> datetime | None:
        """When the last scout cycle completed."""
        return self._last_scout_at

    @property
    def last_scout_duration_ms(self) -> int | None:
        """Duration of the last scout cycle in milliseconds."""
        return self._last_scout_duration_ms

    @property
    def total_profiles(self) -> int:
        """Total profiles created in the last scout run."""
        return self._total_profiles

    @property
    def interval_minutes(self) -> int:
        """Configured interval between scout cycles."""
        return self._interval_minutes

    @property
    def is_running(self) -> bool:
        """Whether the scheduler is currently running."""
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start the scout scheduler as a background asyncio task."""
        if self._interval_minutes <= 0:
            logger.info("Scout scheduler disabled (interval=0)")
            return

        self._shutdown.clear()
        self._subscription = self._event_bus.subscribe(
            [EventType.SYSTEM_SCAN_COMPLETE],
            self._on_scan_complete,
        )
        self._task = asyncio.create_task(self._run_loop())
        logger.info(
            "Scout scheduler started (interval=%dm, initial_delay=%.0fs)",
            self._interval_minutes,
            self._initial_delay,
        )

    async def stop(self) -> None:
        """Stop the scheduler."""
        self._shutdown.set()
        if self._subscription is not None:
            self._event_bus.unsubscribe(self._subscription)
            self._subscription = None
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
            self._task = None
        logger.info("Scout scheduler stopped")

    async def run_now(self) -> int:
        """Trigger an immediate scout cycle. Returns profile count."""
        return await self._run_scout_cycle()

    async def _on_scan_complete(self, event: dict) -> None:
        """Handle scan-complete events to know when port data is fresh."""
        if not self._first_scan_received.is_set():
            self._first_scan_received.set()
            logger.debug("First scan-complete received, scout will start after delay")

    async def _run_loop(self) -> None:
        """Main scheduler loop."""
        # Wait for the first scan to complete so we have port data
        while not self._shutdown.is_set():
            try:
                await asyncio.wait_for(
                    self._first_scan_received.wait(),
                    timeout=5.0,
                )
                break
            except asyncio.TimeoutError:
                if self._shutdown.is_set():
                    return

        # Initial delay after first scan
        try:
            await asyncio.wait_for(
                self._shutdown.wait(),
                timeout=self._initial_delay,
            )
            return  # Shutdown during initial delay
        except asyncio.TimeoutError:
            pass

        # Run scout cycles
        while not self._shutdown.is_set():
            try:
                await self._run_scout_cycle()
            except Exception:
                logger.exception("Scout cycle failed")

            # Wait for interval or manual trigger
            interval_seconds = self._interval_minutes * 60
            try:
                # Use asyncio.wait to handle either shutdown or manual trigger
                done, _ = await asyncio.wait(
                    [
                        asyncio.create_task(self._shutdown.wait()),
                        asyncio.create_task(self._run_now_event.wait()),
                    ],
                    timeout=interval_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # Cancel remaining tasks
                for task in _:
                    task.cancel()

                if self._shutdown.is_set():
                    return
                if self._run_now_event.is_set():
                    self._run_now_event.clear()
            except asyncio.TimeoutError:
                pass

        logger.info("Scout scheduler loop ended")

    async def _run_scout_cycle(self) -> int:
        """Execute a single scout cycle across all devices with open ports."""
        start = time.monotonic()
        logger.info("Starting scout cycle")

        # Query all devices with open ports
        device_ports = await self._get_device_ports()
        if not device_ports:
            logger.info("No devices with open ports to scout")
            return 0

        total_ports = sum(len(ports) for ports in device_ports.values())
        logger.info(
            "Scouting %d devices with %d total ports",
            len(device_ports),
            total_ports,
        )

        count = await self._engine.scout_all(device_ports)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._last_scout_at = datetime.now(timezone.utc)
        self._last_scout_duration_ms = elapsed_ms
        self._total_profiles = count

        logger.info(
            "Scout cycle complete: %d profiles in %dms",
            count,
            elapsed_ms,
        )
        return count

    async def _get_device_ports(self) -> dict[tuple[int, str], list[int]]:
        """Query database for all devices with open ports.

        Returns a mapping of (device_id, ip_address) -> [port_numbers].
        """
        cursor = await self._db.execute(
            """SELECT d.id, d.ip_address, p.port
               FROM devices d
               JOIN device_open_ports p ON p.device_id = d.id
               WHERE d.is_online = 1
               ORDER BY d.id, p.port"""
        )
        rows = await cursor.fetchall()

        result: dict[tuple[int, str], list[int]] = {}
        for row in rows:
            key = (row["id"], row["ip_address"])
            result.setdefault(key, []).append(row["port"])

        return result
