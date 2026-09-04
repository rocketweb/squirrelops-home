"""Lifecycle acceptance for the 2.1 Studio Mini deep decoy."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.decoys.deep.orchestrator import (
    DEEP_SECRET_KEY,
    DeepDecoyOrchestrator,
    load_or_create_deployment_secret,
)


class _SecretStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str) -> None:
        self.values[key] = value


class _IPManager:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def allocate_verified(self, count: int) -> list[str]:
        assert count == 1
        self.calls.append("allocate")
        return ["192.0.2.240"]

    async def add_alias(self, address: str) -> bool:
        self.calls.append(f"alias:add:{address}")
        return True

    async def remove_alias(self, address: str) -> bool:
        self.calls.append(f"alias:remove:{address}")
        return True

    async def is_verified_free(self, address: str) -> bool:
        self.calls.append(f"verify:{address}")
        return True

    def release_reservation(self, address: str) -> None:
        self.calls.append(f"release:{address}")


class _PortForward:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def quarantine_endpoints(self, endpoints: dict[int, str]) -> bool:
        self.calls.append(f"quarantine:{','.join(endpoints.values())}")
        return True

    async def add_forwards(
        self,
        decoy_id: int,
        address: str,
        remaps: dict[int, int],
        *,
        exposed_ports: set[int],
    ) -> bool:
        assert set(remaps) == exposed_ports == {22, 445, 1234, 8765, 11434}
        assert len(set(remaps.values())) == 5
        self.calls.append(f"forwards:add:{address}")
        return True

    async def remove_forwards(self, decoy_id: int) -> bool:
        self.calls.append(f"forwards:remove:{decoy_id}")
        return True


class _MDNS:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def register(self, *_args: Any, **_kwargs: Any) -> bool:
        self.calls.append("mdns:register")
        return True

    async def unregister(self, decoy_id: int) -> None:
        self.calls.append(f"mdns:unregister:{decoy_id}")


class _Guest:
    def __init__(self, calls: list[str], **kwargs: Any) -> None:
        self.calls = calls
        self.kwargs = kwargs
        self.is_running = False

    async def start(self) -> dict[int, int]:
        self.calls.append("guest:start")
        self.is_running = True
        return {22: 49022, 445: 49445}

    async def stop(self) -> None:
        self.calls.append("guest:stop")
        self.is_running = False

    def crash(self, returncode: int) -> None:
        self.is_running = False
        self.kwargs["on_exit"](returncode)


class _AI:
    next_port = 51000

    def __init__(self, calls: list[str], **kwargs: Any) -> None:
        self.calls = calls
        self.surface = kwargs["surface"]
        self.port = 0
        self.on_connection = None
        self.is_running = False

    async def start(self) -> None:
        type(self).next_port += 1
        self.port = type(self).next_port
        self.is_running = True
        self.calls.append(f"ai:start:{self.surface}")

    async def stop(self) -> None:
        self.is_running = False
        self.calls.append(f"ai:stop:{self.surface}")


class _Events:
    def __init__(self) -> None:
        self.items: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        self.items.append((event_type, payload))


async def _orchestrator(
    db: aiosqlite.Connection,
    calls: list[str],
    *,
    guest_factory: Any | None = None,
) -> tuple[DeepDecoyOrchestrator, _Events]:
    events = _Events()
    ip_manager = _IPManager(calls)
    return (
        DeepDecoyOrchestrator(
            db=db,
            event_bus=events,
            ip_manager=ip_manager,
            port_forward_manager=_PortForward(calls),
            mdns_advertiser=_MDNS(calls),
            backend_bind_address_for=lambda address: address,
            deployment_secret=b"s" * 32,
            runtime_path=Path("/trusted/runtime"),
            guest_bundle=Path("/trusted/bundle"),
            guest_factory=guest_factory or (lambda **kwargs: _Guest(calls, **kwargs)),
            ai_factory=lambda **kwargs: _AI(calls, **kwargs),
        ),
        events,
    )


@pytest.mark.asyncio
async def test_deployment_secret_is_stable_and_stored_opaque() -> None:
    store = _SecretStore()

    first = await load_or_create_deployment_secret(store)
    second = await load_or_create_deployment_secret(store)

    assert first == second
    assert len(first) == 32
    assert store.values[DEEP_SECRET_KEY] != first.hex()


@pytest.mark.asyncio
async def test_provision_publishes_one_grouped_host_fail_closed(tmp_path) -> None:
    calls: list[str] = []
    async with aiosqlite.connect(tmp_path / "deep.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        orchestrator, events = await _orchestrator(db, calls)

        assert await orchestrator.start() is True

        cursor = await db.execute(
            "SELECT port, status, is_primary FROM decoys WHERE decoy_type = 'deep'"
        )
        rows = list(await cursor.fetchall())
        assert {(row["port"], row["status"]) for row in rows} == {
            (22, "active"),
            (445, "active"),
            (1234, "active"),
            (8765, "active"),
            (11434, "active"),
        }
        assert [row["port"] for row in rows if row["is_primary"]] == [445]
        cursor = await db.execute("SELECT COUNT(*) FROM planted_credentials")
        assert (await cursor.fetchone())[0] == 4

        assert calls[:2] == ["allocate", "quarantine:192.0.2.240"]
        assert calls.index("alias:add:192.0.2.240") < calls.index("guest:start")
        assert calls.index("guest:start") < calls.index("forwards:add:192.0.2.240")
        assert calls.index("forwards:add:192.0.2.240") < calls.index("mdns:register")
        assert len([call for call in calls if call == "mdns:register"]) == 5
        status_events = [item for item in events.items if item[0] == "decoy.status_changed"]
        assert len(status_events) == 5


@pytest.mark.asyncio
async def test_restart_withdraws_and_reverifies_address_before_republish(tmp_path) -> None:
    calls: list[str] = []
    async with aiosqlite.connect(tmp_path / "deep.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        orchestrator, _events = await _orchestrator(db, calls)
        assert await orchestrator.start() is True
        cursor = await db.execute(
            "SELECT id FROM decoys WHERE decoy_type = 'deep' AND port = 22"
        )
        service_id = int((await cursor.fetchone())["id"])

        calls.clear()
        assert await orchestrator.restart(service_id) is True

        assert calls.index("quarantine:192.0.2.240") < calls.index(
            "alias:remove:192.0.2.240"
        )
        assert calls.index("alias:remove:192.0.2.240") < calls.index(
            "verify:192.0.2.240"
        )
        assert calls.index("verify:192.0.2.240") < calls.index(
            "alias:add:192.0.2.240"
        )
        assert calls.index("alias:add:192.0.2.240") < calls.index("guest:start")


@pytest.mark.asyncio
async def test_callback_from_worker_thread_uses_lifecycle_loop(tmp_path) -> None:
    calls: list[str] = []
    async with aiosqlite.connect(tmp_path / "deep.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        orchestrator, _events = await _orchestrator(db, calls)
        assert await orchestrator.start() is True

        completed = SimpleNamespace(value=False)

        async def mark_completed() -> None:
            completed.value = True

        await asyncio.to_thread(orchestrator._schedule, mark_completed())
        for _ in range(20):
            if completed.value:
                break
            await asyncio.sleep(0.01)

        assert completed.value is True


@pytest.mark.asyncio
async def test_invalid_guest_stays_degraded_and_never_publishes_ports(tmp_path) -> None:
    calls: list[str] = []

    class _RejectedGuest(_Guest):
        async def start(self) -> dict[int, int]:
            self.calls.append("guest:reject")
            raise RuntimeError("guest digest rejected")

    async with aiosqlite.connect(tmp_path / "deep.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        orchestrator, _events = await _orchestrator(
            db,
            calls,
            guest_factory=lambda **kwargs: _RejectedGuest(calls, **kwargs),
        )

        assert await orchestrator.start() is False

        cursor = await db.execute(
            "SELECT id, status FROM decoys WHERE decoy_type = 'deep' ORDER BY id"
        )
        rows = list(await cursor.fetchall())
        assert len(rows) == 5
        assert {row["status"] for row in rows} == {"active"}
        assert all(
            orchestrator.effective_status(row["id"], row["status"]) == "degraded"
            for row in rows
        )
        assert "forwards:add:192.0.2.240" not in calls
        assert "mdns:register" not in calls
        assert "alias:remove:192.0.2.240" in calls
        assert any(call.startswith("forwards:remove:") for call in calls)


@pytest.mark.asyncio
async def test_runtime_crash_quarantines_and_withdraws_the_complete_host(tmp_path) -> None:
    calls: list[str] = []
    guests: list[_Guest] = []

    def guest_factory(**kwargs: Any) -> _Guest:
        guest = _Guest(calls, **kwargs)
        guests.append(guest)
        return guest

    async with aiosqlite.connect(tmp_path / "deep.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        orchestrator, events = await _orchestrator(
            db,
            calls,
            guest_factory=guest_factory,
        )
        assert await orchestrator.start() is True
        cursor = await db.execute(
            "SELECT id, port, status FROM decoys WHERE decoy_type = 'deep' ORDER BY id"
        )
        rows = list(await cursor.fetchall())
        primary_id = next(row["id"] for row in rows if row["port"] == 445)

        calls.clear()
        guests[0].crash(23)
        for _ in range(50):
            if not orchestrator.is_active:
                break
            await asyncio.sleep(0.01)

        assert orchestrator.is_active is False
        assert calls.index("quarantine:192.0.2.240") < calls.index(
            "alias:remove:192.0.2.240"
        )
        assert "guest:stop" in calls
        assert f"mdns:unregister:{primary_id}" in calls
        assert f"forwards:remove:{primary_id}" in calls
        assert {row["status"] for row in rows} == {"active"}
        assert all(
            orchestrator.effective_status(row["id"], row["status"]) == "degraded"
            for row in rows
        )
        degraded = [
            payload
            for event_type, payload in events.items
            if event_type == "decoy.status_changed" and payload["status"] == "degraded"
        ]
        assert len(degraded) == 5
