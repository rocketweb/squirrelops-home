"""Live HTTP acceptance for the 2.1 OpenAI, Ollama, and MCP decoy."""

import json
from datetime import UTC, datetime

import aiosqlite
import httpx
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.decoys.deep.ai_workbench import AIWorkbenchDecoy
from squirrelops_home_sensor.decoys.deep.narrative import (
    IntruderIntent,
    NarrativeStage,
)
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona
from squirrelops_home_sensor.decoys.types.base import DecoyConnectionEvent


@pytest.fixture
async def database(tmp_path):
    db = await aiosqlite.connect(tmp_path / "workbench.db")
    db.row_factory = aiosqlite.Row
    await apply_migrations(db)
    await db.execute(
        """INSERT INTO decoys
           (id, name, decoy_type, bind_address, port, status, created_at, updated_at)
           VALUES (41, 'studio-mini.local', 'ai_workbench', '127.0.0.1', 0,
                   'active', '2026-08-31T14:00:00Z', '2026-08-31T14:00:00Z')"""
    )
    await db.commit()
    yield db
    await db.close()


@pytest.fixture
async def decoy(database):
    instance = AIWorkbenchDecoy(
        decoy_id=41,
        name="studio-mini.local",
        port=0,
        bind_address="127.0.0.1",
        db=database,
        deployment_secret=b"unit-test-deployment-secret-with-32-bytes",
        persona_created_at=datetime(2026, 8, 31, 14, 0, tzinfo=UTC),
    )
    await instance.start()
    yield instance
    await instance.stop()


@pytest.fixture
def base_url(decoy):
    return f"http://{decoy.bind_address}:{decoy.port}"


@pytest.mark.asyncio
async def test_serves_openai_model_list_and_ollama_header(decoy, base_url) -> None:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{base_url}/v1/models")

    assert response.status_code == 200
    assert response.headers["server"] == "Ollama"
    assert response.json()["data"][0]["id"] == "fieldkit-coder:14b"
    assert await decoy.health_check() is True


@pytest.mark.asyncio
async def test_one_request_emits_one_rich_connection_event(decoy, base_url) -> None:
    events: list[DecoyConnectionEvent] = []
    decoy.on_connection = events.append

    async with httpx.AsyncClient() as client:
        await client.get(f"{base_url}/v1/models", headers={"User-Agent": "curl/8.7"})

    assert len(events) == 1
    assert events[0].request_path == "/v1/models"
    assert events[0].intruder_intent == IntruderIntent.SCANNER.value
    assert events[0].narrative_stage == int(NarrativeStage.DISCOVERY)
    assert events[0].interaction_type == "openai.models.list"


@pytest.mark.asyncio
async def test_mcp_tool_call_advances_persisted_campaign(decoy, database, base_url) -> None:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/mcp",
            headers={"User-Agent": "claude-code/1.0"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_runbook", "arguments": {}},
            },
        )

    assert response.status_code == 200
    cursor = await database.execute(
        "SELECT intent, stage FROM deception_campaigns WHERE decoy_id = 41"
    )
    row = await cursor.fetchone()
    assert row["intent"] == IntruderIntent.DEVELOPER_AGENT.value
    assert row["stage"] == int(NarrativeStage.AGENT_TOOL_USE)


@pytest.mark.asyncio
async def test_submitted_planted_key_is_reported_as_credential_use(decoy, base_url) -> None:
    persona = build_studio_mini_persona(
        b"unit-test-deployment-secret-with-32-bytes",
        datetime(2026, 8, 31, 14, 0, tzinfo=UTC),
    )
    events: list[DecoyConnectionEvent] = []
    decoy.on_connection = events.append

    async with httpx.AsyncClient() as client:
        await client.get(
            f"{base_url}/v1/models",
            headers={"Authorization": f"Bearer {persona.openai_api_key}"},
        )

    assert len(events) == 1
    assert events[0].credential_used == persona.openai_api_key


@pytest.mark.asyncio
async def test_secret_returned_by_tool_is_not_misreported_as_submitted(decoy, base_url) -> None:
    events: list[DecoyConnectionEvent] = []
    decoy.on_connection = events.append

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "search_secrets",
                    "arguments": {"query": "OPENAI_API_KEY"},
                },
            },
        )

    assert "sk-proj-" in response.text
    assert events[0].credential_used is None


@pytest.mark.asyncio
async def test_malformed_json_has_byte_exact_boring_error(decoy, base_url) -> None:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/api/chat",
            content=b"{not-json",
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 400
    assert response.content == b'{"error":"invalid JSON body"}'


@pytest.mark.asyncio
async def test_stop_releases_listener(database) -> None:
    decoy = AIWorkbenchDecoy(
        decoy_id=41,
        name="studio-mini.local",
        port=0,
        bind_address="127.0.0.1",
        db=database,
        deployment_secret=b"unit-test-deployment-secret-with-32-bytes",
        persona_created_at=datetime(2026, 8, 31, 14, 0, tzinfo=UTC),
    )
    await decoy.start()
    port = decoy.port
    await decoy.stop()

    assert decoy.is_running is False
    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(f"http://127.0.0.1:{port}/v1/models")


@pytest.mark.asyncio
async def test_split_surface_reports_advertised_port_and_does_not_cross_protocols(
    database,
) -> None:
    decoy = AIWorkbenchDecoy(
        decoy_id=41,
        name="studio-mini.local",
        port=0,
        advertised_port=1234,
        surface="openai",
        bind_address="127.0.0.1",
        db=database,
        deployment_secret=b"unit-test-deployment-secret-with-32-bytes",
        persona_created_at=datetime(2026, 8, 31, 14, 0, tzinfo=UTC),
    )
    events: list[DecoyConnectionEvent] = []
    decoy.on_connection = events.append
    await decoy.start()
    try:
        async with httpx.AsyncClient() as client:
            models = await client.get(f"http://127.0.0.1:{decoy.port}/v1/models")
            ollama = await client.get(f"http://127.0.0.1:{decoy.port}/api/tags")
    finally:
        await decoy.stop()

    assert models.status_code == 200
    assert models.headers["server"] == "uvicorn"
    assert ollama.status_code == 404
    assert [event.dest_port for event in events] == [1234, 1234]


@pytest.mark.asyncio
@pytest.mark.parametrize("path,content_type", [
    ("/v1/chat/completions", "text/event-stream"),
    ("/api/chat", "application/x-ndjson"),
])
async def test_live_stream_framing_and_one_credential_event(decoy, base_url, path, content_type):
    events = []
    decoy.on_connection = events.append
    async with httpx.AsyncClient() as client:
        async with client.stream("POST", base_url + path, json={
            "model": decoy.persona.model_names[0],
            "messages": [{"role": "user", "content": "hello"}], "stream": True,
        }, headers={"Authorization": f"Bearer {decoy.persona.openai_api_key}"}) as response:
            assert response.headers["content-type"].split(";")[0] == content_type
            assert response.headers["transfer-encoding"] == "chunked"
            lines = [line async for line in response.aiter_lines() if line]
    if path.startswith("/v1"):
        assert lines[-1] == "data: [DONE]"
        assert all(json.loads(line[6:])["object"] == "chat.completion.chunk" for line in lines[:-1])
    else:
        assert json.loads(lines[-1])["done"] is True
        assert json.loads(lines[0])["done"] is False
    assert len(events) == 1
    assert events[0].credential_used == decoy.persona.openai_api_key
    assert await decoy.health_check() is True
