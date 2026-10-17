"""AI setup probes use synthetic data, saved credentials, and bounded transport."""

import json
from copy import deepcopy

import httpx
import pytest


@pytest.fixture
def ai_config(sensor_config):
    sensor_config["classifier"] = {
        "llm_provider": "custom",
        "llm_endpoint": "http://localhost:1234/v1",
        "llm_model": "test-model",
        "llm_api_key": "synthetic-test-key",
    }
    return sensor_config


def mock_provider(monkeypatch, handler):
    from squirrelops_home_sensor.api import ai_diagnostics as ai

    monkeypatch.setattr(
        ai,
        "make_client",
        lambda: ai.DiagnosticClient(
            transport=httpx.MockTransport(handler),
            timeout=10,
            follow_redirects=False,
            trust_env=False,
        ),
    )


def test_discovery_is_read_only_and_filters_known_non_chat_models(client, ai_config, monkeypatch):
    before = deepcopy(ai_config)
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "chat", "name": "Chat model"},
                    {"id": "chat"},
                    {"id": "embed", "type": "embeddings"},
                    {"id": "image", "architecture": {"output_modalities": ["image"]}},
                ]
            },
        )

    mock_provider(monkeypatch, provider)
    response = client.post("/config/ai/models")
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert result["status"] == "ok"
    assert result["models"] == [{"id": "chat", "name": "Chat model"}]
    assert str(calls[0].url) == "http://localhost:1234/v1/models"
    assert calls[0].headers["authorization"] == "Bearer synthetic-test-key"
    assert len(calls) == 1 and calls[0].method == "GET"
    assert ai_config == before
    assert "synthetic-test-key" not in json.dumps(result)


def test_test_model_exercises_both_real_parsers_with_synthetic_data(client, ai_config, monkeypatch):
    bodies = []

    def provider(request):
        body = json.loads(request.content)
        bodies.append(body)
        content = (
            {
                "manufacturer": "Example",
                "device_type": "printer",
                "model": "Test",
                "confidence": 0.9,
            }
            if len(bodies) == 1
            else {"hostnames": ["archive"]}
        )
        return httpx.Response(
            200, json={"choices": [{"message": {"content": json.dumps(content)}}]}
        )

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/test").json()
    assert result["status"] == "ok"
    assert result["checks"] == {"classification": True, "naming": True}
    assert len(bodies) == 2
    assert all(b["max_tokens"] == 512 and b["model"] == "test-model" for b in bodies)
    assert "synthetic-printer" in json.dumps(bodies[0])
    assert "synthetic-test-key" not in json.dumps(bodies)
    assert result["elapsed_ms"] >= 0


@pytest.mark.parametrize(
    "code,status,phrase",
    [
        (401, "error", "key"),
        (403, "error", "permission"),
        (402, "error", "credit"),
        (429, "error", "limit"),
        (500, "error", "provider"),
        (404, "unsupported", "manual"),
        (302, "error", "redirect"),
    ],
)
def test_catalog_errors_are_actionable_without_echoing_secrets(
    client, ai_config, monkeypatch, code, status, phrase
):
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(
            code,
            text="synthetic-test-key private provider response",
            headers={"location": "https://unrelated.example/collect"},
        )

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/models").json()
    assert result["status"] == status
    assert phrase in result["message"].lower()
    assert "synthetic-test-key" not in json.dumps(result)
    assert len(calls) == 1


def test_invalid_generation_never_passes(client, ai_config, monkeypatch):
    mock_provider(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Hello, not JSON"}}],
            },
        ),
    )
    result = client.post("/config/ai/test").json()
    assert result["status"] == "error"
    assert result["checks"]["classification"] is False


def test_no_provider_or_missing_cloud_key_never_connects(client, ai_config, monkeypatch):
    def forbidden(request):
        pytest.fail("Unconfigured diagnostics must not contact a provider")

    mock_provider(monkeypatch, forbidden)
    ai_config["classifier"]["llm_provider"] = "none"
    assert client.post("/config/ai/models").json()["status"] == "error"
    ai_config["classifier"].update(llm_provider="openrouter", llm_api_key=None)
    assert client.post("/config/ai/models").json()["status"] == "error"


def test_fireworks_uses_canonical_catalog_and_paginates(client, ai_config, monkeypatch):
    ai_config["classifier"]["llm_provider"] = "fireworks"
    calls = []

    def provider(request):
        calls.append(request)
        assert request.url.host == "api.fireworks.ai"
        assert request.url.path == "/v1/accounts/fireworks/models"
        if len(calls) == 1:
            return httpx.Response(
                200,
                json={
                    "models": [{"name": "accounts/fireworks/models/chat-a"}],
                    "nextPageToken": "page-2",
                },
            )
        assert request.url.params["pageToken"] == "page-2"
        return httpx.Response(200, json={"models": [{"name": "accounts/fireworks/models/chat-b"}]})

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/models").json()
    assert result["status"] == "ok"
    assert len(result["models"]) == 2


def test_oversized_response_is_rejected(client, ai_config, monkeypatch):
    mock_provider(
        monkeypatch, lambda request: httpx.Response(200, content=b"x" * (2 * 1024 * 1024 + 1))
    )
    assert client.post("/config/ai/models").json()["status"] == "error"


def test_timeout_is_reported_without_url_or_key(client, ai_config, monkeypatch):
    def provider(request):
        raise httpx.ReadTimeout("synthetic-test-key", request=request)

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/test").json()
    assert result["status"] == "error"
    assert "timed out" in result["message"]
    assert "synthetic-test-key" not in json.dumps(result)


def test_authentication_required(client, app):
    from squirrelops_home_sensor.api.deps import verify_client_cert

    app.dependency_overrides.pop(verify_client_cert)
    assert client.post("/config/ai/models").status_code in (401, 403)
    assert client.post("/config/ai/test").status_code in (401, 403)


def test_diagnostics_are_rate_limited(client, ai_config, monkeypatch):
    mock_provider(monkeypatch, lambda request: httpx.Response(200, json={"data": []}))
    for _ in range(6):
        assert client.post("/config/ai/models").status_code == 200
    assert client.post("/config/ai/models").status_code == 429


def test_empty_choices_is_a_failed_test_not_a_server_error(client, ai_config, monkeypatch):
    mock_provider(monkeypatch, lambda request: httpx.Response(200, json={"choices": []}))
    result = client.post("/config/ai/test").json()
    assert result["status"] == "error"


@pytest.mark.parametrize(
    "endpoint",
    [
        "file:///etc/passwd",
        "http://user:secret@localhost/v1",
        "http://localhost/v1?api_key=secret",
        "http://[bad",
    ],
)
def test_unsafe_url_shapes_never_connect(client, ai_config, monkeypatch, endpoint):
    ai_config["classifier"]["llm_endpoint"] = endpoint

    def forbidden(request):
        pytest.fail("Invalid URL reached the network")

    mock_provider(monkeypatch, forbidden)
    result = client.post("/config/ai/models").json()
    assert result["status"] == "error"
    assert "secret" not in result["message"]


def test_settings_changed_during_request_discards_result(client, ai_config, monkeypatch):
    def provider(request):
        ai_config["classifier"]["llm_model"] = "replacement-model"
        return httpx.Response(200, json={"data": [{"id": "old-model"}]})

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/models").json()
    assert result["status"] == "error"
    assert result["models"] == []
    assert "changed" in result["message"]


def test_busy_check_does_not_make_another_request(client, app, ai_config, monkeypatch):
    app.state.ai_probe_busy = True

    def forbidden(request):
        pytest.fail("Concurrent probe reached the network")

    mock_provider(monkeypatch, forbidden)
    assert client.post("/config/ai/test").status_code == 409


def test_partial_pass_does_not_claim_naming_success(client, ai_config, monkeypatch):
    calls = []

    def provider(request):
        calls.append(request)
        content = (
            {"manufacturer": "Example", "device_type": "printer", "model": None, "confidence": 0.8}
            if len(calls) == 1
            else {"hostnames": ["../../etc"]}
        )
        return httpx.Response(
            200, json={"choices": [{"message": {"content": json.dumps(content)}}]}
        )

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/test").json()
    assert result["status"] == "error"
    assert result["checks"] == {"classification": True, "naming": False}


def test_cloud_provider_cannot_redirect_saved_key_to_custom_endpoint(
    client, ai_config, monkeypatch
):
    ai_config["classifier"]["llm_provider"] = "openrouter"

    def provider(request):
        assert str(request.url) == "https://openrouter.ai/api/v1/models"
        return httpx.Response(200, json={"data": []})

    mock_provider(monkeypatch, provider)
    assert client.post("/config/ai/models").json()["status"] == "ok"


@pytest.mark.asyncio
async def test_total_deadline_and_cancellation_release_busy_flag(monkeypatch):
    import asyncio
    from types import SimpleNamespace

    from squirrelops_home_sensor.api import ai_diagnostics as ai

    async def slow(request):
        await asyncio.sleep(10)
        return httpx.Response(200, json={"data": []})

    mock_provider(monkeypatch, slow)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    config = {"classifier": {"llm_provider": "custom", "llm_endpoint": "http://localhost:1234/v1"}}
    monkeypatch.setattr(ai, "PROBE_DEADLINE", 0.01)
    assert (await ai._run(request, config, True))["status"] == "error"
    assert request.app.state.ai_probe_busy is False
    monkeypatch.setattr(ai, "PROBE_DEADLINE", 10)
    task = asyncio.create_task(ai._run(request, config, True))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert request.app.state.ai_probe_busy is False


def test_fireworks_catalog_pages_are_bounded(client, ai_config, monkeypatch):
    ai_config["classifier"]["llm_provider"] = "fireworks"
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(200, json={"models": [], "nextPageToken": "always-more"})

    mock_provider(monkeypatch, provider)
    result = client.post("/config/ai/models").json()
    assert len(calls) == 5
    assert "limited" in result["message"]


@pytest.mark.asyncio
async def test_real_loopback_transport_discovers_and_generates_without_live_services():
    import asyncio
    from types import SimpleNamespace

    from squirrelops_home_sensor.api import ai_diagnostics as ai

    calls = []

    async def serve(reader, writer):
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode()
            headers = dict(line.split(": ", 1) for line in head.split("\r\n")[1:] if ": " in line)
            length = int(headers.get("Content-Length", "0"))
            body = json.loads(await reader.readexactly(length)) if length else None
            calls.append((head.split("\r\n")[0], body))
            if body is None:
                data = {"data": [{"id": "synthetic-loopback"}]}
            else:
                content = (
                    {
                        "manufacturer": "Example",
                        "device_type": "printer",
                        "model": "Synthetic",
                        "confidence": 0.9,
                    }
                    if len(calls) == 2
                    else {"hostnames": ["archive"]}
                )
                data = {"choices": [{"message": {"content": json.dumps(content)}}]}
            encoded = json.dumps(data).encode()
            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode()
                + encoded
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
        config = {
            "classifier": {
                "llm_provider": "custom",
                "llm_endpoint": f"http://127.0.0.1:{port}/v1",
                "llm_model": "synthetic-loopback",
            }
        }
        assert (await ai._run(request, config, True))["status"] == "ok"
        result = await ai._run(request, config, False)
        assert result["status"] == "ok"
        assert result["checks"] == {"classification": True, "naming": True}
        assert [call[0] for call in calls] == [
            "GET /v1/models HTTP/1.1",
            "POST /v1/chat/completions HTTP/1.1",
            "POST /v1/chat/completions HTTP/1.1",
        ]
