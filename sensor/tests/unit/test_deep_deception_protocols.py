"""Byte-visible acceptance tests for the 2.1 agent-native bait."""

import json
from datetime import UTC, datetime

import pytest

from squirrelops_home_sensor.decoys.deep.agent_protocols import (
    AgentRequest,
    build_agent_response,
)
from squirrelops_home_sensor.decoys.deep.narrative import (
    InteractionEvidence,
    advance_campaign,
    new_campaign,
)
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona

NONSTREAMING_SHA256 = {
    "/v1/chat/completions": "8271e3b17298cd5fc7d307290538d0a62195aad5367ea19aceb6dbdf84b091a9",
    "/api/chat": "d25d749ec2c7681be9b393fe4948767a5a9ad6cc8c29906f301e05044154309c",
}


def _persona():
    return build_studio_mini_persona(
        b"unit-test-deployment-secret-with-32-bytes",
        datetime(2026, 8, 31, 14, 0, tzinfo=UTC),
    )


def test_openai_models_response_is_byte_exact() -> None:
    response = build_agent_response(
        _persona(),
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(method="GET", path="/v1/models"),
    )

    assert response.status == 200
    assert response.content_type == "application/json"
    assert response.body == (
        b'{"object":"list","data":['
        b'{"id":"fieldkit-coder:14b","object":"model","created":1788184800,'
        b'"owned_by":"hawthorn-ml"},'
        b'{"id":"release-notes:latest","object":"model","created":1788184800,'
        b'"owned_by":"hawthorn-ml"}]}'
    )


def test_ollama_tags_response_has_realistic_shape_and_shared_models() -> None:
    response = build_agent_response(
        _persona(),
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(method="GET", path="/api/tags"),
    )

    assert response.status == 200
    assert response.json_body["models"][0]["name"] == "fieldkit-coder:14b"
    assert response.json_body["models"][0]["details"] == {
        "format": "gguf",
        "family": "qwen3",
        "families": ["qwen3"],
        "parameter_size": "14.8B",
        "quantization_level": "Q4_K_M",
    }


def test_mcp_initialize_negotiates_current_supported_revision() -> None:
    response = build_agent_response(
        _persona(),
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(
            method="POST",
            path="/mcp",
            json_body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        ),
    )

    assert response.json_body == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "studio-build-tools", "version": "0.9.7"},
            "instructions": (
                "Use list_projects before reading the release runbook. "
                "The signing rotation is still in progress."
            ),
        },
    }


def test_mcp_lists_the_four_agent_bait_tools() -> None:
    response = build_agent_response(
        _persona(),
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(
            method="POST",
            path="/mcp",
            json_body={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ),
    )

    tools = response.json_body["result"]["tools"]
    assert [tool["name"] for tool in tools] == [
        "list_projects",
        "read_runbook",
        "get_deployment",
        "search_secrets",
    ]
    assert all(tool["inputSchema"]["type"] == "object" for tool in tools)


def test_agent_runbook_points_deeper_into_only_the_synthetic_world() -> None:
    persona = _persona()
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.44")
    campaign = advance_campaign(
        campaign,
        InteractionEvidence(
            method="POST",
            path="/mcp",
            user_agent="codex-cli/1.2",
            body="tools/call read_runbook",
        ),
    )
    response = build_agent_response(
        persona,
        campaign,
        AgentRequest(
            method="POST",
            path="/mcp",
            json_body={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_runbook", "arguments": {}},
            },
        ),
    )

    text = response.json_body["result"]["content"][0]["text"]
    assert persona.primary_project.path in text
    assert persona.deployment_name in text
    assert persona.git_hostname in text
    assert "http://" not in text
    assert "https://" not in text


def test_secret_search_returns_only_planted_credentials() -> None:
    persona = _persona()
    response = build_agent_response(
        persona,
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(
            method="POST",
            path="/mcp",
            json_body={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "search_secrets",
                    "arguments": {"query": "OPENAI_API_KEY"},
                },
            },
        ),
    )

    text = response.json_body["result"]["content"][0]["text"]
    assert persona.openai_api_key in text
    assert response.credential_exposed == persona.openai_api_key


def test_unknown_mcp_tool_uses_protocol_error_result() -> None:
    response = build_agent_response(
        _persona(),
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(
            method="POST",
            path="/mcp",
            json_body={
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "shell", "arguments": {}},
            },
        ),
    )

    assert response.status == 200
    assert response.json_body["result"]["isError"] is True
    assert "Unknown tool" in response.json_body["result"]["content"][0]["text"]


def test_unknown_route_keeps_a_plain_ollama_style_404() -> None:
    response = build_agent_response(
        _persona(),
        new_campaign(decoy_id=41, source_ip="192.0.2.44"),
        AgentRequest(method="GET", path="/admin"),
    )

    assert response.status == 404
    assert response.body == b'{"error":"not found"}'


@pytest.mark.parametrize("include_usage", [False, True])
def test_openai_stream_uses_sse_chunks_and_preserves_content(include_usage) -> None:
    persona = _persona()
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.44")
    payload = {"model": persona.model_names[0], "stream": True,
               "stream_options": {"include_usage": include_usage}}
    response = build_agent_response(persona, campaign, AgentRequest(
        method="POST", path="/v1/chat/completions", json_body=payload))
    ordinary = build_agent_response(persona, campaign, AgentRequest(
        method="POST", path="/v1/chat/completions", json_body={"stream": False}))
    assert response.content_type == "text/event-stream"
    assert response.body.endswith(b"data: [DONE]\n\n")
    assert response.body == b"".join(response.chunks)
    records = [json.loads(line[6:]) for line in response.body.splitlines()
               if line.startswith(b"data: {")]
    assert records[0]["choices"][0]["delta"] == {"role": "assistant", "content": ""}
    assert all(row["object"] == "chat.completion.chunk" for row in records)
    assert len({row["id"] for row in records}) == 1
    choices = [row["choices"][0] for row in records if row["choices"]]
    assert "".join(row["delta"].get("content", "") for row in choices) == ordinary.json_body["choices"][0]["message"]["content"]
    assert choices[-1] == {"index": 0, "delta": {}, "finish_reason": "stop"}
    if include_usage:
        assert records[-1]["choices"] == []
        assert records[-1]["usage"] == ordinary.json_body["usage"]
    else:
        assert all("usage" not in row for row in records)


@pytest.mark.parametrize("payload", [{}, {"stream": True}])
def test_ollama_stream_defaults_to_ndjson_and_preserves_content(payload) -> None:
    persona = _persona()
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.44")
    response = build_agent_response(persona, campaign, AgentRequest(
        method="POST", path="/api/chat", json_body=payload))
    ordinary = build_agent_response(persona, campaign, AgentRequest(
        method="POST", path="/api/chat", json_body={"stream": False}))
    assert response.content_type == "application/x-ndjson"
    assert response.body == b"".join(response.chunks)
    records = [json.loads(line) for line in response.body.splitlines()]
    assert len(records) > 2
    assert all(row["done"] is False for row in records[:-1])
    assert records[-1]["done"] is True
    assert records[-1]["message"]["content"] == ""
    assert "".join(row["message"]["content"] for row in records) == ordinary.json_body["message"]["content"]
    assert records[-1]["eval_count"] == ordinary.json_body["eval_count"]


def test_explicit_nonstreaming_response_snapshots() -> None:
    persona = _persona()
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.44")
    for path in ("/v1/chat/completions", "/api/chat"):
        response = build_agent_response(persona, campaign, AgentRequest(
            method="POST", path=path, json_body={"stream": False}))
        assert response.content_type == "application/json"
        assert b'"finish_reason":"stop"' in response.body or b'"done":true' in response.body
        # The complete bytes are pinned by the separately retained baseline hashes.
        import hashlib
        expected = NONSTREAMING_SHA256[path]
        assert hashlib.sha256(response.body).hexdigest() == expected
