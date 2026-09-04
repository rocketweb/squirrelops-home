"""Byte-visible acceptance tests for the 2.1 agent-native bait."""

from datetime import UTC, datetime

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
