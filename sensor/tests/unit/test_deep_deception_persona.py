"""Acceptance tests for the coherent 2.1 synthetic Mac world."""

from datetime import UTC, datetime

from squirrelops_home_sensor.decoys.deep.narrative import (
    InteractionEvidence,
    IntruderIntent,
    NarrativeStage,
    advance_campaign,
    new_campaign,
)
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona

_CREATED_AT = datetime(2026, 8, 31, 14, 0, tzinfo=UTC)
_DEPLOYMENT_SECRET = b"unit-test-deployment-secret-with-32-bytes"


def test_persona_is_stable_for_one_installation() -> None:
    first = build_studio_mini_persona(_DEPLOYMENT_SECRET, _CREATED_AT)
    second = build_studio_mini_persona(_DEPLOYMENT_SECRET, _CREATED_AT)

    assert first == second
    assert first.hostname == "studio-mini.local"
    assert first.username == "buildbot"
    assert first.primary_project.slug == "fieldkit-ios"
    assert first.smb_shares == ("Builds", "Engineering", "Time Machine Backups")


def test_installations_share_a_story_but_not_planted_credentials() -> None:
    first = build_studio_mini_persona(_DEPLOYMENT_SECRET, _CREATED_AT)
    second = build_studio_mini_persona(
        b"another-unit-test-deployment-secret-32b",
        _CREATED_AT,
    )

    assert first.hostname == second.hostname
    assert first.primary_project == second.primary_project
    assert first.login_password != second.login_password
    assert first.openai_api_key != second.openai_api_key


def test_guest_seed_and_agent_files_describe_the_same_world() -> None:
    persona = build_studio_mini_persona(_DEPLOYMENT_SECRET, _CREATED_AT)
    files = persona.guest_files()

    assert files["/etc/hostname"] == "studio-mini\n"
    assert persona.primary_project.path in files["/Users/buildbot/.zsh_history"]
    assert persona.primary_project.repository in files[
        "/Users/buildbot/Projects/fieldkit-ios/.git/config"
    ]
    assert persona.openai_api_key in files[
        "/Users/buildbot/Projects/fieldkit-ios/.env.local"
    ]
    assert "search_secrets" in files["/Users/buildbot/.cursor/mcp.json"]
    assert "Time Machine Backups" in files[
        "/Users/buildbot/Documents/Build Recovery.md"
    ]


def test_campaign_intent_and_stage_are_sticky_and_monotonic() -> None:
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.44")

    campaign = advance_campaign(
        campaign,
        InteractionEvidence(method="GET", path="/v1/models", user_agent="curl/8.7"),
    )
    assert campaign.intent is IntruderIntent.SCANNER
    assert campaign.stage is NarrativeStage.DISCOVERY

    campaign = advance_campaign(
        campaign,
        InteractionEvidence(method="GET", path="/.env", user_agent="curl/8.7"),
    )
    assert campaign.intent is IntruderIntent.CREDENTIAL_HUNTER
    assert campaign.stage is NarrativeStage.CREDENTIAL_ACCESS

    campaign = advance_campaign(
        campaign,
        InteractionEvidence(method="GET", path="/v1/models", user_agent="curl/8.7"),
    )
    assert campaign.intent is IntruderIntent.CREDENTIAL_HUNTER
    assert campaign.stage is NarrativeStage.CREDENTIAL_ACCESS


def test_mcp_client_advances_to_agent_tool_use() -> None:
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.45")
    campaign = advance_campaign(
        campaign,
        InteractionEvidence(
            method="POST",
            path="/mcp",
            user_agent="claude-code/1.0",
            body='{"jsonrpc":"2.0","id":2,"method":"tools/call",'
            '"params":{"name":"read_runbook","arguments":{}}}',
        ),
    )

    assert campaign.intent is IntruderIntent.DEVELOPER_AGENT
    assert campaign.stage is NarrativeStage.AGENT_TOOL_USE


def test_write_activity_is_highest_stage() -> None:
    campaign = new_campaign(decoy_id=41, source_ip="192.0.2.46")
    campaign = advance_campaign(
        campaign,
        InteractionEvidence(
            method="WRITE",
            path="/Builds/fieldkit-ios/latest.zip",
            protocol="smb",
            operation="rename_many",
        ),
    )

    assert campaign.intent is IntruderIntent.RANSOMWARE
    assert campaign.stage is NarrativeStage.WRITE_ACTIVITY
