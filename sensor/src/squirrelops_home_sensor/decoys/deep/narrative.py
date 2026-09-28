"""Evidence-based, persistent-friendly campaign state for deep decoys."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum


class IntruderIntent(StrEnum):
    UNKNOWN = "unknown"
    SCANNER = "scanner"
    CREDENTIAL_HUNTER = "credential_hunter"
    RANSOMWARE = "ransomware"
    DEVELOPER_AGENT = "developer_agent"
    HUMAN_OPERATOR = "human_operator"


class NarrativeStage(IntEnum):
    DISCOVERY = 0
    BROWSING = 1
    CREDENTIAL_ACCESS = 2
    AGENT_TOOL_USE = 3
    WRITE_ACTIVITY = 4


@dataclass(frozen=True)
class InteractionEvidence:
    method: str
    path: str
    user_agent: str = ""
    body: str = ""
    protocol: str = "http"
    operation: str = ""


@dataclass(frozen=True)
class CampaignState:
    decoy_id: int
    source_ip: str
    intent: IntruderIntent = IntruderIntent.UNKNOWN
    stage: NarrativeStage = NarrativeStage.DISCOVERY
    scores: dict[IntruderIntent, int] = field(default_factory=dict)
    observation_count: int = 0


_INTENT_PRIORITY = (
    IntruderIntent.RANSOMWARE,
    IntruderIntent.DEVELOPER_AGENT,
    IntruderIntent.CREDENTIAL_HUNTER,
    IntruderIntent.HUMAN_OPERATOR,
    IntruderIntent.SCANNER,
)
_CREDENTIAL_TERMS = (
    ".env",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
)
_AGENT_TERMS = (
    "claude",
    "codex",
    "cursor",
    "mcp",
    "tools/call",
    "tools/list",
    "/v1/chat/completions",
    "/api/chat",
)
_WRITE_TERMS = ("write", "rename", "delete", "encrypt", "truncate", "overwrite")


def new_campaign(decoy_id: int, source_ip: str) -> CampaignState:
    if decoy_id <= 0:
        raise ValueError("Decoy ID must be positive")
    if not source_ip or len(source_ip) > 64:
        raise ValueError("Source address is invalid")
    return CampaignState(decoy_id=decoy_id, source_ip=source_ip)


def _contains_any(value: str, terms: tuple[str, ...]) -> bool:
    folded = value.casefold()
    return any(term in folded for term in terms)


def advance_campaign(
    campaign: CampaignState,
    evidence: InteractionEvidence,
) -> CampaignState:
    """Return campaign state advanced by bounded, explainable evidence."""
    method = evidence.method[:32].casefold()
    path = evidence.path[:2048]
    user_agent = evidence.user_agent[:1024]
    body = evidence.body[:8192]
    protocol = evidence.protocol[:32].casefold()
    operation = evidence.operation[:128]
    combined = "\n".join((path, user_agent, body, operation))

    scores = dict(campaign.scores)

    def add(intent: IntruderIntent, amount: int) -> None:
        scores[intent] = scores.get(intent, 0) + amount

    stage = campaign.stage

    if method in {"get", "head", "connect"}:
        add(IntruderIntent.SCANNER, 1)
    if any(term in user_agent.casefold() for term in ("nmap", "masscan", "zgrab")):
        add(IntruderIntent.SCANNER, 5)
    elif "curl/" in user_agent.casefold() and path in {"/", "/health", "/v1/models"}:
        add(IntruderIntent.SCANNER, 2)

    credential_evidence = _contains_any(combined, _CREDENTIAL_TERMS)
    agent_evidence = _contains_any(combined, _AGENT_TERMS)
    write_evidence = (
        method in {"put", "patch", "delete", "write"}
        or _contains_any(operation, _WRITE_TERMS)
    )

    if credential_evidence:
        add(IntruderIntent.CREDENTIAL_HUNTER, 6)
        stage = max(stage, NarrativeStage.CREDENTIAL_ACCESS)
    elif path not in {"/", "/health", "/api/version", "/v1/models"}:
        stage = max(stage, NarrativeStage.BROWSING)

    if agent_evidence:
        add(IntruderIntent.DEVELOPER_AGENT, 8)
        stage = max(stage, NarrativeStage.AGENT_TOOL_USE)

    if write_evidence:
        add(IntruderIntent.RANSOMWARE, 12 if protocol == "smb" else 8)
        stage = NarrativeStage.WRITE_ACTIVITY

    if any(term in user_agent.casefold() for term in ("mozilla/", "safari/", "finder")):
        add(IntruderIntent.HUMAN_OPERATOR, 4)
        stage = max(stage, NarrativeStage.BROWSING)

    intent = campaign.intent
    best_score = scores.get(intent, 0)
    if intent is IntruderIntent.UNKNOWN and scores:
        intent = max(
            _INTENT_PRIORITY,
            key=lambda candidate: scores.get(candidate, 0),
        )
    else:
        # Require meaningful contradictory evidence before changing an
        # established interpretation. Repeated generic probes must not turn a
        # credential campaign back into a scanner narrative.
        switch_margin = 1 if intent is IntruderIntent.SCANNER else 3
        for candidate in _INTENT_PRIORITY:
            candidate_score = scores.get(candidate, 0)
            if candidate_score >= best_score + switch_margin:
                intent = candidate
                best_score = candidate_score

    return replace(
        campaign,
        intent=intent,
        stage=NarrativeStage(stage),
        scores=scores,
        observation_count=campaign.observation_count + 1,
    )
