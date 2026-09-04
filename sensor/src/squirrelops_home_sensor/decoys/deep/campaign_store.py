"""SQLite persistence for one coherent narrative per decoy and source."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from squirrelops_home_sensor.decoys.deep.narrative import (
    CampaignState,
    InteractionEvidence,
    IntruderIntent,
    NarrativeStage,
    advance_campaign,
    new_campaign,
)


class NarrativeStore:
    """Serialize and persist campaign changes on the sensor event loop."""

    def __init__(self, db: Any) -> None:
        self._db = db
        self._lock = asyncio.Lock()

    @staticmethod
    def _decode_scores(raw: object) -> dict[IntruderIntent, int]:
        if not isinstance(raw, str) or len(raw) > 8192:
            return {}
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(decoded, dict):
            return {}
        scores: dict[IntruderIntent, int] = {}
        for raw_intent, raw_score in decoded.items():
            try:
                intent = IntruderIntent(raw_intent)
            except ValueError:
                continue
            if (
                isinstance(raw_score, int)
                and not isinstance(raw_score, bool)
                and 0 <= raw_score <= 1_000_000
            ):
                scores[intent] = raw_score
        return scores

    @classmethod
    def _state_from_row(cls, row: Any) -> CampaignState:
        return CampaignState(
            decoy_id=int(row["decoy_id"]),
            source_ip=str(row["source_ip"]),
            intent=IntruderIntent(str(row["intent"])),
            stage=NarrativeStage(int(row["stage"])),
            scores=cls._decode_scores(row["scores_json"]),
            observation_count=int(row["observation_count"]),
        )

    async def _row(self, decoy_id: int, source_ip: str) -> Any | None:
        cursor = await self._db.execute(
            """SELECT decoy_id, source_ip, persona_id, intent, stage,
                      scores_json, observation_count
               FROM deception_campaigns
               WHERE decoy_id = ? AND source_ip = ?""",
            (decoy_id, source_ip),
        )
        return await cursor.fetchone()

    async def get(self, decoy_id: int, source_ip: str) -> CampaignState | None:
        """Return the current campaign, or ``None`` before first contact."""
        new_campaign(decoy_id, source_ip)
        row = await self._row(decoy_id, source_ip)
        return None if row is None else self._state_from_row(row)

    async def observe(
        self,
        *,
        decoy_id: int,
        source_ip: str,
        persona_id: str,
        evidence: InteractionEvidence,
    ) -> CampaignState:
        """Advance and atomically upsert a source's campaign state."""
        if persona_id != "studio-mini-v1":
            raise ValueError("Campaign persona must be the reviewed studio-mini identity")
        async with self._lock:
            row = await self._row(decoy_id, source_ip)
            if row is None:
                current = new_campaign(decoy_id, source_ip)
                first_seen_at = datetime.now(UTC).isoformat()
            else:
                if row["persona_id"] != persona_id:
                    raise ValueError("Campaign persona cannot change after first contact")
                current = self._state_from_row(row)
                timestamp_cursor = await self._db.execute(
                    """SELECT first_seen_at FROM deception_campaigns
                       WHERE decoy_id = ? AND source_ip = ?""",
                    (decoy_id, source_ip),
                )
                first_seen_at = (await timestamp_cursor.fetchone())[0]

            advanced = advance_campaign(current, evidence)
            now = datetime.now(UTC).isoformat()
            serialized_scores = json.dumps(
                {
                    intent.value: score
                    for intent, score in sorted(
                        advanced.scores.items(),
                        key=lambda item: item[0].value,
                    )
                },
                separators=(",", ":"),
            )
            await self._db.execute(
                """INSERT INTO deception_campaigns
                       (decoy_id, source_ip, persona_id, intent, stage,
                        scores_json, observation_count, first_seen_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(decoy_id, source_ip) DO UPDATE SET
                       intent = excluded.intent,
                       stage = excluded.stage,
                       scores_json = excluded.scores_json,
                       observation_count = excluded.observation_count,
                       last_seen_at = excluded.last_seen_at""",
                (
                    decoy_id,
                    source_ip,
                    persona_id,
                    advanced.intent.value,
                    int(advanced.stage),
                    serialized_scores,
                    advanced.observation_count,
                    first_seen_at,
                    now,
                ),
            )
            await self._db.commit()
            return advanced
