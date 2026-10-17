"""Persistence acceptance for source-specific 2.1 narratives."""

import aiosqlite
import pytest

from squirrelops_home_sensor.db.migrations import apply_migrations
from squirrelops_home_sensor.db.schema import SCHEMA_VERSION
from squirrelops_home_sensor.decoys.deep.campaign_store import NarrativeStore
from squirrelops_home_sensor.decoys.deep.narrative import (
    InteractionEvidence,
    IntruderIntent,
    NarrativeStage,
)


async def _insert_decoy(db: aiosqlite.Connection, decoy_id: int = 41) -> None:
    await db.execute(
        """INSERT INTO decoys
           (id, name, decoy_type, bind_address, port, status, created_at, updated_at)
           VALUES (?, 'studio-mini.local', 'deep_guest', '192.0.2.200', 22,
                   'active', '2026-08-31T14:00:00Z', '2026-08-31T14:00:00Z')""",
        (decoy_id,),
    )
    await db.commit()


@pytest.mark.asyncio
async def test_schema_v12_adds_campaign_table() -> None:
    async with aiosqlite.connect(":memory:") as db:
        await apply_migrations(db)
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'deception_campaigns'"
        )
        assert await cursor.fetchone() is not None
        cursor = await db.execute("SELECT MAX(version) FROM schema_version")
        assert (await cursor.fetchone())[0] == SCHEMA_VERSION == 12

        cursor = await db.execute("PRAGMA table_info(decoy_connections)")
        columns = {row[1] for row in await cursor.fetchall()}
        assert {
            "intruder_intent",
            "narrative_stage",
            "interaction_type",
        }.issubset(columns)


@pytest.mark.asyncio
async def test_campaign_survives_database_reopen(tmp_path) -> None:
    database_path = tmp_path / "campaigns.db"
    async with aiosqlite.connect(database_path) as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        await _insert_decoy(db)
        store = NarrativeStore(db)
        state = await store.observe(
            decoy_id=41,
            source_ip="192.0.2.44",
            persona_id="studio-mini-v1",
            evidence=InteractionEvidence(
                method="GET",
                path="/.env",
                user_agent="curl/8.7",
            ),
        )
        assert state.intent is IntruderIntent.CREDENTIAL_HUNTER

    async with aiosqlite.connect(database_path) as db:
        db.row_factory = aiosqlite.Row
        store = NarrativeStore(db)
        restored = await store.get(41, "192.0.2.44")

    assert restored is not None
    assert restored.intent is IntruderIntent.CREDENTIAL_HUNTER
    assert restored.stage is NarrativeStage.CREDENTIAL_ACCESS
    assert restored.observation_count == 1


@pytest.mark.asyncio
async def test_campaign_advances_in_place_without_duplicate_rows(tmp_path) -> None:
    async with aiosqlite.connect(tmp_path / "campaigns.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        await _insert_decoy(db)
        store = NarrativeStore(db)
        await store.observe(
            decoy_id=41,
            source_ip="192.0.2.44",
            persona_id="studio-mini-v1",
            evidence=InteractionEvidence(method="GET", path="/v1/models"),
        )
        state = await store.observe(
            decoy_id=41,
            source_ip="192.0.2.44",
            persona_id="studio-mini-v1",
            evidence=InteractionEvidence(
                method="WRITE",
                path="/Builds/latest.zip",
                protocol="smb",
                operation="rename_many",
            ),
        )
        cursor = await db.execute("SELECT COUNT(*) FROM deception_campaigns")
        assert (await cursor.fetchone())[0] == 1

    assert state.intent is IntruderIntent.RANSOMWARE
    assert state.stage is NarrativeStage.WRITE_ACTIVITY
    assert state.observation_count == 2


@pytest.mark.asyncio
async def test_campaign_persona_cannot_change_midstream(tmp_path) -> None:
    async with aiosqlite.connect(tmp_path / "campaigns.db") as db:
        db.row_factory = aiosqlite.Row
        await apply_migrations(db)
        await _insert_decoy(db)
        store = NarrativeStore(db)
        await store.observe(
            decoy_id=41,
            source_ip="192.0.2.44",
            persona_id="studio-mini-v1",
            evidence=InteractionEvidence(method="GET", path="/v1/models"),
        )

        with pytest.raises(ValueError, match="persona"):
            await store.observe(
                decoy_id=41,
                source_ip="192.0.2.44",
                persona_id="different-persona",
                evidence=InteractionEvidence(method="GET", path="/v1/models"),
            )
