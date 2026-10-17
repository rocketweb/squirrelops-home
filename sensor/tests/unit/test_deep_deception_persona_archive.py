"""Memory-only persona archive tests for the isolated guest."""

import io
import json
import tarfile
from datetime import UTC, datetime

from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona
from squirrelops_home_sensor.decoys.deep.persona_archive import build_persona_archive


def _persona():
    return build_studio_mini_persona(
        b"p" * 32,
        datetime(2026, 8, 31, 15, 30, tzinfo=UTC),
    )


def test_archive_is_bounded_and_contains_only_relative_regular_files() -> None:
    archive = build_persona_archive(_persona())

    assert len(archive) < 512 * 1024
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        members = bundle.getmembers()

    assert members
    assert all(member.isfile() for member in members)
    assert all(not member.name.startswith("/") for member in members)
    assert all(".." not in member.name.split("/") for member in members)
    assert [member.name for member in members] == sorted(member.name for member in members)


def test_archive_carries_one_coherent_persona_and_real_project_shape() -> None:
    persona = _persona()
    archive = build_persona_archive(persona)

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        control = json.loads(
            bundle.extractfile("run/squirrelops/persona.json").read().decode("utf-8")
        )
        environment = bundle.extractfile(
            "Users/buildbot/Projects/fieldkit-ios/.env.local"
        ).read().decode("utf-8")
        project = bundle.extractfile(
            "Users/buildbot/Projects/fieldkit-ios/FieldKit.xcodeproj/project.pbxproj"
        ).read().decode("utf-8")

    assert control == {
        "hostname": "studio-mini",
        "login_password": persona.login_password,
        "persona_id": "studio-mini-v1",
        "username": "buildbot",
    }
    assert persona.openai_api_key in environment
    assert persona.source_token in environment
    assert "FieldKit-Staging" in project


def test_archive_bytes_are_stable_for_the_same_persona() -> None:
    persona = _persona()

    assert build_persona_archive(persona) == build_persona_archive(persona)
