"""Deception review: supported factory routes must keep their bytes for one seed.

Every attacker-visible value now comes from the compiled profile, so the
snapshot is taken under a fixed test seed. A diff is still a required review
of the full route output, not a failure to silence.
"""

import hashlib
import json

import pytest

from squirrelops_home_sensor.decoys.credentials import GeneratedCredential
from squirrelops_home_sensor.decoys.orchestrator import _create_decoy_instance
from squirrelops_home_sensor.decoys.profile import compile_profile

SNAPSHOT_SEED = b"classic-factory-presentation-snapshot-seed!!"
from squirrelops_home_sensor.decoys.types.dev_server import DevServerDecoy
from squirrelops_home_sensor.decoys.types.file_share import FileShareDecoy
from squirrelops_home_sensor.decoys.types.home_assistant import HomeAssistantDecoy


@pytest.mark.parametrize(("decoy_type", "expected"), [
    ("file_share", "f1b68f541f5cb767662f966d989a620e6f6eaabb2c9c9cc6ac1b9f725e29e2fc"),
    ("dev_server", "9e62cf5ed8d74ee9d0d8802a4644cd761ad2ba936fa1e22eaa2b541b85a9f9bb"),
    ("home_assistant", "85202b79c3bd849dce013ce85b9e71a24ba1799c9206a09237a2be7e595ce77d"),
])
def test_supported_factory_preserves_response_route_snapshot(decoy_type, expected):
    # Snapshots under SNAPSHOT_SEED; recomputed only after a deception review.
    # Include exact body bytes, routes, status codes, and configured headers,
    # including the deliberately weak/error presentation and custom bait name.
    credentials = [
        GeneratedCredential("password", "fixture:example-only", "qa-secrets.txt"),
        GeneratedCredential("ssh_key", "fixture-key-bytes\n", ".ssh/id_rsa"),
        GeneratedCredential("env_file", "DB_PASSWORD=example-only\n", ".env"),
        GeneratedCredential("ha_token", "fixture-token", "config"),
    ]
    profile = compile_profile(
        SNAPSHOT_SEED, decoy_type=decoy_type, decoy_id=1, password_filename="qa-secrets.txt"
    )
    decoy = _create_decoy_instance(
        decoy_type, 1, "QA", 0, "127.0.0.1", credentials,
        {"password_filename": "qa-secrets.txt"},
        profile=profile,
    )
    assert isinstance(decoy, (FileShareDecoy, DevServerDecoy, HomeAssistantDecoy))
    routes = json.dumps(decoy._build_routes(), sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(routes).hexdigest() == expected, (
        "Decoy-visible output changed; review the full route diff before updating the snapshot"
    )
