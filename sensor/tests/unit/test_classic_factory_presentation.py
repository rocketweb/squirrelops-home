"""Deception review: supported factory routes must keep their existing bytes."""

import hashlib
import json

import pytest

from squirrelops_home_sensor.decoys.credentials import GeneratedCredential
from squirrelops_home_sensor.decoys.orchestrator import _create_decoy_instance
from squirrelops_home_sensor.decoys.types.dev_server import DevServerDecoy
from squirrelops_home_sensor.decoys.types.file_share import FileShareDecoy
from squirrelops_home_sensor.decoys.types.home_assistant import HomeAssistantDecoy


@pytest.mark.parametrize(("decoy_type", "expected"), [
    ("file_share", "109c7813d6ae49a3811dd75a584ee4cf6ca007fdda7952f6995b91be09033caa"),
    ("dev_server", "5328fb034874e3e9a1b5c3b6d1ba17008605f185497bb011f7314494b80f34ed"),
    ("home_assistant", "85e5abaa8d90df7c1a7d29ee7985c7c52016b744e8bb66494de3d2b2ad53619e"),
])
def test_supported_factory_preserves_response_route_snapshot(decoy_type, expected):
    # Snapshots captured from the pre-fix 2026-09-29 package (SHA 541fc783...).
    # Include exact body bytes, routes, status codes, and configured headers,
    # including the deliberately weak/error presentation and custom bait name.
    credentials = [
        GeneratedCredential("password", "fixture:example-only", "qa-secrets.txt"),
        GeneratedCredential("ssh_key", "fixture-key-bytes\n", ".ssh/id_rsa"),
        GeneratedCredential("env_file", "DB_PASSWORD=example-only\n", ".env"),
        GeneratedCredential("ha_token", "fixture-token", "config"),
    ]
    decoy = _create_decoy_instance(
        decoy_type, 1, "QA", 0, "127.0.0.1", credentials,
        {"password_filename": "qa-secrets.txt"},
    )
    assert isinstance(decoy, (FileShareDecoy, DevServerDecoy, HomeAssistantDecoy))
    routes = json.dumps(decoy._build_routes(), sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(routes).hexdigest() == expected, (
        "Decoy-visible output changed; review the full route diff before updating the snapshot"
    )
