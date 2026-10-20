"""Two properties that keep the classic decoys unpredictable from the source.

1. Shared-constant detector: across many seeds, no attacker-visible observable
   a classic decoy presents is constant, except the ones the imitated software
   itself holds constant (allow-listed by name).
2. Wire-literal lint: the decoy type modules carry no version-shaped or
   server-identifying string literals; every such value must come from the
   compiled profile.

Neither test enumerates a tell. They assert the shape of the property.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from pathlib import Path

import pytest

from squirrelops_home_sensor.decoys import types as decoy_types
from squirrelops_home_sensor.decoys.credentials import GeneratedCredential
from squirrelops_home_sensor.decoys.orchestrator import _create_decoy_instance
from squirrelops_home_sensor.decoys.profile import compile_profile

SEEDS = [hashlib.sha256(f"entropy-seed-{index}".encode()).digest() for index in range(16)]

# Observables the imitated software holds constant. Everything else must vary.
CONSTANT_OBSERVABLES = {
    "header:Content-Type",
    "header:X-Powered-By",
    "status",
}

# Whole responses that are fixed strings in the imitated product itself (its
# own error messages). Whether they match the real product is the realism
# differential's job, not this test's.
PRODUCT_CONSTANT_RESPONSES = {
    "home_assistant": {"GET /api/ body", "POST /auth/token body"},
}

_CREDENTIALS = [
    GeneratedCredential("password", "fixture:example-only", "passwords.txt"),
    GeneratedCredential("ssh_key", "fixture-key-bytes\n", ".ssh/id_rsa"),
    GeneratedCredential("env_file", "DB_PASSWORD=example-only\n", ".env"),
    GeneratedCredential("ha_token", "fixture-token", "config"),
]


def _observables(decoy_type: str, seed: bytes) -> dict[str, str]:
    profile = compile_profile(seed, decoy_type=decoy_type, decoy_id=7)
    decoy = _create_decoy_instance(
        decoy_type, 7, "QA", 0, "127.0.0.1", _CREDENTIALS, {}, profile=profile
    )
    seen: dict[str, str] = {}
    for route in decoy._build_routes():
        prefix = f"{route['method']} {route['path']}"
        seen[f"{prefix} status"] = str(route["status"])
        for name, value in route.get("headers", {}).items():
            seen[f"{prefix} header:{name}"] = value
        body = route.get("body", "")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        seen[f"{prefix} body"] = hashlib.sha256(body_bytes).hexdigest()
    return seen


@pytest.mark.parametrize("decoy_type", ["file_share", "dev_server", "home_assistant"])
def test_no_attacker_visible_observable_is_constant_across_seeds(decoy_type: str) -> None:
    values: dict[str, set[str]] = defaultdict(set)
    for seed in SEEDS:
        for key, value in _observables(decoy_type, seed).items():
            values[key].add(value)

    constant = sorted(
        key
        for key, seen in values.items()
        if len(seen) == 1 and key.split(" ", 2)[-1] not in CONSTANT_OBSERVABLES
    )
    # Bait routes whose body is the planted credential itself are the
    # credentials' entropy, not the profile's; they are fixed here on purpose.
    constant = [
        key
        for key in constant
        if not _is_bait_body(decoy_type, key)
        and key not in PRODUCT_CONSTANT_RESPONSES.get(decoy_type, set())
    ]
    assert constant == [], (
        f"{decoy_type}: these observables are identical across {len(SEEDS)} seeds, "
        f"so they are literals an attacker can learn from the source: {constant}"
    )


def _is_bait_body(decoy_type: str, key: str) -> bool:
    bait_paths = {
        "file_share": {"GET /passwords.txt body", "GET /.ssh/id_rsa body"},
        "dev_server": {"GET /.env body"},
        "home_assistant": set(),
    }
    return key in bait_paths[decoy_type]


def test_two_decoys_on_one_install_do_not_share_their_listing() -> None:
    a = _observables("file_share", SEEDS[0])
    profile_b = compile_profile(SEEDS[0], decoy_type="file_share", decoy_id=8)
    decoy_b = _create_decoy_instance(
        "file_share", 8, "QA", 0, "127.0.0.1", _CREDENTIALS, {}, profile=profile_b
    )
    body_b = next(r["body"] for r in decoy_b._build_routes() if r["path"] == "/")
    assert a["GET / body"] != hashlib.sha256(body_b.encode()).hexdigest()


_VERSION_SHAPED = re.compile(r"(?<![\d.])\d+\.\d+\.\d+(?![\d.])")  # not an IPv4 address
_SERVER_SHAPED = re.compile(r"(?i)\b(nginx|apache|express|home assistant)\s*/?\s*\d")
_DATE_SHAPED = re.compile(r"\b\d{2}-[A-Z][a-z]{2}-\d{4}\b")


def _string_literals(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append((node.lineno, node.value))
    return found


@pytest.mark.parametrize("module", ["file_share.py", "dev_server.py", "home_assistant.py"])
def test_decoy_modules_carry_no_wire_identity_literals(module: str) -> None:
    path = Path(decoy_types.__file__).parent / module
    offenders = [
        (line, text[:60])
        for line, text in _string_literals(path)
        if _VERSION_SHAPED.search(text) or _SERVER_SHAPED.search(text) or _DATE_SHAPED.search(text)
    ]
    assert offenders == [], (
        f"{module}: version, server, or date-shaped literals must come from the "
        f"compiled profile, not the source: {offenders}"
    )
