"""Regression tests for release and installer supply-chain controls."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_standalone_python_is_verified_before_extraction() -> None:
    script = (REPO_ROOT / "scripts/build-sensor-venv.sh").read_text()
    tarball_assignment = script.index('TARBALL="$OUTPUT_DIR/${PBS_FILENAME}"')
    verification = script.index('info "Verifying standalone Python SHA-256..."')
    extraction = script.index('tar -xzf "$TARBALL"')

    assert tarball_assignment < verification < extraction
    hashes = re.findall(r'PBS_SHA256="([0-9a-f]{64})"', script)
    assert len(hashes) == 2


def test_github_actions_are_commit_pinned() -> None:
    workflows = REPO_ROOT / ".github/workflows"
    action_refs: list[str] = []
    for path in workflows.glob("*.yml"):
        action_refs.extend(
            re.findall(r"^\s*uses:\s*[^\s@]+@([^\s#]+)", path.read_text(), re.MULTILINE)
        )

    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
