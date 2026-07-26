#!/usr/bin/env python3
"""Fail closed until the Linux release privilege boundary is reviewed."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REVIEWED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
DIRECT_SENSOR_PRIVILEGES = (
    re.compile(r"^\s+network_mode:\s*[\"']?host[\"']?\s*$"),
    re.compile(r"^\s+(?:pid|ipc|uts):\s*[\"']?host[\"']?\s*$"),
    re.compile(r"^\s+privileged:\s*(?:true|[\"']true[\"'])\s*$"),
    re.compile(r"^\s+-\s*(?:NET_RAW|NET_ADMIN)\s*$"),
    re.compile(r"^\s+-\s*/var/run/docker\.sock(?::|$)"),
)
LINUX_RELEASE_MARKERS = (
    "build-linux-container:",
    "container-oci",
    "install.sh",
    ".oci.tar",
    "ghcr.io/rocketweb/squirrelops-sensor",
    "oras cp",
)


class BoundaryError(ValueError):
    """The checked-in release boundary is absent, ambiguous, or unsafe."""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BoundaryError(f"required release file is unavailable: {path}") from exc


def _service_block(text: str, source: Path, service: str) -> list[str]:
    """Extract one Compose service block, including installer heredocs."""

    lines = text.splitlines()
    services_index = next(
        (index for index, line in enumerate(lines) if line == "services:"),
        None,
    )
    if services_index is None:
        raise BoundaryError(f"Compose services block is missing from {source}")

    service_index = next(
        (
            index
            for index in range(services_index + 1, len(lines))
            if lines[index] == f"  {service}:"
        ),
        None,
    )
    if service_index is None:
        raise BoundaryError(f"Compose {service} service is missing from {source}")

    block: list[str] = []
    for line in lines[service_index + 1 :]:
        if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", line) or (
            line and not line[0].isspace()
        ):
            break
        block.append(line)
    return block


def _require_unprivileged_sensor(repo_root: Path) -> None:
    sources = (
        repo_root / "scripts" / "install.sh",
        repo_root / "sensor" / "docker-compose.yml",
    )
    for source in sources:
        text = _read_text(source)
        sensor_block = _service_block(text, source, "sensor")
        helper_block = _service_block(text, source, "network-helper")
        for line in sensor_block:
            if any(pattern.search(line) for pattern in DIRECT_SENSOR_PRIVILEGES):
                raise BoundaryError(
                    "Linux sensor still receives host-level network authority "
                    f"directly in {source}: {line.strip()}"
                )
        sensor_text = "\n".join(sensor_block)
        helper_text = "\n".join(helper_block)
        required_sensor_controls = {
            "fixed non-root identity": re.compile(
                r'^\s+user:\s*["\']?10001:10001["\']?\s*$',
                re.MULTILINE,
            ),
            "drop-all capabilities": re.compile(
                r"^\s+cap_drop:\s*$[\s\S]*?^\s+-\s+ALL\s*$",
                re.MULTILINE,
            ),
            "read-only root filesystem": re.compile(
                r"^\s+read_only:\s*true\s*$",
                re.MULTILINE,
            ),
            "no-new-privileges": re.compile(
                r"^\s+-\s+no-new-privileges:true\s*$",
                re.MULTILINE,
            ),
            "read-only helper socket": re.compile(
                r"^\s+-\s+helper_socket:/run/squirrelops:ro\s*$",
                re.MULTILINE,
            ),
        }
        for label, pattern in required_sensor_controls.items():
            if pattern.search(sensor_text) is None:
                raise BoundaryError(
                    f"Linux sensor is missing {label} in {source}"
                )

        required_helper_controls = {
            "host network namespace": re.compile(
                r"^\s+network_mode:\s*host\s*$",
                re.MULTILINE,
            ),
            "drop-all baseline": re.compile(
                r"^\s+cap_drop:\s*$[\s\S]*?^\s+-\s+ALL\s*$",
                re.MULTILINE,
            ),
            "NET_RAW": re.compile(r"^\s+-\s+NET_RAW\s*$", re.MULTILINE),
            "NET_ADMIN": re.compile(r"^\s+-\s+NET_ADMIN\s*$", re.MULTILINE),
            "read-only root filesystem": re.compile(
                r"^\s+read_only:\s*true\s*$",
                re.MULTILINE,
            ),
            "no-new-privileges": re.compile(
                r"^\s+-\s+no-new-privileges:true\s*$",
                re.MULTILINE,
            ),
            "constrained entry point": re.compile(
                r"^\s+-\s+squirrelops_home_sensor\.privileged\.linux_sidecar\s*$",
                re.MULTILINE,
            ),
        }
        for label, pattern in required_helper_controls.items():
            if pattern.search(helper_text) is None:
                raise BoundaryError(
                    f"Linux network helper is missing {label} in {source}"
                )
        if re.search(r"^\s+privileged:\s*true\s*$", helper_text, re.MULTILINE):
            raise BoundaryError(
                f"Linux network helper must not be privileged in {source}"
            )
        if "/var/run/docker.sock" in helper_text:
            raise BoundaryError(
                f"Linux network helper must not mount the Docker socket in {source}"
            )


def _require_no_linux_release(repo_root: Path) -> None:
    workflow = repo_root / ".github" / "workflows" / "release.yml"
    text = _read_text(workflow)
    present = [marker for marker in LINUX_RELEASE_MARKERS if marker in text]
    if present:
        raise BoundaryError(
            "macOS-only mode still contains Linux publication paths in "
            f"{workflow}: {', '.join(present)}"
        )


def check_boundary(policy_path: Path, repo_root: Path) -> None:
    try:
        policy = json.loads(_read_text(policy_path))
    except json.JSONDecodeError as exc:
        raise BoundaryError(f"release policy is not valid JSON: {policy_path}") from exc

    if policy.get("schema_version") != 3:
        raise BoundaryError("release policy schema must be the reviewed version 3")

    linux_release = policy.get("linux_release")
    if not isinstance(linux_release, dict) or set(linux_release) != {
        "mode",
        "reviewed_at",
    }:
        raise BoundaryError("linux_release must contain only mode and reviewed_at")

    mode = linux_release.get("mode")
    reviewed_at = linux_release.get("reviewed_at")
    if mode == "blocked":
        raise BoundaryError(
            "Linux release is blocked until the constrained sidecar receives "
            "independent review. NET_RAW/NET_ADMIN must remain isolated in the "
            "companion service and remote release controls must be verified."
        )
    if mode not in {
        "constrained-sidecar-reviewed",
        "macos-only-reviewed",
    }:
        raise BoundaryError("Linux release mode is missing or unrecognized")
    if not isinstance(reviewed_at, str) or not REVIEWED_AT_RE.fullmatch(
        reviewed_at
    ):
        raise BoundaryError(
            "an independently reviewed UTC timestamp is required to unblock "
            "the Linux release boundary"
        )

    if mode == "constrained-sidecar-reviewed":
        _require_unprivileged_sensor(repo_root)
    else:
        _require_no_linux_release(repo_root)


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: check-linux-release-boundary.py POLICY_FILE REPOSITORY_ROOT",
            file=sys.stderr,
        )
        return 2

    try:
        check_boundary(Path(sys.argv[1]), Path(sys.argv[2]).resolve())
    except BoundaryError as exc:
        print(f"Linux release boundary check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
