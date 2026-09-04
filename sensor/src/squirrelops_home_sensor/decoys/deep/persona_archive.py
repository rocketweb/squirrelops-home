"""Build the bounded persona payload streamed into the disposable guest."""

from __future__ import annotations

import io
import json
import tarfile

from squirrelops_home_sensor.decoys.deep.persona import StudioMiniPersona

MAX_PERSONA_ARCHIVE_BYTES = 512 * 1024


def _archive_name(path: str) -> str:
    parts = path.removeprefix("/").split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ValueError("Persona path must be a normalized absolute path")
    return "/".join(parts)


def _mode_for(name: str) -> int:
    private_names = (
        "/.env.local",
        "/.zsh_history",
        "/.cursor/",
        "/.claude/",
        "/.codex/",
        "run/squirrelops/persona.json",
    )
    return 0o600 if any(marker in name for marker in private_names) else 0o644


def build_persona_archive(persona: StudioMiniPersona) -> bytes:
    """Return a deterministic regular-file-only tar payload.

    The bytes travel over an anonymous pipe and Virtio socket. They are never
    required to exist as a host file.
    """
    files = {
        _archive_name(path): value.encode("utf-8")
        for path, value in persona.guest_files().items()
    }
    files["run/squirrelops/persona.json"] = json.dumps(
        {
            "hostname": persona.short_hostname,
            "login_password": persona.login_password,
            "persona_id": persona.persona_id,
            "username": persona.username,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    output = io.BytesIO()
    timestamp = int(persona.created_at.timestamp())
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(files):
            content = files[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mtime = timestamp
            info.mode = _mode_for(name)
            if name.startswith("Users/buildbot/"):
                info.uid = 501
                info.gid = 20
                info.uname = "buildbot"
                info.gname = "staff"
            else:
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "wheel"
            archive.addfile(info, io.BytesIO(content))

    payload = output.getvalue()
    if not payload or len(payload) > MAX_PERSONA_ARCHIVE_BYTES:
        raise ValueError("Persona archive is outside the reviewed size limit")
    return payload
