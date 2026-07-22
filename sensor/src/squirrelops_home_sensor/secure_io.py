"""Small helpers for private, atomic runtime files."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def ensure_private_directory(path: Path, *, mode: int = 0o700) -> None:
    """Create *path* and restrict it to the current service identity."""
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chmod(path, mode)


def atomic_write_private_text(path: Path, value: str) -> None:
    """Atomically replace *path* with a mode-0600 regular file.

    Creating the temporary file in the destination directory and replacing the
    final path avoids following pre-created symlinks and never exposes a
    partially written secret-bearing configuration file.
    """
    ensure_private_directory(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
