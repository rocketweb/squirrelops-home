"""Filesystem helpers for writing sensitive files securely.

Private key material and the encrypted secret store must never exist on disk
with world-readable permissions, not even for the brief window between a
``write_text`` and a follow-up ``chmod``. These helpers create the file with
restrictive permissions from the start (via ``mkstemp``, which opens with
0600 and ``O_EXCL``) and then atomically rename it into place.
"""

from __future__ import annotations

import os
import pathlib
import tempfile


def write_bytes_atomic(
    path: str | os.PathLike[str], data: bytes, *, mode: int = 0o600
) -> None:
    """Atomically write ``data`` to ``path`` with the given permission ``mode``.

    The bytes are written to a temporary file in the same directory (created
    with 0600 by ``mkstemp``), fsync'd, chmod'd to ``mode``, then renamed over
    the destination. There is therefore never a window where the destination
    exists with looser permissions than requested.
    """
    dest = pathlib.Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=f".{dest.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_text_atomic(
    path: str | os.PathLike[str], text: str, *, mode: int = 0o600, encoding: str = "utf-8"
) -> None:
    """Atomically write ``text`` to ``path`` with restrictive permissions."""
    write_bytes_atomic(path, text.encode(encoding), mode=mode)
