"""SquirrelOps Home Sensor — network security with active deception."""

from pathlib import Path as _Path

def _read_version() -> str:
    """Read version from the repo-level VERSION file (single source of truth)."""
    # Walk up from this file to find the VERSION file at repo root
    for parent in _Path(__file__).resolve().parents:
        candidate = parent / "VERSION"
        if candidate.is_file():
            return candidate.read_text().strip()
    return "0.0.0"

__version__ = _read_version()
