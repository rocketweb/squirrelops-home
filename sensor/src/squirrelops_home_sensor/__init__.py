"""SquirrelOps Home Sensor — network security with active deception."""

from importlib.metadata import PackageNotFoundError as _PNF
from importlib.metadata import version as _pkg_version
from pathlib import Path as _Path


def _read_version() -> str:
    """Read version from installed package metadata or the repo-level VERSION file."""
    # 1. Installed package metadata (works in Docker / pip / uv installs)
    try:
        return _pkg_version("squirrelops-home-sensor")
    except _PNF:
        pass
    # 2. Repo-level VERSION file (works in editable / development checkouts)
    for parent in _Path(__file__).resolve().parents:
        candidate = parent / "VERSION"
        if candidate.is_file():
            return candidate.read_text().strip()
    return "0.0.0"


__version__ = _read_version()
