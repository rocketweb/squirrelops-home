"""SquirrelOps Home Sensor — network security with active deception."""

from importlib.metadata import PackageNotFoundError as _PNF
from importlib.metadata import version as _pkg_version
from pathlib import Path as _Path


def _read_version() -> str:
    """Read version from installed metadata or the sensor project metadata."""
    # 1. Installed package metadata (works in Docker / pip / uv installs)
    try:
        return _pkg_version("squirrelops-home-sensor")
    except _PNF:
        pass
    # 2. Sensor pyproject (works in editable / development checkouts without
    # coupling the sensor to the macOS distribution version).
    for parent in _Path(__file__).resolve().parents:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            import tomllib

            project = tomllib.loads(candidate.read_text(encoding="utf-8"))
            version = project.get("project", {}).get("version")
            if isinstance(version, str):
                return version
    return "0.0.0"


__version__ = _read_version()
