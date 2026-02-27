"""Tests that verify project scaffolding is correctly set up."""

import importlib
import pathlib

import tomllib


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SENSOR_ROOT = REPO_ROOT / "sensor"


class TestProjectStructure:
    """Verify pyproject.toml, package, and CI configuration exist and are valid."""

    def test_pyproject_toml_exists(self) -> None:
        pyproject = SENSOR_ROOT / "pyproject.toml"
        assert pyproject.exists(), "sensor/pyproject.toml must exist"

    def test_pyproject_toml_has_project_name(self) -> None:
        pyproject = SENSOR_ROOT / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        assert data["project"]["name"] == "squirrelops-home-sensor"

    def test_pyproject_toml_has_python_requires(self) -> None:
        pyproject = SENSOR_ROOT / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        assert "requires-python" in data["project"]
        assert "3.11" in data["project"]["requires-python"]

    def test_pyproject_toml_has_runtime_dependencies(self) -> None:
        pyproject = SENSOR_ROOT / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        deps = [d.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()
                for d in data["project"]["dependencies"]]
        required = ["fastapi", "uvicorn", "websockets", "scapy", "cryptography",
                     "zeroconf", "pydantic", "aiosqlite"]
        for req in required:
            assert req in deps, f"Missing runtime dependency: {req}"

    def test_pyproject_toml_has_dev_dependencies(self) -> None:
        pyproject = SENSOR_ROOT / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        dev_deps_raw = data.get("dependency-groups", {}).get("dev", [])
        dev_deps = [d.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()
                    for d in dev_deps_raw if isinstance(d, str)]
        required = ["pytest", "pytest-asyncio", "httpx", "ruff", "pyright"]
        for req in required:
            assert req in dev_deps, f"Missing dev dependency: {req}"

    def test_package_is_importable(self) -> None:
        mod = importlib.import_module("squirrelops_home_sensor")
        assert hasattr(mod, "__version__")

    def test_ci_workflow_exists(self) -> None:
        ci = REPO_ROOT / ".github" / "workflows" / "sensor-ci.yml"
        assert ci.exists(), ".github/workflows/sensor-ci.yml must exist"

    def test_ci_workflow_has_required_steps(self) -> None:
        import yaml

        ci = REPO_ROOT / ".github" / "workflows" / "sensor-ci.yml"
        data = yaml.safe_load(ci.read_text())
        # Should define at least one job
        assert "jobs" in data
        job_names = list(data["jobs"].keys())
        assert len(job_names) >= 1
        # The first job should have steps referencing ruff, pyright, and pytest
        first_job = data["jobs"][job_names[0]]
        step_texts = " ".join(
            str(step.get("run", "")) + str(step.get("name", ""))
            for step in first_job["steps"]
        )
        assert "ruff" in step_texts, "CI must run ruff"
        assert "pyright" in step_texts, "CI must run pyright"
        assert "pytest" in step_texts, "CI must run pytest"

    def test_default_config_exists(self) -> None:
        defaults = SENSOR_ROOT / "config" / "home_defaults.yaml"
        assert defaults.exists(), "sensor/config/home_defaults.yaml must exist"

    def test_default_config_is_valid_yaml(self) -> None:
        import yaml

        defaults = SENSOR_ROOT / "config" / "home_defaults.yaml"
        data = yaml.safe_load(defaults.read_text())
        assert isinstance(data, dict)
        assert "sensor" in data
