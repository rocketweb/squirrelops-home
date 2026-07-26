"""Tests for Dockerfile and docker-compose.yml correctness.

These tests validate the packaging files as static artifacts -- they do
NOT build images or start containers. That verification is left to CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

# Resolve sensor/ root relative to this test file.
SENSOR_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Dockerfile tests
# ---------------------------------------------------------------------------


class TestDockerfile:
    """Validate Dockerfile structure and required directives."""

    @pytest.fixture(autouse=True)
    def _load_dockerfile(self) -> None:
        self.dockerfile_path = SENSOR_ROOT / "Dockerfile"
        assert self.dockerfile_path.exists(), (
            f"Dockerfile not found at {self.dockerfile_path}"
        )
        self.content = self.dockerfile_path.read_text()
        self.lines = [
            line.strip() for line in self.content.splitlines() if line.strip()
        ]

    def test_base_image_is_python_311(self) -> None:
        """Base image must be python:3.11-slim-bookworm."""
        from_lines = [l for l in self.lines if l.startswith("FROM")]
        assert any(
            "python:3.11-slim-bookworm" in l for l in from_lines
        ), f"Expected python:3.11-slim-bookworm in FROM, got: {from_lines}"

    def test_installs_runtime_libpcap(self) -> None:
        """Helper needs libpcap at runtime, not compiler headers."""
        assert "libpcap0.8" in self.content, "Missing libpcap runtime"
        assert "libpcap-dev" not in self.content

    def test_does_not_install_nmap(self) -> None:
        """Service scans use bounded unprivileged TCP probes."""
        assert "nmap" not in self.content

    def test_installs_uv(self) -> None:
        """Dockerfile must install uv for dependency management."""
        assert "uv" in self.content, "Missing uv installation"

    def test_copies_pyproject(self) -> None:
        """Must copy pyproject.toml for dependency installation."""
        copy_lines = [
            l for l in self.lines if l.startswith("COPY") or l.startswith("ADD")
        ]
        assert any(
            "pyproject.toml" in l for l in copy_lines
        ), f"Missing COPY of pyproject.toml. COPY lines: {copy_lines}"

    def test_copies_source(self) -> None:
        """Must copy the src/ directory."""
        copy_lines = [
            l for l in self.lines if l.startswith("COPY") or l.startswith("ADD")
        ]
        assert any(
            "src/" in l for l in copy_lines
        ), f"Missing COPY of src/. COPY lines: {copy_lines}"

    def test_exposes_port_8443(self) -> None:
        """Must expose port 8443."""
        expose_lines = [l for l in self.lines if l.startswith("EXPOSE")]
        assert any(
            "8443" in l for l in expose_lines
        ), f"Missing EXPOSE 8443. EXPOSE lines: {expose_lines}"

    def test_has_healthcheck(self) -> None:
        """Must define a HEALTHCHECK directive."""
        assert any(
            l.startswith("HEALTHCHECK") for l in self.lines
        ), "Missing HEALTHCHECK directive"

    def test_healthcheck_targets_system_health(self) -> None:
        """HEALTHCHECK should probe /system/health."""
        assert "/system/health" in self.content
        assert "linux_sidecar\", \"--healthcheck" in self.content

    def test_has_cmd_or_entrypoint(self) -> None:
        """Must define a CMD or ENTRYPOINT."""
        assert any(
            l.startswith("CMD") or l.startswith("ENTRYPOINT") for l in self.lines
        ), "Missing CMD or ENTRYPOINT"

    def test_cmd_runs_sensor_module(self) -> None:
        """CMD must run the squirrelops_home_sensor module."""
        cmd_lines = [
            l for l in self.lines
            if l.startswith("CMD") or l.startswith("ENTRYPOINT")
        ]
        assert any(
            "squirrelops_home_sensor" in l for l in cmd_lines
        ), f"CMD does not run squirrelops_home_sensor: {cmd_lines}"

    def test_workdir_is_set(self) -> None:
        """Must set a WORKDIR."""
        assert any(
            l.startswith("WORKDIR") for l in self.lines
        ), "Missing WORKDIR directive"


# ---------------------------------------------------------------------------
# docker-compose.yml tests
# ---------------------------------------------------------------------------


class TestDockerCompose:
    """Validate docker-compose.yml structure and service configuration."""

    @pytest.fixture(autouse=True)
    def _load_compose(self) -> None:
        self.compose_path = SENSOR_ROOT / "docker-compose.yml"
        assert self.compose_path.exists(), (
            f"docker-compose.yml not found at {self.compose_path}"
        )
        self.compose: dict = yaml.safe_load(self.compose_path.read_text())

    def test_is_valid_yaml(self) -> None:
        """File must parse as valid YAML."""
        assert isinstance(self.compose, dict)

    def test_has_services_key(self) -> None:
        assert "services" in self.compose

    def test_has_sensor_service(self) -> None:
        assert "sensor" in self.compose["services"]

    def test_has_constrained_network_helper_service(self) -> None:
        assert "network-helper" in self.compose["services"]

    def test_sensor_has_build(self) -> None:
        sensor = self.compose["services"]["sensor"]
        assert "build" in sensor, "Sensor service missing 'build' key"

    def test_sensor_exposes_port_8443(self) -> None:
        sensor = self.compose["services"]["sensor"]
        if sensor.get("network_mode") == "host":
            assert sensor.get("environment", {}).get("SQUIRRELOPS_PORT") == "8443"
            return
        ports = sensor.get("ports", [])
        port_strings = [str(p) for p in ports]
        assert any(
            "8443" in p for p in port_strings
        ), f"Sensor does not expose port 8443. Ports: {port_strings}"

    def test_sensor_drops_all_capabilities(self) -> None:
        sensor = self.compose["services"]["sensor"]
        assert sensor.get("cap_add", []) == []
        assert sensor.get("cap_drop") == ["ALL"]

    def test_helper_has_only_required_network_capabilities(self) -> None:
        helper = self.compose["services"]["network-helper"]
        assert helper.get("cap_drop") == ["ALL"]
        assert set(helper.get("cap_add", [])) == {"NET_RAW", "NET_ADMIN"}

    def test_sensor_is_non_root_and_read_only(self) -> None:
        sensor = self.compose["services"]["sensor"]
        assert sensor.get("user") == "10001:10001"
        assert sensor.get("read_only") is True
        assert "no-new-privileges:true" in sensor.get("security_opt", [])

    def test_helper_is_read_only_and_cannot_gain_privileges(self) -> None:
        helper = self.compose["services"]["network-helper"]
        assert helper.get("read_only") is True
        assert "no-new-privileges:true" in helper.get("security_opt", [])

    def test_sensor_has_volume_for_persistent_data(self) -> None:
        sensor = self.compose["services"]["sensor"]
        volumes = sensor.get("volumes", [])
        assert len(volumes) > 0, "Sensor has no volumes"
        volume_strings = [str(v) for v in volumes]
        assert any(
            "/app/data" in v or "sensor_data" in v for v in volume_strings
        ), f"No persistent data volume found. Volumes: {volume_strings}"

    def test_only_helper_has_network_mode_host(self) -> None:
        sensor = self.compose["services"]["sensor"]
        helper = self.compose["services"]["network-helper"]
        assert sensor.get("network_mode") != "host"
        assert helper.get("network_mode") == "host"

    def test_sensor_uses_private_static_bridge_address(self) -> None:
        sensor = self.compose["services"]["sensor"]
        assert (
            sensor["networks"]["sensor_private"]["ipv4_address"]
            == "172.30.0.2"
        )

    def test_sensor_mounts_helper_socket_read_only(self) -> None:
        mounts = [str(value) for value in self.compose["services"]["sensor"]["volumes"]]
        assert "helper_socket:/run/squirrelops:ro" in mounts

    def test_sensor_has_restart_policy(self) -> None:
        sensor = self.compose["services"]["sensor"]
        assert "restart" in sensor, "Sensor missing restart policy"
        assert sensor["restart"] == "unless-stopped", (
            f"Expected restart: unless-stopped, got: {sensor['restart']}"
        )

    def test_sensor_has_squirrelops_data_dir_env(self) -> None:
        sensor = self.compose["services"]["sensor"]
        env = sensor.get("environment", {})
        if isinstance(env, list):
            env_keys = [e.split("=")[0] for e in env]
        else:
            env_keys = list(env.keys())
        assert "SQUIRRELOPS_DATA_DIR" in env_keys, (
            f"Missing SQUIRRELOPS_DATA_DIR env var. Keys: {env_keys}"
        )

    def test_sensor_has_squirrelops_port_env(self) -> None:
        sensor = self.compose["services"]["sensor"]
        env = sensor.get("environment", {})
        if isinstance(env, list):
            env_keys = [e.split("=")[0] for e in env]
        else:
            env_keys = list(env.keys())
        assert "SQUIRRELOPS_PORT" in env_keys, (
            f"Missing SQUIRRELOPS_PORT env var. Keys: {env_keys}"
        )

    def test_has_named_volume_definition(self) -> None:
        """Top-level 'volumes' key should define sensor_data."""
        assert "volumes" in self.compose, "Missing top-level volumes key"
        assert "sensor_data" in self.compose["volumes"], (
            f"Missing sensor_data volume. Defined: {list(self.compose['volumes'].keys())}"
        )
