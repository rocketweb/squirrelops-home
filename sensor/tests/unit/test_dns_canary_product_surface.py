"""Product-surface tests for unsupported DNS canaries."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from squirrelops_home_sensor.__main__ import (
    create_orchestrator,
    create_scouts_subsystem,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_default_config_does_not_offer_dns_canaries() -> None:
    defaults = yaml.safe_load(
        (REPO_ROOT / "sensor/config/home_defaults.yaml").read_text(encoding="utf-8")
    )

    assert "dns_canaries" not in defaults["decoys"]


def test_classic_decoy_factory_never_enables_dns_canaries() -> None:
    config = {
        "credential_filename": "passwords.txt",
        "decoys": {
            "max_decoys": 3,
            "dns_canaries": {
                "enabled": True,
                "domain": "canary.example.com",
            },
        },
        "network": {"interface": "en0"},
        "scouts": {},
    }

    with (
        patch(
            "squirrelops_home_sensor.decoys.orchestrator.DecoyOrchestrator"
        ) as orchestrator_type,
        patch(
            "squirrelops_home_sensor.__main__._detect_sensor_ip",
            return_value="192.168.1.79",
        ),
    ):
        create_orchestrator(config, MagicMock(), MagicMock())

    kwargs = orchestrator_type.call_args.kwargs
    assert "canary_enabled" not in kwargs
    assert "canary_domain" not in kwargs


def test_mimic_factory_never_enables_dns_canaries() -> None:
    config = {
        "decoys": {
            "dns_canaries": {
                "enabled": True,
                "domain": "canary.example.com",
            }
        },
        "network": {
            "subnet": "192.168.1.0/24",
            "interface": "en0",
        },
        "scouts": {
            "enabled": True,
            "max_concurrent_probes": 20,
            "max_mimic_decoys": 10,
            "virtual_ip_range_start": 200,
            "virtual_ip_range_end": 250,
        },
    }

    with (
        patch("squirrelops_home_sensor.network.port_forward.PortForwardManager"),
        patch("squirrelops_home_sensor.network.virtual_ip.IPAllocator"),
        patch("squirrelops_home_sensor.network.virtual_ip.VirtualIPManager"),
        patch("squirrelops_home_sensor.scouts.engine.ScoutEngine"),
        patch("squirrelops_home_sensor.scouts.mdns.MimicMDNSAdvertiser"),
        patch(
            "squirrelops_home_sensor.scouts.orchestrator.MimicOrchestrator"
        ) as orchestrator_type,
        patch("squirrelops_home_sensor.scouts.scheduler.ScoutScheduler"),
        patch("squirrelops_home_sensor.scouts.templates.MimicTemplateGenerator"),
        patch(
            "squirrelops_home_sensor.__main__._detect_sensor_ip",
            return_value="192.168.1.79",
        ),
    ):
        create_scouts_subsystem(
            config,
            MagicMock(),
            MagicMock(),
            MagicMock(),
        )

    kwargs = orchestrator_type.call_args.kwargs
    assert "canary_enabled" not in kwargs
    assert "canary_domain" not in kwargs


def test_public_docs_do_not_advertise_dns_canary_monitoring() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    user_guide = (REPO_ROOT / "docs/USER_GUIDE.md").read_text(encoding="utf-8")
    deployment_config = (REPO_ROOT / "sensor/docker-compose.yml").read_text(
        encoding="utf-8"
    )
    public_docs = readme + user_guide + deployment_config

    unsupported_claims = (
        "DNS Canary Support",
        "DNS Canary Configuration",
        "DNS Canary Setup",
        "local DNS monitor",
        "passive DNS monitoring",
        "passively sniffs DNS",
        "Canaries off by default",
        "SQUIRRELOPS_DECOYS__DNS_CANARIES__ENABLED=true",
    )
    for claim in unsupported_claims:
        assert claim not in public_docs

    assert "DNS canaries are not available in this release" in user_guide
