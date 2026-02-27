"""Tests for resource profile detection and enforcement."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from squirrelops_home_sensor.profiles import (
    PROFILE_SETTINGS,
    LLMMode,
    ProfileSettings,
    ResourceProfile,
    apply_profile,
    detect_profile,
    get_profile_limits,
)


class TestResourceProfileEnum:
    """ResourceProfile is a StrEnum with three values."""

    def test_lite_value(self) -> None:
        assert ResourceProfile.LITE == "lite"
        assert ResourceProfile.LITE.value == "lite"

    def test_standard_value(self) -> None:
        assert ResourceProfile.STANDARD == "standard"
        assert ResourceProfile.STANDARD.value == "standard"

    def test_full_value(self) -> None:
        assert ResourceProfile.FULL == "full"
        assert ResourceProfile.FULL.value == "full"

    def test_enum_members_count(self) -> None:
        assert len(ResourceProfile) == 3

    def test_string_construction(self) -> None:
        assert ResourceProfile("lite") is ResourceProfile.LITE
        assert ResourceProfile("standard") is ResourceProfile.STANDARD
        assert ResourceProfile("full") is ResourceProfile.FULL

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            ResourceProfile("turbo")


class TestLLMMode:
    """LLMMode is a StrEnum with three values."""

    def test_values(self) -> None:
        assert LLMMode.LOCAL_SIGNATURES == "local_signatures"
        assert LLMMode.CLOUD_LLM == "cloud_llm"
        assert LLMMode.LOCAL_LLM == "local_llm"


class TestProfileSettings:
    """PROFILE_SETTINGS maps each profile to correct limits."""

    def test_lite_settings(self) -> None:
        settings = PROFILE_SETTINGS[ResourceProfile.LITE]
        assert isinstance(settings, ProfileSettings)
        assert settings.scan_interval == 900
        assert settings.max_decoys == 3
        assert settings.llm_mode == LLMMode.LOCAL_SIGNATURES

    def test_standard_settings(self) -> None:
        settings = PROFILE_SETTINGS[ResourceProfile.STANDARD]
        assert isinstance(settings, ProfileSettings)
        assert settings.scan_interval == 300
        assert settings.max_decoys == 8
        assert settings.llm_mode == LLMMode.CLOUD_LLM

    def test_full_settings(self) -> None:
        settings = PROFILE_SETTINGS[ResourceProfile.FULL]
        assert isinstance(settings, ProfileSettings)
        assert settings.scan_interval == 60
        assert settings.max_decoys == 16
        assert settings.llm_mode == LLMMode.LOCAL_LLM

    def test_all_profiles_have_settings(self) -> None:
        for profile in ResourceProfile:
            assert profile in PROFILE_SETTINGS


class TestDetectProfile:
    """detect_profile auto-selects based on system resources."""

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_high_resources_returns_full(self, mock_psutil: object) -> None:
        """>=16GB RAM and >=8 CPU cores -> FULL."""
        mock_psutil.virtual_memory.return_value.total = 16 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 8  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.FULL

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_very_high_resources_returns_full(self, mock_psutil: object) -> None:
        """32GB RAM and 16 cores -> FULL."""
        mock_psutil.virtual_memory.return_value.total = 32 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 16  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.FULL

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_medium_resources_returns_standard(self, mock_psutil: object) -> None:
        """>=4GB RAM and >=2 CPU cores but below FULL thresholds -> STANDARD."""
        mock_psutil.virtual_memory.return_value.total = 8 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 4  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.STANDARD

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_minimum_standard_thresholds(self, mock_psutil: object) -> None:
        """Exactly 4GB RAM and 2 cores -> STANDARD."""
        mock_psutil.virtual_memory.return_value.total = 4 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 2  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.STANDARD

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_low_ram_returns_lite(self, mock_psutil: object) -> None:
        """2GB RAM with 4 cores -> LITE (RAM too low for STANDARD)."""
        mock_psutil.virtual_memory.return_value.total = 2 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 4  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.LITE

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_low_cpu_returns_lite(self, mock_psutil: object) -> None:
        """8GB RAM with 1 core -> LITE (CPU too low for STANDARD)."""
        mock_psutil.virtual_memory.return_value.total = 8 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 1  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.LITE

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_high_ram_low_cpu_returns_standard(self, mock_psutil: object) -> None:
        """16GB RAM with 4 cores -> STANDARD (CPU too low for FULL)."""
        mock_psutil.virtual_memory.return_value.total = 16 * 1024 * 1024 * 1024  # type: ignore[attr-defined]
        mock_psutil.cpu_count.return_value = 4  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.STANDARD

    @patch("squirrelops_home_sensor.profiles.psutil", None)
    def test_psutil_not_available_returns_standard(self) -> None:
        """If psutil is not installed, fall back to STANDARD."""
        assert detect_profile() == ResourceProfile.STANDARD

    @patch("squirrelops_home_sensor.profiles.psutil")
    def test_psutil_raises_exception_returns_standard(
        self, mock_psutil: object
    ) -> None:
        """If psutil calls raise, fall back to STANDARD."""
        mock_psutil.virtual_memory.side_effect = RuntimeError("no /proc")  # type: ignore[attr-defined]
        assert detect_profile() == ResourceProfile.STANDARD


class TestGetProfileLimits:
    """get_profile_limits returns a dict with the profile's limits."""

    def test_lite_limits(self) -> None:
        limits = get_profile_limits(ResourceProfile.LITE)
        assert limits["scan_interval"] == 900
        assert limits["max_decoys"] == 3
        assert limits["llm_mode"] == "local_signatures"

    def test_standard_limits(self) -> None:
        limits = get_profile_limits(ResourceProfile.STANDARD)
        assert limits["scan_interval"] == 300
        assert limits["max_decoys"] == 8
        assert limits["llm_mode"] == "cloud_llm"

    def test_full_limits(self) -> None:
        limits = get_profile_limits(ResourceProfile.FULL)
        assert limits["scan_interval"] == 60
        assert limits["max_decoys"] == 16
        assert limits["llm_mode"] == "local_llm"


class TestApplyProfile:
    """apply_profile merges profile settings into a config dict."""

    def test_applies_scan_interval(self) -> None:
        config: dict[str, object] = {"scan_interval": 999, "other_key": "untouched"}
        result = apply_profile(config, ResourceProfile.LITE)
        assert result["scan_interval"] == 900
        assert result["other_key"] == "untouched"

    def test_applies_max_decoys(self) -> None:
        config: dict[str, object] = {}
        result = apply_profile(config, ResourceProfile.STANDARD)
        assert result["max_decoys"] == 8

    def test_applies_llm_mode(self) -> None:
        config: dict[str, object] = {}
        result = apply_profile(config, ResourceProfile.FULL)
        assert result["llm_mode"] == "local_llm"

    def test_sets_profile_key(self) -> None:
        config: dict[str, object] = {}
        result = apply_profile(config, ResourceProfile.LITE)
        assert result["profile"] == "lite"

    def test_does_not_mutate_original(self) -> None:
        config: dict[str, object] = {"scan_interval": 999}
        result = apply_profile(config, ResourceProfile.FULL)
        assert config["scan_interval"] == 999
        assert result["scan_interval"] == 60

    def test_profile_switching(self) -> None:
        """Switching from one profile to another updates all fields."""
        config: dict[str, object] = {}
        config = apply_profile(config, ResourceProfile.LITE)
        assert config["scan_interval"] == 900
        assert config["max_decoys"] == 3

        config = apply_profile(config, ResourceProfile.FULL)
        assert config["scan_interval"] == 60
        assert config["max_decoys"] == 16
        assert config["llm_mode"] == "local_llm"
        assert config["profile"] == "full"

    def test_switching_from_full_to_lite_reduces_limits(self) -> None:
        config: dict[str, object] = {}
        config = apply_profile(config, ResourceProfile.FULL)
        config = apply_profile(config, ResourceProfile.LITE)
        assert config["scan_interval"] == 900
        assert config["max_decoys"] == 3
        assert config["llm_mode"] == "local_signatures"
