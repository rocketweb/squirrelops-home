"""The decoy profile compiler: every attacker-visible value is a seeded draw.

Kerckhoffs for deception. The generator and its corpora are public; the
install's draw is a function of a secret it never reveals. These tests pin the
properties that make that true: determinism for one seed, independence across
seeds and decoys, and draws that stay inside the corpus (realism).
"""

from __future__ import annotations

import json
from datetime import UTC
from importlib import resources

import pytest

from squirrelops_home_sensor.decoys import corpora
from squirrelops_home_sensor.decoys.profile import (
    PROFILE_SCHEMA,
    DecoyProfile,
    compile_profile,
    derive_key,
)

SEED_A = b"a" * 32
SEED_B = b"b" * 32


def _corpus(name: str) -> dict:
    return json.loads(resources.files(corpora).joinpath(f"{name}.json").read_text("utf-8"))


class TestDerivation:
    def test_same_inputs_same_key(self) -> None:
        assert derive_key(SEED_A, "file_share", "7", "server_version") == derive_key(
            SEED_A, "file_share", "7", "server_version"
        )

    def test_every_input_separates_the_key(self) -> None:
        base = derive_key(SEED_A, "file_share", "7", "server_version")
        assert derive_key(SEED_B, "file_share", "7", "server_version") != base
        assert derive_key(SEED_A, "dev_server", "7", "server_version") != base
        assert derive_key(SEED_A, "file_share", "8", "server_version") != base
        assert derive_key(SEED_A, "file_share", "7", "hostname") != base

    def test_parts_cannot_collide_by_concatenation(self) -> None:
        # "ab" + "c" must not derive the same key as "a" + "bc".
        assert derive_key(SEED_A, "ab", "c") != derive_key(SEED_A, "a", "bc")

    def test_short_seed_is_refused(self) -> None:
        with pytest.raises(ValueError):
            derive_key(b"short", "x")


class TestCompile:
    def test_deterministic_for_one_seed(self) -> None:
        one = compile_profile(SEED_A, decoy_type="file_share", decoy_id=3)
        two = compile_profile(SEED_A, decoy_type="file_share", decoy_id=3)
        assert one == two
        assert isinstance(one, DecoyProfile)
        assert one.schema == PROFILE_SCHEMA

    def test_seed_changes_everything_that_can_change(self) -> None:
        a = compile_profile(SEED_A, decoy_type="file_share", decoy_id=3)
        b = compile_profile(SEED_B, decoy_type="file_share", decoy_id=3)
        # Two draws can legitimately land on the same version; the listing
        # (names, dates, sizes) has far more entropy and must differ.
        assert a.listing != b.listing

    def test_two_decoys_of_one_type_on_one_install_differ(self) -> None:
        a = compile_profile(SEED_A, decoy_type="file_share", decoy_id=3)
        b = compile_profile(SEED_A, decoy_type="file_share", decoy_id=4)
        assert a.listing != b.listing

    @pytest.mark.parametrize("decoy_type", ["file_share", "dev_server", "home_assistant"])
    def test_versions_come_from_the_corpus(self, decoy_type: str) -> None:
        versions = _corpus("versions")
        for decoy_id in range(1, 25):
            profile = compile_profile(SEED_A, decoy_type=decoy_type, decoy_id=decoy_id)
            software = profile.server_software
            assert profile.server_version in {v["version"] for v in versions[software]}
            if profile.framework_version is not None:
                assert profile.framework_version in {
                    v["version"] for v in versions[profile.framework_software]
                }

    def test_file_share_profile_shape(self) -> None:
        profile = compile_profile(
            SEED_A, decoy_type="file_share", decoy_id=3, password_filename="qa-secrets.txt"
        )
        assert profile.server_software == "nginx"
        assert profile.server_header == f"nginx/{profile.server_version}"
        names = [entry.name for entry in profile.listing]
        assert "qa-secrets.txt" in names, "the configured bait file is always listed"
        assert ".ssh/" in names, "the planted key's directory is always listed"
        assert 3 <= len(profile.listing) <= 7
        assert len(set(names)) == len(names), "no duplicate names in a listing"
        for entry in profile.listing:
            assert entry.modified.tzinfo is UTC
            assert entry.is_dir == entry.name.endswith("/")
            assert (entry.size is None) == entry.is_dir
        # Timestamps are spread over a believable window, not all one day.
        stamps = sorted(entry.modified for entry in profile.listing)
        assert (stamps[-1] - stamps[0]).days >= 7

    def test_dev_server_profile_shape(self) -> None:
        profile = compile_profile(SEED_A, decoy_type="dev_server", decoy_id=3)
        assert profile.server_software == "express"
        assert profile.framework_software == "next"
        assert profile.server_header is None, "Express sets X-Powered-By, not Server"
        assert 60 <= profile.uptime_seconds <= 90 * 86400
        assert profile.app_version.count(".") == 2

    def test_home_assistant_profile_shape(self) -> None:
        profile = compile_profile(SEED_A, decoy_type="home_assistant", decoy_id=3)
        assert profile.server_software == "home_assistant"
        assert profile.hostname and " " not in profile.hostname
        assert profile.server_version.startswith("20")

    def test_unknown_type_is_refused(self) -> None:
        with pytest.raises(ValueError):
            compile_profile(SEED_A, decoy_type="mimic", decoy_id=1)

    def test_round_trips_through_json(self) -> None:
        profile = compile_profile(SEED_A, decoy_type="file_share", decoy_id=3)
        restored = DecoyProfile.from_json(profile.to_json())
        assert restored == profile


class TestCorpora:
    def test_versions_corpus_is_weighted_and_well_formed(self) -> None:
        versions = _corpus("versions")
        for software, entries in versions.items():
            assert entries, software
            for entry in entries:
                assert set(entry) == {"version", "weight"}, (software, entry)
                assert entry["weight"] > 0
                assert entry["version"].count(".") >= 1

    def test_listing_corpus_names_are_plausible(self) -> None:
        listing = _corpus("listing")
        assert len(listing["files"]) >= 12 and len(listing["directories"]) >= 6
        for name in listing["files"]:
            assert "/" not in name and " " not in name
        for name in listing["directories"]:
            assert name.endswith("/") and " " not in name
