"""Unit tests for the OUI database generation script.

Tests cover name cleaning/normalization, CSV parsing, module generation,
and the manufacturer type mapping.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import textwrap

import pytest

# Add scripts/ to sys.path so we can import the generation module
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from update_oui_db import (
    MANUFACTURER_ALIASES,
    MANUFACTURER_TYPES,
    clean_manufacturer_name,
    generate_oui_module,
    parse_oui_csv,
)


# ---------------------------------------------------------------------------
# clean_manufacturer_name
# ---------------------------------------------------------------------------


class TestCleanManufacturerName:
    """Verify manufacturer name cleaning and normalization."""

    def test_strips_inc(self) -> None:
        assert clean_manufacturer_name("Apple, Inc.") == "Apple"

    def test_strips_ltd(self) -> None:
        assert clean_manufacturer_name("Raspberry Pi (Trading) Ltd") == "Raspberry Pi"

    def test_strips_llc(self) -> None:
        assert clean_manufacturer_name("Google LLC") == "Google"

    def test_strips_corporate(self) -> None:
        assert clean_manufacturer_name("Intel Corporate") == "Intel"

    def test_strips_co_ltd(self) -> None:
        assert clean_manufacturer_name("Samsung Electronics Co.,Ltd") == "Samsung"

    def test_strips_ag(self) -> None:
        assert clean_manufacturer_name("Siemens AG") == "Siemens"

    def test_strips_parenthetical(self) -> None:
        assert clean_manufacturer_name("Raspberry Pi (Trading) Ltd") == "Raspberry Pi"

    def test_title_cases_all_caps(self) -> None:
        assert clean_manufacturer_name("UBIQUITI NETWORKS INC") == "Ubiquiti"

    def test_preserves_already_clean(self) -> None:
        assert clean_manufacturer_name("Sonos") == "Sonos"

    def test_strips_trailing_comma(self) -> None:
        assert clean_manufacturer_name("Cisco Systems,") == "Cisco"

    def test_strips_extra_whitespace(self) -> None:
        assert clean_manufacturer_name("  Dell   Technologies  ") == "Dell"

    def test_alias_amazon(self) -> None:
        assert clean_manufacturer_name("Amazon Technologies Inc.") == "Amazon"

    def test_alias_google(self) -> None:
        assert clean_manufacturer_name("Google LLC") == "Google"

    def test_alias_ubiquiti(self) -> None:
        assert clean_manufacturer_name("Ubiquiti Inc") == "Ubiquiti"


# ---------------------------------------------------------------------------
# parse_oui_csv
# ---------------------------------------------------------------------------


class TestParseOuiCsv:
    """Verify IEEE MA-L CSV parsing."""

    def test_parses_standard_row(self) -> None:
        csv_text = textwrap.dedent("""\
            Registry,Assignment,Organization Name,Organization Address
            MA-L,A483E7,Apple Inc.,1 Infinite Loop Cupertino CA US
        """)
        result = parse_oui_csv(csv_text)
        assert "A4:83:E7" in result
        assert result["A4:83:E7"] == "Apple"

    def test_skips_header(self) -> None:
        csv_text = textwrap.dedent("""\
            Registry,Assignment,Organization Name,Organization Address
            MA-L,AABBCC,TestCo Inc.,123 Main St
        """)
        result = parse_oui_csv(csv_text)
        # Header should not appear as a key
        assert "Re:gi:st" not in result
        assert len(result) == 1

    def test_skips_invalid_assignment(self) -> None:
        csv_text = textwrap.dedent("""\
            Registry,Assignment,Organization Name,Organization Address
            MA-L,ZZZZZZ,BadCo,Address
            MA-L,AABBCC,GoodCo,Address
        """)
        result = parse_oui_csv(csv_text)
        assert len(result) == 1
        assert "AA:BB:CC" in result

    def test_handles_multiple_entries(self) -> None:
        csv_text = textwrap.dedent("""\
            Registry,Assignment,Organization Name,Organization Address
            MA-L,A483E7,Apple Inc.,1 Infinite Loop
            MA-L,001A11,Google LLC,1600 Amphitheatre
            MA-L,B827EB,Raspberry Pi (Trading) Ltd,Maurice Wilkes Building
        """)
        result = parse_oui_csv(csv_text)
        assert len(result) == 3
        assert result["A4:83:E7"] == "Apple"
        assert result["00:1A:11"] == "Google"
        assert result["B8:27:EB"] == "Raspberry Pi"

    def test_empty_csv_returns_empty(self) -> None:
        result = parse_oui_csv("")
        assert result == {}

    def test_normalizes_names_during_parsing(self) -> None:
        csv_text = textwrap.dedent("""\
            Registry,Assignment,Organization Name,Organization Address
            MA-L,AABBCC,UBIQUITI NETWORKS INC,685 Third Avenue
        """)
        result = parse_oui_csv(csv_text)
        assert result["AA:BB:CC"] == "Ubiquiti"


# ---------------------------------------------------------------------------
# generate_oui_module
# ---------------------------------------------------------------------------


def _load_generated_module(path: pathlib.Path) -> dict:
    """Load a generated Python module via importlib and return its namespace."""
    spec = importlib.util.spec_from_file_location("_generated_oui_db", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return vars(module)


class TestGenerateOuiModule:
    """Verify Python module generation."""

    def test_generates_valid_python(self, tmp_path: pathlib.Path) -> None:
        oui_data = {
            "AA:BB:CC": "Apple",
            "11:22:33": "Google",
        }
        output = tmp_path / "oui_db.py"
        generate_oui_module(oui_data, output)

        ns = _load_generated_module(output)
        assert "OUI_DB" in ns
        assert "MANUFACTURER_TYPES" in ns
        assert ns["OUI_DB"]["AA:BB:CC"] == "Apple"
        assert ns["OUI_DB"]["11:22:33"] == "Google"

    def test_includes_header_comment(self, tmp_path: pathlib.Path) -> None:
        output = tmp_path / "oui_db.py"
        generate_oui_module({"AA:BB:CC": "TestCo"}, output)
        content = output.read_text()

        assert "Auto-generated" in content
        assert "DO NOT EDIT" in content
        assert "update_oui_db.py" in content
        assert "standards-oui.ieee.org" in content

    def test_includes_manufacturer_types(self, tmp_path: pathlib.Path) -> None:
        output = tmp_path / "oui_db.py"
        generate_oui_module({"AA:BB:CC": "Apple"}, output)

        ns = _load_generated_module(output)
        assert "MANUFACTURER_TYPES" in ns
        assert "Apple" in ns["MANUFACTURER_TYPES"]
        assert ns["MANUFACTURER_TYPES"]["Apple"] == "computer"

    def test_escapes_quotes_in_names(self, tmp_path: pathlib.Path) -> None:
        oui_data = {
            "AA:BB:CC": 'Acme "Best" Corp',
        }
        output = tmp_path / "oui_db.py"
        generate_oui_module(oui_data, output)

        # Must produce valid Python even with quotes in names
        ns = _load_generated_module(output)
        assert ns["OUI_DB"]["AA:BB:CC"] == 'Acme "Best" Corp'


# ---------------------------------------------------------------------------
# MANUFACTURER_TYPES mapping
# ---------------------------------------------------------------------------


class TestManufacturerTypes:
    """Verify the manufacturer type mapping is well-formed."""

    @pytest.mark.parametrize(
        "brand",
        ["Sonos", "Ubiquiti", "Ring", "Apple", "Samsung"],
    )
    def test_has_common_brands(self, brand: str) -> None:
        assert brand in MANUFACTURER_TYPES

    def test_types_are_valid_nonempty_strings(self) -> None:
        for name, device_type in MANUFACTURER_TYPES.items():
            assert isinstance(device_type, str), f"{name} type is not a string"
            assert len(device_type) > 0, f"{name} has empty type"
