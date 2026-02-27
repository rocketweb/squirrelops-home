#!/usr/bin/env python3
"""Generate the OUI database module from the IEEE MA-L CSV registry.

Downloads the official IEEE OUI CSV, cleans manufacturer names using alias
tables and suffix stripping, and writes a Python module that the sensor's
SignatureDB can import for OUI prefix lookups.

Usage:
    python scripts/update_oui_db.py

Output:
    sensor/src/squirrelops_home_sensor/devices/oui_db.py
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Canonical manufacturer alias table
# ---------------------------------------------------------------------------

MANUFACTURER_ALIASES: dict[str, str] = {
    "Amazon Technologies": "Amazon",
    "Amazon.Com Services": "Amazon",
    "Apple": "Apple",
    "Arris Group": "Arris",
    "Asus Computer": "Asus",
    "Asustek Computer": "Asus",
    "Belkin": "Belkin",
    "Bose": "Bose",
    "Cisco Systems": "Cisco",
    "Dell Technologies": "Dell",
    "D-Link": "D-Link",
    "Ecobee": "Ecobee",
    "Espressif": "Espressif",
    "Google": "Google",
    "Hewlett Packard": "HP",
    "Hewlett Packard Enterprise": "HPE",
    "Hon Hai Precision": "Foxconn",
    "Huawei Technologies": "Huawei",
    "Intel": "Intel",
    "Juniper Networks": "Juniper",
    "Lenovo": "Lenovo",
    "Lg Electronics": "LG",
    "Lg Innotek": "LG",
    "Liteon Technology": "Liteon",
    "Microsoft": "Microsoft",
    "Motorola Mobility": "Motorola",
    "Murata Manufacturing": "Murata",
    "Netgear": "Netgear",
    "Nintendo": "Nintendo",
    "Pegatron": "Pegatron",
    "Philips": "Philips",
    "Qualcomm": "Qualcomm",
    "Raspberry Pi": "Raspberry Pi",
    "Realtek Semiconductor": "Realtek",
    "Ring": "Ring",
    "Roku": "Roku",
    "Samsung Electronics": "Samsung",
    "Shenzhen Reecam Tech": "Reecam",
    "Signify": "Philips Hue",
    "Sony": "Sony",
    "Sonos": "Sonos",
    "Synology": "Synology",
    "Texas Instruments": "Texas Instruments",
    "Tp-Link": "TP-Link",
    "Tp-Link Systems": "TP-Link",
    "Tuya Smart": "Tuya",
    "Ubiquiti": "Ubiquiti",
    "Ubiquiti Networks": "Ubiquiti",
    "Wistron": "Wistron",
    "Xiaomi Communications": "Xiaomi",
    "Zyxel Communications": "Zyxel",
}

# ---------------------------------------------------------------------------
# Manufacturer -> default device type mapping
# ---------------------------------------------------------------------------

MANUFACTURER_TYPES: dict[str, str] = {
    "Amazon": "smart_speaker",
    "Apple": "computer",
    "Arris": "network_equipment",
    "Asus": "computer",
    "Belkin": "network_equipment",
    "Bose": "speaker",
    "Cisco": "network_equipment",
    "D-Link": "network_equipment",
    "Dell": "computer",
    "Ecobee": "thermostat",
    "Espressif": "iot_device",
    "Foxconn": "computer",
    "Google": "smart_speaker",
    "HP": "computer",
    "HPE": "computer",
    "Huawei": "smartphone",
    "Intel": "computer",
    "Juniper": "network_equipment",
    "LG": "smart_tv",
    "Lenovo": "computer",
    "Liteon": "computer",
    "Microsoft": "computer",
    "Motorola": "smartphone",
    "Murata": "iot_device",
    "Netgear": "network_equipment",
    "Nintendo": "game_console",
    "Pegatron": "computer",
    "Philips": "iot_device",
    "Philips Hue": "smart_lighting",
    "Qualcomm": "iot_device",
    "Raspberry Pi": "sbc",
    "Realtek": "network_equipment",
    "Reecam": "camera",
    "Ring": "camera",
    "Roku": "streaming",
    "Samsung": "smartphone",
    "Signify": "smart_lighting",
    "Sonos": "speaker",
    "Sony": "smart_tv",
    "Synology": "nas",
    "TP-Link": "network_equipment",
    "Texas Instruments": "iot_device",
    "Tuya": "iot_device",
    "Ubiquiti": "network_equipment",
    "Wistron": "computer",
    "Xiaomi": "smartphone",
    "Zyxel": "network_equipment",
}

# ---------------------------------------------------------------------------
# Legal suffixes to strip (order matters — longer patterns first)
# ---------------------------------------------------------------------------

_LEGAL_SUFFIXES = [
    r"\bCo\.,\s*Ltd\.?",
    r"\bCorporation\b",
    r"\bCorporate\b",
    r"\bInternational\b",
    r"\bTechnologies\b",
    r"\bTechnology\b",
    r"\bLimited\b",
    r"\bInc\.?",
    r"\bLtd\.?",
    r"\bLLC\b",
    r"\bCorp\.?",
    r"\bGmbH\b",
    r"\bS\.A\.?",
    r"\bB\.V\.?",
    r"\bN\.V\.?",
    r"\bPty\.?",
    r"\bPLC\b",
    r"\bA\.?G\.?",
    r"\bCo\.?",
]

_SUFFIX_RE = re.compile(
    r"(?:" + "|".join(_LEGAL_SUFFIXES) + r")\s*$",
    re.IGNORECASE,
)

_PAREN_RE = re.compile(r"\s*\([^)]*\)\s*")


# ---------------------------------------------------------------------------
# Name cleaning
# ---------------------------------------------------------------------------


def clean_manufacturer_name(raw: str) -> str:
    """Clean and normalize a raw IEEE manufacturer name.

    Steps:
    1. Strip leading/trailing whitespace
    2. Remove parenthetical content (e.g., "(Trading)")
    3. Strip legal suffixes (Inc., Ltd., LLC, etc.)
    4. Title-case (handles ALL CAPS input)
    5. Collapse multiple spaces
    6. Strip trailing commas
    7. Apply the alias table
    """
    name = raw.strip()

    # Remove parenthetical content
    name = _PAREN_RE.sub(" ", name)

    # Strip legal suffixes (may need multiple passes for chained suffixes)
    for _ in range(3):
        name = _SUFFIX_RE.sub("", name)

    # Title-case
    name = name.strip().title()

    # Collapse multiple spaces
    name = re.sub(r"\s+", " ", name).strip()

    # Strip trailing commas
    name = name.rstrip(",").strip()

    # Apply alias table
    if name in MANUFACTURER_ALIASES:
        name = MANUFACTURER_ALIASES[name]

    return name


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------


def parse_oui_csv(csv_text: str) -> dict[str, str]:
    """Parse IEEE MA-L CSV format into a prefix -> manufacturer dict.

    The IEEE CSV has columns: Registry, Assignment, Organization Name, ...
    Assignment is a 6-character hex string (e.g., "A483E7") which we convert
    to colon-separated format ("A4:83:E7").

    Parameters
    ----------
    csv_text:
        Raw CSV text content from the IEEE OUI registry.

    Returns
    -------
    dict[str, str]:
        Mapping of "AA:BB:CC" OUI prefix to cleaned manufacturer name.
    """
    result: dict[str, str] = {}

    reader = csv.reader(io.StringIO(csv_text))

    # Skip header row
    try:
        header = next(reader)
    except StopIteration:
        return result

    for row in reader:
        if len(row) < 3:
            continue

        assignment = row[1].strip()

        # Validate hex assignment (must be exactly 6 hex characters)
        if len(assignment) != 6 or not all(c in "0123456789ABCDEFabcdef" for c in assignment):
            continue

        # Convert to AA:BB:CC format
        assignment = assignment.upper()
        prefix = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"

        # Clean the manufacturer name
        org_name = row[2].strip()
        if not org_name:
            continue

        manufacturer = clean_manufacturer_name(org_name)
        if manufacturer:
            result[prefix] = manufacturer

    return result


# ---------------------------------------------------------------------------
# Module generation
# ---------------------------------------------------------------------------

IEEE_SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def generate_oui_module(oui_data: dict[str, str], output_path: Path) -> None:
    """Write the OUI database as a Python module.

    Generates a module containing:
    - ``OUI_DB``: dict mapping "AA:BB:CC" prefix to manufacturer name
    - ``MANUFACTURER_TYPES``: dict mapping manufacturer name to device type

    Parameters
    ----------
    oui_data:
        Mapping of OUI prefix to cleaned manufacturer name.
    output_path:
        Filesystem path to write the generated Python module.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entry_count = len(oui_data)

    lines: list[str] = []

    # Header comment
    lines.append('"""Auto-generated OUI (Organizationally Unique Identifier) database.')
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append(f"Entries:   {entry_count:,}")
    lines.append(f"Source:    {IEEE_SOURCE_URL}")
    lines.append("")
    lines.append("DO NOT EDIT — regenerate with: python scripts/update_oui_db.py")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")

    # OUI_DB dict
    lines.append("OUI_DB: dict[str, str] = {")
    for prefix in sorted(oui_data.keys()):
        manufacturer = oui_data[prefix]
        # Escape any quotes in the manufacturer name
        escaped = manufacturer.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{prefix}": "{escaped}",')
    lines.append("}")
    lines.append("")

    # MANUFACTURER_TYPES dict
    lines.append("MANUFACTURER_TYPES: dict[str, str] = {")
    for name in sorted(MANUFACTURER_TYPES.keys()):
        device_type = MANUFACTURER_TYPES[name]
        escaped_name = name.replace("\\", "\\\\").replace('"', '\\"')
        escaped_type = device_type.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{escaped_name}": "{escaped_type}",')
    lines.append("}")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """Download the IEEE OUI CSV and generate the database module."""
    import httpx

    output_path = (
        Path(__file__).resolve().parents[1]
        / "sensor"
        / "src"
        / "squirrelops_home_sensor"
        / "devices"
        / "oui_db.py"
    )

    print(f"Downloading OUI CSV from {IEEE_SOURCE_URL} ...")
    response = httpx.get(IEEE_SOURCE_URL, timeout=60.0, follow_redirects=True)
    response.raise_for_status()

    print("Parsing CSV ...")
    oui_data = parse_oui_csv(response.text)
    print(f"Parsed {len(oui_data):,} OUI entries")

    print(f"Writing module to {output_path} ...")
    generate_oui_module(oui_data, output_path)
    print("Done.")


if __name__ == "__main__":
    main()
