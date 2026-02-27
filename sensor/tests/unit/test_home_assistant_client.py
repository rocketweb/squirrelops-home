"""Tests for HomeAssistantClient and parse helpers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from squirrelops_home_sensor.integrations.home_assistant import (
    HAArea,
    HADevice,
    HomeAssistantClient,
    parse_ha_areas,
    parse_ha_devices,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HA_URL = "http://homeassistant.local:8123"
HA_TOKEN = "test-long-lived-access-token"


@pytest.fixture
def client() -> HomeAssistantClient:
    return HomeAssistantClient(url=HA_URL, token=HA_TOKEN)


# ---------------------------------------------------------------------------
# TestHADataclasses
# ---------------------------------------------------------------------------


class TestHADataclasses:
    def test_ha_device_fields(self) -> None:
        dev = HADevice(
            id="abc",
            name="Light",
            manufacturer="Philips",
            model="Hue",
            mac_addresses=frozenset({"aa:bb:cc:dd:ee:ff"}),
            area_id="area1",
        )
        assert dev.id == "abc"
        assert dev.name == "Light"
        assert dev.manufacturer == "Philips"
        assert dev.model == "Hue"
        assert dev.mac_addresses == frozenset({"aa:bb:cc:dd:ee:ff"})
        assert dev.area_id == "area1"

    def test_ha_device_frozen(self) -> None:
        dev = HADevice(
            id="abc",
            name="Light",
            manufacturer=None,
            model=None,
            mac_addresses=frozenset(),
            area_id=None,
        )
        with pytest.raises(AttributeError):
            dev.name = "New Name"  # type: ignore[misc]

    def test_ha_area_fields(self) -> None:
        area = HAArea(id="area1", name="Living Room")
        assert area.id == "area1"
        assert area.name == "Living Room"

    def test_ha_area_frozen(self) -> None:
        area = HAArea(id="area1", name="Living Room")
        with pytest.raises(AttributeError):
            area.name = "Kitchen"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestParseHADevices
# ---------------------------------------------------------------------------


class TestParseHADevices:
    def test_device_with_mac_is_parsed(self) -> None:
        raw = [
            {
                "id": "dev1",
                "name": "Smart Plug",
                "manufacturer": "TP-Link",
                "model": "HS103",
                "connections": [["mac", "AA:BB:CC:DD:EE:FF"]],
                "area_id": "living_room",
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 1
        dev = devices[0]
        assert dev.id == "dev1"
        assert dev.name == "Smart Plug"
        assert dev.manufacturer == "TP-Link"
        assert dev.model == "HS103"
        assert dev.mac_addresses == frozenset({"aa:bb:cc:dd:ee:ff"})
        assert dev.area_id == "living_room"

    def test_device_without_mac_is_skipped(self) -> None:
        raw = [
            {
                "id": "dev_zigbee",
                "name": "Zigbee Sensor",
                "manufacturer": "Aqara",
                "model": "WSDCGQ11LM",
                "connections": [["zigbee", "0x00158d0001234567"]],
                "area_id": None,
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 0

    def test_device_with_empty_connections_is_skipped(self) -> None:
        raw = [
            {
                "id": "dev_empty",
                "name": "Virtual",
                "manufacturer": None,
                "model": None,
                "connections": [],
                "area_id": None,
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 0

    def test_device_with_multiple_macs(self) -> None:
        raw = [
            {
                "id": "dev_multi",
                "name": "Multi-NIC Server",
                "manufacturer": "Dell",
                "model": "PowerEdge",
                "connections": [
                    ["mac", "11:22:33:44:55:66"],
                    ["mac", "AA:BB:CC:DD:EE:FF"],
                ],
                "area_id": "server_room",
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 1
        assert devices[0].mac_addresses == frozenset(
            {"11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"}
        )

    def test_missing_optional_fields(self) -> None:
        """Devices with None name, manufacturer, model, area_id are handled."""
        raw = [
            {
                "id": "dev_minimal",
                "name": None,
                "manufacturer": None,
                "model": None,
                "connections": [["mac", "AA:BB:CC:DD:EE:FF"]],
                "area_id": None,
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 1
        dev = devices[0]
        assert dev.name is None
        assert dev.manufacturer is None
        assert dev.model is None
        assert dev.area_id is None

    def test_missing_keys_handled(self) -> None:
        """Devices with missing keys (not just None values) are handled gracefully."""
        raw = [
            {
                "id": "dev_sparse",
                "connections": [["mac", "AA:BB:CC:DD:EE:FF"]],
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 1
        dev = devices[0]
        assert dev.name is None
        assert dev.manufacturer is None
        assert dev.model is None
        assert dev.area_id is None

    def test_mac_addresses_normalized_to_lowercase(self) -> None:
        raw = [
            {
                "id": "dev1",
                "name": "Test",
                "manufacturer": None,
                "model": None,
                "connections": [["mac", "AA:BB:CC:DD:EE:FF"]],
                "area_id": None,
            }
        ]
        devices = parse_ha_devices(raw)
        assert "aa:bb:cc:dd:ee:ff" in devices[0].mac_addresses

    def test_mixed_connection_types(self) -> None:
        """Only mac connections are extracted, non-mac are ignored."""
        raw = [
            {
                "id": "dev_mixed",
                "name": "Hybrid Device",
                "manufacturer": "Test",
                "model": "X",
                "connections": [
                    ["zigbee", "0x00158d0001234567"],
                    ["mac", "11:22:33:44:55:66"],
                    ["upnp", "uuid:abc-123"],
                ],
                "area_id": None,
            }
        ]
        devices = parse_ha_devices(raw)
        assert len(devices) == 1
        assert devices[0].mac_addresses == frozenset({"11:22:33:44:55:66"})


# ---------------------------------------------------------------------------
# TestParseHAAreas
# ---------------------------------------------------------------------------


class TestParseHAAreas:
    def test_parse_areas(self) -> None:
        raw = [
            {"area_id": "living_room", "name": "Living Room"},
            {"area_id": "bedroom", "name": "Bedroom"},
        ]
        areas = parse_ha_areas(raw)
        assert len(areas) == 2
        assert areas[0] == HAArea(id="living_room", name="Living Room")
        assert areas[1] == HAArea(id="bedroom", name="Bedroom")

    def test_parse_empty_areas(self) -> None:
        assert parse_ha_areas([]) == []


# ---------------------------------------------------------------------------
# Fake WebSocket for testing _ws_command
# ---------------------------------------------------------------------------


class FakeWebSocket:
    """Simulates the HA WebSocket protocol for testing."""

    def __init__(self, responses: list[dict]) -> None:
        self._responses = list(responses)
        self._sent: list[str] = []

    async def recv(self) -> str:
        return json.dumps(self._responses.pop(0))

    async def send(self, data: str) -> None:
        self._sent.append(data)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    @property
    def sent_messages(self) -> list[dict]:
        return [json.loads(m) for m in self._sent]


# ---------------------------------------------------------------------------
# TestHomeAssistantClient
# ---------------------------------------------------------------------------


class TestHomeAssistantClient:
    # -- test_connection (HTTP) --

    async def test_connection_success(
        self, client: HomeAssistantClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{HA_URL}/api/",
            json={"message": "API running."},
            status_code=200,
        )
        assert await client.test_connection() is True

    async def test_connection_401_returns_false(
        self, client: HomeAssistantClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{HA_URL}/api/",
            status_code=401,
        )
        assert await client.test_connection() is False

    async def test_connection_unreachable_returns_false(
        self, client: HomeAssistantClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_exception(
            httpx.ConnectError("Connection refused"),
            url=f"{HA_URL}/api/",
        )
        assert await client.test_connection() is False

    async def test_bearer_token_sent_in_header(
        self, client: HomeAssistantClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{HA_URL}/api/",
            json={"message": "API running."},
        )
        await client.test_connection()
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["authorization"] == f"Bearer {HA_TOKEN}"

    # -- get_devices (WebSocket) --

    async def test_get_devices_returns_parsed_list(
        self, client: HomeAssistantClient
    ) -> None:
        fake_ws = FakeWebSocket([
            {"type": "auth_required"},
            {"type": "auth_ok"},
            {
                "id": 1,
                "type": "result",
                "success": True,
                "result": [
                    {
                        "id": "dev1",
                        "name": "Plug",
                        "manufacturer": "TP-Link",
                        "model": "HS103",
                        "connections": [["mac", "AA:BB:CC:DD:EE:FF"]],
                        "area_id": "room1",
                    },
                    {
                        "id": "dev2",
                        "name": "Zigbee Sensor",
                        "manufacturer": "Aqara",
                        "model": "WSDCGQ11LM",
                        "connections": [["zigbee", "0x00158d0001234567"]],
                        "area_id": None,
                    },
                ],
            },
        ])
        with patch("squirrelops_home_sensor.integrations.home_assistant.websockets.connect", return_value=fake_ws):
            devices = await client.get_devices()
        assert len(devices) == 1
        assert devices[0].id == "dev1"
        assert devices[0].mac_addresses == frozenset({"aa:bb:cc:dd:ee:ff"})

    async def test_get_devices_sends_correct_ws_command(
        self, client: HomeAssistantClient
    ) -> None:
        fake_ws = FakeWebSocket([
            {"type": "auth_required"},
            {"type": "auth_ok"},
            {"id": 1, "type": "result", "success": True, "result": []},
        ])
        with patch("squirrelops_home_sensor.integrations.home_assistant.websockets.connect", return_value=fake_ws):
            await client.get_devices()
        # Verify auth message
        assert fake_ws.sent_messages[0] == {
            "type": "auth",
            "access_token": HA_TOKEN,
        }
        # Verify registry command
        assert fake_ws.sent_messages[1] == {
            "id": 1,
            "type": "config/device_registry/list",
        }

    async def test_get_devices_ws_connect_failure_returns_empty(
        self, client: HomeAssistantClient
    ) -> None:
        with patch(
            "squirrelops_home_sensor.integrations.home_assistant.websockets.connect",
            side_effect=OSError("Connection refused"),
        ):
            devices = await client.get_devices()
        assert devices == []

    async def test_get_devices_ws_auth_failure_returns_empty(
        self, client: HomeAssistantClient
    ) -> None:
        fake_ws = FakeWebSocket([
            {"type": "auth_required"},
            {"type": "auth_invalid", "message": "Invalid access token"},
        ])
        with patch("squirrelops_home_sensor.integrations.home_assistant.websockets.connect", return_value=fake_ws):
            devices = await client.get_devices()
        assert devices == []

    # -- get_areas (WebSocket) --

    async def test_get_areas_returns_parsed_list(
        self, client: HomeAssistantClient
    ) -> None:
        fake_ws = FakeWebSocket([
            {"type": "auth_required"},
            {"type": "auth_ok"},
            {
                "id": 1,
                "type": "result",
                "success": True,
                "result": [
                    {"area_id": "room1", "name": "Living Room"},
                    {"area_id": "room2", "name": "Kitchen"},
                ],
            },
        ])
        with patch("squirrelops_home_sensor.integrations.home_assistant.websockets.connect", return_value=fake_ws):
            areas = await client.get_areas()
        assert len(areas) == 2
        assert areas[0] == HAArea(id="room1", name="Living Room")
        assert areas[1] == HAArea(id="room2", name="Kitchen")

    async def test_get_areas_ws_failure_returns_empty(
        self, client: HomeAssistantClient
    ) -> None:
        with patch(
            "squirrelops_home_sensor.integrations.home_assistant.websockets.connect",
            side_effect=OSError("Connection refused"),
        ):
            areas = await client.get_areas()
        assert areas == []

    async def test_get_areas_command_failure_returns_empty(
        self, client: HomeAssistantClient
    ) -> None:
        fake_ws = FakeWebSocket([
            {"type": "auth_required"},
            {"type": "auth_ok"},
            {"id": 1, "type": "result", "success": False, "error": {"code": "not_found"}},
        ])
        with patch("squirrelops_home_sensor.integrations.home_assistant.websockets.connect", return_value=fake_ws):
            areas = await client.get_areas()
        assert areas == []

    # -- ws_url derivation --

    def test_ws_url_from_http(self) -> None:
        c = HomeAssistantClient(url="http://ha.local:8123", token="t")
        assert c._ws_url == "ws://ha.local:8123"

    def test_ws_url_from_https(self) -> None:
        c = HomeAssistantClient(url="https://ha.local:8123", token="t")
        assert c._ws_url == "wss://ha.local:8123"
