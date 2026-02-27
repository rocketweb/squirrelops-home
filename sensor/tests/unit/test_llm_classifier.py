"""Unit tests for OpenAI-compatible LLM device classifier."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from squirrelops_home_sensor.devices.llm_classifier import (
    OpenAICompatibleClassifier,
    _build_user_prompt,
)
from squirrelops_home_sensor.devices.signatures import DeviceClassification
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chat_response(content: dict | str) -> httpx.Response:
    """Build a mock httpx.Response mimicking an OpenAI chat completion."""
    if isinstance(content, dict):
        content = json.dumps(content)
    body = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 30, "total_tokens": 80},
    }
    return httpx.Response(
        status_code=200,
        json=body,
        request=httpx.Request("POST", "http://localhost:1234/v1/chat/completions"),
    )


_SAMPLE_FINGERPRINT = CompositeFingerprint(
    mac_address="A4:83:E7:11:22:33",
    mdns_hostname="sarahs-iphone",
    dhcp_fingerprint_hash="abc123",
    open_ports_hash="def456",
    connection_pattern_hash="ghi789",
)

_SAMPLE_LLM_REPLY = {
    "manufacturer": "Apple",
    "device_type": "smartphone",
    "model": "iPhone 15",
    "confidence": 0.92,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def classifier_no_key() -> OpenAICompatibleClassifier:
    """Classifier without API key (local LLM)."""
    return OpenAICompatibleClassifier(
        endpoint="http://localhost:1234/v1",
        model="llama-3.2-3b",
    )


@pytest.fixture
def classifier_with_key() -> OpenAICompatibleClassifier:
    """Classifier with API key (cloud LLM)."""
    return OpenAICompatibleClassifier(
        endpoint="https://api.openai.com/v1",
        model="gpt-4o-mini",
        api_key="sk-test-key-123",
    )


# ---------------------------------------------------------------------------
# Successful classification
# ---------------------------------------------------------------------------

class TestSuccessfulClassification:
    """Tests for the happy path -- well-formed LLM responses."""

    @pytest.mark.asyncio
    async def test_returns_correct_classification(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        mock_response = _make_chat_response(_SAMPLE_LLM_REPLY)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            result = await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        assert isinstance(result, DeviceClassification)
        assert result.manufacturer == "Apple"
        assert result.device_type == "smartphone"
        assert result.model == "iPhone 15"
        assert result.confidence == pytest.approx(0.92)
        assert result.source == "llm"

    @pytest.mark.asyncio
    async def test_sends_to_correct_url(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        mock_response = _make_chat_response(_SAMPLE_LLM_REPLY)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        call_args = mock_post.call_args
        assert call_args[0][0] == "http://localhost:1234/v1/chat/completions"

    @pytest.mark.asyncio
    async def test_endpoint_trailing_slash_stripped(self) -> None:
        """Trailing slash on endpoint should not cause double-slash in URL."""
        classifier = OpenAICompatibleClassifier(
            endpoint="http://localhost:1234/v1/",
            model="test-model",
        )
        mock_response = _make_chat_response(_SAMPLE_LLM_REPLY)
        with patch.object(classifier._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await classifier.classify(_SAMPLE_FINGERPRINT)

        call_args = mock_post.call_args
        assert call_args[0][0] == "http://localhost:1234/v1/chat/completions"

    @pytest.mark.asyncio
    async def test_includes_model_in_payload(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        mock_response = _make_chat_response(_SAMPLE_LLM_REPLY)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["model"] == "llama-3.2-3b"

    @pytest.mark.asyncio
    async def test_null_model_in_response(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        reply = {
            "manufacturer": "Unknown Vendor",
            "device_type": "iot_sensor",
            "model": None,
            "confidence": 0.45,
        }
        mock_response = _make_chat_response(reply)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            result = await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        assert result.model is None
        assert result.device_type == "iot_sensor"
        assert result.confidence == pytest.approx(0.45)

    @pytest.mark.asyncio
    async def test_missing_model_defaults_to_none(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """When the LLM omits 'model' entirely, it should default to None."""
        reply = {
            "manufacturer": "Acme",
            "device_type": "router",
            "confidence": 0.60,
        }
        mock_response = _make_chat_response(reply)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            result = await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        assert result.model is None

    @pytest.mark.asyncio
    async def test_missing_confidence_defaults_to_half(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """When 'confidence' is omitted, default to 0.5."""
        reply = {
            "manufacturer": "Acme",
            "device_type": "router",
        }
        mock_response = _make_chat_response(reply)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            result = await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        assert result.confidence == pytest.approx(0.5)

    @pytest.mark.asyncio
    async def test_strips_think_tags(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """Models that emit <think>...</think> blocks should still parse."""
        content = (
            '<think>This looks like an Apple device based on the OUI prefix.</think>\n'
            '{"manufacturer": "Apple", "device_type": "smartphone", "model": "iPhone 15", "confidence": 0.9}'
        )
        mock_response = _make_chat_response(content)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            result = await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        assert result.manufacturer == "Apple"
        assert result.confidence == pytest.approx(0.9)

    @pytest.mark.asyncio
    async def test_extracts_json_from_markdown_fences(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """JSON wrapped in markdown code fences should still parse."""
        content = (
            'Here is the classification:\n'
            '```json\n'
            '{"manufacturer": "Samsung", "device_type": "smart_tv", "model": null, "confidence": 0.7}\n'
            '```'
        )
        mock_response = _make_chat_response(content)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            result = await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        assert result.manufacturer == "Samsung"
        assert result.device_type == "smart_tv"


# ---------------------------------------------------------------------------
# API key handling
# ---------------------------------------------------------------------------

class TestAPIKeyHandling:
    """Tests for API key header inclusion/exclusion."""

    @pytest.mark.asyncio
    async def test_includes_api_key_header(
        self, classifier_with_key: OpenAICompatibleClassifier
    ) -> None:
        mock_response = _make_chat_response(_SAMPLE_LLM_REPLY)
        with patch.object(classifier_with_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await classifier_with_key.classify(_SAMPLE_FINGERPRINT)

        call_kwargs = mock_post.call_args[1]
        headers = call_kwargs["headers"]
        assert headers["Authorization"] == "Bearer sk-test-key-123"

    @pytest.mark.asyncio
    async def test_no_auth_header_without_key(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        mock_response = _make_chat_response(_SAMPLE_LLM_REPLY)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

        call_kwargs = mock_post.call_args[1]
        headers = call_kwargs["headers"]
        assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

class TestPromptConstruction:
    """Tests for _build_user_prompt and the prompts sent to the LLM."""

    def test_prompt_includes_mac_oui(self) -> None:
        fp = CompositeFingerprint(mac_address="A4:83:E7:11:22:33")
        prompt = _build_user_prompt(fp)
        assert "A4:83:E7" in prompt
        assert "MAC OUI prefix" in prompt

    def test_prompt_includes_mdns_hostname(self) -> None:
        fp = CompositeFingerprint(mdns_hostname="sarahs-iphone")
        prompt = _build_user_prompt(fp)
        assert "sarahs-iphone" in prompt
        assert "mDNS hostname" in prompt

    def test_prompt_includes_dhcp_hash(self) -> None:
        fp = CompositeFingerprint(dhcp_fingerprint_hash="abc123")
        prompt = _build_user_prompt(fp)
        assert "abc123" in prompt
        assert "DHCP fingerprint hash" in prompt

    def test_prompt_includes_open_ports_hash(self) -> None:
        fp = CompositeFingerprint(open_ports_hash="def456")
        prompt = _build_user_prompt(fp)
        assert "def456" in prompt
        assert "Open ports hash" in prompt

    def test_prompt_includes_connection_pattern_hash(self) -> None:
        fp = CompositeFingerprint(connection_pattern_hash="ghi789")
        prompt = _build_user_prompt(fp)
        assert "ghi789" in prompt
        assert "Connection pattern hash" in prompt

    def test_prompt_omits_none_signals(self) -> None:
        fp = CompositeFingerprint(mac_address="A4:83:E7:11:22:33")
        prompt = _build_user_prompt(fp)
        assert "mDNS" not in prompt
        assert "DHCP" not in prompt
        assert "Open ports" not in prompt
        assert "Connection pattern" not in prompt

    def test_empty_fingerprint_has_header_only(self) -> None:
        fp = CompositeFingerprint()
        prompt = _build_user_prompt(fp)
        assert prompt == "Classify this network device based on the following signals:"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for HTTP errors, timeouts, and malformed responses."""

    @pytest.mark.asyncio
    async def test_http_error_raises(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        error_response = httpx.Response(
            status_code=500,
            json={"error": "Internal server error"},
            request=httpx.Request("POST", "http://localhost:1234/v1/chat/completions"),
        )
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = error_response
            with pytest.raises(httpx.HTTPStatusError):
                await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

    @pytest.mark.asyncio
    async def test_timeout_raises(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Connection timed out")
            with pytest.raises(httpx.TimeoutException):
                await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

    @pytest.mark.asyncio
    async def test_malformed_json_raises(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """When the LLM returns non-JSON content, json.loads should raise."""
        mock_response = _make_chat_response("This is not valid JSON at all")
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            with pytest.raises(json.JSONDecodeError):
                await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

    @pytest.mark.asyncio
    async def test_missing_manufacturer_raises(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """When 'manufacturer' is missing from the response, KeyError is raised."""
        reply = {"device_type": "router", "confidence": 0.8}
        mock_response = _make_chat_response(reply)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            with pytest.raises(KeyError):
                await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

    @pytest.mark.asyncio
    async def test_missing_device_type_raises(
        self, classifier_no_key: OpenAICompatibleClassifier
    ) -> None:
        """When 'device_type' is missing from the response, KeyError is raised."""
        reply = {"manufacturer": "Apple", "confidence": 0.8}
        mock_response = _make_chat_response(reply)
        with patch.object(classifier_no_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            with pytest.raises(KeyError):
                await classifier_no_key.classify(_SAMPLE_FINGERPRINT)

    @pytest.mark.asyncio
    async def test_http_401_raises(
        self, classifier_with_key: OpenAICompatibleClassifier
    ) -> None:
        """Authentication failure raises HTTPStatusError."""
        error_response = httpx.Response(
            status_code=401,
            json={"error": {"message": "Invalid API key"}},
            request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
        )
        with patch.object(classifier_with_key._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = error_response
            with pytest.raises(httpx.HTTPStatusError):
                await classifier_with_key.classify(_SAMPLE_FINGERPRINT)
