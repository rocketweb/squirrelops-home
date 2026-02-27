"""OpenAI-compatible LLM classifier for device fingerprints.

Works with any API exposing the /v1/chat/completions endpoint:
- OpenAI API (cloud, Standard profile)
- LM Studio (local, Full profile)
- Ollama with OpenAI-compatible mode (local, Full profile)
"""

from __future__ import annotations

import json
import logging
import re

import httpx

from squirrelops_home_sensor.devices.classifier import LLMClassifier
from squirrelops_home_sensor.devices.signatures import DeviceClassification
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a network device classifier. Given network fingerprint signals, "
    "identify the device manufacturer, type, and model. Respond with ONLY a JSON "
    "object containing: manufacturer (string), device_type (string, e.g. smartphone, "
    "laptop, smart_speaker, nas, router, printer, camera, smart_tv, game_console, "
    "iot_sensor, unknown), model (string or null), confidence (float 0.0-1.0)."
)


def _build_user_prompt(fingerprint: CompositeFingerprint) -> str:
    """Build a user prompt from available fingerprint signals."""
    lines = ["Classify this network device based on the following signals:"]

    if fingerprint.mac_address is not None:
        oui = fingerprint.mac_address[:8]
        lines.append(f"- MAC OUI prefix: {oui}")

    if fingerprint.mdns_hostname is not None:
        lines.append(f"- mDNS hostname: {fingerprint.mdns_hostname}")

    if fingerprint.dhcp_fingerprint_hash is not None:
        lines.append(f"- DHCP fingerprint hash: {fingerprint.dhcp_fingerprint_hash}")

    if fingerprint.open_ports_hash is not None:
        lines.append(f"- Open ports hash: {fingerprint.open_ports_hash}")

    if fingerprint.connection_pattern_hash is not None:
        lines.append(f"- Connection pattern hash: {fingerprint.connection_pattern_hash}")

    return "\n".join(lines)


class OpenAICompatibleClassifier(LLMClassifier):
    """LLM classifier using OpenAI-compatible chat completions API.

    Parameters
    ----------
    endpoint:
        Base URL for the API (e.g., "http://localhost:1234/v1" or
        "https://api.openai.com/v1").
    model:
        Model name to use (e.g., "gpt-4o-mini", "llama-3.2-3b").
    api_key:
        Optional API key. Required for cloud APIs, not needed for local.
    timeout:
        Request timeout in seconds.
    """

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        base = endpoint.rstrip("/")
        # Ensure /v1 suffix for OpenAI-compatible APIs
        if not base.endswith("/v1"):
            base = f"{base}/v1"
        self._endpoint = base
        self._model = model
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=timeout)

    async def classify(self, fingerprint: CompositeFingerprint) -> DeviceClassification:
        """Classify a device by sending fingerprint signals to the LLM.

        Raises on HTTP errors, timeouts, or malformed responses -- the
        caller (DeviceClassifier) catches all exceptions and degrades
        gracefully.
        """
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(fingerprint)},
            ],
            "temperature": 0.1,
        }

        response = await self._client.post(
            f"{self._endpoint}/chat/completions",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        # Strip <think>...</think> blocks some models emit before the JSON
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        # Extract JSON object even if surrounded by markdown fences or prose
        json_match = re.search(r"\{[^{}]*\}", content, flags=re.DOTALL)
        if json_match:
            content = json_match.group(0)

        parsed = json.loads(content)

        manufacturer = parsed["manufacturer"]
        device_type = parsed["device_type"]
        model = parsed.get("model")
        confidence = float(parsed.get("confidence", 0.5))

        return DeviceClassification(
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            confidence=confidence,
            source="llm",
        )
