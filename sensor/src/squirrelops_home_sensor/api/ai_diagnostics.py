"""Operator-only AI discovery and synthetic acceptance. Never reads device data."""

from __future__ import annotations

import asyncio
import re
import time
from copy import deepcopy
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from squirrelops_home_sensor.api.deps import get_config, verify_client_cert
from squirrelops_home_sensor.devices.classifier import DeviceClassificationEvidence
from squirrelops_home_sensor.devices.llm_classifier import (
    CLOUD_LLM_PROVIDERS,
    OpenAICompatibleClassifier,
    resolve_llm_endpoint,
)
from squirrelops_home_sensor.fingerprint.composite import CompositeFingerprint


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/config/ai", tags=["config"], dependencies=[Depends(_no_store)])
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_MODELS = 1000
PROBE_DEADLINE = 50


class DiagnosticClient(httpx.AsyncClient):
    """Bound replies and output tokens without changing production prompts/parsers."""

    async def bounded_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async with self.stream(method, url, **kwargs) as response:
            response.raise_for_status()  # Includes redirects; never forward a key.
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError("Diagnostic response is too large")
                content.extend(chunk)
            return httpx.Response(
                response.status_code, content=bytes(content), request=response.request
            )

    async def post(self, url, **kwargs) -> httpx.Response:
        kwargs["json"] = {**kwargs["json"], "max_tokens": 512}
        return await self.bounded_request("POST", url, **kwargs)


def make_client() -> DiagnosticClient:
    return DiagnosticClient(timeout=20, follow_redirects=False, trust_env=False)


def _settings(config: dict, *, require_model: bool) -> tuple[str, str, str, str | None]:
    settings = config.get("classifier", {})
    provider = str(settings.get("llm_provider") or "custom").strip().lower()
    endpoint = resolve_llm_endpoint(provider, settings.get("llm_endpoint"))
    model = str(settings.get("llm_model") or "").strip()
    key = settings.get("llm_api_key") or None
    if not endpoint:
        raise ValueError("Choose an AI provider and save its endpoint first.")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise ValueError("The AI endpoint URL is invalid.") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(
            "Use an HTTP or HTTPS API base URL without embedded credentials, query, or fragment."
        )
    if provider in CLOUD_LLM_PROVIDERS and not key:
        raise ValueError("Save this provider's API key before connecting.")
    if require_model and not model:
        raise ValueError("Choose or enter a model before testing.")
    endpoint = endpoint.rstrip("/")
    if not endpoint.endswith("/v1"):
        endpoint += "/v1"
    return provider, endpoint, model, key


def _model(row: object, provider: str) -> dict | None:
    if not isinstance(row, dict):
        raise ValueError("Invalid catalog entry")
    identifier = row.get("name") if provider == "fireworks" else row.get("id")
    name = row.get("displayName") if provider == "fireworks" else row.get("name")
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 512:
        raise ValueError("Invalid model identifier")
    if any(ord(char) < 32 or ord(char) == 127 for char in identifier):
        raise ValueError("Invalid model identifier")
    # Retain unknown capabilities for custom servers. Only exclude positive
    # evidence of incompatibility; the generation test is authoritative.
    if row.get("type") in {"embedding", "embeddings"}:
        return None
    architecture = row.get("architecture") or {}
    if not isinstance(architecture, dict):
        raise ValueError("Invalid model metadata")
    for field in ("input_modalities", "output_modalities"):
        modalities = architecture.get(field)
        if isinstance(modalities, list) and "text" not in modalities:
            return None
    if not isinstance(name, str) or not name.strip():
        name = identifier
    return {"id": identifier, "name": " ".join(name.split())[:256]}


async def discover(config: dict, client: DiagnosticClient) -> dict:
    provider, endpoint, model, key = _settings(config, require_model=False)
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    url = endpoint + "/models"
    params: dict = {}
    if provider == "fireworks":
        match = re.fullmatch(r"accounts/([a-zA-Z0-9_-]+)/models/[^/]+", model)
        account = match[1] if match else "fireworks"
        url = f"https://api.fireworks.ai/v1/accounts/{account}/models"
        params = {"pageSize": 200}
    models = {}
    truncated = False
    for _ in range(5):
        response = await client.bounded_request("GET", url, headers=headers, params=params)
        body = response.json()
        rows = body["models" if provider == "fireworks" else "data"]
        if not isinstance(rows, list):
            raise ValueError("Invalid model catalog")
        for row in rows[:MAX_MODELS]:
            entry = _model(row, provider)
            if entry and entry["id"] not in models:
                models[entry["id"]] = entry
            if len(models) >= MAX_MODELS:
                break
        token = body.get("nextPageToken") if provider == "fireworks" else None
        truncated = bool(token) or len(rows) > MAX_MODELS or len(models) >= MAX_MODELS
        if not token or len(models) >= MAX_MODELS:
            break
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError("Invalid pagination token")
        params["pageToken"] = token
    message = (
        f"Found {len(models)} models. Select one and test it; discovery does not verify generation."
        if models
        else "The endpoint responded but listed no chat models. Load a model or enter its ID manually."
    )
    if provider == "fireworks":
        message += " Catalog entries may require a deployment; you can enter a deployment model ID manually."
    if truncated:
        message += " The list is limited; manual model IDs are still supported."
    return {
        "status": "ok",
        "message": message,
        "models": sorted(models.values(), key=lambda item: item["name"].casefold()),
    }


async def test_model(config: dict, client: DiagnosticClient, checks: dict) -> dict:
    _, endpoint, model, key = _settings(config, require_model=True)
    classifier = OpenAICompatibleClassifier(endpoint, model, api_key=key, client=client)
    await classifier.classify(
        CompositeFingerprint(),
        DeviceClassificationEvidence(
            dns_hostname="synthetic-printer", open_ports=(631,), detected_services=("ipp",)
        ),
    )
    checks["classification"] = True
    names = await classifier.suggest_decoy_hostnames(
        existing_hostnames=["example-office", "example-backup"],
        count=1,
        allow_identifiers=False,
    )
    if not names or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]|[a-zA-Z]", names[0]):
        raise ValueError("Invalid hostname suggestion")
    if names[0].lower() in {"example-office", "example-backup"}:
        raise ValueError("Repeated existing hostname")
    checks["naming"] = True
    return {
        "status": "ok",
        "message": "Test passed: classification and decoy naming returned usable data.",
    }


def _failure(exc: Exception, discovery: bool) -> tuple[str, str]:
    # Never expose provider bodies, URLs, exception strings, or credentials.
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if discovery and code in {404, 405, 501}:
            return (
                "unsupported",
                "Model discovery is unavailable. Enter a model ID manually and use Test model.",
            )
        messages = {
            401: "The provider rejected the API key. Check and save the key, then retry.",
            403: "The API key does not have permission for this operation or model.",
            402: "The provider requires credits or billing setup.",
            404: "The selected model or inference endpoint was not found.",
            429: "The provider's rate or quota limit was reached. Check your account and retry later.",
        }
        if 300 <= code < 400:
            return (
                "error",
                "The endpoint returned a redirect. Save its final API URL; credentials were not forwarded.",
            )
        return "error", messages.get(
            code,
            f"The provider rejected the request (HTTP {code}). Check model compatibility and provider status.",
        )
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return "error", "The AI request timed out. Check the endpoint or model loading, then retry."
    if isinstance(exc, httpx.RequestError):
        return (
            "error",
            "The sensor could not connect securely to the AI endpoint. Check its address, TLS certificate, and network access.",
        )
    return (
        "error",
        "The endpoint returned incompatible or oversized data. Try a chat model that can return the required JSON.",
    )


async def _run(request: Request, config: dict, discovery: bool) -> dict:
    # This is a control-plane limit, not a restriction on decoy services.
    now = time.monotonic()
    attempts = [t for t in getattr(request.app.state, "ai_probe_attempts", []) if now - t < 60]
    if len(attempts) >= 6:
        raise HTTPException(429, "Too many AI checks. Wait a minute before retrying.")
    if getattr(request.app.state, "ai_probe_busy", False):
        raise HTTPException(409, "Another AI check is in progress. Try again shortly.")
    request.app.state.ai_probe_attempts = [*attempts, now]
    request.app.state.ai_probe_busy = True
    checks = {"classification": False, "naming": False}
    try:
        snapshot = deepcopy(config.get("classifier", {}))
        snapshot_config = {"classifier": snapshot}
        try:
            _settings(snapshot_config, require_model=not discovery)
        except ValueError as exc:
            # Only our fixed configuration messages, not upstream exceptions.
            return {
                "status": "error",
                "message": str(exc),
                "models": [],
                "checks": checks,
                "elapsed_ms": 0,
            }
        try:
            async with asyncio.timeout(PROBE_DEADLINE), make_client() as client:
                result = (
                    await discover(snapshot_config, client)
                    if discovery
                    else await test_model(snapshot_config, client, checks)
                )
        except (
            httpx.HTTPError,
            httpx.InvalidURL,
            TimeoutError,
            ValueError,
            KeyError,
            TypeError,
            IndexError,
        ) as exc:
            status, message = _failure(exc, discovery)
            result = {"status": status, "message": message}
        if snapshot != config.get("classifier", {}):
            result = {
                "status": "error",
                "message": "AI settings changed during this check. Test the current settings again.",
            }
        return {
            "models": [],
            **result,
            "checks": checks,
            "elapsed_ms": int((time.monotonic() - now) * 1000),
        }
    finally:
        request.app.state.ai_probe_busy = False


@router.post("/models")
async def list_models(
    request: Request, config: dict = Depends(get_config), _auth: dict = Depends(verify_client_cert)
) -> dict:
    return await _run(request, config, True)


@router.post("/test")
async def validate_model(
    request: Request, config: dict = Depends(get_config), _auth: dict = Depends(verify_client_cert)
) -> dict:
    return await _run(request, config, False)
