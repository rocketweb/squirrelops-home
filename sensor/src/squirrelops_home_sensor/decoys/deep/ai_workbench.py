"""Live OpenAI-compatible, Ollama, and MCP deep-decoy service."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from datetime import UTC, datetime
from typing import Any

from aiohttp import web

from squirrelops_home_sensor.decoys.deep.agent_protocols import (
    AgentRequest,
    build_agent_response,
)
from squirrelops_home_sensor.decoys.deep.campaign_store import NarrativeStore
from squirrelops_home_sensor.decoys.deep.narrative import InteractionEvidence
from squirrelops_home_sensor.decoys.deep.persona import build_studio_mini_persona
from squirrelops_home_sensor.decoys.types.base import BaseDecoy, DecoyConnectionEvent

logger = logging.getLogger(__name__)

_MAX_REQUEST_BYTES = 64 * 1024
_REQUEST_BODY_TIMEOUT_SECONDS = 5.0


def _interaction_type(path: str, payload: Any) -> str:
    normalized = path.partition("?")[0]
    static = {
        "/v1/models": "openai.models.list",
        "/v1/chat/completions": "openai.chat.completions",
        "/api/tags": "ollama.models.list",
        "/api/show": "ollama.model.show",
        "/api/chat": "ollama.chat",
        "/": "ollama.version",
        "/api/version": "ollama.version",
    }
    if normalized != "/mcp":
        return static.get(normalized, "http.unknown")
    if not isinstance(payload, dict):
        return "mcp.invalid"
    method = str(payload.get("method") or "unknown")[:128]
    if method == "tools/call":
        params = payload.get("params")
        if isinstance(params, dict):
            tool_name = str(params.get("name") or "unknown")[:128]
            return f"mcp.tools.call.{tool_name}"
    return f"mcp.{method.replace('/', '.')}"


class AIWorkbenchDecoy(BaseDecoy):
    """Serve agent-native bait and persist one narrative per source."""

    def __init__(
        self,
        *,
        decoy_id: int,
        name: str,
        port: int,
        bind_address: str,
        db: Any,
        deployment_secret: bytes,
        persona_created_at: datetime,
        advertised_port: int | None = None,
        surface: str = "combined",
        campaign_store: NarrativeStore | None = None,
    ) -> None:
        super().__init__(
            decoy_id=decoy_id,
            name=name,
            port=port,
            bind_address=bind_address,
            decoy_type="ai_workbench",
        )
        self._persona = build_studio_mini_persona(
            deployment_secret,
            persona_created_at,
        )
        self._campaigns = campaign_store or NarrativeStore(db)
        if surface not in {"combined", "openai", "ollama", "mcp"}:
            raise ValueError("AI workbench surface is not reviewed")
        self._surface = surface
        self._advertised_port = port if advertised_port is None else advertised_port
        if not 0 <= self._advertised_port <= 65535:
            raise ValueError("AI workbench advertised port is invalid")
        self._runner: web.AppRunner | None = None
        self._site: web.SockSite | None = None
        self._socket: socket.socket | None = None
        self._running = False

    @property
    def persona(self):
        return self._persona

    async def _read_body(self, request: web.Request) -> bytes:
        try:
            async with asyncio.timeout(_REQUEST_BODY_TIMEOUT_SECONDS):
                body = await request.read()
        except TimeoutError as exc:
            raise web.HTTPRequestTimeout() from exc
        if len(body) > _MAX_REQUEST_BYTES:
            raise web.HTTPRequestEntityTooLarge(
                max_size=_MAX_REQUEST_BYTES,
                actual_size=len(body),
            )
        return body

    @staticmethod
    def _decode_json(body: bytes) -> Any:
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON body") from exc

    def _submitted_credential(self, request: web.Request, body_text: str) -> str | None:
        authorization = request.headers.get("Authorization", "")[:8192]
        for credential in (
            self._persona.openai_api_key,
            self._persona.source_token,
            self._persona.login_password,
        ):
            if credential in authorization or credential in body_text:
                return credential
        return None

    async def _handle(self, request: web.Request) -> web.Response:
        body = await self._read_body(request)
        body_text = body.decode("utf-8", errors="replace")[:8192]
        payload: Any = None
        malformed_json = False
        if body:
            try:
                payload = self._decode_json(body)
            except ValueError:
                malformed_json = True

        peer = request.transport.get_extra_info("peername") if request.transport else None
        source_ip = str(peer[0]) if peer else "0.0.0.0"
        source_port = int(peer[1]) if peer and len(peer) > 1 else 0
        path = request.path_qs[:2048]
        interaction_type = _interaction_type(path, payload)
        campaign = await self._campaigns.observe(
            decoy_id=self.decoy_id,
            source_ip=source_ip,
            persona_id=self._persona.persona_id,
            evidence=InteractionEvidence(
                method=request.method,
                path=path,
                user_agent=request.headers.get("User-Agent", ""),
                body=body_text,
            ),
        )
        credential_used = self._submitted_credential(request, body_text)
        self._notify_connection(
            DecoyConnectionEvent(
                source_ip=source_ip,
                source_port=source_port,
                dest_port=self._advertised_port,
                protocol="tcp",
                timestamp=datetime.now(UTC),
                request_path=path,
                credential_used=credential_used,
                intruder_intent=campaign.intent.value,
                narrative_stage=int(campaign.stage),
                interaction_type=interaction_type,
            )
        )

        if malformed_json:
            response_body = b'{"error":"invalid JSON body"}'
            return web.Response(
                body=response_body,
                status=400,
                content_type="application/json",
                headers={"Server": self._server_header},
            )

        normalized_path = request.path
        allowed_paths = {
            "openai": {"/v1/models", "/v1/chat/completions"},
            "ollama": {"/", "/api/version", "/api/tags", "/api/show", "/api/chat"},
            "mcp": {"/mcp"},
        }
        if self._surface != "combined" and normalized_path not in allowed_paths[self._surface]:
            return web.Response(
                body=b'{"error":"not found"}',
                status=404,
                content_type="application/json",
                headers={"Server": self._server_header},
            )

        response = build_agent_response(
            self._persona,
            campaign,
            AgentRequest(
                method=request.method,
                path=path,
                json_body=payload,
            ),
        )
        return web.Response(
            body=response.body,
            status=response.status,
            content_type=response.content_type,
            headers={"Server": self._server_header},
        )

    @property
    def _server_header(self) -> str:
        return "Ollama" if self._surface in {"combined", "ollama"} else "uvicorn"

    async def start(self) -> None:
        if self._running:
            raise RuntimeError("AI workbench decoy is already running")
        application = web.Application(client_max_size=_MAX_REQUEST_BYTES)
        application.router.add_route("*", "/{path_info:.*}", self._handle)
        runner = web.AppRunner(
            application,
            access_log=None,
            handler_cancellation=True,
            max_line_size=8190,
            max_field_size=8190,
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.bind_address, self.port))
            listener.listen(128)
            listener.setblocking(False)
            self.port = int(listener.getsockname()[1])
            await runner.setup()
            site = web.SockSite(runner, listener)
            await site.start()
        except BaseException:
            listener.close()
            await runner.cleanup()
            raise

        self._runner = runner
        self._site = site
        self._socket = listener
        self._running = True
        logger.info(
            "AI workbench decoy '%s' started on %s:%d",
            self.name,
            self.bind_address,
            self.port,
        )

    async def stop(self) -> None:
        runner = self._runner
        listener = self._socket
        self._runner = None
        self._site = None
        self._socket = None
        self._running = False
        if runner is not None:
            await runner.cleanup()
        if listener is not None:
            try:
                listener.close()
            except OSError:
                logger.debug("AI workbench listener cleanup failed", exc_info=True)
        logger.info("AI workbench decoy '%s' stopped", self.name)

    async def health_check(self) -> bool:
        return (
            self._running
            and self._runner is not None
            and self._site is not None
            and self._socket is not None
            and self._socket.fileno() >= 0
        )

    @property
    def is_running(self) -> bool:
        return self._running
