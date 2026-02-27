"""Alert dispatcher -- fans out alerts to configured delivery methods.

Each method is an async callable that receives an alert payload dict.
Methods can have a minimum severity threshold so that low-priority
alerts only go to the log, while critical alerts go everywhere.

Built-in method factories:
  - ``create_slack_handler(webhook_url)`` -- POST to Slack webhook
  - ``create_log_handler(logger_name)`` -- structured JSON to Python logger
  - ``create_apns_handler(relay_url, ...)`` -- push via APNs relay
  - ``create_apns_stub_handler()`` -- no-op placeholder (kept for compat)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable, Protocol

from squirrelops_home_sensor.alerts.types import Severity, severity_emoji


logger = logging.getLogger(__name__)


# -- Type aliases ----------------------------------------------------

AlertPayload = dict[str, Any]
AlertHandler = Callable[[AlertPayload], Awaitable[None]]


class EventBusProtocol(Protocol):
    def subscribe(self, event_types: list[str], callback: Any) -> None: ...


# -- Method configuration --------------------------------------------

class MethodConfig:
    """Wraps a method configuration dict for convenience."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.name: str = config["name"]
        self.handler: AlertHandler = config["handler"]
        self.min_severity: Severity = Severity(config.get("min_severity", "low"))

    def accepts(self, severity: Severity) -> bool:
        """Return True if this method should receive alerts at the given
        severity level."""
        return severity >= self.min_severity


# -- Alert Dispatcher ------------------------------------------------

class AlertDispatcher:
    """Fans out alert payloads to all configured delivery methods.

    Parameters
    ----------
    methods:
        List of method config dicts, each with keys:
        - ``name``: human label (e.g. "slack", "log")
        - ``handler``: async callable(alert_payload)
        - ``min_severity``: minimum severity string (default "low")
    """

    def __init__(self, methods: list[dict[str, Any]]) -> None:
        self._methods = [MethodConfig(m) for m in methods]

    def subscribe_to(self, event_bus: EventBusProtocol) -> None:
        """Subscribe to ``alert.new`` events on the given event bus."""
        event_bus.subscribe(["alert.new"], self._on_alert_event)

    async def _on_alert_event(
        self, event_type: str, payload: AlertPayload, *args: Any
    ) -> None:
        """Event bus callback -- dispatches the alert payload."""
        await self.dispatch(payload)

    async def dispatch(self, alert_payload: AlertPayload) -> None:
        """Send the alert to all methods whose severity threshold is met.

        If a method handler raises an exception, the error is logged but
        dispatch continues to remaining methods (best-effort fan-out).
        """
        severity = Severity(alert_payload["severity"])

        for method in self._methods:
            if not method.accepts(severity):
                continue

            try:
                await method.handler(alert_payload)
            except Exception:
                logger.exception(
                    "Alert dispatch failed for method %s (alert_id=%s)",
                    method.name,
                    alert_payload.get("alert_id"),
                )


# -- Slack payload formatter -----------------------------------------

def format_slack_payload(alert_payload: AlertPayload, *, include_device_info: bool = False) -> dict[str, Any]:
    """Build a Slack Block Kit message from an alert payload.

    Returns a dict suitable for POST-ing to a Slack webhook URL.
    """
    severity_str = alert_payload["severity"]
    severity = Severity(severity_str)
    emoji = severity_emoji(severity)
    title = alert_payload["title"]
    detail = alert_payload.get("detail", "")
    source_ip = alert_payload.get("source_ip")
    created_at = alert_payload.get("created_at", "")
    alert_type = alert_payload.get("alert_type", "")

    # Fallback plain text (Slack API requirement)
    text = f"{emoji} [{severity_str.upper()}] {title}"

    # Rich blocks
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {title}",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:* {emoji} {severity_str.upper()}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Type:* `{alert_type}`",
                },
            ],
        },
    ]

    # Source IP field (if present)
    if source_ip:
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Source IP:* `{source_ip}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:* {created_at}",
                    },
                ],
            }
        )
    else:
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:* {created_at}",
                    },
                ],
            }
        )

    # Detail
    if detail:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_{detail}_",
                },
            }
        )

    # Device identifiers (only if opted in)
    if include_device_info:
        device_fields: list[dict[str, Any]] = []
        source_mac = alert_payload.get("source_mac")
        device_id = alert_payload.get("device_id")
        if source_mac:
            device_fields.append({"type": "mrkdwn", "text": f"*MAC:* `{source_mac}`"})
        if device_id:
            device_fields.append({"type": "mrkdwn", "text": f"*Device ID:* {device_id}"})
        if device_fields:
            blocks.append({"type": "section", "fields": device_fields})

    return {"text": text, "blocks": blocks}


# -- Built-in handler factories --------------------------------------

def create_slack_handler(
    webhook_url: str,
    *,
    include_device_info: bool = False,
    session_factory: Callable | None = None,
) -> AlertHandler:
    """Create an async handler that POSTs formatted alerts to a Slack
    webhook URL.

    Parameters
    ----------
    webhook_url:
        Full Slack incoming webhook URL.
    session_factory:
        Optional callable that returns an async HTTP session (for testing).
        Defaults to creating an ``aiohttp.ClientSession``.
    """

    async def _handler(alert_payload: AlertPayload) -> None:
        slack_msg = format_slack_payload(alert_payload, include_device_info=include_device_info)

        if session_factory is not None:
            session = session_factory()
        else:
            import aiohttp

            session = aiohttp.ClientSession()

        async with session:
            resp = await session.post(webhook_url, json=slack_msg)
            resp.raise_for_status()

    return _handler


def create_log_handler(
    logger_name: str = "squirrelops.alerts",
) -> AlertHandler:
    """Create an async handler that writes structured JSON to a Python logger.

    Every alert is logged at INFO level as a single JSON line containing
    the full alert payload.
    """
    log = logging.getLogger(logger_name)

    async def _handler(alert_payload: AlertPayload) -> None:
        log.info(json.dumps(alert_payload, default=str))

    return _handler


def create_apns_handler(
    relay_url: str,
    *,
    relay_token: str = "",
    device_token: str = "",
    session_factory: Callable | None = None,
) -> AlertHandler:
    """Create an async handler that sends push notifications via the APNs relay.

    Parameters
    ----------
    relay_url:
        Full URL of the APNs relay endpoint (e.g. a Vercel Edge Function).
    relay_token:
        Optional bearer token for authenticating with the relay.
    device_token:
        APNs device token for the target device.  If empty, the handler
        silently skips sending.
    session_factory:
        Optional callable that returns an async HTTP session (for testing).
        Defaults to creating an ``aiohttp.ClientSession``.
    """

    async def _handler(alert_payload: AlertPayload) -> None:
        if not relay_url or not device_token:
            logger.debug("APNs handler: missing relay_url or device_token, skipping")
            return

        push_body = {
            "device_token": device_token,
            "title": alert_payload.get("title", "SquirrelOps Alert"),
            "body": alert_payload.get("detail", ""),
            "category": alert_payload.get("alert_type", "ALERT"),
            "severity": alert_payload.get("severity", "low"),
        }

        timeout: object | None = None
        if session_factory is not None:
            session = session_factory()
        else:
            import aiohttp

            session = aiohttp.ClientSession()
            timeout = aiohttp.ClientTimeout(total=10)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if relay_token:
            headers["Authorization"] = f"Bearer {relay_token}"

        post_kwargs: dict[str, object] = {
            "json": push_body,
            "headers": headers,
        }
        if timeout is not None:
            post_kwargs["timeout"] = timeout

        try:
            async with session:
                resp = await session.post(relay_url, **post_kwargs)  # type: ignore[arg-type]
                if resp.status != 200:
                    logger.warning("APNs relay returned %d", resp.status)
        except Exception:
            logger.exception("APNs relay request failed")

    return _handler


def create_apns_stub_handler() -> AlertHandler:
    """Create a no-op APNs handler stub.

    This is a placeholder for future Apple Push Notification Service
    integration. It logs the alert at DEBUG level and returns.
    """

    async def _handler(alert_payload: AlertPayload) -> None:
        logger.debug(
            "APNs stub: would send push for alert_id=%s",
            alert_payload.get("alert_id"),
        )

    return _handler
