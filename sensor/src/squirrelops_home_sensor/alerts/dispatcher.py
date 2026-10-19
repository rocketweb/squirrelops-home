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

import hashlib
import hmac
import json
import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic, time
from typing import Any, Protocol
from urllib.parse import urlsplit

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


@dataclass
class _DeliveryFailureState:
    consecutive_failures: int = 0
    retry_after: float = 0.0


class AlertDeliveryError(RuntimeError):
    """A credential-safe notification delivery failure."""


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

    def __init__(
        self,
        methods: list[dict[str, Any]],
        *,
        failure_backoff_base: float = 30.0,
        failure_backoff_max: float = 900.0,
        renotify_cooldown: float = 300.0,
        max_tracked_alerts: int = 4096,
    ) -> None:
        self._methods = [MethodConfig(m) for m in methods]
        self._failure_states: dict[str, _DeliveryFailureState] = {}
        self._failure_backoff_base = failure_backoff_base
        self._failure_backoff_max = failure_backoff_max
        self._clock: Callable[[], float] = monotonic
        # alert id -> ((severity, title), time of last re-notification or None)
        if max_tracked_alerts < 1:
            raise ValueError("max_tracked_alerts must be positive")
        self._notified_summaries: OrderedDict[
            Any, tuple[tuple[str, str], float | None]
        ] = OrderedDict()
        self._renotify_cooldown = renotify_cooldown
        self._max_tracked_alerts = max_tracked_alerts

    def subscribe_to(self, event_bus: EventBusProtocol) -> None:
        """Subscribe to new alerts and to material changes to open ones."""
        event_bus.subscribe(["alert.new"], self._on_alert_event)
        event_bus.subscribe(["alert.updated"], self._on_alert_updated)

    async def _on_alert_updated(
        self,
        event: dict[str, Any] | str,
        payload: AlertPayload | None = None,
        *args: Any,
    ) -> None:
        """Deliver an updated alert only when what the user would read changed.

        A decoy-trip alert folds every repeat connection from one source into a
        single open row, so a scan burst can update the same alert hundreds of
        times. Delivering each update would be worse than the silence it
        replaces, so an update is only notified when its visible summary
        changes, meaning severity or title, and at most once per cooldown.

        Severity and title are the right signal because they are what the alert
        row shows: the title promotes to "Port scan detected from X" the moment
        a second endpoint is touched, which is the moment the character of the
        event actually changed.
        """
        payload = self._payload_of(event, payload)
        if payload is None:
            return

        # ``alert.updated`` is also used for lifecycle bookkeeping. A resolved,
        # dismissed, or otherwise actioned alert is no longer notification
        # eligible even if its retained severity and title happen to change.
        # Producers include these timestamps in the event snapshot, so filter
        # before the summary/cooldown logic can turn closure into a new page.
        detail = payload.get("detail")
        if (
            payload.get("read_at")
            or payload.get("actioned_at")
            or (isinstance(detail, dict) and detail.get("resolved_at"))
        ):
            alert_id = payload.get("id")
            if alert_id is not None:
                # A lifecycle timestamp ends this notification episode. If the
                # same row is later reactivated, its unchanged summary is fresh
                # signal and must be eligible for delivery again.
                self._notified_summaries.pop(alert_id, None)
            return

        alert_id = payload.get("id")
        summary = (str(payload.get("severity", "")), str(payload.get("title", "")))
        now = self._clock()

        if alert_id is not None:
            previous = self._notified_summaries.get(alert_id)
            if previous is not None:
                last_summary, last_renotified_at = previous
                if summary == last_summary:
                    return
                # The cooldown governs the gap between re-notifications, not
                # the gap from the original alert. last_renotified_at is None
                # until this alert has been re-notified once, so the first
                # material change (usually the title promoting to a port scan)
                # is never held back.
                if (
                    last_renotified_at is not None
                    and now - last_renotified_at < self._renotify_cooldown
                ):
                    # Too soon. Leave the baseline alone so this change is still
                    # pending and gets delivered once the cooldown expires.
                    return

        await self.dispatch(payload, event_type="alert.updated")

        # After dispatch, not before: dispatch records the delivered summary
        # with no re-notification time, and this is the write that starts the
        # cooldown for the next material change.
        if alert_id is not None:
            self._remember_summary(alert_id, summary, now)

    def record_delivered_summary(self, alert_payload: AlertPayload) -> None:
        """Seed the summary an alert was last notified with."""
        alert_id = alert_payload.get("id")
        if alert_id is None:
            return
        self._remember_summary(
            alert_id,
            (
                str(alert_payload.get("severity", "")),
                str(alert_payload.get("title", "")),
            ),
            None,
        )

    def _remember_summary(
        self,
        alert_id: Any,
        summary: tuple[str, str],
        renotified_at: float | None,
    ) -> None:
        """Record a bounded, least-recently-updated notification baseline."""
        self._notified_summaries.pop(alert_id, None)
        self._notified_summaries[alert_id] = (summary, renotified_at)
        while len(self._notified_summaries) > self._max_tracked_alerts:
            self._notified_summaries.popitem(last=False)

    @staticmethod
    def _payload_of(
        event: dict[str, Any] | str,
        payload: AlertPayload | None,
    ) -> AlertPayload | None:
        if payload is not None:
            return payload
        if isinstance(event, dict) and isinstance(event.get("payload"), dict):
            return event["payload"]
        if isinstance(event, dict):
            return event
        return None

    async def _on_alert_event(
        self,
        event: dict[str, Any] | str,
        payload: AlertPayload | None = None,
        *args: Any,
    ) -> None:
        """Event bus callback -- dispatches the alert payload.

        The production EventBus calls subscribers with one event dict, while
        older tests and lightweight stubs call ``callback(event_type, payload)``.
        Accept both shapes so dispatch is not silently disconnected.
        """
        if payload is None:
            if isinstance(event, dict) and isinstance(event.get("payload"), dict):
                payload = event["payload"]
            elif isinstance(event, dict):
                payload = event
        if payload is None:
            logger.warning("Alert dispatcher received event without payload: %r", event)
            return
        await self.dispatch(payload, event_type="alert.new")

    async def dispatch(
        self,
        alert_payload: AlertPayload,
        *,
        event_type: str = "alert.new",
    ) -> None:
        """Send the alert to all methods whose severity threshold is met.

        If a method handler raises an exception, the error is logged but
        dispatch continues to remaining methods (best-effort fan-out).
        Handlers receive a copy carrying ``event_type`` so an outbound
        contract can say whether this is a new alert or a material change.
        """
        severity = Severity(alert_payload["severity"])
        self.record_delivered_summary(alert_payload)
        alert_payload = {**alert_payload, "event_type": event_type}

        for method in self._methods:
            if not method.accepts(severity):
                continue

            state = self._failure_states.setdefault(
                method.name, _DeliveryFailureState()
            )
            now = self._clock()
            if now < state.retry_after:
                continue

            try:
                await method.handler(alert_payload)
            except Exception as exc:
                state.consecutive_failures += 1
                delay = min(
                    self._failure_backoff_base
                    * (2 ** (state.consecutive_failures - 1)),
                    self._failure_backoff_max,
                )
                state.retry_after = now + delay
                # Do not interpolate exception text or retain a traceback here.
                # HTTP client exceptions commonly embed credential-bearing URLs.
                logger.error(
                    "Alert dispatch failed for method %s (alert_id=%s, error=%s); "
                    "retrying after %.0fs",
                    method.name,
                    alert_payload.get("alert_id"),
                    type(exc).__name__,
                    delay,
                )
            else:
                state.consecutive_failures = 0
                state.retry_after = 0.0


def build_methods_from_config(
    config: dict[str, Any],
    *,
    sensor_id: str | None = None,
    sensor_version: str | None = None,
) -> list[dict[str, Any]]:
    """Build alert delivery methods from the live sensor config."""
    methods: list[dict[str, Any]] = [
        {"name": "log", "handler": create_log_handler(), "min_severity": "low"},
    ]
    alert_methods = config.get("alert_methods", {})
    if not isinstance(alert_methods, dict):
        return methods

    slack_cfg = alert_methods.get("slack", {})
    if isinstance(slack_cfg, dict) and slack_cfg.get("enabled"):
        webhook_url = str(slack_cfg.get("webhook_url", "")).strip()
        if webhook_url:
            methods.append({
                "name": "slack",
                "handler": create_slack_handler(
                    webhook_url,
                    include_device_info=bool(slack_cfg.get("include_device_info", False)),
                ),
                "min_severity": slack_cfg.get("min_severity", "low"),
            })
        else:
            logger.warning("Slack alert method enabled without webhook_url; skipping")

    push_cfg = alert_methods.get("push", alert_methods.get("apns", {}))
    if isinstance(push_cfg, dict) and push_cfg.get("enabled"):
        methods.append({
            "name": "apns",
            "handler": create_apns_handler(
                str(push_cfg.get("relay_url", config.get("apns_relay_url", ""))).strip(),
                relay_token=str(push_cfg.get("relay_token", config.get("apns_relay_token", ""))),
                device_token=str(push_cfg.get("device_token", "")),
            ),
            "min_severity": push_cfg.get("min_severity", "low"),
        })

    # The response contract: one documented JSON event per alert, for the
    # operator's own automation (router block, HA automation, SIEM).
    webhook_cfg = alert_methods.get("webhook", {})
    if isinstance(webhook_cfg, dict) and webhook_cfg.get("enabled"):
        webhook_url = str(webhook_cfg.get("webhook_url", "")).strip()
        if _is_http_url(webhook_url):
            methods.append({
                "name": "webhook",
                "handler": create_webhook_handler(
                    webhook_url,
                    signing_secret=str(webhook_cfg.get("signing_secret", "") or ""),
                    # Device identifiers are the point of this method: a MAC is
                    # what a controller blocks on. Still operator-controlled.
                    include_device_info=bool(webhook_cfg.get("include_device_info", True)),
                    sensor_id=sensor_id,
                    sensor_version=sensor_version,
                ),
                "min_severity": webhook_cfg.get("min_severity", "low"),
            })
        else:
            logger.warning("Webhook alert method enabled without an http(s) webhook_url; skipping")

    ha_method = alert_methods.get("home_assistant", {})
    ha_cfg = config.get("home_assistant", {})
    if isinstance(ha_method, dict) and ha_method.get("enabled"):
        ha_url = str(ha_cfg.get("url", "")).strip() if isinstance(ha_cfg, dict) else ""
        ha_token = str(ha_cfg.get("token", "")) if isinstance(ha_cfg, dict) else ""
        if isinstance(ha_cfg, dict) and ha_cfg.get("enabled") and ha_url and ha_token:
            methods.append({
                "name": "home_assistant",
                "handler": create_home_assistant_event_handler(
                    ha_url,
                    ha_token,
                    include_device_info=bool(ha_method.get("include_device_info", True)),
                    sensor_id=sensor_id,
                    sensor_version=sensor_version,
                ),
                "min_severity": ha_method.get("min_severity", "low"),
            })
        else:
            logger.warning(
                "Home Assistant alert method enabled without a configured, enabled "
                "Home Assistant integration; skipping"
            )

    return methods


def _is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


class ConfigurableAlertDispatcher(AlertDispatcher):
    """Alert dispatcher that resolves delivery methods from live config."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        sensor_id: str | None = None,
        sensor_version: str | None = None,
    ) -> None:
        self._config = config
        self._sensor_id = sensor_id
        self._sensor_version = sensor_version
        super().__init__(methods=[])

    async def dispatch(
        self,
        alert_payload: AlertPayload,
        *,
        event_type: str = "alert.new",
    ) -> None:
        self._methods = [
            MethodConfig(m)
            for m in build_methods_from_config(
                self._config,
                sensor_id=self._sensor_id,
                sensor_version=self._sensor_version,
            )
        ]
        await super().dispatch(alert_payload, event_type=event_type)


# -- Response contract ------------------------------------------------
#
# The outbound event an operator automates against. Its shape is the
# contract: fields are added only with a schema bump, and nothing internal
# (event sequence numbers, read markers, detail blobs) ever rides along.

RESPONSE_EVENT_SCHEMA = "squirrelops.alert/1"

_TITLE_LIMIT = 256
_SUMMARY_LIMIT = 512
_NAME_LIMIT = 128


def _bounded_str(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value[:limit]


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def format_response_event(
    alert_payload: AlertPayload,
    *,
    include_device_info: bool,
    sensor_id: str | None = None,
    sensor_version: str | None = None,
) -> dict[str, Any]:
    """Render an alert as the documented ``squirrelops.alert/1`` event."""
    source: dict[str, Any] = {"ip": _bounded_str(alert_payload.get("source_ip"), 64)}
    if include_device_info:
        mac = _bounded_str(alert_payload.get("source_mac"), 32)
        if mac:
            source["mac"] = mac
        device_id = _int_or_none(alert_payload.get("device_id"))
        if device_id is not None:
            source["device_id"] = device_id

    decoy: dict[str, Any] | None = None
    decoy_id = _int_or_none(alert_payload.get("decoy_id"))
    decoy_name = _bounded_str(alert_payload.get("decoy_name"), _NAME_LIMIT)
    dest_port = _int_or_none(alert_payload.get("dest_port"))
    if decoy_id is not None or decoy_name or dest_port is not None:
        decoy = {
            "id": decoy_id,
            "name": decoy_name,
            "port": dest_port,
            "protocol": _bounded_str(alert_payload.get("protocol"), 16),
        }

    campaign: dict[str, Any] | None = None
    intent = _bounded_str(alert_payload.get("intruder_intent"), 32)
    stage = _int_or_none(alert_payload.get("narrative_stage"))
    if intent or stage is not None:
        campaign = {
            "intent": intent,
            "stage": stage,
            "stage_label": _STAGE_LABELS.get(stage) if stage is not None else None,
        }

    event_type = alert_payload.get("event_type")
    return {
        "schema": RESPONSE_EVENT_SCHEMA,
        "event": event_type if event_type in ("alert.new", "alert.updated") else "alert.new",
        "sent_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensor": {"id": sensor_id, "version": sensor_version},
        "alert": {
            "id": _int_or_none(alert_payload.get("id")),
            "type": _bounded_str(alert_payload.get("alert_type"), 64),
            "severity": _bounded_str(alert_payload.get("severity"), 16),
            "title": _bounded_str(alert_payload.get("title"), _TITLE_LIMIT),
            "summary": _bounded_str(_outbound_detail(alert_payload), _SUMMARY_LIMIT),
            "created_at": _bounded_str(alert_payload.get("created_at"), 64),
        },
        "source": source,
        "decoy": decoy,
        "campaign": campaign,
    }


def encode_response_event(event: dict[str, Any]) -> bytes:
    """Canonical bytes: compact, sorted keys, so a receiver can re-sign them."""
    return json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_response_event(body: bytes, *, secret: str, timestamp: int) -> str:
    """``t=<unix>,v1=<hex HMAC-SHA256(secret, "<unix>." + body)>``.

    The timestamp is inside the signed material so a captured event cannot
    be replayed later without the receiver noticing the age.
    """
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def create_webhook_handler(
    webhook_url: str,
    *,
    signing_secret: str = "",
    include_device_info: bool = True,
    sensor_id: str | None = None,
    sensor_version: str | None = None,
    session_factory: Callable | None = None,
    clock: Callable[[], float] = time,
) -> AlertHandler:
    """POST the response event to the operator's own endpoint."""

    async def _handler(alert_payload: AlertPayload) -> None:
        event = format_response_event(
            alert_payload,
            include_device_info=include_device_info,
            sensor_id=sensor_id,
            sensor_version=sensor_version,
        )
        body = encode_response_event(event)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"squirrelops-home-sensor/{sensor_version or 'unknown'}",
            "X-SquirrelOps-Schema": RESPONSE_EVENT_SCHEMA,
            "X-SquirrelOps-Event": event["event"],
        }
        if signing_secret:
            headers["X-SquirrelOps-Signature"] = sign_response_event(
                body, secret=signing_secret, timestamp=int(clock())
            )

        post_kwargs: dict[str, object] = {"data": body, "headers": headers}
        if session_factory is not None:
            session = session_factory()
        else:
            import aiohttp

            session = aiohttp.ClientSession()
            post_kwargs["timeout"] = aiohttp.ClientTimeout(total=10)

        try:
            async with session:
                resp = await session.post(webhook_url, **post_kwargs)  # type: ignore[arg-type]
                status = int(getattr(resp, "status", 0))
                if not 200 <= status < 300:
                    raise AlertDeliveryError(f"Webhook returned HTTP {status}")
        except AlertDeliveryError:
            raise
        except Exception as exc:
            # Client exceptions embed the URL, which may carry a token.
            raise AlertDeliveryError(
                f"Webhook request failed ({type(exc).__name__})"
            ) from None

    return _handler


def create_home_assistant_event_handler(
    ha_url: str,
    ha_token: str,
    *,
    include_device_info: bool = True,
    sensor_id: str | None = None,
    sensor_version: str | None = None,
    client_factory: Callable | None = None,
) -> AlertHandler:
    """Fire the same response event as a ``squirrelops_alert`` HA event."""

    async def _handler(alert_payload: AlertPayload) -> None:
        event = format_response_event(
            alert_payload,
            include_device_info=include_device_info,
            sensor_id=sensor_id,
            sensor_version=sensor_version,
        )
        if client_factory is not None:
            client = client_factory()
        else:
            from squirrelops_home_sensor.integrations.home_assistant import HomeAssistantClient

            client = HomeAssistantClient(ha_url, ha_token)
        try:
            delivered = await client.fire_event(HOME_ASSISTANT_EVENT_TYPE, event)
        except Exception as exc:
            raise AlertDeliveryError(
                f"Home Assistant event request failed ({type(exc).__name__})"
            ) from None
        if not delivered:
            raise AlertDeliveryError("Home Assistant did not accept the event")

    return _handler


HOME_ASSISTANT_EVENT_TYPE = "squirrelops_alert"


# -- Slack payload formatter -----------------------------------------

_STAGE_LABELS = {
    0: "discovery",
    1: "browsing",
    2: "credential access",
    3: "agent tool use",
    4: "write activity",
}


def _outbound_detail(alert_payload: AlertPayload) -> str:
    """The one line an outbound channel shows under the title.

    Producers that carry structured detail send a ``summary`` string
    alongside it. The dict is for the row and the app; rendered here it would
    reach an operator as a Python repr, so it is never used as text.
    """
    summary = alert_payload.get("summary")
    if isinstance(summary, str) and summary:
        return summary[:512]
    detail = alert_payload.get("detail")
    if isinstance(detail, str):
        return detail[:512]
    return ""


def format_slack_payload(
    alert_payload: AlertPayload,
    *,
    include_device_info: bool = False,
) -> dict[str, Any]:
    """Build a Slack Block Kit message from an alert payload.

    Returns a dict suitable for POST-ing to a Slack webhook URL.
    """
    severity_str = alert_payload["severity"]
    severity = Severity(severity_str)
    emoji = severity_emoji(severity)
    title = alert_payload["title"]
    detail = _outbound_detail(alert_payload)
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

    # Campaign context from the deep decoys, when the producer supplied it.
    intent = alert_payload.get("intruder_intent")
    stage = alert_payload.get("narrative_stage")
    context_fields: list[dict[str, Any]] = []
    if isinstance(intent, str) and intent:
        context_fields.append(
            {"type": "mrkdwn", "text": f"*Intent:* {intent.replace('_', ' ')[:32]}"}
        )
    if isinstance(stage, int) and not isinstance(stage, bool) and stage in _STAGE_LABELS:
        context_fields.append({"type": "mrkdwn", "text": f"*Stage:* {_STAGE_LABELS[stage]}"})
    if context_fields:
        blocks.append({"type": "section", "fields": context_fields})

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

        try:
            async with session:
                if session_factory is None:
                    import aiohttp

                    resp = await session.post(
                        webhook_url,
                        json=slack_msg,
                        timeout=aiohttp.ClientTimeout(total=10),
                    )
                else:
                    resp = await session.post(webhook_url, json=slack_msg)
                status = int(getattr(resp, "status", 0))
                if not 200 <= status < 300:
                    raise AlertDeliveryError(
                        f"Slack webhook returned HTTP {status}"
                    )
        except AlertDeliveryError:
            raise
        except Exception as exc:
            # aiohttp exceptions include the full request URL in their string
            # representation. Replace them before the dispatcher logs anything.
            raise AlertDeliveryError(
                f"Slack webhook request failed ({type(exc).__name__})"
            ) from None

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
            "body": _outbound_detail(alert_payload),
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
