"""Splunk alert webhook: verify, validate, store, then hand the incident to the Discord layer."""

from __future__ import annotations

import hmac
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiohttp import web

from .models import Incident
from .store import SEVERITIES, IncidentStore
from .validators import ValidationError, parse_hostname, parse_ip

log = logging.getLogger("soc_bot")

MAX_BODY_BYTES = 64 * 1024
_SEVERITY_ALIASES = {"info": "Informational", "informational": "Informational"}


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] or None


def _severity(value: Any) -> str:
    key = str(value or "").strip().lower()
    for severity in SEVERITIES:
        if key == severity.lower():
            return severity
    return _SEVERITY_ALIASES.get(key, "Medium")


def parse_alert(payload: Any) -> dict[str, Any]:
    """Turn a Splunk webhook body into incident fields. Splunk sends the first result row under `result`."""
    if not isinstance(payload, dict):
        raise ValidationError("Payload must be a JSON object.")
    rule = _text(payload.get("search_name"), 200)
    if not rule:
        raise ValidationError("`search_name` is required.")
    result = payload.get("result")
    if not isinstance(result, dict):
        result = {}

    host = src_ip = None
    if raw_host := _text(result.get("host"), 253):
        try:
            host = parse_hostname(raw_host)
        except ValidationError:
            host = None
    if raw_ip := _text(result.get("src_ip"), 64):
        try:
            src_ip = str(parse_ip(raw_ip))
        except ValidationError:
            src_ip = None

    url = _text(payload.get("results_link"), 500)
    if url and not url.startswith(("http://", "https://")):
        url = None
    return {
        "rule": rule,
        "severity": _severity(result.get("severity")),
        "host": host,
        "src_ip": src_ip,
        "description": _text(result.get("_raw") or result.get("description"), 1000) or "",
        "url": url,
    }


def create_app(
    store: IncidentStore,
    secret: str,
    on_incident: Callable[[Incident], Awaitable[None]],
) -> web.Application:
    async def splunk_alert(request: web.Request) -> web.Response:
        # Splunk's built-in webhook cannot set headers, so a query-string token is accepted too.
        supplied = request.headers.get("X-Webhook-Secret") or request.query.get("secret", "")
        if not hmac.compare_digest(supplied.encode(), secret.encode()):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            fields = parse_alert(await request.json())
        except (ValueError, ValidationError) as exc:
            return web.json_response({"error": str(exc) or "invalid JSON"}, status=400)
        incident = await store.create(**fields)
        try:
            await on_incident(incident)
        except Exception:
            # The alert is already stored; a Discord failure must not make Splunk retry.
            log.exception("Failed to post alert #%s", incident.id)
        return web.json_response({"id": incident.id}, status=201)

    app = web.Application(client_max_size=MAX_BODY_BYTES)
    app.router.add_post("/webhook/splunk", splunk_alert)
    return app
