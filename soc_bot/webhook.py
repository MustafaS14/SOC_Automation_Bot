"""Splunk alert webhook: verify, validate, store, then hand the incident to the Discord layer."""

from __future__ import annotations

import hmac
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

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


def _link(value: Any, expected_host: str | None) -> str | None:
    """Accept a plain http(s) URL, and when the Splunk host is known only one on that host."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url or len(url) > 500 or any(c.isspace() or not c.isprintable() for c in url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return None
    if expected_host and parts.hostname.lower() != expected_host.lower():
        return None
    return url


def parse_alert(payload: Any, link_host: str | None = None) -> dict[str, Any]:
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

    return {
        "rule": rule,
        "severity": _severity(result.get("severity")),
        "host": host,
        "src_ip": src_ip,
        "description": _text(result.get("_raw") or result.get("description"), 1000) or "",
        "url": _link(payload.get("results_link"), link_host),
    }


class RateLimiter:
    """Sliding-window limit on requests per period."""

    def __init__(self, limit: int, period: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self._limit = limit
        self._period = period
        self._clock = clock
        self._hits: deque[float] = deque()

    def allow(self) -> bool:
        now = self._clock()
        while self._hits and now - self._hits[0] >= self._period:
            self._hits.popleft()
        if len(self._hits) >= self._limit:
            return False
        self._hits.append(now)
        return True


def create_app(
    store: IncidentStore,
    secret: str,
    on_incident: Callable[[Incident], Awaitable[None]],
    *,
    max_per_minute: int = 30,
    link_host: str | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> web.Application:
    if not secret.strip():
        # compare_digest(b"", b"") is True, so an empty secret would accept anyone.
        raise ValueError("The webhook secret must not be empty.")
    if max_per_minute < 1:
        raise ValueError("max_per_minute must be at least 1.")
    limiter = RateLimiter(max_per_minute, clock=clock)

    async def splunk_alert(request: web.Request) -> web.Response:
        supplied = request.headers.get("X-Webhook-Secret", "")
        if not hmac.compare_digest(supplied.encode(), secret.encode()):
            return web.json_response({"error": "unauthorized"}, status=401)
        # Only authenticated calls count, so strangers cannot lock Splunk out.
        if not limiter.allow():
            return web.json_response({"error": "rate limit exceeded"}, status=429, headers={"Retry-After": "60"})
        try:
            fields = parse_alert(await request.json(), link_host)
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
