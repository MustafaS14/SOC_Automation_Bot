"""Read-only incident API, registered on the webhook's aiohttp app when API_SECRET is set.

GET only: no route here can create, change or close anything. The secret is accepted in the X-Api-Secret header and
never in the URL. Free text goes through `redact()` on the way out, errors are generic, and the rate limit is the
webhook's own `RateLimiter` (a separate budget, so reading incidents cannot delay Splunk's alerts).
"""

from __future__ import annotations

import hmac
import logging
import time
from collections.abc import Callable
from typing import Any

from aiohttp import web

from .audit import redact
from .clients.base import NotFoundError
from .models import Comment, Incident
from .store import SEVERITIES, IncidentStore
from .store.incidents import _STATUS_SQL, ORDERS
from .webhook import RateLimiter

log = logging.getLogger("soc_bot")

STATUSES = tuple(_STATUS_SQL)
MAX_LIMIT = 50
MIN_SECRET_LENGTH = 32


def _iso(value: Any) -> str | None:
    return value.isoformat() if value else None


def _clean(value: str | None) -> str | None:
    return redact(value) if value else value


def comment_json(c: Comment) -> dict[str, Any]:
    return {"author": _clean(c.author), "body": redact(c.body), "created": _iso(c.created)}


def incident_json(inc: Incident, *, comments: bool = False) -> dict[str, Any]:
    """Only incident fields; nothing else from the database or the host is ever added."""
    data: dict[str, Any] = {
        "id": inc.id, "rule": _clean(inc.rule), "severity": inc.severity, "status": inc.status,
        "host": _clean(inc.host), "src_ip": inc.src_ip, "assignee": _clean(inc.assignee),
        "description": redact(inc.description), "url": inc.url, "classification": inc.classification,
        "created": _iso(inc.created), "updated": _iso(inc.updated),
    }
    if comments:
        data["comments"] = [comment_json(c) for c in inc.comments]
    return data


def _error(status: int, message: str, headers: dict[str, str] | None = None) -> web.Response:
    return web.json_response({"error": message}, status=status, headers=headers)


def register(
    app: web.Application,
    store: IncidentStore,
    secret: str,
    *,
    max_per_minute: int = 30,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    if len(secret.strip()) < MIN_SECRET_LENGTH:
        # An empty secret would accept anyone (compare_digest(b"", b"") is True), a short one is guessable.
        raise ValueError(f"The API secret must be at least {MIN_SECRET_LENGTH} characters.")
    limiter = RateLimiter(max_per_minute, clock=clock)

    def guard(handler: Callable[[web.Request], Any]):
        async def wrapper(request: web.Request) -> web.Response:
            supplied = request.headers.get("X-Api-Secret", "")
            if not hmac.compare_digest(supplied.encode(), secret.encode()):
                return _error(401, "unauthorized")
            if not limiter.allow():  # only authenticated calls count, so strangers cannot lock the console out
                return _error(429, "rate limit exceeded", {"Retry-After": "60"})
            try:
                return await handler(request)
            except web.HTTPException:
                raise
            except Exception:
                log.exception("Incident API failed on %s", request.path)  # the client only ever sees a generic error
                return _error(500, "internal error")

        return wrapper

    async def list_incidents(request: web.Request) -> web.Response:
        q = request.query
        status, severity, order = q.get("status", "open"), q.get("severity") or None, q.get("order", "newest")
        if status not in STATUSES:
            return _error(400, "status must be one of: " + ", ".join(STATUSES))
        if severity is not None and severity not in SEVERITIES:
            return _error(400, "severity must be one of: " + ", ".join(SEVERITIES))
        if order not in ORDERS:
            return _error(400, "order must be one of: " + ", ".join(ORDERS))
        try:
            limit = int(q.get("limit", "10"))
        except ValueError:
            return _error(400, "limit must be a whole number")
        rows = await store.list(status, severity, max(1, min(limit, MAX_LIMIT)), order)
        return web.json_response({"incidents": [incident_json(i) for i in rows]})

    async def counts(request: web.Request) -> web.Response:
        return web.json_response(await store.counts())

    async def one_incident(request: web.Request) -> web.Response:
        try:
            inc = await store.get(int(request.match_info["incident_id"]))
        except (ValueError, NotFoundError):
            return _error(404, "not found")
        return web.json_response(incident_json(inc, comments=True))

    # No add_post / add_put / add_delete anywhere: those methods answer 405.
    app.router.add_get("/api/incidents", guard(list_incidents))
    app.router.add_get("/api/incidents/{incident_id}", guard(one_incident))
    app.router.add_get("/api/counts", guard(counts))
