"""CSRF tokens, login throttling by address and response headers."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import deque

from flask import Flask, Response, abort, request, session

CSRF_KEY = "csrf"

CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


def csrf_token() -> str:
    token = session.get(CSRF_KEY)
    if not token:
        token = session[CSRF_KEY] = secrets.token_urlsafe(32)
    return token


def check_csrf() -> None:
    sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    expected = session.get(CSRF_KEY, "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(400, "The form expired or came from another site. Reload the page and try again.")


class Throttle:
    """At most `limit` hits per `period` seconds for each key (here: the client address)."""

    def __init__(self, limit: int, period: float, clock=time.monotonic):
        self._limit, self._period, self._clock = limit, period, clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self._period:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            if len(self._hits) > 5000:  # drop idle keys so a scan from many addresses cannot grow this forever
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= self._period]:
                    del self._hits[k]
            return True


def add_headers(app: Flask) -> None:
    @app.after_request
    def headers(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp
