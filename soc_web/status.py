"""The small status strip: is Splunk reachable, when did the last alert arrive.

Probing happens on the background loop and at most once per `ttl` seconds, and pages show the last known answer, so a
Splunk that is down or slow never makes a page wait.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

PROBE_TIMEOUT = 5.0


class StatusProbe:
    def __init__(self, backends: Any, *, ttl: float = 30.0, clock: Callable[[], float] = time.monotonic):
        self._b, self._ttl, self._clock = backends, ttl, clock
        self._checked: float | None = None
        self._running = False
        self.splunk = "off" if backends.splunk is None else "checking"
        self.last_alert: datetime | None = None

    async def _probe(self) -> None:
        try:
            if self._b.splunk is not None:
                try:
                    await asyncio.wait_for(self._b.splunk.search("| makeresults count=1", earliest="-1m"), PROBE_TIMEOUT)
                    self.splunk = "up"
                except Exception:
                    self.splunk = "down"
            newest = await self._b.store.list("all", None, 1)
            self.last_alert = newest[0].created if newest else None
        finally:
            self._running = False

    def snapshot(self) -> dict[str, Any]:
        """The last known state, starting a refresh in the background when it is older than the ttl."""
        now = self._clock()
        if not self._running and (self._checked is None or now - self._checked >= self._ttl):
            self._running, self._checked = True, now
            self._b.runner.spawn(self._probe())
        return {
            "mode": "mock" if self._b.settings.mock_mode else "live",
            "splunk": self.splunk,
            "ai": self._b.settings.ai_backend if self._b.assistant is not None else "off",
            "last_alert": self.last_alert,
        }
