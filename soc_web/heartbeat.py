"""The heartbeat monitor: when did each host last send its five-minute heartbeat?

The victim writes `soc-heartbeat: alive` to auth.log every five minutes (infra/heartbeat/), Filebeat ships it, and the
console asks Splunk for the newest one per host. A host that is alive and connected is never silent for long, so the
age of its last heartbeat tells an analyst whether the log pipeline still works. The thresholds match the Splunk
alert (silent after 15 minutes), so the widget turns red when the alert fires.

Like the status strip, the Splunk question runs on the background loop at most once per `ttl` seconds and a page
shows the last known answer, so a slow or dead Splunk never makes a page wait. Host names come from Splunk and are
untrusted: they are cut down to a safe length here and the page shows them as text.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import Any

log = logging.getLogger("soc_web")

SLOT = 300           # one heartbeat every five minutes
SLOTS = 72           # six hours of slots, shown as ticks
LATE = 600           # more than two missed beats: amber
SILENT = 900         # the Splunk alert fires here: red
MAX_HOSTS = 12
PROBE_TIMEOUT = 20.0
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SEVERITY = {"ok": 0, "late": 1, "silent": 2}

# `last` is the newest heartbeat per host; `slots` lists the five-minute slots that had at least one.
# Splunk's REST search needs the word `search` in front (the saved alert in the UI does not), as in soc_bot/hunts.py.
SPL = (
    'search index=linux sourcetype=linux:auth "soc-heartbeat: alive" '
    "| eval slot=floor(_time/300)*300 "
    "| stats latest(_time) AS last values(slot) AS slots BY host "
    '| eval slots=mvjoin(slots,",")'
)
EARLIEST = "-6h"


def _number(value: Any) -> int | None:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def classify(age: int) -> str:
    return "ok" if age < LATE else "late" if age < SILENT else "silent"


def build_hosts(rows: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    """Turn Splunk rows into one entry per host: last heartbeat, its age, a state, and a tick for each five-minute slot."""
    current = int(now // SLOT) * SLOT
    first = current - (SLOTS - 1) * SLOT
    hosts: list[dict[str, Any]] = []
    for row in rows:
        host, last = str(row.get("host", "")), _number(row.get("last"))
        if not HOST_RE.match(host) or last is None:
            continue
        have = {n for n in (_number(x) for x in str(row.get("slots", "")).split(",")) if n is not None}
        ticks = []
        for i in range(SLOTS):
            start = first + i * SLOT
            # 1 = heartbeat seen, 0 = missed, 2 = the slot that is still running (not a miss yet)
            ticks.append(1 if start in have else 2 if start == current else 0)
        age = max(0, int(now - last))
        hosts.append({"host": host, "last": last, "age": age, "state": classify(age), "ticks": ticks})
    hosts.sort(key=lambda h: (-SEVERITY[h["state"]], h["host"]))
    return hosts[:MAX_HOSTS]


class HeartbeatProbe:
    def __init__(self, backends: Any, *, ttl: float = 30.0, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time):
        self._b, self._ttl, self._clock, self._wall = backends, ttl, clock, wall
        self._checked: float | None = None
        self._running = False
        self._rows: list[dict[str, Any]] | None = None  # None until the first answer
        self._failed = False
        self._error = ""  # the type of the last failure, for the panel; never the message

    async def _probe(self) -> None:
        import asyncio

        try:
            rows = await asyncio.wait_for(self._b.splunk.search(SPL, earliest=EARLIEST), PROBE_TIMEOUT)
            self._rows, self._failed, self._error = rows, False, ""
        except Exception as exc:  # noqa: BLE001 - any failure means "unknown", never "silent"
            self._failed, self._error = True, type(exc).__name__
            log.warning("Heartbeat search failed: %s %s", type(exc).__name__, str(exc)[:200])
        finally:
            self._running = False

    def snapshot(self) -> dict[str, Any]:
        """The last known state, starting a refresh in the background when it is older than the ttl.

        state: off (Splunk not configured), unknown (no answer yet or Splunk not answering), none (Splunk answers but
        has no heartbeat in six hours), or the worst of ok / late / silent over the hosts.
        """
        if self._b.splunk is None:
            return {"state": "off", "hosts": [], "now": int(self._wall()), "slot": SLOT, "late": LATE, "silent": SILENT,
                    "error": ""}
        now = self._clock()
        if not self._running and (self._checked is None or now - self._checked >= self._ttl):
            self._running, self._checked = True, now
            self._b.runner.spawn(self._probe())
        wall = self._wall()
        hosts = build_hosts(self._rows, wall) if self._rows is not None and not self._failed else []
        if self._failed or self._rows is None:
            state = "unknown"
        elif not hosts:
            state = "none"
        else:
            state = hosts[0]["state"]
        return {"state": state, "hosts": hosts, "now": int(wall), "slot": SLOT, "late": LATE, "silent": SILENT,
                "error": self._error if self._failed else ""}
