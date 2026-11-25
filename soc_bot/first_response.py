"""Automatic first response: the read-only lookups an analyst would run first on a new alert.

Only predefined hunts and the IP enrichment are used. Nothing here changes a host, and a private
address is never sent to a third party (the enrichment client already guarantees that).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .hunts import build
from .models import Incident, IpReport
from .validators import ValidationError

log = logging.getLogger("soc_bot")

WINDOW = "1h"
HOST_HUNT = "host_commands"
IP_HUNT = "ip_activity"
MAX_COMMENT_ROWS = 5


@dataclass
class HuntOutcome:
    name: str
    label: str
    rows: list[dict[str, Any]] | None = None  # None means the search failed
    error: str | None = None


@dataclass
class FirstResponse:
    window: str = WINDOW
    hunts: list[HuntOutcome] = field(default_factory=list)
    report: IpReport | None = None
    enrich_error: str | None = None

    @property
    def empty(self) -> bool:
        return not self.hunts and self.report is None and self.enrich_error is None


async def _hunt(splunk: Any, name: str, label: str, target: str, window: str) -> HuntOutcome:
    try:
        spl, earliest = build(name, window, target)
        rows = await splunk.search(spl, earliest=earliest)
        return HuntOutcome(name, label, rows=rows)
    except ValidationError as exc:
        return HuntOutcome(name, label, error=str(exc))
    except Exception as exc:  # a Splunk outage must not stop the other lookups
        log.warning("First-response hunt %s failed: %s", name, type(exc).__name__)
        return HuntOutcome(name, label, error=type(exc).__name__)


async def run(incident: Incident, *, splunk: Any, enrichment: Any, window: str = WINDOW) -> FirstResponse:
    result = FirstResponse(window=window)
    if splunk is not None and incident.host:
        result.hunts.append(await _hunt(splunk, HOST_HUNT, "Commands on host", incident.host, window))
    if incident.src_ip:
        if splunk is not None:
            result.hunts.append(await _hunt(splunk, IP_HUNT, "Events mentioning the source IP", incident.src_ip, window))
        if enrichment is not None:
            try:
                result.report = await enrichment.enrich_ip(incident.src_ip)
            except ValidationError as exc:
                result.enrich_error = str(exc)
            except Exception as exc:
                log.warning("First-response enrichment failed: %s", type(exc).__name__)
                result.enrich_error = type(exc).__name__
    return result


def summary(result: FirstResponse) -> str:
    """Plain-text version stored as an incident comment (also shown in the web console)."""
    lines = [f"Automatic first response (last {result.window}, read-only):"]
    for hunt in result.hunts:
        if hunt.rows is None:
            lines.append(f"- {hunt.label}: search failed ({hunt.error}).")
            continue
        lines.append(f"- {hunt.label}: {len(hunt.rows)} event(s).")
        for row in hunt.rows[:MAX_COMMENT_ROWS]:
            raw = str(row.get("_raw", "")).replace("\n", " ")[:160]
            lines.append(f"    {row.get('_time', '')} {raw}".rstrip())
    if result.report is not None:
        report = result.report
        parts = [f"verdict {report.verdict}"]
        if report.abuse_score is not None:
            parts.append(f"AbuseIPDB {report.abuse_score}/100")
        if report.vt_malicious is not None:
            parts.append(f"VirusTotal {report.vt_malicious} malicious")
        lines.append(f"- Source IP {report.ip}: " + ", ".join(parts) + ".")
    elif result.enrich_error:
        lines.append(f"- Source IP enrichment failed ({result.enrich_error}).")
    return "\n".join(lines)
