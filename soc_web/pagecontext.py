"""What the chat widget tells the assistant about the page the user is on.

The server builds this itself, route by route, from the same data the page shows and for the same tier that may open
the page. The browser sends only which page it is on (a path), never any page text, and nothing here is HTML. The text
is capped and run through redact(), and the prompt wraps it as untrusted data: incident descriptions and commands come
from alerts and can hold attacker-controlled text.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from soc_bot.audit import redact

MAX_CONTEXT_CHARS = 3000
MAX_LINE = 300
MAX_ROWS = 12

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass(frozen=True)
class PageContext:
    label: str  # shown to the user in the chip: "incident #10"
    text: str  # what the assistant is given ("" for pages that only send their name)


def _line(value: Any) -> str:
    return _CONTROL.sub("", " ".join(str(value).split()))[:MAX_LINE]


def finish(label: str, lines: Iterable[str]) -> PageContext:
    """Join, redact and cap. The cap is applied after redaction, so a secret cannot straddle the cut."""
    text = redact("\n".join(lines))[:MAX_CONTEXT_CHARS]
    return PageContext(label, text)


def only_name(label: str) -> PageContext:
    return PageContext(label, "")


def dashboard(counts: Mapping[str, Mapping[str, int]], open_total: int, threat: str, recent: Sequence[Any]) -> PageContext:
    lines = [f"Threat level: {threat}", f"Open incidents: {open_total}"]
    lines += [f"{k}: {v}" for k, v in sorted(counts["status"].items())]
    lines += [f"Open {k}: {v}" for k, v in sorted(counts["open_by_severity"].items())]
    for i in list(recent)[:MAX_ROWS]:
        lines.append(f"#{i.id} {_line(i.rule)} | {i.severity} | {i.status} | {_line(i.host or 'no host')}")
    return finish("dashboard", lines)


def incident_list(rows: Sequence[Any], status: str, severity: str | None, order: str) -> PageContext:
    lines = [f"Filter: status={status}, severity={severity or 'any'}, order={order}", f"Shown: {len(rows)}"]
    for i in list(rows)[:MAX_ROWS]:
        lines.append(f"#{i.id} {_line(i.rule)} | {i.severity} | {i.status} | {_line(i.host or 'no host')}")
    return finish("incident list", lines)


def incident(inc: Any, timeline: Sequence[Mapping[str, Any]]) -> PageContext:
    """The incident page: its facts, then the timeline as the page lists it, oldest first."""
    lines = [
        f"Incident #{inc.id}: {_line(inc.rule)}", f"Severity: {inc.severity}", f"Status: {inc.status}",
        f"Host: {_line(inc.host or 'none')}", f"Source IP: {_line(inc.src_ip or 'none')}",
        f"Assignee: {_line(inc.assignee or 'none')}", f"Classification: {_line(inc.classification or 'none')}",
        f"Description: {_line(inc.description)}", "Timeline:",
    ]
    for e in list(timeline)[-MAX_ROWS:]:
        when = e["when"].strftime("%Y-%m-%d %H:%M") if e.get("when") else "n/a"
        who = f" by {_line(e['who'])}" if e.get("who") else ""
        text = f": {_line(e['text'])}" if e.get("text") else ""
        lines.append(f"- {when} {e['label']}{who}{text}")
    return finish(f"incident #{inc.id}", lines)


def hunt(form: Mapping[str, str], columns: Sequence[str], rows: Sequence[Mapping[str, Any]], total: int) -> PageContext:
    lines = [f"Hunt: {_line(form.get('template', ''))}, window {_line(form.get('window', ''))}, "
             f"target {_line(form.get('target') or 'none')}", f"Rows: {total} (first {min(len(rows), MAX_ROWS)} shown here)",
             "Columns: " + ", ".join(_line(c) for c in columns[:12])]
    for row in list(rows)[:MAX_ROWS]:
        lines.append(" | ".join(_line(row.get(c, ""))[:120] for c in columns[:6]))
    return finish("hunt results", lines)


def enrichment(report: Any) -> PageContext:
    lines = [f"IP: {report.ip}", f"Verdict: {report.verdict}", f"Public address: {report.is_public}",
             f"AbuseIPDB score: {report.abuse_score}", f"AbuseIPDB reports: {report.abuse_reports}",
             f"VirusTotal malicious: {report.vt_malicious}", f"VirusTotal suspicious: {report.vt_suspicious}",
             f"Country: {_line(report.country or 'n/a')}", f"Provider: {_line(report.isp or 'n/a')}"]
    lines += [f"Note: {_line(e)}" for e in report.errors[:3]]
    return finish(f"enrichment of {report.ip}", lines)


def audit_rows(rows: Sequence[Mapping[str, Any]], total: int, shown: Mapping[str, str]) -> PageContext:
    lines = [f"Audit entries matching: {total}", "Filters: " + (", ".join(f"{k}={v}" for k, v in shown.items()) or "none")]
    for r in list(rows)[:MAX_ROWS]:
        lines.append(f"{r['ts']} | {_line(r['actor'])} | {r['action']} | {_line(r['target'])} | {r['outcome']} | {r['channel']}")
    return finish("audit log", lines)


class RecentResults:
    """The last hunt and enrichment result each user was shown. Those pages answer a POST, so a later request cannot
    rebuild them from the address alone. Kept in memory, per user and tier, for a few minutes."""

    def __init__(self, ttl: float = 600.0, clock: Callable[[], float] = time.monotonic):
        self._ttl, self._clock = ttl, clock
        self._items: dict[tuple[int, str], tuple[int, float, PageContext]] = {}
        self._lock = threading.Lock()

    def put(self, user_id: int, tier: int, kind: str, context: PageContext) -> None:
        with self._lock:
            self._items[(user_id, kind)] = (int(tier), self._clock(), context)
            if len(self._items) > 1000:
                now = self._clock()
                self._items = {k: v for k, v in self._items.items() if now - v[1] < self._ttl}

    def get(self, user_id: int, tier: int, kind: str) -> PageContext | None:
        """Only for the same tier it was shown at, so a demoted user never gets a higher tier's result back."""
        with self._lock:
            item = self._items.get((user_id, kind))
        if item and item[0] == int(tier) and self._clock() - item[1] < self._ttl:
            return item[2]
        return None

    def clear(self, user_id: int) -> None:
        with self._lock:
            for key in [k for k in self._items if k[0] == user_id]:
                del self._items[key]
