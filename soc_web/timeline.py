"""The Timeline page: detected attacks and raw activity on one shared time axis.

Top panel: alerts (the bot's incidents) per time slot, stacked by attack type. Bottom panel: log activity from Splunk
per time slot, stacked by kind of activity. Both use the same slots and the same horizontal scale, so a spike in one
lines up with the other: a spike of activity with no alert under it is a gap in the detections. They are two panels with
their own vertical scales, never one chart with two axes.

Everything here is plain functions on plain data (no Flask, no Splunk), so it is easy to test. Nothing from Splunk or the
incident store reaches the page as text except through the fixed labels below: rule names are folded into a few known
attack types, and activity kinds are the labels this module gives them. Times are UTC, like the rest of the console.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from soc_bot import attack_coverage

PRESETS = {
    "1h": ("Last hour", 3600),
    "6h": ("Last 6 hours", 6 * 3600),
    "24h": ("Last 24 hours", 24 * 3600),
    "7d": ("Last 7 days", 7 * 86400),
    "30d": ("Last 30 days", 30 * 86400),
}
DEFAULT_PRESET = "24h"
MIN_SPAN = 600
MAX_SPAN = 31 * 86400
BUCKETS = (60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400)  # slot sizes in seconds
TARGET_SLOTS = 96

# Chart geometry (SVG user units; the SVG scales to the page width).
WIDTH, LEFT, RIGHT, TOP, BOTTOM = 960, 48, 14, 12, 36
GAP = 2           # surface gap between stacked segments
MAX_BAR = 24
ROUND = 4
MIN_LABEL_PX = 84
TICK_STEPS = (300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 432000, 864000)  # clock-aligned


@dataclass(frozen=True)
class Kind:
    key: str
    label: str
    cls: str     # colour slot in style.css (a1.. for attacks, b1.. for activity)


ATTACKS = (
    Kind("discovery", "Discovery burst", "a1"),
    Kind("masquerade", "Masquerading", "a2"),
    Kind("health", "Pipeline health", "a3"),
    Kind("other", "Other alerts", "a0"),
)
# Fixed stacking order, bottom to top; the colours were validated in this order on the console's dark surface.
ACTIVITY = (
    Kind("commands", "Commands run", "b1"),
    Kind("auth", "Logins and sudo", "b2"),
    Kind("system", "Cron and system", "b3"),
    Kind("failed", "Failed logins", "b4"),
)
_BY_LABEL = {k.label: k for k in ACTIVITY}


def attack_kind(rule: str) -> Kind:
    """The attack type of a detection rule, by its name. Anything unknown is "Other alerts"."""
    name = (rule or "").lower()
    if "discovery burst" in name:
        return ATTACKS[0]
    if "masquerad" in name:
        return ATTACKS[1]
    if "heartbeat" in name:
        return ATTACKS[2]
    return ATTACKS[3]


def techniques_for(kind: Kind) -> list[str]:
    """ATT&CK IDs of the tested techniques that the rules of this attack type cover."""
    return [t.id for t in attack_coverage.TECHNIQUES
            if t.status == attack_coverage.TESTED and any(attack_kind(r).key == kind.key for r in t.rules)]


# ---- the time frame ------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Range:
    start: datetime      # aligned down to a slot boundary, UTC
    end: datetime        # aligned up to a slot boundary, UTC
    bucket: int          # seconds per slot
    slots: int
    preset: str          # "" for a custom range
    from_text: str       # for the date fields, "YYYY-MM-DDTHH:MM"
    to_text: str
    error: str = ""      # why the asked-for range was not used, if so


def pick_bucket(span: float) -> int:
    for size in BUCKETS:
        if math.ceil(span / size) <= TARGET_SLOTS:
            return size
    return BUCKETS[-1]


def _utc(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, timezone.utc)


def _make(start: datetime, end: datetime, preset: str, error: str = "") -> Range:
    bucket = pick_bucket((end - start).total_seconds())
    first = math.floor(start.timestamp() / bucket) * bucket
    last = math.ceil(end.timestamp() / bucket) * bucket
    return Range(_utc(first), _utc(last), bucket, int((last - first) // bucket), preset,
                 start.strftime("%Y-%m-%dT%H:%M"), end.strftime("%Y-%m-%dT%H:%M"), error)


def parse_range(args: Mapping[str, str], now: datetime) -> Range:
    """The time frame from the page's query string: a preset (`range=6h`) or a custom `from` and `to` in UTC."""
    now = now.replace(second=0, microsecond=0)
    preset = args.get("range", "")
    if preset in PRESETS:
        return _make(now - timedelta(seconds=PRESETS[preset][1]), now, preset)
    error = ""
    if args.get("from") or args.get("to"):
        try:
            start = datetime.strptime(args.get("from", ""), "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)
            end = datetime.strptime(args.get("to", ""), "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            error = "Enter both dates as year-month-day and a time."
        else:
            span = (end - start).total_seconds()
            if span < MIN_SPAN:
                error = "The end must be at least ten minutes after the start."
            elif span > MAX_SPAN:
                error = "The time frame can be at most 31 days."
            else:
                return _make(start, end, "")
        error += " Showing the last 24 hours instead."
    return _make(now - timedelta(seconds=PRESETS[DEFAULT_PRESET][1]), now, DEFAULT_PRESET, error)


# ---- the data ------------------------------------------------------------------------------------------------

def activity_spl(bucket: int) -> str:
    """Splunk search for log activity per slot and kind. Heartbeat lines are left out: they are not activity."""
    size = int(bucket)
    return (
        'search index=linux NOT "soc-heartbeat" '
        '| where sourcetype!="linux:audit" OR match(_raw,"type=EXECVE") '
        '| eval kind=case(sourcetype="linux:audit","Commands run", '
        'match(_raw,"(?i)failed password|authentication failure|invalid user"),"Failed logins", '
        'match(_raw,"CRON"),"Cron and system", '
        'match(_raw,"(?i)sudo|accepted|session opened|new session|logged in"),"Logins and sudo", '
        'true(),"Cron and system") '
        f"| eval b=floor(_time/{size})*{size} "
        "| stats count by b kind"
    )


def _number(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def group_alerts(series: Mapping[str, list[int]], slots: int) -> dict[str, list[int]]:
    """Fold per-rule counts into the attack types."""
    out = {k.key: [0] * slots for k in ATTACKS}
    for rule, counts in series.items():
        target = out[attack_kind(rule).key]
        for i, n in enumerate(counts[:slots]):
            target[i] += max(0, int(n))
    return out


def parse_activity(rows: list[dict[str, Any]], rng: Range) -> dict[str, list[int]]:
    out = {k.key: [0] * rng.slots for k in ACTIVITY}
    first = int(rng.start.timestamp())
    for row in rows:
        kind, when, count = _BY_LABEL.get(str(row.get("kind"))), _number(row.get("b")), _number(row.get("count"))
        if kind is None or when is None or count is None or count < 0:
            continue
        index = (when - first) // rng.bucket
        if 0 <= index < rng.slots:
            out[kind.key][index] += count
    return out


# ---- the drawing ---------------------------------------------------------------------------------------------

def nice_ticks(peak: int) -> tuple[int, list[int]]:
    """A top value and whole-number tick values for a count axis: 0, 1, 2 ... or 0, 5, 10 ... never 0.5."""
    peak = peak if peak > 0 else 4
    step = 1
    while peak / step > 5:
        step *= 2 if str(step)[0] in "15" else 2.5  # 1, 2, 5, 10, 20, 50 ...
        step = int(step)
    top = int(math.ceil(peak / step) * step)
    return top, list(range(0, top + 1, step))


SLOT_NAMES = {60: "minute", 300: "5 minutes", 900: "15 minutes", 1800: "30 minutes", 3600: "hour", 10800: "3 hours",
              21600: "6 hours", 43200: "12 hours", 86400: "day"}


def when_label(start: datetime, bucket: int) -> str:
    end = start + timedelta(seconds=bucket)
    day = f"{start:%b} {start.day}"
    if bucket >= 86400:
        return f"{day} (UTC)"
    return f"{day}, {start:%H:%M}\u2013{end:%H:%M} UTC"


def _segment(x: float, y: float, w: float, h: float, r: float) -> str:
    """A bar segment as a path: square at the bottom, rounded at the top when `r` is set."""
    if r <= 0:
        return f"M{x:.1f},{y + h:.1f}V{y:.1f}H{x + w:.1f}V{y + h:.1f}Z"
    return (f"M{x:.1f},{y + h:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}H{x + w - r:.1f}"
            f"Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}V{y + h:.1f}Z")


def stack_chart(kinds: tuple[Kind, ...], data: Mapping[str, list[int]], rng: Range, height: int) -> dict[str, Any]:
    """Geometry for one stacked-column panel: columns, axis ticks and gridlines. The page only prints it."""
    n = rng.slots
    plot_w, plot_h = WIDTH - LEFT - RIGHT, height - TOP - BOTTOM
    totals = [sum(data[k.key][i] for k in kinds) for i in range(n)]
    top, ticks = nice_ticks(max(totals) if totals else 0)
    base = TOP + plot_h
    slot = plot_w / n
    bar_w = max(1.5, min(MAX_BAR, slot - 2))
    columns = []
    for i in range(n):
        cell_x = LEFT + i * slot
        x = cell_x + (slot - bar_w) / 2
        present = [k for k in kinds if data[k.key][i] > 0]
        segments, below = [], 0
        for position, kind in enumerate(present):
            value = data[kind.key][i]
            y_top = base - (below + value) / top * plot_h
            y_bottom = base - below / top * plot_h
            if position > 0:
                y_bottom -= GAP
            h = max(1.0, y_bottom - y_top)
            radius = min(ROUND, bar_w / 2, h) if position == len(present) - 1 else 0
            segments.append({"cls": kind.cls, "path": _segment(x, y_top, bar_w, h, radius)})
            below += value
        columns.append({"i": i, "x": round(cell_x, 1), "w": round(slot, 1), "total": totals[i], "segments": segments})
    # Ticks fall on round clock times (every 30 minutes, every 6 hours, at midnight ...), not every Nth slot.
    step = next((t for t in TICK_STEPS if t % rng.bucket == 0 and t / rng.bucket * slot >= MIN_LABEL_PX), TICK_STEPS[-1])
    first_epoch = int(rng.start.timestamp())
    xticks, last_day = [], None
    for i in range(n):
        if (first_epoch + i * rng.bucket) % step:
            continue
        at = rng.start + timedelta(seconds=i * rng.bucket)
        if rng.bucket >= 86400:
            label, sub = f"{at:%b} {at.day}", ""
        else:
            label = f"{at:%H:%M}"
            sub = f"{at:%b} {at.day}" if at.date() != last_day else ""
        last_day = at.date()
        xticks.append({"x": round(LEFT + i * slot, 1), "label": label, "sub": sub})
    return {
        "width": WIDTH, "height": height, "left": LEFT, "right": WIDTH - RIGHT, "base": base, "top": TOP,
        "plot_h": plot_h, "columns": columns, "empty": not any(totals), "peak": max(totals) if totals else 0,
        "yticks": [{"y": round(base - v / top * plot_h, 1), "label": str(v)} for v in ticks],
        "xticks": xticks,
        "legend": [{"label": k.label, "cls": k.cls, "total": sum(data[k.key])} for k in kinds],
    }


def build(rng: Range, alerts: Mapping[str, list[int]] | None, activity: Mapping[str, list[int]] | None) -> dict[str, Any]:
    """Everything the page needs. `alerts` or `activity` is None when that source could not be read."""
    view: dict[str, Any] = {"range": rng, "alerts": None, "activity": None, "tiles": {}, "tips": []}
    if alerts is not None:
        view["alerts"] = stack_chart(ATTACKS, alerts, rng, 250)
        for entry, kind in zip(view["alerts"]["legend"], ATTACKS, strict=True):
            entry["techniques"] = techniques_for(kind)
    if activity is not None:
        view["activity"] = stack_chart(ACTIVITY, activity, rng, 230)
    for i in range(rng.slots):
        at = rng.start + timedelta(seconds=i * rng.bucket)
        row_alerts = [[k.label, alerts[k.key][i], k.cls] for k in ATTACKS if alerts and alerts[k.key][i]]
        row_activity = [[k.label, activity[k.key][i], k.cls] for k in ACTIVITY if activity and activity[k.key][i]]
        view["tips"].append({"when": when_label(at, rng.bucket), "alerts": row_alerts, "activity": row_activity,
                             "alert_total": sum(r[1] for r in row_alerts),
                             "activity_total": sum(r[1] for r in row_activity)})
    columns = ([(k.label, "Alerts", alerts[k.key]) for k in ATTACKS] if alerts is not None else []) + \
              ([(k.label, "Activity", activity[k.key]) for k in ACTIVITY] if activity is not None else [])
    view["headers"] = [{"label": label, "group": group} for label, group, _ in columns]
    view["table"] = [{"when": tip["when"], "cells": [c[2][i] for c in columns]}
                     for i, tip in enumerate(view["tips"]) if any(c[2][i] for c in columns)]
    view["slot_name"] = SLOT_NAMES.get(rng.bucket, f"{rng.bucket} seconds")
    tiles = view["tiles"]
    if alerts is not None:
        per_slot = [sum(alerts[k.key][i] for k in ATTACKS) for i in range(rng.slots)]
        totals = {k.label: sum(alerts[k.key]) for k in ATTACKS}
        tiles["alerts"] = sum(per_slot)
        tiles["alert_peak"] = max(per_slot) if per_slot else 0
        tiles["alert_peak_when"] = view["tips"][per_slot.index(max(per_slot))]["when"] if any(per_slot) else ""
        tiles["top_type"] = max(totals, key=totals.get) if any(totals.values()) else ""
        tiles["top_type_count"] = max(totals.values()) if totals else 0
    if activity is not None:
        per_slot = [sum(activity[k.key][i] for k in ACTIVITY) for i in range(rng.slots)]
        tiles["activity"] = sum(per_slot)
        tiles["activity_peak"] = max(per_slot) if per_slot else 0
        tiles["activity_peak_when"] = view["tips"][per_slot.index(max(per_slot))]["when"] if any(per_slot) else ""
    return view
