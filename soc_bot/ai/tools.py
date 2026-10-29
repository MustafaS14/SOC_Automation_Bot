"""Read-only lookups the assistant may request, each with a minimum clearance level.

The model is only shown the tools its asker may use, and `execute` checks the level again, so a denied
call can never return data. No tool here changes anything.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .. import hunts
from ..audit import read_recent
from ..clients import APIError, NotFoundError
from ..rbac import Permission
from ..validators import ValidationError, is_protected_host, parse_hostname, parse_incident_ref, parse_ip

MAX_RESULT_CHARS = 6000
_CELL = 300

# What each person sees in the answer, and what `/soc-help` calls their level.
LEVEL_LABELS = {
    Permission.VIEWER: "Viewer",
    Permission.READ: "Analyst",
    Permission.TRIAGE: "Analyst",
    Permission.RESPONSE: "Responder",
    Permission.ADMIN: "Admin",
}


@dataclass(frozen=True)
class ToolContext:
    store: Any
    splunk: Any = None
    enrichment: Any = None
    ssh: Any = None
    isolation_denylist: tuple[str, ...] = ()
    audit_log_path: str = ""
    max_rows: int = 20


@dataclass(frozen=True)
class ToolResult:
    text: str
    denied: bool = False
    error: bool = False


Handler = Callable[[ToolContext, Permission, dict[str, Any]], Awaitable[str]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    min_level: Permission
    handler: Handler


def _cut(value: Any, limit: int = _CELL) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _when(dt: Any) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "n/a"


def _rows(ctx: ToolContext, requested: Any, default: int = 10) -> int:
    try:
        n = int(requested)
    except (TypeError, ValueError):
        n = default
    return max(1, min(n, ctx.max_rows))


# ---- VIEWER level: summaries only, no hostnames, addresses, commands or comments

async def _incident_counts(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    counts = await ctx.store.counts()
    by_status = counts["status"]
    open_total = sum(n for status, n in by_status.items() if status != "Closed")
    severity = ", ".join(f"{k}: {v}" for k, v in sorted(counts["open_by_severity"].items())) or "none"
    statuses = ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items())) or "none"
    return f"open incidents: {open_total}; by status: {statuses}; open by severity: {severity}"


async def _incident_summary(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    inc = await ctx.store.get(parse_incident_ref(str(args.get("incident", ""))))
    return (
        f"incident #{inc.id}: rule={_cut(inc.rule)}; severity={inc.severity}; status={inc.status}; "
        f"classification={inc.classification or 'n/a'}; created={_when(inc.created)}; "
        f"updated={_when(inc.updated)}; comments={len(inc.comments)}"
    )


async def _list_incidents(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    status = str(args.get("status", "open")).lower()
    severity = args.get("severity")
    if severity is not None:
        severity = str(severity).title()
    try:
        incidents = await ctx.store.list(status=status, severity=severity, limit=_rows(ctx, args.get("limit")))
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if not incidents:
        return "no incidents match"
    show_host = level >= Permission.READ
    lines = []
    for inc in incidents:
        host = f"; host={_cut(inc.host or 'n/a', 80)}" if show_host else ""
        lines.append(f"#{inc.id} rule={_cut(inc.rule, 120)}; severity={inc.severity}; status={inc.status}{host}; created={_when(inc.created)}")
    return "\n".join(lines)


# ---- READ level (Analyst): details, hunts, reputation

async def _get_incident(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    inc = await ctx.store.get(parse_incident_ref(str(args.get("incident", ""))))
    lines = [
        f"incident #{inc.id}: rule={_cut(inc.rule)}; severity={inc.severity}; status={inc.status}; "
        f"classification={inc.classification or 'n/a'}; host={inc.host or 'n/a'}; src_ip={inc.src_ip or 'n/a'}; "
        f"assignee={inc.assignee or 'n/a'}; created={_when(inc.created)}; updated={_when(inc.updated)}",
        f"description: {_cut(inc.description, 600) or 'n/a'}",
    ]
    for comment in inc.comments[-10:]:
        lines.append(f"comment by {_cut(comment.author, 60)} at {_when(comment.created)}: {_cut(comment.body)}")
    return "\n".join(lines)


async def _run_hunt(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    if ctx.splunk is None:
        return "ERROR: Splunk is not configured."
    template = str(args.get("template", ""))
    window = str(args.get("window", "1h"))
    target = args.get("target")
    spl, earliest = hunts.build(template, window, str(target) if target else None)
    rows = await ctx.splunk.search(spl, earliest=earliest)
    if not rows:
        return "search returned no rows"
    shown = rows[: ctx.max_rows]
    lines = ["; ".join(f"{k}={_cut(v)}" for k, v in row.items() if not str(k).startswith("_") or k in {"_time", "_raw"}) for row in shown]
    if len(rows) > len(shown):
        lines.append(f"(capped: showing {len(shown)} of {len(rows)} rows)")
    return "\n".join(lines)


async def _enrich_ip(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    if ctx.enrichment is None:
        return "ERROR: IP reputation is not configured."
    ip = parse_ip(str(args.get("ip", "")))
    report = await ctx.enrichment.enrich_ip(str(ip))
    errors = f"; errors={'; '.join(report.errors)}" if report.errors else ""
    return (
        f"ip={report.ip}; verdict={report.verdict}; public={report.is_public}; "
        f"abuse_score={report.abuse_score}; vt_malicious={report.vt_malicious}; country={report.country}{errors}"
    )


# ---- RESPONSE level (Responder): what an isolation would do. It never isolates.

async def _isolation_preview(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    host = parse_hostname(str(args.get("host", "")))
    if is_protected_host(host, ctx.isolation_denylist):
        return f"host {host} is on the deny-list (critical asset): the bot refuses to isolate it"
    if ctx.ssh is None:
        return "ERROR: host isolation is not configured."
    name, _address = ctx.ssh.resolve(host)
    return (
        f"host {name} is in the responder inventory and not on the deny-list. Isolating it would cut its network "
        "traffic while management SSH stays open; it needs a reason, an incident number and a confirmation click "
        "from a person. This preview did not isolate anything."
    )


# ---- ADMIN level: who asked what

async def _recent_audit(ctx: ToolContext, level: Permission, args: dict[str, Any]) -> str:
    if not ctx.audit_log_path:
        return "ERROR: the audit log is not configured."
    entries = read_recent(ctx.audit_log_path, _rows(ctx, args.get("limit"), default=10))
    if not entries:
        return "audit log is empty"
    return "\n".join(
        f"{_cut(e.get('ts', ''), 32)} actor={_cut(e.get('actor', ''), 60)} action={_cut(e.get('action', ''), 40)} "
        f"target={_cut(e.get('target', ''), 60)} outcome={_cut(e.get('outcome', ''), 20)}"
        for e in entries
    )


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in (
        Tool("incident_counts", 'incident_counts() - how many incidents are open or closed, and open ones by severity',
             Permission.VIEWER, _incident_counts),
        Tool("incident_summary", 'incident_summary(incident) - one incident without hostnames, IPs or commands',
             Permission.VIEWER, _incident_summary),
        Tool("list_incidents", 'list_incidents(status="open|new|active|closed|all", severity, limit) - recent incidents',
             Permission.VIEWER, _list_incidents),
        Tool("get_incident", 'get_incident(incident) - full detail of one incident: host, IP, description, comments',
             Permission.READ, _get_incident),
        Tool("run_hunt", 'run_hunt(template, window, target) - template is host_commands (target=hostname), '
             'ip_activity (target=IP) or ssh_failures; window is 15m, 1h, 24h or 7d',
             Permission.READ, _run_hunt),
        Tool("enrich_ip", 'enrich_ip(ip) - reputation of a public IP address', Permission.READ, _enrich_ip),
        Tool("isolation_preview", 'isolation_preview(host) - what isolating a host would do; never isolates',
             Permission.RESPONSE, _isolation_preview),
        Tool("recent_audit", 'recent_audit(limit) - the newest audit-log entries: who asked or did what',
             Permission.ADMIN, _recent_audit),
    )
}


def tools_for(level: Permission) -> list[Tool]:
    return [t for t in TOOLS.values() if level >= t.min_level]


async def execute(ctx: ToolContext, level: Permission, name: str, args: Any) -> ToolResult:
    tool = TOOLS.get(name)
    if tool is None:
        return ToolResult(f"ERROR: unknown tool {_cut(name, 40)!r}", error=True)
    if level < tool.min_level:
        return ToolResult("ACCESS_DENIED: this lookup needs a higher clearance level", denied=True)
    if not isinstance(args, dict):
        return ToolResult("ERROR: args must be a JSON object", error=True)
    try:
        text = await tool.handler(ctx, level, args)
    except ValidationError as exc:
        return ToolResult(f"ERROR: {exc}", error=True)
    except NotFoundError as exc:
        return ToolResult(f"ERROR: {exc.message}", error=True)
    except APIError as exc:
        return ToolResult(f"ERROR: {exc.service} could not answer (status {exc.status})", error=True)
    return ToolResult(text if len(text) <= MAX_RESULT_CHARS else text[: MAX_RESULT_CHARS - 20] + "\n(output truncated)")


def describe_args(args: Any) -> str:
    try:
        return json.dumps(args, sort_keys=True, default=str)[:200]
    except (TypeError, ValueError):
        return "{}"
