from __future__ import annotations

from datetime import datetime
from typing import Any

import discord
from discord.utils import escape_markdown, format_dt

from ..models import Incident, IpReport, IsolationResult

SEVERITY_COLORS = {
    "High": discord.Color.red(),
    "Medium": discord.Color.orange(),
    "Low": discord.Color.gold(),
    "Informational": discord.Color.blue(),
}
VERDICT_COLORS = {
    "Malicious": discord.Color.red(),
    "Suspicious": discord.Color.orange(),
    "Clean": discord.Color.green(),
    "Internal": discord.Color.greyple(),
    "Unknown": discord.Color.light_grey(),
    "Incomplete": discord.Color.light_grey(),
}


def _t(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def md(text: str | None, limit: int = 1024) -> str:
    """Escape untrusted text for an embed; brackets too, so `[x](url)` cannot render as a link."""
    escaped = escape_markdown(text or "", ignore_links=False).replace("[", "\\[").replace("]", "\\]")
    return _t(escaped, limit)


def _when(dt: datetime | None) -> str:
    return format_dt(dt, "R") if dt else "n/a"


def _label(classification: str | None) -> str:
    return (classification or "n/a").replace("_", " ").title()


def incident_list(incidents: list[Incident], status: str, severity: str | None) -> discord.Embed:
    title = f"Incidents - {status}" + (f" / {severity}" if severity else "")
    embed = discord.Embed(title=title, color=discord.Color.blurple())
    if not incidents:
        embed.description = "No incidents match this filter."
        return embed
    lines = []
    for i in incidents:
        owner = md(i.assignee, 60) if i.assignee else "unassigned"
        target = md(i.host, 60) if i.host else "no host"
        lines.append(
            f"**#{i.id}** `{i.severity.upper():<13}` `{i.status:<6}` {md(i.rule, 90)}\n"
            f"-# {target} | {owner} | created {_when(i.created)}"
        )
    embed.description = _t("\n".join(lines), 4000)
    embed.set_footer(text="Use /incident show <number> for details")
    return embed


def incident_detail(incident: Incident) -> discord.Embed:
    embed = discord.Embed(
        title=_t(f"#{incident.id} - {md(incident.rule, 240)}", 256),
        url=incident.url,
        description=md(incident.description, 1000) or None,
        color=SEVERITY_COLORS.get(incident.severity, discord.Color.default()),
    )
    embed.add_field(name="Severity", value=incident.severity)
    embed.add_field(name="Status", value=incident.status)
    embed.add_field(name="Assignee", value=md(incident.assignee, 100) if incident.assignee else "unassigned")
    embed.add_field(name="Host", value=md(incident.host, 100) if incident.host else "n/a")
    embed.add_field(name="Source IP", value=f"`{incident.src_ip}`" if incident.src_ip else "n/a")
    embed.add_field(name="Created", value=_when(incident.created))
    if incident.classification:
        embed.add_field(name="Classification", value=_label(incident.classification))
    if incident.comments:
        lines = [f"**{md(c.author, 60)}**: {md(c.body, 200)}" for c in incident.comments[-5:]]
        embed.add_field(name=f"Comments ({len(incident.comments)})", value=_t("\n".join(lines), 1024), inline=False)
    return embed


def ip_report(report: IpReport) -> discord.Embed:
    embed = discord.Embed(
        title=f"IP enrichment - {report.ip}",
        description=f"Verdict: **{report.verdict}**",
        color=VERDICT_COLORS.get(report.verdict, discord.Color.default()),
    )
    if not report.is_public:
        embed.add_field(
            name="Note",
            value="Private/reserved address - not sent to external threat-intel services.",
            inline=False,
        )
        return embed
    if report.abuse_score is not None:
        embed.add_field(name="AbuseIPDB score", value=f"{report.abuse_score}/100")
        embed.add_field(name="Abuse reports (90d)", value=str(report.abuse_reports or 0))
    if report.vt_malicious is not None:
        embed.add_field(
            name="VirusTotal",
            value=f"{report.vt_malicious} malicious / {report.vt_suspicious or 0} suspicious / "
                  f"{report.vt_harmless or 0} harmless",
            inline=False,
        )
    for name, value in (
        ("Country", report.country),
        ("ISP", report.isp),
        ("AS owner", report.as_owner),
        ("Usage", report.usage_type),
    ):
        if value:
            embed.add_field(name=name, value=md(value, 200))
    if report.errors:
        embed.add_field(name="Warnings", value=md("; ".join(report.errors)), inline=False)
    return embed


def close_confirm(incident: Incident, label: str, comment: str) -> discord.Embed:
    embed = discord.Embed(
        title=f"Close incident #{incident.id}?",
        description=md(incident.rule, 500),
        color=discord.Color.orange(),
    )
    embed.add_field(name="Classification", value=label, inline=False)
    embed.add_field(name="Comment", value=md(comment), inline=False)
    embed.set_footer(text="Confirm within 60 seconds")
    return embed


def incident_closed(incident: Incident, actor: str) -> discord.Embed:
    embed = discord.Embed(
        title=f"Incident #{incident.id} closed",
        description=md(incident.rule, 500),
        url=incident.url,
        color=discord.Color.green(),
    )
    embed.add_field(name="Classification", value=_label(incident.classification))
    embed.add_field(name="Closed by", value=md(actor, 100))
    return embed


def isolation_confirm(
    verb: str, hostname: str, address: str, reason: str, incident: Incident
) -> discord.Embed:
    embed = discord.Embed(
        title=f"{verb} host {md(hostname, 200)}?",
        color=discord.Color.red() if verb == "Isolate" else discord.Color.orange(),
    )
    embed.add_field(name="Address", value=f"`{address}`")
    embed.add_field(name="Linked incident", value=f"#{incident.id} - {md(incident.rule, 200)}", inline=False)
    embed.add_field(name="Reason", value=md(reason), inline=False)
    embed.set_footer(text="Confirm within 60 seconds")
    return embed


def isolation_result(result: IsolationResult, actor: str, incident: Incident) -> discord.Embed:
    embed = discord.Embed(
        title=f"{result.action.capitalize()} completed for {md(result.host, 200)}",
        color=discord.Color.green(),
    )
    embed.add_field(name="Address", value=f"`{result.address}`")
    embed.add_field(name="Requested by", value=md(actor, 100))
    embed.add_field(name="Incident", value=f"#{incident.id}")
    if result.output:
        embed.add_field(name="Script output", value=md(result.output, 300), inline=False)
    return embed


def hunt_results(label: str, window: str, rows: list[dict[str, Any]]) -> discord.Embed:
    embed = discord.Embed(title=f"Hunt - {_t(label, 200)} ({window})", color=discord.Color.blurple())
    if not rows:
        embed.description = "No events found."
        return embed
    lines = [" | ".join(f"{k}={v}" for k, v in row.items() if not k.startswith("_") or k in {"_time", "_raw"})
             for row in rows]
    # A triple backtick in log data would end the code block early.
    body = "\n".join(lines).replace("```", "'''")
    embed.description = f"```\n{_t(body, 3900)}\n```"
    embed.set_footer(text=f"{len(rows)} row(s)")
    return embed


def ai_answer(question: str, text: str) -> discord.Embed:
    embed = discord.Embed(description=md(text, 3500), color=discord.Color.blurple())
    embed.set_footer(text=_t(" ".join(question.split()), 100))
    return embed


def ai_note(incident_id: int, text: str) -> discord.Embed:
    embed = discord.Embed(title=f"Triage note for #{incident_id}", description=md(text, 3500), color=discord.Color.blurple())
    embed.set_footer(text="Suggestion only. A person decides and acts.")
    return embed


def notice(text: str, color: discord.Color | None = None) -> discord.Embed:
    return discord.Embed(description=text, color=color or discord.Color.light_grey())


def error(text: str) -> discord.Embed:
    return discord.Embed(title="Request failed", description=_t(text, 2000), color=discord.Color.dark_red())


def audit_entry(entry: dict[str, Any]) -> discord.Embed:
    outcome = entry.get("outcome", "")
    color = {
        "success": discord.Color.green(),
        "denied": discord.Color.dark_red(),
        "blocked": discord.Color.dark_red(),
        "error": discord.Color.red(),
    }.get(outcome, discord.Color.light_grey())
    embed = discord.Embed(title=f"audit: {entry.get('action')}", color=color)
    embed.add_field(name="Actor", value=f"<@{entry.get('actor_id')}>")
    embed.add_field(name="Target", value=md(str(entry.get("target")), 200))
    embed.add_field(name="Outcome", value=outcome)
    extras = {k: v for k, v in entry.items() if k not in {"ts", "actor", "actor_id", "action", "target", "outcome"}}
    if extras:
        embed.add_field(
            name="Details",
            value=_t("\n".join(f"{k}: {md(str(v), 200)}" for k, v in extras.items()), 1024),
            inline=False,
        )
    embed.set_footer(text=entry.get("ts", ""))
    return embed
