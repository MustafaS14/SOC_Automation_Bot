from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

import discord
from discord.utils import escape_markdown, format_dt

from ..models import Entity, Incident, IpReport, Machine, MachineAction

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
}


def _t(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _md(text: str | None, limit: int = 1024) -> str:
    return _t(escape_markdown(text or ""), limit)


def _when(dt: datetime | None) -> str:
    return format_dt(dt, "R") if dt else "n/a"


def incident_list(incidents: list[Incident], status: str, severity: str | None) -> discord.Embed:
    title = f"Sentinel incidents - {status}" + (f" / {severity}" if severity else "")
    embed = discord.Embed(title=title, color=discord.Color.blurple())
    if not incidents:
        embed.description = "No incidents match this filter."
        return embed
    lines = []
    for i in incidents:
        owner = _md(i.owner, 60) if i.owner else "unassigned"
        lines.append(
            f"**#{i.number}** `{i.severity.upper():<13}` `{i.status:<6}` {_md(i.title, 90)}\n"
            f"-# {i.alerts_count} alert(s) | {owner} | created {_when(i.created)}"
        )
    embed.description = _t("\n".join(lines), 4000)
    embed.set_footer(text="Use /incident show <number> for details")
    return embed


def incident_detail(incident: Incident, entities: list[Entity]) -> discord.Embed:
    embed = discord.Embed(
        title=_t(f"#{incident.number} - {incident.title}", 256),
        url=incident.url,
        description=_md(incident.description, 1000) or None,
        color=SEVERITY_COLORS.get(incident.severity, discord.Color.default()),
    )
    embed.add_field(name="Severity", value=incident.severity)
    embed.add_field(name="Status", value=incident.status)
    embed.add_field(name="Owner", value=_md(incident.owner, 100) if incident.owner else "unassigned")
    embed.add_field(name="Alerts", value=str(incident.alerts_count))
    embed.add_field(name="Created", value=_when(incident.created))
    if incident.classification:
        embed.add_field(name="Classification", value=incident.classification)
    if incident.tactics:
        embed.add_field(name="MITRE tactics", value=_md(", ".join(incident.tactics)), inline=False)
    if incident.products:
        embed.add_field(name="Sources", value=_md(", ".join(incident.products)), inline=False)

    grouped: dict[str, list[str]] = defaultdict(list)
    for entity in entities:
        grouped[entity.kind].append(entity.name)
    for kind, names in list(grouped.items())[:8]:
        shown = ", ".join(f"`{escape_markdown(n)}`" for n in names[:10])
        if len(names) > 10:
            shown += f" (+{len(names) - 10} more)"
        embed.add_field(name=f"{kind} entities", value=_t(shown, 1024), inline=False)

    embed.set_footer(text=f"Incident ID {incident.id}")
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
            embed.add_field(name=name, value=_md(value, 200))
    if report.errors:
        embed.add_field(name="Warnings", value=_md("; ".join(report.errors)), inline=False)
    return embed


def close_confirm(incident: Incident, label: str, comment: str) -> discord.Embed:
    embed = discord.Embed(
        title=f"Close incident #{incident.number}?",
        description=_md(incident.title, 500),
        color=discord.Color.orange(),
    )
    embed.add_field(name="Classification", value=label, inline=False)
    embed.add_field(name="Comment", value=_md(comment), inline=False)
    embed.set_footer(text="Confirm within 60 seconds")
    return embed


def comment_status(commented: bool) -> str:
    return "Audit comment added" if commented else "WARNING: audit comment failed - add one manually"


def incident_closed(incident: Incident, actor: str, commented: bool) -> discord.Embed:
    embed = discord.Embed(
        title=f"Incident #{incident.number} closed",
        description=_md(incident.title, 500),
        url=incident.url,
        color=discord.Color.green(),
    )
    embed.add_field(name="Classification", value=incident.classification or "n/a")
    embed.add_field(name="Closed by", value=_md(actor, 100))
    embed.set_footer(text=comment_status(commented))
    return embed


def device_action_confirm(
    machine: Machine, verb: str, reason: str, isolation_type: str | None, incident: Incident
) -> discord.Embed:
    embed = discord.Embed(
        title=f"{verb} device {machine.name}?",
        color=discord.Color.red() if verb == "Isolate" else discord.Color.orange(),
    )
    embed.add_field(name="Device ID", value=f"`{machine.id}`", inline=False)
    embed.add_field(name="OS", value=machine.os_platform or "n/a")
    embed.add_field(name="Health", value=machine.health_status or "n/a")
    embed.add_field(name="Risk", value=machine.risk_score or "n/a")
    embed.add_field(name="Last IP", value=machine.last_ip or "n/a")
    embed.add_field(name="Last seen", value=_when(machine.last_seen))
    if isolation_type:
        embed.add_field(name="Isolation type", value=isolation_type)
    embed.add_field(name="Linked incident", value=f"#{incident.number} - {_md(incident.title, 200)}", inline=False)
    embed.add_field(name="Reason", value=_md(reason), inline=False)
    embed.set_footer(text="Confirm within 60 seconds")
    return embed


def device_action_result(
    machine: Machine, action: MachineAction, actor: str, incident: Incident, commented: bool
) -> discord.Embed:
    embed = discord.Embed(
        title=f"{action.type} submitted for {machine.name}",
        description="Track progress in the Defender portal Action center.",
        color=discord.Color.green(),
    )
    embed.add_field(name="Action ID", value=f"`{action.id}`", inline=False)
    embed.add_field(name="Status", value=action.status or "Pending")
    embed.add_field(name="Requested by", value=_md(actor, 100))
    embed.add_field(name="Incident", value=f"#{incident.number}")
    embed.set_footer(text=comment_status(commented))
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
    embed.add_field(name="Target", value=_md(str(entry.get("target")), 200))
    embed.add_field(name="Outcome", value=outcome)
    extras = {k: v for k, v in entry.items() if k not in {"ts", "actor", "actor_id", "action", "target", "outcome"}}
    if extras:
        embed.add_field(
            name="Details",
            value=_t("\n".join(f"{k}: {escape_markdown(str(v))}" for k, v in extras.items()), 1024),
            inline=False,
        )
    embed.set_footer(text=entry.get("ts", ""))
    return embed
