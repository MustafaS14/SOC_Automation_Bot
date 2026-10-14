from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from ...rbac import Permission
from ...validators import parse_incident_ref, parse_ip
from .. import embeds
from ..checks import require

if TYPE_CHECKING:
    from ..bot import SocBot


class EnrichmentCog(commands.Cog):
    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="enrich", description="Threat-intel reputation lookup for an IP address")
    @app_commands.guild_only()
    @app_commands.describe(ip="IPv4 or IPv6 address", incident="Optional incident number/GUID to record the result on")
    @require(Permission.READ)
    async def enrich(self, interaction: discord.Interaction, ip: str, incident: str | None = None) -> None:
        parse_ip(ip)
        ref = parse_incident_ref(incident) if incident else None
        await interaction.response.defer(thinking=True)
        inc = await self.bot.sentinel.resolve_incident(ref) if ref else None
        report = await self.bot.enrichment.enrich_ip(ip)
        embed = embeds.ip_report(report)
        commented = None
        if inc:
            commented = await self.bot.comment_incident(
                interaction,
                inc,
                f"IP enrichment {report.ip}: verdict {report.verdict}, "
                f"AbuseIPDB {report.abuse_score if report.abuse_score is not None else 'n/a'}/100, "
                f"VirusTotal {report.vt_malicious if report.vt_malicious is not None else 'n/a'} malicious",
            )
            embed.set_footer(text=f"Incident #{inc.number}: " + embeds.comment_status(commented))
        await interaction.followup.send(embed=embed)
        await self.bot.audit(interaction, "enrich.ip", report.ip, "success", notify=False,
                             verdict=report.verdict, incident=inc.number if inc else None,
                             incident_commented=commented)
