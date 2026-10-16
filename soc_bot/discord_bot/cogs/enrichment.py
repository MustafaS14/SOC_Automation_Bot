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
    @app_commands.describe(ip="IPv4 or IPv6 address", incident="Optional incident number to record the result on")
    @require(Permission.READ)
    async def enrich(self, interaction: discord.Interaction, ip: str, incident: str | None = None) -> None:
        parse_ip(ip)
        ref = parse_incident_ref(incident) if incident else None
        await self.enrich_ip(interaction, ip, ref)

    async def enrich_ip(self, interaction: discord.Interaction, ip: str, incident_id: int | None) -> None:
        """Shared by /enrich and the alert Enrich button; `ip` is already validated."""
        await interaction.response.defer(thinking=True)
        inc = await self.bot.store.get(incident_id) if incident_id else None
        report = await self.bot.enrichment.enrich_ip(ip)
        embed = embeds.ip_report(report)
        if inc:
            await self.bot.store.add_comment(
                inc.id,
                str(interaction.user),
                f"IP enrichment {report.ip}: verdict {report.verdict}, "
                f"AbuseIPDB {report.abuse_score if report.abuse_score is not None else 'n/a'}/100, "
                f"VirusTotal {report.vt_malicious if report.vt_malicious is not None else 'n/a'} malicious",
            )
            embed.set_footer(text=f"Recorded on incident #{inc.id}")
        await interaction.followup.send(embed=embed)
        await self.bot.audit(interaction, "enrich.ip", report.ip, "success", notify=False,
                             verdict=report.verdict, incident=inc.id if inc else None)
