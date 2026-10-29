from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from .. import embeds

if TYPE_CHECKING:
    from ..bot import SocBot

HELP_TEXT = """\
**VIEWER**
`/ask <question>` - ask the SOC assistant (answers depend on your tier)

**READ**
`/incident list [status] [severity] [limit]` - list incidents
`/incident show <incident>` - details + comments
`/enrich <ip> [incident]` - AbuseIPDB / VirusTotal reputation
`/hunt <template> [window] [target]` - predefined Splunk search

**TRIAGE**
`/incident comment <incident> <message>` - add a comment
`/incident close <incident> <classification> <comment>` - close incident

**RESPONSE**
`/isolate <host> <reason> <incident>` - isolate host over SSH
`/unisolate <host> <reason> <incident>` - release host
"""


class GeneralCog(commands.Cog):
    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="soc-help", description="Show SOC bot commands and your access tier")
    @app_commands.guild_only()
    async def soc_help(self, interaction: discord.Interaction) -> None:
        roles = getattr(interaction.user, "roles", [])
        level = self.bot.policy.level_for(r.id for r in roles)
        embed = embeds.notice(HELP_TEXT, discord.Color.blurple())
        embed.title = "SOC Bot commands"
        embed.set_footer(text=f"Your tier: {level.name if level else 'none'}"
                         + (" | MOCK MODE" if self.bot.settings.mock_mode else ""))
        await interaction.response.send_message(embed=embed, ephemeral=True)
