from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.app_commands import Choice
from discord.ext import commands

from ... import hunts
from ...clients import NotConfiguredError
from ...rbac import Permission
from .. import embeds
from ..checks import require

if TYPE_CHECKING:
    from ..bot import SocBot

HUNT_CHOICES = [Choice(name=h.label, value=key) for key, h in hunts.HUNTS.items()]
WINDOW_CHOICES = [Choice(name=label, value=key) for key, label in hunts.WINDOWS.items()]


class HuntCog(commands.Cog):
    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="hunt", description="Run a predefined read-only Splunk search")
    @app_commands.describe(
        template="Search template",
        window="Time window",
        target="Hostname or IP (for templates that need one)",
    )
    @app_commands.choices(template=HUNT_CHOICES, window=WINDOW_CHOICES)
    @app_commands.guild_only()
    @require(Permission.READ)
    async def hunt(
        self,
        interaction: discord.Interaction,
        template: str,
        window: str = "1h",
        target: str | None = None,
    ) -> None:
        spl, earliest = hunts.build(template, window, target)
        if self.bot.splunk is None:
            raise NotConfiguredError("Splunk is not configured (SPLUNK_URL / SPLUNK_TOKEN).")
        await interaction.response.defer(thinking=True)
        rows = await self.bot.splunk.search(spl, earliest=earliest)
        await interaction.followup.send(embed=embeds.hunt_results(hunts.HUNTS[template].label, window, rows))
        await self.bot.audit(interaction, "hunt.run", template, "success", notify=False,
                             window=window, target=target, rows=len(rows))
