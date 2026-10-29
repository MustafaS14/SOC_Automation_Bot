from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from ...ai.tools import LEVEL_LABELS
from ...clients import NotConfiguredError
from ...rbac import Permission
from .. import embeds
from ..checks import require

if TYPE_CHECKING:
    from ..bot import SocBot


class AskCog(commands.Cog):
    """Questions for the read-only SOC assistant. What it may look up depends on the asker's tier."""

    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="ask", description="Ask the SOC assistant about incidents and data")
    @app_commands.describe(question="Your question (up to 500 characters)")
    @app_commands.guild_only()
    @require(Permission.VIEWER)
    async def ask(self, interaction: discord.Interaction, question: app_commands.Range[str, 1, 500]) -> None:
        if self.bot.assistant is None:
            raise NotConfiguredError("The AI assistant is not enabled (AI_BACKEND).")
        roles = getattr(interaction.user, "roles", [])
        level = self.bot.policy.level_for(r.id for r in roles) or Permission.VIEWER
        await interaction.response.defer(thinking=True)
        answer = await self.bot.assistant.ask(question, level, interaction.user.id)
        await interaction.followup.send(embed=embeds.ai_answer(question, answer.text))
        await self.bot.audit(
            interaction, "ai.ask", LEVEL_LABELS[level], answer.outcome, notify=False,
            tools=",".join(answer.tools_used) or None, denied=True if answer.denied else None,
            calls=answer.calls, question=question[:200],
        )
