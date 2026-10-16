from __future__ import annotations

from typing import TYPE_CHECKING, cast

import discord
from discord import app_commands

from ..rbac import Permission

if TYPE_CHECKING:
    from .bot import SocBot


class AccessDenied(app_commands.CheckFailure):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


async def ensure(interaction: discord.Interaction, level: Permission) -> None:
    """Enforce guild, channel and role-tier restrictions; shared by slash commands and buttons."""
    bot = cast("SocBot", interaction.client)
    if interaction.guild is None or not isinstance(interaction.user, discord.Member):
        raise AccessDenied("SOC commands are only available inside the SOC server.")
    if bot.settings.guild_id and interaction.guild_id != bot.settings.guild_id:
        raise AccessDenied("This server is not authorised to use the SOC bot.")
    if not bot.policy.channel_allowed(interaction.channel_id):
        raise AccessDenied("This channel is not authorised for SOC commands.")
    if not bot.policy.is_allowed((r.id for r in interaction.user.roles), level):
        raise AccessDenied(f"You need the **{level.name}** SOC role tier (or higher) to run this command.")


def require(level: Permission):
    """App-command check enforcing guild, channel and role-tier restrictions."""

    async def predicate(interaction: discord.Interaction) -> bool:
        await ensure(interaction, level)
        return True

    return app_commands.check(predicate)
