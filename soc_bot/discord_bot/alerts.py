"""Buttons on alert messages. DynamicItem keeps them working after a bot restart."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, cast

import discord

from ..rbac import Permission
from . import embeds
from .checks import ensure

if TYPE_CHECKING:
    from .bot import SocBot

_ACTIONS = {
    "ack": ("Acknowledge", discord.ButtonStyle.primary, Permission.TRIAGE),
    "enrich": ("Enrich IP", discord.ButtonStyle.secondary, Permission.READ),
    "isolate": ("Isolate host", discord.ButtonStyle.danger, Permission.RESPONSE),
}


class AlertButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"soc:(?P<action>ack|enrich|isolate):(?P<id>[0-9]+)",
):
    def __init__(self, action: str, incident_id: int):
        label, style, _ = _ACTIONS[action]
        super().__init__(
            discord.ui.Button(label=label, style=style, custom_id=f"soc:{action}:{incident_id}")
        )
        self.action = action
        self.incident_id = incident_id

    @classmethod
    async def from_custom_id(
        cls, interaction: discord.Interaction, item: discord.ui.Button, match: re.Match[str], /
    ) -> AlertButton:
        return cls(match["action"], int(match["id"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        bot = cast("SocBot", interaction.client)
        await ensure(interaction, _ACTIONS[self.action][2])
        incident = await bot.store.get(self.incident_id)
        actor = str(interaction.user)

        if self.action == "ack":
            updated = await bot.store.acknowledge(incident.id, actor)
            await interaction.response.send_message(
                embed=embeds.notice(
                    f"Incident **#{updated.id}** acknowledged by {embeds.md(actor, 100)}.", discord.Color.green()
                )
            )
            await bot.audit(interaction, "incident.ack", f"#{incident.id}", "success", notify=False)
        elif self.action == "enrich":
            if not incident.src_ip:
                await interaction.response.send_message(
                    embed=embeds.notice("This incident has no source IP."), ephemeral=True
                )
                return
            await bot.cogs["EnrichmentCog"].enrich_ip(interaction, incident.src_ip, incident.id)  # type: ignore[attr-defined]
        else:
            if not incident.host:
                await interaction.response.send_message(
                    embed=embeds.notice("This incident has no host."), ephemeral=True
                )
                return
            await bot.cogs["ResponseCog"].device_action(  # type: ignore[attr-defined]
                interaction, "Isolate", incident.host, f"Isolation requested from alert #{incident.id}", incident.id
            )

    async def on_error(self, interaction: discord.Interaction, error: Exception) -> None:
        bot = cast("SocBot", interaction.client)
        await bot.handle_error(interaction, f"alert.{self.action}", error)


def alert_view(incident_id: int) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    for action in _ACTIONS:
        view.add_item(AlertButton(action, incident_id))
    return view
