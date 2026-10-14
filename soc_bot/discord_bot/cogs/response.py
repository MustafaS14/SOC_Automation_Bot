from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.app_commands import Choice
from discord.ext import commands

from ...rbac import Permission
from ...validators import is_protected_host, parse_hostname, parse_incident_ref
from .. import embeds
from ..checks import require
from ..views import ConfirmView

if TYPE_CHECKING:
    from ..bot import SocBot

ISOLATION_CHOICES = [
    Choice(name="Full - block all network traffic except Defender", value="Full"),
    Choice(name="Selective - also allow Outlook/Teams/Skype", value="Selective"),
]


class ResponseCog(commands.Cog):
    """Containment actions via Microsoft Defender for Endpoint."""

    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="isolate", description="Network-isolate a device via Defender for Endpoint")
    @app_commands.describe(
        host="Device hostname (short name or FQDN)",
        reason="Justification (recorded in MDE, Sentinel and the audit log)",
        incident="Sentinel incident number/GUID this containment belongs to",
        isolation_type="Full (default) or Selective isolation",
    )
    @app_commands.choices(isolation_type=ISOLATION_CHOICES)
    @app_commands.guild_only()
    @require(Permission.RESPONSE)
    async def isolate(
        self,
        interaction: discord.Interaction,
        host: str,
        reason: app_commands.Range[str, 5, 500],
        incident: str,
        isolation_type: str = "Full",
    ) -> None:
        await self._device_action(interaction, "Isolate", host, reason, incident, isolation_type)

    @app_commands.command(name="unisolate", description="Release a device from network isolation")
    @app_commands.describe(
        host="Device hostname (short name or FQDN)",
        reason="Justification for release",
        incident="Sentinel incident number/GUID this release belongs to",
    )
    @app_commands.guild_only()
    @require(Permission.RESPONSE)
    async def unisolate(
        self,
        interaction: discord.Interaction,
        host: str,
        reason: app_commands.Range[str, 5, 500],
        incident: str,
    ) -> None:
        await self._device_action(interaction, "Unisolate", host, reason, incident, None)

    async def _device_action(
        self,
        interaction: discord.Interaction,
        verb: str,
        host: str,
        reason: str,
        incident_ref: str,
        isolation_type: str | None,
    ) -> None:
        action_name = f"device.{verb.lower()}"
        hostname = parse_hostname(host)
        ref = parse_incident_ref(incident_ref)
        if verb == "Isolate" and await self._blocked(interaction, action_name, hostname):
            return

        await interaction.response.defer(thinking=True)
        incident = await self.bot.sentinel.resolve_incident(ref)
        machine = await self.bot.defender.find_machine(hostname)
        if verb == "Isolate" and await self._blocked(interaction, action_name, machine.name.lower()):
            return

        view = ConfirmView(interaction.user.id)
        await interaction.edit_original_response(
            embed=embeds.device_action_confirm(machine, verb, reason, isolation_type, incident), view=view
        )
        if not await view.ask():
            await interaction.edit_original_response(
                embed=embeds.notice(f"{verb} of `{machine.name}` cancelled."), view=None
            )
            await self.bot.audit(interaction, action_name, machine.name, "cancelled")
            return

        await interaction.edit_original_response(
            embed=embeds.notice(f"Submitting {verb.lower()} request for `{machine.name}`..."), view=None
        )
        actor = str(interaction.user)
        mde_comment = (
            f"{reason} | via SOC Bot by {actor} ({interaction.user.id}) | Sentinel incident #{incident.number}"
        )

        if verb == "Isolate":
            action = await self.bot.defender.isolate(machine.id, mde_comment, isolation_type or "Full")
        else:
            action = await self.bot.defender.unisolate(machine.id, mde_comment)

        commented = await self.bot.comment_incident(
            interaction,
            incident,
            f"{verb} requested for device {machine.name}. Reason: {reason}. MDE action ID: {action.id}",
        )

        await interaction.edit_original_response(
            embed=embeds.device_action_result(machine, action, actor, incident, commented)
        )
        await self.bot.audit(
            interaction, action_name, machine.name, "success",
            machine_id=machine.id, action_id=action.id, reason=reason,
            isolation_type=isolation_type, incident=incident.number, incident_commented=commented,
        )

    async def _blocked(self, interaction: discord.Interaction, action: str, hostname: str) -> bool:
        if not is_protected_host(hostname, self.bot.settings.isolation_denylist):
            return False
        message = (
            f"`{hostname}` is on the isolation deny-list (critical asset). "
            "Isolate it from the Defender portal through the change-approval process."
        )
        if interaction.response.is_done():
            await interaction.edit_original_response(embed=embeds.error(message), view=None)
        else:
            await interaction.response.send_message(embed=embeds.error(message), ephemeral=True)
        await self.bot.audit(interaction, action, hostname, "blocked", reason="deny-list")
        return True
