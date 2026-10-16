from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from ...clients import NotConfiguredError
from ...rbac import Permission
from ...validators import is_protected_host, parse_hostname, parse_incident_ref
from .. import embeds
from ..checks import require
from ..views import ConfirmView

if TYPE_CHECKING:
    from ..bot import SocBot


class ResponseCog(commands.Cog):
    """Containment actions over SSH on lab hosts."""

    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="isolate", description="Network-isolate a host (management SSH stays open)")
    @app_commands.describe(
        host="Hostname from the responder inventory",
        reason="Justification (recorded in the incident and the audit log)",
        incident="Incident number this containment belongs to",
    )
    @app_commands.guild_only()
    @require(Permission.RESPONSE)
    async def isolate(
        self,
        interaction: discord.Interaction,
        host: str,
        reason: app_commands.Range[str, 5, 500],
        incident: str,
    ) -> None:
        await self.device_action(
            interaction, "Isolate", parse_hostname(host), reason, parse_incident_ref(incident)
        )

    @app_commands.command(name="unisolate", description="Release a host from network isolation")
    @app_commands.describe(
        host="Hostname from the responder inventory",
        reason="Justification for release",
        incident="Incident number this release belongs to",
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
        await self.device_action(
            interaction, "Unisolate", parse_hostname(host), reason, parse_incident_ref(incident)
        )

    async def device_action(
        self,
        interaction: discord.Interaction,
        verb: str,
        hostname: str,
        reason: str,
        incident_id: int,
    ) -> None:
        """Shared by the slash commands and the alert Isolate button; `hostname` is already validated."""
        action_name = f"device.{verb.lower()}"
        if self.bot.ssh is None:
            raise NotConfiguredError("Host isolation is not configured (RESPONDER_HOSTS / RESPONDER_SSH_KEY).")
        if verb == "Isolate" and await self._blocked(interaction, action_name, hostname):
            return

        await interaction.response.defer(thinking=True)
        incident = await self.bot.store.get(incident_id)
        address = self.bot.ssh.resolve(hostname)

        view = ConfirmView(interaction.user.id)
        await interaction.edit_original_response(
            embed=embeds.isolation_confirm(verb, hostname, address, reason, incident), view=view
        )
        if not await view.ask():
            await interaction.edit_original_response(
                embed=embeds.notice(f"{verb} of `{hostname}` cancelled."), view=None
            )
            await self.bot.audit(interaction, action_name, hostname, "cancelled")
            return

        await interaction.edit_original_response(
            embed=embeds.notice(f"Running {verb.lower()} on `{hostname}`..."), view=None
        )
        actor = str(interaction.user)
        if verb == "Isolate":
            result = await self.bot.ssh.isolate(hostname)
        else:
            result = await self.bot.ssh.unisolate(hostname)

        await self.bot.store.add_comment(
            incident.id, actor, f"{verb} executed on {hostname} ({address}). Reason: {reason}"
        )
        await interaction.edit_original_response(embed=embeds.isolation_result(result, actor, incident))
        await self.bot.audit(
            interaction, action_name, hostname, "success",
            address=address, reason=reason, incident=incident.id,
        )

    async def _blocked(self, interaction: discord.Interaction, action: str, hostname: str) -> bool:
        if not is_protected_host(hostname, self.bot.settings.isolation_denylist):
            return False
        message = (
            f"`{hostname}` is on the isolation deny-list (critical asset). "
            "Isolate it manually through the change-approval process."
        )
        if interaction.response.is_done():
            await interaction.edit_original_response(embed=embeds.error(message), view=None)
        else:
            await interaction.response.send_message(embed=embeds.error(message), ephemeral=True)
        await self.bot.audit(interaction, action, hostname, "blocked", reason="deny-list")
        return True
