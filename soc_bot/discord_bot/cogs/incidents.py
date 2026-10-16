from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.app_commands import Choice
from discord.ext import commands

from ...rbac import Permission
from ...store import SEVERITIES
from ...validators import parse_incident_ref
from .. import embeds
from ..checks import require
from ..views import ConfirmView

if TYPE_CHECKING:
    from ..bot import SocBot

STATUS_CHOICES = [
    Choice(name="Open (New + Active)", value="open"),
    Choice(name="New", value="new"),
    Choice(name="Active", value="active"),
    Choice(name="Closed", value="closed"),
    Choice(name="All", value="all"),
]
SEVERITY_CHOICES = [Choice(name=s, value=s) for s in SEVERITIES]
CLOSE_CHOICES = [
    Choice(name="True Positive", value="true_positive"),
    Choice(name="False Positive", value="false_positive"),
    Choice(name="Benign", value="benign"),
]
CLOSE_LABELS = {c.value: c.name for c in CLOSE_CHOICES}


@app_commands.guild_only()
class IncidentCog(
    commands.GroupCog, group_name="incident", group_description="Splunk alert incident triage"
):
    def __init__(self, bot: SocBot):
        self.bot = bot

    @app_commands.command(name="list", description="List recent incidents")
    @app_commands.describe(status="Incident status filter", severity="Only this severity", limit="How many (1-25)")
    @app_commands.choices(status=STATUS_CHOICES, severity=SEVERITY_CHOICES)
    @require(Permission.READ)
    async def list_incidents(
        self,
        interaction: discord.Interaction,
        status: str = "open",
        severity: str | None = None,
        limit: app_commands.Range[int, 1, 25] = 10,
    ) -> None:
        await interaction.response.defer(thinking=True)
        incidents = await self.bot.store.list(status=status, severity=severity, limit=limit)
        await interaction.followup.send(embed=embeds.incident_list(incidents, status, severity))
        await self.bot.audit(interaction, "incident.list", status, "success", notify=False,
                             severity=severity, count=len(incidents))

    @app_commands.command(name="show", description="Show incident details and comments")
    @app_commands.describe(incident="Incident number (e.g. 12)")
    @require(Permission.READ)
    async def show(self, interaction: discord.Interaction, incident: str) -> None:
        ref = parse_incident_ref(incident)
        await interaction.response.defer(thinking=True)
        inc = await self.bot.store.get(ref)
        await interaction.followup.send(embed=embeds.incident_detail(inc))
        await self.bot.audit(interaction, "incident.show", f"#{inc.id}", "success", notify=False)

    @app_commands.command(name="comment", description="Add a comment to an incident")
    @app_commands.describe(incident="Incident number", message="Comment text")
    @require(Permission.TRIAGE)
    async def comment(
        self,
        interaction: discord.Interaction,
        incident: str,
        message: app_commands.Range[str, 1, 1000],
    ) -> None:
        ref = parse_incident_ref(incident)
        await interaction.response.defer(thinking=True)
        await self.bot.store.add_comment(ref, str(interaction.user), message)
        await interaction.followup.send(
            embed=embeds.notice(f"Comment added to incident **#{ref}**.", discord.Color.green())
        )
        await self.bot.audit(interaction, "incident.comment", f"#{ref}", "success", message=message)

    @app_commands.command(name="close", description="Close an incident with a classification")
    @app_commands.describe(
        incident="Incident number",
        classification="Closing classification",
        comment="Why the incident is being closed",
    )
    @app_commands.choices(classification=CLOSE_CHOICES)
    @require(Permission.TRIAGE)
    async def close(
        self,
        interaction: discord.Interaction,
        incident: str,
        classification: str,
        comment: app_commands.Range[str, 3, 1000],
    ) -> None:
        ref = parse_incident_ref(incident)
        await interaction.response.defer(thinking=True)
        inc = await self.bot.store.get(ref)
        if inc.status == "Closed":
            await interaction.edit_original_response(
                embed=embeds.notice(f"Incident **#{inc.id}** is already closed.")
            )
            return

        label = CLOSE_LABELS[classification]
        view = ConfirmView(interaction.user.id)
        await interaction.edit_original_response(embed=embeds.close_confirm(inc, label, comment), view=view)
        if not await view.ask():
            await interaction.edit_original_response(
                embed=embeds.notice(f"Closing incident #{inc.id} cancelled."), view=None
            )
            await self.bot.audit(interaction, "incident.close", f"#{inc.id}", "cancelled")
            return

        actor = str(interaction.user)
        updated = await self.bot.store.close(inc.id, classification, comment, actor)
        await interaction.edit_original_response(embed=embeds.incident_closed(updated, actor), view=None)
        await self.bot.audit(interaction, "incident.close", f"#{inc.id}", "success",
                             classification=label, comment=comment)
