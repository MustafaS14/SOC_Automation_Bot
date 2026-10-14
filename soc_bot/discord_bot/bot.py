from __future__ import annotations

import html
import logging
from typing import Any

import discord
import httpx
from discord import app_commands
from discord.ext import commands

from ..audit import AuditLogger
from ..clients import APIError, DefenderClient, EnrichmentClient, NotFoundError, SentinelClient
from ..config import Settings
from ..models import Incident
from ..rbac import AccessPolicy
from ..validators import ValidationError
from . import embeds
from .checks import AccessDenied
from .cogs import EnrichmentCog, GeneralCog, IncidentCog, ResponseCog

log = logging.getLogger("soc_bot")


class SocBot(commands.Bot):
    def __init__(self, settings: Settings):
        super().__init__(
            command_prefix=commands.when_mentioned,
            intents=discord.Intents.default(),
            allowed_mentions=discord.AllowedMentions.none(),
            help_command=None,
        )
        self.settings = settings
        self.policy = AccessPolicy(
            read_role_ids=settings.read_role_ids,
            triage_role_ids=settings.triage_role_ids,
            response_role_ids=settings.response_role_ids,
            allowed_channel_ids=settings.allowed_channel_ids,
        )
        self.audit_log = AuditLogger(settings.audit_log_path)
        self._http: httpx.AsyncClient | None = None
        self._credential: Any = None
        self.sentinel: Any = None
        self.defender: Any = None
        self.enrichment: Any = None

    async def setup_hook(self) -> None:
        self._init_clients()
        for cog in (IncidentCog(self), EnrichmentCog(self), ResponseCog(self), GeneralCog(self)):
            await self.add_cog(cog)
        self.tree.on_error = self.on_app_command_error  # type: ignore[method-assign]

        if self.settings.guild_id:
            guild = discord.Object(id=self.settings.guild_id)
            self.tree.copy_global_to(guild=guild)
            synced = await self.tree.sync(guild=guild)
        else:
            synced = await self.tree.sync()
        log.info("Synced %d application commands", len(synced))

    def _init_clients(self) -> None:
        s = self.settings
        if s.mock_mode:
            from ..clients.mock import MockDefenderClient, MockEnrichmentClient, MockSentinelClient

            log.warning("MOCK MODE: using in-memory Sentinel/Defender/TI data")
            self.sentinel = MockSentinelClient()
            self.defender = MockDefenderClient()
            self.enrichment = MockEnrichmentClient()
            return

        from azure.identity.aio import DefaultAzureCredential

        self._http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        self._credential = DefaultAzureCredential()
        self.sentinel = SentinelClient(
            subscription_id=s.subscription_id,
            resource_group=s.resource_group,
            workspace_name=s.workspace_name,
            credential=self._credential,
            http=self._http,
            api_version=s.sentinel_api_version,
        )
        self.defender = DefenderClient(credential=self._credential, http=self._http, api_base=s.defender_api_base)
        self.enrichment = EnrichmentClient(
            http=self._http, abuseipdb_key=s.abuseipdb_api_key, virustotal_key=s.virustotal_api_key
        )

    async def on_ready(self) -> None:
        log.info("Logged in as %s (%s)", self.user, getattr(self.user, "id", "?"))

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()
        if self._credential:
            await self._credential.close()
        self.audit_log.close()
        await super().close()

    async def comment_incident(
        self, interaction: discord.Interaction, incident: Incident, text: str
    ) -> bool:
        """Best-effort audit comment on a Sentinel incident; never fails the primary action."""
        message = f"[SOC Bot] {text} (by {interaction.user} / {interaction.user.id})"
        try:
            # Sentinel renders comments as HTML.
            await self.sentinel.add_comment(incident.id, html.escape(message))
            return True
        except APIError as exc:
            log.warning("Failed to comment on incident #%s: %s", incident.number, exc)
            return False

    async def audit(
        self,
        interaction: discord.Interaction,
        action: str,
        target: str,
        outcome: str,
        *,
        notify: bool = True,
        **details: Any,
    ) -> None:
        entry = self.audit_log.record(
            actor=str(interaction.user),
            actor_id=interaction.user.id,
            action=action,
            target=target,
            outcome=outcome,
            channel_id=interaction.channel_id,
            **{k: v for k, v in details.items() if v is not None},
        )
        if not (notify and self.settings.audit_channel_id):
            return
        channel = self.get_channel(self.settings.audit_channel_id)
        if isinstance(channel, discord.abc.Messageable):
            try:
                await channel.send(embed=embeds.audit_entry(entry))
            except discord.HTTPException:
                log.warning("Failed to post audit entry to channel %s", self.settings.audit_channel_id)

    async def on_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ) -> None:
        original = getattr(error, "original", error)
        command = interaction.command.qualified_name if interaction.command else "unknown"

        if isinstance(error, AccessDenied):
            message = error.reason
            await self.audit(interaction, command, "-", "denied", reason=error.reason)
        elif isinstance(original, ValidationError):
            message = str(original)
        elif isinstance(original, NotFoundError):
            message = original.message
        elif isinstance(original, APIError):
            if original.status == 412:
                message = "The incident was modified by someone else. Re-run the command to retry."
            elif original.status in (401, 403):
                message = f"The bot's Azure identity is not authorised for this {original.service} action."
            else:
                message = f"{original.service} returned {original.status}: {original.message}"
            await self.audit(interaction, command, "-", "error", status=original.status, error=original.message)
        else:
            log.exception("Unhandled error in /%s", command, exc_info=original)
            message = "Unexpected error - check the bot logs."
            await self.audit(interaction, command, "-", "error", error=type(original).__name__)

        try:
            if interaction.response.is_done():
                await interaction.edit_original_response(embed=embeds.error(message), view=None, content=None)
            else:
                await interaction.response.send_message(embed=embeds.error(message), ephemeral=True)
        except discord.HTTPException:
            log.warning("Could not deliver error message for /%s", command)
