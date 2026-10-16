from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

import discord
import httpx
from aiohttp import web
from discord import app_commands
from discord.ext import commands

from .. import webhook
from ..audit import AuditLogger
from ..clients import (
    APIError,
    EnrichmentClient,
    HecClient,
    NotConfiguredError,
    NotFoundError,
    SplunkClient,
    SshResponseClient,
)
from ..config import Settings
from ..models import Incident
from ..rbac import AccessPolicy
from ..store import IncidentStore
from ..validators import ValidationError
from . import embeds
from .alerts import AlertButton, alert_view
from .checks import AccessDenied
from .cogs import EnrichmentCog, GeneralCog, HuntCog, IncidentCog, ResponseCog

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
        self._splunk_http: httpx.AsyncClient | None = None
        self._web_runner: web.AppRunner | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self.store: IncidentStore
        self.splunk: Any = None
        self.hec: Any = None
        self.ssh: Any = None
        self.enrichment: Any = None

    async def setup_hook(self) -> None:
        await self._init_backends()
        self.add_dynamic_items(AlertButton)
        for cog in (IncidentCog(self), EnrichmentCog(self), HuntCog(self), ResponseCog(self), GeneralCog(self)):
            await self.add_cog(cog)
        self.tree.on_error = self.on_app_command_error  # type: ignore[method-assign]
        await self._start_webhook()

        if self.settings.guild_id:
            guild = discord.Object(id=self.settings.guild_id)
            self.tree.copy_global_to(guild=guild)
            synced = await self.tree.sync(guild=guild)
        else:
            synced = await self.tree.sync()
        log.info("Synced %d application commands", len(synced))

    async def _init_backends(self) -> None:
        s = self.settings
        if s.mock_mode:
            from ..clients import mock

            log.warning("MOCK MODE: using in-memory incidents, Splunk, SSH and TI data")
            self.store = IncidentStore(":memory:")
            await mock.seed_incidents(self.store)
            self.splunk = mock.MockSplunkClient()
            self.ssh = mock.MockSshResponseClient()
            self.enrichment = mock.MockEnrichmentClient()
            return

        self.store = IncidentStore(s.db_path)
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        self.enrichment = EnrichmentClient(
            http=self._http, abuseipdb_key=s.abuseipdb_api_key, virustotal_key=s.virustotal_api_key
        )
        if s.splunk_url:
            # Lab Splunk usually has a self-signed certificate, so TLS verification is configurable.
            self._splunk_http = httpx.AsyncClient(timeout=httpx.Timeout(30.0), verify=s.splunk_verify_tls)
            self.splunk = SplunkClient(http=self._splunk_http, base_url=s.splunk_url, token=s.splunk_token)
            if s.splunk_hec_url:
                self.hec = HecClient(http=self._splunk_http, url=s.splunk_hec_url, token=s.splunk_hec_token)
        if s.responder_hosts:
            self.ssh = SshResponseClient(
                hosts=s.responder_hosts,
                user=s.responder_user,
                key_path=s.responder_ssh_key,
                known_hosts=s.responder_known_hosts,
            )

    async def _start_webhook(self) -> None:
        s = self.settings
        if not s.webhook_secret:
            log.warning("WEBHOOK_SECRET not set: alert webhook disabled")
            return
        app = webhook.create_app(
            self.store, s.webhook_secret, self.post_alert, max_per_minute=s.webhook_rate_limit
        )
        self._web_runner = web.AppRunner(app)
        await self._web_runner.setup()
        await web.TCPSite(self._web_runner, s.webhook_host, s.webhook_port).start()
        log.info("Alert webhook listening on %s:%d", s.webhook_host, s.webhook_port)

    async def post_alert(self, incident: Incident) -> None:
        channel_id = self.settings.alert_channel_id
        if not (channel_id and self.is_ready()):
            log.warning("Alert #%s stored but not posted (no ALERT_CHANNEL_ID or bot not ready)", incident.id)
            return
        channel = self.get_channel(channel_id)
        if isinstance(channel, discord.abc.Messageable):
            await channel.send(embed=embeds.incident_detail(incident), view=alert_view(incident.id))

    async def on_ready(self) -> None:
        log.info("Logged in as %s (%s)", self.user, getattr(self.user, "id", "?"))

    async def close(self) -> None:
        if self._web_runner:
            await self._web_runner.cleanup()
        for client in (self._http, self._splunk_http):
            if client:
                await client.aclose()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if hasattr(self, "store"):
            self.store.shutdown()
        self.audit_log.close()
        await super().close()

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

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
        if self.hec:
            self._spawn(self.hec.send(entry))
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
        command = interaction.command.qualified_name if interaction.command else "unknown"
        await self.handle_error(interaction, command, error)

    async def handle_error(self, interaction: discord.Interaction, command: str, error: Exception) -> None:
        original = getattr(error, "original", error)

        if isinstance(error, AccessDenied):
            message = error.reason
            await self.audit(interaction, command, "-", "denied", reason=error.reason)
        elif isinstance(original, (ValidationError, NotConfiguredError)):
            message = str(original)
        elif isinstance(original, NotFoundError):
            message = original.message
        elif isinstance(original, APIError):
            if original.status == 409:
                message = original.message
            elif original.status in (401, 403):
                message = f"{original.service} rejected the bot's credentials."
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
