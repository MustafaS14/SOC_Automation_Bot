"""Flask is synchronous, the bot's store and clients are async: one background event loop runs them all."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx

from soc_bot.ai import Assistant, ToolContext, build_assistant
from soc_bot.audit import AuditLogger
from soc_bot.clients import EnrichmentClient, HecClient, SplunkClient
from soc_bot.config import Settings
from soc_bot.store import IncidentStore

log = logging.getLogger("soc_web")
T = TypeVar("T")


class AsyncRunner:
    """Runs coroutines on one event loop in a background thread and hands the result back to the caller."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="soc-web-loop", daemon=True)
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, T], timeout: float = 60.0) -> T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    def spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        """Fire and forget (audit forwarding). A failure is logged, never raised to the request."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        future.add_done_callback(lambda f: f.exception() and log.warning("Background task failed: %s", f.exception()))

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop.close()


@dataclass
class Backends:
    settings: Settings
    runner: AsyncRunner
    store: IncidentStore
    audit_log: AuditLogger
    splunk: Any = None
    hec: Any = None
    enrichment: Any = None
    assistant: Assistant | None = None
    clients: tuple[httpx.AsyncClient, ...] = ()

    def close(self) -> None:
        async def shutdown() -> None:
            for client in self.clients:
                await client.aclose()

        try:
            self.runner.run(shutdown(), timeout=10)
        finally:
            self.store.shutdown()
            self.audit_log.close()


def build_backends(settings: Settings, runner: AsyncRunner) -> Backends:
    """The same data sources as the bot, minus SSH: the console cannot isolate a host."""
    return runner.run(_build(settings, runner))


async def _build(settings: Settings, runner: AsyncRunner) -> Backends:
    s = settings
    audit_log = AuditLogger(s.audit_log_path)
    if s.mock_mode:
        from soc_bot.clients import mock

        store = IncidentStore(":memory:")
        await mock.seed_incidents(store)
        backends = Backends(s, runner, store, audit_log, splunk=mock.MockSplunkClient(),
                            enrichment=mock.MockEnrichmentClient())
    else:
        store = IncidentStore(s.db_path)
        http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        clients = [http]
        backends = Backends(
            s, runner, store, audit_log,
            enrichment=EnrichmentClient(http=http, abuseipdb_key=s.abuseipdb_api_key, virustotal_key=s.virustotal_api_key),
        )
        if s.splunk_url:
            splunk_http = httpx.AsyncClient(timeout=httpx.Timeout(30.0), verify=s.splunk_verify_tls)
            clients.append(splunk_http)
            backends.splunk = SplunkClient(http=splunk_http, base_url=s.splunk_url, token=s.splunk_token)
            if s.splunk_hec_url:
                backends.hec = HecClient(http=splunk_http, url=s.splunk_hec_url, token=s.splunk_hec_token)
        backends.clients = tuple(clients)
    backends.assistant = build_assistant(
        s,
        ToolContext(
            store=store,
            splunk=backends.splunk,
            enrichment=backends.enrichment,
            ssh=None,  # the console never isolates, and neither may the assistant on its behalf
            isolation_denylist=s.isolation_denylist,
            audit_log_path=s.audit_log_path,
            max_rows=s.ai_max_rows,
        ),
    )
    return backends
