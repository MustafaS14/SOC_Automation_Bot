"""Splunk REST search (:8089) and HTTP Event Collector clients."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from .base import APIError, raise_for_status

log = logging.getLogger("soc_bot")


class SplunkClient:
    service = "Splunk"

    def __init__(self, *, http: httpx.AsyncClient, base_url: str, token: str):
        self._http = http
        self._base = base_url.rstrip("/")
        self._token = token

    async def search(self, spl: str, earliest: str = "-1h", latest: str = "now") -> list[dict[str, Any]]:
        """Run a one-shot search; callers must pass SPL built from validated templates only."""
        try:
            resp = await self._http.post(
                f"{self._base}/services/search/jobs/export",
                headers={"Authorization": f"Bearer {self._token}"},
                data={"search": spl, "earliest_time": earliest, "latest_time": latest, "output_mode": "json"},
            )
        except httpx.HTTPError as exc:
            raise APIError(self.service, 502, f"{type(exc).__name__} reaching Splunk") from exc
        raise_for_status(self.service, resp)
        rows: list[dict[str, Any]] = []
        for line in resp.text.splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
                rows.append(obj["result"])
        return rows


class HecClient:
    """Forwards audit entries to Splunk; failures are logged, never raised."""

    def __init__(self, *, http: httpx.AsyncClient, url: str, token: str, index: str = "soc_audit"):
        self._http = http
        self._url = url
        self._token = token
        self._index = index

    async def send(self, event: dict[str, Any]) -> None:
        try:
            resp = await self._http.post(
                self._url,
                headers={"Authorization": f"Splunk {self._token}"},
                json={"event": event, "sourcetype": "soc_bot:audit", "index": self._index},
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("Failed to forward audit entry to Splunk HEC: %s", type(exc).__name__)
