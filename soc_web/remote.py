"""Read-only client for the bot's incident API: the same read methods as the local store, over HTTP.

`RemoteIncidentStore` is a drop-in for `IncidentStore` where the console and the assistant tools only read (`list`,
`get`, `counts`). The write methods exist so a slip cannot reach a local database by accident, and all of them refuse.
Short timeouts, one attempt, no retries: when soc-siem is down the caller gets a clear error straight away.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from soc_bot.clients.base import APIError, NotFoundError
from soc_bot.models import Comment, Incident, _parse_dt, parse_techniques

SERVICE = "soc-siem"
TIMEOUT = httpx.Timeout(5.0, connect=3.0)
READ_ONLY = "This console shows live data from soc-siem and is read-only here. Use the Discord bot to change incidents."


class ReadOnlyError(APIError):
    """A write was attempted in remote mode. Status 405, with a message that is safe to show."""

    def __init__(self) -> None:
        super().__init__(SERVICE, 405, READ_ONLY)


def _incident(data: dict[str, Any]) -> Incident:
    comments = [
        Comment(author=str(c.get("author") or ""), body=str(c.get("body") or ""), created=_parse_dt(c.get("created")))
        for c in data.get("comments") or []
        if isinstance(c, dict)
    ]
    return Incident(
        id=int(data["id"]), rule=str(data.get("rule") or ""), severity=str(data.get("severity") or ""),
        status=str(data.get("status") or ""), host=data.get("host"), src_ip=data.get("src_ip"),
        assignee=data.get("assignee"), description=str(data.get("description") or ""), url=data.get("url"),
        classification=data.get("classification"), created=_parse_dt(data.get("created")),
        updated=_parse_dt(data.get("updated")), comments=comments,
        techniques=parse_techniques(data.get("techniques")),
    )


class RemoteIncidentStore:
    remote = True

    def __init__(self, base_url: str, secret: str, *, http: httpx.AsyncClient | None = None):
        self._base = base_url.rstrip("/")
        # The secret lives only in the header of this client. It is never put in a URL, a message or a log line.
        self._http = http or httpx.AsyncClient(timeout=TIMEOUT, headers={"X-Api-Secret": secret})
        self._owns_http = http is None
        if http is not None:
            self._http.headers["X-Api-Secret"] = secret

    async def _get(self, path: str, **params: Any) -> Any:
        try:
            resp = await self._http.get(self._base + path, params={k: v for k, v in params.items() if v is not None})
        except httpx.TimeoutException as exc:
            raise APIError(SERVICE, 504, "soc-siem did not answer in time.") from exc
        except httpx.HTTPError as exc:
            raise APIError(SERVICE, 503, "soc-siem is unreachable.") from exc
        if resp.status_code == 404:
            raise NotFoundError(SERVICE, 404, "Incident not found")
        if resp.status_code in (401, 403):
            raise APIError(SERVICE, resp.status_code, "The incident API rejected the console's secret.")
        if resp.status_code == 429:
            raise APIError(SERVICE, 429, "The incident API is rate limiting the console. Try again in a minute.")
        if resp.status_code != 200:
            raise APIError(SERVICE, resp.status_code, "The incident API returned an error.")
        try:
            return resp.json()
        except ValueError as exc:
            raise APIError(SERVICE, 502, "The incident API sent something that is not JSON.") from exc

    async def list(self, status: str = "open", severity: str | None = None, limit: int = 10,
                   order: str = "newest", technique: str | None = None) -> list[Incident]:
        body = await self._get("/api/incidents", status=status, severity=severity, limit=limit, order=order,
                               technique=technique)
        try:
            return [_incident(row) for row in body["incidents"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise APIError(SERVICE, 502, "The incident API sent an unexpected answer.") from exc

    async def get(self, incident_id: int) -> Incident:
        body = await self._get(f"/api/incidents/{int(incident_id)}")
        try:
            return _incident(body)
        except (KeyError, TypeError, ValueError) as exc:
            raise APIError(SERVICE, 502, "The incident API sent an unexpected answer.") from exc

    async def counts(self) -> dict[str, dict[str, int]]:
        body = await self._get("/api/counts")
        try:
            return {"status": dict(body["status"]), "open_by_severity": dict(body["open_by_severity"])}
        except (KeyError, TypeError, ValueError) as exc:
            raise APIError(SERVICE, 502, "The incident API sent an unexpected answer.") from exc

    async def timeline(self, start: datetime, end: datetime, bucket: int) -> dict[str, list[int]]:
        """Incident counts per time slot and rule, from soc-siem. An older bot without the route gets a clear message."""
        try:
            body = await self._get("/api/timeline", start=int(start.timestamp()), end=int(end.timestamp()), bucket=bucket)
        except NotFoundError as exc:
            raise APIError(SERVICE, 404, "soc-siem runs an older bot without the timeline route. Update and restart it.") from exc
        try:
            return {str(rule): [int(n) for n in counts] for rule, counts in dict(body["series"]).items()}
        except (KeyError, TypeError, ValueError) as exc:
            raise APIError(SERVICE, 502, "The incident API sent an unexpected answer.") from exc

    async def audit(self, *, offset: int = 0, limit: int = 50, **filters: Any) -> tuple[list[dict[str, Any]], int]:
        """The bot's audit entries (what happened in Discord), newest first. Older bots without the route give a clear error."""
        try:
            body = await self._get("/api/audit", offset=offset, limit=limit, **{k: v for k, v in filters.items() if v})
        except NotFoundError as exc:
            raise APIError(SERVICE, 404, "soc-siem runs an older bot without the audit route. Update and restart it.") from exc
        try:
            return [e for e in body["entries"] if isinstance(e, dict)], int(body["total"])
        except (KeyError, TypeError, ValueError) as exc:
            raise APIError(SERVICE, 502, "The incident API sent an unexpected answer.") from exc

    # ---- writes: refused, and never sent anywhere ------------------------------------------------------------

    async def create(self, *args: Any, **kwargs: Any) -> Incident:
        raise ReadOnlyError

    async def add_comment(self, *args: Any, **kwargs: Any) -> None:
        raise ReadOnlyError

    async def acknowledge(self, *args: Any, **kwargs: Any) -> Incident:
        raise ReadOnlyError

    async def close(self, *args: Any, **kwargs: Any) -> Incident:
        raise ReadOnlyError

    def shutdown(self) -> None:
        """Called from the console's own thread after the loop work is done; the client is closed by `aclose`."""

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()
