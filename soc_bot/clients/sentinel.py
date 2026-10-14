"""Thin async client for the Microsoft Sentinel (SecurityInsights) REST API.

Docs: https://learn.microsoft.com/rest/api/securityinsights/
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from ..models import Entity, Incident
from .base import AsyncTokenCredential, NotFoundError, bearer_headers, raise_for_status

ARM_SCOPE = "https://management.azure.com/.default"

# Classification -> reason pairs accepted by the Sentinel API.
CLOSE_OPTIONS: dict[str, tuple[str, str | None]] = {
    "tp_suspicious": ("TruePositive", "SuspiciousActivity"),
    "bp_expected": ("BenignPositive", "SuspiciousButExpected"),
    "fp_logic": ("FalsePositive", "IncorrectAlertLogic"),
    "fp_data": ("FalsePositive", "InaccurateData"),
    "undetermined": ("Undetermined", None),
}

STATUS_FILTERS = {
    "open": "properties/status ne 'Closed'",
    "new": "properties/status eq 'New'",
    "active": "properties/status eq 'Active'",
    "closed": "properties/status eq 'Closed'",
    "all": None,
}

SEVERITIES = ("High", "Medium", "Low", "Informational")


class SentinelClient:
    service = "Sentinel"

    def __init__(
        self,
        *,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
        credential: AsyncTokenCredential,
        http: httpx.AsyncClient,
        api_version: str = "2024-03-01",
    ):
        self._base = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )
        self._credential = credential
        self._http = http
        self._api_version = api_version

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        params = {"api-version": self._api_version, **kwargs.pop("params", {})}
        headers = await bearer_headers(self._credential, ARM_SCOPE)
        resp = await self._http.request(
            method, f"{self._base}{path}", params=params, headers=headers, **kwargs
        )
        raise_for_status(self.service, resp)
        return resp.json() if resp.content else {}

    async def list_incidents(
        self, status: str = "open", severity: str | None = None, top: int = 10
    ) -> list[Incident]:
        filters = []
        if STATUS_FILTERS.get(status):
            filters.append(STATUS_FILTERS[status])
        if severity:
            if severity not in SEVERITIES:
                raise ValueError(f"Unknown severity {severity!r}")
            filters.append(f"properties/severity eq '{severity}'")
        params: dict[str, Any] = {
            "$orderby": "properties/createdTimeUtc desc",
            "$top": max(1, min(top, 50)),
        }
        if filters:
            params["$filter"] = " and ".join(filters)
        data = await self._request("GET", "/incidents", params=params)
        return [Incident.from_api(item) for item in data.get("value", [])]

    async def get_incident(self, incident_id: str) -> Incident:
        data = await self._request("GET", f"/incidents/{incident_id}")
        return Incident.from_api(data)

    async def resolve_incident(self, ref: int | str) -> Incident:
        """Look up an incident by number (as analysts see it) or by GUID."""
        if isinstance(ref, str):
            return await self.get_incident(ref)
        data = await self._request(
            "GET",
            "/incidents",
            params={"$filter": f"properties/incidentNumber eq {int(ref)}", "$top": 1},
        )
        items = data.get("value", [])
        if not items:
            raise NotFoundError(self.service, 404, f"Incident #{ref} not found")
        return Incident.from_api(items[0])

    async def get_entities(self, incident_id: str) -> list[Entity]:
        data = await self._request("POST", f"/incidents/{incident_id}/entities")
        return [Entity.from_api(e) for e in data.get("entities", [])]

    async def add_comment(self, incident_id: str, message: str) -> None:
        comment_id = str(uuid.uuid4())
        await self._request(
            "PUT",
            f"/incidents/{incident_id}/comments/{comment_id}",
            json={"properties": {"message": message}},
        )

    async def close_incident(
        self, incident: Incident, option: str, comment: str
    ) -> Incident:
        classification, reason = CLOSE_OPTIONS[option]
        properties: dict[str, Any] = {
            "title": incident.title,
            "severity": incident.severity,
            "description": incident.description,
            "status": "Closed",
            "classification": classification,
            "classificationComment": comment,
            "labels": incident.labels,
        }
        if reason:
            properties["classificationReason"] = reason
        if incident.owner_raw:
            properties["owner"] = incident.owner_raw
        body: dict[str, Any] = {"properties": properties}
        if incident.etag:
            # Optimistic concurrency: fail instead of overwriting someone else's change.
            body["etag"] = incident.etag
        data = await self._request("PUT", f"/incidents/{incident.id}", json=body)
        return Incident.from_api(data)
