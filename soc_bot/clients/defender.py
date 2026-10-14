"""Async client for Microsoft Defender for Endpoint machine actions.

Docs: https://learn.microsoft.com/defender-endpoint/api/isolate-machine
"""

from __future__ import annotations

from typing import Any

import httpx

from ..models import Machine, MachineAction
from .base import APIError, AsyncTokenCredential, NotFoundError, bearer_headers, raise_for_status

MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"


class DefenderClient:
    service = "Defender for Endpoint"

    def __init__(self, *, credential: AsyncTokenCredential, http: httpx.AsyncClient, api_base: str):
        self._credential = credential
        self._http = http
        self._base = api_base.rstrip("/")

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        headers = await bearer_headers(self._credential, MDE_SCOPE)
        resp = await self._http.request(method, f"{self._base}{path}", headers=headers, **kwargs)
        raise_for_status(self.service, resp)
        return resp.json() if resp.content else {}

    async def find_machine(self, hostname: str) -> Machine:
        """Resolve a hostname (short or FQDN, already validated) to exactly one device."""
        data = await self._request(
            "GET",
            "/api/machines",
            params={"$filter": f"startswith(computerDnsName,'{hostname}')", "$top": 25},
        )
        machines = [Machine.from_api(m) for m in data.get("value", [])]
        exact = [
            m for m in machines
            if m.name.lower() == hostname or m.name.lower().split(".", 1)[0] == hostname
        ]
        if len(exact) > 1:
            active = [m for m in exact if (m.health_status or "").lower() != "inactive"]
            exact = active or exact
        if not exact:
            raise NotFoundError(self.service, 404, f"No device named `{hostname}` found")
        if len(exact) > 1:
            names = ", ".join(f"{m.name} ({m.id[:8]})" for m in exact)
            raise APIError(self.service, 409, f"Hostname is ambiguous, matches: {names}")
        return exact[0]

    async def isolate(self, machine_id: str, comment: str, isolation_type: str = "Full") -> MachineAction:
        data = await self._request(
            "POST",
            f"/api/machines/{machine_id}/isolate",
            json={"Comment": comment, "IsolationType": isolation_type},
        )
        return MachineAction.from_api(data)

    async def unisolate(self, machine_id: str, comment: str) -> MachineAction:
        data = await self._request(
            "POST", f"/api/machines/{machine_id}/unisolate", json={"Comment": comment}
        )
        return MachineAction.from_api(data)
