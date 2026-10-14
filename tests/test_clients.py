import json
from types import SimpleNamespace

import httpx
import pytest

from soc_bot.clients import APIError, DefenderClient, NotFoundError, SentinelClient

BASE = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights"
    "/workspaces/ws/providers/Microsoft.SecurityInsights"
)


class FakeCredential:
    def __init__(self):
        self.scopes = []

    async def get_token(self, *scopes, **_):
        self.scopes.extend(scopes)
        return SimpleNamespace(token="fake-token")


def incident_json(number=1042, status="New"):
    return {
        "name": "0b3f8a9e-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
        "etag": '"etag-1"',
        "properties": {
            "incidentNumber": number,
            "title": "Suspicious PowerShell",
            "severity": "High",
            "status": status,
            "description": "desc",
            "labels": [],
            "createdTimeUtc": "2026-10-13T10:00:00Z",
            "additionalData": {"alertsCount": 3, "tactics": ["Execution"]},
            "incidentUrl": "https://portal.azure.com/#incident",
        },
    }


def make_client(handler):
    cred = FakeCredential()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = SentinelClient(
        subscription_id="sub", resource_group="rg", workspace_name="ws", credential=cred, http=http
    )
    return client, cred


async def test_list_incidents_builds_odata_query():
    seen = {}

    def handler(request: httpx.Request):
        seen["path"] = request.url.path
        seen["params"] = dict(request.url.params)
        seen["auth"] = request.headers["Authorization"]
        return httpx.Response(200, json={"value": [incident_json()]})

    client, cred = make_client(handler)
    incidents = await client.list_incidents(status="open", severity="High", top=5)

    assert seen["path"] == BASE + "/incidents"
    assert seen["params"]["$filter"] == "properties/status ne 'Closed' and properties/severity eq 'High'"
    assert seen["params"]["$top"] == "5"
    assert seen["params"]["api-version"] == "2024-03-01"
    assert seen["auth"] == "Bearer fake-token"
    assert cred.scopes == ["https://management.azure.com/.default"]
    assert incidents[0].number == 1042 and incidents[0].alerts_count == 3


async def test_list_rejects_unknown_severity():
    client, _ = make_client(lambda r: httpx.Response(200, json={"value": []}))
    with pytest.raises(ValueError):
        await client.list_incidents(severity="High' or 1 eq 1")


async def test_resolve_by_number_not_found():
    client, _ = make_client(lambda r: httpx.Response(200, json={"value": []}))
    with pytest.raises(NotFoundError):
        await client.resolve_incident(9999)


async def test_close_incident_sends_classification_and_etag():
    captured = {}

    def handler(request: httpx.Request):
        if request.method == "PUT":
            captured["path"] = request.url.path
            captured["body"] = json.loads(request.content)
            closed = incident_json(status="Closed")
            closed["properties"]["classification"] = "TruePositive"
            return httpx.Response(200, json=closed)
        return httpx.Response(200, json={"value": [incident_json()]})

    client, _ = make_client(handler)
    incident = await client.resolve_incident(1042)
    updated = await client.close_incident(incident, "tp_suspicious", "confirmed malware")

    props = captured["body"]["properties"]
    assert captured["path"] == f"{BASE}/incidents/{incident.id}"
    assert captured["body"]["etag"] == '"etag-1"'
    assert props["status"] == "Closed"
    assert props["classification"] == "TruePositive"
    assert props["classificationReason"] == "SuspiciousActivity"
    assert updated.status == "Closed"


async def test_api_errors_are_surfaced():
    client, _ = make_client(
        lambda r: httpx.Response(403, json={"error": {"code": "AuthorizationFailed", "message": "nope"}})
    )
    with pytest.raises(APIError) as exc:
        await client.list_incidents()
    assert exc.value.status == 403 and exc.value.message == "nope"


async def test_defender_find_and_isolate():
    calls = []

    def handler(request: httpx.Request):
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"value": [
                {"id": "abc123", "computerDnsName": "ws-fin-017.corp.contoso.com", "healthStatus": "Active"},
                {"id": "def456", "computerDnsName": "ws-fin-0170.corp.contoso.com", "healthStatus": "Active"},
            ]})
        return httpx.Response(201, json={"id": "act-1", "type": "Isolate", "status": "Pending", "machineId": "abc123"})

    cred = FakeCredential()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = DefenderClient(credential=cred, http=http, api_base="https://api.securitycenter.microsoft.com")

    machine = await client.find_machine("ws-fin-017")
    assert machine.id == "abc123"
    action = await client.isolate(machine.id, "test", "Full")

    assert calls[0].url.params["$filter"] == "startswith(computerDnsName,'ws-fin-017')"
    assert calls[1].url.path == "/api/machines/abc123/isolate"
    assert json.loads(calls[1].content) == {"Comment": "test", "IsolationType": "Full"}
    assert action.status == "Pending"
    assert cred.scopes[0] == "https://api.securitycenter.microsoft.com/.default"
