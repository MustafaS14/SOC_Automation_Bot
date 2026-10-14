"""In-memory stand-ins for Sentinel, Defender and TI APIs.

Enabled with SOC_BOT_MOCK=true so the bot can be demoed (and the walkthrough GIF
recorded) without an Azure tenant. Interfaces mirror the real clients.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from ..models import Entity, Incident, IpReport, Machine, MachineAction
from ..validators import is_public_ip, parse_ip
from .base import APIError, NotFoundError
from .sentinel import CLOSE_OPTIONS, SEVERITIES

_NOW = datetime.now(timezone.utc)


def _incident(number: int, title: str, severity: str, status: str, minutes_ago: int,
              tactics: list[str], products: list[str], alerts: int) -> Incident:
    return Incident(
        id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"mock-incident-{number}")),
        number=number,
        title=title,
        severity=severity,
        status=status,
        description=f"[MOCK] {title}",
        created=_NOW - timedelta(minutes=minutes_ago),
        alerts_count=alerts,
        tactics=tactics,
        products=products,
        url="https://portal.azure.com/#view/Microsoft_Azure_Security_Insights",
        etag='"mock"',
    )


class MockSentinelClient:
    service = "Sentinel (mock)"

    def __init__(self) -> None:
        self.incidents: dict[str, Incident] = {}
        self.comments: dict[str, list[str]] = {}
        self.entities: dict[str, list[Entity]] = {}
        seed = [
            (_incident(1042, "Suspicious PowerShell download cradle on WS-FIN-017", "High", "New", 12,
                       ["Execution", "CommandAndControl"], ["Microsoft Defender for Endpoint"], 3),
             [Entity("Host", "ws-fin-017"), Entity("Account", "j.doe"), Entity("Ip", "185.220.101.4"),
              Entity("Url", "http://185.220.101.4/a.ps1")]),
            (_incident(1041, "Impossible travel activity for a.smith", "Medium", "Active", 55,
                       ["InitialAccess"], ["Microsoft Entra ID Protection"], 2),
             [Entity("Account", "a.smith"), Entity("Ip", "45.155.205.233"), Entity("Ip", "8.8.8.8")]),
            (_incident(1040, "Multiple failed sign-ins followed by success", "Medium", "New", 140,
                       ["CredentialAccess"], ["Azure Sentinel"], 5),
             [Entity("Account", "svc-backup"), Entity("Ip", "104.248.30.9")]),
            (_incident(1039, "Rare process executed on SRV-WEB-02", "Low", "New", 300,
                       ["Execution"], ["Azure Sentinel"], 1),
             [Entity("Host", "srv-web-02")]),
            (_incident(1038, "Mailbox forwarding rule to external domain", "Informational", "Closed", 900,
                       ["Exfiltration"], ["Microsoft Defender for Office 365"], 1),
             [Entity("Account", "m.lee")]),
        ]
        for incident, entities in seed:
            self.incidents[incident.id] = incident
            self.entities[incident.id] = entities
            self.comments[incident.id] = []

    async def list_incidents(self, status: str = "open", severity: str | None = None, top: int = 10) -> list[Incident]:
        await asyncio.sleep(0.3)
        items = sorted(self.incidents.values(), key=lambda i: i.number, reverse=True)
        if status == "open":
            items = [i for i in items if i.status != "Closed"]
        elif status in {"new", "active", "closed"}:
            items = [i for i in items if i.status.lower() == status]
        if severity:
            if severity not in SEVERITIES:
                raise ValueError(f"Unknown severity {severity!r}")
            items = [i for i in items if i.severity == severity]
        return items[:top]

    async def get_incident(self, incident_id: str) -> Incident:
        try:
            return self.incidents[incident_id]
        except KeyError:
            raise NotFoundError(self.service, 404, "Incident not found") from None

    async def resolve_incident(self, ref: int | str) -> Incident:
        await asyncio.sleep(0.2)
        if isinstance(ref, str):
            return await self.get_incident(ref)
        for incident in self.incidents.values():
            if incident.number == ref:
                return incident
        raise NotFoundError(self.service, 404, f"Incident #{ref} not found")

    async def get_entities(self, incident_id: str) -> list[Entity]:
        return list(self.entities.get(incident_id, []))

    async def add_comment(self, incident_id: str, message: str) -> None:
        await self.get_incident(incident_id)
        self.comments[incident_id].append(message)

    async def close_incident(self, incident: Incident, option: str, comment: str) -> Incident:
        await asyncio.sleep(0.4)
        classification, _ = CLOSE_OPTIONS[option]
        incident.status = "Closed"
        incident.classification = classification
        self.comments[incident.id].append(f"Closed: {comment}")
        return incident


class MockDefenderClient:
    service = "Defender for Endpoint (mock)"

    def __init__(self) -> None:
        self.machines = {
            m.name.split(".")[0]: m
            for m in (
                Machine("a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0", "ws-fin-017.corp.contoso.com",
                        "Windows11", "Active", "High", "10.10.4.17", _NOW - timedelta(minutes=2)),
                Machine("b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1", "srv-web-02.corp.contoso.com",
                        "WindowsServer2022", "Active", "Medium", "10.20.1.2", _NOW - timedelta(minutes=5)),
                Machine("c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2", "dc01.corp.contoso.com",
                        "WindowsServer2022", "Active", "None", "10.0.0.10", _NOW - timedelta(minutes=1)),
            )
        }
        self.isolated: set[str] = set()

    async def find_machine(self, hostname: str) -> Machine:
        await asyncio.sleep(0.3)
        machine = self.machines.get(hostname.split(".")[0])
        if not machine:
            raise NotFoundError(self.service, 404, f"No device named `{hostname}` found")
        return machine

    async def isolate(self, machine_id: str, comment: str, isolation_type: str = "Full") -> MachineAction:
        await asyncio.sleep(0.5)
        if machine_id in self.isolated:
            raise APIError(self.service, 400, "Device is already isolated")
        self.isolated.add(machine_id)
        return MachineAction(str(uuid.uuid4()), "Isolate", "Pending", machine_id, "soc-bot")

    async def unisolate(self, machine_id: str, comment: str) -> MachineAction:
        await asyncio.sleep(0.5)
        if machine_id not in self.isolated:
            raise APIError(self.service, 400, "Device is not isolated")
        self.isolated.discard(machine_id)
        return MachineAction(str(uuid.uuid4()), "Unisolate", "Pending", machine_id, "soc-bot")


class MockEnrichmentClient:
    _KNOWN = {
        "185.220.101.4": dict(abuse_score=100, abuse_reports=2384, country="DE", isp="Tor Exit Node",
                              usage_type="Reserved", vt_malicious=14, vt_suspicious=3, vt_harmless=55,
                              as_owner="Stiftung Erneuerbare Freiheit"),
        "45.155.205.233": dict(abuse_score=62, abuse_reports=311, country="RU", isp="Example Hosting LLC",
                               usage_type="Data Center/Web Hosting/Transit", vt_malicious=3, vt_suspicious=1,
                               vt_harmless=60, as_owner="Example Hosting LLC"),
        "8.8.8.8": dict(abuse_score=0, abuse_reports=12, country="US", isp="Google LLC",
                        usage_type="Content Delivery Network", vt_malicious=0, vt_suspicious=0,
                        vt_harmless=70, as_owner="GOOGLE"),
    }

    async def enrich_ip(self, value: str) -> IpReport:
        await asyncio.sleep(0.4)
        ip = parse_ip(value)
        report = IpReport(ip=str(ip), is_public=is_public_ip(ip))
        if not report.is_public:
            return report
        known = self._KNOWN.get(str(ip))
        if known is None:
            seed = hashlib.sha256(str(ip).encode()).digest()
            known = dict(abuse_score=seed[0] % 40, abuse_reports=seed[1] % 50, country="NL",
                         isp="Mock ISP", usage_type="Fixed Line ISP", vt_malicious=seed[2] % 2,
                         vt_suspicious=0, vt_harmless=60, as_owner="MOCK-AS")
        for key, val in known.items():
            setattr(report, key, val)
        return report
