from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Incident:
    id: str
    number: int
    title: str
    severity: str
    status: str
    description: str = ""
    owner: str | None = None
    created: datetime | None = None
    alerts_count: int = 0
    tactics: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    url: str | None = None
    classification: str | None = None
    etag: str | None = None
    labels: list[dict[str, Any]] = field(default_factory=list)
    owner_raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Incident:
        props = data.get("properties", {})
        extra = props.get("additionalData", {}) or {}
        owner = props.get("owner") or {}
        return cls(
            id=data["name"],
            number=int(props.get("incidentNumber", 0)),
            title=props.get("title", ""),
            severity=props.get("severity", "Informational"),
            status=props.get("status", "New"),
            description=props.get("description", "") or "",
            owner=owner.get("assignedTo") or owner.get("userPrincipalName") or owner.get("email"),
            created=_parse_dt(props.get("createdTimeUtc")),
            alerts_count=int(extra.get("alertsCount", 0)),
            tactics=list(extra.get("tactics", []) or []),
            products=list(extra.get("alertProductNames", []) or []),
            url=props.get("incidentUrl"),
            classification=props.get("classification"),
            etag=data.get("etag"),
            labels=list(props.get("labels", []) or []),
            owner_raw=owner,
        )


@dataclass
class Entity:
    kind: str
    name: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Entity:
        props = data.get("properties", {})
        name = (
            props.get("friendlyName")
            or props.get("address")
            or props.get("hostName")
            or props.get("accountName")
            or props.get("url")
            or props.get("hashValue")
            or "?"
        )
        return cls(kind=data.get("kind", "Unknown"), name=str(name))


@dataclass
class Machine:
    id: str
    name: str
    os_platform: str | None = None
    health_status: str | None = None
    risk_score: str | None = None
    last_ip: str | None = None
    last_seen: datetime | None = None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Machine:
        return cls(
            id=data["id"],
            name=data.get("computerDnsName", ""),
            os_platform=data.get("osPlatform"),
            health_status=data.get("healthStatus"),
            risk_score=data.get("riskScore"),
            last_ip=data.get("lastIpAddress"),
            last_seen=_parse_dt(data.get("lastSeen")),
        )


@dataclass
class MachineAction:
    id: str
    type: str
    status: str
    machine_id: str
    requestor: str | None = None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> MachineAction:
        return cls(
            id=data.get("id", ""),
            type=data.get("type", ""),
            status=data.get("status", ""),
            machine_id=data.get("machineId", ""),
            requestor=data.get("requestor"),
        )


@dataclass
class IpReport:
    ip: str
    is_public: bool
    abuse_score: int | None = None
    abuse_reports: int | None = None
    country: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    vt_malicious: int | None = None
    vt_suspicious: int | None = None
    vt_harmless: int | None = None
    as_owner: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if not self.is_public:
            return "Internal"
        score = self.abuse_score or 0
        malicious = self.vt_malicious or 0
        if score >= 75 or malicious >= 5:
            return "Malicious"
        if score >= 25 or malicious >= 1 or (self.vt_suspicious or 0) >= 2:
            return "Suspicious"
        if self.abuse_score is None and self.vt_malicious is None:
            return "Unknown"
        return "Clean"
