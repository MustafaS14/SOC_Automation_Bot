from __future__ import annotations

from collections.abc import Mapping
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
class Comment:
    author: str
    body: str
    created: datetime | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> Comment:
        return cls(author=row["author"], body=row["body"], created=_parse_dt(row["created"]))


@dataclass
class Incident:
    id: int
    rule: str
    severity: str
    status: str
    host: str | None = None
    src_ip: str | None = None
    assignee: str | None = None
    description: str = ""
    url: str | None = None
    classification: str | None = None
    created: datetime | None = None
    updated: datetime | None = None
    comments: list[Comment] = field(default_factory=list)

    @classmethod
    def from_row(cls, row: Mapping[str, Any], comments: list[Comment] | None = None) -> Incident:
        return cls(
            id=row["id"],
            rule=row["rule"],
            severity=row["severity"],
            status=row["status"],
            host=row["host"],
            src_ip=row["src_ip"],
            assignee=row["assignee"],
            description=row["description"] or "",
            url=row["url"],
            classification=row["classification"],
            created=_parse_dt(row["created"]),
            updated=_parse_dt(row["updated"]),
            comments=comments or [],
        )


@dataclass
class IsolationResult:
    host: str
    address: str
    action: str
    output: str = ""


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
        # A failed lookup must not read as a clean result.
        if self.errors:
            return "Incomplete"
        return "Clean"
