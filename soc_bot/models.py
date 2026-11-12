from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# MITRE ATT&CK technique or sub-technique ID, for example T1036 or T1036.004.
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MAX_TECHNIQUES = 12


def parse_techniques(value: Any) -> list[str]:
    """Technique IDs from a list or from text separated by commas, spaces or semicolons.

    Anything that is not a well-formed ID is dropped, so free text can never reach a card, a page or a query
    through this field. Order is kept, duplicates are removed and the list is capped.
    """
    if isinstance(value, str):
        parts: list[Any] = re.split(r"[,;\s]+", value)
    elif isinstance(value, (list, tuple)):
        parts = []
        for item in value:
            parts.extend(re.split(r"[,;\s]+", item) if isinstance(item, str) else [])
    else:
        return []
    found: list[str] = []
    for part in parts:
        tag = part.strip().upper()
        if TECHNIQUE_RE.match(tag) and tag not in found:
            found.append(tag)
    return found[:MAX_TECHNIQUES]


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
    techniques: list[str] = field(default_factory=list)

    @classmethod
    def from_row(cls, row: Mapping[str, Any], comments: list[Comment] | None = None) -> Incident:
        try:
            techniques = parse_techniques(row["techniques"])
        except (KeyError, IndexError):  # a row from a database or test that predates the column
            techniques = []
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
            techniques=techniques,
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
            # Both lookups failed (or neither ran): say so rather than implying a neutral answer.
            return "Incomplete" if self.errors else "Unknown"
        # A failed lookup must not read as a clean result.
        if self.errors:
            return "Incomplete"
        return "Clean"
