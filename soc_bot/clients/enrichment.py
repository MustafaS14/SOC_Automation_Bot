"""IP reputation enrichment from AbuseIPDB and VirusTotal."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..models import IpReport
from ..validators import is_public_ip, parse_ip


def _dict_at(body: Any, *keys: str) -> dict[str, Any]:
    """Follow `keys` through nested dicts; any other shape raises ValueError, which callers record."""
    for key in keys:
        body = body.get(key) if isinstance(body, dict) else None
    if not isinstance(body, dict):
        raise ValueError("unexpected response shape")
    return body


class EnrichmentClient:
    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        abuseipdb_key: str | None = None,
        virustotal_key: str | None = None,
    ):
        self._http = http
        self._abuse_key = abuseipdb_key
        self._vt_key = virustotal_key

    async def enrich_ip(self, value: str) -> IpReport:
        ip = parse_ip(value)
        report = IpReport(ip=str(ip), is_public=is_public_ip(ip))
        if not report.is_public:
            # Never leak internal addressing to third-party services.
            return report
        if not (self._abuse_key or self._vt_key):
            report.errors.append("No threat-intel API keys configured")
            return report
        await asyncio.gather(self._abuseipdb(report), self._virustotal(report))
        return report

    async def _abuseipdb(self, report: IpReport) -> None:
        if not self._abuse_key:
            return
        try:
            resp = await self._http.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": report.ip, "maxAgeInDays": 90},
                headers={"Key": self._abuse_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = _dict_at(resp.json(), "data")
        except (httpx.HTTPError, ValueError) as exc:
            report.errors.append(f"AbuseIPDB: {type(exc).__name__}")
            return
        report.abuse_score = data.get("abuseConfidenceScore")
        report.abuse_reports = data.get("totalReports")
        report.country = report.country or data.get("countryCode")
        report.isp = data.get("isp")
        report.usage_type = data.get("usageType")

    async def _virustotal(self, report: IpReport) -> None:
        if not self._vt_key:
            return
        try:
            resp = await self._http.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{report.ip}",
                headers={"x-apikey": self._vt_key},
            )
            resp.raise_for_status()
            attrs = _dict_at(resp.json(), "data", "attributes")
        except (httpx.HTTPError, ValueError) as exc:
            report.errors.append(f"VirusTotal: {type(exc).__name__}")
            return
        stats = attrs.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        report.vt_malicious = stats.get("malicious")
        report.vt_suspicious = stats.get("suspicious")
        report.vt_harmless = stats.get("harmless")
        report.as_owner = attrs.get("as_owner")
        report.country = report.country or attrs.get("country")
