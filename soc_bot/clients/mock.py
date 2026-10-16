"""In-memory stand-ins for Splunk, SSH response and threat intel.

Enabled with SOC_BOT_MOCK=true so the bot can be demoed without the lab VMs.
Incidents use the real store backed by an in-memory SQLite database.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone

from ..models import IpReport, IsolationResult
from ..store import IncidentStore
from ..validators import is_public_ip, parse_ip
from .base import APIError, NotFoundError

_SEED = (
    ("Suspicious discovery commands on soc-victim", "High", "soc-victim", "192.168.56.30",
     "auditd execve burst: whoami, id, uname -a, cat /etc/passwd"),
    ("SSH brute force from external IP", "Medium", "soc-victim", "185.220.101.4",
     "27 failed SSH logins in 2 minutes"),
    ("Rare process executed on soc-attacker", "Low", "soc-attacker", None, "Unusual binary under /tmp"),
    ("New sudo user created", "Informational", "soc-victim", None, "useradd observed"),
)


async def seed_incidents(store: IncidentStore) -> None:
    for rule, severity, host, src_ip, description in _SEED:
        await store.create(rule=rule, severity=severity, host=host, src_ip=src_ip, description=description)
    closed = await store.create(rule="Cron job anomaly", severity="Low", host="soc-victim")
    await store.close(closed.id, "benign", "Scheduled debian-sa1 job", "soc-bot")


class MockSplunkClient:
    service = "Splunk (mock)"

    async def search(self, spl: str, earliest: str = "-1h", latest: str = "now") -> list[dict[str, str]]:
        await asyncio.sleep(0.4)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return [
            {"_time": now, "host": "soc-victim", "_raw": "type=EXECVE msg=audit(...): argc=1 a0=\"whoami\""},
            {"_time": now, "host": "soc-victim", "_raw": "type=EXECVE msg=audit(...): argc=2 a0=\"cat\" a1=\"/etc/passwd\""},
        ]


class MockSshResponseClient:
    service = "SSH responder (mock)"

    def __init__(self) -> None:
        self.hosts = {"soc-victim": "192.168.56.20", "soc-attacker": "192.168.56.30"}
        self.isolated: set[str] = set()

    def resolve(self, hostname: str) -> str:
        address = self.hosts.get(hostname.lower().split(".", 1)[0])
        if address is None:
            raise NotFoundError(self.service, 404, f"`{hostname}` is not in the responder inventory")
        return address

    async def isolate(self, hostname: str) -> IsolationResult:
        address = self.resolve(hostname)
        await asyncio.sleep(0.5)
        if address in self.isolated:
            raise APIError(self.service, 400, "Host is already isolated")
        self.isolated.add(address)
        return IsolationResult(hostname, address, "isolate", "isolated")

    async def unisolate(self, hostname: str) -> IsolationResult:
        address = self.resolve(hostname)
        await asyncio.sleep(0.5)
        if address not in self.isolated:
            raise APIError(self.service, 400, "Host is not isolated")
        self.isolated.discard(address)
        return IsolationResult(hostname, address, "unisolate", "released")


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
