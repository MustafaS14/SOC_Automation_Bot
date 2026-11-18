"""In-memory stand-ins for Splunk, SSH response and threat intel.

Enabled with SOC_BOT_MOCK=true so the bot can be demoed without the lab VMs.
Incidents use the real store backed by an in-memory SQLite database.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import ClassVar

from ..models import IpReport, IsolationResult
from ..store import IncidentStore
from ..validators import is_public_ip, parse_ip
from .base import APIError
from .ssh_response import SshResponseClient

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
        if "stats count by b kind" in spl:
            # Demo activity: a steady trickle of cron and logins, with a burst of commands in the middle of the window.
            import re

            size = int(re.search(r"floor\(_time/(\d+)\)", spl).group(1))
            first, last = int(float(earliest)) // size * size, int(float(latest)) // size * size
            slots = list(range(first, last, size))
            rows = []
            for n, b in enumerate(slots):
                rows.append({"b": str(b), "kind": "Cron and system", "count": "3"})
                if n % 4 == 0:
                    rows.append({"b": str(b), "kind": "Logins and sudo", "count": "2"})
                if len(slots) // 2 <= n < len(slots) // 2 + 2:
                    rows.append({"b": str(b), "kind": "Commands run", "count": str(30 + 10 * (n % 2))})
                if n == len(slots) // 3:
                    rows.append({"b": str(b), "kind": "Failed logins", "count": "12"})
            return rows
        if "soc-heartbeat" in spl:
            # Demo heartbeats: one host that beats every five minutes, with a gap about two hours ago.
            import time

            stamp = int(time.time())
            current = stamp // 300 * 300
            slots = [current - i * 300 for i in range(72) if not 22 <= i <= 26]
            slots = [s for s in slots if s <= stamp - 90]
            return [{"host": "soc-victim", "last": str(max(slots) + 17), "slots": ",".join(str(s) for s in slots)}]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return [
            {"_time": now, "host": "soc-victim", "_raw": "type=EXECVE msg=audit(...): argc=1 a0=\"whoami\""},
            {"_time": now, "host": "soc-victim", "_raw": "type=EXECVE msg=audit(...): argc=2 a0=\"cat\" a1=\"/etc/passwd\""},
        ]


class MockSshResponseClient(SshResponseClient):
    service = "SSH responder (mock)"

    def __init__(self) -> None:
        super().__init__(
            hosts={"soc-victim": "192.168.56.20", "soc-attacker": "192.168.56.30"},
            user="responder",
            key_path="",
        )
        self.isolated: set[str] = set()

    async def _run(self, action: str, hostname: str) -> IsolationResult:
        name, address = self.resolve(hostname)
        await asyncio.sleep(0.5)
        if action == "isolate":
            if address in self.isolated:
                raise APIError(self.service, 400, "Host is already isolated")
            self.isolated.add(address)
            return IsolationResult(name, address, action, "[MOCK] isolated - no real host was touched")
        if address not in self.isolated:
            raise APIError(self.service, 400, "Host is not isolated")
        self.isolated.discard(address)
        return IsolationResult(name, address, action, "[MOCK] released - no real host was touched")


class MockEnrichmentClient:
    _KNOWN: ClassVar[dict[str, dict]] = {
        "185.220.101.4": {"abuse_score": 100, "abuse_reports": 2384, "country": "DE", "isp": "Tor Exit Node",
                              "usage_type": "Reserved", "vt_malicious": 14, "vt_suspicious": 3, "vt_harmless": 55,
                              "as_owner": "Stiftung Erneuerbare Freiheit"},
        "45.155.205.233": {"abuse_score": 62, "abuse_reports": 311, "country": "RU", "isp": "Example Hosting LLC",
                               "usage_type": "Data Center/Web Hosting/Transit", "vt_malicious": 3, "vt_suspicious": 1,
                               "vt_harmless": 60, "as_owner": "Example Hosting LLC"},
        "8.8.8.8": {"abuse_score": 0, "abuse_reports": 12, "country": "US", "isp": "Google LLC",
                        "usage_type": "Content Delivery Network", "vt_malicious": 0, "vt_suspicious": 0,
                        "vt_harmless": 70, "as_owner": "GOOGLE"},
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
            known = {"abuse_score": seed[0] % 40, "abuse_reports": seed[1] % 50, "country": "NL",
                         "isp": "Mock ISP", "usage_type": "Fixed Line ISP", "vt_malicious": seed[2] % 2,
                         "vt_suspicious": 0, "vt_harmless": 60, "as_owner": "MOCK-AS"}
        for key, val in known.items():
            setattr(report, key, val)
        return report
