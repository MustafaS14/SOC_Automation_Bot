"""Host isolation over SSH as a restricted user that may only run two sudoers-listed scripts."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import asyncssh

from ..models import IsolationResult
from .base import APIError, NotFoundError

# Fixed commands: no user-supplied text ever reaches the remote shell.
_COMMANDS = {
    "isolate": "sudo -n /usr/local/sbin/soc-isolate",
    "unisolate": "sudo -n /usr/local/sbin/soc-unisolate",
}


class SshResponseClient:
    service = "SSH responder"

    def __init__(
        self,
        *,
        hosts: Mapping[str, str],
        user: str,
        key_path: str,
        known_hosts: str = "",
        timeout: float = 20.0,
    ):
        self._hosts = dict(hosts)
        self._user = user
        self._key_path = key_path
        self._known_hosts = known_hosts
        self._timeout = timeout

    def resolve(self, hostname: str) -> str:
        """Map a validated hostname to its inventory address; unknown hosts are never contacted."""
        address = self._hosts.get(hostname.lower().split(".", 1)[0])
        if address is None:
            raise NotFoundError(self.service, 404, f"`{hostname}` is not in the responder inventory")
        return address

    async def isolate(self, hostname: str) -> IsolationResult:
        return await self._run("isolate", hostname)

    async def unisolate(self, hostname: str) -> IsolationResult:
        return await self._run("unisolate", hostname)

    async def _run(self, action: str, hostname: str) -> IsolationResult:
        address = self.resolve(hostname)
        options: dict[str, object] = {}
        if self._known_hosts:
            options["known_hosts"] = self._known_hosts  # never pass None: asyncssh would skip host-key checks
        try:
            async with asyncssh.connect(
                address,
                username=self._user,
                client_keys=[self._key_path],
                connect_timeout=self._timeout,
                **options,
            ) as conn:
                result = await asyncio.wait_for(conn.run(_COMMANDS[action], check=False), self._timeout)
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            raise APIError(self.service, 502, f"{type(exc).__name__}: {str(exc)[:200]}") from exc
        if result.exit_status != 0:
            detail = str(result.stderr or result.stdout or "no output").strip()[:300]
            raise APIError(self.service, 500, f"{action} script exited {result.exit_status}: {detail}")
        return IsolationResult(
            host=hostname, address=address, action=action, output=str(result.stdout or "").strip()[:300]
        )
