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

    def resolve(self, hostname: str) -> tuple[str, str]:
        """Return (inventory name, address) for a validated hostname.

        A typed FQDN must equal an inventory entry exactly, so `dc01.evil.com` never maps to `dc01`.
        Only a bare short name may match the short part of an inventory FQDN, and only if unique.
        """
        name = hostname.strip().lower()
        if name in self._hosts:
            return name, self._hosts[name]
        if "." not in name:
            matches = sorted(key for key in self._hosts if key.split(".", 1)[0] == name)
            if len(matches) == 1:
                return matches[0], self._hosts[matches[0]]
            if matches:
                raise APIError(self.service, 409, f"`{name}` is ambiguous, matches: {', '.join(matches)}")
        raise NotFoundError(self.service, 404, f"`{name}` is not in the responder inventory")

    async def isolate(self, hostname: str) -> IsolationResult:
        return await self._run("isolate", hostname)

    async def unisolate(self, hostname: str) -> IsolationResult:
        return await self._run("unisolate", hostname)

    async def _run(self, action: str, hostname: str) -> IsolationResult:
        name, address = self.resolve(hostname)
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
            host=name, address=address, action=action, output=str(result.stdout or "").strip()[:300]
        )
