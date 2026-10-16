"""Role-based access control for chat commands.

Tiers are hierarchical: RESPONSE implies TRIAGE implies READ.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum


class Permission(IntEnum):
    READ = 1
    TRIAGE = 2
    RESPONSE = 3


@dataclass(frozen=True)
class AccessPolicy:
    read_role_ids: frozenset[int]
    triage_role_ids: frozenset[int]
    response_role_ids: frozenset[int]
    allowed_channel_ids: frozenset[int] = frozenset()

    def level_for(self, role_ids: Iterable[int]) -> Permission | None:
        roles = set(role_ids)
        if roles & self.response_role_ids:
            return Permission.RESPONSE
        if roles & self.triage_role_ids:
            return Permission.TRIAGE
        if roles & self.read_role_ids:
            return Permission.READ
        return None

    def is_allowed(self, role_ids: Iterable[int], required: Permission) -> bool:
        level = self.level_for(role_ids)
        return level is not None and level >= required

    def channel_allowed(self, channel_id: int | None) -> bool:
        # An empty allow-list means no channels, not every channel.
        return channel_id is not None and channel_id in self.allowed_channel_ids
