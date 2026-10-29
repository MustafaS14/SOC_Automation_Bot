"""Role-based access control for chat commands.

Tiers are hierarchical: ADMIN implies RESPONSE implies TRIAGE implies READ implies VIEWER.
VIEWER may only use the AI assistant's summary-level answers; it cannot run the other commands.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum


class Permission(IntEnum):
    # Values start at 1 so that every tier is truthy.
    VIEWER = 1
    READ = 2
    TRIAGE = 3
    RESPONSE = 4
    ADMIN = 5


@dataclass(frozen=True)
class AccessPolicy:
    read_role_ids: frozenset[int]
    triage_role_ids: frozenset[int]
    response_role_ids: frozenset[int]
    allowed_channel_ids: frozenset[int] = frozenset()
    viewer_role_ids: frozenset[int] = frozenset()
    admin_role_ids: frozenset[int] = frozenset()

    def level_for(self, role_ids: Iterable[int]) -> Permission | None:
        roles = set(role_ids)
        if roles & self.admin_role_ids:
            return Permission.ADMIN
        if roles & self.response_role_ids:
            return Permission.RESPONSE
        if roles & self.triage_role_ids:
            return Permission.TRIAGE
        if roles & self.read_role_ids:
            return Permission.READ
        if roles & self.viewer_role_ids:
            return Permission.VIEWER
        return None

    def is_allowed(self, role_ids: Iterable[int], required: Permission) -> bool:
        level = self.level_for(role_ids)
        return level is not None and level >= required

    def channel_allowed(self, channel_id: int | None) -> bool:
        # An empty allow-list means no channels, not every channel.
        return channel_id is not None and channel_id in self.allowed_channel_ids
