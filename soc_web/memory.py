"""Short follow-up memory for the Ask page: the last couple of exchanges, per signed-in user.

What is remembered is only what that user was already shown, tagged with the clearance level it was shown at. An
exchange is offered back to the assistant only when the user's level *now* is at least that level, so lowering an
account's tier immediately drops everything it saw at the higher one, and one user's history never reaches another.
The memory lives in this process only (nothing is written to disk) and each entry expires.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass

from soc_bot.ai import Exchange
from soc_bot.ai.assistant import MAX_HISTORY_ANSWER, MAX_HISTORY_QUESTION
from soc_bot.rbac import Permission

MAX_USERS = 500


@dataclass(frozen=True)
class _Entry:
    level: Permission
    exchange: Exchange
    at: float


class ConversationMemory:
    def __init__(self, *, max_exchanges: int = 2, ttl: float = 1800.0, clock: Callable[[], float] = time.monotonic):
        self._max, self._ttl, self._clock = max_exchanges, ttl, clock
        self._by_user: OrderedDict[int, deque[_Entry]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def max_exchanges(self) -> int:
        return self._max

    @property
    def ttl_minutes(self) -> int:
        return round(self._ttl / 60)

    def _fresh(self, user_id: int) -> deque[_Entry]:
        entries = self._by_user.get(user_id)
        if entries is None:
            return deque()
        now = self._clock()
        while entries and now - entries[0].at >= self._ttl:
            entries.popleft()
        if not entries:
            del self._by_user[user_id]
            return deque()
        return entries

    def history(self, user_id: int, level: Permission) -> list[Exchange]:
        """The user's remembered exchanges, oldest first, excluding any recorded above `level`."""
        with self._lock:
            return [e.exchange for e in self._fresh(user_id) if e.level <= level]

    def count(self, user_id: int, level: Permission) -> int:
        return len(self.history(user_id, level))

    def add(self, user_id: int, level: Permission, question: str, answer: str, tools: str = "") -> None:
        exchange = Exchange(question[:MAX_HISTORY_QUESTION], answer[:MAX_HISTORY_ANSWER], tools)
        with self._lock:
            entries = self._fresh(user_id) or self._by_user.setdefault(user_id, deque())
            entries.append(_Entry(level, exchange, self._clock()))
            while len(entries) > self._max:
                entries.popleft()
            self._by_user.move_to_end(user_id)
            while len(self._by_user) > MAX_USERS:
                self._by_user.popitem(last=False)

    def clear(self, user_id: int) -> None:
        with self._lock:
            self._by_user.pop(user_id, None)
