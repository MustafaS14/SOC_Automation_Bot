"""Question in, answer out: the loop between the model and the clearance-checked tools."""

from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..rbac import Permission
from ..validators import ValidationError
from .backends import AiBackend, BackendError
from .prompt import PLAIN_MARKER, SYSTEM_PROMPT, TOOL_PROTOCOL_REMINDER
from .tools import LEVEL_LABELS, ToolContext, describe_args, execute, tools_for

log = logging.getLogger("soc_bot")

MAX_QUESTION_CHARS = 500
MAX_LOOKUPS = 3
MAX_ANSWER_CHARS = 2200  # room for the answer, its evidence and the plain-words part


@dataclass
class AiAnswer:
    text: str
    outcome: str  # answered, rate_limited, budget, error
    tools_used: list[str] = field(default_factory=list)
    denied: bool = False
    calls: int = 0


class _Window:
    """Allow at most `limit` events per `period` seconds."""

    def __init__(self, limit: int, period: float, clock: Callable[[], float]):
        self._limit, self._period, self._clock = limit, period, clock
        self._hits: deque[float] = deque()

    def allow(self) -> bool:
        now = self._clock()
        while self._hits and now - self._hits[0] >= self._period:
            self._hits.popleft()
        if len(self._hits) >= self._limit:
            return False
        self._hits.append(now)
        return True


_PLAIN_RE = re.compile(rf"^[ 	]*{re.escape(PLAIN_MARKER)}[ 	]*", re.IGNORECASE | re.MULTILINE)


def split_plain_words(text: str) -> tuple[str, str | None]:
    """(the technical answer, the plain-words part or None). The marker must start a line."""
    match = _PLAIN_RE.search(text)
    if match is None:
        return text, None
    plain = text[match.end():].strip()
    return text[: match.start()].rstrip(), plain or None


def _safe(text: str) -> str:
    """Make untrusted text unable to close or forge the tags the prompt is built from."""
    return text.replace("<", "&lt;").replace(">", "&gt;")


def build_prompt(
    level: Permission, question: str, lookups: list[tuple[str, object, str]], *, final: bool = False
) -> str:
    parts = [f"<user_level>{LEVEL_LABELS[level]}</user_level>", "<tools>"]
    parts += [f"- {tool.description}" for tool in tools_for(level)]
    parts += ["</tools>", f"<question>{_safe(question)}</question>"]
    if lookups:
        parts.append("<lookups>")
        for name, args, result in lookups:
            parts.append(f'<log_data tool="{name}" args={_safe(describe_args(args))!r}>\n{_safe(result)}\n</log_data>')
        parts.append("</lookups>")
    if final:
        parts.append('You have used all your lookups. Answer now with {"answer": "..."}.')
    parts.append(TOOL_PROTOCOL_REMINDER)
    return "\n".join(parts)


def parse_reply(raw: str) -> tuple[str, object]:
    """('tool', (name, args)), ('answer', text) or ('invalid', None)."""
    start = raw.find("{")
    if start == -1:
        text = raw.strip()
        return ("answer", text) if text else ("invalid", None)
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw[start:])
    except ValueError:
        return "invalid", None
    if isinstance(obj, dict) and isinstance(obj.get("tool"), str):
        return "tool", (obj["tool"], obj.get("args", {}))
    if isinstance(obj, dict) and isinstance(obj.get("answer"), str) and obj["answer"].strip():
        return "answer", obj["answer"].strip()
    return "invalid", None


class Assistant:
    def __init__(
        self,
        backend: AiBackend,
        ctx: ToolContext,
        *,
        user_questions_per_hour: int = 12,
        auto_notes_per_hour: int = 6,
        daily_calls: int = 150,
        clock: Callable[[], float] = time.monotonic,
        today: Callable[[], str] | None = None,
    ):
        self._backend = backend
        self._ctx = ctx
        self._user_limit = user_questions_per_hour
        self._clock = clock
        self._users: dict[int, _Window] = {}
        self._auto = _Window(auto_notes_per_hour, 3600.0, clock)
        self._daily_cap = daily_calls
        self._today = today or (lambda: datetime.now(timezone.utc).date().isoformat())
        self._day = self._today()
        self._spent = 0

    def _spend(self) -> bool:
        if (today := self._today()) != self._day:
            self._day, self._spent = today, 0
        if self._spent >= self._daily_cap:
            return False
        self._spent += 1
        return True

    def _allow_user(self, user_id: int) -> bool:
        window = self._users.setdefault(user_id, _Window(self._user_limit, 3600.0, self._clock))
        return window.allow()

    async def ask(self, question: str, level: Permission, user_id: int, *, automatic: bool = False) -> AiAnswer:
        question = " ".join(question.split())
        if not question:
            raise ValidationError("Ask a question first.")
        if len(question) > MAX_QUESTION_CHARS:
            raise ValidationError(f"Keep the question under {MAX_QUESTION_CHARS} characters.")
        allowed = self._auto.allow() if automatic else self._allow_user(user_id)
        if not allowed:
            return AiAnswer("The question limit for this hour is used up. Try again later.", "rate_limited")

        answer = AiAnswer("", "error")
        lookups: list[tuple[str, object, str]] = []
        invalid = 0
        for round_no in range(MAX_LOOKUPS + 2):
            final = len(lookups) >= MAX_LOOKUPS
            if not self._spend():
                answer.text, answer.outcome = "The assistant's daily budget is used up. Try again tomorrow.", "budget"
                return answer
            answer.calls += 1
            try:
                raw = await self._backend.complete(SYSTEM_PROMPT, build_prompt(level, question, lookups, final=final))
            except BackendError as exc:
                log.warning("AI backend failed: %s", exc)
                answer.text = "The assistant is unavailable right now."
                return answer
            kind, value = parse_reply(raw)
            if kind == "answer":
                answer.text, answer.outcome = str(value)[:MAX_ANSWER_CHARS], "answered"
                return answer
            if kind == "invalid" or final:
                invalid += 1
                if invalid >= 2:
                    break
                continue
            name, args = value  # type: ignore[misc]
            result = await execute(self._ctx, level, name, args)
            answer.tools_used.append(name)
            answer.denied = answer.denied or result.denied
            lookups.append((name, args, result.text))
        answer.text = "I couldn't put together an answer. Please rephrase the question."
        return answer

    async def triage_note(self, incident_id: int) -> AiAnswer:
        question = (
            f"Write a short triage note for incident #{incident_id}: what happened, the likely MITRE ATT&CK "
            "technique, true or false positive with confidence, and what to check next."
        )
        return await self.ask(question, Permission.READ, 0, automatic=True)
