"""Chat conversations for the console's widget and the Ask page, kept in the console's own database.

A conversation belongs to one user *at one tier*. Every lookup matches both, so a user who is later given a lower (or
higher) tier starts with a fresh list: what was said at another level is never read back at this one. Nothing is ever
deleted: a conversation can be renamed or archived, and that is all. Text is redacted before it is stored and capped in
length, and a conversation holds a limited number of messages.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from soc_bot.ai import Exchange
from soc_bot.audit import redact
from soc_bot.rbac import Permission

from .users import UserStore

MAX_MESSAGES = 60  # per conversation, questions and answers together
MAX_TEXT = 4000
MAX_TITLE = 80
AUTO_TITLE = 60
MAX_LISTED = 100
ROLES = ("user", "assistant")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    tier INTEGER NOT NULL,
    title TEXT NOT NULL,
    created TEXT NOT NULL,
    updated TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS chats_owner ON chats (user_id, tier, archived, updated);
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL REFERENCES chats (id),
    role TEXT NOT NULL,
    text TEXT NOT NULL,
    page TEXT,
    tools TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_messages_chat ON chat_messages (chat_id, id);
"""


class ChatError(ValueError):
    """A message safe to show the user."""


@dataclass(frozen=True)
class Chat:
    id: int
    title: str
    created: str
    updated: str
    archived: bool


@dataclass(frozen=True)
class Message:
    role: str
    text: str
    page: str | None
    created: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(text: str, limit: int, *, one_line: bool = False) -> str:
    """Secrets redacted, whitespace tidied, length capped: the form in which anything is stored."""
    text = " ".join(text.split()) if one_line else text.strip()
    return redact(text)[:limit]


class ConversationStore:
    def __init__(self, users: UserStore):
        self._db, self._lock = users.db, users.lock
        with self._lock:
            self._db.executescript(_SCHEMA)

    def _owned(self, user_id: int, tier: Permission, chat_id: int) -> sqlite3.Row | None:
        return self._db.execute(
            "SELECT * FROM chats WHERE id = ? AND user_id = ? AND tier = ?", (chat_id, user_id, int(tier))
        ).fetchone()

    @staticmethod
    def _chat(row: sqlite3.Row) -> Chat:
        return Chat(row["id"], row["title"], row["created"], row["updated"], bool(row["archived"]))

    def list(self, user_id: int, tier: Permission, *, archived: bool = False) -> list[Chat]:
        """This user's conversations at this tier, newest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM chats WHERE user_id = ? AND tier = ? AND archived = ? "
                "ORDER BY updated DESC, id DESC LIMIT ?",
                (user_id, int(tier), int(archived), MAX_LISTED),
            ).fetchall()
        return [self._chat(r) for r in rows]

    def get(self, user_id: int, tier: Permission, chat_id: int) -> Chat | None:
        with self._lock:
            row = self._owned(user_id, tier, chat_id)
        return self._chat(row) if row else None

    def create(self, user_id: int, tier: Permission, first_question: str) -> Chat:
        """Start a conversation, titled from its first question."""
        title = clean(first_question, AUTO_TITLE, one_line=True) or "New conversation"
        now = _now()
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO chats (user_id, tier, title, created, updated) VALUES (?, ?, ?, ?, ?)",
                (user_id, int(tier), title, now, now),
            )
        return Chat(int(cur.lastrowid), title, now, now, False)

    def messages(self, user_id: int, tier: Permission, chat_id: int) -> list[Message]:
        with self._lock:
            if not self._owned(user_id, tier, chat_id):
                return []
            rows = self._db.execute(
                "SELECT role, text, page, created FROM chat_messages WHERE chat_id = ? ORDER BY id", (chat_id,)
            ).fetchall()
        return [Message(r["role"], r["text"], r["page"], r["created"]) for r in rows]

    def add(self, user_id: int, tier: Permission, chat_id: int, role: str, text: str, *, page: str | None = None,
            tools: str = "") -> None:
        if role not in ROLES:
            raise ChatError("Unknown message role.")
        with self._lock, self._db:
            if not self._owned(user_id, tier, chat_id):
                raise ChatError("That conversation does not exist.")
            (count,) = self._db.execute("SELECT COUNT(*) FROM chat_messages WHERE chat_id = ?", (chat_id,)).fetchone()
            if count >= MAX_MESSAGES:
                raise ChatError("This conversation is full. Start a new one.")
            now = _now()
            self._db.execute(
                "INSERT INTO chat_messages (chat_id, role, text, page, tools, created) VALUES (?, ?, ?, ?, ?, ?)",
                (chat_id, role, clean(text, MAX_TEXT), page, tools[:120], now),
            )
            self._db.execute("UPDATE chats SET updated = ? WHERE id = ?", (now, chat_id))

    def rename(self, user_id: int, tier: Permission, chat_id: int, title: str) -> None:
        title = clean(title, MAX_TITLE, one_line=True)
        if not title:
            raise ChatError("Give the conversation a name.")
        with self._lock, self._db:
            if not self._owned(user_id, tier, chat_id):
                raise ChatError("That conversation does not exist.")
            self._db.execute("UPDATE chats SET title = ? WHERE id = ?", (title, chat_id))

    def set_archived(self, user_id: int, tier: Permission, chat_id: int, archived: bool) -> None:
        with self._lock, self._db:
            if not self._owned(user_id, tier, chat_id):
                raise ChatError("That conversation does not exist.")
            self._db.execute("UPDATE chats SET archived = ? WHERE id = ?", (int(archived), chat_id))

    def history(self, user_id: int, tier: Permission, chat_id: int, exchanges: int = 2) -> list[Exchange]:
        """The last few question-and-answer pairs of this conversation, for a follow-up."""
        with self._lock:
            if not self._owned(user_id, tier, chat_id):
                return []
            rows = self._db.execute(
                "SELECT role, text, tools FROM chat_messages WHERE chat_id = ? ORDER BY id", (chat_id,)
            ).fetchall()
        pairs: list[Exchange] = []
        for earlier, later in zip(rows, rows[1:]):
            if earlier["role"] == "user" and later["role"] == "assistant" and later["tools"]:
                pairs.append(Exchange(earlier["text"], later["text"], later["tools"]))
        return pairs[-exchanges:]
