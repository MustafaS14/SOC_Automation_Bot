"""Local web accounts: scrypt password hashes, role tiers shared with the bot, lockout after failed logins."""

from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from soc_bot.rbac import Permission

TIERS = {
    "viewer": Permission.VIEWER,
    "read": Permission.READ,
    "triage": Permission.TRIAGE,
    "response": Permission.RESPONSE,
    "admin": Permission.ADMIN,
}
MIN_PASSWORD = 12
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    tier INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created TEXT NOT NULL,
    last_login TEXT,
    session_version INTEGER NOT NULL DEFAULT 0
);
"""


class UserError(ValueError):
    pass


@dataclass(frozen=True)
class User:
    id: int
    username: str
    tier: Permission
    active: bool = True
    session_version: int = 0

    @property
    def tier_name(self) -> str:
        return self.tier.name.lower()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_user(row: sqlite3.Row) -> User:
    return User(row["id"], row["username"], Permission(row["tier"]), bool(row["active"]), row["session_version"])


def check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise UserError(f"The password must be at least {MIN_PASSWORD} characters.")


class UserStore:
    def __init__(self, path: str, *, max_failed: int = 5, lockout_minutes: int = 15):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        columns = {r["name"] for r in self._db.execute("PRAGMA table_info(users)")}
        if "session_version" not in columns:  # a database made before sessions could be revoked
            with self._db:
                self._db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
        self._lock = threading.Lock()
        self._max_failed = max_failed
        self._lockout = timedelta(minutes=lockout_minutes)
        # Verified against when the username is unknown, so a miss takes as long as a wrong password.
        self._dummy_hash = generate_password_hash("not-a-real-password")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def create(self, username: str, password: str, tier: str) -> User:
        username = username.strip().lower()
        if not _USERNAME.match(username):
            raise UserError("Usernames are 3 to 32 characters: lowercase letters, digits, dot, dash, underscore.")
        if tier not in TIERS:
            raise UserError(f"Unknown tier {tier!r}. Choose one of: {', '.join(TIERS)}.")
        check_password_strength(password)
        with self._lock, self._db:
            try:
                cur = self._db.execute(
                    "INSERT INTO users (username, password_hash, tier, created) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), int(TIERS[tier]), _now().isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise UserError(f"User {username!r} already exists.") from exc
            row = self._db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        return _row_user(row)

    def get(self, user_id: int) -> User | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_user(row) if row else None

    def list(self) -> list[User]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [_row_user(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def authenticate(self, username: str, password: str) -> User | None:
        """The user on success. None for any failure, so callers cannot tell which part was wrong."""
        username = username.strip().lower()
        with self._lock, self._db:
            row = self._db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row is None:
                check_password_hash(self._dummy_hash, password)
                return None
            locked_until = row["locked_until"]
            if locked_until and datetime.fromisoformat(locked_until) > _now():
                return None
            if not check_password_hash(row["password_hash"], password):
                failed = row["failed_attempts"] + 1
                lock = _now() + self._lockout if failed >= self._max_failed else None
                self._db.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (0 if lock else failed, lock.isoformat() if lock else None, row["id"]),
                )
                return None
            if not row["active"]:
                return None
            self._db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                (_now().isoformat(), row["id"]),
            )
        return _row_user(row)

    def _update(self, username: str, sql: str, *params: object) -> None:
        with self._lock, self._db:
            cur = self._db.execute(f"UPDATE users SET {sql} WHERE username = ?", (*params, username.strip().lower()))
            if cur.rowcount == 0:
                raise UserError(f"No user named {username!r}.")

    def set_password(self, username: str, password: str) -> None:
        check_password_strength(password)
        self._update(username, "password_hash = ?, failed_attempts = 0, locked_until = NULL, session_version = session_version + 1",
                     generate_password_hash(password))

    def set_tier(self, username: str, tier: str) -> None:
        if tier not in TIERS:
            raise UserError(f"Unknown tier {tier!r}. Choose one of: {', '.join(TIERS)}.")
        self._update(username, "tier = ?", int(TIERS[tier]))

    def set_active(self, username: str, active: bool) -> None:
        self._update(username, "active = ?, session_version = session_version + 1", int(active))

    def revoke_sessions(self, user_id: int) -> None:
        """Every cookie issued so far for this user stops working (the cookie carries the version it was issued at)."""
        with self._lock, self._db:
            self._db.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user_id,))
