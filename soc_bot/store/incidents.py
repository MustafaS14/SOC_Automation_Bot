"""SQLite incident store: Splunk raises alerts, incident state lives here."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

from ..clients.base import APIError, NotFoundError
from ..models import Comment, Incident

T = TypeVar("T")

SEVERITIES = ("High", "Medium", "Low", "Informational")
CLASSIFICATIONS = ("true_positive", "false_positive", "benign")

# Fixed map so status filters never reach SQL as text.
_STATUS_SQL = {
    "open": "status != 'Closed'",
    "new": "status = 'New'",
    "active": "status = 'Active'",
    "closed": "status = 'Closed'",
    "all": "1 = 1",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    host TEXT,
    src_ip TEXT,
    status TEXT NOT NULL DEFAULT 'New',
    assignee TEXT,
    description TEXT NOT NULL DEFAULT '',
    url TEXT,
    classification TEXT,
    created TEXT NOT NULL,
    updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_incident ON comments(incident_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentStore:
    service = "Incident store"

    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def shutdown(self) -> None:
        with self._lock:
            self._db.close()

    async def _run(self, fn: Callable[..., T], *args: Any) -> T:
        return await asyncio.to_thread(self._call, fn, *args)

    def _call(self, fn: Callable[..., T], *args: Any) -> T:
        with self._lock, self._db:  # the inner block commits, or rolls back on error
            return fn(self._db, *args)

    def _not_found(self, incident_id: int) -> NotFoundError:
        return NotFoundError(self.service, 404, f"Incident #{incident_id} not found")

    async def create(
        self,
        *,
        rule: str,
        severity: str,
        host: str | None = None,
        src_ip: str | None = None,
        description: str = "",
        url: str | None = None,
    ) -> Incident:
        if severity not in SEVERITIES:
            raise ValueError(f"Unknown severity {severity!r}")

        def op(db: sqlite3.Connection) -> Incident:
            now = _now()
            cur = db.execute(
                "INSERT INTO incidents (rule, severity, host, src_ip, description, url, created, updated) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rule, severity, host, src_ip, description, url, now, now),
            )
            row = db.execute("SELECT * FROM incidents WHERE id = ?", (cur.lastrowid,)).fetchone()
            return Incident.from_row(row)

        return await self._run(op)

    async def list(self, status: str = "open", severity: str | None = None, limit: int = 10) -> list[Incident]:
        if status not in _STATUS_SQL:
            raise ValueError(f"Unknown status {status!r}")
        if severity is not None and severity not in SEVERITIES:
            raise ValueError(f"Unknown severity {severity!r}")

        def op(db: sqlite3.Connection) -> list[Incident]:
            sql = f"SELECT * FROM incidents WHERE {_STATUS_SQL[status]}"
            params: list[Any] = []
            if severity:
                sql += " AND severity = ?"
                params.append(severity)
            sql += " ORDER BY id DESC LIMIT ?"
            params.append(max(1, min(limit, 50)))
            return [Incident.from_row(r) for r in db.execute(sql, params)]

        return await self._run(op)

    async def counts(self) -> dict[str, dict[str, int]]:
        """Incident totals by status and, for open incidents, by severity."""

        def op(db: sqlite3.Connection) -> dict[str, dict[str, int]]:
            by_status = {
                row["status"]: row["n"]
                for row in db.execute("SELECT status, COUNT(*) AS n FROM incidents GROUP BY status")
            }
            open_by_severity = {
                row["severity"]: row["n"]
                for row in db.execute(
                    "SELECT severity, COUNT(*) AS n FROM incidents WHERE status != 'Closed' GROUP BY severity"
                )
            }
            return {"status": by_status, "open_by_severity": open_by_severity}

        return await self._run(op)

    async def get(self, incident_id: int) -> Incident:
        def op(db: sqlite3.Connection) -> Incident:
            row = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise self._not_found(incident_id)
            comments = [
                Comment.from_row(c)
                for c in db.execute(
                    "SELECT author, body, created FROM comments WHERE incident_id = ? ORDER BY id",
                    (incident_id,),
                )
            ]
            return Incident.from_row(row, comments)

        return await self._run(op)

    async def add_comment(self, incident_id: int, author: str, body: str) -> None:
        def op(db: sqlite3.Connection) -> None:
            self._add_comment(db, incident_id, author, body)

        await self._run(op)

    def _add_comment(self, db: sqlite3.Connection, incident_id: int, author: str, body: str) -> None:
        now = _now()
        if db.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
            raise self._not_found(incident_id)
        db.execute(
            "INSERT INTO comments (incident_id, author, body, created) VALUES (?, ?, ?, ?)",
            (incident_id, author, body, now),
        )
        db.execute("UPDATE incidents SET updated = ? WHERE id = ?", (now, incident_id))

    async def acknowledge(self, incident_id: int, assignee: str) -> Incident:
        def op(db: sqlite3.Connection) -> None:
            cur = db.execute(
                "UPDATE incidents SET status = 'Active', assignee = ?, updated = ? "
                "WHERE id = ? AND status = 'New'",
                (assignee, _now(), incident_id),
            )
            if cur.rowcount == 0:
                row = db.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
                if row is None:
                    raise self._not_found(incident_id)
                raise APIError(self.service, 409, f"Incident #{incident_id} is already {row['status'].lower()}.")

        await self._run(op)
        return await self.get(incident_id)

    async def close(self, incident_id: int, classification: str, comment: str, actor: str) -> Incident:
        if classification not in CLASSIFICATIONS:
            raise ValueError(f"Unknown classification {classification!r}")

        def op(db: sqlite3.Connection) -> None:
            cur = db.execute(
                "UPDATE incidents SET status = 'Closed', classification = ?, updated = ? "
                "WHERE id = ? AND status != 'Closed'",
                (classification, _now(), incident_id),
            )
            if cur.rowcount == 0:
                if db.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone() is None:
                    raise self._not_found(incident_id)
                # Someone else closed it between the analyst's lookup and confirm.
                raise APIError(self.service, 409, f"Incident #{incident_id} is already closed.")
            self._add_comment(db, incident_id, actor, f"Closed as {classification}: {comment}")

        await self._run(op)
        return await self.get(incident_id)
