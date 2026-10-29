from __future__ import annotations

import json
import logging
import queue
from datetime import datetime, timezone
from logging.handlers import QueueHandler, QueueListener
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSON Lines audit trail of every command and its outcome."""

    def __init__(self, path: str | Path):
        self._file_handler = logging.FileHandler(path, encoding="utf-8")
        self._file_handler.setFormatter(logging.Formatter("%(message)s"))
        # Disk writes happen on a background thread so the event loop never blocks.
        records: queue.SimpleQueue[logging.LogRecord] = queue.SimpleQueue()
        self._listener = QueueListener(records, self._file_handler)
        self._listener.start()
        self._logger = logging.getLogger("soc_bot.audit")
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)
        self._logger.handlers = [QueueHandler(records)]

    def close(self) -> None:
        self._listener.stop()
        self._file_handler.close()

    def record(
        self,
        *,
        actor: str,
        actor_id: int,
        action: str,
        target: str,
        outcome: str,
        **details: Any,
    ) -> dict[str, Any]:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "actor_id": actor_id,
            "action": action,
            "target": target,
            "outcome": outcome,
            **details,
        }
        self._logger.info(json.dumps(entry, default=str))
        return entry


def read_recent(path: str | Path, limit: int = 20) -> list[dict[str, Any]]:
    """The newest `limit` audit entries, oldest first. Unreadable lines are skipped; a missing file is empty."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in lines[-max(1, limit) * 3 :]:
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            entries.append(obj)
    return entries[-max(1, limit) :]
