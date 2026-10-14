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
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        # Disk writes happen on a background thread so the event loop never blocks.
        records: queue.SimpleQueue[logging.LogRecord] = queue.SimpleQueue()
        self._listener = QueueListener(records, file_handler)
        self._listener.start()
        self._logger = logging.getLogger("soc_bot.audit")
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)
        self._logger.handlers = [QueueHandler(records)]

    def close(self) -> None:
        self._listener.stop()

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
