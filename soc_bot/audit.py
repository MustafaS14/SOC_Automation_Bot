from __future__ import annotations

import json
import logging
import queue
import re
from datetime import datetime, timezone
from logging.handlers import QueueHandler, QueueListener
from pathlib import Path
from typing import Any


# Things that look like secrets are blanked before anything is written, because questions and comments are free text
# and people paste keys into them. Not a guarantee, a safety net.
_SECRET_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}",                              # API keys (Anthropic, OpenAI style)
    r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}",             # GitHub tokens
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",                                 # Slack tokens
    r"\bAKIA[0-9A-Z]{16}\b",                                           # AWS access key ids
    r"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",    # Discord bot tokens
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",   # JWTs
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}",
    r"\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*\S+",
    r"\b[A-Fa-f0-9]{40,}\b",                                           # long hex strings (hashes, keys)
)]
REDACTED = "[redacted]"


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


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
            **{k: redact(v) if isinstance(v, str) else v for k, v in details.items()},
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
