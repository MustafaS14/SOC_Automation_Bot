"""AI triage assistant: read-only, clearance-gated, behind a swappable backend."""

from __future__ import annotations

from ..config import Settings
from .assistant import AiAnswer, Assistant, split_plain_words
from .backends import AiBackend, BackendError, ClaudeCodeBackend, MockBackend
from .tools import ToolContext


def build_assistant(settings: Settings, ctx: ToolContext) -> Assistant | None:
    """The configured assistant, or None when AI_BACKEND is off."""
    if settings.ai_backend == "off":
        return None
    backend: AiBackend
    if settings.ai_backend == "mock":
        backend = MockBackend()
    else:
        backend = ClaudeCodeBackend(settings.ai_command, settings.ai_model, settings.ai_timeout)
    return Assistant(
        backend,
        ctx,
        user_questions_per_hour=settings.ai_user_questions_per_hour,
        auto_notes_per_hour=settings.ai_auto_notes_per_hour,
        daily_calls=settings.ai_daily_calls,
    )


__all__ = ["AiAnswer", "AiBackend", "Assistant", "BackendError", "ClaudeCodeBackend", "MockBackend", "ToolContext", "build_assistant", "split_plain_words"]
