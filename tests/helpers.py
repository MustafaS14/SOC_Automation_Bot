"""Fakes for exercising Discord cogs without a gateway connection."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock


class FakeUser:
    def __init__(self, user_id: int = 42, name: str = "analyst"):
        self.id = user_id
        self.display_name = name
        self._name = name

    def __str__(self) -> str:
        return self._name


class FakeResponse:
    def __init__(self):
        self.done = False
        self.defer = AsyncMock(side_effect=self._mark_done)
        self.send_message = AsyncMock(side_effect=self._mark_done)

    async def _mark_done(self, *args, **kwargs):
        self.done = True

    def is_done(self) -> bool:
        return self.done


def make_interaction(user: FakeUser | None = None):
    return SimpleNamespace(
        response=FakeResponse(),
        followup=SimpleNamespace(send=AsyncMock()),
        edit_original_response=AsyncMock(),
        user=user or FakeUser(),
        channel_id=1,
    )


def patch_confirm(monkeypatch, module) -> dict[str, bool]:
    """Replace ConfirmView in `module` with a stub whose answer is answers['confirm']."""
    answers = {"confirm": True}

    class StubView:
        def __init__(self, author_id):
            pass

        async def ask(self):
            return answers["confirm"]

    monkeypatch.setattr(module, "ConfirmView", StubView)
    return answers


def sent_embed(mock: AsyncMock):
    """The embed passed to the last call of a send/edit mock."""
    return mock.await_args.kwargs["embed"]
