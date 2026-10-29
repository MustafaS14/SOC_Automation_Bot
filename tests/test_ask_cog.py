from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_bot.ai.assistant import AiAnswer
from soc_bot.clients import NotConfiguredError
from soc_bot.discord_bot import embeds
from soc_bot.discord_bot.bot import SocBot
from soc_bot.discord_bot.cogs.ask import AskCog
from soc_bot.models import Incident
from soc_bot.rbac import AccessPolicy, Permission

from .helpers import make_interaction, sent_embed

POLICY = AccessPolicy(frozenset({1}), frozenset(), frozenset(), frozenset({100}), viewer_role_ids=frozenset({4}))


def interaction_with_role(role_id):
    interaction = make_interaction()
    interaction.user.roles = [SimpleNamespace(id=role_id)]
    return interaction


async def test_ask_passes_the_askers_tier_and_audits():
    assistant = SimpleNamespace(ask=AsyncMock(return_value=AiAnswer("Two open.", "answered", ["incident_counts"], False, 2)))
    bot = SimpleNamespace(assistant=assistant, policy=POLICY, audit=AsyncMock())
    cog, interaction = AskCog(bot), interaction_with_role(4)

    await cog.ask.callback(cog, interaction, question="how many incidents?")

    assert assistant.ask.await_args.args[1] is Permission.VIEWER
    assert sent_embed(interaction.followup.send).description == "Two open."
    action, target, outcome = bot.audit.await_args.args[1:4]
    assert (action, target, outcome) == ("ai.ask", "Viewer", "answered")
    assert bot.audit.await_args.kwargs["tools"] == "incident_counts"


async def test_ask_records_denials():
    answer = AiAnswer("That's outside your clearance level.", "answered", ["get_incident"], True, 2)
    bot = SimpleNamespace(assistant=SimpleNamespace(ask=AsyncMock(return_value=answer)), policy=POLICY, audit=AsyncMock())
    cog = AskCog(bot)
    await cog.ask.callback(cog, interaction_with_role(4), question="show incident 1")
    assert bot.audit.await_args.kwargs["denied"] is True


async def test_ask_without_assistant_says_it_is_not_enabled():
    bot = SimpleNamespace(assistant=None, policy=POLICY, audit=AsyncMock())
    cog = AskCog(bot)
    with pytest.raises(NotConfiguredError):
        await cog.ask.callback(cog, interaction_with_role(4), question="hello")


def test_answer_embed_escapes_untrusted_text_and_links():
    embed = embeds.ai_answer("q", "see [click](http://evil.example) **bold**")
    assert "[click]" not in embed.description and "http://evil.example" in embed.description
    assert "\\[click\\]" in embed.description


class FakeChannel:
    def __init__(self):
        self.sent = []

    async def send(self, **kwargs):
        self.sent.append(kwargs)


def fake_bot(answer=None, error=None):
    async def triage_note(incident_id):
        if error:
            raise error
        return answer

    return SimpleNamespace(
        assistant=SimpleNamespace(triage_note=triage_note),
        audit_log=SimpleNamespace(record=lambda **kwargs: kwargs),
        hec=None,
        store=SimpleNamespace(add_comment=AsyncMock()),
        _spawn=lambda coro: coro.close(),
    )


INCIDENT = Incident(id=3, rule="r", severity="High", status="New")


async def test_triage_note_is_posted_and_stored_as_a_comment():
    bot, channel = fake_bot(AiAnswer("Likely Discovery.", "answered", ["get_incident"], False, 2)), FakeChannel()
    await SocBot._post_triage_note(bot, INCIDENT, channel)
    bot.store.add_comment.assert_awaited_once_with(3, "triage-assistant", "Likely Discovery.")
    assert channel.sent[0]["embed"].title == "Triage note for #3"


async def test_triage_note_is_skipped_when_rate_limited():
    bot, channel = fake_bot(AiAnswer("limit", "rate_limited")), FakeChannel()
    await SocBot._post_triage_note(bot, INCIDENT, channel)
    assert channel.sent == [] and not bot.store.add_comment.await_count


async def test_triage_note_failure_never_raises():
    bot, channel = fake_bot(error=RuntimeError("boom")), FakeChannel()
    await SocBot._post_triage_note(bot, INCIDENT, channel)
    assert channel.sent == []
