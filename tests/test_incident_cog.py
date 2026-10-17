from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_bot.clients import NotFoundError
from soc_bot.discord_bot.cogs import incidents as incidents_module
from soc_bot.discord_bot.cogs.incidents import IncidentCog
from soc_bot.store import IncidentStore
from soc_bot.validators import ValidationError

from .helpers import FakeUser, make_interaction, patch_confirm, sent_embed


@pytest.fixture
async def env(monkeypatch):
    store = IncidentStore(":memory:")
    first = await store.create(rule="Discovery commands", severity="High", host="soc-victim", src_ip="1.2.3.4")
    await store.create(rule="Noisy cron", severity="Low")
    bot = SimpleNamespace(store=store, audit=AsyncMock())
    answers = patch_confirm(monkeypatch, incidents_module)
    yield SimpleNamespace(bot=bot, cog=IncidentCog(bot), first=first, answers=answers)
    store.shutdown()


def audited(env):
    return [(c.args[1], c.args[2], c.args[3]) for c in env.bot.audit.await_args_list]


async def test_list_shows_incidents_and_audits(env):
    interaction = make_interaction()
    await env.cog.list_incidents.callback(env.cog, interaction, status="open", severity=None, limit=10)

    description = sent_embed(interaction.followup.send).description
    assert "Discovery commands" in description and "Noisy cron" in description
    assert audited(env) == [("incident.list", "open", "success")]


async def test_list_filters_by_severity(env):
    interaction = make_interaction()
    await env.cog.list_incidents.callback(env.cog, interaction, status="open", severity="High", limit=10)

    description = sent_embed(interaction.followup.send).description
    assert "Discovery commands" in description and "Noisy cron" not in description


async def test_show_renders_incident_and_comments(env):
    await env.bot.store.add_comment(env.first.id, "analyst", "looking into it")
    interaction = make_interaction()
    await env.cog.show.callback(env.cog, interaction, incident="#1")

    embed = sent_embed(interaction.followup.send)
    assert embed.title == "#1 - Discovery commands"
    assert any("looking into it" in f.value for f in embed.fields)
    assert audited(env) == [("incident.show", "#1", "success")]


async def test_show_unknown_incident_raises_not_found(env):
    with pytest.raises(NotFoundError):
        await env.cog.show.callback(env.cog, make_interaction(), incident="99")


@pytest.mark.parametrize("ref", ["\u00b2", "abc", "0", "1; DROP TABLE incidents", "0b3f8a9e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"])
async def test_invalid_refs_fail_validation_before_any_work(env, ref):
    interaction = make_interaction()
    for call in (
        env.cog.show.callback(env.cog, interaction, incident=ref),
        env.cog.comment.callback(env.cog, interaction, incident=ref, message="hello"),
        env.cog.close.callback(env.cog, interaction, incident=ref, classification="benign", comment="reason"),
    ):
        with pytest.raises(ValidationError):
            await call
    interaction.response.defer.assert_not_awaited()


async def test_comment_is_attributed_to_the_analyst(env):
    interaction = make_interaction(FakeUser(7, "alice"))
    await env.cog.comment.callback(env.cog, interaction, incident="1", message="<b>hi</b>")

    comment = (await env.bot.store.get(1)).comments[-1]
    assert (comment.author, comment.body) == ("alice", "<b>hi</b>")
    assert audited(env) == [("incident.comment", "#1", "success")]


async def test_comment_on_unknown_incident(env):
    with pytest.raises(NotFoundError):
        await env.cog.comment.callback(env.cog, make_interaction(), incident="99", message="hello")


async def test_confirmed_close_updates_store_and_audits(env):
    interaction = make_interaction(FakeUser(7, "alice"))
    await env.cog.close.callback(
        env.cog, interaction, incident="1", classification="true_positive", comment="host contained"
    )

    closed = await env.bot.store.get(1)
    assert closed.status == "Closed" and closed.classification == "true_positive"
    assert "alice" == closed.comments[-1].author and "host contained" in closed.comments[-1].body
    assert audited(env) == [("incident.close", "#1", "success")]
    assert env.bot.audit.await_args.kwargs["classification"] == "True Positive"


async def test_cancelled_close_changes_nothing(env):
    env.answers["confirm"] = False
    await env.cog.close.callback(env.cog, make_interaction(), incident="1", classification="benign", comment="reason")

    assert (await env.bot.store.get(1)).status == "New"
    assert audited(env) == [("incident.close", "#1", "cancelled")]


async def test_closing_an_already_closed_incident_is_a_noop(env):
    await env.bot.store.close(1, "benign", "earlier", "bob")
    interaction = make_interaction()
    await env.cog.close.callback(env.cog, interaction, incident="1", classification="false_positive", comment="again")

    assert (await env.bot.store.get(1)).classification == "benign"
    assert "already closed" in sent_embed(interaction.edit_original_response).description
    assert audited(env) == []


async def test_closed_by_field_escapes_the_actor_name(env):
    interaction = make_interaction(FakeUser(7, "**admin** [click](http://evil.example)"))
    await env.cog.close.callback(env.cog, interaction, incident="1", classification="benign", comment="fine")

    closed_by = {f.name: f.value for f in sent_embed(interaction.edit_original_response).fields}["Closed by"]
    assert "**admin**" not in closed_by and "[click](" not in closed_by
