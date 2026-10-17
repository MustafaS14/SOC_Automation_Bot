from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_bot.clients import NotConfiguredError, NotFoundError
from soc_bot.discord_bot import alerts as alerts_module
from soc_bot.discord_bot import embeds
from soc_bot.discord_bot.alerts import AlertButton, alert_view
from soc_bot.discord_bot.checks import AccessDenied
from soc_bot.discord_bot.cogs.enrichment import EnrichmentCog
from soc_bot.discord_bot.cogs.hunt import HuntCog
from soc_bot.models import IpReport
from soc_bot.rbac import Permission
from soc_bot.store import IncidentStore
from soc_bot.validators import ValidationError

from .helpers import FakeUser, make_interaction, sent_embed


@pytest.fixture
async def store():
    s = IncidentStore(":memory:")
    yield s
    s.shutdown()


# --- /hunt ---

async def test_hunt_runs_template_with_validated_target(store):
    search = AsyncMock(return_value=[{"_time": "t", "host": "soc-victim", "_raw": "whoami"}])
    bot = SimpleNamespace(splunk=SimpleNamespace(search=search), audit=AsyncMock())
    cog, interaction = HuntCog(bot), make_interaction()

    await cog.hunt.callback(cog, interaction, template="host_commands", window="24h", target="SOC-Victim")

    spl = search.await_args.args[0]
    assert 'host="soc-victim"' in spl and search.await_args.kwargs["earliest"] == "-24h"
    assert "whoami" in sent_embed(interaction.followup.send).description
    assert bot.audit.await_args.args[1:4] == ("hunt.run", "host_commands", "success")


@pytest.mark.parametrize("target", ['x" | delete index=linux', "a b", "`", ""])
async def test_hunt_rejects_spl_in_target_before_contacting_splunk(target):
    search = AsyncMock()
    bot = SimpleNamespace(splunk=SimpleNamespace(search=search), audit=AsyncMock())
    interaction = make_interaction()
    with pytest.raises(ValidationError):
        await HuntCog(bot).hunt.callback(HuntCog(bot), interaction, template="host_commands", window="1h", target=target)
    search.assert_not_awaited()
    interaction.response.defer.assert_not_awaited()


async def test_hunt_without_splunk_is_not_configured():
    bot = SimpleNamespace(splunk=None, audit=AsyncMock())
    with pytest.raises(NotConfiguredError):
        await HuntCog(bot).hunt.callback(HuntCog(bot), make_interaction(), template="ssh_failures", window="1h", target=None)


# --- /enrich ---

def enrichment_bot(store, report):
    return SimpleNamespace(
        store=store, audit=AsyncMock(), enrichment=SimpleNamespace(enrich_ip=AsyncMock(return_value=report))
    )


async def test_enrich_records_verdict_on_linked_incident(store):
    await store.create(rule="r", severity="High", src_ip="8.8.8.8")
    bot = enrichment_bot(store, IpReport(ip="8.8.8.8", is_public=True, abuse_score=90, vt_malicious=6))
    cog, interaction = EnrichmentCog(bot), make_interaction(FakeUser(1, "alice"))

    await cog.enrich.callback(cog, interaction, ip="8.8.8.8", incident="1")

    comment = (await store.get(1)).comments[-1]
    assert comment.author == "alice" and "verdict Malicious" in comment.body
    assert "Verdict: **Malicious**" in sent_embed(interaction.followup.send).description
    assert bot.audit.await_args.kwargs["incident"] == 1


async def test_enrich_without_incident_leaves_store_alone(store):
    await store.create(rule="r", severity="High")
    bot = enrichment_bot(store, IpReport(ip="8.8.8.8", is_public=True, abuse_score=0, vt_malicious=0))
    await EnrichmentCog(bot).enrich.callback(EnrichmentCog(bot), make_interaction(), ip="8.8.8.8", incident=None)
    assert (await store.get(1)).comments == []


async def test_enrich_validates_before_lookup(store):
    bot = enrichment_bot(store, IpReport(ip="x", is_public=True))
    cog, interaction = EnrichmentCog(bot), make_interaction()
    with pytest.raises(ValidationError):
        await cog.enrich.callback(cog, interaction, ip="999.1.1.1", incident=None)
    with pytest.raises(NotFoundError):
        await cog.enrich.callback(cog, interaction, ip="8.8.8.8", incident="42")
    bot.enrichment.enrich_ip.assert_not_awaited()


# --- alert buttons ---

@pytest.fixture
def alert_env(monkeypatch):
    ensure = AsyncMock()
    monkeypatch.setattr(alerts_module, "ensure", ensure)
    return ensure


def alert_interaction(bot, name="alice"):
    interaction = make_interaction(FakeUser(5, name))
    interaction.client = bot
    return interaction


async def test_alert_view_has_three_persistent_buttons():
    view = alert_view(7)
    assert [c.item.custom_id for c in view.children] == ["soc:ack:7", "soc:enrich:7", "soc:isolate:7"]
    assert view.timeout is None


@pytest.mark.parametrize(
    "action, level",
    [("ack", Permission.TRIAGE), ("enrich", Permission.READ), ("isolate", Permission.RESPONSE)],
)
async def test_each_button_enforces_its_tier(store, alert_env, action, level):
    await store.create(rule="r", severity="High", host="soc-victim", src_ip="1.2.3.4")
    bot = SimpleNamespace(
        store=store, audit=AsyncMock(),
        cogs={"EnrichmentCog": SimpleNamespace(enrich_ip=AsyncMock()),
              "ResponseCog": SimpleNamespace(device_action=AsyncMock())},
    )
    interaction = alert_interaction(bot)

    await AlertButton(action, 1).callback(interaction)

    alert_env.assert_awaited_once_with(interaction, level)


async def test_denied_user_changes_nothing(store, alert_env):
    await store.create(rule="r", severity="High")
    alert_env.side_effect = AccessDenied("no")
    interaction = alert_interaction(SimpleNamespace(store=store, audit=AsyncMock(), cogs={}))

    with pytest.raises(AccessDenied):
        await AlertButton("ack", 1).callback(interaction)
    assert (await store.get(1)).status == "New"


async def test_ack_marks_active_and_assigns(store, alert_env):
    await store.create(rule="r", severity="High")
    bot = SimpleNamespace(store=store, audit=AsyncMock(), cogs={})
    interaction = alert_interaction(bot)

    await AlertButton("ack", 1).callback(interaction)

    incident = await store.get(1)
    assert (incident.status, incident.assignee) == ("Active", "alice")
    assert bot.audit.await_args.args[1:4] == ("incident.ack", "#1", "success")


async def test_enrich_button_delegates_with_the_alert_ip(store, alert_env):
    await store.create(rule="r", severity="High", src_ip="1.2.3.4")
    enrich = SimpleNamespace(enrich_ip=AsyncMock())
    bot = SimpleNamespace(store=store, audit=AsyncMock(), cogs={"EnrichmentCog": enrich})
    interaction = alert_interaction(bot)

    await AlertButton("enrich", 1).callback(interaction)
    enrich.enrich_ip.assert_awaited_once_with(interaction, "1.2.3.4", 1)


async def test_isolate_button_delegates_with_the_alert_host(store, alert_env):
    await store.create(rule="r", severity="High", host="soc-victim")
    response = SimpleNamespace(device_action=AsyncMock())
    bot = SimpleNamespace(store=store, audit=AsyncMock(), cogs={"ResponseCog": response})
    interaction = alert_interaction(bot)

    await AlertButton("isolate", 1).callback(interaction)

    args = response.device_action.await_args.args
    assert args[:3] == (interaction, "Isolate", "soc-victim") and "#1" in args[3] and args[4] == 1


@pytest.mark.parametrize("action, field", [("enrich", "src_ip"), ("isolate", "host")])
async def test_buttons_explain_when_the_alert_lacks_data(store, alert_env, action, field):
    await store.create(rule="r", severity="High")
    cogs = {"EnrichmentCog": SimpleNamespace(enrich_ip=AsyncMock()),
            "ResponseCog": SimpleNamespace(device_action=AsyncMock())}
    interaction = alert_interaction(SimpleNamespace(store=store, audit=AsyncMock(), cogs=cogs))

    await AlertButton(action, 1).callback(interaction)

    assert interaction.response.send_message.await_args.kwargs["ephemeral"] is True
    cogs["EnrichmentCog"].enrich_ip.assert_not_awaited()
    cogs["ResponseCog"].device_action.assert_not_awaited()


async def test_button_errors_go_to_the_bot_error_handler():
    bot = SimpleNamespace(handle_error=AsyncMock())
    interaction = alert_interaction(bot)
    boom = RuntimeError("boom")

    await AlertButton("ack", 1).on_error(interaction, boom)
    bot.handle_error.assert_awaited_once_with(interaction, "alert.ack", boom)


EVIL_NAME = "**admin** [click](http://evil.example) `x` ||s||"


async def test_ack_notice_escapes_the_actor_name(store, alert_env):
    await store.create(rule="r", severity="High")
    bot = SimpleNamespace(store=store, audit=AsyncMock(), cogs={})
    interaction = alert_interaction(bot, EVIL_NAME)

    await AlertButton("ack", 1).callback(interaction)

    text = sent_embed(interaction.response.send_message).description
    assert "**admin**" not in text and "[click](" not in text and "||s||" not in text
    assert "acknowledged by" in text and "\\[click\\]" in text
    assert (await store.get(1)).assignee == EVIL_NAME  # stored as typed; escaped only when rendered
    assert "[click](" not in embeds.incident_detail(await store.get(1)).fields[2].value
