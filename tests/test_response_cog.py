from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_bot.clients import NotConfiguredError, NotFoundError, SshResponseClient
from soc_bot.discord_bot.cogs import response as response_module
from soc_bot.discord_bot.cogs.response import ResponseCog
from soc_bot.models import IsolationResult
from soc_bot.store import IncidentStore

from .helpers import FakeUser, make_interaction, patch_confirm

HOSTS = {"srv1.corp.local": "10.0.0.5", "dc01": "10.0.0.6", "soc-victim": "192.168.56.20"}


class RecordingSsh(SshResponseClient):
    def __init__(self):
        super().__init__(hosts=HOSTS, user="responder", key_path="k")
        self.calls: list[tuple[str, str]] = []

    async def _run(self, action, hostname):
        name, address = self.resolve(hostname)
        self.calls.append((action, name))
        return IsolationResult(name, address, action, "ok")


@pytest.fixture
async def env(monkeypatch):
    store = IncidentStore(":memory:")
    incident = await store.create(rule="Test alert", severity="High", host="srv1.corp.local")
    bot = SimpleNamespace(
        ssh=RecordingSsh(), store=store, audit=AsyncMock(),
        settings=SimpleNamespace(isolation_denylist=("dc*", "*.corp.local")),
    )
    answers = patch_confirm(monkeypatch, response_module)
    yield SimpleNamespace(bot=bot, cog=ResponseCog(bot), incident=incident, answers=answers)
    store.shutdown()


def audit_outcomes(env):
    return [(c.args[1], c.args[2], c.args[3]) for c in env.bot.audit.await_args_list]


def refusal_text(interaction):
    """The refusal embed text, whether it was sent before or after the interaction was deferred."""
    mock = interaction.response.send_message
    if mock.await_args is None:
        mock = interaction.edit_original_response
    return mock.await_args.kwargs["embed"].description


ISOLATE_ADVICE = "Isolate it manually through the change-approval process."
UNISOLATE_ADVICE = "Releasing a protected host must also be done outside the bot, through the change-approval process."


async def test_isolate_on_deny_listed_typed_name_is_refused(env):
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Isolate", "dc01", "reason here", env.incident.id)

    assert env.bot.ssh.calls == []
    interaction.response.defer.assert_not_awaited()  # refused before any lookup
    assert audit_outcomes(env) == [("device.isolate", "dc01", "blocked")]
    text = refusal_text(interaction)
    assert "`dc01` is on the deny-list" in text and ISOLATE_ADVICE in text and "outside the bot" not in text


async def test_isolate_on_deny_listed_resolved_name_is_refused(env):
    # "srv1" is not on the deny-list, but it resolves to srv1.corp.local which matches *.corp.local.
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Isolate", "srv1", "reason here", env.incident.id)

    assert env.bot.ssh.calls == []
    assert audit_outcomes(env) == [("device.isolate", "srv1.corp.local", "blocked")]
    text = refusal_text(interaction)
    assert "`srv1.corp.local` is on the deny-list" in text and ISOLATE_ADVICE in text


async def test_unisolate_on_deny_listed_typed_name_is_refused_with_release_wording(env):
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Unisolate", "dc01", "reason here", env.incident.id)

    assert env.bot.ssh.calls == []
    interaction.response.defer.assert_not_awaited()
    assert audit_outcomes(env) == [("device.unisolate", "dc01", "blocked")]
    text = refusal_text(interaction)
    assert UNISOLATE_ADVICE in text and ISOLATE_ADVICE not in text


async def test_unisolate_on_deny_listed_resolved_name_is_refused_with_release_wording(env):
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Unisolate", "srv1", "reason here", env.incident.id)

    assert env.bot.ssh.calls == []
    assert audit_outcomes(env) == [("device.unisolate", "srv1.corp.local", "blocked")]
    assert UNISOLATE_ADVICE in refusal_text(interaction)


async def test_refused_host_never_reaches_the_confirm_step(env):
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Unisolate", "srv1", "reason here", env.incident.id)
    for call in interaction.edit_original_response.await_args_list:
        assert call.kwargs.get("view") is None  # no Confirm/Cancel buttons were ever offered
    assert (await env.bot.store.get(env.incident.id)).comments == []


async def test_foreign_fqdn_is_rejected_not_mapped_to_inventory(env):
    env.bot.settings.isolation_denylist = ()
    with pytest.raises(NotFoundError):
        await env.cog.device_action(make_interaction(), "Isolate", "soc-victim.evil.com", "reason here", env.incident.id)
    assert env.bot.ssh.calls == []


async def test_confirmed_isolation_runs_ssh_comments_and_audits(env):
    interaction = make_interaction(FakeUser(42, "analyst"))
    await env.cog.device_action(interaction, "Isolate", "soc-victim", "C2 beacon", env.incident.id)

    assert env.bot.ssh.calls == [("isolate", "soc-victim")]
    comment = (await env.bot.store.get(env.incident.id)).comments[-1]
    assert comment.author == "analyst"
    assert "Isolate executed on soc-victim (192.168.56.20). Reason: C2 beacon" in comment.body
    assert audit_outcomes(env) == [("device.isolate", "soc-victim", "success")]
    assert env.bot.audit.await_args.kwargs["incident"] == env.incident.id


async def test_result_embed_escapes_the_actor_name(env):
    interaction = make_interaction(FakeUser(42, "**admin** [click](http://evil.example)"))
    await env.cog.device_action(interaction, "Isolate", "soc-victim", "C2 beacon", env.incident.id)

    fields = {f.name: f.value for f in interaction.edit_original_response.await_args.kwargs["embed"].fields}
    assert "**admin**" not in fields["Requested by"] and "[click](" not in fields["Requested by"]


async def test_confirmed_unisolate_runs_ssh_and_audits(env):
    await env.cog.device_action(make_interaction(), "Unisolate", "soc-victim", "false alarm", env.incident.id)

    assert env.bot.ssh.calls == [("unisolate", "soc-victim")]
    assert audit_outcomes(env) == [("device.unisolate", "soc-victim", "success")]


async def test_cancelled_isolation_does_nothing(env):
    env.answers["confirm"] = False
    await env.cog.device_action(make_interaction(), "Isolate", "soc-victim", "C2 beacon", env.incident.id)

    assert env.bot.ssh.calls == []
    assert (await env.bot.store.get(env.incident.id)).comments == []
    assert audit_outcomes(env) == [("device.isolate", "soc-victim", "cancelled")]


async def test_unknown_incident_stops_before_any_ssh(env):
    with pytest.raises(NotFoundError):
        await env.cog.device_action(make_interaction(), "Isolate", "soc-victim", "reason here", 999)
    assert env.bot.ssh.calls == []


async def test_isolation_not_configured(env):
    env.bot.ssh = None
    with pytest.raises(NotConfiguredError):
        await env.cog.device_action(make_interaction(), "Isolate", "soc-victim", "reason here", env.incident.id)
