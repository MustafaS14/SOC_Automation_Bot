from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_bot.clients import NotConfiguredError, NotFoundError, SshResponseClient
from soc_bot.discord_bot.cogs import response as response_module
from soc_bot.discord_bot.cogs.response import ResponseCog
from soc_bot.models import IsolationResult
from soc_bot.store import IncidentStore

HOSTS = {"srv1.corp.local": "10.0.0.5", "dc01": "10.0.0.6", "soc-victim": "192.168.56.20"}


class RecordingSsh(SshResponseClient):
    def __init__(self):
        super().__init__(hosts=HOSTS, user="responder", key_path="k")
        self.calls: list[tuple[str, str]] = []

    async def _run(self, action, hostname):
        name, address = self.resolve(hostname)
        self.calls.append((action, name))
        return IsolationResult(name, address, action, "ok")


class FakeResponse:
    def __init__(self):
        self.done = False
        self.defer = AsyncMock(side_effect=self._defer)
        self.send_message = AsyncMock()

    async def _defer(self, **_):
        self.done = True

    def is_done(self):
        return self.done


def make_interaction():
    return SimpleNamespace(
        response=FakeResponse(),
        edit_original_response=AsyncMock(),
        user=SimpleNamespace(id=42, __str__=lambda self: "analyst"),
    )


@pytest.fixture
async def env(monkeypatch):
    store = IncidentStore(":memory:")
    incident = await store.create(rule="Test alert", severity="High", host="srv1.corp.local")
    bot = SimpleNamespace(
        ssh=RecordingSsh(), store=store, audit=AsyncMock(),
        settings=SimpleNamespace(isolation_denylist=("dc*", "*.corp.local")),
    )
    answers = {"confirm": True}

    class FakeView:
        def __init__(self, author_id):
            pass

        async def ask(self):
            return answers["confirm"]

    monkeypatch.setattr(response_module, "ConfirmView", FakeView)
    yield SimpleNamespace(bot=bot, cog=ResponseCog(bot), incident=incident, answers=answers)
    store.shutdown()


def audit_outcomes(env):
    return [(c.args[1], c.args[2], c.args[3]) for c in env.bot.audit.await_args_list]


async def test_typed_name_on_denylist_is_blocked_before_resolution(env):
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Isolate", "dc01", "reason here", env.incident.id)

    assert env.bot.ssh.calls == []
    interaction.response.defer.assert_not_awaited()
    assert audit_outcomes(env) == [("device.isolate", "dc01", "blocked")]


async def test_resolved_name_is_checked_against_denylist_again(env):
    # "srv1" is not on the deny-list, but it resolves to srv1.corp.local which matches *.corp.local.
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Isolate", "srv1", "reason here", env.incident.id)

    assert env.bot.ssh.calls == []
    assert audit_outcomes(env) == [("device.isolate", "srv1.corp.local", "blocked")]


async def test_foreign_fqdn_is_rejected_not_mapped_to_inventory(env):
    env.bot.settings.isolation_denylist = ()
    with pytest.raises(NotFoundError):
        await env.cog.device_action(make_interaction(), "Isolate", "soc-victim.evil.com", "reason here", env.incident.id)
    assert env.bot.ssh.calls == []


async def test_confirmed_isolation_runs_ssh_comments_and_audits(env):
    interaction = make_interaction()
    await env.cog.device_action(interaction, "Isolate", "soc-victim", "C2 beacon", env.incident.id)

    assert env.bot.ssh.calls == [("isolate", "soc-victim")]
    comments = (await env.bot.store.get(env.incident.id)).comments
    assert "Isolate executed on soc-victim (192.168.56.20). Reason: C2 beacon" in comments[-1].body
    assert audit_outcomes(env) == [("device.isolate", "soc-victim", "success")]
    assert env.bot.audit.await_args.kwargs["incident"] == env.incident.id


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
