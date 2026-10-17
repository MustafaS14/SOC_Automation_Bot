from types import SimpleNamespace
from unittest.mock import MagicMock

import discord
import pytest
from discord import app_commands

from soc_bot.discord_bot.checks import AccessDenied, ensure, require
from soc_bot.rbac import AccessPolicy, Permission

GUILD, CHANNEL = 10, 100
READ_ROLE, TRIAGE_ROLE, RESPONSE_ROLE = 1, 2, 3


def make_bot(guild_id=GUILD, channels=frozenset({CHANNEL})):
    return SimpleNamespace(
        settings=SimpleNamespace(guild_id=guild_id),
        policy=AccessPolicy(
            read_role_ids=frozenset({READ_ROLE}),
            triage_role_ids=frozenset({TRIAGE_ROLE}),
            response_role_ids=frozenset({RESPONSE_ROLE}),
            allowed_channel_ids=channels,
        ),
    )


def make_interaction(bot=None, *, role_ids=(READ_ROLE,), guild_id=GUILD, channel_id=CHANNEL, in_guild=True, member=True):
    user = MagicMock(spec=discord.Member if member else discord.User)
    user.roles = [SimpleNamespace(id=r) for r in role_ids]
    return SimpleNamespace(
        client=bot or make_bot(),
        guild=object() if in_guild else None,
        guild_id=guild_id,
        channel_id=channel_id,
        user=user,
    )


async def denied(interaction, level=Permission.READ) -> str:
    with pytest.raises(AccessDenied) as exc:
        await ensure(interaction, level)
    return exc.value.reason


async def test_direct_message_is_refused():
    assert "only available inside the SOC server" in await denied(make_interaction(in_guild=False))


async def test_user_that_is_not_a_guild_member_is_refused():
    assert "only available inside the SOC server" in await denied(make_interaction(member=False))


async def test_wrong_guild_is_refused():
    assert "server is not authorised" in await denied(make_interaction(guild_id=GUILD + 1))


async def test_any_guild_is_allowed_when_no_guild_is_pinned():
    await ensure(make_interaction(make_bot(guild_id=None), guild_id=999), Permission.READ)


async def test_wrong_channel_is_refused():
    assert "channel is not authorised" in await denied(make_interaction(channel_id=CHANNEL + 1))


async def test_empty_channel_allow_list_refuses_every_channel():
    interaction = make_interaction(make_bot(channels=frozenset()))
    assert "channel is not authorised" in await denied(interaction)


async def test_missing_channel_id_is_refused():
    assert "channel is not authorised" in await denied(make_interaction(channel_id=None))


async def test_user_without_any_role_is_refused():
    reason = await denied(make_interaction(role_ids=(999,)))
    assert "**READ**" in reason


async def test_user_with_no_roles_at_all_is_refused():
    assert "**READ**" in await denied(make_interaction(role_ids=()))


@pytest.mark.parametrize(
    "role, required",
    [(READ_ROLE, Permission.TRIAGE), (READ_ROLE, Permission.RESPONSE), (TRIAGE_ROLE, Permission.RESPONSE)],
)
async def test_role_below_the_required_tier_is_refused(role, required):
    reason = await denied(make_interaction(role_ids=(role,)), required)
    assert f"**{required.name}**" in reason


@pytest.mark.parametrize(
    "role, required",
    [
        (READ_ROLE, Permission.READ),
        (TRIAGE_ROLE, Permission.READ), (TRIAGE_ROLE, Permission.TRIAGE),
        (RESPONSE_ROLE, Permission.READ), (RESPONSE_ROLE, Permission.TRIAGE), (RESPONSE_ROLE, Permission.RESPONSE),
    ],
)
async def test_allowed_user_passes_and_higher_tiers_inherit(role, required):
    assert await ensure(make_interaction(role_ids=(role,)), required) is None


async def test_highest_role_wins_when_the_user_holds_several():
    await ensure(make_interaction(role_ids=(READ_ROLE, RESPONSE_ROLE)), Permission.RESPONSE)


async def test_guild_is_checked_before_channel_and_role():
    interaction = make_interaction(guild_id=GUILD + 1, channel_id=CHANNEL + 1, role_ids=())
    assert "server is not authorised" in await denied(interaction)


async def test_require_decorator_runs_the_same_check():
    @require(Permission.TRIAGE)
    async def command(interaction): ...

    (predicate,) = command.__discord_app_commands_checks__
    assert await predicate(make_interaction(role_ids=(TRIAGE_ROLE,))) is True
    with pytest.raises(AccessDenied):
        await predicate(make_interaction(role_ids=(READ_ROLE,)))
    assert issubclass(AccessDenied, app_commands.CheckFailure)
