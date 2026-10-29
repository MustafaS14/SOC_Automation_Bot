import logging
from types import SimpleNamespace

import discord

from soc_bot.config import Settings
from soc_bot.discord_bot.bot import MOCK_BANNER, SocBot
from soc_bot.models import Incident


def make_settings(tmp_path, **overrides):
    values = dict(
        discord_token="t", guild_id=None, allowed_channel_ids=frozenset({1}), audit_channel_id=None,
        read_role_ids=frozenset({1}), triage_role_ids=frozenset(), response_role_ids=frozenset(),
        isolation_denylist=(), mock_mode=True, audit_log_path=str(tmp_path / "audit.jsonl"),
    )
    return Settings(**{**values, **overrides})


async def test_mock_mode_logs_a_multi_line_banner(tmp_path, caplog):
    bot = SocBot(make_settings(tmp_path))
    with caplog.at_level(logging.WARNING, logger="soc_bot"):
        await bot._init_backends()
    bot.store.shutdown()
    bot.audit_log.close()

    warnings = [r.getMessage() for r in caplog.records if r.name == "soc_bot" and r.levelno == logging.WARNING]
    assert warnings == list(MOCK_BANNER)
    assert len(MOCK_BANNER) >= 3 and any("MOCK MODE IS ON" in line for line in MOCK_BANNER)


async def test_real_mode_logs_no_banner(tmp_path, caplog):
    bot = SocBot(make_settings(tmp_path, mock_mode=False, webhook_secret="s", db_path=str(tmp_path / "i.db")))
    with caplog.at_level(logging.WARNING, logger="soc_bot"):
        await bot._init_backends()
    bot.store.shutdown()
    bot.audit_log.close()
    await bot._http.aclose()

    assert not any("MOCK MODE" in r.getMessage() for r in caplog.records)


class FakeChannel(discord.abc.Messageable):
    def __init__(self):
        self.sent = []

    async def _get_channel(self):
        return self

    async def send(self, **kwargs):
        self.sent.append(kwargs)


async def post(mock_mode):
    channel = FakeChannel()
    fake_bot = SimpleNamespace(
        settings=SimpleNamespace(alert_channel_id=9, mock_mode=mock_mode),
        is_ready=lambda: True,
        get_channel=lambda channel_id: channel,
        assistant=None,
    )
    await SocBot.post_alert(fake_bot, Incident(id=3, rule="r", severity="High", status="New"))
    return channel.sent


async def test_alert_embed_footer_says_mock_mode():
    (sent,) = await post(mock_mode=True)
    assert sent["embed"].footer.text == "MOCK MODE" and sent["embed"].title == "#3 - r"


async def test_alert_embed_has_no_mock_footer_in_real_mode():
    (sent,) = await post(mock_mode=False)
    assert sent["embed"].footer.text is None
