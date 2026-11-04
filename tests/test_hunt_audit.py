"""/hunt with the real SocBot.audit and AuditLogger. The cog tests mock audit, which hid a keyword collision."""

import json

from soc_bot.discord_bot.bot import SocBot
from soc_bot.discord_bot.cogs.hunt import HuntCog

from .helpers import make_interaction
from .test_bot_mock import make_settings


async def test_hunt_writes_a_real_audit_entry(tmp_path):
    bot = SocBot(make_settings(tmp_path))
    await bot._init_backends()
    cog, interaction = HuntCog(bot), make_interaction()

    await cog.hunt.callback(cog, interaction, template="host_commands", window="1h", target="soc-victim")

    bot.store.shutdown()
    bot.audit_log.close()  # flushes the background writer
    entries = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == "hunt.run" and entry["outcome"] == "success"
    assert entry["target"] == "host_commands"  # the template, not overwritten by the searched host
    assert entry["hunt_target"] == "soc-victim" and entry["window"] == "1h" and entry["rows"] == 2
