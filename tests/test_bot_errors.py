from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_bot.clients import APIError, NotConfiguredError, NotFoundError
from soc_bot.discord_bot import embeds
from soc_bot.discord_bot.bot import SocBot
from soc_bot.discord_bot.checks import AccessDenied
from soc_bot.models import Incident, IpReport
from soc_bot.validators import ValidationError

from .helpers import make_interaction

HOSTILE = "[click here](http://evil.example) **bold** `code` ||spoiler||"


async def handled(error, *, done=False):
    bot = SimpleNamespace(audit=AsyncMock())
    interaction = make_interaction()
    if done:
        await interaction.response.defer()
    await SocBot.handle_error(bot, interaction, "hunt", error)
    mock = interaction.edit_original_response if done else interaction.response.send_message
    return bot, mock.await_args.kwargs["embed"].description


async def test_upstream_error_text_is_escaped():
    _, text = await handled(APIError("Splunk", 400, HOSTILE))
    assert "[click here](" not in text and "\\[click here\\]" in text
    assert "**bold**" not in text and "||spoiler||" not in text


async def test_not_found_text_is_escaped_too():
    _, text = await handled(NotFoundError("Splunk", 404, HOSTILE))
    assert "[click here](" not in text


async def test_credentials_errors_do_not_echo_upstream_text():
    _, text = await handled(APIError("Splunk", 403, HOSTILE))
    assert "evil.example" not in text and "rejected the bot's credentials" in text


async def test_conflict_message_is_shown_to_the_analyst():
    _, text = await handled(APIError("Incident store", 409, "Incident #4 is already closed."))
    assert "already closed" in text


async def test_errors_are_audited_with_the_command_name():
    bot, _ = await handled(APIError("Splunk", 500, "boom"))
    assert bot.audit.await_args.args[1:4] == ("hunt", "-", "error")


async def test_access_denied_is_audited_and_explained():
    bot, text = await handled(AccessDenied("You need the **TRIAGE** SOC role tier"))
    assert "TRIAGE" in text and bot.audit.await_args.args[3] == "denied"


@pytest.mark.parametrize("error", [ValidationError("`x` is not a valid hostname."), NotConfiguredError("Splunk is not configured")])
async def test_validation_and_config_errors_pass_through(error):
    _, text = await handled(error)
    assert text == str(error)


async def test_unexpected_errors_do_not_leak_details():
    bot, text = await handled(RuntimeError("secret internal path C:\\x"))
    assert "secret" not in text and "Unexpected error" in text
    assert bot.audit.await_args.kwargs["error"] == "RuntimeError"


async def test_error_after_defer_edits_the_original_response():
    _, text = await handled(APIError("Splunk", 500, "boom"), done=True)
    assert "boom" in text


# --- embed escaping ---

def test_md_neutralises_masked_links_and_formatting():
    text = embeds.md(HOSTILE)
    assert "[click here](" not in text and "\\[click here\\]" in text
    assert "**bold**" not in text and "`code`" not in text


def test_incident_embeds_escape_splunk_supplied_text():
    incident = Incident(
        id=1, rule=HOSTILE, severity="High", status="New", host="**h**", description=HOSTILE,
    )
    embed = embeds.incident_detail(incident)
    assert "[click here](" not in embed.title and "[click here](" not in embed.description
    assert "**h**" not in embed.fields[2].value + embed.fields[3].value
    assert "[click here](" not in embeds.incident_list([incident], "open", None).description


def test_hunt_rows_cannot_break_out_of_the_code_block():
    embed = embeds.hunt_results("label", "1h", [{"_time": "t", "_raw": "```\n@everyone [x](http://evil)"}])
    assert embed.description.count("```") == 2


def test_incomplete_verdict_has_a_colour():
    report = IpReport(ip="1.1.1.1", is_public=True, errors=["x"])
    assert embeds.ip_report(report).color == embeds.VERDICT_COLORS["Incomplete"]
