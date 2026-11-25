from types import SimpleNamespace

import discord
import pytest

from soc_bot import first_response
from soc_bot.config import ConfigError, _severity_list
from soc_bot.discord_bot import embeds
from soc_bot.discord_bot.bot import SocBot
from soc_bot.models import Incident, IpReport


class FakeSplunk:
    def __init__(self, rows=None, fail=False):
        self.rows, self.fail, self.calls = rows if rows is not None else [{"_time": "t", "_raw": "whoami"}], fail, []

    async def search(self, spl, earliest="-1h", latest="now"):
        self.calls.append((spl, earliest))
        if self.fail:
            raise RuntimeError("down")
        return self.rows


class FakeEnrichment:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    async def enrich_ip(self, ip):
        self.calls.append(ip)
        if self.fail:
            raise RuntimeError("down")
        return IpReport(ip=ip, is_public=False)


def incident(**kw):
    return Incident(**{"id": 7, "rule": "r", "severity": "High", "status": "New", "host": "soc-victim",
                       "src_ip": "192.168.56.30", **kw})


async def test_runs_host_hunt_ip_hunt_and_enrichment():
    splunk, enrich = FakeSplunk(), FakeEnrichment()
    result = await first_response.run(incident(), splunk=splunk, enrichment=enrich)
    assert [h.name for h in result.hunts] == ["host_commands", "ip_activity"]
    assert 'host="soc-victim"' in splunk.calls[0][0] and splunk.calls[0][1] == "-1h"
    assert enrich.calls == ["192.168.56.30"] and result.report.verdict == "Internal"
    text = first_response.summary(result)
    assert "1 event(s)" in text and "Internal" in text


async def test_skips_what_the_incident_lacks():
    splunk, enrich = FakeSplunk(), FakeEnrichment()
    result = await first_response.run(incident(host=None, src_ip=None), splunk=splunk, enrichment=enrich)
    assert result.empty and not splunk.calls and not enrich.calls


async def test_bad_values_are_rejected_not_searched():
    splunk = FakeSplunk()
    result = await first_response.run(incident(host='x" | delete', src_ip="nope"), splunk=splunk, enrichment=None)
    assert not splunk.calls and all(h.rows is None for h in result.hunts)


async def test_failures_are_reported_not_raised():
    result = await first_response.run(incident(), splunk=FakeSplunk(fail=True), enrichment=FakeEnrichment(fail=True))
    assert all(h.rows is None for h in result.hunts) and result.enrich_error == "RuntimeError"
    assert "failed" in first_response.summary(result)
    assert embeds.first_response(7, result).fields


def test_embed_shows_rows_and_verdict():
    result = first_response.FirstResponse(
        hunts=[first_response.HuntOutcome("host_commands", "Commands on host", rows=[{"_time": "t", "_raw": "a```b"}])],
        report=IpReport(ip="192.168.56.30", is_public=False),
    )
    embed = embeds.first_response(7, result)
    assert "'''" in embed.fields[0].value and "Internal" in embed.fields[1].value


def test_severity_setting(monkeypatch):
    monkeypatch.delenv("FS", raising=False)
    assert _severity_list("FS", ("High", "Medium")) == ("High", "Medium")
    monkeypatch.setenv("FS", "medium, HIGH")
    assert _severity_list("FS", ()) == ("High", "Medium")
    monkeypatch.setenv("FS", "")
    assert _severity_list("FS", ("High",)) == ()
    monkeypatch.setenv("FS", "urgent")
    with pytest.raises(ConfigError):
        _severity_list("FS", ())


class Channel(discord.abc.Messageable):
    def __init__(self):
        self.sent = []

    async def _get_channel(self):
        return self

    async def send(self, **kw):
        self.sent.append(kw)


class Store:
    def __init__(self):
        self.comments = []

    async def add_comment(self, incident_id, author, body):
        self.comments.append((incident_id, author, body))


class Audit:
    def __init__(self):
        self.entries = []

    def record(self, **kw):
        self.entries.append(kw)
        return kw


def make_bot(splunk, severities=("High", "Medium")):
    chan = Channel()
    bot = SimpleNamespace(
        settings=SimpleNamespace(alert_channel_id=9, mock_mode=False, first_response_severities=severities),
        is_ready=lambda: True, get_channel=lambda _id: chan, assistant=None, splunk=splunk,
        enrichment=FakeEnrichment(), hec=None, store=Store(), audit_log=Audit(), spawned=[],
    )
    bot._spawn = bot.spawned.append
    bot._first_response = lambda inc, ch: SocBot._first_response(bot, inc, ch)
    return bot, chan


@pytest.mark.parametrize("severity,expected", [("High", 1), ("Medium", 1), ("Low", 0), ("Informational", 0)])
async def test_post_alert_spawns_first_response_only_for_configured_severities(severity, expected):
    bot, chan = make_bot(FakeSplunk())
    await SocBot.post_alert(bot, incident(severity=severity))
    assert len(bot.spawned) == expected
    for coro in bot.spawned:
        await coro
    assert len(chan.sent) == 1 + expected


async def test_first_response_comment_audit_and_card():
    bot, chan = make_bot(FakeSplunk())
    await SocBot._first_response(bot, incident(), chan)
    assert bot.store.comments[0][1] == "first-response"
    assert bot.audit_log.entries[0]["action"] == "auto.first_response" and bot.audit_log.entries[0]["outcome"] == "success"
    assert chan.sent[0]["embed"].title == "First response for #7"


async def test_partial_outcome_when_a_search_fails():
    bot, chan = make_bot(FakeSplunk(fail=True))
    await SocBot._first_response(bot, incident(), chan)
    assert bot.audit_log.entries[0]["outcome"] == "partial"


async def test_first_response_never_raises():
    bot, chan = make_bot(FakeSplunk())

    async def boom(*a, **k):
        raise RuntimeError("db")

    bot.store.add_comment = boom
    await SocBot._first_response(bot, incident(), chan)
    assert not chan.sent
