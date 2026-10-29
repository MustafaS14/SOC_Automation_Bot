import json

import pytest

from soc_bot.ai.assistant import build_prompt
from soc_bot.ai.tools import LEVEL_LABELS, TOOLS, ToolContext, execute, tools_for
from soc_bot.audit import read_recent
from soc_bot.models import IpReport
from soc_bot.rbac import Permission
from soc_bot.store import IncidentStore


class FakeSplunk:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    async def search(self, spl, earliest="-1h", latest="now"):
        self.calls.append((spl, earliest))
        return self.rows


class FakeEnrichment:
    async def enrich_ip(self, value):
        return IpReport(ip=value, is_public=True, abuse_score=90, vt_malicious=7, country="XX")


class FakeSsh:
    def resolve(self, hostname):
        return hostname, "192.168.56.20"


@pytest.fixture
async def store():
    s = IncidentStore(":memory:")
    yield s
    s.shutdown()


async def seeded(store):
    inc = await store.create(
        rule="Discovery commands", severity="High", host="soc-victim", src_ip="203.0.113.9",
        description="whoami; id; uname -a",
    )
    await store.add_comment(inc.id, "alice", "looks like Caldera")
    return inc


def names(level):
    return {t.name for t in tools_for(level)}


def test_tools_grow_with_the_level():
    assert names(Permission.VIEWER) == {"incident_counts", "incident_summary", "list_incidents"}
    assert {"get_incident", "run_hunt", "enrich_ip"} <= names(Permission.READ)
    assert "isolation_preview" not in names(Permission.TRIAGE)
    assert "isolation_preview" in names(Permission.RESPONSE)
    assert "recent_audit" not in names(Permission.RESPONSE)
    assert names(Permission.ADMIN) == set(TOOLS)


def test_every_level_has_a_label():
    assert set(LEVEL_LABELS) == set(Permission)


def test_prompt_only_lists_the_askers_tools():
    prompt = build_prompt(Permission.VIEWER, "how many incidents?", [])
    assert "<user_level>Viewer</user_level>" in prompt
    assert "incident_counts" in prompt
    for hidden in ("get_incident", "run_hunt", "enrich_ip", "isolation_preview", "recent_audit"):
        assert hidden not in prompt


async def test_denied_call_returns_no_data(store):
    await seeded(store)
    ctx = ToolContext(store=store)
    result = await execute(ctx, Permission.VIEWER, "get_incident", {"incident": "1"})
    assert result.denied and result.text.startswith("ACCESS_DENIED")
    assert "soc-victim" not in result.text and "203.0.113.9" not in result.text


async def test_viewer_summary_hides_host_ip_description_and_comments(store):
    inc = await seeded(store)
    ctx = ToolContext(store=store)
    text = (await execute(ctx, Permission.VIEWER, "incident_summary", {"incident": inc.id})).text
    assert "Discovery commands" in text and "severity=High" in text and "comments=1" in text
    for secret in ("soc-victim", "203.0.113.9", "whoami", "Caldera"):
        assert secret not in text


async def test_viewer_list_hides_hosts_but_analyst_sees_them(store):
    await seeded(store)
    ctx = ToolContext(store=store)
    viewer = (await execute(ctx, Permission.VIEWER, "list_incidents", {})).text
    analyst = (await execute(ctx, Permission.READ, "list_incidents", {})).text
    assert "soc-victim" not in viewer and "soc-victim" in analyst


async def test_analyst_gets_full_detail(store):
    inc = await seeded(store)
    text = (await execute(ToolContext(store=store), Permission.READ, "get_incident", {"incident": str(inc.id)})).text
    assert "soc-victim" in text and "203.0.113.9" in text and "whoami" in text and "looks like Caldera" in text


async def test_counts(store):
    await seeded(store)
    text = (await execute(ToolContext(store=store), Permission.VIEWER, "incident_counts", {})).text
    assert "open incidents: 1" in text and "High: 1" in text


async def test_bad_arguments_become_errors_not_exceptions(store):
    ctx = ToolContext(store=store)
    assert (await execute(ctx, Permission.READ, "get_incident", {"incident": "abc"})).error
    assert (await execute(ctx, Permission.READ, "get_incident", {"incident": "99"})).text.startswith("ERROR")
    assert (await execute(ctx, Permission.READ, "get_incident", "not a dict")).error
    assert (await execute(ctx, Permission.ADMIN, "format_disk", {})).error


async def test_hunt_validates_target_and_caps_rows(store):
    rows = [{"_time": str(i), "host": "soc-victim", "_raw": "x" * 1000} for i in range(50)]
    splunk = FakeSplunk(rows)
    ctx = ToolContext(store=store, splunk=splunk, max_rows=5)

    bad = await execute(ctx, Permission.READ, "run_hunt", {"template": "host_commands", "target": 'x" | delete'})
    assert bad.error and splunk.calls == []

    ok = await execute(ctx, Permission.READ, "run_hunt", {"template": "host_commands", "window": "1h", "target": "SOC-Victim"})
    assert 'host="soc-victim"' in splunk.calls[0][0]
    assert ok.text.count("\n") == 5 and "showing 5 of 50" in ok.text
    assert max(len(line) for line in ok.text.splitlines()) < 500


async def test_hunt_without_splunk_is_an_error_text(store):
    result = await execute(ToolContext(store=store), Permission.READ, "run_hunt", {"template": "ssh_failures"})
    assert result.text == "ERROR: Splunk is not configured."


async def test_enrich_ip(store):
    ctx = ToolContext(store=store, enrichment=FakeEnrichment())
    text = (await execute(ctx, Permission.READ, "enrich_ip", {"ip": "203.0.113.9"})).text
    assert "verdict=Malicious" in text


async def test_isolation_preview_never_isolates_and_respects_denylist(store):
    ctx = ToolContext(store=store, ssh=FakeSsh(), isolation_denylist=("dc*",))
    assert (await execute(ctx, Permission.READ, "isolation_preview", {"host": "soc-victim"})).denied
    ok = (await execute(ctx, Permission.RESPONSE, "isolation_preview", {"host": "soc-victim"})).text
    assert "did not isolate anything" in ok
    blocked = (await execute(ctx, Permission.RESPONSE, "isolation_preview", {"host": "dc01"})).text
    assert "deny-list" in blocked


async def test_recent_audit_is_admin_only(store, tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps({"ts": "t1", "actor": "bob", "action": "incident.close", "target": "#1", "outcome": "success"})
        + "\nnot json\n"
    )
    ctx = ToolContext(store=store, audit_log_path=str(path))
    assert (await execute(ctx, Permission.RESPONSE, "recent_audit", {})).denied
    text = (await execute(ctx, Permission.ADMIN, "recent_audit", {})).text
    assert "actor=bob" in text and "incident.close" in text


def test_read_recent_handles_missing_and_limits(tmp_path):
    assert read_recent(tmp_path / "missing.jsonl") == []
    path = tmp_path / "a.jsonl"
    path.write_text("\n".join(json.dumps({"n": i}) for i in range(10)) + "\n")
    assert [e["n"] for e in read_recent(path, 3)] == [7, 8, 9]
