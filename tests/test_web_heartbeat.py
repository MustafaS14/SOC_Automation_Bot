"""The heartbeat monitor: the state it reports, the endpoint behind it, and the widget on the page."""

import asyncio
import re
import time
from pathlib import Path

from soc_web.heartbeat import LATE, SILENT, SLOT, SLOTS, HeartbeatProbe, build_hosts

from .web_helpers import login, stack  # noqa: F401

STATIC = Path(__file__).resolve().parents[1] / "soc_web" / "static"
NOW = 1_700_000_000.0  # any fixed moment


def row(host="soc-victim", age=60, slots=None):
    current = int(NOW // SLOT) * SLOT
    have = [current - i * SLOT for i in range(1, 6)] if slots is None else slots
    return {"host": host, "last": str(int(NOW - age)), "slots": ",".join(str(s) for s in have)}


def test_age_decides_the_state_with_the_same_limits_as_the_alert():
    assert LATE == 600 and SILENT == 900  # the Splunk alert fires at 15 minutes
    states = [build_hosts([row(age=a)], NOW)[0]["state"] for a in (0, LATE - 1, LATE, SILENT - 1, SILENT, 5000)]
    assert states == ["ok", "ok", "late", "late", "silent", "silent"]


def test_ticks_cover_six_hours_and_do_not_count_the_running_slot_as_a_miss():
    current = int(NOW // SLOT) * SLOT
    ticks = build_hosts([row(slots=[current - SLOT, current - 3 * SLOT])], NOW)[0]["ticks"]
    assert len(ticks) == SLOTS
    assert ticks[-1] == 2          # the slot that is still running
    assert ticks[-2] == 1 and ticks[-4] == 1
    assert ticks[-3] == 0          # a slot that closed with no heartbeat
    assert ticks[0] == 0


def test_bad_rows_and_odd_host_names_are_dropped_and_the_worst_host_comes_first():
    rows = [row("good-host", age=30), row("<script>alert(1)</script>"), {"host": "no-last"}, row("x" * 100),
            row("late-host", age=700), row("dead.host", age=4000), {"host": "bad", "last": "soon"}]
    hosts = build_hosts(rows, NOW)
    assert [h["host"] for h in hosts] == ["dead.host", "late-host", "good-host"]


class FakeSplunk:
    def __init__(self, rows=None, fail=False):
        self.rows, self.fail, self.calls = rows if rows is not None else [], fail, 0

    async def search(self, spl, earliest="-1h", latest="now"):
        self.calls += 1
        assert "soc-heartbeat: alive" in spl and earliest == "-6h"
        if self.fail:
            raise ConnectionError("down")
        return self.rows


def settle(backends, probe):
    for _ in range(400):
        if not probe._running:
            return
        backends.runner.run(asyncio.sleep(0.02))


def probe_state(backends, splunk, **kw):
    backends.splunk = splunk
    probe = HeartbeatProbe(backends, wall=lambda: NOW, **kw)
    first = probe.snapshot()["state"]
    settle(backends, probe)
    return first, probe


def test_state_is_unknown_until_splunk_answers_then_ok_none_or_unknown_again(stack):  # noqa: F811
    _, backends, _ = stack
    first, probe = probe_state(backends, FakeSplunk([row(age=30)]))
    assert first == "unknown" and probe.snapshot()["state"] == "ok"
    _, probe = probe_state(backends, FakeSplunk([]))
    assert probe.snapshot()["state"] == "none"
    # A Splunk that does not answer is "unknown", never "silent": nobody should be told the victim died because of that.
    _, probe = probe_state(backends, FakeSplunk(fail=True))
    snap = probe.snapshot()
    assert snap["state"] == "unknown" and snap["hosts"] == []
    backends.splunk = None
    assert HeartbeatProbe(backends).snapshot()["state"] == "off"


def test_a_failed_refresh_after_a_good_one_hides_the_old_hosts(stack):  # noqa: F811
    _, backends, _ = stack
    now = [0.0]
    splunk = FakeSplunk([row(age=30)])
    backends.splunk = splunk
    probe = HeartbeatProbe(backends, ttl=30, clock=lambda: now[0], wall=lambda: NOW)
    probe.snapshot()
    settle(backends, probe)
    assert probe.snapshot()["state"] == "ok" and splunk.calls == 1  # one search per ttl, however often it is read
    splunk.fail, now[0] = True, 31
    probe.snapshot()
    settle(backends, probe)
    assert probe.snapshot()["state"] == "unknown"


def poll(client, tries=60):
    for _ in range(tries):
        data = client.get("/heartbeat.json").get_json()
        if data["state"] != "unknown":
            return data
        time.sleep(0.1)
    return data


def test_endpoint_serves_the_demo_heartbeat_to_read_tier_and_up(stack):  # noqa: F811
    app, _, _ = stack
    client, _ = login(app, "read")
    data = poll(client)
    assert data["state"] == "ok"
    assert [h["host"] for h in data["hosts"]] == ["soc-victim"]
    assert len(data["hosts"][0]["ticks"]) == SLOTS and 0 in data["hosts"][0]["ticks"]  # the demo has a gap
    resp = client.get("/heartbeat.json")
    assert resp.headers["Cache-Control"] == "no-store" and resp.mimetype == "application/json"


def test_endpoint_is_refused_below_read_tier_and_without_a_login(stack):  # noqa: F811
    app, _, _ = stack
    viewer, _ = login(app, "viewer")
    assert viewer.get("/heartbeat.json").status_code == 403
    assert app.test_client().get("/heartbeat.json").status_code in (302, 401, 403)


def test_widget_is_on_every_page_for_read_tier_and_up_but_not_for_viewers_or_the_login_page(stack):  # noqa: F811
    app, _, _ = stack
    client, _ = login(app, "read")
    for path in ("/", "/incidents", "/hunt", "/coverage", "/enrich"):
        html = client.get(path).get_data(as_text=True)
        assert 'id="hb"' in html and "heartbeat.js" in html, path
    assert 'id="hb-size"' in html  # the bigger/smaller switch
    viewer, _ = login(app, "viewer")
    assert 'id="hb"' not in viewer.get("/").get_data(as_text=True)
    assert 'id="hb"' not in app.test_client().get("/login").get_data(as_text=True)
    assert client.get("/static/heartbeat.js").status_code == 200


def test_script_puts_text_in_as_text_and_the_page_needs_no_inline_script_or_style():
    js = (STATIC / "heartbeat.js").read_text(encoding="utf8")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "document.write", "setAttribute(\"style\""):
        assert banned not in js, banned
    assert "/heartbeat.json" in js and not re.search(r"https?://", js)
