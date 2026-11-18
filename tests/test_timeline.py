"""The timeline: time frames and slot sizes, folding rules into attack types, the chart geometry, the bot's
/api/timeline route and the store query behind it."""

from datetime import datetime, timedelta, timezone

import pytest
from aiohttp.test_utils import TestClient, TestServer

from soc_bot.store import IncidentStore
from soc_bot.webhook import create_app
from soc_web import timeline as tl

NOW = datetime(2026, 11, 18, 15, 37, 45, tzinfo=timezone.utc)
API_SECRET = "a" * 40
HEADERS = {"X-Api-Secret": API_SECRET}
DISCOVERY = "Discovery burst: several reconnaissance commands in ten minutes"
MASQUERADE = "Masquerading process: ./splunkd from home directory"


# ---- the time frame ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("span, slot", [(3600, 60), (6 * 3600, 300), (86400, 900), (7 * 86400, 10800), (30 * 86400, 43200)])
def test_slot_size_keeps_about_a_hundred_slots_or_fewer(span, slot):
    assert tl.pick_bucket(span) == slot
    assert span / slot <= tl.TARGET_SLOTS


def test_presets_end_now_and_are_aligned_to_whole_slots():
    for key, (_, seconds) in tl.PRESETS.items():
        r = tl.parse_range({"range": key}, NOW)
        assert r.preset == key and r.error == ""
        assert r.start.timestamp() % r.bucket == 0 and r.end.timestamp() % r.bucket == 0
        assert r.end >= NOW.replace(second=0) and (r.end - r.start).total_seconds() >= seconds
        assert r.slots == (r.end - r.start).total_seconds() / r.bucket


def test_a_custom_range_is_read_as_utc_and_bad_ones_fall_back_with_a_reason():
    r = tl.parse_range({"from": "2026-11-18T10:00", "to": "2026-11-18T12:30"}, NOW)
    assert (r.preset, r.bucket, r.slots, r.error) == ("", 300, 30, "")
    assert r.start == datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
    for args, why in (({"from": "yesterday", "to": "now"}, "Enter both dates"),
                      ({"from": "2026-11-18T10:00", "to": "2026-11-18T10:05"}, "ten minutes"),
                      ({"from": "2026-11-18T12:00", "to": "2026-11-18T10:00"}, "ten minutes"),
                      ({"from": "2026-01-01T00:00", "to": "2026-11-18T00:00"}, "31 days"),
                      ({"from": "2026-11-18T10:00"}, "Enter both dates")):
        bad = tl.parse_range(args, NOW)
        assert why in bad.error and bad.preset == tl.DEFAULT_PRESET, args
    assert tl.parse_range({}, NOW).preset == tl.DEFAULT_PRESET and tl.parse_range({"range": "x"}, NOW).error == ""


# ---- attack types and activity -------------------------------------------------------------------------------

def test_rules_fold_into_a_few_known_attack_types_and_unknown_ones_are_other():
    assert tl.attack_kind(DISCOVERY).key == "discovery"
    assert tl.attack_kind(MASQUERADE).key == "masquerade"
    assert tl.attack_kind("Heartbeat: no pipeline heartbeat from a host for 15 minutes").key == "health"
    assert tl.attack_kind("<script>alert(1)</script>").key == "other" and tl.attack_kind("").key == "other"
    r = tl.parse_range({"range": "1h"}, NOW)
    out = tl.group_alerts({DISCOVERY: [1] * r.slots, "Cron anomaly": [2] * r.slots, "Other too": [1] * r.slots}, r.slots)
    assert out["discovery"] == [1] * r.slots and out["other"] == [3] * r.slots and out["masquerade"] == [0] * r.slots


def test_every_tested_attack_type_lists_its_attck_techniques():
    assert "T1036.005" in tl.techniques_for(tl.ATTACKS[1])
    assert {"T1033", "T1057", "T1082", "T1087.001", "T1016"} <= set(tl.techniques_for(tl.ATTACKS[0]))
    assert tl.techniques_for(tl.ATTACKS[3]) == []


def test_activity_rows_land_in_the_right_slot_and_junk_is_ignored():
    r = tl.parse_range({"from": "2026-11-18T10:00", "to": "2026-11-18T11:00"}, NOW)
    first = int(r.start.timestamp())
    rows = [{"b": str(first), "kind": "Commands run", "count": "7"},
            {"b": str(first + r.bucket), "kind": "Failed logins", "count": "2"},
            {"b": str(first + r.bucket), "kind": "Failed logins", "count": "3"},
            {"b": str(first - r.bucket), "kind": "Commands run", "count": "9"},        # before the range
            {"b": str(first + r.bucket * r.slots), "kind": "Commands run", "count": "9"},       # after the range
            {"b": str(first), "kind": "Something else", "count": "4"},            # not a known kind
            {"b": "soon", "kind": "Commands run", "count": "1"}, {"b": str(first), "kind": "Commands run", "count": "-5"}]
    out = tl.parse_activity(rows, r)
    assert out["commands"][0] == 7 and out["failed"][1] == 5
    assert sum(sum(v) for v in out.values()) == 12


def test_activity_search_buckets_by_epoch_like_the_chart_and_skips_heartbeats():
    spl = tl.activity_spl(300)
    assert spl.startswith("search index=linux ")          # Splunk's REST search needs the word search
    assert "floor(_time/300)*300" in spl and spl.endswith("stats count by b kind")
    assert 'NOT "soc-heartbeat"' in spl and "type=EXECVE" in spl
    with pytest.raises(ValueError):
        tl.activity_spl("300; delete")


# ---- the drawing ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("peak, top", [(0, 4), (1, 1), (4, 4), (7, 8), (23, 25), (480, 500)])
def test_count_axis_uses_whole_numbers_and_reaches_the_peak(peak, top):
    got, ticks = tl.nice_ticks(peak)
    assert got == top and ticks[0] == 0 and ticks[-1] == top and all(isinstance(t, int) for t in ticks)
    assert len(ticks) <= 6


def chart(alerts, hours=6):
    r = tl.parse_range({"range": f"{hours}h"}, NOW)
    grouped = tl.group_alerts(alerts(r.slots), r.slots)
    return r, tl.stack_chart(tl.ATTACKS, grouped, r, 250)


def test_bars_are_thin_stacked_with_a_gap_and_inside_the_plot():
    r, c = chart(lambda n: {DISCOVERY: [0] * (n - 1) + [3], MASQUERADE: [0] * (n - 1) + [1]})
    assert len(c["columns"]) == r.slots and c["peak"] == 4 and not c["empty"]
    last = c["columns"][-1]
    assert [s["cls"] for s in last["segments"]] == ["a1", "a2"]       # stacked in the fixed order
    for column in c["columns"][:-1]:
        assert column["segments"] == []                                # nothing drawn for empty slots
    for ys in (c["top"], c["base"]):
        assert 0 <= ys <= c["height"]
    assert c["yticks"][0]["label"] == "0" and c["yticks"][0]["y"] == c["base"]


def test_an_empty_period_is_flagged_so_the_page_can_say_so():
    _, c = chart(lambda n: {})
    assert c["empty"] and c["peak"] == 0 and [t["label"] for t in c["yticks"]] == ["0", "1", "2", "3", "4"]


def test_time_ticks_sit_on_round_clock_times():
    _, c = chart(lambda n: {}, hours=6)
    assert [t["label"] for t in c["xticks"]] == ["10:00", "11:00", "12:00", "13:00", "14:00", "15:00"]
    assert c["xticks"][0]["sub"] == "Nov 18" and all(t["sub"] == "" for t in c["xticks"][1:])
    r = tl.parse_range({"range": "7d"}, NOW)
    daily = tl.stack_chart(tl.ATTACKS, tl.group_alerts({}, r.slots), r, 250)
    assert all(t["label"] == "00:00" for t in daily["xticks"])         # midnights, each with its date underneath


def test_build_gives_totals_the_busiest_slot_a_table_and_survives_one_side_missing():
    r = tl.parse_range({"range": "6h"}, NOW)
    alerts = tl.group_alerts({DISCOVERY: [0] * (r.slots - 3) + [1, 0, 2], MASQUERADE: [0] * (r.slots - 1) + [1]}, r.slots)
    activity = {k.key: [0] * r.slots for k in tl.ACTIVITY}
    activity["commands"][5] = 40
    v = tl.build(r, alerts, activity)
    assert v["tiles"]["alerts"] == 4 and v["tiles"]["alert_peak"] == 3 and v["tiles"]["top_type"] == "Discovery burst"
    assert v["tiles"]["activity"] == 40 and v["tiles"]["activity_peak"] == 40
    assert len(v["tips"]) == r.slots and v["table"][0]["when"].endswith("UTC") and len(v["headers"]) == 8
    assert all(any(row["cells"]) for row in v["table"])                 # only slots with something in them
    only_alerts = tl.build(r, alerts, None)
    assert only_alerts["activity"] is None and "activity" not in only_alerts["tiles"] and len(only_alerts["headers"]) == 4
    assert tl.build(r, None, None)["tiles"] == {}


# ---- the store and the bot's API -----------------------------------------------------------------------------

@pytest.fixture
async def store():
    s = IncidentStore(":memory:")
    ids = {}
    for name in ("a", "b", "c", "d", "e"):
        ids[name] = (await s.create(rule=DISCOVERY if name != "c" else MASQUERADE, severity="Medium")).id
    start = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
    when = {"a": start + timedelta(minutes=1), "b": start + timedelta(minutes=4, seconds=59),
            "c": start + timedelta(minutes=5), "d": start - timedelta(seconds=1), "e": start + timedelta(hours=1)}
    for name, at in when.items():
        s._db.execute("UPDATE incidents SET created = ? WHERE id = ?", (at.isoformat(), ids[name]))
    yield s, start
    s.shutdown()


async def test_the_store_counts_incidents_per_slot_and_rule(store):
    s, start = store
    series = await s.timeline(start, start + timedelta(hours=1), 300)    # [start, start+1h): d is just before, e is on the end
    assert series == {DISCOVERY: [2] + [0] * 11, MASQUERADE: [0, 1] + [0] * 10}


async def test_the_store_refuses_a_range_it_cannot_chart(store):
    s, start = store
    for args in ((start, start, 300), (start, start - timedelta(hours=1), 300), (start, start + timedelta(hours=1), 0),
                 (start, start + timedelta(days=30), 60)):
        with pytest.raises(ValueError):
            await s.timeline(*args)


@pytest.fixture
async def api(store):
    async def noop(incident):
        pass

    s, start = store
    app = create_app(s, "w" * 40, noop, api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        client.start = int(start.timestamp())
        yield client


async def test_timeline_route_needs_the_secret_and_answers_with_counts_only(api):
    url = f"/api/timeline?start={api.start}&end={api.start + 3600}&bucket=300"
    assert (await api.get(url)).status == 401
    resp = await api.get(url, headers=HEADERS)
    assert resp.status == 200
    body = await resp.json()
    assert body["bucket"] == 300 and body["series"][DISCOVERY][0] == 2 and body["series"][MASQUERADE][1] == 1
    assert set(body) == {"start", "end", "bucket", "series"}
    assert (await api.post(url, headers=HEADERS)).status == 405


@pytest.mark.parametrize("query", ["", "start=1&end=2", "start=a&end=b&bucket=60", "start=100&end=50&bucket=60",
                                   "start=0&end=100000&bucket=30", "start=0&end=10000000&bucket=60",
                                   "start=0&end=999999999999&bucket=86400", "start=99999999999999&end=999999999999999&bucket=60"])
async def test_timeline_route_rejects_bad_ranges_without_an_error_page(api, query):
    resp = await api.get(f"/api/timeline?{query}", headers=HEADERS)
    assert resp.status == 400 and set(await resp.json()) == {"error"}
