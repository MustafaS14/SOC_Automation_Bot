"""The Timeline page: what it shows, how it handles a bad time frame and a failing data source, and that nothing
from the data can inject markup."""

import re
from pathlib import Path

from soc_bot.clients.base import APIError

from .web_helpers import login, stack  # noqa: F401

STATIC = Path(__file__).resolve().parents[1] / "soc_web" / "static"


def page(client, query=""):
    resp = client.get("/timeline" + query)
    assert resp.status_code == 200, resp.status_code
    return resp.get_data(as_text=True)


def test_page_shows_both_charts_the_legends_the_tiles_and_a_table_twin(stack):  # noqa: F811
    app, _, _ = stack
    client, _ = login(app, "read")
    html = page(client)
    for needle in ('id="tl-a-t"', 'id="tl-b-t"', "Detected attacks", "Log activity", "Alerts in this period",
                   "Peak activity", "Show as a table", "Commands run", "Failed logins", "Discovery burst", "Masquerading"):
        assert needle in html, needle
    assert "class=\"tl-svg\"" in html and html.count('class="tl-hit"') > 100      # a hover target per slot, per chart
    assert "data-tips=" in html


def test_presets_are_links_and_the_active_one_is_marked(stack):  # noqa: F811
    app, _, _ = stack
    client, _ = login(app, "read")
    html = page(client, "?range=6h")
    assert 'href="/timeline?range=7d"' in html
    active = re.findall(r'class="tl-chip on"[^>]*aria-current="true">([^<]+)<', html)
    assert active == ["Last 6 hours"]
    assert "Alerts per 5 minutes" in html


def test_a_custom_range_is_used_and_a_bad_one_explains_itself(stack):  # noqa: F811
    app, _, _ = stack
    client, _ = login(app, "read")
    good = page(client, "?from=2026-11-18T10:00&to=2026-11-18T12:30")
    assert 'value="2026-11-18T10:00"' in good and 'value="2026-11-18T12:30"' in good and "Nov 18" in good
    bad = page(client, "?from=2026-11-18T12:00&to=2026-11-18T10:00")
    assert "at least ten minutes" in bad and "Showing the last 24 hours instead" in bad
    attack = page(client, '?from="><script>alert(1)</script>&to=x')
    assert "<script>alert(1)" not in attack and "Enter both dates" in attack


def test_data_cannot_inject_markup_and_no_script_runs_inline(stack):  # noqa: F811
    app, backends, _ = stack
    backends.runner.run(backends.store.create(rule="<script>alert(1)</script>", severity="High"))
    client, _ = login(app, "read")
    html = page(client)
    assert "<script>alert(1)" not in html and "Other alerts" in html
    assert " style=" not in html and " onclick=" not in html
    assert html.count("<script") == 3 and '<script src="/static/timeline.js" defer></script>' in html


def test_one_side_failing_leaves_the_other_chart_and_says_why(stack, monkeypatch):  # noqa: F811
    app, backends, _ = stack
    client, _ = login(app, "read")
    real_splunk = backends.splunk
    backends.splunk = None
    html = page(client)
    assert "Log activity is unavailable" in html and "Splunk is not configured" in html and 'id="tl-a-t"' in html
    assert "Peak activity" not in html and "Alerts in this period" in html

    async def down(*args):
        raise APIError("soc-siem", 503, "soc-siem is unreachable.")

    monkeypatch.setattr(backends.store, "timeline", down)
    backends.splunk = real_splunk
    html = page(client)
    assert "Alerts are unavailable" in html and "soc-siem is unreachable" in html and 'id="tl-b-t"' in html
    assert "Alerts in this period" not in html and "Peak activity" in html


def test_page_is_for_the_read_tier_and_up_and_the_menu_links_to_it(stack):  # noqa: F811
    app, _, _ = stack
    viewer, _ = login(app, "viewer")
    assert viewer.get("/timeline").status_code == 403
    assert app.test_client().get("/timeline").status_code in (302, 401, 403)
    client, _ = login(app, "read")
    assert 'href="/timeline"' in client.get("/").get_data(as_text=True)
    assert client.get("/static/timeline.js").status_code == 200


def test_script_puts_text_in_as_text_and_fetches_nothing():
    js = (STATIC / "timeline.js").read_text(encoding="utf8")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "document.write", 'setAttribute("style"',
                   "fetch(", "XMLHttpRequest"):
        assert banned not in js, banned
    assert not re.search(r"https?://", js)
