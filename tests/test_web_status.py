import asyncio

from soc_web.status import StatusProbe

from .web_helpers import login, stack  # noqa: F401


class FakeSplunk:
    def __init__(self, fail=False, delay=0.0):
        self.fail, self.delay, self.calls = fail, delay, 0

    async def search(self, spl, earliest="-1h", latest="now"):
        self.calls += 1
        await asyncio.sleep(self.delay)
        if self.fail:
            raise ConnectionError("down")
        return [{}]


def settle(backends, probe):
    for _ in range(400):
        if not probe._running:
            return
        backends.runner.run(asyncio.sleep(0.02))


def test_reports_splunk_up_down_and_not_configured(stack):
    _, backends, _ = stack
    backends.splunk = None
    probe = StatusProbe(backends)
    assert probe.snapshot()["splunk"] == "off"
    for fail, expected in ((False, "up"), (True, "down")):
        backends.splunk = FakeSplunk(fail=fail, delay=0.3)
        probe = StatusProbe(backends)
        assert probe.snapshot()["splunk"] == "checking"  # never waits for the probe
        settle(backends, probe)
        assert probe.snapshot()["splunk"] == expected


def test_probe_runs_at_most_once_per_ttl_and_shows_the_last_alert(stack):
    _, backends, _ = stack
    now = [0.0]
    backends.splunk = FakeSplunk()
    probe = StatusProbe(backends, ttl=30, clock=lambda: now[0])
    probe.snapshot()
    settle(backends, probe)
    probe.snapshot()
    assert backends.splunk.calls == 1
    now[0] = 31
    probe.snapshot()
    settle(backends, probe)
    assert backends.splunk.calls == 2
    assert probe.snapshot()["last_alert"] is not None  # the mock backend seeds incidents


def test_slow_splunk_does_not_slow_the_page(stack):
    import time

    app, backends, _ = stack
    backends.splunk = FakeSplunk(delay=1.0)
    client, _ = login(app, "triage")
    started = time.monotonic()
    html = client.get("/").get_data(as_text=True)
    assert time.monotonic() - started < 0.9
    assert 'role="status"' in html
    backends.runner.run(asyncio.sleep(1.2))  # let the probe finish before the loop is closed


def test_strip_shows_mode_ai_and_is_for_signed_in_users_only(stack):
    app, backends, _ = stack
    assert 'role="status"' not in app.test_client().get("/login").get_data(as_text=True)
    html = login(app, "viewer")[0].get("/").get_data(as_text=True)
    assert "<b>Mode</b> mock" in html and "<b>AI</b> mock" in html
    backends.runner.run(asyncio.sleep(0.7))  # let the mock Splunk probe finish
    assert "203.0." not in html.split('role="status"')[1].split("</div>")[0]


def test_strip_shows_real_values_on_every_page(stack):
    """A page that passes its own `status` (the incident filter) must not blank the strip."""
    import re

    app, _, _ = stack
    client, _ = login(app, "admin")
    for path in ("/", "/incidents", "/incidents?status=closed", "/incidents/1", "/hunt", "/enrich", "/ask", "/audit"):
        html = client.get(path).get_data(as_text=True)
        strip = re.search(r'role="status".*?</div></div>', html, re.S).group(0)
        assert "<b>Mode</b> mock" in strip and "<b>AI</b> mock" in strip, path
