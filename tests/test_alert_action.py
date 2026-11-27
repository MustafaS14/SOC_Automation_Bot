"""The Splunk alert action: it retries a temporary failure, queues what it cannot deliver, and never retries a rejection."""

import importlib.util
import io
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "infra" / "siem" / "splunk" / "soc_bot_alert" / "bin" / "soc_bot_webhook.py"
SECRET = "s" * 40
ALERT = {"search_name": "Discovery commands", "result": {"host": "soc-victim"}, "results_link": "http://splunk/x"}


@pytest.fixture
def action(tmp_path):
    spec = importlib.util.spec_from_file_location("soc_bot_webhook_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "local").mkdir()
    module.APP = str(tmp_path)
    module.sleeps = []
    return module


class FakeBot:
    """A local HTTP server that answers with a scripted list of statuses, then 201 forever."""

    def __init__(self, statuses=()):
        self.statuses = list(statuses)
        self.received = []
        bot = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                bot.received.append((self.headers.get("X-Webhook-Secret"), json.loads(self.rfile.read(length))))
                status = bot.statuses.pop(0) if bot.statuses else 201
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/webhook/splunk"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def make_bot():
    bots = []

    def make(statuses=()):
        bots.append(FakeBot(statuses))
        return bots[-1]

    yield make
    for b in bots:
        b.stop()


def run(action, url, tmp_path, alert=ALERT):
    (tmp_path / "local" / "url").write_text(url)
    (tmp_path / "local" / "secret").write_text(SECRET)
    return action.main(["x", "--execute"], io.StringIO(json.dumps(alert)), sleep=action.sleeps.append)


def test_a_healthy_bot_gets_the_alert_once_with_the_secret_header(action, make_bot, tmp_path):
    bot = make_bot()
    assert run(action, bot.url, tmp_path) == 0
    assert bot.received == [(SECRET, ALERT)]
    assert action.sleeps == []
    assert not (tmp_path / "local" / "spool").exists()


def test_a_restarting_bot_is_retried_until_it_answers(action, make_bot, tmp_path):
    bot = make_bot([503, 502])
    assert run(action, bot.url, tmp_path) == 0
    assert len(bot.received) == 3
    assert action.sleeps == [2, 5]
    assert not (tmp_path / "local" / "spool").exists()


def test_a_rate_limited_bot_is_retried(action, make_bot, tmp_path):
    bot = make_bot([429])
    assert run(action, bot.url, tmp_path) == 0
    assert len(bot.received) == 2


@pytest.mark.parametrize("status", [400, 401, 403])
def test_a_rejection_is_never_retried_or_queued(action, make_bot, tmp_path, status):
    bot = make_bot([status, status, status, status])
    assert run(action, bot.url, tmp_path) == 1
    assert len(bot.received) == 1  # the same request would fail again
    assert not (tmp_path / "local" / "spool").exists()


def test_an_unreachable_bot_is_retried_then_the_alert_is_queued(action, tmp_path):
    assert run(action, "http://127.0.0.1:9/webhook/splunk", tmp_path) == 1  # nothing listens on port 9
    assert action.sleeps == [2, 5, 15]
    queued = list((tmp_path / "local" / "spool").glob("*.json"))
    assert len(queued) == 1
    assert json.loads(queued[0].read_text()) == ALERT
    assert SECRET not in queued[0].read_text()  # the secret is never written to the spool
    if os.name == "posix":
        assert oct(queued[0].stat().st_mode & 0o777) == "0o600"


def test_a_queued_alert_is_sent_before_the_next_one(action, make_bot, tmp_path):
    run(action, "http://127.0.0.1:9/webhook/splunk", tmp_path)  # bot down: queued
    bot = make_bot()
    newer = {**ALERT, "search_name": "Cron anomaly"}
    assert run(action, bot.url, tmp_path, newer) == 0
    assert [b["search_name"] for _, b in bot.received] == ["Discovery commands", "Cron anomaly"]
    assert list((tmp_path / "local" / "spool").glob("*.json")) == []


def test_flushing_stops_while_the_bot_is_still_down(action, make_bot, tmp_path):
    spool = tmp_path / "local" / "spool"
    for i in range(3):
        action.spool_add(str(spool), {**ALERT, "search_name": f"a{i}"}, now=time.time() + i)
    bot = make_bot([503])
    assert action.spool_flush(str(spool), bot.url, SECRET, sleep=action.sleeps.append) == 0
    assert len(bot.received) == 1  # it did not hammer a bot that just said 503
    assert len(list(spool.glob("*.json"))) == 3


def test_a_rejected_queued_alert_is_dropped_not_kept_forever(action, make_bot, tmp_path):
    spool = tmp_path / "local" / "spool"
    action.spool_add(str(spool), ALERT)
    bot = make_bot([400])
    action.spool_flush(str(spool), bot.url, SECRET)
    assert list(spool.glob("*.json")) == []


def test_old_and_broken_queue_entries_are_dropped(action, make_bot, tmp_path):
    spool = tmp_path / "local" / "spool"
    old = action.spool_add(str(spool), ALERT)
    ancient = time.time() - action.SPOOL_MAX_AGE - 60
    os.utime(old, (ancient, ancient))
    (spool / "000000000000001-1.json").write_text("not json")
    bot = make_bot()
    assert action.spool_flush(str(spool), bot.url, SECRET) == 0
    assert bot.received == []
    assert list(spool.glob("*.json")) == []


def test_the_queue_has_a_size_cap_and_drops_the_oldest(action, tmp_path):
    spool = tmp_path / "local" / "spool"
    for i in range(action.SPOOL_MAX_FILES + 5):
        action.spool_add(str(spool), {"n": i}, now=1000 + i)
    files = sorted(spool.glob("*.json"))
    assert len(files) == action.SPOOL_MAX_FILES
    assert json.loads(files[0].read_text())["n"] == 5  # the five oldest are gone


def test_only_execute_mode_is_supported(action):
    assert action.main(["x"], io.StringIO("{}")) == 2
    assert action.main(["x", "--other"], io.StringIO("{}")) == 2


def test_the_scheduled_flush_sends_the_queue_without_a_new_alert(action, make_bot, tmp_path):
    run(action, "http://127.0.0.1:9/webhook/splunk", tmp_path)  # bot down: queued
    bot = make_bot()
    (tmp_path / "local" / "url").write_text(bot.url)
    assert action.main(["x", "--flush"], io.StringIO(""), sleep=action.sleeps.append) == 0
    assert [b["search_name"] for _, b in bot.received] == ["Discovery commands"]
    assert list((tmp_path / "local" / "spool").glob("*.json")) == []


def test_the_scheduled_flush_keeps_the_queue_while_the_bot_is_down(action, tmp_path):
    run(action, "http://127.0.0.1:9/webhook/splunk", tmp_path)
    assert action.main(["x", "--flush"], io.StringIO(""), sleep=action.sleeps.append) == 0
    assert len(list((tmp_path / "local" / "spool").glob("*.json"))) == 1


def test_the_scheduled_flush_with_an_empty_queue_needs_no_settings(action, tmp_path):
    assert action.main(["x", "--flush"], io.StringIO("")) == 0  # no local/url exists: it must not even look for one


def test_the_scheduled_input_runs_the_resend_script_every_two_minutes():
    conf = (SCRIPT.parent.parent / "default" / "inputs.conf").read_text()
    assert "[script://$SPLUNK_HOME/etc/apps/soc_bot_alert/bin/soc_bot_resend.py]" in conf and "interval = 120" in conf and "disabled = 0" in conf
    assert (SCRIPT.parent / "soc_bot_resend.py").is_file()


def test_classification():
    spec = importlib.util.spec_from_file_location("soc_bot_webhook_classify", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert [m.classify(s) for s in (200, 201, 429, 500, 503, None, 400, 401, 404)] == [
        "sent", "sent", "temporary", "temporary", "temporary", "temporary", "rejected", "rejected", "rejected"]
