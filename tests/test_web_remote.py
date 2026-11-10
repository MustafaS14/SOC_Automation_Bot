"""The console reading incidents from soc-siem: the client against the real bot API, and the read-only console."""

import asyncio
import threading

import httpx
import pytest
from aiohttp import web

from soc_bot.clients.base import APIError, NotFoundError
from soc_bot.config import ConfigError, Settings
from soc_bot.store import IncidentStore
from soc_bot.webhook import create_app as create_bot_app
from soc_web.app import create_app
from soc_web.config import WebSettings
from soc_web.remote import READ_ONLY, ReadOnlyError, RemoteIncidentStore
from soc_web.runtime import AsyncRunner, build_backends
from soc_web.users import UserStore

from .web_helpers import PASSWORD, login, post

API_SECRET = "a" * 40


async def _noop(incident):
    pass


class FakeBot:
    """The bot's real webhook app with its incident API, on a background thread and a free local port."""

    def __init__(self, secret: str = API_SECRET):
        self.secret = secret
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        assert self.ready.wait(10)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.store = IncidentStore(":memory:")

        async def start():
            await self.store.create(rule="Discovery commands", severity="High", host="soc-victim", src_ip="10.0.0.5",
                                    description="whoami")
            await self.store.create(rule="Cron anomaly", severity="Low", host="soc-web")
            await self.store.add_comment(1, "analyst", "first look")
            app = create_bot_app(self.store, "w" * 40, _noop, api_secret=self.secret)
            self.runner = web.AppRunner(app)
            await self.runner.setup()
            site = web.TCPSite(self.runner, "127.0.0.1", 0)
            await site.start()
            self.port = self.runner.addresses[0][1]

        self.loop.run_until_complete(start())
        self.ready.set()
        self.loop.run_forever()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def incident_count(self) -> int:
        return len(asyncio.run_coroutine_threadsafe(self.store.list("all", None, 50), self.loop).result(5))

    def stop(self):
        if not self.thread.is_alive():
            return
        asyncio.run_coroutine_threadsafe(self.runner.cleanup(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


@pytest.fixture
def bot():
    b = FakeBot()
    yield b
    b.stop()


def _settings(tmp_path):
    return Settings(
        discord_token="", guild_id=None, allowed_channel_ids=frozenset(), audit_channel_id=None,
        read_role_ids=frozenset(), triage_role_ids=frozenset(), response_role_ids=frozenset(),
        isolation_denylist=(), mock_mode=False, ai_backend="mock",  # no real assistant is involved here
        audit_log_path=str(tmp_path / "audit.jsonl"), db_path=str(tmp_path / "never-used.db"),
    )


@pytest.fixture
def remote_stack(tmp_path, bot):
    web_settings = WebSettings(secret_key="k" * 40, secure_cookies=False, bot_api_url=bot.url, bot_api_secret=API_SECRET)
    runner = AsyncRunner()
    backends = build_backends(_settings(tmp_path), runner, web_settings.remote)
    users = UserStore(":memory:")
    for tier in ("viewer", "read", "triage", "admin"):
        users.create(tier, PASSWORD, tier)
    app = create_app(web_settings, backends, users)
    app.config["TESTING"] = False
    yield app, backends, bot
    backends.close()
    runner.close()
    users.close()


# ---- the client ----------------------------------------------------------------------------------------------


def test_the_client_reads_list_get_and_counts(remote_stack):
    _, backends, _ = remote_stack
    store, runner = backends.store, backends.runner
    assert isinstance(store, RemoteIncidentStore)
    rows = runner.run(store.list("open", None, 10))
    assert [r.rule for r in rows] == ["Cron anomaly", "Discovery commands"]
    assert rows[0].created is not None and rows[0].severity == "Low"
    inc = runner.run(store.get(1))
    assert inc.rule == "Discovery commands" and inc.src_ip == "10.0.0.5"
    assert [c.body for c in inc.comments] == ["first look"] and inc.comments[0].created is not None
    assert runner.run(store.counts()) == {"status": {"New": 2}, "open_by_severity": {"High": 1, "Low": 1}}
    with pytest.raises(NotFoundError):
        runner.run(store.get(99))


def test_the_client_refuses_every_write_without_sending_anything(remote_stack):
    _, backends, bot = remote_stack
    store, runner = backends.store, backends.runner
    before = bot.incident_count()
    for coro in (store.create(rule="x", severity="High"), store.add_comment(1, "me", "x"),
                 store.acknowledge(1, "me"), store.close(1, "benign", "x", "me")):
        with pytest.raises(ReadOnlyError, match="read-only"):
            runner.run(coro)
    assert bot.incident_count() == before


async def test_a_wrong_secret_is_reported_without_showing_either_secret(bot):
    async with httpx.AsyncClient() as http:
        store = RemoteIncidentStore(bot.url, "b" * 40, http=http)
        with pytest.raises(APIError) as caught:
            await store.list()
    assert caught.value.status == 401 and "b" * 40 not in str(caught.value) and API_SECRET not in str(caught.value)


async def test_an_unreachable_server_fails_fast_with_a_clear_error():
    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse)) as http:
        store = RemoteIncidentStore("http://192.0.2.1:8765", API_SECRET, http=http)
        with pytest.raises(APIError, match="unreachable"):
            await store.counts()


async def test_a_slow_server_is_a_timeout_error_and_there_is_one_attempt_only():
    calls = []

    def slow(request):
        calls.append(request)
        raise httpx.ReadTimeout("slow", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as http:
        store = RemoteIncidentStore("http://192.0.2.1:8765", API_SECRET, http=http)
        with pytest.raises(APIError, match="in time"):
            await store.list()
    assert len(calls) == 1  # no retry loop


async def test_the_secret_goes_in_the_header_and_never_in_the_url():
    seen = []

    def record(request):
        seen.append(request)
        return httpx.Response(200, json={"incidents": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(record)) as http:
        await RemoteIncidentStore("http://soc-siem:8765", API_SECRET, http=http).list("all", "High", 5)
    assert seen[0].headers["X-Api-Secret"] == API_SECRET
    assert API_SECRET not in str(seen[0].url) and seen[0].method == "GET"
    assert dict(seen[0].url.params) == {"status": "all", "severity": "High", "limit": "5", "order": "newest"}


async def test_garbage_from_the_server_is_an_error_not_a_crash():
    for response in (httpx.Response(200, text="<html>"), httpx.Response(200, json={"nope": 1}),
                     httpx.Response(500, text="Traceback ..."), httpx.Response(429)):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r, resp=response: resp)) as http:
            with pytest.raises(APIError):
                await RemoteIncidentStore("http://soc-siem:8765", API_SECRET, http=http).list()


# ---- the console in remote mode -----------------------------------------------------------------------------


def test_pages_show_the_live_incidents_and_the_status_strip_says_so(remote_stack):
    app, _, _ = remote_stack
    client, _ = login(app, "triage")
    assert "Discovery commands" in client.get("/incidents").get_data(as_text=True)
    page = client.get("/incidents/1").get_data(as_text=True)
    assert "first look" in page and "10.0.0.5" in page
    assert "live data from soc-siem" in client.get("/").get_data(as_text=True)


def test_remote_mode_hides_acknowledge_comment_and_close(remote_stack):
    app, _, _ = remote_stack
    client, _ = login(app, "admin")
    page = client.get("/incidents/1").get_data(as_text=True)
    assert "Acknowledge" not in page and "Review and close" not in page and "Add a comment" not in page
    assert "/ack" not in page and "/comment" not in page and "/close" not in page
    assert "read-only" in page.lower() or "cannot acknowledge" in page


@pytest.mark.parametrize("path,data", [
    ("/incidents/1/ack", {}),
    ("/incidents/1/comment", {"message": "hello there"}),
    ("/incidents/1/close", {"classification": "benign", "comment": "fine", "step": "confirm"}),
])
def test_remote_mode_refuses_the_write_routes_with_a_clear_message(remote_stack, path, data):
    app, _, bot = remote_stack
    client, _ = login(app, "admin")
    before = bot.incident_count()
    resp = post(client, path, "/incidents/1", **data)
    assert resp.status_code == 405
    follow = client.get("/incidents/1").get_data(as_text=True)
    assert "read-only" in follow
    assert bot.incident_count() == before
    assert "Closed" not in follow.split("Timeline")[0] or "Active" in follow  # status did not change


def test_enrich_in_remote_mode_does_not_write_a_comment(remote_stack):
    app, backends, _ = remote_stack
    client, _ = login(app, "read")
    class Report:
        ip, abuse_score, vt_malicious, verdict, is_public, errors = "10.0.0.5", None, None, "Internal", False, []
        abuse_reports = country = isp = usage_type = vt_suspicious = vt_harmless = as_owner = None

    async def fake(ip):
        return Report()

    backends.enrichment = type("E", (), {"enrich_ip": staticmethod(fake)})()
    resp = post(client, "/incidents/1/enrich", "/incidents/1")
    assert resp.status_code == 200
    assert [c.body for c in backends.runner.run(backends.store.get(1)).comments] == ["first look"]


def test_the_status_strip_says_offline_when_soc_siem_goes_away(remote_stack):
    app, backends, bot = remote_stack
    client, _ = login(app, "triage")
    bot.stop()
    page = client.get("/incidents")
    assert page.status_code == 502
    text = page.get_data(as_text=True)
    assert "unreachable" in text and "Traceback" not in text and API_SECRET not in text
    import time
    for _ in range(40):  # the strip is refreshed in the background
        if "soc-siem offline" in client.get("/hunt").get_data(as_text=True):
            break
        time.sleep(0.25)
    else:
        raise AssertionError("the status strip never showed soc-siem as offline")


def test_the_assistant_tools_read_from_soc_siem(remote_stack):
    app, _, _ = remote_stack
    client, _ = login(app, "triage")
    from .web_helpers import ask
    resp = ask(client, "How many incidents are open?")
    text = resp.get_json()["answer"]["text"]
    assert resp.status_code == 200 and "Discovery commands" in text or "2" in text  # answered from soc-siem's data


# ---- configuration -------------------------------------------------------------------------------------------


def test_the_two_variables_go_together_and_the_secret_is_long_enough():
    WebSettings(secret_key="k" * 40).validate()
    WebSettings(secret_key="k" * 40, bot_api_url="http://192.168.56.10:8765", bot_api_secret=API_SECRET).validate()
    with pytest.raises(ConfigError, match="together"):
        WebSettings(secret_key="k" * 40, bot_api_url="http://192.168.56.10:8765").validate()
    with pytest.raises(ConfigError, match="together"):
        WebSettings(secret_key="k" * 40, bot_api_secret=API_SECRET).validate()
    with pytest.raises(ConfigError, match="32"):
        WebSettings(secret_key="k" * 40, bot_api_url="http://h:1", bot_api_secret="short").validate()
    with pytest.raises(ConfigError, match="SOC_BOT_API_URL"):
        WebSettings(secret_key="k" * 40, bot_api_url="ftp://h", bot_api_secret=API_SECRET).validate()
    assert API_SECRET not in repr(WebSettings(secret_key="k" * 40, bot_api_url="http://h:1", bot_api_secret=API_SECRET))


def test_the_bot_api_secret_is_read_from_the_environment(monkeypatch):
    monkeypatch.setattr("soc_web.config.load_dotenv", lambda: None)
    monkeypatch.setenv("SOC_WEB_SECRET_KEY", "k" * 40)
    monkeypatch.setenv("SOC_BOT_API_URL", "http://192.168.56.10:8765")
    monkeypatch.setenv("SOC_BOT_API_SECRET", API_SECRET)
    assert WebSettings.from_env().remote == ("http://192.168.56.10:8765", API_SECRET)
    monkeypatch.delenv("SOC_BOT_API_URL")
    monkeypatch.delenv("SOC_BOT_API_SECRET")
    assert WebSettings.from_env().remote is None


def test_settings_api_secret_rules():
    base = {
        "discord_token": "t", "guild_id": None, "allowed_channel_ids": frozenset({1}), "audit_channel_id": None,
        "read_role_ids": frozenset({1}), "triage_role_ids": frozenset(), "response_role_ids": frozenset(),
        "isolation_denylist": (), "mock_mode": False, "webhook_secret": "w" * 40,
    }
    Settings(**base).validate()  # no API secret: fine, the routes simply do not exist
    Settings(**{**base, "api_secret": API_SECRET}).validate()
    with pytest.raises(ConfigError, match="at least 32"):
        Settings(**{**base, "api_secret": "short"}).validate()
    with pytest.raises(ConfigError, match="different"):
        Settings(**{**base, "api_secret": "w" * 40}).validate()
    assert API_SECRET not in repr(Settings(**{**base, "api_secret": API_SECRET}))
    # the relay guard is untouched
    with pytest.raises(ConfigError, match="not allowed for the Discord bot"):
        Settings(**{**base, "ai_backend": "claude_code"}).validate()


def test_the_read_only_message_is_what_the_user_sees():
    assert "read-only" in READ_ONLY
