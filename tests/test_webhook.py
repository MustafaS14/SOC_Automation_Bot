import pytest
from aiohttp.test_utils import TestClient, TestServer

from soc_bot.store import IncidentStore
from soc_bot.validators import ValidationError
from soc_bot.webhook import create_app, parse_alert

SPLUNK_PAYLOAD = {
    "sid": "rt_1",
    "search_name": "Discovery commands",
    "results_link": "https://splunk:8000/app/search/@go?sid=rt_1",
    "result": {"host": "SOC-Victim", "src_ip": "192.168.56.30", "severity": "high", "_raw": "whoami"},
}


SPLUNK_HOSTS = frozenset({"splunk"})


def test_parse_alert_normalises_fields():
    fields = parse_alert(SPLUNK_PAYLOAD, SPLUNK_HOSTS)
    assert fields["rule"] == "Discovery commands"
    assert fields["severity"] == "High"
    assert fields["host"] == "soc-victim" and fields["src_ip"] == "192.168.56.30"
    assert fields["url"] == SPLUNK_PAYLOAD["results_link"]


def test_parse_alert_drops_bad_values_instead_of_trusting_them():
    fields = parse_alert({
        "search_name": "r",
        "results_link": "javascript:alert(1)",
        "result": {"host": "bad host`", "src_ip": "not-an-ip", "severity": "catastrophic"},
    })
    assert fields["host"] is None and fields["src_ip"] is None
    assert fields["url"] is None and fields["severity"] == "Medium"


@pytest.mark.parametrize(
    "link",
    [
        "javascript:alert(1)", "ftp://splunk/x", "//splunk/x", "https://", "https://user:pw@splunk/x",
        "https://splunk/a b", "https://splunk/\nx", "https://splunk/" + "a" * 600, 5, None,
    ],
)
def test_malformed_alert_links_are_dropped(link):
    assert parse_alert({"search_name": "r", "results_link": link}, SPLUNK_HOSTS)["url"] is None


def link_of(link, hosts):
    return parse_alert({"search_name": "r", "results_link": link}, frozenset(hosts))["url"]


def test_link_on_an_allowed_host_is_kept():
    link = "https://splunk.lab/app/search/@go?sid=1"
    assert link_of(link, {"splunk.lab"}) == link


def test_link_host_comparison_ignores_port_and_case():
    # SPLUNK_URL points at the management port (8089); the results link is on the web port (8000).
    link = "https://Splunk.Lab:8000/app/search/@go?sid=1"
    assert link_of(link, {"splunk.lab"}) == link
    assert link_of("http://splunk.lab/x", {"splunk.lab"}) == "http://splunk.lab/x"


def test_link_on_another_host_is_dropped():
    assert link_of("https://evil.example/login", {"splunk.lab"}) is None
    assert link_of("https://splunk.lab.evil.example/x", {"splunk.lab"}) is None
    assert link_of("https://evil.example/@splunk.lab", {"splunk.lab"}) is None


def test_any_listed_host_is_accepted():
    hosts = {"splunk.lab", "192.168.56.10"}
    assert link_of("https://192.168.56.10:8000/x", hosts) == "https://192.168.56.10:8000/x"
    assert link_of("https://splunk.lab/x", hosts) == "https://splunk.lab/x"
    assert link_of("https://other.lab/x", hosts) is None


def test_link_is_dropped_when_no_host_is_configured():
    assert link_of("https://splunk.lab/x", set()) is None
    assert parse_alert(SPLUNK_PAYLOAD)["url"] is None  # default: no allowed hosts


async def test_create_app_warns_when_links_cannot_be_allowed(caplog):
    async def on_incident(incident):
        pass

    with caplog.at_level("WARNING", logger="soc_bot"):
        create_app(IncidentStore(":memory:"), "s", on_incident)
        create_app(IncidentStore(":memory:"), "s", on_incident, link_hosts=frozenset({"splunk"}))
    warnings = [r.getMessage() for r in caplog.records if "alert links will be dropped" in r.getMessage()]
    assert len(warnings) == 1 and "WEBHOOK_LINK_HOSTS" in warnings[0]


async def test_webhook_stores_link_only_for_allowed_hosts():
    store = IncidentStore(":memory:")

    async def on_incident(incident):
        pass

    app = create_app(store, "s3cret", on_incident, link_hosts=SPLUNK_HOSTS)
    headers = {"X-Webhook-Secret": "s3cret"}
    async with TestClient(TestServer(app)) as c:
        await c.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers=headers)
        await c.post("/webhook/splunk", json={**SPLUNK_PAYLOAD, "results_link": "https://evil.example/x"}, headers=headers)
    assert (await store.get(1)).url == SPLUNK_PAYLOAD["results_link"]
    assert (await store.get(2)).url is None
    store.shutdown()


@pytest.mark.parametrize("payload", [[], "x", {}, {"search_name": "  "}])
def test_parse_alert_rejects_invalid(payload):
    with pytest.raises(ValidationError):
        parse_alert(payload)


@pytest.fixture
async def client():
    store = IncidentStore(":memory:")
    posted = []

    async def on_incident(incident):
        posted.append(incident)

    server = TestServer(create_app(store, "s3cret", on_incident))
    async with TestClient(server) as c:
        c.store, c.posted = store, posted
        yield c
    store.shutdown()


async def test_webhook_stores_and_posts(client):
    resp = await client.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers={"X-Webhook-Secret": "s3cret"})
    assert resp.status == 201 and (await resp.json()) == {"id": 1}
    assert (await client.store.get(1)).rule == "Discovery commands"
    assert [i.id for i in client.posted] == [1]


async def test_query_string_secret_is_not_accepted(client):
    resp = await client.post("/webhook/splunk?secret=s3cret", json=SPLUNK_PAYLOAD)
    assert resp.status == 401
    assert await client.store.list(status="all") == []


@pytest.mark.parametrize("secret", ["", "   "])
def test_create_app_rejects_empty_secret(secret):
    async def on_incident(incident):
        pass

    with pytest.raises(ValueError):
        create_app(IncidentStore(":memory:"), secret, on_incident)


async def test_empty_header_is_rejected_when_secret_is_set(client):
    resp = await client.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers={"X-Webhook-Secret": ""})
    assert resp.status == 401


@pytest.mark.parametrize("headers", [{}, {"X-Webhook-Secret": "wrong"}])
async def test_webhook_rejects_bad_secret(client, headers):
    resp = await client.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers=headers)
    assert resp.status == 401
    assert await client.store.list(status="all") == []


async def test_webhook_rejects_bad_json_and_oversize(client):
    headers = {"X-Webhook-Secret": "s3cret"}
    assert (await client.post("/webhook/splunk", data=b"{nope", headers=headers)).status == 400
    assert (await client.post("/webhook/splunk", json={"x": 1}, headers=headers)).status == 400
    assert (await client.post("/webhook/splunk", data=b"x" * 70_000, headers=headers)).status == 413


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


async def test_rate_limit_blocks_floods_and_recovers():
    store = IncidentStore(":memory:")
    posted = []
    clock = FakeClock()

    async def on_incident(incident):
        posted.append(incident)

    headers = {"X-Webhook-Secret": "s3cret"}
    app = create_app(store, "s3cret", on_incident, max_per_minute=3, clock=clock)
    async with TestClient(TestServer(app)) as c:
        statuses = [(await c.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers=headers)).status for _ in range(5)]
        assert statuses == [201, 201, 201, 429, 429]
        assert len(await store.list(status="all")) == 3 and len(posted) == 3

        limited = await c.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers=headers)
        assert limited.headers["Retry-After"] == "60"

        clock.now = 61
        assert (await c.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers=headers)).status == 201
    store.shutdown()


async def test_unauthenticated_requests_do_not_consume_the_rate_limit():
    store = IncidentStore(":memory:")

    async def on_incident(incident):
        pass

    app = create_app(store, "s3cret", on_incident, max_per_minute=1, clock=FakeClock())
    async with TestClient(TestServer(app)) as c:
        for _ in range(5):
            assert (await c.post("/webhook/splunk", json=SPLUNK_PAYLOAD)).status == 401
        ok = await c.post("/webhook/splunk", json=SPLUNK_PAYLOAD, headers={"X-Webhook-Secret": "s3cret"})
        assert ok.status == 201
    store.shutdown()
