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


def test_parse_alert_normalises_fields():
    fields = parse_alert(SPLUNK_PAYLOAD)
    assert fields["rule"] == "Discovery commands"
    assert fields["severity"] == "High"
    assert fields["host"] == "soc-victim" and fields["src_ip"] == "192.168.56.30"
    assert fields["url"].startswith("https://")


def test_parse_alert_drops_bad_values_instead_of_trusting_them():
    fields = parse_alert({
        "search_name": "r",
        "results_link": "javascript:alert(1)",
        "result": {"host": "bad host`", "src_ip": "not-an-ip", "severity": "catastrophic"},
    })
    assert fields["host"] is None and fields["src_ip"] is None
    assert fields["url"] is None and fields["severity"] == "Medium"


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


async def test_webhook_accepts_query_secret_for_splunk_builtin_action(client):
    resp = await client.post("/webhook/splunk?secret=s3cret", json=SPLUNK_PAYLOAD)
    assert resp.status == 201


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
