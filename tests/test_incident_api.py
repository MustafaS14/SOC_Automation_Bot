"""The bot's read-only incident API: authentication, filters, limits, redaction, and that nothing can be written."""

import pytest
from aiohttp.test_utils import TestClient, TestServer

from soc_bot.audit import redact
from soc_bot.store import IncidentStore
from soc_bot.webhook import create_app

API_SECRET = "a" * 40
HEADERS = {"X-Api-Secret": API_SECRET}


async def noop(incident):
    pass


@pytest.fixture
async def seeded():
    store = IncidentStore(":memory:")
    a = await store.create(rule="Discovery commands", severity="High", host="soc-victim", src_ip="10.0.0.5",
                           description="whoami")
    await store.create(rule="Cron anomaly", severity="Low", host="soc-victim")
    await store.create(rule="Masquerading", severity="Medium", host="soc-web")
    await store.acknowledge(a.id, "analyst")
    closed = await store.create(rule="Old one", severity="Low")
    await store.close(closed.id, "benign", "scheduled job", "analyst")
    yield store
    store.shutdown()


@pytest.fixture
async def api(seeded):
    app = create_app(seeded, "w" * 40, noop, api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        client.store = seeded
        yield client


async def test_missing_or_wrong_secret_is_401_and_the_right_one_is_200(api):
    assert (await api.get("/api/incidents")).status == 401
    assert (await api.get("/api/incidents", headers={"X-Api-Secret": "wrong"})).status == 401
    assert (await api.get("/api/incidents", headers={"X-Api-Secret": ""})).status == 401
    assert (await api.get("/api/incidents/1", headers={"X-Api-Secret": "wrong"})).status == 401
    ok = await api.get("/api/incidents", headers=HEADERS)
    assert ok.status == 200
    assert {i["rule"] for i in (await ok.json())["incidents"]} == {"Discovery commands", "Cron anomaly", "Masquerading"}


async def test_the_webhook_secret_does_not_open_the_api(api):
    resp = await api.get("/api/incidents", headers={"X-Api-Secret": "w" * 40})
    assert resp.status == 401


async def test_the_secret_in_the_query_string_is_never_accepted(api):
    assert (await api.get(f"/api/incidents?secret={API_SECRET}")).status == 401
    assert (await api.get(f"/api/incidents?api_secret={API_SECRET}&X-Api-Secret={API_SECRET}")).status == 401


async def test_routes_are_absent_when_no_api_secret_is_set(seeded):
    app = create_app(seeded, "w" * 40, noop)
    async with TestClient(TestServer(app)) as client:
        for path in ("/api/incidents", "/api/incidents/1", "/api/counts"):
            assert (await client.get(path, headers=HEADERS)).status == 404
        assert not [r for r in app.router.routes() if "/api" in (r.resource.canonical if r.resource else "")]


def test_the_api_secret_must_differ_from_the_webhook_secret_and_not_be_short():
    store = IncidentStore(":memory:")
    with pytest.raises(ValueError, match="different"):
        create_app(store, "s" * 40, noop, api_secret="s" * 40)
    with pytest.raises(ValueError, match="at least 32"):
        create_app(store, "w" * 40, noop, api_secret="short")
    store.shutdown()


async def test_status_severity_order_filters(api):
    async def rules(query):
        resp = await api.get("/api/incidents" + query, headers=HEADERS)
        assert resp.status == 200
        return [i["rule"] for i in (await resp.json())["incidents"]]

    assert await rules("?status=closed") == ["Old one"]
    assert await rules("?status=new") == ["Masquerading", "Cron anomaly"]
    assert await rules("?status=active") == ["Discovery commands"]
    assert len(await rules("?status=all")) == 4
    assert await rules("?status=all&severity=Low") == ["Old one", "Cron anomaly"]
    assert (await rules("?status=all&order=oldest"))[0] == "Discovery commands"
    assert len(await rules("")) == 3  # the default is open incidents


async def test_the_limit_is_capped_at_fifty_and_floored_at_one():
    store = IncidentStore(":memory:")
    for i in range(60):
        await store.create(rule=f"rule {i}", severity="Low")
    app = create_app(store, "w" * 40, noop, api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        async def count(query):
            return len((await (await client.get("/api/incidents" + query, headers=HEADERS)).json())["incidents"])

        assert await count("?limit=500") == 50
        assert await count("?limit=7") == 7
        assert await count("?limit=0") == 1
        assert await count("?limit=-5") == 1
        assert await count("") == 10  # the default
        assert (await client.get("/api/incidents?limit=abc", headers=HEADERS)).status == 400
    store.shutdown()


async def test_bad_filters_are_400_with_a_plain_message(api):
    for query in ("?status=weird", "?severity=Catastrophic", "?order=sideways"):
        resp = await api.get("/api/incidents" + query, headers=HEADERS)
        assert resp.status == 400 and "error" in await resp.json()


async def test_one_incident_has_its_comments_and_an_unknown_id_is_404(api):
    await api.store.add_comment(1, "analyst", "looked at it")
    one = await api.get("/api/incidents/1", headers=HEADERS)
    body = await one.json()
    assert one.status == 200 and body["rule"] == "Discovery commands" and body["status"] == "Active"
    assert [c["body"] for c in body["comments"]] == ["looked at it"]
    for path in ("/api/incidents/999", "/api/incidents/0", "/api/incidents/abc", "/api/incidents/-1"):
        resp = await api.get(path, headers=HEADERS)
        assert resp.status == 404 and await resp.json() == {"error": "not found"}, path


async def test_the_list_does_not_carry_comments(api):
    await api.store.add_comment(1, "analyst", "private note")
    rows = (await (await api.get("/api/incidents?status=all", headers=HEADERS)).json())["incidents"]
    assert all("comments" not in row for row in rows)


async def test_only_incident_fields_come_back(api):
    body = await (await api.get("/api/incidents/1", headers=HEADERS)).json()
    assert set(body) == {"id", "rule", "severity", "status", "host", "src_ip", "assignee", "description", "url",
                         "classification", "created", "updated", "comments"}


async def test_counts_match_the_store(api):
    body = await (await api.get("/api/counts", headers=HEADERS)).json()
    assert body == await api.store.counts()
    assert body["status"] == {"Active": 1, "New": 2, "Closed": 1}


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
@pytest.mark.parametrize("path", ["/api/incidents", "/api/incidents/1", "/api/counts"])
async def test_write_methods_are_refused_even_with_the_secret(api, method, path):
    before = await api.store.counts()
    resp = await getattr(api, method)(path, headers=HEADERS, json={"rule": "x", "severity": "High"})
    assert resp.status == 405
    assert await api.store.counts() == before


async def test_free_text_is_redacted():
    store = IncidentStore(":memory:")
    key = "sk-" + "a1B2c3D4" * 4
    inc = await store.create(rule="r", severity="High", description=f"curl with password: hunter2 and {key}")
    await store.add_comment(inc.id, "analyst", f"token = abc123def456 {key}")
    app = create_app(store, "w" * 40, noop, api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        text = await (await client.get(f"/api/incidents/{inc.id}", headers=HEADERS)).text()
        listed = await (await client.get("/api/incidents", headers=HEADERS)).text()
    for out in (text, listed):
        assert "hunter2" not in out and key not in out and "abc123def456" not in out
        assert "[redacted]" in out or out is listed and "hunter2" not in out
    store.shutdown()


def test_the_secret_headers_are_redacted_in_text():
    assert "abc" not in redact("X-Api-Secret: abcabcabc")
    assert "abc" not in redact("x-webhook-secret=abcabcabc")


async def test_the_rate_limit_applies_to_authenticated_calls_only(seeded):
    now = [0.0]
    app = create_app(seeded, "w" * 40, noop, max_per_minute=3, clock=lambda: now[0], api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        for _ in range(10):  # strangers do not use up the budget
            assert (await client.get("/api/incidents")).status == 401
        for _ in range(3):
            assert (await client.get("/api/incidents", headers=HEADERS)).status == 200
        limited = await client.get("/api/incidents", headers=HEADERS)
        assert limited.status == 429 and limited.headers["Retry-After"] == "60"
        now[0] += 61
        assert (await client.get("/api/incidents", headers=HEADERS)).status == 200


async def test_the_api_budget_is_separate_from_the_webhooks(seeded):
    now = [0.0]
    app = create_app(seeded, "w" * 40, noop, max_per_minute=2, clock=lambda: now[0], api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        for _ in range(5):
            await client.get("/api/incidents", headers=HEADERS)
        alert = {"search_name": "r", "result": {"severity": "high"}}
        assert (await client.post("/webhook/splunk", json=alert, headers={"X-Webhook-Secret": "w" * 40})).status == 201


async def test_errors_are_generic_with_no_stack_trace(seeded):
    class Broken(IncidentStore):
        async def list(self, *a, **k):
            raise RuntimeError("secret internal detail /home/x/incidents.db")

    store = Broken(":memory:")
    app = create_app(store, "w" * 40, noop, api_secret=API_SECRET)
    async with TestClient(TestServer(app)) as client:
        resp = await client.get("/api/incidents", headers=HEADERS)
        text = await resp.text()
    assert resp.status == 500 and "secret internal detail" not in text and "Traceback" not in text
    assert await resp.json() == {"error": "internal error"}
    store.shutdown()
