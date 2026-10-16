import json

import pytest

from soc_bot.audit import AuditLogger
from soc_bot.clients import APIError, NotFoundError
from soc_bot.store import IncidentStore


def test_audit_logger_writes_jsonl_and_closes_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.record(actor="a", actor_id=1, action="device.isolate", target="ws1\ninjected", outcome="success")
    audit.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["target"] == "ws1\ninjected"
    assert audit._file_handler.stream is None  # handle released


@pytest.fixture
def store():
    s = IncidentStore(":memory:")
    yield s
    s.shutdown()


async def test_create_list_get(store):
    a = await store.create(rule="Discovery", severity="High", host="soc-victim", src_ip="1.2.3.4")
    await store.create(rule="Other", severity="Low")
    assert a.id == 1 and a.status == "New"

    high = await store.list(severity="High")
    assert [i.rule for i in high] == ["Discovery"]
    assert [i.id for i in await store.list()] == [2, 1]

    fetched = await store.get(1)
    assert fetched.host == "soc-victim" and fetched.src_ip == "1.2.3.4"


async def test_unknown_incident_and_bad_filters(store):
    with pytest.raises(NotFoundError):
        await store.get(99)
    with pytest.raises(NotFoundError):
        await store.add_comment(99, "a", "x")
    with pytest.raises(ValueError):
        await store.list(status="open' OR 1=1 --")
    with pytest.raises(ValueError):
        await store.create(rule="r", severity="Critical")


async def test_comment_and_acknowledge(store):
    inc = await store.create(rule="r", severity="Medium")
    await store.add_comment(inc.id, "analyst", "<b>looking</b>")
    updated = await store.acknowledge(inc.id, "analyst")
    assert updated.status == "Active" and updated.assignee == "analyst"
    assert [(c.author, c.body) for c in updated.comments] == [("analyst", "<b>looking</b>")]
    with pytest.raises(APIError) as exc:
        await store.acknowledge(inc.id, "other")
    assert exc.value.status == 409


async def test_close_records_classification_and_rejects_double_close(store):
    inc = await store.create(rule="r", severity="High")
    closed = await store.close(inc.id, "true_positive", "confirmed", "analyst")
    assert closed.status == "Closed" and closed.classification == "true_positive"
    assert "Closed as true_positive: confirmed" in closed.comments[-1].body
    with pytest.raises(APIError) as exc:
        await store.close(inc.id, "benign", "again", "other")
    assert exc.value.status == 409
    with pytest.raises(ValueError):
        await store.close(inc.id, "bogus", "x", "a")
    assert [i.id for i in await store.list(status="open")] == []
