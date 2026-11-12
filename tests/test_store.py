import pytest

from soc_bot.clients import APIError, NotFoundError
from soc_bot.store import IncidentStore


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


async def test_status_filters(store):
    new = await store.create(rule="new", severity="Low")
    active = await store.create(rule="active", severity="Low")
    closed = await store.create(rule="closed", severity="Low")
    await store.acknowledge(active.id, "a")
    await store.close(closed.id, "benign", "ok", "a")

    ids = lambda items: sorted(i.id for i in items)  # noqa: E731
    assert ids(await store.list(status="open")) == ids([new, active])
    assert ids(await store.list(status="new")) == [new.id]
    assert ids(await store.list(status="active")) == [active.id]
    assert ids(await store.list(status="closed")) == [closed.id]
    assert len(await store.list(status="all")) == 3


async def test_limit_is_clamped(store):
    for i in range(3):
        await store.create(rule=f"r{i}", severity="Low")
    assert len(await store.list(limit=0)) == 1
    assert len(await store.list(limit=2)) == 2


async def test_unknown_incident_and_bad_filters(store):
    with pytest.raises(NotFoundError):
        await store.get(99)
    with pytest.raises(NotFoundError):
        await store.add_comment(99, "a", "x")
    with pytest.raises(NotFoundError):
        await store.acknowledge(99, "a")
    with pytest.raises(NotFoundError):
        await store.close(99, "benign", "x", "a")
    with pytest.raises(ValueError):
        await store.list(status="open' OR 1=1 --")
    with pytest.raises(ValueError):
        await store.list(severity="High' OR 1=1 --")
    with pytest.raises(ValueError):
        await store.create(rule="r", severity="Critical")


async def test_sql_metacharacters_are_stored_as_data(store):
    nasty = "x'); DROP TABLE incidents;--"
    inc = await store.create(rule=nasty, severity="Low", description=nasty)
    await store.add_comment(inc.id, nasty, nasty)
    fetched = await store.get(inc.id)
    assert fetched.rule == nasty and fetched.comments[0].body == nasty


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


async def test_failed_close_leaves_no_partial_comment(store):
    inc = await store.create(rule="r", severity="High")
    await store.close(inc.id, "benign", "first", "a")
    with pytest.raises(APIError):
        await store.close(inc.id, "benign", "second", "b")
    assert len((await store.get(inc.id)).comments) == 1


async def test_data_survives_reopen(tmp_path):
    path = str(tmp_path / "incidents.db")
    first = IncidentStore(path)
    await first.create(rule="persisted", severity="Low")
    first.shutdown()
    second = IncidentStore(path)
    assert [i.rule for i in await second.list(status="all")] == ["persisted"]
    second.shutdown()


async def test_list_orders_and_rejects_unknown_order():
    import pytest

    from soc_bot.store import IncidentStore

    store = IncidentStore(":memory:")
    for rule, sev in (("a", "Low"), ("b", "High"), ("c", "Medium"), ("d", "High")):
        await store.create(rule=rule, severity=sev)
    names = lambda rows: [i.rule for i in rows]  # noqa: E731
    assert names(await store.list("all", None, 10, "newest")) == ["d", "c", "b", "a"]
    assert names(await store.list("all", None, 10, "oldest")) == ["a", "b", "c", "d"]
    assert names(await store.list("all", None, 10, "severity")) == ["d", "b", "c", "a"]
    with pytest.raises(ValueError):
        await store.list("all", None, 10, "id; DROP TABLE incidents")
    store.shutdown()


async def test_techniques_round_trip_and_filter(store):
    await store.create(rule="Masq", severity="High", techniques=["T1036.004"])
    await store.create(rule="Recon", severity="Medium", techniques=["T1033", "T1087.001", "T1057"])
    await store.create(rule="Untagged", severity="Low")

    assert (await store.get(2)).techniques == ["T1033", "T1087.001", "T1057"]
    assert (await store.get(3)).techniques == []
    assert [i.rule for i in await store.list(technique="T1087.001")] == ["Recon"]
    assert [i.rule for i in await store.list(technique="T1036")] == ["Masq"]  # a parent matches its sub-techniques
    assert [i.rule for i in await store.list(technique="T1036.004")] == ["Masq"]
    assert [i.rule for i in await store.list(technique="T1087")] == ["Recon"]
    assert await store.list(technique="T9999") == []


async def test_technique_input_is_cleaned_before_it_is_stored(store):
    inc = await store.create(rule="r", severity="Low", techniques=["T1033", "<script>", "t1033", "T1057 T1082"])
    assert inc.techniques == ["T1033", "T1057", "T1082"]


async def test_a_bad_technique_filter_is_refused_not_sent_to_sql(store):
    for bad in ("", "T1", "T1033' OR '1'='1", "%", "T1033.%"):
        with pytest.raises(ValueError):
            await store.list(technique=bad)


async def test_an_old_database_gains_the_column_and_keeps_its_incidents(tmp_path):
    import sqlite3

    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, severity TEXT NOT NULL,
            host TEXT, src_ip TEXT, status TEXT NOT NULL DEFAULT 'New', assignee TEXT,
            description TEXT NOT NULL DEFAULT '', url TEXT, classification TEXT, created TEXT NOT NULL,
            updated TEXT NOT NULL);
        CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
            author TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL);
        INSERT INTO incidents (rule, severity, created, updated) VALUES ('Old alert', 'High', 'x', 'x');
    """)
    db.commit()
    db.close()

    store = IncidentStore(path)
    try:
        assert (await store.get(1)).techniques == []
        new = await store.create(rule="New alert", severity="High", techniques=["T1036.004"])
        assert new.techniques == ["T1036.004"]
    finally:
        store.shutdown()
    IncidentStore(path).shutdown()  # opening it a second time must not try to add the column again
