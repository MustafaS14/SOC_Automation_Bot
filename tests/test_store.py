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


# --- repeats are folded into the open incident -------------------------------------------------------------------


async def test_repeat_is_folded_into_the_open_incident(store):
    first = await store.create(rule="Sudo", severity="Medium", host="soc-victim", description="first")
    merged = await store.merge_repeat(rule="Sudo", host="soc-victim", src_ip=None, description="again", window=3600)
    assert merged is not None and merged.id == first.id and merged.repeats == 1
    assert merged.comments[-1].author == "splunk" and "again" in merged.comments[-1].body
    assert len(await store.list(status="all")) == 1  # no second incident


async def test_repeat_needs_the_same_rule_host_and_source(store):
    await store.create(rule="Sudo", severity="Medium", host="soc-victim", src_ip="1.2.3.4")
    for rule, host, ip in (("Other", "soc-victim", "1.2.3.4"), ("Sudo", "soc-siem", "1.2.3.4"), ("Sudo", "soc-victim", "9.9.9.9"),
                           ("Sudo", "soc-victim", None)):
        assert await store.merge_repeat(rule=rule, host=host, src_ip=ip, description="", window=3600) is None
    assert (await store.merge_repeat(rule="Sudo", host="soc-victim", src_ip="1.2.3.4", description="", window=3600)).repeats == 1


async def test_repeat_matches_missing_host_and_source_with_each_other(store):
    first = await store.create(rule="Heartbeat", severity="High")
    again = await store.merge_repeat(rule="Heartbeat", host=None, src_ip=None, description="", window=3600)
    assert again is not None and again.id == first.id


async def test_closed_incidents_are_never_merged_into(store):
    inc = await store.create(rule="Sudo", severity="Medium", host="h")
    await store.close(inc.id, "benign", "ok", "a")
    assert await store.merge_repeat(rule="Sudo", host="h", src_ip=None, description="", window=3600) is None


async def test_repeat_outside_the_window_opens_a_new_incident(store):
    inc = await store.create(rule="Sudo", severity="Medium", host="h")
    store._db.execute("UPDATE incidents SET updated = '2020-01-01T00:00:00+00:00' WHERE id = ?", (inc.id,))
    assert await store.merge_repeat(rule="Sudo", host="h", src_ip=None, description="", window=3600) is None


async def test_window_of_zero_turns_merging_off(store):
    await store.create(rule="Sudo", severity="Medium", host="h")
    assert await store.merge_repeat(rule="Sudo", host="h", src_ip=None, description="", window=0) is None


async def test_steady_repeats_keep_extending_the_window(store):
    inc = await store.create(rule="Sudo", severity="Medium", host="h")
    for _ in range(3):
        merged = await store.merge_repeat(rule="Sudo", host="h", src_ip=None, description="", window=3600)
    assert merged.id == inc.id and merged.repeats == 3


# --- closing stale incidents ---------------------------------------------------------------------------------------


def _age(store, incident_id, when="2020-01-01T00:00:00+00:00"):
    store._db.execute("UPDATE incidents SET updated = ? WHERE id = ?", (when, incident_id))


async def test_close_stale_closes_old_new_incidents_as_benign(store):
    from datetime import timedelta

    old = await store.create(rule="Old", severity="High")
    fresh = await store.create(rule="Fresh", severity="High")
    _age(store, old.id)
    closed = await store.close_stale(timedelta(hours=24), label="24h")
    assert [i.id for i in closed] == [old.id]
    after = await store.get(old.id)
    assert after.status == "Closed" and after.classification == "benign"
    assert after.comments[-1].author == "housekeeping" and "24h" in after.comments[-1].body
    assert (await store.get(fresh.id)).status == "New"


async def test_close_stale_leaves_acknowledged_incidents_unless_asked(store):
    from datetime import timedelta

    inc = await store.create(rule="Mine", severity="High")
    await store.acknowledge(inc.id, "analyst")
    _age(store, inc.id)
    assert await store.close_stale(timedelta(hours=1)) == []
    assert (await store.get(inc.id)).status == "Active"
    assert [i.id for i in await store.close_stale(timedelta(hours=1), include_active=True)] == [inc.id]


async def test_close_stale_dry_run_changes_nothing(store):
    from datetime import timedelta

    inc = await store.create(rule="Old", severity="High")
    _age(store, inc.id)
    assert [i.id for i in await store.close_stale(timedelta(hours=1), dry_run=True)] == [inc.id]
    assert (await store.get(inc.id)).status == "New"


async def test_close_stale_rejects_a_zero_age(store):
    from datetime import timedelta

    with pytest.raises(ValueError):
        await store.close_stale(timedelta(0))


async def test_old_database_without_the_repeats_column_is_migrated(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, severity TEXT NOT NULL,"
                     " host TEXT, src_ip TEXT, status TEXT NOT NULL DEFAULT 'New', assignee TEXT, description TEXT NOT NULL DEFAULT '',"
                     " url TEXT, classification TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);"
                     "INSERT INTO incidents (rule, severity, created, updated) VALUES ('r', 'High', 'x', 'x');")
    db.commit()
    db.close()
    migrated = IncidentStore(str(path))
    try:
        assert (await migrated.get(1)).repeats == 0
    finally:
        migrated.shutdown()
