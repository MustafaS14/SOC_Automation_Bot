"""The close-stale command: age parsing, a dry run, a real run, and the audit trail."""

import argparse
import json
import sqlite3
from datetime import timedelta

import pytest

from soc_bot.__main__ import main, parse_age


@pytest.mark.parametrize("text, expected", [("90m", timedelta(minutes=90)), ("24h", timedelta(hours=24)), ("7D", timedelta(days=7))])
def test_parse_age(text, expected):
    assert parse_age(text) == expected


@pytest.mark.parametrize("text", ["", "0h", "5", "h", "1w", "-3h", "1.5h", "24 hours"])
def test_parse_age_rejects_bad_values(text):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_age(text)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    db, audit = tmp_path / "incidents.db", tmp_path / "audit.jsonl"
    monkeypatch.setattr("soc_bot.config.load_dotenv", lambda: None)  # never read the real .env
    from soc_bot.store import IncidentStore

    store = IncidentStore(str(db))
    import asyncio

    async def seed():
        await store.create(rule="Old test alert", severity="High", host="soc-victim")
        await store.create(rule="Fresh alert", severity="Medium", host="soc-victim")

    asyncio.run(seed())
    store._db.execute("UPDATE incidents SET updated = '2020-01-01T00:00:00+00:00' WHERE id = 1")
    store._db.commit()
    store.shutdown()
    for name in ("DISCORD_TOKEN", "WEBHOOK_SECRET", "SPLUNK_URL", "SPLUNK_TOKEN", "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN",
                 "RESPONDER_HOSTS", "RESPONDER_SSH_KEY", "SOC_BOT_MOCK", "API_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit))
    return db, audit


def _status(db, incident_id):
    return sqlite3.connect(db).execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()[0]


def test_dry_run_lists_but_changes_nothing(lab, capsys):
    db, audit = lab
    assert main(["close-stale", "--older-than", "24h", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Would close 1 incident(s)" in out and "Old test alert" in out and "Fresh alert" not in out
    assert _status(db, 1) == "New"
    assert json.loads(audit.read_text().splitlines()[-1])["outcome"] == "dry-run"


def test_real_run_closes_only_the_old_incident_and_audits_it(lab, capsys):
    db, audit = lab
    assert main(["close-stale", "--older-than", "24h"]) == 0
    assert "Closed 1 incident(s)" in capsys.readouterr().out
    assert _status(db, 1) == "Closed" and _status(db, 2) == "New"
    entry = json.loads(audit.read_text().splitlines()[-1])
    assert entry["action"] == "close-stale" and entry["outcome"] == "success" and entry["ids"] == [1]


def test_bad_age_is_a_usage_error(lab, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["close-stale", "--older-than", "soon"])
    assert exc.value.code == 2
