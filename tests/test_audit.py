import json

from soc_bot.audit import AuditLogger


def test_audit_logger_writes_jsonl_and_closes_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.record(actor="a", actor_id=1, action="device.isolate", target="ws1\ninjected", outcome="success")
    audit.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["target"] == "ws1\ninjected"
    assert audit._file_handler.stream is None  # handle released


def test_audit_logger_appends_across_restarts(tmp_path):
    path = tmp_path / "audit.jsonl"
    for action in ("first", "second"):
        audit = AuditLogger(path)
        audit.record(actor="a", actor_id=1, action=action, target="t", outcome="success")
        audit.close()
    assert [json.loads(line)["action"] for line in path.read_text(encoding="utf-8").splitlines()] == ["first", "second"]


def test_secrets_in_free_text_are_redacted(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    pasted = ("why does sk-ant-api03-abcdefghijklmnop1234 fail? token=abc123secret ghp_" + "a" * 30
              + " Bearer " + "x" * 30 + " " + "ab" * 24)
    audit.record(actor="a", actor_id=1, action="ai.ask", target="t", outcome="success", question=pasted, calls=2)
    audit.close()
    entry = json.loads(path.read_text(encoding="utf-8"))
    assert entry["calls"] == 2
    for leaked in ("sk-ant", "abc123secret", "ghp_", "xxxxxxxx", "abababab"):
        assert leaked not in entry["question"]
    assert entry["question"].startswith("why does [redacted] fail?")


def test_ordinary_text_is_not_redacted(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.record(actor="a", actor_id=1, action="x", target="t", outcome="success",
                 message="Brute force from 203.0.113.9 against ws-01, closing as true positive")
    audit.close()
    assert "203.0.113.9" in path.read_text(encoding="utf-8")
