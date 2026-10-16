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
