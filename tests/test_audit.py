import json
from types import SimpleNamespace

from soc_bot.audit import AuditLogger
from soc_bot.clients import APIError
from soc_bot.config import Settings
from soc_bot.discord_bot import SocBot
from soc_bot.models import Incident


def test_audit_logger_writes_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.record(actor="a", actor_id=1, action="device.isolate", target="ws1\ninjected", outcome="success")
    audit.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["target"] == "ws1\ninjected"


class FakeSentinel:
    def __init__(self, fail=False):
        self.fail = fail
        self.comments = []

    async def add_comment(self, incident_id, message):
        if self.fail:
            raise APIError("Sentinel", 500, "boom")
        self.comments.append((incident_id, message))


def make_bot(tmp_path):
    settings = Settings(
        discord_token="x", guild_id=None, allowed_channel_ids=frozenset(), audit_channel_id=None,
        read_role_ids=frozenset({1}), triage_role_ids=frozenset(), response_role_ids=frozenset(),
        isolation_denylist=(), mock_mode=True, audit_log_path=str(tmp_path / "a.jsonl"),
    )
    return SocBot(settings)


async def test_incident_comment_is_html_escaped_and_attributed(tmp_path):
    bot = make_bot(tmp_path)
    bot.sentinel = FakeSentinel()
    interaction = SimpleNamespace(user=type("U", (), {"id": 42, "__str__": lambda self: "analyst"})())
    incident = Incident(id="guid", number=7, title="t", severity="High", status="New")

    assert await bot.comment_incident(interaction, incident, "Reason: <script>alert(1)</script>")
    (_, message), = bot.sentinel.comments
    assert "&lt;script&gt;" in message and "<script>" not in message
    assert "analyst / 42" in message
    bot.audit_log.close()


async def test_incident_comment_failure_does_not_raise(tmp_path):
    bot = make_bot(tmp_path)
    bot.sentinel = FakeSentinel(fail=True)
    interaction = SimpleNamespace(user=type("U", (), {"id": 1, "__str__": lambda self: "a"})())
    incident = Incident(id="guid", number=7, title="t", severity="High", status="New")
    assert await bot.comment_incident(interaction, incident, "x") is False
    bot.audit_log.close()
