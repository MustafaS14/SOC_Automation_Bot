"""Try the assistant from a terminal, without Discord: python -m soc_bot.ai.demo --level viewer "how many incidents?"

Uses the same fake incidents, hunts and IP data as SOC_BOT_MOCK. The default backend is the scripted mock;
--backend claude_code runs the real relay (Claude Code must be installed and logged in).
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

from ..audit import AuditLogger
from ..clients import mock
from ..rbac import Permission
from ..store import IncidentStore
from . import Assistant, ClaudeCodeBackend, MockBackend, ToolContext

LEVELS = {"viewer": Permission.VIEWER, "analyst": Permission.READ, "responder": Permission.RESPONSE, "admin": Permission.ADMIN}


async def run(question: str, level: Permission, backend_name: str) -> None:
    store = IncidentStore(":memory:")
    audit_path = Path(tempfile.mkdtemp()) / "audit.jsonl"
    audit = AuditLogger(audit_path)
    audit.record(actor="demo-user", actor_id=1, action="incident.show", target="#1", outcome="success")
    try:
        await mock.seed_incidents(store)
        ctx = ToolContext(
            store=store,
            splunk=mock.MockSplunkClient(),
            enrichment=mock.MockEnrichmentClient(),
            ssh=mock.MockSshResponseClient(),
            isolation_denylist=("dc*",),
            audit_log_path=str(audit_path),
        )
        backend = MockBackend() if backend_name == "mock" else ClaudeCodeBackend()
        answer = await Assistant(backend, ctx).ask(question, level, user_id=1)
        print(f"[{level.name} | {answer.outcome} | tools: {', '.join(answer.tools_used) or 'none'} | model calls: {answer.calls}]")
        print(answer.text)
    finally:
        audit.close()
        store.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("question")
    parser.add_argument("--level", choices=sorted(LEVELS), default="analyst")
    parser.add_argument("--backend", choices=["mock", "claude_code"], default="mock")
    args = parser.parse_args()
    asyncio.run(run(args.question, LEVELS[args.level], args.backend))


if __name__ == "__main__":
    main()
