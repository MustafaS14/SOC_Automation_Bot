import json
import os
import stat

import pytest

from soc_bot.ai import build_assistant
from soc_bot.ai.backends import BackendError, ClaudeCodeBackend, MockBackend
from soc_bot.ai.tools import ToolContext
from soc_bot.config import Settings

FAKE_CLAUDE = """#!/bin/sh
printf '%s\\n' "$@" > "$OUT/args.txt"
cat > "$OUT/stdin.txt"
env > "$OUT/env.txt"
pwd > "$OUT/cwd.txt"
echo '{"answer": "from the fake claude"}'
"""


def write_script(directory, body):
    path = directory / "claude"
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


async def test_claude_code_gets_no_tools_and_no_bot_secrets(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    command = write_script(tmp_path, FAKE_CLAUDE)
    os.environ["OUT"], os.environ["DISCORD_TOKEN"], os.environ["SPLUNK_TOKEN"] = str(out), "SECRET-A", "SECRET-B"
    try:
        # OUT must reach the script for this test only, so it is passed through the kept variable HOME.
        backend = ClaudeCodeBackend(command, model="sonnet", timeout=10)
        backend.build_env = lambda: {"PATH": os.environ["PATH"], "OUT": str(out)}  # type: ignore[method-assign]
        reply = await backend.complete("SYSTEM TEXT", "THE <question>")
    finally:
        for key in ("OUT", "DISCORD_TOKEN", "SPLUNK_TOKEN"):
            os.environ.pop(key, None)

    assert json.loads(reply) == {"answer": "from the fake claude"}
    args = (out / "args.txt").read_text().splitlines()
    assert args[0] == "-p" and "--system-prompt" in args and args[args.index("--system-prompt") + 1] == "SYSTEM TEXT"
    assert args[args.index("--tools") + 1] == ""
    assert "--no-session-persistence" in args and "--strict-mcp-config" in args
    assert "--model" in args and args[args.index("--model") + 1] == "sonnet"
    assert "Bash" in args and "WebFetch" in args  # explicitly denied as a second lock
    assert (out / "stdin.txt").read_text() == "THE <question>"  # the prompt travels on stdin, not in argv
    assert "SECRET" not in (out / "env.txt").read_text()
    assert (out / "cwd.txt").read_text().strip() != os.getcwd()


def test_default_environment_keeps_only_what_login_needs():
    os.environ["DISCORD_TOKEN"] = "SECRET"
    try:
        env = ClaudeCodeBackend().build_env()
    finally:
        os.environ.pop("DISCORD_TOKEN")
    assert "DISCORD_TOKEN" not in env and set(env) <= {
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"
    }


async def test_missing_command_is_a_backend_error():
    with pytest.raises(BackendError):
        await ClaudeCodeBackend("/nonexistent/claude").complete("s", "p")


async def test_nonzero_exit_is_a_backend_error(tmp_path):
    command = write_script(tmp_path, "#!/bin/sh\ncat >/dev/null\necho boom >&2\nexit 3\n")
    with pytest.raises(BackendError, match="exit status 3"):
        await ClaudeCodeBackend(command, timeout=10).complete("s", "p")


async def test_timeout_kills_the_process(tmp_path):
    command = write_script(tmp_path, "#!/bin/sh\nsleep 30\n")
    with pytest.raises(BackendError, match="timed out"):
        await ClaudeCodeBackend(command, timeout=0.3).complete("s", "p")


async def test_mock_backend_answers_in_the_protocol_format():
    prompt = "<tools>\n- incident_counts() - x\n</tools>\n<question>how many incidents?</question>"
    assert json.loads(await MockBackend().complete("sys", prompt)) == {"tool": "incident_counts", "args": {}}


SETTINGS = dict(
    discord_token="t", guild_id=None, allowed_channel_ids=frozenset({1}), audit_channel_id=None,
    read_role_ids=frozenset({1}), triage_role_ids=frozenset(), response_role_ids=frozenset(),
    isolation_denylist=(), mock_mode=True,
)


def test_build_assistant_follows_the_setting():
    ctx = ToolContext(store=None)
    assert build_assistant(Settings(**{**SETTINGS, "ai_backend": "off"}), ctx) is None
    assert build_assistant(Settings(**{**SETTINGS, "ai_backend": "mock"}), ctx) is not None
    assert build_assistant(Settings(**{**SETTINGS, "ai_backend": "claude_code"}), ctx) is not None
