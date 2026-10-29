"""Where the assistant's text comes from: Claude Code on this machine, or a scripted mock for tests and demos.

A backend only turns (system prompt, prompt) into reply text. It holds no tools and no credentials of the bot.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from typing import Protocol

from .prompt import DENIED_REPLY, OFF_TOPIC_REPLY

log = logging.getLogger("soc_bot")


class BackendError(RuntimeError):
    """The backend could not produce a reply. The text is for the log only, never for chat."""


class AiBackend(Protocol):
    async def complete(self, system: str, prompt: str) -> str: ...


# Everything Claude Code can do on its own. None of it is wanted here; `--tools ""` already removes them,
# and listing them as denied is a second lock.
_BUILTIN_TOOLS = (
    "Bash Edit MultiEdit Write Read Glob Grep NotebookEdit WebFetch WebSearch Task TodoWrite BashOutput KillShell"
)
_ENV_KEEP = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME")
_MAX_OUTPUT = 20_000


class ClaudeCodeBackend:
    """Runs `claude -p` (Claude Code's non-interactive mode) with every tool switched off.

    Claude Code must already be installed and logged in for the user that runs the bot. The prompt goes in
    through stdin, the bot's own secrets are not passed on, and the process runs in an empty folder.
    """

    def __init__(self, command: str = "claude", model: str = "", timeout: float = 90.0):
        self._command = command
        self._model = model
        self._timeout = timeout

    def build_args(self, system: str) -> list[str]:
        args = [
            self._command, "-p",
            "--system-prompt", system,
            "--tools", "",
            "--disallowedTools", *_BUILTIN_TOOLS.split(),
            "--permission-mode", "dontAsk",
            "--strict-mcp-config",
            "--disable-slash-commands",
            "--no-session-persistence",
            "--output-format", "text",
        ]
        if self._model:
            args += ["--model", self._model]
        return args

    def build_env(self) -> dict[str, str]:
        return {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}

    async def complete(self, system: str, prompt: str) -> str:
        if shutil.which(self._command, path=os.environ.get("PATH")) is None:
            raise BackendError(f"{self._command!r} was not found on PATH")
        workdir = tempfile.mkdtemp(prefix="soc-ai-")
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.build_args(system),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=self.build_env(),
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(prompt.encode()), self._timeout)
            except asyncio.TimeoutError as exc:
                proc.kill()
                await proc.wait()
                raise BackendError(f"timed out after {self._timeout:.0f}s") from exc
        except OSError as exc:
            raise BackendError(f"could not start {self._command!r}: {type(exc).__name__}") from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        if proc.returncode != 0:
            raise BackendError(f"exit status {proc.returncode}: {err.decode(errors='replace')[:200]}")
        return out.decode(errors="replace").strip()[:_MAX_OUTPUT]


def _reply(answer: str) -> str:
    return json.dumps({"answer": answer})


def _call(tool: str, **args: str) -> str:
    return json.dumps({"tool": tool, "args": args})


_SOC_WORDS = (
    "incident", "alert", "host", "ip", "detect", "attack", "log", "command", "isolat", "splunk", "soc",
    "malware", "login", "ssh", "sudo", "audit", "hunt", "severity", "triage", "mitre", "discovery", "caldera",
    "whoami", "machine", "server", "threat", "suspicious", "button", "bot", "dashboard", "ran", "run",
)
_SECRET_WORDS = ("password", "token", "secret", "credential", "api key", "private key")


class MockBackend:
    """A tiny rule-based stand-in so the whole flow can be tried without a model."""

    async def complete(self, system: str, prompt: str) -> str:
        question = self._between(prompt, "<question>", "</question>").lower()
        tools = set(re.findall(r"^- (\w+)\(", prompt, re.M))
        lookups = re.findall(r'<log_data tool="(\w+)"[^>]*>\n(.*?)\n</log_data>', prompt, re.S)

        if lookups:
            data = lookups[-1][1]
            if data.startswith("ACCESS_DENIED"):
                return _reply(DENIED_REPLY)
            if data.startswith("ERROR"):
                return _reply("I couldn't look that up: " + data[7:160])
            return _reply(f"{data[:500]}\nConfidence: low (mock assistant, no real model).\nNot checked: everything else.")

        if any(w in question for w in _SECRET_WORDS):
            return _reply("I can't share credentials or configuration.")
        host = re.search(r"\b(soc-[a-z0-9-]+)\b", question)
        ip = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", question)
        number = re.search(r"#?\b(\d{1,9})\b", question)
        if not (any(w in question for w in _SOC_WORDS) or host or ip):
            return _reply(OFF_TOPIC_REPLY)

        def use(tool: str, **args: str) -> str:
            return _call(tool, **args) if tool in tools else _reply(DENIED_REPLY)

        imperative = re.match(r"\s*(isolate|unisolate|close|acknowledge|comment|delete|block)\b", question)
        if imperative:
            return _reply("I can't take actions. Use the button on the incident, or the matching slash command.")
        if "audit" in question or "who asked" in question:
            return use("recent_audit")
        if "isolat" in question:
            return use("isolation_preview", host=host.group(1)) if host else _reply("Tell me which host.")
        if ip:
            return use("enrich_ip", ip=ip.group(0))
        if any(w in question for w in ("command", " ran", "run on", "executed", "last hour")):
            return use("run_hunt", template="host_commands", window="1h", target=host.group(1)) if host else _reply("Tell me which host.")
        if "failed" in question and "ssh" in question:
            return use("run_hunt", template="ssh_failures", window="24h")
        if "incident" in question and number and any(w in question for w in ("detail", "real", "true", "false", "host", "why")):
            return use("get_incident", incident=number.group(1))
        if "incident" in question and number:
            return use("incident_summary", incident=number.group(1))
        if any(w in question for w in ("how many", "count", "open")):
            return use("incident_counts")
        if any(w in question for w in ("list", "recent", "latest", "show")):
            return use("list_incidents", status="open")
        return _reply("(mock) I can answer questions about incidents, counts, hosts, commands and detections.")

    @staticmethod
    def _between(text: str, start: str, end: str) -> str:
        i, j = text.find(start), text.find(end)
        return text[i + len(start) : j] if i != -1 and j > i else ""
