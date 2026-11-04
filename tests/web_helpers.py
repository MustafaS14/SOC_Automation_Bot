"""A real web app on mock backends, with one account per tier."""

from __future__ import annotations

import re

import pytest

from soc_bot.config import Settings
from soc_web.app import create_app
from soc_web.config import WebSettings
from soc_web.runtime import AsyncRunner, build_backends
from soc_web.users import UserStore

PASSWORD = "correct horse battery"
TIER_NAMES = ("viewer", "read", "triage", "admin")


@pytest.fixture
def stack(tmp_path):
    settings = Settings(
        discord_token="", guild_id=None, allowed_channel_ids=frozenset(), audit_channel_id=None,
        read_role_ids=frozenset(), triage_role_ids=frozenset(), response_role_ids=frozenset(),
        isolation_denylist=(), mock_mode=True, ai_backend="mock",
        audit_log_path=str(tmp_path / "audit.jsonl"),
    )
    web = WebSettings(secret_key="k" * 40, secure_cookies=False, max_failed_logins=3)
    runner = AsyncRunner()
    backends = build_backends(settings, runner)
    users = UserStore(":memory:", max_failed=3, lockout_minutes=15)
    for tier in TIER_NAMES:
        users.create(tier, PASSWORD, tier)
    app = create_app(web, backends, users)
    app.config["TESTING"] = False  # keep real error handling, so 500 pages are exercised
    yield app, backends, users
    backends.close()
    runner.close()
    users.close()


def token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token in page"
    return match.group(1)


def login(app, username: str = "triage", password: str = PASSWORD):
    client = app.test_client()
    page = client.get("/login").get_data(as_text=True)
    resp = client.post("/login", data={"username": username, "password": password, "csrf_token": token(page)})
    return client, resp


def post(client, path: str, page_path: str, **data):
    """POST with a CSRF token taken from `page_path`, the page whose form would send it."""
    html = client.get(page_path).get_data(as_text=True)
    return client.post(path, data={"csrf_token": token(html), **data})
