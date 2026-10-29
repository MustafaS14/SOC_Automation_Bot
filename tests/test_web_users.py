import pytest

from soc_bot.config import ConfigError
from soc_bot.rbac import Permission
from soc_web.config import WebSettings
from soc_web.security import Throttle
from soc_web.users import UserError, UserStore

GOOD = "correct horse battery"


@pytest.fixture
def users():
    store = UserStore(":memory:", max_failed=3, lockout_minutes=15)
    yield store
    store.close()


def test_create_and_authenticate(users):
    user = users.create("Alice", GOOD, "triage")
    assert user.username == "alice" and user.tier is Permission.TRIAGE
    assert users.authenticate("ALICE", GOOD).id == user.id
    assert users.authenticate("alice", "wrong wrong wrong") is None
    assert users.authenticate("bob", GOOD) is None


def test_password_is_stored_hashed(users):
    users.create("alice", GOOD, "read")
    stored = users._db.execute("SELECT password_hash FROM users").fetchone()[0]
    assert GOOD not in stored and stored.startswith(("scrypt:", "pbkdf2:"))


@pytest.mark.parametrize("name", ["ab", "has space", "UPPER!", "../x", "a" * 40, "-lead"])
def test_bad_usernames_rejected(users, name):
    with pytest.raises(UserError):
        users.create(name, GOOD, "read")


def test_short_password_and_unknown_tier_and_duplicates(users):
    with pytest.raises(UserError, match="at least"):
        users.create("alice", "short", "read")
    with pytest.raises(UserError, match="Unknown tier"):
        users.create("alice", GOOD, "root")
    users.create("alice", GOOD, "read")
    with pytest.raises(UserError, match="already exists"):
        users.create("alice", GOOD, "read")


def test_lockout_after_max_failures_then_right_password_still_refused(users):
    users.create("alice", GOOD, "read")
    for _ in range(3):
        assert users.authenticate("alice", "wrong wrong wrong") is None
    assert users.authenticate("alice", GOOD) is None


def test_success_resets_failure_count(users):
    users.create("alice", GOOD, "read")
    users.authenticate("alice", "wrong wrong wrong")
    users.authenticate("alice", "wrong wrong wrong")
    assert users.authenticate("alice", GOOD) is not None
    users.authenticate("alice", "wrong wrong wrong")
    users.authenticate("alice", "wrong wrong wrong")
    assert users.authenticate("alice", GOOD) is not None  # two since the reset, below the limit of three


def test_password_reset_clears_lock(users):
    users.create("alice", GOOD, "read")
    for _ in range(3):
        users.authenticate("alice", "wrong wrong wrong")
    users.set_password("alice", "another long passphrase")
    assert users.authenticate("alice", "another long passphrase") is not None


def test_disabled_user_cannot_sign_in_and_can_be_re_enabled(users):
    users.create("alice", GOOD, "read")
    users.set_active("alice", False)
    assert users.authenticate("alice", GOOD) is None
    users.set_active("alice", True)
    assert users.authenticate("alice", GOOD) is not None


def test_set_tier_and_missing_user(users):
    users.create("alice", GOOD, "read")
    users.set_tier("alice", "admin")
    assert users.authenticate("alice", GOOD).tier is Permission.ADMIN
    with pytest.raises(UserError, match="No user"):
        users.set_tier("ghost", "read")
    with pytest.raises(UserError, match="Unknown tier"):
        users.set_tier("alice", "god")


def test_throttle_window():
    now = [0.0]
    throttle = Throttle(2, 10, clock=lambda: now[0])
    assert throttle.allow("a") and throttle.allow("a") and not throttle.allow("a")
    assert throttle.allow("b")  # keys are independent
    now[0] = 11
    assert throttle.allow("a")


def test_web_settings_validation(monkeypatch):
    with pytest.raises(ConfigError, match="32 characters"):
        WebSettings(secret_key="short").validate()
    with pytest.raises(ConfigError, match="PORT"):
        WebSettings(secret_key="k" * 40, port=0).validate()
    monkeypatch.delenv("SOC_WEB_SECRET_KEY", raising=False)
    monkeypatch.setattr("soc_web.config.load_dotenv", lambda: None)
    with pytest.raises(ConfigError):
        WebSettings.from_env()  # a real deployment must set its own key
    assert len(WebSettings.from_env(mock_mode=True).secret_key) >= 32  # mock mode makes a throwaway one
    assert WebSettings(secret_key="k" * 40).secure_cookies is True  # Secure cookies unless switched off


def test_settings_can_skip_discord_requirements():
    from soc_bot.config import Settings

    base = dict(
        discord_token="", guild_id=None, allowed_channel_ids=frozenset(), audit_channel_id=None,
        read_role_ids=frozenset(), triage_role_ids=frozenset(), response_role_ids=frozenset(),
        isolation_denylist=(), mock_mode=True,
    )
    Settings(**base).validate(require_discord=False)
    with pytest.raises(ConfigError):
        Settings(**base).validate()
    # The alert webhook belongs to the bot, so a real (non-mock) console does not need its secret either.
    real = {**base, "mock_mode": False}
    Settings(**real).validate(require_discord=False)
    with pytest.raises(ConfigError, match="WEBHOOK_SECRET"):
        Settings(**{**real, "discord_token": "t", "allowed_channel_ids": frozenset({1}),
                    "read_role_ids": frozenset({1})}).validate()
