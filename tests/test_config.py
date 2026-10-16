import pytest

from soc_bot.config import ConfigError, Settings

BASE = dict(
    discord_token="t", guild_id=None, allowed_channel_ids=frozenset({1}), audit_channel_id=None,
    read_role_ids=frozenset({1}), triage_role_ids=frozenset(), response_role_ids=frozenset(),
    isolation_denylist=(), mock_mode=False, webhook_secret="s",
)


def test_valid_minimal_config():
    Settings(**BASE).validate()


def test_refuses_to_start_without_channels_or_roles():
    with pytest.raises(ConfigError, match="channels"):
        Settings(**{**BASE, "allowed_channel_ids": frozenset()}).validate()
    with pytest.raises(ConfigError, match="RBAC"):
        Settings(**{**BASE, "read_role_ids": frozenset()}).validate()


def test_webhook_secret_required_outside_mock_mode():
    with pytest.raises(ConfigError, match="WEBHOOK_SECRET"):
        Settings(**{**BASE, "webhook_secret": ""}).validate()
    Settings(**{**BASE, "webhook_secret": "", "mock_mode": True}).validate()


def test_half_configured_backends_are_rejected():
    with pytest.raises(ConfigError, match="SPLUNK_TOKEN"):
        Settings(**{**BASE, "splunk_url": "https://x:8089"}).validate()
    with pytest.raises(ConfigError, match="RESPONDER_SSH_KEY"):
        Settings(**{**BASE, "responder_hosts": {"h": "10.0.0.1"}}).validate()


def test_responder_hosts_parsing(monkeypatch):
    from soc_bot.config import _host_map

    monkeypatch.setenv("RESPONDER_HOSTS", "Soc-Victim=192.168.56.20, b=10.0.0.2")
    assert _host_map("RESPONDER_HOSTS") == {"soc-victim": "192.168.56.20", "b": "10.0.0.2"}
    monkeypatch.setenv("RESPONDER_HOSTS", "soc-victim=notanip")
    with pytest.raises(ConfigError):
        _host_map("RESPONDER_HOSTS")
