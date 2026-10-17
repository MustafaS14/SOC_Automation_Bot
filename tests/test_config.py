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


def test_secrets_are_not_in_repr():
    text = repr(Settings(**{**BASE, "discord_token": "TOKEN123", "webhook_secret": "SECRET123",
                            "splunk_token": "SPL123", "splunk_hec_token": "HEC123",
                            "abuseipdb_api_key": "ABUSE123", "virustotal_api_key": "VT123"}))
    for secret in ("TOKEN123", "SECRET123", "SPL123", "HEC123", "ABUSE123", "VT123"):
        assert secret not in text


def test_token_required_even_in_mock_mode():
    # Mock mode still connects to Discord; tests build Settings directly and skip validate().
    with pytest.raises(ConfigError, match="DISCORD_TOKEN"):
        Settings(**{**BASE, "discord_token": "", "mock_mode": True}).validate()


def test_rate_limit_must_be_positive():
    with pytest.raises(ConfigError, match="WEBHOOK_RATE_LIMIT"):
        Settings(**{**BASE, "webhook_rate_limit": 0}).validate()


def test_from_env_strips_keys_and_defaults_to_loopback(monkeypatch):
    monkeypatch.setattr("soc_bot.config.load_dotenv", lambda: None)
    env = {
        "DISCORD_TOKEN": " tok ", "ALLOWED_CHANNEL_IDS": "1", "RBAC_READ_ROLE_IDS": "2",
        "WEBHOOK_SECRET": " s ", "ABUSEIPDB_API_KEY": "  abuse  ", "VIRUSTOTAL_API_KEY": "   ",
    }
    for name in ("WEBHOOK_HOST", "WEBHOOK_RATE_LIMIT", "SOC_BOT_MOCK", "SPLUNK_URL", "SPLUNK_TOKEN",
                 "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN", "RESPONDER_HOSTS", "RESPONDER_SSH_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    settings = Settings.from_env()
    assert settings.discord_token == "tok" and settings.webhook_secret == "s"
    assert settings.abuseipdb_api_key == "abuse" and settings.virustotal_api_key is None
    assert settings.webhook_host == "127.0.0.1" and settings.webhook_rate_limit == 30
    assert settings.webhook_port == 8765


def _from_env(monkeypatch, **extra):
    monkeypatch.setattr("soc_bot.config.load_dotenv", lambda: None)
    env = {"DISCORD_TOKEN": "t", "ALLOWED_CHANNEL_IDS": "1", "RBAC_READ_ROLE_IDS": "2", "WEBHOOK_SECRET": "s"}
    for name in ("WEBHOOK_PORT", "WEBHOOK_RATE_LIMIT", "SOC_BOT_MOCK", "SPLUNK_URL", "SPLUNK_TOKEN",
                 "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN", "RESPONDER_HOSTS", "RESPONDER_SSH_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {**env, **extra}.items():
        monkeypatch.setenv(name, value)
    return Settings.from_env()


@pytest.mark.parametrize("name", ["WEBHOOK_RATE_LIMIT", "WEBHOOK_PORT"])
def test_explicit_zero_is_rejected_not_replaced_by_the_default(monkeypatch, name):
    with pytest.raises(ConfigError, match=name):
        _from_env(monkeypatch, **{name: "0"})


def test_explicit_values_are_kept(monkeypatch):
    settings = _from_env(monkeypatch, WEBHOOK_PORT="9000", WEBHOOK_RATE_LIMIT="5")
    assert (settings.webhook_port, settings.webhook_rate_limit) == (9000, 5)


def test_port_out_of_range_is_rejected():
    with pytest.raises(ConfigError, match="WEBHOOK_PORT"):
        Settings(**{**BASE, "webhook_port": 70000}).validate()


@pytest.mark.parametrize(
    "extra, name",
    [
        ({"splunk_url": "https://s:8089", "splunk_token": "t"}, "SPLUNK_URL"),
        ({"splunk_hec_url": "https://s:8088", "splunk_hec_token": "t"}, "SPLUNK_HEC_URL"),
        ({"responder_hosts": {"h": "10.0.0.1"}, "responder_ssh_key": "k"}, "RESPONDER_HOSTS"),
        ({"splunk_token": "t"}, "SPLUNK_TOKEN"),
    ],
)
def test_mock_mode_refuses_to_run_beside_real_backend_settings(extra, name):
    with pytest.raises(ConfigError, match=f"SOC_BOT_MOCK.*{name}"):
        Settings(**{**BASE, "mock_mode": True, **extra}).validate()


def test_mock_mode_alone_is_fine():
    Settings(**{**BASE, "mock_mode": True, "webhook_secret": ""}).validate()


def test_alert_link_hosts_come_from_splunk_url_and_the_explicit_list():
    assert Settings(**BASE).alert_link_hosts == frozenset()
    from_url = Settings(**{**BASE, "splunk_url": "https://Splunk.Lab:8089", "splunk_token": "t"})
    assert from_url.alert_link_hosts == frozenset({"splunk.lab"})  # the management port is ignored
    both = Settings(**{**BASE, "splunk_url": "https://splunk.lab:8089", "splunk_token": "t",
                       "webhook_link_hosts": ("192.168.56.10",)})
    assert both.alert_link_hosts == frozenset({"splunk.lab", "192.168.56.10"})
    only_list = Settings(**{**BASE, "webhook_link_hosts": ("splunk.lab",)})
    assert only_list.alert_link_hosts == frozenset({"splunk.lab"})


@pytest.mark.parametrize("entry", ["https://splunk.lab", "splunk.lab:8000", "splunk.lab/app", "a b"])
def test_link_hosts_must_be_bare_hostnames(entry):
    with pytest.raises(ConfigError, match="WEBHOOK_LINK_HOSTS"):
        Settings(**{**BASE, "webhook_link_hosts": (entry,)}).validate()


def test_link_hosts_are_parsed_and_lowercased_from_env(monkeypatch):
    settings = _from_env(monkeypatch, WEBHOOK_LINK_HOSTS=" Splunk.Lab , 192.168.56.10 ")
    assert settings.webhook_link_hosts == ("splunk.lab", "192.168.56.10")
