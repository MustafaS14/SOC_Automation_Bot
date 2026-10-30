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


def test_viewer_or_admin_roles_alone_are_enough():
    Settings(**{**BASE, "read_role_ids": frozenset(), "viewer_role_ids": frozenset({7})}).validate()
    Settings(**{**BASE, "read_role_ids": frozenset(), "admin_role_ids": frozenset({8})}).validate()


def test_ai_backend_must_be_known_and_mock_needs_mock_mode():
    Settings(**{**BASE, "ai_backend": "claude_code"}).validate()
    with pytest.raises(ConfigError, match="AI_BACKEND"):
        Settings(**{**BASE, "ai_backend": "gpt"}).validate()
    with pytest.raises(ConfigError, match="SOC_BOT_MOCK"):
        Settings(**{**BASE, "ai_backend": "mock"}).validate()
    Settings(**{**BASE, "ai_backend": "mock", "mock_mode": True}).validate()


def test_ai_limits_must_be_sane():
    with pytest.raises(ConfigError, match="AI_"):
        Settings(**{**BASE, "ai_daily_calls": 0}).validate()
    with pytest.raises(ConfigError, match="AI_TIMEOUT"):
        Settings(**{**BASE, "ai_timeout": 1.0}).validate()


def test_ai_defaults_are_off(monkeypatch):
    monkeypatch.setenv("DISCORD_TOKEN", "t")
    monkeypatch.setenv("ALLOWED_CHANNEL_IDS", "1")
    monkeypatch.setenv("RBAC_VIEWER_ROLE_IDS", "7")
    monkeypatch.setenv("WEBHOOK_SECRET", "s")
    for name in ("AI_BACKEND", "SOC_BOT_MOCK"):
        monkeypatch.delenv(name, raising=False)
    assert Settings.from_env().ai_backend == "off"
    monkeypatch.setenv("SOC_BOT_MOCK", "true")
    assert Settings.from_env().ai_backend == "mock"


def test_unresolved_1password_reference_is_refused(monkeypatch):
    from soc_bot.config import reject_unresolved_references

    monkeypatch.setenv("DISCORD_TOKEN", "op://SOC-Lab/discord/token")
    monkeypatch.setenv("SPLUNK_TOKEN", "  op://SOC-Lab/splunk/token")
    with pytest.raises(ConfigError) as exc:
        reject_unresolved_references()
    message = str(exc.value)
    assert "DISCORD_TOKEN" in message and "SPLUNK_TOKEN" in message and "op run" in message
    assert "SOC-Lab" not in message  # names the variables, never echoes the references


def test_real_values_pass_the_reference_check(monkeypatch):
    from soc_bot.config import reject_unresolved_references

    monkeypatch.setenv("DISCORD_TOKEN", "a-real-looking-token")
    reject_unresolved_references()  # no error


def test_secret_reads_the_environment_first(monkeypatch, tmp_path):
    from soc_bot.config import secret

    (tmp_path / "discord_token").write_text("from-the-file\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("DISCORD_TOKEN", " from-the-environment ")
    assert secret("DISCORD_TOKEN") == "from-the-environment"


def test_secret_falls_back_to_a_systemd_credential_and_stays_out_of_the_environment(monkeypatch, tmp_path):
    import os

    from soc_bot.config import secret

    (tmp_path / "discord_token").write_text("from-the-file\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.delenv("DISCORD_TOKEN", raising=False)
    assert secret("DISCORD_TOKEN") == "from-the-file"
    assert "DISCORD_TOKEN" not in os.environ


def test_secret_is_empty_when_nothing_provides_it(monkeypatch, tmp_path):
    from soc_bot.config import secret

    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    assert secret("SPLUNK_TOKEN") == ""
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))  # directory without the file
    assert secret("SPLUNK_TOKEN") == ""
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "missing"))
    assert secret("SPLUNK_TOKEN") == ""


def test_secret_never_reads_outside_the_credentials_directory(monkeypatch, tmp_path):
    from soc_bot.config import secret

    (tmp_path / "outside").write_text("stolen")
    inner = tmp_path / "creds"
    inner.mkdir()
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(inner))
    assert secret("../OUTSIDE") == "" and secret("sub/x") == ""


def test_settings_use_credentials_for_every_secret(monkeypatch, tmp_path):
    from soc_web.config import WebSettings

    (tmp_path / "soc_web_secret_key").write_text("k" * 40)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.delenv("SOC_WEB_SECRET_KEY", raising=False)
    assert WebSettings.from_env().secret_key == "k" * 40
