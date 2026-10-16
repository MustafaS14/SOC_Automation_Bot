from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    pass


def _bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int_or_none(name: str) -> int | None:
    value = os.getenv(name, "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer ID") from exc


def _id_set(name: str) -> frozenset[int]:
    raw = os.getenv(name, "")
    try:
        return frozenset(int(part) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a comma-separated list of integer IDs") from exc


def _str_list(name: str) -> tuple[str, ...]:
    return tuple(p.strip().lower() for p in os.getenv(name, "").split(",") if p.strip())


def _host_map(name: str) -> dict[str, str]:
    hosts: dict[str, str] = {}
    for part in os.getenv(name, "").split(","):
        if not part.strip():
            continue
        host, _, address = part.partition("=")
        host = host.strip().lower()
        try:
            if not host:
                raise ValueError(host)
            hosts[host] = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ConfigError(f"{name} must look like host=ip,host=ip") from exc
    return hosts


@dataclass(frozen=True)
class Settings:
    discord_token: str = field(repr=False)
    guild_id: int | None
    allowed_channel_ids: frozenset[int]
    audit_channel_id: int | None
    read_role_ids: frozenset[int]
    triage_role_ids: frozenset[int]
    response_role_ids: frozenset[int]
    isolation_denylist: tuple[str, ...]
    mock_mode: bool
    alert_channel_id: int | None = None
    db_path: str = "incidents.db"
    webhook_host: str = "127.0.0.1"
    webhook_port: int = 8765
    webhook_secret: str = field(default="", repr=False)
    webhook_rate_limit: int = 30
    splunk_url: str = ""
    splunk_token: str = field(default="", repr=False)
    splunk_verify_tls: bool = True
    splunk_hec_url: str = ""
    splunk_hec_token: str = field(default="", repr=False)
    responder_user: str = "responder"
    responder_ssh_key: str = ""
    responder_known_hosts: str = ""
    responder_hosts: dict[str, str] = field(default_factory=dict)
    abuseipdb_api_key: str | None = field(default=None, repr=False)
    virustotal_api_key: str | None = field(default=None, repr=False)
    audit_log_path: str = "audit.jsonl"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        settings = cls(
            discord_token=os.getenv("DISCORD_TOKEN", "").strip(),
            guild_id=_int_or_none("DISCORD_GUILD_ID"),
            allowed_channel_ids=_id_set("ALLOWED_CHANNEL_IDS"),
            audit_channel_id=_int_or_none("AUDIT_CHANNEL_ID"),
            read_role_ids=_id_set("RBAC_READ_ROLE_IDS"),
            triage_role_ids=_id_set("RBAC_TRIAGE_ROLE_IDS"),
            response_role_ids=_id_set("RBAC_RESPONSE_ROLE_IDS"),
            isolation_denylist=_str_list("ISOLATION_DENYLIST"),
            mock_mode=_bool(os.getenv("SOC_BOT_MOCK")),
            alert_channel_id=_int_or_none("ALERT_CHANNEL_ID"),
            db_path=os.getenv("DB_PATH", "incidents.db").strip(),
            webhook_host=os.getenv("WEBHOOK_HOST", "127.0.0.1").strip(),
            webhook_port=_int_or_none("WEBHOOK_PORT") or 8765,
            webhook_secret=os.getenv("WEBHOOK_SECRET", "").strip(),
            webhook_rate_limit=_int_or_none("WEBHOOK_RATE_LIMIT") or 30,
            splunk_url=os.getenv("SPLUNK_URL", "").strip().rstrip("/"),
            splunk_token=os.getenv("SPLUNK_TOKEN", "").strip(),
            splunk_verify_tls=_bool(os.getenv("SPLUNK_VERIFY_TLS", "true")),
            splunk_hec_url=os.getenv("SPLUNK_HEC_URL", "").strip(),
            splunk_hec_token=os.getenv("SPLUNK_HEC_TOKEN", "").strip(),
            responder_user=os.getenv("RESPONDER_USER", "responder").strip(),
            responder_ssh_key=os.getenv("RESPONDER_SSH_KEY", "").strip(),
            responder_known_hosts=os.getenv("RESPONDER_KNOWN_HOSTS", "").strip(),
            responder_hosts=_host_map("RESPONDER_HOSTS"),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip() or None,
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip() or None,
            audit_log_path=os.getenv("AUDIT_LOG_PATH", "audit.jsonl"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        missing = []
        if not self.discord_token:
            missing.append("DISCORD_TOKEN")
        if not self.mock_mode and not self.webhook_secret:
            missing.append("WEBHOOK_SECRET")
        # Each backend is optional, but a half-configured one is an error.
        pairs = (
            (("SPLUNK_URL", "SPLUNK_TOKEN"), (self.splunk_url, self.splunk_token)),
            (("SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"), (self.splunk_hec_url, self.splunk_hec_token)),
            (("RESPONDER_HOSTS", "RESPONDER_SSH_KEY"), (self.responder_hosts, self.responder_ssh_key)),
        )
        if not self.mock_mode:
            for names, values in pairs:
                if any(values) and not all(values):
                    missing.extend(n for n, v in zip(names, values) if not v)
        if missing:
            raise ConfigError("Missing required settings: " + ", ".join(missing))
        if self.webhook_rate_limit < 1:
            raise ConfigError("WEBHOOK_RATE_LIMIT must be at least 1.")
        if not (self.read_role_ids or self.triage_role_ids or self.response_role_ids):
            raise ConfigError(
                "No RBAC roles configured. Set RBAC_READ_ROLE_IDS / RBAC_TRIAGE_ROLE_IDS / "
                "RBAC_RESPONSE_ROLE_IDS so the bot is not open to everyone."
            )
        if not self.allowed_channel_ids:
            raise ConfigError(
                "No channels configured. Set ALLOWED_CHANNEL_IDS so commands are not accepted everywhere."
            )
