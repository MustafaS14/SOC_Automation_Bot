from __future__ import annotations

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


@dataclass(frozen=True)
class Settings:
    discord_token: str
    guild_id: int | None
    allowed_channel_ids: frozenset[int]
    audit_channel_id: int | None
    read_role_ids: frozenset[int]
    triage_role_ids: frozenset[int]
    response_role_ids: frozenset[int]
    isolation_denylist: tuple[str, ...]
    mock_mode: bool
    subscription_id: str = ""
    resource_group: str = ""
    workspace_name: str = ""
    sentinel_api_version: str = "2024-03-01"
    defender_api_base: str = "https://api.securitycenter.microsoft.com"
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
            subscription_id=os.getenv("SENTINEL_SUBSCRIPTION_ID", "").strip(),
            resource_group=os.getenv("SENTINEL_RESOURCE_GROUP", "").strip(),
            workspace_name=os.getenv("SENTINEL_WORKSPACE_NAME", "").strip(),
            sentinel_api_version=os.getenv("SENTINEL_API_VERSION", "2024-03-01").strip(),
            defender_api_base=os.getenv(
                "DEFENDER_API_BASE", "https://api.securitycenter.microsoft.com"
            ).strip().rstrip("/"),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
            audit_log_path=os.getenv("AUDIT_LOG_PATH", "audit.jsonl"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        missing = []
        if not self.discord_token:
            missing.append("DISCORD_TOKEN")
        if not self.mock_mode:
            for name, value in (
                ("SENTINEL_SUBSCRIPTION_ID", self.subscription_id),
                ("SENTINEL_RESOURCE_GROUP", self.resource_group),
                ("SENTINEL_WORKSPACE_NAME", self.workspace_name),
            ):
                if not value:
                    missing.append(name)
        if missing:
            raise ConfigError("Missing required settings: " + ", ".join(missing))
        if not (self.read_role_ids or self.triage_role_ids or self.response_role_ids):
            raise ConfigError(
                "No RBAC roles configured. Set RBAC_READ_ROLE_IDS / RBAC_TRIAGE_ROLE_IDS / "
                "RBAC_RESPONSE_ROLE_IDS so the bot is not open to everyone."
            )
