from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from dotenv import load_dotenv

from soc_bot.config import ConfigError, _bool, _int_default


LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
WILDCARD_HOSTS = ("", "0.0.0.0", "::")


def default_hosts(bind_host: str, configured: str) -> tuple[str, ...]:
    """The accepted Host names: the configured list, else loopback plus the address it listens on (any, if it listens on all)."""
    names = tuple(h.strip().lower() for h in configured.split(",") if h.strip())
    if names:
        return names
    if bind_host in WILDCARD_HOSTS:
        return ()
    return tuple(dict.fromkeys((*LOOPBACK_HOSTS, bind_host.lower())))


@dataclass(frozen=True)
class WebSettings:
    secret_key: str = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 8000
    users_db: str = "web_users.db"
    session_hours: int = 8
    # Cookies are marked Secure by default, so a plain-HTTP lab address needs SOC_WEB_SECURE_COOKIES=false.
    secure_cookies: bool = True
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    # Host names the console answers to (a Host header outside the list is refused). Empty means any, which is only
    # the default when it listens on every address and no list was given.
    allowed_hosts: tuple[str, ...] = ()
    # How many reverse proxies sit in front. 0 means none, so X-Forwarded-* headers are ignored and cannot be forged.
    trusted_proxies: int = 0

    @classmethod
    def from_env(cls, *, mock_mode: bool = False) -> WebSettings:
        load_dotenv()
        key = os.getenv("SOC_WEB_SECRET_KEY", "").strip()
        if not key and mock_mode:
            key = secrets.token_hex(32)  # demo only: sessions end when the process restarts
        host = os.getenv("SOC_WEB_HOST", "127.0.0.1").strip()
        settings = cls(
            secret_key=key,
            host=host,
            port=_int_default("SOC_WEB_PORT", 8000),
            users_db=os.getenv("SOC_WEB_USERS_DB", "web_users.db").strip(),
            session_hours=_int_default("SOC_WEB_SESSION_HOURS", 8),
            secure_cookies=_bool(os.getenv("SOC_WEB_SECURE_COOKIES", "true")),
            max_failed_logins=_int_default("SOC_WEB_MAX_FAILED_LOGINS", 5),
            lockout_minutes=_int_default("SOC_WEB_LOCKOUT_MINUTES", 15),
            allowed_hosts=default_hosts(host, os.getenv("SOC_WEB_ALLOWED_HOSTS", "")),
            trusted_proxies=_int_default("SOC_WEB_TRUSTED_PROXIES", 0),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if len(self.secret_key) < 32:
            raise ConfigError(
                "SOC_WEB_SECRET_KEY must be at least 32 characters. Generate one with: "
                'python -c "import secrets; print(secrets.token_hex(32))"'
            )
        if not 1 <= self.port <= 65535:
            raise ConfigError("SOC_WEB_PORT must be between 1 and 65535.")
        if not 0 <= self.trusted_proxies <= 5:
            raise ConfigError("SOC_WEB_TRUSTED_PROXIES must be between 0 and 5.")
        if min(self.session_hours, self.max_failed_logins, self.lockout_minutes) < 1:
            raise ConfigError(
                "SOC_WEB_SESSION_HOURS, SOC_WEB_MAX_FAILED_LOGINS and SOC_WEB_LOCKOUT_MINUTES must be at least 1."
            )
