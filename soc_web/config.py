from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from dotenv import load_dotenv

from soc_bot.config import ConfigError, _bool, _int_default


@dataclass(frozen=True)
class WebSettings:
    secret_key: str = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 8080
    users_db: str = "web_users.db"
    session_hours: int = 8
    # Cookies are marked Secure by default, so a plain-HTTP lab address needs SOC_WEB_SECURE_COOKIES=false.
    secure_cookies: bool = True
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    @classmethod
    def from_env(cls, *, mock_mode: bool = False) -> WebSettings:
        load_dotenv()
        key = os.getenv("SOC_WEB_SECRET_KEY", "").strip()
        if not key and mock_mode:
            key = secrets.token_hex(32)  # demo only: sessions end when the process restarts
        settings = cls(
            secret_key=key,
            host=os.getenv("SOC_WEB_HOST", "127.0.0.1").strip(),
            port=_int_default("SOC_WEB_PORT", 8080),
            users_db=os.getenv("SOC_WEB_USERS_DB", "web_users.db").strip(),
            session_hours=_int_default("SOC_WEB_SESSION_HOURS", 8),
            secure_cookies=_bool(os.getenv("SOC_WEB_SECURE_COOKIES", "true")),
            max_failed_logins=_int_default("SOC_WEB_MAX_FAILED_LOGINS", 5),
            lockout_minutes=_int_default("SOC_WEB_LOCKOUT_MINUTES", 15),
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
        if min(self.session_hours, self.max_failed_logins, self.lockout_minutes) < 1:
            raise ConfigError(
                "SOC_WEB_SESSION_HOURS, SOC_WEB_MAX_FAILED_LOGINS and SOC_WEB_LOCKOUT_MINUTES must be at least 1."
            )
