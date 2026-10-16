"""Input validation for anything typed into chat before it reaches an API."""

from __future__ import annotations

import fnmatch
import ipaddress
import re

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$")


class ValidationError(ValueError):
    pass


def _shown(value: str) -> str:
    """Truncate and strip characters that could break the Discord markdown the value is echoed in."""
    return "".join(c for c in value[:64] if c.isprintable() and c not in "`*_~|<>@")


def parse_incident_ref(value: str) -> int:
    """Accept an incident number such as ``1042`` or ``#1042``."""
    value = value.strip().lstrip("#")
    # isdigit() also accepts characters like '²' that int() rejects, so require ASCII.
    if not (value.isascii() and value.isdigit()) or len(value) > 9 or int(value) <= 0:
        raise ValidationError(f"`{_shown(value)}` is not a valid incident number.")
    return int(value)


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"`{_shown(value)}` is not a valid IPv4/IPv6 address.") from exc


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_global and not ip.is_multicast


def parse_hostname(value: str) -> str:
    value = value.strip().lower()
    if not _HOSTNAME_RE.match(value):
        raise ValidationError(f"`{_shown(value)}` is not a valid hostname.")
    return value


def is_protected_host(hostname: str, denylist: tuple[str, ...]) -> bool:
    short = hostname.split(".", 1)[0]
    return any(
        fnmatch.fnmatch(hostname, pattern) or fnmatch.fnmatch(short, pattern) for pattern in denylist
    )
