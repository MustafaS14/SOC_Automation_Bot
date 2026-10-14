"""Input validation for anything typed into chat before it reaches an API."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import uuid

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$")


class ValidationError(ValueError):
    pass


def parse_incident_ref(value: str) -> int | str:
    """Accept either a Sentinel incident number (e.g. ``1042``) or incident GUID."""
    value = value.strip().lstrip("#")
    if value.isdigit():
        number = int(value)
        if number <= 0:
            raise ValidationError("Incident number must be positive.")
        return number
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValidationError(
            f"`{value[:64]}` is not a valid incident number or incident ID (GUID)."
        ) from exc


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"`{value[:64]}` is not a valid IPv4/IPv6 address.") from exc


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_global and not ip.is_multicast


def parse_hostname(value: str) -> str:
    value = value.strip().lower()
    if not _HOSTNAME_RE.match(value):
        raise ValidationError(f"`{value[:64]}` is not a valid hostname.")
    return value


def is_protected_host(hostname: str, denylist: tuple[str, ...]) -> bool:
    short = hostname.split(".", 1)[0]
    return any(
        fnmatch.fnmatch(hostname, pattern) or fnmatch.fnmatch(short, pattern) for pattern in denylist
    )
