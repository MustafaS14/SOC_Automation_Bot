"""Predefined read-only SPL searches. Chat input only fills validated parameters, never SPL."""

from __future__ import annotations

from dataclasses import dataclass

from .validators import ValidationError, parse_hostname, parse_ip

WINDOWS = {"15m": "Last 15 minutes", "1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days"}


@dataclass(frozen=True)
class Hunt:
    label: str
    spl: str
    param: str | None  # "host", "ip" or None; fills {target}


# Assumes events land in index=linux; adjust once the Logstash pipeline is built.
HUNTS = {
    "host_commands": Hunt(
        "Commands executed on a host (auditd)",
        'search index=linux host="{target}" exec_cmd | table _time host _raw | head 20',
        "host",
    ),
    "ip_activity": Hunt(
        "Events mentioning an IP",
        'search index=linux "{target}" | table _time host _raw | head 20',
        "ip",
    ),
    "ssh_failures": Hunt(
        "Failed SSH logins by host",
        'search index=linux "Failed password" | stats count by host | sort - count | head 20',
        None,
    ),
}


def build(name: str, window: str, target: str | None) -> tuple[str, str]:
    """Return (spl, earliest) for a template, rejecting anything outside the allow-lists."""
    hunt = HUNTS.get(name)
    if hunt is None or window not in WINDOWS:
        raise ValidationError("Unknown hunt template or time window.")
    if hunt.param is None:
        return hunt.spl, f"-{window}"
    if not target:
        raise ValidationError(f"This hunt needs a {hunt.param} as the target.")
    value = parse_hostname(target) if hunt.param == "host" else str(parse_ip(target))
    return hunt.spl.format(target=value), f"-{window}"
