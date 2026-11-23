from __future__ import annotations

import argparse
import asyncio
import logging
import re
import sys
from collections.abc import Sequence
from datetime import timedelta

from .config import ConfigError, Settings

_AGE_RE = re.compile(r"^(\d+)([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_age(text: str) -> timedelta:
    """'90m', '24h' or '7d' as a timedelta. Zero and anything else is an error."""
    match = _AGE_RE.match(text.strip().lower())
    if not match or int(match.group(1)) == 0:
        raise argparse.ArgumentTypeError("use a positive age such as 90m, 24h or 7d")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m soc_bot", description="SOC bot. With no command it runs the bot.")
    sub = parser.add_subparsers(dest="command")
    stale = sub.add_parser(
        "close-stale",
        help="close incidents nobody has touched for a while, as benign",
        description="Close incidents with no activity for --older-than. Only New incidents unless --include-active. "
        "Every run is written to the audit log. Run it from the bot's folder so it finds the same database.",
    )
    stale.add_argument("--older-than", default="24h", metavar="AGE", help="90m, 24h or 7d (default 24h)")
    stale.add_argument("--include-active", action="store_true", help="also close incidents an analyst has acknowledged")
    stale.add_argument("--dry-run", action="store_true", help="only list what would be closed")
    return parser


def close_stale(older_than: timedelta, *, include_active: bool, dry_run: bool, label: str) -> int:
    try:
        settings = Settings.from_env(require_discord=False)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    from .audit import AuditLogger
    from .store import IncidentStore

    store = IncidentStore(settings.db_path)
    audit = AuditLogger(settings.audit_log_path)
    try:
        found = asyncio.run(store.close_stale(older_than, include_active=include_active, dry_run=dry_run, label=label))
        verb = "Would close" if dry_run else "Closed"
        for inc in found:
            print(f"  #{inc.id} {inc.severity:<13} {inc.status:<7} {inc.host or '-':<12} {inc.rule}")
        print(f"{verb} {len(found)} incident(s) with no activity for {label}.")
        audit.record(
            actor="cli", actor_id=0, action="close-stale", target=f"{len(found)} incident(s)",
            outcome="dry-run" if dry_run else "success", older_than=label, include_active=include_active,
            ids=[inc.id for inc in found],
        )
    finally:
        audit.close()
        store.shutdown()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "close-stale":
        try:
            age = parse_age(args.older_than)
        except argparse.ArgumentTypeError as exc:
            parser.error(f"--older-than: {exc}")
        return close_stale(age, include_active=args.include_active, dry_run=args.dry_run, label=args.older_than.lower())

    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    from .discord_bot import SocBot

    SocBot(settings).run(settings.discord_token, log_handler=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
