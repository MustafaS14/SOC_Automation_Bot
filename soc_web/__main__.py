"""Run the console, and manage its accounts.

    python -m soc_web                      start the server
    python -m soc_web user add alice --tier triage
    python -m soc_web user list | passwd | tier | disable | enable
"""

from __future__ import annotations

import argparse
import getpass
import logging
import secrets
import sys

from soc_bot.config import ConfigError, Settings

from .config import WebSettings
from .users import TIERS, UserError, UserStore


def _store(web: WebSettings) -> UserStore:
    return UserStore(web.users_db, max_failed=web.max_failed_logins, lockout_minutes=web.lockout_minutes)


def _ask_password() -> str:
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat it: "):
        raise UserError("The two passwords differ.")
    return first


def _user_command(args: argparse.Namespace) -> int:
    try:
        web = WebSettings.from_env(mock_mode=True)  # account management does not need the real secret key
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    users = _store(web)
    try:
        if args.action == "add":
            user = users.create(args.username, _ask_password(), args.tier)
            print(f"Created {user.username} ({user.tier_name}).")
        elif args.action == "list":
            for u in users.list():
                print(f"{u.username:<32} {u.tier_name:<9} {'active' if u.active else 'disabled'}")
        elif args.action == "passwd":
            users.set_password(args.username, _ask_password())
            print(f"Password changed for {args.username}.")
        elif args.action == "tier":
            users.set_tier(args.username, args.tier)
            print(f"{args.username} is now {args.tier}.")
        else:
            users.set_active(args.username, args.action == "enable")
            print(f"{args.username} {args.action}d.")
    except UserError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        users.close()
    return 0


def _serve() -> int:
    try:
        settings = Settings.from_env(require_discord=False)
        web = WebSettings.from_env(mock_mode=settings.mock_mode)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    log = logging.getLogger("soc_web")

    from waitress import serve

    from .app import create_app
    from .runtime import AsyncRunner, build_backends

    runner = AsyncRunner()
    backends = build_backends(settings, runner)
    users = _store(web)
    if settings.mock_mode:
        log.warning("MOCK MODE: demo data only, nothing real is read or changed.")
        if users.count() == 0:
            password = secrets.token_urlsafe(12)
            users.create("demo", password, "admin")
            print(f"\nDemo account created. Sign in as 'demo' with password: {password}\n", flush=True)
    elif users.count() == 0:
        print("No accounts yet. Create one with: python -m soc_web user add <name> --tier triage", file=sys.stderr)
    if web.host not in ("127.0.0.1", "::1", "localhost"):
        log.warning("Listening on %s over plain HTTP. Put a TLS reverse proxy in front before using real credentials.",
                    web.host)

    app = create_app(web, backends, users)
    log.info("Console at http://%s:%d", web.host, web.port)
    try:
        serve(app, host=web.host, port=web.port, threads=4, ident="soc-web")
    finally:
        users.close()
        backends.close()
        runner.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m soc_web")
    sub = parser.add_subparsers(dest="command")
    user = sub.add_parser("user", help="manage console accounts")
    actions = user.add_subparsers(dest="action", required=True)
    add = actions.add_parser("add")
    add.add_argument("username")
    add.add_argument("--tier", choices=list(TIERS), default="read")
    actions.add_parser("list")
    for name in ("passwd", "disable", "enable"):
        actions.add_parser(name).add_argument("username")
    tier = actions.add_parser("tier")
    tier.add_argument("username")
    tier.add_argument("tier", choices=list(TIERS))
    args = parser.parse_args()
    return _user_command(args) if args.command == "user" else _serve()


if __name__ == "__main__":
    sys.exit(main())
