from __future__ import annotations

import logging
import sys

from .config import ConfigError, Settings


def main() -> int:
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
