#!/usr/bin/env bash
# Cold start for soc-siem: Splunk + Logstash, the alert definitions, and the bot (in tmux).
# Safe to run again: it only starts what is not already running.
#   bash scripts/lab/start-siem.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

REPO="${REPO:-$HOME/SOC_Automation_Bot}"
SIEM_DIR="${SIEM_DIR:-$HOME/siem}"
SPLUNK_CONTAINER="${SPLUNK_CONTAINER:-splunk}"
BOT_PORT=8765

check_clock

say "Code"
if git -C "$REPO" pull --ff-only >/dev/null 2>&1; then
    ok "repository up to date"
else
    warn "git pull did not run cleanly; carrying on with the code that is here"
fi

say "Splunk and Logstash"
if [ -f "$SIEM_DIR/docker-compose.yml" ]; then
    (cd "$SIEM_DIR" && docker compose up -d) >/dev/null 2>&1 && ok "containers started" || warn "docker compose up failed"
else
    docker start "$SPLUNK_CONTAINER" logstash >/dev/null 2>&1 && ok "containers started" || warn "docker start failed (names: docker ps -a)"
fi

splunk_healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$SPLUNK_CONTAINER" 2>/dev/null)" = "healthy" ]; }
echo "  waiting for Splunk to become healthy (a cold boot takes up to 15 minutes)..."
if wait_for 900 splunk_healthy; then
    ok "Splunk is healthy"
else
    bad "Splunk is not healthy yet. Check: docker ps ; docker logs --tail 20 $SPLUNK_CONTAINER"
    exit 1
fi

say "Alert definitions"
if bash "$REPO/infra/siem/splunk/install_alerts.sh" >/dev/null 2>&1; then
    ok "alerts installed (default throttle)"
else
    bad "install_alerts.sh failed; run it by hand to see why"
fi
echo "  then open Splunk /debug/refresh and click Refresh once"

say "Bot"
if pgrep -f "python -m soc_bot" >/dev/null; then
    ok "bot already running"
else
    tmux kill-session -t bot 2>/dev/null
    tmux new-session -d -s bot "cd '$REPO' && . .venv/bin/activate && python -m soc_bot; echo; echo 'Bot stopped. Press Enter to close.'; read"
    if wait_for 40 port_open "$BOT_PORT"; then
        ok "bot started in tmux session 'bot' (attach: tmux attach -t bot)"
    else
        bad "bot is not listening on $BOT_PORT. Look at it: tmux attach -t bot"
    fi
fi

say "Done. Next: bash scripts/lab/start-victim.sh on soc-victim, then start-attacker.sh on soc-attacker."
