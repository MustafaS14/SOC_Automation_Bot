#!/usr/bin/env bash
# Cold start for soc-attacker: Caldera (in tmux) and the SOC profiles. The agent runs on soc-victim, not here.
# Safe to run again: it only starts what is not already running.
#   bash scripts/lab/start-attacker.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

REPO="${REPO:-$HOME/SOC_Automation_Bot}"
CALDERA_DIR="${CALDERA_DIR:-$HOME/caldera}"
SERVER="http://127.0.0.1:8888"
LOG="$HOME/caldera-start.log"

check_clock

say "Code and Caldera profiles"
git -C "$REPO" pull --ff-only >/dev/null 2>&1 && ok "repository up to date" || warn "git pull did not run cleanly; carrying on"
if bash "$REPO/attack-scenarios/caldera/install.sh" >/dev/null 2>&1; then ok "profiles installed"; else bad "install.sh failed; run it by hand to see why"; fi

start_caldera() {   # $1 = extra server.py flags
    tmux kill-session -t caldera 2>/dev/null
    : > "$LOG"
    tmux new-session -d -s caldera \
        "cd '$CALDERA_DIR' && . venv/bin/activate && python3 server.py --insecure $1 2>&1 | tee '$LOG'; echo; echo 'Caldera stopped. Press Enter to close.'; read"
}

say "Caldera server"
if port_open 8888; then
    ok "Caldera already running"
else
    start_caldera ""
    echo "  waiting for Caldera (up to 2 minutes)..."
    if ! wait_for 120 port_open 8888; then
        if grep -q "Failed to decrypt saved Caldera state" "$LOG"; then
            warn "saved state could not be read; starting fresh (old operations are dropped, profiles are kept)"
            start_caldera "--fresh"
            wait_for 120 port_open 8888
        fi
    fi
    if port_open 8888; then ok "Caldera started in tmux session 'caldera' (attach: tmux attach -t caldera)"; else bad "Caldera did not come up. Look at it: tmux attach -t caldera"; exit 1; fi
fi
if wait_for 30 curl -fs -o /dev/null "$SERVER"; then ok "web UI answers (log in as red / admin, typing the password by hand)"; fi

say "Done. Now run bash ~/lab/start-victim.sh on soc-victim, which starts the agent there. Then open http://192.168.56.30:8888 in a private window."
