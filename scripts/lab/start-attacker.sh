#!/usr/bin/env bash
# Cold start for soc-attacker: Caldera (in tmux), the SOC profiles, and exactly one agent.
# Safe to run again: it only starts what is not already running.
#   bash scripts/lab/start-attacker.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

REPO="${REPO:-$HOME/SOC_Automation_Bot}"
CALDERA_DIR="${CALDERA_DIR:-$HOME/caldera}"
AGENT_DIR="${AGENT_DIR:-$HOME/agent}"
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

say "Agent"
mkdir -p "$AGENT_DIR"
size=$(stat -c %s "$AGENT_DIR/splunkd" 2>/dev/null || echo 0)
if [ "$size" -lt 1000000 ]; then
    echo "  downloading the agent..."
    rm -f "$AGENT_DIR/splunkd" 2>/dev/null || mv "$AGENT_DIR/splunkd" "$AGENT_DIR/splunkd.bad.$$" 2>/dev/null
    curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "$SERVER/file/download" > "$AGENT_DIR/splunkd"
    chmod +x "$AGENT_DIR/splunkd"
    size=$(stat -c %s "$AGENT_DIR/splunkd" 2>/dev/null || echo 0)
fi
if [ "$size" -lt 1000000 ]; then bad "agent download is only $size bytes; is Caldera really up?"; exit 1; fi
ok "agent file ready ($size bytes)"

running=$(pgrep -x splunkd | wc -l)
if [ "$running" -eq 1 ]; then
    ok "one agent already running"
else
    [ "$running" -gt 1 ] && { warn "$running agents running; stopping them so only one remains"; sudo pkill -x splunkd; sleep 2; }
    sudo -v
    (cd "$AGENT_DIR" && sudo nohup ./splunkd -server "$SERVER" -group red > "$HOME/agent.log" 2>&1 &)
    sleep 5
    running=$(pgrep -x splunkd | wc -l)
    if [ "$running" -eq 1 ]; then ok "agent started (log: ~/agent.log)"; else bad "expected 1 agent, found $running (see ~/agent.log)"; fi
fi

say "Done. In a private browser window open http://192.168.56.30:8888, check the agent on the Agents tab, then start the 'SOC full coverage' operation."
