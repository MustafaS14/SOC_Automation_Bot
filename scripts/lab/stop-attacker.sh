#!/usr/bin/env bash
# Stop the agent and Caldera cleanly (Caldera saves its state on Ctrl+C) before powering off soc-attacker.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"
say "Stopping the agent"
sudo pkill -x splunkd 2>/dev/null; ok "agent stopped"
say "Stopping Caldera"
tmux send-keys -t caldera C-c 2>/dev/null
for _ in $(seq 1 15); do port_open 8888 || break; sleep 2; done
tmux kill-session -t caldera 2>/dev/null
if port_open 8888; then warn "Caldera is still listening; check: ps aux | grep server.py"; else ok "Caldera stopped. Power off with: sudo poweroff"; fi
