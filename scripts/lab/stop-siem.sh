#!/usr/bin/env bash
# Stop the bot cleanly before powering off soc-siem. Splunk and Logstash stop with the VM.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"
say "Stopping the bot"
tmux send-keys -t bot C-c 2>/dev/null
sleep 2
tmux kill-session -t bot 2>/dev/null
pkill -f "python -m soc_bot" 2>/dev/null
ok "bot stopped. Power off with: sudo poweroff"
