#!/usr/bin/env bash
# Stop the Caldera agent on soc-victim before powering it off. auditd and Filebeat stop with the VM.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"
say "Stopping the agent"
sudo pkill -x splunkd 2>/dev/null
ok "agent stopped. Power off with: sudo poweroff"
