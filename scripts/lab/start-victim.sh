#!/usr/bin/env bash
# Cold start for soc-victim: auditd (with the SOC rules) and Filebeat.
#   bash scripts/lab/start-victim.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

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

say "Done. The heartbeat on the console dashboard should turn green within a few minutes."
