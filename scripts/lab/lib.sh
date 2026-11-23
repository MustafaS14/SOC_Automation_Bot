# Shared helpers for the lab start/stop scripts. Source this file; do not run it.

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32mOK\033[0m   %s\n' "$*"; }
warn() { printf '  \033[1;33mWARN\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; }

# wait_for <seconds> <command...>: run the command every 2 s until it succeeds or time runs out.
wait_for() {
    local limit="$1"; shift
    local waited=0
    while ! "$@" >/dev/null 2>&1; do
        sleep 2
        waited=$((waited + 2))
        [ "$waited" -ge "$limit" ] && return 1
    done
    return 0
}

port_open() { ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }

check_clock() {
    say "Clock"
    if timedatectl 2>/dev/null | grep -q 'synchronized: yes'; then
        ok "clock is synchronised"
        return
    fi
    warn "clock not synchronised, restarting time sync"
    sudo systemctl restart systemd-timesyncd
    sleep 5
    if timedatectl 2>/dev/null | grep -q 'synchronized: yes'; then
        ok "clock is synchronised now"
    else
        warn "still not synchronised; wait a minute and run: timedatectl | grep synchronized"
    fi
}
