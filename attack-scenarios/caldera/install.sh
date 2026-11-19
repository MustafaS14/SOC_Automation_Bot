#!/bin/bash
# Copy the SOC lab attack profiles into a Caldera install. Run it on soc-attacker, then restart Caldera.
# Usage: bash install.sh [CALDERA_DIR]     (default ~/caldera)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALDERA="${1:-$HOME/caldera}"
[ -d "$CALDERA/data" ] || { echo "No Caldera data folder at $CALDERA/data" >&2; exit 1; }
mkdir -p "$CALDERA/data/abilities/soc-lab"
cp "$HERE"/abilities/*.yml "$CALDERA/data/abilities/soc-lab/"
cp "$HERE"/adversaries/*.yml "$CALDERA/data/adversaries/"
echo "Installed $(ls "$HERE"/abilities | wc -l) abilities and $(ls "$HERE"/adversaries | wc -l) adversary into $CALDERA/data."
echo "Now restart Caldera (tmux attach -t caldera, Ctrl+C, python3 server.py, then Ctrl+b d)."
