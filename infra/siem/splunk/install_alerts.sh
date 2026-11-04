#!/bin/bash
# Install the saved searches (alerts) from this repository into the Splunk container on soc-siem.
#
# Usage: bash install_alerts.sh [SUPPRESS_PERIOD]
#   SUPPRESS_PERIOD  how long an alert stays quiet per host after it fires, for example 30m (default),
#                    15m or 5m. A period shorter than the 15-minute lookback can repeat a card.
#
# It keeps a timestamped backup of the live file inside the container, writes the repository copy with
# the chosen period, and checks that the bot action is still switched on. Then reload Splunk's config
# without a restart: open http://<soc-siem>:8000/en-GB/debug/refresh and click Refresh.
set -euo pipefail

PERIOD="${1:-30m}"
if ! [[ "$PERIOD" =~ ^[0-9]+[smhd]$ ]]; then
  echo "SUPPRESS_PERIOD must look like 30m, 15m or 5m" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/savedsearches.conf"
DEST=/opt/splunk/etc/apps/search/local/savedsearches.conf

[ -f "$SRC" ] || { echo "Missing $SRC" >&2; exit 1; }

BACKUP="$DEST.bak.$(date +%Y%m%d%H%M%S)"
docker exec -u splunk splunk cp "$DEST" "$BACKUP"
sed "s/^alert.suppress.period = .*/alert.suppress.period = $PERIOD/" "$SRC" \
  | docker exec -i -u splunk splunk tee "$DEST" > /dev/null

echo "Backup:  $BACKUP (inside the splunk container)"
echo "Checks:"
docker exec -u splunk splunk grep -n "alert.suppress.period\|action.soc_bot_webhook\|^\[" "$DEST"
echo "Done. Now open http://192.168.56.10:8000/en-GB/debug/refresh and click Refresh."
