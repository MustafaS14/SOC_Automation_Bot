# soc_bot_alert: Splunk custom alert action

A small Splunk app that adds one alert action, **SOC Bot webhook**. When a saved search fires, Splunk runs `bin/soc_bot_webhook.py`, which posts the alert as JSON to the Discord bot's `/webhook/splunk` endpoint. The bot turns it into the alert card in the `#soc-alerts` channel.

```
saved search fires -> soc_bot_webhook.py -> POST http://172.18.0.1:8765/webhook/splunk -> bot -> Discord card
```

## Files

| File | Purpose |
|---|---|
| `default/app.conf` | Declares the app (hidden from the Splunk menu). |
| `default/alert_actions.conf` | Registers the `soc_bot_webhook` action (`is_custom = 1`, JSON payload, Python 3). |
| `bin/soc_bot_webhook.py` | Reads the alert JSON from stdin and forwards `search_name`, `result` and `results_link` to the bot. Retries temporary failures and queues what it cannot deliver (see below). Exits 1 on any failure so Splunk records it. |
| `metadata/default.meta` | `export = system` so the `search` app can see the action. Without it the action is "not found". |

Two files are **not** in the repo on purpose, because they are specific to one lab and one is a secret:

| Local file (on soc-siem only) | Content |
|---|---|
| `local/url` | The webhook URL, for example `http://172.18.0.1:8765/webhook/splunk`. |
| `local/secret` | The shared secret, the same value as `WEBHOOK_SECRET` in the bot's `.env`. Sent as the `X-Webhook-Secret` header. |

## Retries and the queue

Splunk runs an alert action once and never retries it, so a card used to be lost when the bot was down at that moment. The script now handles that itself:

- A **temporary** failure (the bot is unreachable, restarting, rate limiting with 429, or answering 5xx) is retried 4 times, waiting 2, 5 and 15 seconds between tries.
- A **rejection** (400, 401, 403 and the like) is never retried and never queued, because the same request would fail again. Check the secret and the payload instead.
- If the bot is still unreachable after the retries, the alert is written to `local/spool/` (one small JSON file each, readable by the `splunk` user only, holding the alert and never the secret) and the action exits 1 so Splunk logs the failure.
- At the start of every run the script first re-sends the queued alerts, oldest first, up to 10 a run, and stops at the first one that still fails. Queued alerts older than 24 hours are dropped, and the queue keeps at most 50 files.
- **Every two minutes** a scripted input (`default/inputs.conf`, running `bin/soc_bot_resend.py`) does the same re-send on its own, so a queued card arrives within about two minutes of the bot coming back, without waiting for another alert. It does nothing when the queue is empty and indexes nothing. While the bot is still down it logs one warning per run in `splunkd.log` (`ExecProcessor`).

Limits to know: a card can be late (by a few minutes, or up to 24 hours if the bot stays down) but is not lost. A late card can also double up when the bot had accepted the alert but the answer was lost; the bot merges the repeat into the open incident. Splunk's per-host throttle (30 minutes) still applies to the alert, not to the re-send.

To see the queue on soc-siem: `docker exec -u splunk splunk ls /opt/splunk/etc/apps/soc_bot_alert/local/spool` (use your container's name). The folder is readable only by the `splunk` user, so without `-u splunk` you get "Permission denied".

## Install on soc-siem

Splunk runs in Docker, so the app is copied into the container:

1. Copy this folder to `/opt/splunk/etc/apps/soc_bot_alert/` inside the container (as the `splunk` user).
2. Create `local/url` and `local/secret` there, readable by the `splunk` user only.
3. Reload without a restart: open `http://<soc-siem>:8000/en-US/debug/refresh` and confirm. The scheduled re-send is a new input, which Splunk may pick up only after a restart (`docker restart splunk`, then wait for `healthy`); test it as described below.
4. Enable the action on an alert by adding `action.soc_bot_webhook = 1` to its stanza in `apps/search/local/savedsearches.conf`. The alert editor does not list custom actions that have no UI form, so this is done in the file. The repo copy is [`../savedsearches.conf`](../savedsearches.conf).

## Test the scheduled re-send

With the bot running, put a fake queued alert in the spool. It is picked up within about two minutes and a card appears in `#soc-alerts` without any alert firing:

```
docker exec -u splunk splunk mkdir -p /opt/splunk/etc/apps/soc_bot_alert/local/spool
echo '{"search_name":"Resend test","result":{"host":"soc-victim","src_ip":"192.168.56.30","severity":"Medium"},"results_link":null}' | docker exec -i -u splunk splunk sh -c 'cat > /opt/splunk/etc/apps/soc_bot_alert/local/spool/000000000000001-1.json'
docker exec -u splunk splunk ls /opt/splunk/etc/apps/soc_bot_alert/local/spool
```

The last command should list nothing again after the card is posted. Delete the test incident with `/close` if you do not want it on the board.

## Why the URL uses 172.18.0.1

Splunk is inside the `siem_default` Docker network, so `localhost` means the container itself. The host's address on that network is the gateway, `172.18.0.1`. The bot listens on that address only (`WEBHOOK_HOST`), so the webhook is not exposed on the lab network.

## Test

```
curl -sS -X POST http://172.18.0.1:8765/webhook/splunk \
  -H "X-Webhook-Secret: <your secret>" -H "Content-Type: application/json" \
  -d '{"search_name":"Test alert","result":{"host":"soc-victim","src_ip":"192.168.56.30","severity":"Medium"}}'
```

A JSON reply with an `id` means the bot accepted it and posted a card. In Splunk, `| sendalert soc_bot_webhook` proves the action is visible, but it reports an error because that ad-hoc search has no `search_name` and the bot answers 400. That is expected.

If a real alert does not reach Discord, check `index=_internal sourcetype=splunkd component=sendmodalert` and the bot's log. Alert throttling (`alert.suppress.period = 30m` per host) also hides repeats, so a second firing inside 30 minutes is silent by design.
