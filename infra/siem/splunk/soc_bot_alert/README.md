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
| `bin/soc_bot_webhook.py` | Reads the alert JSON from stdin and forwards `search_name`, `result` and `results_link` to the bot. Exits 1 on any error so Splunk records the failure. |
| `metadata/default.meta` | `export = system` so the `search` app can see the action. Without it the action is "not found". |

Two files are **not** in the repo on purpose, because they are specific to one lab and one is a secret:

| Local file (on soc-siem only) | Content |
|---|---|
| `local/url` | The webhook URL, for example `http://172.18.0.1:8765/webhook/splunk`. |
| `local/secret` | The shared secret, the same value as `WEBHOOK_SECRET` in the bot's `.env`. Sent as the `X-Webhook-Secret` header. |

## Install on soc-siem

Splunk runs in Docker, so the app is copied into the container:

1. Copy this folder to `/opt/splunk/etc/apps/soc_bot_alert/` inside the container (as the `splunk` user).
2. Create `local/url` and `local/secret` there, readable by the `splunk` user only.
3. Reload without a restart: open `http://<soc-siem>:8000/en-US/debug/refresh` and confirm.
4. Enable the action on an alert by adding `action.soc_bot_webhook = 1` to its stanza in `apps/search/local/savedsearches.conf`. The alert editor does not list custom actions that have no UI form, so this is done in the file. The repo copy is [`../savedsearches.conf`](../savedsearches.conf).

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
