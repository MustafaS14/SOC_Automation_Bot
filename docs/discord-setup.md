# Discord setup

How the Discord side of the lab was set up: the application, the private server, the roles and the bot's `.env`. No token, secret or personal ID belongs in the repo; the IDs below are placeholders.

## 1. The application

In the [Developer Portal](https://discord.com/developers/applications):

1. **New Application**, give it a name, a description and tags. Add an icon and a banner (optional).
2. **Installation** tab: set **Install Link** to *None*. A private app must not have a default authorization link.
3. **Bot** tab: turn **Public Bot** off. Leave all three privileged intents off; the bot only uses slash commands and buttons.
4. **Reset Token** and copy it once, straight into the bot's `.env` (never into chat, an issue or a commit). If the bot says "Improper token", the value was usually pasted twice; a valid token has three parts separated by dots.

## 2. Invite the bot

Build the invite URL with `client_id` set to the application ID and:

- scopes: `bot applications.commands`
- permissions integer: `84992` (View Channels, Send Messages, Embed Links, Read Message History)

Open it while logged in as the server owner and pick the private server.

## 3. Server layout

Turn on Developer Mode (User Settings, Advanced) to copy IDs.

| Channel | Purpose | Who sees it |
|---|---|---|
| `#soc-commands` | Slash commands (`/incident`, `/enrich`, `/hunt`, `/isolate`, `/ask`, `/soc-help`) | the roles you choose |
| `#soc-alerts` | Alert cards posted by the bot with their buttons | the roles you choose |
| `#soc-audit` | Feed of every action taken (acknowledge, close, isolate) | the roles you choose; each only needs View Channel |

All three are **private channels**. Roles: `soc-viewer`, `soc-analyst`, `soc-responder`, `soc-admin`, mapped to the bot's permission tiers.

Permissions:

- `@everyone`: View Channel denied on every SOC channel.
- Each SOC role: only **View Channel** allowed. Roles do not need Send Messages; slash commands and button clicks are interactions, not messages.
- The bot (its own role): **View Channel, Send Messages, Embed Links, Read Message History** allowed, everything else left off, on each of the three channels.

Each channel also has a short topic that says what belongs there.

## 3b. Bot `.env`

Created on `soc-siem`, mode `600`, never committed:

```
DISCORD_TOKEN=<from the Developer Portal>
DISCORD_GUILD_ID=<server id>
ALLOWED_CHANNEL_IDS=<soc-commands id>,<soc-alerts id>,<soc-audit id>
ALERT_CHANNEL_ID=<soc-alerts id>
AUDIT_CHANNEL_ID=<soc-audit id>
RBAC_VIEWER_ROLE_IDS=<soc-viewer id>
RBAC_READ_ROLE_IDS=
RBAC_TRIAGE_ROLE_IDS=<soc-analyst id>
RBAC_RESPONSE_ROLE_IDS=<soc-responder id>
RBAC_ADMIN_ROLE_IDS=<soc-admin id>
WEBHOOK_SECRET=<long random string>
WEBHOOK_HOST=172.18.0.1
WEBHOOK_PORT=8765
```

The bot reads five role variables, one per tier, and higher tiers include the lower ones. Discord role names are free, so map them like this (the names on the left are the ones used in this lab):

| Discord role | Variable | What the tier can do |
| --- | --- | --- |
| `soc-viewer` | `RBAC_VIEWER_ROLE_IDS` | Only the summary-level answers of `/ask` |
| (not used here) | `RBAC_READ_ROLE_IDS` | List and show incidents, `/enrich`, `/hunt` |
| `soc-analyst` | `RBAC_TRIAGE_ROLE_IDS` | READ, plus comment on, acknowledge and close incidents |
| `soc-responder` | `RBAC_RESPONSE_ROLE_IDS` | TRIAGE, plus `/isolate` and `/unisolate` |
| `soc-admin` | `RBAC_ADMIN_ROLE_IDS` | Everything |

The bot refuses to start if none of these is set. Variables you do not use can stay empty.

Two details that cost time: `ALLOWED_CHANNEL_IDS` must include the alert channel or the card's buttons fail with "didn't respond in time", and `WEBHOOK_HOST` is the Docker gateway of the `siem_default` network so that Splunk (in a container) can reach the bot but the lab network cannot.

## 4. Run and test

```
cd ~/SOC_Automation_Bot && source .venv/bin/activate
python -m soc_bot
```

Use a second SSH window for other commands. Test the webhook with the `curl` in [the alert action README](../infra/siem/splunk/soc_bot_alert/README.md). A card with the buttons Acknowledge, Enrich IP and Isolate host should appear in `#soc-alerts`, and `/soc-help` should answer in `#soc-commands` with the commands allowed for your tier.
