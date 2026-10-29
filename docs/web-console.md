# Web console

A Flask app in [`soc_web/`](../soc_web/) that gives analysts the bot's triage workflow in a browser. It runs as its own process (`python -m soc_web`) and uses the same incident store, hunt templates, enrichment clients, AI assistant and audit log as the Discord bot.

## What it does

| Page | Minimum tier | What it does |
|---|---|---|
| Dashboard | VIEWER | Counts of incidents by status and open ones by severity; the latest open incidents for READ and above |
| Incidents, incident detail | READ | Filter by status and severity, read details and comments |
| Acknowledge, comment, close | TRIAGE | Close takes a second confirmation page, like the bot's confirm button |
| Enrich | READ | AbuseIPDB and VirusTotal verdict for an IP; optionally recorded as an incident comment |
| Hunt | READ | The predefined read-only SPL templates from `soc_bot/hunts.py`; input only fills a validated host or IP |
| Ask | VIEWER | The AI assistant, answering at the signed-in user's tier |
| Audit | ADMIN | The newest 100 audit entries from both the bot and the console |

Tiers are the bot's (`VIEWER < READ < TRIAGE < RESPONSE < ADMIN`). **There is no isolate or release button**: the console is built without the SSH client, and the assistant is given none either.

## Run it

```powershell
pip install -r requirements.txt
python -c "import secrets; print(secrets.token_hex(32))"   # put the result in SOC_WEB_SECRET_KEY in .env
python -m soc_web user add alice --tier triage              # asks for the password twice
python -m soc_web                                           # http://127.0.0.1:8080
```

The console reads the same `.env` as the bot, but needs no Discord token, role IDs or channel IDs. Point `DB_PATH` at the bot's incident database to see its incidents; alerts arrive through the bot's webhook, not the console.

Account commands: `user list`, `user passwd <name>`, `user tier <name> <tier>`, `user disable <name>`, `user enable <name>`. There is no sign-up page and no admin page for accounts, on purpose: accounts are made on the machine that runs the console.

**Demo:** with `SOC_BOT_MOCK=true` the console uses in-memory fake data and, if there are no accounts, creates `demo` (ADMIN) and prints its random password once.

## Security notes

- **Passwords** are stored as scrypt hashes, at least 12 characters. After 5 failed sign-ins (configurable) an account is locked for 15 minutes, and each address may try 20 sign-ins per 5 minutes. A wrong username and a wrong password give the same answer and take about the same time.
- **Sessions** are signed cookies: `HttpOnly`, `SameSite=Lax`, `Secure` unless `SOC_WEB_SECURE_COOKIES=false`, and renewed at every sign-in. The user's tier is read from the database on every request, so disabling an account or lowering a tier applies at once.
- **CSRF:** every POST needs a per-session token.
- **Content Security Policy** allows no scripts at all and no inline styles, and the pages contain none. Alert text, comments and Splunk rows are untrusted, and Jinja escapes them. An alert link is only shown as a link if it is `http` or `https`.
- **Audit:** every incident list or detail view, change, hunt, enrichment, question and audit view is written to the audit log with `channel: web` and the client address, and forwarded to Splunk HEC when that is configured. Failed sign-ins are logged with the typed username but never the password.
- **Comment authors** are stored as `name@web`, so a console account cannot pass itself off as a Discord user of the same name.

## Before using it beyond localhost

- The server speaks plain HTTP. For any other address put a TLS reverse proxy in front, and keep `SOC_WEB_SECURE_COOKIES=true`. The console does not trust `X-Forwarded-For`, so behind a proxy the per-address sign-in limit sees the proxy's address.
- The bot and the console append to the same `AUDIT_LOG_PATH` from two processes. That works for these short single-line writes; if you need strict ordering, give each its own file.
- Closing an incident is the one change that cannot be undone from the console.

## Layout

```
soc_web/
├── __main__.py      # server and `user` commands
├── app.py           # routes and the permission check on each
├── config.py        # SOC_WEB_* settings
├── runtime.py       # background event loop and the shared backends
├── security.py      # CSRF, sign-in throttle, response headers
├── users.py         # accounts: hashing, tiers, lockout
├── templates/       # Jinja pages (no JavaScript)
└── static/style.css
```
