# Web console

A Flask app in [`soc_web/`](../soc_web/) that gives analysts the bot's triage workflow in a browser. It runs as its own process (`python -m soc_web`) and uses the same incident store, hunt templates, enrichment clients, AI assistant and audit log as the Discord bot.

> **Localhost only, unless a TLS proxy is in front.** The server speaks plain HTTP, so sign-in passwords and session cookies cross the network unencrypted on any address other than `127.0.0.1`. It binds to `127.0.0.1` by default. To reach it from another machine, put a TLS reverse proxy in front and keep `SOC_WEB_SECURE_COOKIES=true`. The console logs a warning if it is started on any other address.

![Dashboard in the demo (mock) mode](screenshots/dashboard.png)

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

The assistant's per-tool clearance is shared code with the bot. The page-level tiers in the table are set in `soc_web/app.py` (`@needs(...)`) to match the bot's `@require(...)` commands, so if you change a command's tier in one place, change it in the other.

**How answers are shown.** On the Ask page the assistant's answer is laid out as a titled card of labelled rows (severity as a badge, "none" instead of `n/a`), a table when there are several rows (hunt results, incident lists), and a separate block for Confidence and Not checked. Free-form text from a real model stays as paragraphs. Below it, a box called **In plain words** shows 2 or 3 non-technical sentences. The assistant's prompt asks for that part after "Not checked:", and never on a refusal, so refusals stay word for word. The parsing lives in `soc_web/answers.py`. The prompt change is in `soc_bot/ai/prompt.py`, so Discord answers carry the same "In plain words:" paragraph, as plain text.

Pages a user's tier does not allow return 403, and the nav only shows what the account can open ([screenshot](screenshots/viewer-refused.png)).

## Run it

```powershell
pip install -r requirements.txt
python -c "import secrets; print(secrets.token_hex(32))"   # put the result in SOC_WEB_SECRET_KEY in .env
python -m soc_web user add alice --tier triage              # asks for the password twice
python -m soc_web                                           # http://127.0.0.1:8000
```

The console reads the same `.env` as the bot, but needs no Discord token, role IDs, channel IDs or `WEBHOOK_SECRET`. Point `DB_PATH` at the bot's incident database to see its incidents; alerts arrive through the bot's webhook, not the console.

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
- **Shared audit log.** The bot and the console append whole lines to the same `AUDIT_LOG_PATH`, each from its own process. That is fine for this lab. If they ever run as separate services (different machines, containers or accounts), give each its own file, or use the copy in Splunk (`index=soc_audit`, set `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN`) as the combined record. The Audit page reads only the file it is pointed at.
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
└── static/
    ├── style.css    # the space-UI theme: pure CSS, including the planet
    └── fonts/       # Orbitron and Exo 2, self-hosted, with their SIL Open Font License files
```

## The look

A retro space-UI theme: cream, teal and orange on charcoal, ridged menu tabs for incidents with a coloured severity marker, and a planet on the dashboard with one orbiting moon for each severity that still has open incidents.

It is cosmetic. Tier names are shown as ranks (Cadet, Scout, Pilot, Guardian, Commander for VIEWER up to ADMIN), the threat level comes from the worst severity still open, and severities get star ratings. None of it changes what a tier may do.

It is built to fit the security policy: no JavaScript, no inline styles and no outside fonts, so the policy still reads `default-src 'none'` with `style-src 'self'` and `font-src 'self'`. The planet is drawn in CSS. Orbits stop turning when the browser asks for reduced motion.
