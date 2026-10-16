# Bot refactor plan: from Azure to the local Splunk lab

The bot was first written against Microsoft Sentinel and Defender for Endpoint. The project now runs as a fully local lab (see [architecture.md](architecture.md)), so the **data sources and response backend change**, while the Discord, security, and audit layers stay.

## Target behaviour

| Command | Before (Azure) | After (local lab) |
|---|---|---|
| Alert intake | Polls Sentinel incidents | Splunk alert **webhook** → bot HTTP endpoint → SQLite incident store → embed posted in the alerts channel |
| `/incident list\|show` | Sentinel REST | Reads the SQLite store |
| `/incident comment\|close` | Sentinel REST | Updates SQLite; close also sends an audit event to Splunk HEC |
| `/hunt <query>` (new) | n/a | Splunk REST `:8089` search with a validated, read-only SPL template |
| `/enrich <ip>` | AbuseIPDB + VirusTotal | Unchanged |
| `/isolate`, `/unisolate` | Defender for Endpoint API | SSH as restricted `responder` user running a sudoers-limited script (ufw lockdown that keeps the management channel open) |
| `/soc-help` | Static help | Update the text only |

## Keep as is (generic)

| File | Why |
|---|---|
| `soc_bot/rbac.py`, `config.py` (structure) | READ/TRIAGE/RESPONSE tiers and fail-closed startup apply to any backend |
| `soc_bot/validators.py` | IP, hostname and deny-list checks are needed for SSH isolation too |
| `soc_bot/audit.py` | JSONL audit log; also forward entries to Splunk HEC |
| `soc_bot/clients/base.py`, `clients/enrichment.py` | httpx helpers and threat-intel lookups |
| `discord_bot/checks.py`, `views.py` | Role checks and confirm buttons |
| `discord_bot/cogs/enrichment.py`, `general.py` | Only text changes |
| `tests/test_rbac.py`, `test_validators.py`, `test_audit.py` | Still valid (adjust the Sentinel-comment test) |

## Replace

| Old | New |
|---|---|
| `clients/sentinel.py` | `store/incidents.py` (SQLite: id, rule, severity, host, src_ip, status, assignee, comments, timestamps) |
| `clients/defender.py` | `clients/ssh_response.py` (asyncssh; fixed command, no user-supplied shell text) |
| `clients/mock.py` | Update the mocks to the new interfaces; keep `SOC_BOT_MOCK=true` for demos |
| `cogs/incidents.py` | Same commands, backed by the store; classification choices become `true_positive`, `false_positive`, `benign` |
| `cogs/response.py` | Same confirm + deny-list + audit flow; calls `ssh_response` |
| `DefaultAzureCredential` in `bot.py` | Remove; add Splunk token and SSH key settings |
| `.env.example`, `requirements.txt` | Drop `azure-identity` and Azure vars; add `SPLUNK_URL`, `SPLUNK_TOKEN`, `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `RESPONDER_SSH_KEY`, `WEBHOOK_SECRET`; add `asyncssh` and `aiohttp` (or FastAPI) |
| `tests/test_clients.py` | Rewrite with `httpx.MockTransport` against Splunk REST; add store tests |

## Add

1. **Webhook receiver**: small async HTTP server inside the bot process. Verify a shared secret header, validate the JSON, insert into SQLite, post an embed with Acknowledge/Enrich/Isolate buttons.
2. **`/hunt`**: only predefined SPL templates with validated parameters (host, IP, time window). Never pass free-form SPL from Discord.
3. **Responder script** on the victim: `/usr/local/sbin/soc-isolate` and `soc-unisolate`, allowed through a `sudoers.d` entry for the `responder` user only. Isolation keeps SSH from the SIEM host open so the host can be released.
4. **Audit forwarding**: every close or isolate action also sent to Splunk HEC (index `soc_audit`).

## Order of work

1. Build the SIEM VM and get logs into Splunk (infra first; the bot needs real alerts to react to).
2. Add the SQLite store and webhook receiver; test with `curl` and a fake alert.
3. Port `/incident` commands to the store.
4. Add `/hunt`.
5. Add SSH isolation and test on the victim snapshot.
6. Remove Azure code and update README and `docs/flowchart.md`.

## Rules to keep

- No secrets in the repo; `.env` stays ignored.
- Every state-changing command: RBAC check, deny-list check, confirm button, audit entry.
- The bot never builds shell commands or SPL from raw user text.
