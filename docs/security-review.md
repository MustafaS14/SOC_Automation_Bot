# Security review

The bot can isolate hosts and close incidents, so it was reviewed like production code before being pointed at the lab. This page lists what the review found, how each finding was fixed, and what is still open. The review was a read-through of the code and its tests (last checked at commit `49f9f49`); it was not a penetration test, and the bot has not yet been run against a live Splunk or the victim VM.

Severity is a judgement call for a lab setting: **High** means an unauthenticated or unintended action was possible, **Medium** means a weakness that needs another failure to matter, **Low** means polish or hardening.

## Findings that were fixed

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | An empty `WEBHOOK_SECRET` authenticated every request (`compare_digest(b"", b"")` is true) | High | Startup refuses an empty secret and `create_app` rejects a blank one; a test covers the empty case |
| 2 | Webhook secret accepted in the URL query string, where it ends up in access logs and Splunk config | Medium | Secret is read only from the `X-Webhook-Secret` header; a test asserts `?secret=` is rejected. The webhook binds to `127.0.0.1` by default |
| 3 | No rate limit on the webhook, so a valid sender could flood SQLite and Discord | Medium | Sliding-window limiter returning 429 with `Retry-After`; unauthenticated requests do not use up the budget |
| 4 | An empty `ALLOWED_CHANNEL_IDS` meant every channel was allowed (fail-open) | Medium | The bot refuses to start without allowed channels, and `channel_allowed` returns false for an empty list |
| 5 | `dc01.evil.com` was mapped to inventory host `dc01` by stripping the domain, which could sidestep the deny-list | High | Dotted names must match an inventory entry exactly; the deny-list is checked on both the typed name and the resolved name |
| 6 | The deny-list was applied to isolate only, so protected hosts could be released from chat | Low | The same check now runs for unisolate and the flowchart matches |
| 7 | Secrets were visible in the settings object's `repr` (Discord token) or missing from it | Medium | Every secret field uses `repr=False` and is whitespace-stripped; a test checks the repr |
| 8 | IP verdict said "Clean" when one reputation lookup had failed | Medium | The verdict is "Incomplete" if any source failed and nothing malicious was seen |
| 9 | Incident parser crashed on non-ASCII digits (for example `²`) and echoed raw input inside backticks | Low | ASCII-only digit check; echoed input is stripped of markdown characters |
| 10 | Splunk's error format was not understood and long upstream messages were echoed into Discord | Low | `raise_for_status` handles Splunk and HEC shapes and list-shaped JSON, and truncates to 300 characters |
| 11 | Text from Splunk (alert name, URL, upstream errors) was placed in Discord embeds unescaped | Low | Markdown is escaped in the embeds; alert links must be plain http(s), without credentials, and pinned to the Splunk host when `SPLUNK_URL` is set |
| 12 | `SOC_BOT_MOCK=true` could be left on next to real settings and report fake isolations as successful | Medium | Mock mode logs a warning at startup, refuses to start when real Splunk or SSH settings are present, and leaves the webhook disabled |
| 13 | `WEBHOOK_PORT=0` and `WEBHOOK_RATE_LIMIT=0` were silently replaced by the defaults | Low | Explicit zero is rejected at startup |
| 14 | `ssh_response.py` imported a type that did not exist, so the SSH module could not load | Medium (correctness) | The type was added and the module imports cleanly |
| 15 | The "acknowledged by" notice put the Discord username into the message unescaped | Low | The name is escaped with the same helper as the other embeds; a test covers a name with markdown characters |
| 16 | Alert links could point at any http(s) host when `SPLUNK_URL` was not set | Low | The link is now dropped unless its host is `SPLUNK_URL`'s host or listed in `WEBHOOK_LINK_HOSTS` (ports ignored); a startup warning says when links will be dropped |
| 17 | The deny-list refusal for unisolate used the wording for isolate | Low | The message is now specific to each action |
| 18 | A reputation API returning an unexpected JSON shape raised an unhandled error in `/enrich` | Low | Non-object bodies are treated as a failed lookup and recorded in `errors`, so the verdict is "Incomplete" |

## Controls that were already in place and kept

- Three permission tiers (read, triage, response); a higher tier includes the lower ones, and the bot will not start with no roles configured.
- Confirm button on state-changing commands, usable only by the person who ran the command.
- Audit log: one JSON line per action, also forwarded to Splunk HEC.
- SQL uses placeholders only; status and severity map through fixed tables.
- SPL is never built from free text: three fixed templates with a validated host or IP and an allow-listed time window.
- SSH runs two fixed commands with no arguments, as a restricted `responder` user limited by `sudoers` to two scripts, with host-key verification left on.

## Still open

| Item | Severity | Notes |
|---|---|---|
| The webhook rate limit is global, not per sender | Low | Someone holding the secret could use up the budget and delay real alerts. Mitigation: rotate the secret and keep the webhook on a private address |
| Webhook secret travels over plain HTTP inside the lab network | Low | Acceptable on the isolated host-only network; use TLS or a reverse proxy anywhere else |
| The responder's SSH key needs a forced command | Medium | Documented in `infra/responder/README.md`; it must be applied in `authorized_keys` when the lab is built |
| Deny-listed hosts cannot be released from chat | Info | By design, but a host isolated outside the bot stays isolated until someone acts manually; this belongs in a runbook |
| The auditd rule logs 64-bit `execve` only and is noisy | Low | A 32-bit rule and filtering by user will be added when detections are tuned |
| `SPLUNK_URL` is not checked for a scheme | Low | A value like `splunk.lab:8089` has no hostname, so alert links are dropped with only the generic warning |
| Non-numeric values inside a reputation API response are not type-checked | Low | A string where a number is expected could still raise inside the verdict logic; not covered by a test |
| Validation and "not configured" error text is sent to Discord without markdown escaping | Low | The validators already strip backticks from echoed input, so the practical risk is small; unverified |
| Mock mode shows its footer on alert embeds only | Info | Confirm and result embeds carry a `[MOCK]` tag instead |
| Tests for the isolate and unisolate deny-list refusal were not located in review | Low | The code path is as described above, but a dedicated test should be confirmed |
| Not yet tested against a live Splunk and a real isolation | Medium | Planned for the next phase of the lab |

## How this was done

Each finding was checked against the code at a specific commit, fixed by the coding assistant in small steps with tests, and re-read after the push. That loop (review, fix, test, re-review) is the same one a security team would run before putting a new tool into service.
