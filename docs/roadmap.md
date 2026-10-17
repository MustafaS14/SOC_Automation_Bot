# Roadmap

What is built, what comes next, and ideas for extending the project. The ideas are not commitments; the order is by value for effort. Current status is in the [README](../README.md).

## Phase 1: finish the pipeline (next)

1. Build `soc-siem` with Splunk and Logstash; ship the victim's auditd logs through Filebeat. See [lab-build-log.md](lab-build-log.md), section 7.
2. Write the first detection for the Discovery scenario and connect the Splunk alert to the bot's webhook.
3. Create the `responder` user on the victim, restrict its SSH key with a forced command, and test isolation from a snapshot.
4. Record a short demo: attack, alert in Discord, triage, isolation.

## Phase 2: make it look like real SOC work

| Idea | Why it matters |
|---|---|
| Tag each detection with its MITRE ATT&CK technique and keep a coverage table (what Caldera can run versus what is detected) | Real teams track detection coverage; it also shows the gaps |
| A detection test script: run a Caldera operation, wait, and check the expected alert reached the bot | Proves each rule works ("detection as code") |
| More scenarios, each with a write-up and a detection: SSH brute force, persistence through cron or a new user, privilege escalation attempt | A small library beats one demo |
| Alert noise control: suppress known-benign activity, merge repeated alerts into one incident, raise severity on repetition | False positives are the everyday problem in a SOC; show alert counts before and after |
| Metrics from the incident store: time to detect and time to respond, shown in a `/stats` command or a dashboard | Managers ask for these numbers |

## Phase 3: automation and reporting

| Idea | Why it matters |
|---|---|
| Automatic first response: on a high-severity alert, the bot runs `/hunt` and `/enrich` and attaches the results to the incident before an analyst opens it | This is the "automation" in the project name |
| A Splunk dashboard: alerts over time, top hosts, open versus closed incidents | Quick to build and good for screenshots |
| `/report`: a markdown summary of an incident (alert, actions, who did what, outcome) | Mirrors the post-incident reports real teams write |
| Match source IPs and file hashes against a free threat-intel feed | Raises severity automatically on a hit |

## Phase 4: larger extensions (only if the rest is done)

- A Windows victim with Sysmon, since most enterprise attacks target Windows.
- Network telemetry with Suricata or Zeek on the host-only network, to see the command-and-control traffic.
- A runbook per alert type: what an analyst checks and when to isolate.
- Running the bot as a service, with database backups, token rotation and TLS between Splunk and the bot.

## Known gaps to close along the way

Listed in [security-review.md](security-review.md), under "Still open". The bot has not yet run against a live Splunk or a real isolation, and the auditd rule covers 64-bit `execve` only.
